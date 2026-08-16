/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Sesame receive path (section 3.4, D-SES-6).  Initiation messages
 * are deduped by base key (D-SES-6.1) before any handshake, so a re-sent
 * initial routes to the existing session instead of forking one; a fresh base
 * key runs X3DH respond, creates and inserts the session, and decrypts the
 * embedded first frame, deferring OPK consumption until that frame verifies
 * (D-X3DH-10).  Double Ratchet messages are associated by trial-decrypting the
 * encrypted header against the sender DeviceRecord's sessions in list order
 * (active first, then inactive), each session running the full D-DR-17
 * procedure; the first session whose header opens owns the message, and a
 * payload failure there is a hard error, never a continue (D-SES-6.3).  Every
 * mutation stages through the context's gy_op and reaches the store only on a
 * verified payload; any failure aborts to a uniform error (D-SES-6.2).
 */

#include <string.h>

#include "recv.h"

/* ---- context ----------------------------------------------------------- */

int
gy_recv_ctx_init(struct gy_recv_ctx *c, const struct gy_store *store,
                 const struct gy_suite_desc *desc,
                 const struct gy_keypair *local_ik,
                 const struct gy_keypair *spks, size_t n_spks,
                 const struct gy_keypair *opks, size_t n_opks, uint8_t aead_id,
                 const struct gy_expiry_cfg *expiry, gy_recv_clock_fn clock,
                 void *clock_ctx)
{
    if (c == NULL || store == NULL || desc == NULL || local_ik == NULL ||
        spks == NULL || n_spks == 0)
        return GY_ERR_ARG;
    if (opks == NULL && n_opks != 0)
        return GY_ERR_ARG;
    memset(c, 0, sizeof(*c));
    c->store = store;
    c->desc = desc;
    c->local_ik = local_ik;
    c->spks = spks;
    c->n_spks = n_spks;
    c->opks = opks;
    c->n_opks = n_opks;
    c->aead_id = aead_id;
    if (expiry != NULL)
        c->expiry = *expiry;
    c->clock = clock;
    c->clock_ctx = clock_ctx;
    return GY_OK;
}

static uint64_t
recv_now(struct gy_recv_ctx *c)
{
    return c->clock != NULL ? c->clock(c->clock_ctx) : 0;
}

/* Position of a SessionID in a DeviceRecord: 0 active, 1 inactive, -1 absent. */
static int
session_position(const struct gy_device_record *d,
                 const uint8_t id[GY_SESSION_ID_LEN])
{
    uint32_t i;

    if (d->has_active && gy_const_memcmp(d->active, id, GY_SESSION_ID_LEN) == 0)
        return 0;
    for (i = 0; i < d->n_inactive; i++)
        if (gy_const_memcmp(d->inactive[i], id, GY_SESSION_ID_LEN) == 0)
            return 1;
    return -1;
}

/*
 * Run one candidate session against a DR frame.  On a header match that then
 * verifies, stages the advanced session (and its activation if it was
 * inactive), sets *out_len, and returns GY_OK with *owned = 1.  On a header
 * match whose payload fails, returns GY_ERR_VERIFY with *owned = 1 (hard error,
 * D-SES-6.3).  On no header match, returns GY_ERR_VERIFY with *owned = 0 (the
 * caller continues to the next session).
 */
static int
try_session(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
            const uint8_t *device_id, size_t device_id_len,
            const uint8_t id[GY_SESSION_ID_LEN], int from_inactive,
            const uint8_t *frame, size_t frame_len, uint8_t *out, size_t cap,
            size_t *out_len, int *owned)
{
    struct gy_session s;
    size_t n = cap;
    int found, matched = 0, rc;

    *owned = 0;
    rc = gy_op_load_session(&c->op, id, &s, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_VERIFY; /* dangling id: treat as no match */

    rc = gy_dr_decrypt_assoc(&s.dr, out, cap, &n, frame, frame_len, s.ad,
                             s.ad_len, &matched);
    if (!matched) {
        gy_session_free(&s);
        return GY_ERR_VERIFY; /* continue to the next candidate */
    }
    *owned = 1;
    if (rc != GY_OK) {
        gy_session_free(&s); /* header matched, payload failed: hard error */
        return GY_ERR_VERIFY;
    }

    s.nrecv++;
    if (c->clock != NULL)
        s.last_recv_at = recv_now(c);
    rc = gy_op_put_session(&c->op, &s);
    gy_session_free(&s);
    if (rc != GY_OK)
        return rc;
    if (from_inactive)
        rc = gy_device_activate_session(&c->op, user_id, user_id_len, device_id,
                                        device_id_len, id);
    if (rc == GY_OK)
        *out_len = n;
    return rc;
}

/* ---- Double Ratchet path (D-SES-6.3) ----------------------------------- */

static int
recv_dr(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
        const uint8_t *device_id, size_t device_id_len, const uint8_t *frame,
        size_t frame_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_device_record dev;
    uint8_t dk[GY_DEVKEY_LEN];
    uint32_t i;
    int found, owned, rc;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(&c->op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (!found) {
        gy_device_record_free(&dev);
        return GY_ERR_VERIFY;
    }

    /* Active session first, then inactive in list order (D-SES-6.3). */
    if (dev.has_active) {
        c->last_sessions_tried++;
        rc = try_session(c, user_id, user_id_len, device_id, device_id_len,
                         dev.active, 0, frame, frame_len, out, cap, out_len,
                         &owned);
        if (owned) {
            gy_device_record_free(&dev);
            return rc;
        }
    }
    for (i = 0; i < dev.n_inactive; i++) {
        c->last_sessions_tried++;
        rc = try_session(c, user_id, user_id_len, device_id, device_id_len,
                         dev.inactive[i], 1, frame, frame_len, out, cap,
                         out_len, &owned);
        if (owned) {
            gy_device_record_free(&dev);
            return rc;
        }
    }
    gy_device_record_free(&dev);
    return GY_ERR_VERIFY; /* nothing matched: uniform not-found */
}

/* ---- initiation path (D-SES-6.1 / D-X3DH-10) --------------------------- */

/* Parse IK_A / EK_A public keys from the carried prefix of an initial message. */
static void
parse_base_keys(const struct gy_suite_desc *desc, const uint8_t *inner,
                struct gy_public_key *ika, struct gy_public_key *ekb)
{
    size_t cpl = desc->curve_pk_len;
    size_t kw = 4 + 1 + cpl; /* pkid_be32 || curve_type || curve_pk */

    memset(ika, 0, sizeof(*ika));
    memset(ekb, 0, sizeof(*ekb));
    ika->curve_type = inner[2 + 4];
    memcpy(ika->pk, inner + 2 + 5, cpl);
    ekb->curve_type = inner[2 + kw + 4];
    memcpy(ekb->pk, inner + 2 + kw + 5, cpl);
}

static int
recv_init(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
          const uint8_t *device_id, size_t device_id_len, const uint8_t *inner,
          size_t inner_len, uint8_t *out, size_t cap, size_t *out_len)
{
    const struct gy_suite_desc *desc = c->desc;
    struct gy_public_key ika, ekb;
    struct gy_dr_secrets secrets;
    struct gy_x3dh_local local;
    struct gy_x3dh_opk_ref opk_ref;
    struct gy_device_record dev;
    struct gy_session s;
    const struct gy_keypair *matched_spk;
    uint8_t ad[GY_X3DH_AD_MAX];
    uint8_t dk[GY_DEVKEY_LEN];
    uint8_t sid[GY_SESSION_ID_LEN];
    size_t cpl = desc->curve_pk_len;
    size_t prefix_len = 2 + 2 * (4 + 1 + cpl) + 16;
    size_t adl = 0, ctlen, n = cap, i;
    int found, owned, rc;

    if (inner_len < prefix_len)
        return GY_ERR_VERIFY;
    ctlen = gy_be32_get(inner + prefix_len - 4);
    if (ctlen == 0 || inner_len < prefix_len + ctlen)
        return GY_ERR_VERIFY;

    /* SessionID from the carried base key (IK_A, EK_A). */
    parse_base_keys(desc, inner, &ika, &ekb);
    memset(&s, 0, sizeof(s));
    rc = gy_session_id(&s, desc, &ika, &ekb);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    memcpy(sid, s.id, GY_SESSION_ID_LEN);

    /* Base-key dedupe (D-SES-6.1): a known base routes to that session. */
    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(&c->op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (found) {
        int pos = session_position(&dev, sid);

        if (pos >= 0) {
            gy_device_record_free(&dev);
            rc = try_session(c, user_id, user_id_len, device_id, device_id_len,
                             sid, pos == 1, inner + prefix_len, ctlen, out, cap,
                             out_len, &owned);
            return rc; /* owns it (success) or uniform reject */
        }
    }
    gy_device_record_free(&dev);

    /* Fresh base: record the sender identity (TOFU / key-change fail-closed). */
    rc = gy_conditional_update(&c->op, desc->suite_id, user_id, user_id_len,
                               device_id, device_id_len, &ika, NULL);
    if (rc != GY_OK)
        return rc; /* GY_ERR_KEY_CHANGED surfaces; nothing staged */

    local.ik = c->local_ik;
    local.opks = c->opks;
    local.n_opks = c->n_opks;
    memset(&secrets, 0, sizeof(secrets));
    memset(&opk_ref, 0, sizeof(opk_ref));
    memset(&s, 0, sizeof(s));

    /* Try the current SPK, then retained history in turn (D-X3DH-5
     * rotation): spk_id is public wire data (carried in the clear in
     * inner), so this leaks nothing new via timing that an eavesdropper
     * cannot already see.  gy_x3dh_respond's own pkid check fails fast
     * before any DH, so a non-matching candidate costs one comparison. */
    matched_spk = NULL;
    rc = GY_ERR_VERIFY;
    for (i = 0; i < c->n_spks; i++) {
        local.spk = &c->spks[i];
        rc = gy_x3dh_respond(desc, &secrets, ad, &adl, &opk_ref, &local, inner,
                             inner_len);
        if (rc == GY_OK) {
            matched_spk = &c->spks[i];
            break;
        }
    }
    if (rc != GY_OK) {
        rc = GY_ERR_VERIFY; /* uniform: no handshake/prekey oracle */
        goto out;
    }
    rc = gy_dr_init_bob(&s.dr, desc, c->aead_id, &secrets, matched_spk);
    if (rc != GY_OK) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    memcpy(s.ad, ad, adl);
    s.ad_len = (uint8_t)adl;
    rc = gy_session_id(&s, desc, &ika, &ekb);
    if (rc != GY_OK) {
        rc = GY_ERR_VERIFY;
        goto out;
    }

    /* First frame must decrypt BEFORE anything commits (D-X3DH-10). */
    rc = gy_dr_decrypt(&s.dr, out, cap, &n, inner + prefix_len, ctlen, s.ad,
                       s.ad_len);
    if (rc != GY_OK) {
        rc = GY_ERR_VERIFY; /* OPK retained: the deferred consume never runs */
        goto out;
    }
    s.nrecv = 1;
    if (c->clock != NULL)
        s.last_recv_at = recv_now(c);

    rc = gy_op_put_session(&c->op, &s);
    if (rc != GY_OK)
        goto out;
    rc = gy_device_insert_session(&c->op, user_id, user_id_len, device_id,
                                  device_id_len, s.id);
    if (rc != GY_OK)
        goto out;
    if (opk_ref.present)
        rc = gy_op_consume_opk(&c->op, opk_ref.pkid);
    if (rc == GY_OK)
        *out_len = n;
out:
    gy_session_free(&s);
    gy_secure_zero(&secrets, sizeof(secrets));
    gy_secure_zero(ad, sizeof(ad));
    return rc;
}

/* ---- entry ------------------------------------------------------------- */

static int
recv_process(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
             const uint8_t *device_id, size_t device_id_len, const uint8_t *msg,
             size_t msg_len, uint8_t *out, size_t cap, size_t *out_len)
{
    const uint8_t *inner;
    size_t inner_len;

    if (msg_len < 3)
        return GY_ERR_VERIFY;
    if (msg[0] != GY_WIRE_VERSION || msg[1] != c->desc->suite_id)
        return GY_ERR_VERIFY;
    inner = msg + 3;
    inner_len = msg_len - 3;
    /* Inner version/suite must match the outer envelope (D-GEN-1). */
    if (inner_len < 2 || inner[0] != msg[0] || inner[1] != msg[1])
        return GY_ERR_VERIFY;

    if (msg[2] == GY_MSG_INIT)
        return recv_init(c, user_id, user_id_len, device_id, device_id_len,
                         inner, inner_len, out, cap, out_len);
    if (msg[2] == GY_MSG_DR)
        return recv_dr(c, user_id, user_id_len, device_id, device_id_len, inner,
                       inner_len, out, cap, out_len);
    return GY_ERR_VERIFY;
}

int
gy_recv(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
        const uint8_t *device_id, size_t device_id_len, const uint8_t *msg,
        size_t msg_len, uint8_t *out, size_t *out_len)
{
    int rc;

    if (c == NULL || user_id == NULL || device_id == NULL || msg == NULL ||
        out_len == NULL)
        return GY_ERR_ARG;
    if (out == NULL) {
        *out_len = msg_len; /* plaintext is always shorter than the frame */
        return GY_OK;
    }

    c->last_sessions_tried = 0;
    rc = gy_op_begin(&c->op, c->store);
    if (rc != GY_OK)
        return rc;
    rc = recv_process(c, user_id, user_id_len, device_id, device_id_len, msg,
                      msg_len, out, *out_len, out_len);
    if (rc == GY_OK)
        rc = gy_op_commit(&c->op);
    else
        gy_op_abort(&c->op);
    return rc;
}
