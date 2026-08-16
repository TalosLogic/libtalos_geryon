/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Sesame send path (section 3.3).  The fan-out is a per-session
 * loop: gy_send_prepare classifies each target device, gy_send_encrypt runs one
 * device's active-session Double Ratchet step, and gy_send_initiate starts a
 * session from a bundle and emits the D-X3DH-15 initial message (X3DH prefix
 * with the complete first DR frame after its ciphertext-length field).  Every
 * mutation stages into the context's gy_op and reaches the store only at
 * gy_send_commit (D-SES-10).
 */

#include <string.h>

#include "send.h"

/*
 * Message-size upper bounds for the OpenSSL-style sizing calls.  A DR frame is
 * version || suite || hdr_salt || enc_header_len_be16 || enc_header || payload
 * (D-DR-16); the initial message prepends the X3DH prefix (D-X3DH-15).
 */
#define GY_SEND_DR_OVERHEAD                                                    \
    (2 + GY_HE_SALT_LEN + 2 + GY_DR_ENC_HEADER_MAX + GY_AEAD_MAX_TAG)
#define GY_SEND_MSG_SIZE(ptlen) (GY_SEND_DR_OVERHEAD + (ptlen))
#define GY_SEND_INIT_SIZE(ptlen) (GY_X3DH_PREFIX_MAX + GY_SEND_MSG_SIZE(ptlen))

/* ---- context / transaction -------------------------------------------- */

int
gy_send_ctx_init(struct gy_send_ctx *c, const struct gy_store *store,
                 const struct gy_suite_desc *desc,
                 const struct gy_keypair *local_ik, uint8_t aead_id,
                 const struct gy_expiry_cfg *expiry,
                 const uint8_t *self_user_id, size_t self_user_id_len,
                 const uint8_t *self_device_id, size_t self_device_id_len)
{
    if (c == NULL || store == NULL || desc == NULL || local_ik == NULL)
        return GY_ERR_ARG;
    if (self_user_id_len > GY_USER_ID_MAX ||
        self_device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    memset(c, 0, sizeof(*c));
    c->store = store;
    c->desc = desc;
    c->local_ik = local_ik;
    c->aead_id = aead_id;
    if (expiry != NULL)
        c->expiry = *expiry;
    c->self_user_id = self_user_id;
    c->self_user_id_len = self_user_id_len;
    c->self_device_id = self_device_id;
    c->self_device_id_len = self_device_id_len;
    return GY_OK;
}

int
gy_send_begin(struct gy_send_ctx *c)
{
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    rc = gy_op_begin(&c->op, c->store);
    if (rc != GY_OK)
        return rc;
    c->begun = 1;
    return GY_OK;
}

void
gy_send_abort(struct gy_send_ctx *c)
{
    if (c != NULL) {
        gy_op_abort(&c->op);
        c->begun = 0;
    }
}

int
gy_send_commit(struct gy_send_ctx *c)
{
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    if (!c->begun)
        return GY_ERR_STATE;
    rc = gy_op_commit(&c->op);
    c->begun = 0;
    return rc;
}

/* ---- fan-out enumeration (section 3.3) --------------------------------- */

static int
is_self_device(const struct gy_send_ctx *c, const uint8_t *user_id,
               size_t user_id_len, const uint8_t *device_id,
               size_t device_id_len)
{
    /* Self is the (self UserID, self DeviceID) pair, D-SES-12: a peer sharing
     * only the DeviceID byte string is a different device, not excluded. */
    return c->self_user_id != NULL && c->self_device_id != NULL &&
           c->self_user_id_len == user_id_len &&
           c->self_device_id_len == device_id_len &&
           gy_const_memcmp(c->self_user_id, user_id, user_id_len) == 0 &&
           gy_const_memcmp(c->self_device_id, device_id, device_id_len) == 0;
}

/* Classify a single known device from its DeviceRecord + active session. */
static int
classify_device(struct gy_send_ctx *c, const uint8_t *user_id,
                size_t user_id_len, const uint8_t *device_id,
                size_t device_id_len, enum gy_send_status *status)
{
    struct gy_device_record dev;
    struct gy_session s;
    uint8_t dk[GY_DEVKEY_LEN];
    int found, rc;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(&c->op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (!found || !dev.has_active) {
        *status = GY_SEND_NEEDS_BUNDLE;
        gy_device_record_free(&dev);
        return GY_OK;
    }
    rc = gy_op_load_session(&c->op, dev.active, &s, &found);
    gy_device_record_free(&dev);
    if (rc != GY_OK)
        return rc;
    if (!found) {
        *status = GY_SEND_NEEDS_BUNDLE; /* dangling active id */
        return GY_OK;
    }
    *status =
        gy_session_expired(&c->expiry, &s) ? GY_SEND_STALE : GY_SEND_MESSAGE;
    gy_session_free(&s);
    return GY_OK;
}

int
gy_send_prepare(struct gy_send_ctx *c, const struct gy_send_target *targets,
                size_t n, struct gy_send_desc *descs, size_t *desc_count)
{
    struct gy_user_record usr;
    size_t need = 0, cap, t;
    uint32_t i;
    int found, rc;

    if (c == NULL || desc_count == NULL || (n > 0 && targets == NULL))
        return GY_ERR_ARG;
    if (!c->begun)
        return GY_ERR_STATE;
    cap = descs != NULL ? *desc_count : 0;

    for (t = 0; t < n; t++) {
        rc = gy_op_load_user(&c->op, targets[t].user_id, targets[t].user_id_len,
                             &usr, &found);
        if (rc != GY_OK)
            return rc;
        if (!found)
            continue; /* unknown user: arrives via the reject/bundle path */

        for (i = 0; i < usr.n_devices; i++) {
            const uint8_t *did = usr.device_id[i];
            size_t dl = usr.device_id_len[i];
            enum gy_send_status st;

            if (is_self_device(c, targets[t].user_id, targets[t].user_id_len,
                               did, dl))
                continue;
            rc = classify_device(c, targets[t].user_id, targets[t].user_id_len,
                                 did, dl, &st);
            if (rc != GY_OK) {
                gy_user_record_free(&usr);
                return rc;
            }
            if (descs != NULL && need < cap) {
                struct gy_send_desc *d = &descs[need];

                memset(d, 0, sizeof(*d));
                memcpy(d->user_id, targets[t].user_id, targets[t].user_id_len);
                d->user_id_len = targets[t].user_id_len;
                memcpy(d->device_id, did, dl);
                d->device_id_len = dl;
                d->status = st;
            }
            need++;
        }
        gy_user_record_free(&usr);
    }

    *desc_count = need;
    if (descs != NULL && need > cap)
        return GY_ERR_ARG; /* buffer too small; needed count reported */
    return GY_OK;
}

/* ---- per-session encrypt (section 3.3) --------------------------------- */

int
gy_send_encrypt(struct gy_send_ctx *c, const uint8_t *user_id,
                size_t user_id_len, const uint8_t *device_id,
                size_t device_id_len, const uint8_t *pt, size_t ptlen,
                uint8_t *out, size_t *out_len)
{
    struct gy_device_record dev;
    struct gy_session s;
    uint8_t dk[GY_DEVKEY_LEN];
    int found, rc;

    if (c == NULL || device_id == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (out == NULL) {
        *out_len = GY_SEND_MSG_SIZE(ptlen);
        return GY_OK;
    }
    if (!c->begun)
        return GY_ERR_STATE;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(&c->op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (!found || !dev.has_active) {
        gy_device_record_free(&dev);
        return GY_ERR_STATE;
    }
    rc = gy_op_load_session(&c->op, dev.active, &s, &found);
    gy_device_record_free(&dev);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_STATE;

    if (gy_session_expired(&c->expiry, &s)) {
        gy_session_free(&s);
        return GY_ERR_EXPIRED; /* never send under a stale device (D-SES-7) */
    }

    rc =
        gy_dr_encrypt(&s.dr, out, *out_len, out_len, pt, ptlen, s.ad, s.ad_len);
    if (rc != GY_OK)
        goto out;
    s.nsend++;
    rc = gy_op_put_session(&c->op, &s);
out:
    gy_session_free(&s);
    return rc;
}

/* ---- initiation (section 3.3 / D-X3DH-15) ------------------------------ */

static int
send_initiate_core(struct gy_send_ctx *c, const uint8_t *user_id,
                   size_t user_id_len, const uint8_t *device_id,
                   size_t device_id_len, const struct gy_prekey_bundle *bundle,
                   const uint8_t *pt, size_t ptlen, struct gy_key_change *chg,
                   uint8_t *out, size_t *out_len)
{
    const struct gy_suite_desc *desc;
    struct gy_dr_secrets secrets;
    struct gy_keypair ek;
    struct gy_session s;
    uint8_t prefix[GY_X3DH_PREFIX_MAX];
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t prefix_len = 0, ad_len = 0, frame_len = 0, cap;
    int rc;

    if (c == NULL || device_id == NULL || bundle == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (out == NULL) {
        *out_len = GY_SEND_INIT_SIZE(ptlen);
        return GY_OK;
    }
    if (!c->begun)
        return GY_ERR_STATE;
    desc = c->desc;

    /* Create-or-update the peer records first; fail closed on a key change. */
    rc = gy_conditional_update(&c->op, desc->suite_id, user_id, user_id_len,
                               device_id, device_id_len, &bundle->ik, chg);
    if (rc != GY_OK)
        return rc; /* includes GY_ERR_KEY_CHANGED (nothing staged) */

    memset(&secrets, 0, sizeof(secrets));
    memset(&ek, 0, sizeof(ek));
    memset(&s, 0, sizeof(s));

    rc = gy_keypair_generate(desc, &ek);
    if (rc != GY_OK)
        goto out;
    rc = gy_x3dh_initiate(desc, &secrets, ad, &ad_len, prefix, &prefix_len,
                          c->local_ik, bundle, &ek);
    if (rc != GY_OK)
        goto out;
    rc = gy_dr_init_alice(&s.dr, desc, c->aead_id, &secrets, bundle->spk.pk);
    if (rc != GY_OK)
        goto out;
    memcpy(s.ad, ad, ad_len);
    s.ad_len = (uint8_t)ad_len;
    rc = gy_session_id(&s, desc, &c->local_ik->pub, &ek.pub);
    if (rc != GY_OK)
        goto out;

    /* Message = X3DH prefix then the complete first DR frame; the prefix ends
     * in a zero ciphertext_len placeholder we overwrite with the frame len. */
    cap = *out_len;
    if (prefix_len < 4 || prefix_len > cap) {
        rc = GY_ERR_ARG;
        goto out;
    }
    memcpy(out, prefix, prefix_len);
    rc = gy_dr_encrypt(&s.dr, out + prefix_len, cap - prefix_len, &frame_len,
                       pt, ptlen, s.ad, s.ad_len);
    if (rc != GY_OK)
        goto out;
    gy_be32_put(out + prefix_len - 4, (uint32_t)frame_len);
    *out_len = prefix_len + frame_len;
    s.nsend++;

    /* Stage the session, then insert its id as the device's active session
     * (read-your-writes lets the insert see the just-staged DeviceRecord). */
    rc = gy_op_put_session(&c->op, &s);
    if (rc != GY_OK)
        goto out;
    rc = gy_device_insert_session(&c->op, user_id, user_id_len, device_id,
                                  device_id_len, s.id);
out:
    gy_session_free(&s);
    gy_secure_zero(&secrets, sizeof(secrets));
    gy_secure_zero(&ek, sizeof(ek));
    gy_secure_zero(prefix, sizeof(prefix));
    gy_secure_zero(ad, sizeof(ad));
    return rc;
}

int
gy_send_initiate(struct gy_send_ctx *c, const uint8_t *user_id,
                 size_t user_id_len, const uint8_t *device_id,
                 size_t device_id_len, const struct gy_prekey_bundle *bundle,
                 const uint8_t *pt, size_t ptlen, struct gy_key_change *chg,
                 uint8_t *out, size_t *out_len)
{
    return send_initiate_core(c, user_id, user_id_len, device_id, device_id_len,
                              bundle, pt, ptlen, chg, out, out_len);
}

int
gy_session_reinitiate(struct gy_send_ctx *c, const uint8_t *user_id,
                      size_t user_id_len, const uint8_t *device_id,
                      size_t device_id_len,
                      const struct gy_prekey_bundle *bundle, const uint8_t *pt,
                      size_t ptlen, struct gy_key_change *chg, uint8_t *out,
                      size_t *out_len)
{
    /* Insert semantics already demote any existing active session, so a fresh
     * initiation IS the orphan escape (D-SES-8). */
    return send_initiate_core(c, user_id, user_id_len, device_id, device_id_len,
                              bundle, pt, ptlen, chg, out, out_len);
}
