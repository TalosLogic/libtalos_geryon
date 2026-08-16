/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Public API (re-hosted on gy_custodian): the
 * include/geryon.h protocol operations, implemented as thin glue over the
 * session/ contexts and the proto/ wire helpers.  The custodian lifecycle
 * (create/open/close/reset/change_credential/generate_identity) and the
 * gy_custodian struct itself live in custodian.c/.h; this file is everything
 * that operates on an already-unlocked custodian.  References only session/
 * and proto/ symbols (the facade re-exports the few kex/core primitives it
 * needs), keeping proto/ clear of ratchet/ and core/ per the layer audit.
 */

#include <string.h>

#include "geryon.h"

#include "custodian.h"
#include "envelope.h"

/*
 * The public fan-out types are laid out identically to the internal ones, so
 * gy_prepare bridges by pointer without copying an unbounded array.  These
 * assertions fail the build if the layouts ever drift apart.
 */
_Static_assert(sizeof(gy_target) == sizeof(struct gy_send_target),
               "gy_target must match gy_send_target");
_Static_assert(sizeof(gy_fanout_desc) == sizeof(struct gy_send_desc),
               "gy_fanout_desc must match gy_send_desc");

int
gy_publish_bundle(gy_custodian *c, uint8_t *out, size_t *out_len)
{
    return gy_custodian_publish_bundle(c, out, out_len);
}

int
gy_self_fingerprint(gy_custodian *c, uint8_t *out, size_t *out_len)
{
    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (out == NULL) {
        *out_len = c->desc->hash_len;
        return GY_OK;
    }
    if (*out_len < c->desc->hash_len)
        return GY_ERR_ARG;
    *out_len = c->desc->hash_len;
    return gy_proto_fingerprint(c->desc, out, &c->ik.pub);
}

/* ---- send -------------------------------------------------------------- */

int
gy_send_open(gy_custodian *c)
{
    if (c == NULL)
        return GY_ERR_ARG;
    if (!c->have_identity)
        return GY_ERR_STATE;
    if (c->send_open)
        return GY_ERR_STATE;
    {
        int rc = gy_send_begin(&c->send);
        if (rc != GY_OK)
            return rc;
    }
    c->send_open = 1;
    return GY_OK;
}

int
gy_prepare(gy_custodian *c, const gy_target *targets, size_t n,
           gy_fanout_desc *descs, size_t *desc_count)
{
    if (c == NULL)
        return GY_ERR_ARG;
    return gy_send_prepare(&c->send, (const struct gy_send_target *)targets, n,
                           (struct gy_send_desc *)descs, desc_count);
}

/* Set the 3-byte envelope header over an inner message already at out + 3. */
static void
frame_envelope(gy_custodian *c, uint8_t *out, uint8_t msg_type)
{
    out[0] = GY_PROTOCOL_VERSION;
    out[1] = c->desc->suite_id;
    out[2] = msg_type;
}

int
gy_encrypt(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
           const uint8_t *device_id, size_t device_id_len, const uint8_t *pt,
           size_t ptlen, uint8_t *out, size_t *out_len)
{
    size_t inner;
    int rc;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (out == NULL) {
        rc = gy_send_encrypt(&c->send, user_id, user_id_len, device_id,
                             device_id_len, pt, ptlen, NULL, &inner);
        if (rc == GY_OK)
            *out_len = inner + GY_ENVELOPE_HDR_LEN;
        return rc;
    }
    if (*out_len < GY_ENVELOPE_HDR_LEN)
        return GY_ERR_ARG;
    inner = *out_len - GY_ENVELOPE_HDR_LEN;
    rc = gy_send_encrypt(&c->send, user_id, user_id_len, device_id,
                         device_id_len, pt, ptlen, out + GY_ENVELOPE_HDR_LEN,
                         &inner);
    if (rc != GY_OK)
        return rc;
    frame_envelope(c, out, GY_MSG_DR);
    *out_len = inner + GY_ENVELOPE_HDR_LEN;
    return GY_OK;
}

/* Shared body for gy_initiate / gy_reinitiate. */
static int
api_initiate(gy_custodian *c, int reinit, const uint8_t *user_id,
             size_t user_id_len, const uint8_t *device_id, size_t device_id_len,
             const uint8_t *bundle, size_t bundle_len, const uint8_t *pt,
             size_t ptlen, gy_keychange *chg, uint8_t *out, size_t *out_len)
{
    struct gy_prekey_bundle b;
    struct gy_key_change ic;
    size_t inner;
    uint8_t *dst;
    int rc;

    if (c == NULL || out_len == NULL)
        return GY_ERR_ARG;
    memset(&b, 0, sizeof(b)); /* size query passes &b unread; keep it defined */

    if (out == NULL) {
        /* Size query: inner size plus the envelope header. */
        if (reinit)
            rc = gy_session_reinitiate(&c->send, user_id, user_id_len,
                                       device_id, device_id_len, &b, pt, ptlen,
                                       NULL, NULL, &inner);
        else
            rc = gy_send_initiate(&c->send, user_id, user_id_len, device_id,
                                  device_id_len, &b, pt, ptlen, NULL, NULL,
                                  &inner);
        if (rc == GY_OK)
            *out_len = inner + GY_ENVELOPE_HDR_LEN;
        return rc;
    }

    memset(&b, 0, sizeof(b));
    rc = gy_bundle_parse(&b, c->desc, bundle, bundle_len);
    if (rc != GY_OK)
        return rc;
    if (*out_len < GY_ENVELOPE_HDR_LEN)
        return GY_ERR_ARG;
    inner = *out_len - GY_ENVELOPE_HDR_LEN;
    dst = out + GY_ENVELOPE_HDR_LEN;
    memset(&ic, 0, sizeof(ic));
    if (reinit)
        rc = gy_session_reinitiate(&c->send, user_id, user_id_len, device_id,
                                   device_id_len, &b, pt, ptlen,
                                   chg != NULL ? &ic : NULL, dst, &inner);
    else
        rc = gy_send_initiate(&c->send, user_id, user_id_len, device_id,
                              device_id_len, &b, pt, ptlen,
                              chg != NULL ? &ic : NULL, dst, &inner);
    if (chg != NULL && rc == GY_ERR_KEY_CHANGED) {
        chg->fp_len = ic.fp_len;
        memcpy(chg->old_fp, ic.old_fp, ic.fp_len);
        memcpy(chg->new_fp, ic.new_fp, ic.fp_len);
    }
    if (rc != GY_OK)
        return rc;
    frame_envelope(c, out, GY_MSG_INIT);
    *out_len = inner + GY_ENVELOPE_HDR_LEN;
    return rc;
}

int
gy_initiate(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
            const uint8_t *device_id, size_t device_id_len,
            const uint8_t *bundle, size_t bundle_len, const uint8_t *pt,
            size_t ptlen, gy_keychange *chg, uint8_t *out, size_t *out_len)
{
    return api_initiate(c, 0, user_id, user_id_len, device_id, device_id_len,
                        bundle, bundle_len, pt, ptlen, chg, out, out_len);
}

int
gy_reinitiate(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
              const uint8_t *device_id, size_t device_id_len,
              const uint8_t *bundle, size_t bundle_len, const uint8_t *pt,
              size_t ptlen, gy_keychange *chg, uint8_t *out, size_t *out_len)
{
    return api_initiate(c, 1, user_id, user_id_len, device_id, device_id_len,
                        bundle, bundle_len, pt, ptlen, chg, out, out_len);
}

int
gy_commit(gy_custodian *c)
{
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    if (!c->send_open)
        return GY_ERR_STATE;
    rc = gy_send_commit(&c->send);
    c->send_open = 0;
    return rc;
}

void
gy_rollback(gy_custodian *c)
{
    if (c != NULL && c->send_open) {
        gy_send_abort(&c->send);
        c->send_open = 0;
    }
}

/* ---- receive ----------------------------------------------------------- */

int
gy_receive(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
           const uint8_t *device_id, size_t device_id_len, const uint8_t *msg,
           size_t msg_len, uint8_t *out, size_t *out_len)
{
    if (c == NULL)
        return GY_ERR_ARG;
    if (out != NULL && !c->have_identity)
        return GY_ERR_STATE;
    return gy_recv(&c->recv, user_id, user_id_len, device_id, device_id_len,
                   msg, msg_len, out, out_len);
}

/* ---- lifecycle management (peer records) -------------------------------- */

int
gy_accept_identity(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
                   const uint8_t *device_id, size_t device_id_len,
                   const uint8_t *bundle, size_t bundle_len)
{
    struct gy_prekey_bundle b;
    int rc;

    if (c == NULL || device_id == NULL || user_id == NULL)
        return GY_ERR_ARG;
    rc = gy_bundle_parse(&b, c->desc, bundle, bundle_len);
    if (rc != GY_OK)
        return rc;

    rc = gy_op_begin(&c->recv.op, &c->store);
    if (rc != GY_OK)
        return rc;
    rc = gy_accept_key_change(&c->recv.op, c->desc->suite_id, user_id,
                              user_id_len, device_id, device_id_len, &b.ik);
    if (rc == GY_OK)
        rc = gy_op_commit(&c->recv.op);
    else
        gy_op_abort(&c->recv.op);
    return rc;
}

int
gy_purge_device(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
                const uint8_t *device_id, size_t device_id_len)
{
    int rc;

    if (c == NULL)
        return GY_ERR_ARG;
    rc = gy_op_begin(&c->recv.op, &c->store);
    if (rc != GY_OK)
        return rc;
    rc = gy_delete_device(&c->recv.op, user_id, user_id_len, device_id,
                          device_id_len);
    if (rc == GY_OK)
        rc = gy_op_commit(&c->recv.op);
    else
        gy_op_abort(&c->recv.op);
    return rc;
}

int
gy_purge_user(gy_custodian *c, const uint8_t *user_id, size_t user_id_len)
{
    if (c == NULL)
        return GY_ERR_ARG;
    /* gy_delete_user drives its own per-device commits (D-SES-2). */
    return gy_delete_user(&c->store, &c->recv.op, user_id, user_id_len);
}

int
gy_pq_pending(gy_custodian *c, const uint8_t *user_id, size_t user_id_len,
              const uint8_t *device_id, size_t device_id_len)
{
    (void)user_id;
    (void)user_id_len;
    (void)device_id;
    (void)device_id_len;
    if (c == NULL)
        return GY_ERR_ARG;
    /* Classical suites carry no PQ state; the state is reserved so a future
     * suite can report it here additively. */
    return c->desc->is_hybrid ? GY_PQ_PENDING : GY_PQ_NOT_APPLICABLE;
}
