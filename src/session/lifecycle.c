/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Sesame lifecycle state machine (D-SES-2/5/7/9): identity-key
 * conditional update with fail-closed key-change handling (D-X3DH-11), session
 * insert/activate through the staging engine, session expiration mechanics
 * (D-SES-7), and device/user deletion for compromise recovery (D-SES-2).  Every
 * mutating path stages through a gy_op and leaves the commit to the caller
 * (gy_delete_user excepted, see its comment).
 */

#include <string.h>

#include "lifecycle.h"

/* ---- expiration (D-SES-7) ---------------------------------------------- */

int
gy_expiry_cfg_init(struct gy_expiry_cfg *cfg, uint32_t max_send,
                   uint32_t max_recv, uint64_t max_latency)
{
    if (cfg == NULL)
        return GY_ERR_ARG;
    gy_secure_zero(cfg, sizeof(*cfg));
    if (max_send == 0 || max_recv == 0)
        return GY_ERR_ARG;
    /* Section 4.2 inequality, in 64-bit to avoid overflow (D-SES-7). */
    if ((uint64_t)max_recv <= (uint64_t)max_send + 2 * max_latency)
        return GY_ERR_ARG;
    cfg->enabled = 1;
    cfg->max_send = max_send;
    cfg->max_recv = max_recv;
    cfg->max_latency = max_latency;
    return GY_OK;
}

void
gy_expiry_cfg_disable(struct gy_expiry_cfg *cfg)
{
    if (cfg != NULL)
        gy_secure_zero(cfg, sizeof(*cfg));
}

int
gy_session_expired(const struct gy_expiry_cfg *cfg, const struct gy_session *s)
{
    if (cfg == NULL || s == NULL || !cfg->enabled)
        return 0;
    if (s->nsend >= cfg->max_send)
        return 1;
    if (s->nrecv >= cfg->max_recv)
        return 1;
    return 0;
}

int
gy_session_stale(const struct gy_expiry_cfg *cfg, const struct gy_session *s,
                 uint64_t now)
{
    if (cfg == NULL || s == NULL || !cfg->enabled || s->last_recv_at == 0)
        return 0;
    if (now <= s->last_recv_at)
        return 0; /* clock rollback: not (yet) stale */
    return now - s->last_recv_at > cfg->max_latency;
}

int
gy_identity_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                        const struct gy_public_key *ik)
{
    if (desc == NULL || out == NULL || ik == NULL)
        return GY_ERR_ARG;
    return gy_fingerprint(desc, out, ik);
}

int
gy_hybrid_identity_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                               const struct gy_hybrid_identity_public_key *ik)
{
    if (desc == NULL || out == NULL || ik == NULL)
        return GY_ERR_ARG;
    return gy_hybrid_ikhash(desc, ik, out);
}

/* ---- identity-key comparison ------------------------------------------- */

/*
 * True if two identity public keys are the same key.  Compares the curve type
 * and curve_pk_len key bytes (const-time), the fields that EncodeEC and the
 * fingerprint cover; the PKID is a local handle and not part of identity.
 */
static int
ik_equal(const struct gy_suite_desc *desc, const struct gy_public_key *a,
         const struct gy_public_key *b)
{
    if (a->curve_type != b->curve_type)
        return 0;
    return gy_const_memcmp(a->pk, b->pk, desc->curve_pk_len) == 0;
}

/* ---- deferred full-device deletion (no UserRecord touch) --------------- */

static int
defer_delete_device_inner(struct gy_op *op, const uint8_t *user_id,
                          size_t user_id_len, const uint8_t *device_id,
                          size_t device_id_len)
{
    struct gy_hybrid_device_record dev;
    uint8_t dk[GY_DEVKEY_LEN];
    uint32_t i;
    int found, rc;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device_any(op, dk, GY_DEVKEY_LEN, &dev, NULL, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_OK; /* nothing to delete (idempotent) */

    if (dev.base.has_active) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.base.active,
                          GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }
    for (i = 0; i < dev.base.n_inactive; i++) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.base.inactive[i],
                          GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }
    rc = gy_op_delete(op, GY_REC_DEVICE, dk, GY_DEVKEY_LEN);
out:
    gy_hybrid_device_record_free(&dev);
    return rc;
}

/* ---- conditional update (section 3.2, D-SES-9) ------------------------- */

int
gy_conditional_update(struct gy_op *op, uint8_t suite_id,
                      const uint8_t *user_id, size_t user_id_len,
                      const uint8_t *device_id, size_t device_id_len,
                      const struct gy_public_key *ik, struct gy_key_change *chg)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    struct gy_device_record dev;
    struct gy_user_record usr;
    uint8_t fp[GY_HASH_MAX];
    uint8_t dk[GY_DEVKEY_LEN];
    int found, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || ik == NULL ||
        desc == NULL)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;
    if (ik->curve_type != desc->curve_type)
        return GY_ERR_STATE; /* cross-suite key (downgrade signal) */

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;

    if (found) {
        if (dev.suite_id != suite_id) {
            gy_device_record_free(&dev);
            return GY_ERR_STATE;
        }
        if (!ik_equal(desc, &dev.ik, ik)) {
            /* Fail closed: surface the change, stage nothing (D-SES-9). */
            if (chg != NULL) {
                chg->fp_len = desc->hash_len;
                memcpy(chg->old_fp, dev.fingerprint, desc->hash_len);
                rc = gy_fingerprint(desc, chg->new_fp, ik);
            }
            gy_device_record_free(&dev);
            return rc == GY_OK ? GY_ERR_KEY_CHANGED : rc;
        }
        /* Known device, same key: records re-staged unchanged. */
    } else {
        rc = gy_fingerprint(desc, fp, ik);
        if (rc != GY_OK)
            return rc;
        rc = gy_device_record_init(&dev, suite_id, device_id, device_id_len, ik,
                                   fp, desc->hash_len);
        if (rc != GY_OK)
            return rc;
    }

    rc = gy_op_load_user(op, user_id, user_id_len, &usr, &found);
    if (rc != GY_OK)
        goto out;
    if (!found) {
        rc = gy_user_record_init(&usr, suite_id, user_id, user_id_len);
        if (rc != GY_OK)
            goto out;
    }

    if (gy_user_device_index(&usr, device_id, device_id_len) < 0) {
        uint8_t ev[GY_DEVICE_ID_MAX];
        size_t ev_len = 0;
        int did_evict = 0;

        rc = gy_user_device_insert(&usr, device_id, device_id_len, ev, &ev_len,
                                   &did_evict);
        if (rc != GY_OK)
            goto out;
        if (did_evict) {
            rc =
                defer_delete_device_inner(op, user_id, user_id_len, ev, ev_len);
            if (rc != GY_OK)
                goto out;
        }
    }

    rc = gy_op_put_device(op, &dev, dk, GY_DEVKEY_LEN);
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_user(op, &usr);
out:
    gy_secure_zero(fp, sizeof(fp));
    gy_device_record_free(&dev);
    gy_user_record_free(&usr);
    return rc;
}

/* Full hybrid identity equality: curve + ML-KEM ek + ML-DSA pk (section 4.2). */
static int
hybrid_ik_equal(const struct gy_suite_desc *desc,
                const struct gy_hybrid_device_record *dev,
                const struct gy_hybrid_identity_public_key *ik)
{
    if (dev->base.ik.curve_type != ik->base.curve.curve_type)
        return 0;
    if (gy_const_memcmp(dev->base.ik.pk, ik->base.curve.pk,
                        desc->curve_pk_len) != 0)
        return 0;
    if (gy_const_memcmp(dev->mlkem_ek, ik->base.mlkem_ek, desc->kem_pk_len) !=
        0)
        return 0;
    return gy_const_memcmp(dev->mldsa_pk, ik->mldsa_pk, desc->dsa_pk_len) == 0;
}

int
gy_hybrid_conditional_update(struct gy_op *op, uint8_t suite_id,
                             const uint8_t *user_id, size_t user_id_len,
                             const uint8_t *device_id, size_t device_id_len,
                             const struct gy_hybrid_identity_public_key *ik,
                             struct gy_key_change *chg)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    struct gy_hybrid_device_record dev;
    struct gy_user_record usr;
    uint8_t fp[GY_HASH_MAX];
    uint8_t dk[GY_DEVKEY_LEN];
    int found, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || ik == NULL ||
        desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;
    if (ik->base.curve.curve_type != desc->curve_type)
        return GY_ERR_STATE; /* cross-suite key (downgrade signal) */

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_hybrid_device(op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;

    if (found) {
        if (dev.base.suite_id != suite_id) {
            gy_hybrid_device_record_free(&dev);
            return GY_ERR_STATE;
        }
        if (!hybrid_ik_equal(desc, &dev, ik)) {
            /* Fail closed on ANY identity component change (curve or PQ). */
            if (chg != NULL) {
                chg->fp_len = desc->hash_len;
                memcpy(chg->old_fp, dev.base.fingerprint, desc->hash_len);
                rc = gy_hybrid_ikhash(desc, ik, chg->new_fp);
            }
            gy_hybrid_device_record_free(&dev);
            return rc == GY_OK ? GY_ERR_KEY_CHANGED : rc;
        }
        /* Known device, same full identity: records re-staged unchanged. */
    } else {
        rc = gy_hybrid_ikhash(desc, ik, fp);
        if (rc != GY_OK)
            return rc;
        rc = gy_hybrid_device_record_init(
            &dev, suite_id, device_id, device_id_len, ik, fp, desc->hash_len);
        if (rc != GY_OK)
            return rc;
    }

    rc = gy_op_load_user(op, user_id, user_id_len, &usr, &found);
    if (rc != GY_OK)
        goto out;
    if (!found) {
        rc = gy_user_record_init(&usr, suite_id, user_id, user_id_len);
        if (rc != GY_OK)
            goto out;
    }

    if (gy_user_device_index(&usr, device_id, device_id_len) < 0) {
        uint8_t ev[GY_DEVICE_ID_MAX];
        size_t ev_len = 0;
        int did_evict = 0;

        rc = gy_user_device_insert(&usr, device_id, device_id_len, ev, &ev_len,
                                   &did_evict);
        if (rc != GY_OK)
            goto out;
        if (did_evict) {
            rc =
                defer_delete_device_inner(op, user_id, user_id_len, ev, ev_len);
            if (rc != GY_OK)
                goto out;
        }
    }

    rc = gy_op_put_hybrid_device(op, &dev, dk, GY_DEVKEY_LEN);
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_user(op, &usr);
out:
    gy_secure_zero(fp, sizeof(fp));
    gy_hybrid_device_record_free(&dev);
    gy_user_record_free(&usr);
    return rc;
}

int
gy_accept_key_change(struct gy_op *op, uint8_t suite_id, const uint8_t *user_id,
                     size_t user_id_len, const uint8_t *device_id,
                     size_t device_id_len, const struct gy_public_key *ik)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    struct gy_device_record dev, ndev;
    uint8_t fp[GY_HASH_MAX];
    uint8_t dk[GY_DEVKEY_LEN];
    uint32_t i;
    int found, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || ik == NULL ||
        desc == NULL)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;
    if (ik->curve_type != desc->curve_type)
        return GY_ERR_STATE;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device(op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_STATE;
    if (dev.suite_id != suite_id) {
        rc = GY_ERR_STATE;
        goto out;
    }

    /* Section 3.2 replacement: delete every session of the old key. */
    if (dev.has_active) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.active, GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }
    for (i = 0; i < dev.n_inactive; i++) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.inactive[i],
                          GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }

    rc = gy_fingerprint(desc, fp, ik);
    if (rc != GY_OK)
        goto out;
    rc = gy_device_record_init(&ndev, suite_id, device_id, device_id_len, ik,
                               fp, desc->hash_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_device(op, &ndev, dk, GY_DEVKEY_LEN);
    gy_device_record_free(&ndev);
out:
    gy_secure_zero(fp, sizeof(fp));
    gy_device_record_free(&dev);
    return rc;
}

int
gy_hybrid_accept_key_change(struct gy_op *op, uint8_t suite_id,
                            const uint8_t *user_id, size_t user_id_len,
                            const uint8_t *device_id, size_t device_id_len,
                            const struct gy_hybrid_identity_public_key *ik)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    struct gy_hybrid_device_record dev, ndev;
    uint8_t fp[GY_HASH_MAX];
    uint8_t dk[GY_DEVKEY_LEN];
    uint32_t i;
    int found, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || ik == NULL ||
        desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;
    if (ik->base.curve.curve_type != desc->curve_type)
        return GY_ERR_STATE;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_hybrid_device(op, dk, GY_DEVKEY_LEN, &dev, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_STATE;
    if (dev.base.suite_id != suite_id) {
        rc = GY_ERR_STATE;
        goto out;
    }

    /* Section 3.2 replacement: delete every session of the old identity. */
    if (dev.base.has_active) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.base.active,
                          GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }
    for (i = 0; i < dev.base.n_inactive; i++) {
        rc = gy_op_delete(op, GY_REC_SESSION, dev.base.inactive[i],
                          GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }

    rc = gy_hybrid_ikhash(desc, ik, fp);
    if (rc != GY_OK)
        goto out;
    rc = gy_hybrid_device_record_init(&ndev, suite_id, device_id, device_id_len,
                                      ik, fp, desc->hash_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_hybrid_device(op, &ndev, dk, GY_DEVKEY_LEN);
    gy_hybrid_device_record_free(&ndev);
out:
    gy_secure_zero(fp, sizeof(fp));
    gy_hybrid_device_record_free(&dev);
    return rc;
}

/* ---- session insert / activate through the engine (D-SES-5) ------------ */

int
gy_device_insert_session(struct gy_op *op, const uint8_t *user_id,
                         size_t user_id_len, const uint8_t *device_id,
                         size_t device_id_len,
                         const uint8_t id[GY_SESSION_ID_LEN])
{
    struct gy_hybrid_device_record dev;
    uint8_t dk[GY_DEVKEY_LEN];
    uint8_t evicted[GY_SESSION_ID_LEN];
    int found, is_hyb = 0, did_evict = 0, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || id == NULL)
        return GY_ERR_ARG;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device_any(op, dk, GY_DEVKEY_LEN, &dev, &is_hyb, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_STATE;

    rc = gy_device_session_insert(&dev.base, id, evicted, &did_evict);
    if (rc != GY_OK)
        goto out;
    if (did_evict) {
        rc = gy_op_delete(op, GY_REC_SESSION, evicted, GY_SESSION_ID_LEN);
        if (rc != GY_OK)
            goto out;
    }
    rc = gy_op_put_device_any(op, &dev, is_hyb, dk, GY_DEVKEY_LEN);
out:
    gy_hybrid_device_record_free(&dev);
    return rc;
}

int
gy_device_activate_session(struct gy_op *op, const uint8_t *user_id,
                           size_t user_id_len, const uint8_t *device_id,
                           size_t device_id_len,
                           const uint8_t id[GY_SESSION_ID_LEN])
{
    struct gy_hybrid_device_record dev;
    uint8_t dk[GY_DEVKEY_LEN];
    int found, is_hyb = 0, rc;

    if (op == NULL || user_id == NULL || device_id == NULL || id == NULL)
        return GY_ERR_ARG;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device_any(op, dk, GY_DEVKEY_LEN, &dev, &is_hyb, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_ERR_STATE;

    rc = gy_device_session_activate(&dev.base, id);
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_device_any(op, &dev, is_hyb, dk, GY_DEVKEY_LEN);
out:
    gy_hybrid_device_record_free(&dev);
    return rc;
}

/* ---- PQ-authentication state query (HYBRID_SPEC section 8.4) ------------ */

int
gy_device_pq_state(struct gy_op *op, const uint8_t *user_id, size_t user_id_len,
                   const uint8_t *device_id, size_t device_id_len,
                   int *confirmed, int *found)
{
    struct gy_hybrid_device_record dev;
    struct gy_session s;
    uint8_t dk[GY_DEVKEY_LEN];
    int have, sfound, rc;

    if (op == NULL || user_id == NULL || device_id == NULL ||
        confirmed == NULL || found == NULL)
        return GY_ERR_ARG;
    *found = 0;

    rc = gy_devrec_key(user_id, user_id_len, device_id, device_id_len, dk);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_device_any(op, dk, GY_DEVKEY_LEN, &dev, NULL, &have);
    if (rc != GY_OK)
        return rc;
    if (!have || !dev.base.has_active) {
        gy_hybrid_device_record_free(&dev);
        return GY_OK;
    }

    rc = gy_op_load_session(op, dev.base.active, &s, &sfound);
    gy_hybrid_device_record_free(&dev);
    if (rc != GY_OK)
        return rc;
    if (!sfound)
        return GY_OK;

    *confirmed = (s.pq_pending == GY_HYBRID_PQ_CONFIRMED);
    *found = 1;
    gy_session_free(&s);
    return GY_OK;
}

/* ---- device / user deletion (compromise recovery, D-SES-2) ------------- */

int
gy_delete_device(struct gy_op *op, const uint8_t *user_id, size_t user_id_len,
                 const uint8_t *device_id, size_t device_id_len)
{
    struct gy_user_record usr;
    int found, rc;

    if (op == NULL || user_id == NULL || device_id == NULL)
        return GY_ERR_ARG;
    if (device_id_len == 0 || device_id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;

    rc = defer_delete_device_inner(op, user_id, user_id_len, device_id,
                                   device_id_len);
    if (rc != GY_OK)
        return rc;

    rc = gy_op_load_user(op, user_id, user_id_len, &usr, &found);
    if (rc != GY_OK)
        return rc;
    if (!found)
        return GY_OK; /* no index to update */

    rc = gy_user_device_remove(&usr, device_id, device_id_len);
    if (rc == GY_ERR_STATE) {
        rc = GY_OK; /* device not in index: leave the record untouched */
        goto out;
    }
    if (rc != GY_OK)
        goto out;
    rc = gy_op_put_user(op, &usr);
out:
    gy_user_record_free(&usr);
    return rc;
}

int
gy_delete_user(const struct gy_store *store, struct gy_op *op,
               const uint8_t *user_id, size_t user_id_len)
{
    uint8_t ids[GY_DEVICE_MAX][GY_DEVICE_ID_MAX];
    uint8_t lens[GY_DEVICE_MAX];
    struct gy_user_record usr;
    uint32_t n, i;
    int found, rc;

    if (store == NULL || op == NULL || user_id == NULL)
        return GY_ERR_ARG;
    if (user_id_len == 0 || user_id_len > GY_USER_ID_MAX)
        return GY_ERR_ARG;

    /* Snapshot the device index under one read transaction. */
    rc = gy_op_begin(op, store);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_load_user(op, user_id, user_id_len, &usr, &found);
    if (rc != GY_OK) {
        gy_op_abort(op);
        return rc;
    }
    if (!found) {
        gy_op_abort(op);
        return GY_OK;
    }
    n = usr.n_devices;
    for (i = 0; i < n; i++) {
        memcpy(ids[i], usr.device_id[i], GY_DEVICE_ID_MAX);
        lens[i] = usr.device_id_len[i];
    }
    gy_user_record_free(&usr);
    gy_op_abort(op);

    /* One transaction per device (a full device fits; a full user does not). */
    for (i = 0; i < n; i++) {
        rc = gy_op_begin(op, store);
        if (rc != GY_OK)
            return rc;
        rc = defer_delete_device_inner(op, user_id, user_id_len, ids[i],
                                       lens[i]);
        if (rc != GY_OK) {
            gy_op_abort(op);
            gy_secure_zero(ids, sizeof(ids));
            return rc;
        }
        rc = gy_op_commit(op); /* aborts internally on failure */
        if (rc != GY_OK) {
            gy_secure_zero(ids, sizeof(ids));
            return rc;
        }
    }
    gy_secure_zero(ids, sizeof(ids));

    /* Finally drop the UserRecord itself. */
    rc = gy_op_begin(op, store);
    if (rc != GY_OK)
        return rc;
    rc = gy_op_delete(op, GY_REC_USER, user_id, user_id_len);
    if (rc != GY_OK) {
        gy_op_abort(op);
        return rc;
    }
    return gy_op_commit(op);
}
