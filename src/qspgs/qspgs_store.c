/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * QSPGS store-integrated wrappers (QSPGS_SPEC.md section 9, D-QGS-8).  The
 * *_stored trio over gy_qspgs_store, the quantum-safe analogue of
 * gy_group_create_stored et al. (D-GRP-7).  Only the at-rest secrets (muk,
 * skbase || vkbase, gk) plus the attested acquaintance records (ep || vkbase ||
 * acq, keyed by a granter UID) are ever written; every derived secret is
 * rederived on load and skpsdn / the sk_r blob never touch storage (section
 * 2.2).  Each record is ver(1) || format_version(2, BE) || payload, so a
 * corrupted or version-flipped blob is rejected on load rather than fed to a
 * key schedule.  This translation unit is CLIENT (geryon_qspgs): it handles
 * secret key material, so it never links into the sk-free server facade.
 */

#include "qspgs_store.h"

#include <string.h>

#include "error.h"
#include "qspgs_field.h" /* GY_QSPGS_JOINLINK_SECRET */
#include "qspgs_keys.h" /* gy_qspgs_master_key_len / _base_skb_len / _base_vkb_len */
#include "qspgs_ops.h" /* gy_qspgs_member_ctx_open / _clear */
#include "util.h"      /* gy_secure_zero */

/* Write the record header ver || format_version(BE16); returns the header len. */
static size_t
put_hdr(uint8_t *blob, uint16_t format_version)
{
    blob[0] = GY_QSPGS_REC_VERSION;
    blob[1] = (uint8_t)(format_version >> 8);
    blob[2] = (uint8_t)(format_version & 0xff);
    return GY_QSPGS_REC_HDR_LEN;
}

/*
 * Frame header || payload into a stack blob and store it under (kind, id).  The
 * blob is zeroized before returning whatever the store callback reported.
 */
static int
store_keyed(const struct gy_qspgs_store *store, enum gy_qspgs_rec_kind kind,
            const uint8_t *id, size_t id_len, const uint8_t *payload,
            size_t payload_len)
{
    uint8_t blob[GY_QSPGS_REC_BLOB_MAX];
    size_t off;
    int rc;

    off = put_hdr(blob, GY_QSPGS_FORMAT_VERSION);
    memcpy(blob + off, payload, payload_len);
    rc = store->store(store->ctx, kind, id, id_len, blob, off + payload_len);
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

/*
 * Load (kind, id), validate the header and total length against expect_len
 * (the exact payload width for this record), and copy the payload to out.
 * *out_fmt, when non-NULL, receives the stored format_version.  The transient
 * blob is always zeroized.
 */
static int
load_keyed(const struct gy_qspgs_store *store, enum gy_qspgs_rec_kind kind,
           const uint8_t *id, size_t id_len, size_t expect_len,
           uint16_t *out_fmt, uint8_t *out_payload)
{
    uint8_t blob[GY_QSPGS_REC_BLOB_MAX];
    size_t blen = 0;
    uint16_t fmt;
    int rc;

    rc = store->load(store->ctx, kind, id, id_len, blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != GY_QSPGS_REC_HDR_LEN + expect_len ||
        blob[0] != GY_QSPGS_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }
    /* SEC-v1.5.0 INFO-2: enforce the D-QGS-12 format-version window the header
     * text promises, so a record written at an epoch this build does not
     * implement is refused on load rather than fed to a key schedule. */
    fmt = (uint16_t)(((uint16_t)blob[1] << 8) | blob[2]);
    if (fmt < GY_QSPGS_MIN_SUPPORTED_FORMAT_VERSION ||
        fmt > GY_QSPGS_MAX_SUPPORTED_FORMAT_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_UNSUPPORTED;
    }
    if (out_fmt != NULL)
        *out_fmt = fmt;
    if (out_payload != NULL)
        memcpy(out_payload, blob + GY_QSPGS_REC_HDR_LEN, expect_len);
    gy_secure_zero(blob, sizeof(blob));
    return GY_OK;
}

/* True for a UID within the accepted length window. */
static int
uid_ok(const uint8_t *uid, size_t uid_len)
{
    return (uid != NULL && uid_len == GY_QSPGS_UID_LEN);
}

/* ---- MUK record ---------------------------------------------------------- */

int
gy_qspgs_muk_store(const struct gy_qspgs_store *store, uint8_t suite_id,
                   const uint8_t *uid, size_t uid_len, const uint8_t *muk)
{
    size_t mklen;

    if (store == NULL || store->store == NULL || muk == NULL ||
        !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    return store_keyed(store, GY_QREC_MUK, uid, uid_len, muk, mklen);
}

int
gy_qspgs_muk_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                  const uint8_t *uid, size_t uid_len, uint8_t *out, size_t cap,
                  size_t *out_len)
{
    size_t mklen;
    int rc;

    if (store == NULL || store->load == NULL || out == NULL ||
        out_len == NULL || !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;
    if (cap < mklen)
        return GY_ERR_TOOLONG;

    rc = load_keyed(store, GY_QREC_MUK, uid, uid_len, mklen, NULL, out);
    if (rc != GY_OK)
        return rc;
    *out_len = mklen;
    return GY_OK;
}

/* ---- BASE_KEY record (skbase || vkbase) ---------------------------------- */

int
gy_qspgs_base_key_store(const struct gy_qspgs_store *store, uint8_t suite_id,
                        const uint8_t *uid, size_t uid_len, const uint8_t *skb,
                        const uint8_t *vkb)
{
    uint8_t payload[GY_QSPGS_SKB_MAX + GY_QSPGS_VKB_MAX];
    size_t skblen, vkblen;
    int rc;

    if (store == NULL || store->store == NULL || skb == NULL || vkb == NULL ||
        !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    skblen = gy_qspgs_base_skb_len(suite_id);
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    if (skblen == 0 || vkblen == 0)
        return GY_ERR_ARG;

    memcpy(payload, skb, skblen);
    memcpy(payload + skblen, vkb, vkblen);
    rc = store_keyed(store, GY_QREC_BASE_KEY, uid, uid_len, payload,
                     skblen + vkblen);
    gy_secure_zero(payload, sizeof(payload));
    return rc;
}

int
gy_qspgs_base_key_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                       const uint8_t *uid, size_t uid_len, uint8_t *out_skb,
                       uint8_t *out_vkb)
{
    uint8_t payload[GY_QSPGS_SKB_MAX + GY_QSPGS_VKB_MAX];
    size_t skblen, vkblen;
    int rc;

    if (store == NULL || store->load == NULL || out_skb == NULL ||
        out_vkb == NULL || !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    skblen = gy_qspgs_base_skb_len(suite_id);
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    if (skblen == 0 || vkblen == 0)
        return GY_ERR_ARG;

    rc = load_keyed(store, GY_QREC_BASE_KEY, uid, uid_len, skblen + vkblen,
                    NULL, payload);
    if (rc != GY_OK)
        return rc;
    memcpy(out_skb, payload, skblen);
    memcpy(out_vkb, payload + skblen, vkblen);
    gy_secure_zero(payload, sizeof(payload));
    return GY_OK;
}

/* ---- ACQUAINTANCE record (ep || vkbase || acq) --------------------------- */

/* Big-endian 64-bit pack/unpack (local, to avoid pulling a wire header). */
static void
put_be64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

static uint64_t
get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

int
gy_qspgs_acquaintance_store(const struct gy_qspgs_store *store,
                            uint8_t suite_id, const uint8_t *uid,
                            size_t uid_len, const uint8_t *vkb,
                            const uint8_t *acq, const uint8_t *uk, uint64_t ep)
{
    uint8_t payload[8 + GY_QSPGS_VKB_MAX + 2 * GY_QSPGS_MASTER_KEY_MAX];
    size_t vkblen, mklen;
    int rc;

    if (store == NULL || store->store == NULL || vkb == NULL || acq == NULL ||
        uk == NULL || !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    mklen = gy_qspgs_master_key_len(suite_id);
    if (vkblen == 0 || mklen == 0)
        return GY_ERR_ARG;

    /* ep(8) || vkbase || acq || uk (D-QGS-13 E4: uk stored with the AcqRec so
     * IsCorrectUserKey can re-check acq == KDF(uk); format_version 1). */
    put_be64(payload, ep);
    memcpy(payload + 8, vkb, vkblen);
    memcpy(payload + 8 + vkblen, acq, mklen);
    memcpy(payload + 8 + vkblen + mklen, uk, mklen);
    rc = store_keyed(store, GY_QREC_ACQUAINTANCE, uid, uid_len, payload,
                     8 + vkblen + 2 * mklen);
    gy_secure_zero(payload, sizeof(payload));
    return rc;
}

int
gy_qspgs_acquaintance_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                           const uint8_t *uid, size_t uid_len, uint8_t *out_vkb,
                           uint8_t *out_acq, uint8_t *out_uk, uint64_t *out_ep)
{
    uint8_t payload[8 + GY_QSPGS_VKB_MAX + 2 * GY_QSPGS_MASTER_KEY_MAX];
    size_t vkblen, mklen;
    int rc;

    if (store == NULL || store->load == NULL || out_vkb == NULL ||
        out_acq == NULL || out_uk == NULL || out_ep == NULL ||
        !uid_ok(uid, uid_len))
        return GY_ERR_ARG;
    vkblen = gy_qspgs_base_vkb_len(suite_id);
    mklen = gy_qspgs_master_key_len(suite_id);
    if (vkblen == 0 || mklen == 0)
        return GY_ERR_ARG;

    rc = load_keyed(store, GY_QREC_ACQUAINTANCE, uid, uid_len,
                    8 + vkblen + 2 * mklen, NULL, payload);
    if (rc != GY_OK)
        return rc;
    *out_ep = get_be64(payload);
    memcpy(out_vkb, payload + 8, vkblen);
    memcpy(out_acq, payload + 8 + vkblen, mklen);
    memcpy(out_uk, payload + 8 + vkblen + mklen, mklen);
    gy_secure_zero(payload, sizeof(payload));
    return GY_OK;
}

/* ---- GROUP_KEY record ---------------------------------------------------- */

int
gy_qspgs_group_key_store(const struct gy_qspgs_store *store, uint8_t suite_id,
                         const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *gk)
{
    size_t mklen;

    if (store == NULL || store->store == NULL || gid == NULL || gk == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    return store_keyed(store, GY_QREC_GROUP_KEY, gid, GY_QSPGS_GID_LEN, gk,
                       mklen);
}

int
gy_qspgs_group_key_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                        const uint8_t gid[GY_QSPGS_GID_LEN], uint8_t *out,
                        size_t cap, size_t *out_len)
{
    size_t mklen;
    int rc;

    if (store == NULL || store->load == NULL || gid == NULL || out == NULL ||
        out_len == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;
    if (cap < mklen)
        return GY_ERR_TOOLONG;

    /* Read-your-writes (SEC-v1.5.0 LOW-4, D-SES-10): while a rotating edit is
     * staged, the staged gk is the operative key for the admin that emitted the
     * new core (deriving its new signer vkr, re-delivering the key), so prefer
     * the pending slot and fall back to the committed gk.  On rollback the
     * pending slot is dropped and this reverts to the still-current gk. */
    rc = load_keyed(store, GY_QREC_GROUP_KEY_PENDING, gid, GY_QSPGS_GID_LEN,
                    mklen, NULL, out);
    if (rc == GY_ERR_NOT_FOUND)
        rc = load_keyed(store, GY_QREC_GROUP_KEY, gid, GY_QSPGS_GID_LEN, mklen,
                        NULL, out);
    if (rc != GY_OK)
        return rc;
    *out_len = mklen;
    return GY_OK;
}

/* ---- staged GROUP_KEY (SEC-v1.5.0 LOW-4) --------------------------------- */

int
gy_qspgs_group_key_stage(const struct gy_qspgs_store *store, uint8_t suite_id,
                         const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *gk)
{
    uint8_t cur[GY_QSPGS_MASTER_KEY_MAX];
    size_t mklen;
    int rc;

    if (store == NULL || store->store == NULL || store->load == NULL ||
        gid == NULL || gk == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    /* Refuse to overwrite an unresolved staged gk: the prior edit must be
     * committed or rolled back first (the send path's single-open discipline). */
    rc = load_keyed(store, GY_QREC_GROUP_KEY_PENDING, gid, GY_QSPGS_GID_LEN,
                    mklen, NULL, cur);
    gy_secure_zero(cur, sizeof(cur));
    if (rc == GY_OK)
        return GY_ERR_STATE;
    if (rc != GY_ERR_NOT_FOUND)
        return rc;

    return store_keyed(store, GY_QREC_GROUP_KEY_PENDING, gid, GY_QSPGS_GID_LEN,
                       gk, mklen);
}

int
gy_qspgs_group_key_commit(const struct gy_qspgs_store *store, uint8_t suite_id,
                          const uint8_t gid[GY_QSPGS_GID_LEN])
{
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    size_t mklen;
    int rc;

    if (store == NULL || store->store == NULL || store->load == NULL ||
        store->remove == NULL || gid == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    rc = load_keyed(store, GY_QREC_GROUP_KEY_PENDING, gid, GY_QSPGS_GID_LEN,
                    mklen, NULL, gk);
    if (rc != GY_OK)
        return rc; /* GY_ERR_NOT_FOUND when nothing is staged. */

    /* Promote, then drop the pending slot.  Store first so a crash between the
     * two leaves the (now correct) current gk in place and a stale pending that
     * a retried commit converges away; the old gk is superseded here. */
    rc =
        store_keyed(store, GY_QREC_GROUP_KEY, gid, GY_QSPGS_GID_LEN, gk, mklen);
    gy_secure_zero(gk, sizeof(gk));
    if (rc != GY_OK)
        return rc;
    return store->remove(store->ctx, GY_QREC_GROUP_KEY_PENDING, gid,
                         GY_QSPGS_GID_LEN);
}

int
gy_qspgs_group_key_rollback(const struct gy_qspgs_store *store,
                            const uint8_t gid[GY_QSPGS_GID_LEN])
{
    if (store == NULL || store->remove == NULL || gid == NULL)
        return GY_ERR_ARG;

    /* Drop the staged gk; the current gk is untouched.  Idempotent. */
    return store->remove(store->ctx, GY_QREC_GROUP_KEY_PENDING, gid,
                         GY_QSPGS_GID_LEN);
}

/* ---- JOIN_LINK record ---------------------------------------------------- */

int
gy_qspgs_joinlink_secret_store(const struct gy_qspgs_store *store,
                               const uint8_t gid[GY_QSPGS_GID_LEN],
                               const uint8_t *jls)
{
    if (store == NULL || store->store == NULL || gid == NULL || jls == NULL)
        return GY_ERR_ARG;

    return store_keyed(store, GY_QREC_JOIN_LINK, gid, GY_QSPGS_GID_LEN, jls,
                       GY_QSPGS_JOINLINK_SECRET);
}

int
gy_qspgs_joinlink_secret_load(const struct gy_qspgs_store *store,
                              const uint8_t gid[GY_QSPGS_GID_LEN], uint8_t *out,
                              size_t cap, size_t *out_len)
{
    int rc;

    if (store == NULL || store->load == NULL || gid == NULL || out == NULL ||
        out_len == NULL)
        return GY_ERR_ARG;
    if (cap < GY_QSPGS_JOINLINK_SECRET)
        return GY_ERR_TOOLONG;

    rc = load_keyed(store, GY_QREC_JOIN_LINK, gid, GY_QSPGS_GID_LEN,
                    GY_QSPGS_JOINLINK_SECRET, NULL, out);
    if (rc != GY_OK)
        return rc;
    *out_len = GY_QSPGS_JOINLINK_SECRET;
    return GY_OK;
}

int
gy_qspgs_joinlink_secret_delete(const struct gy_qspgs_store *store,
                                const uint8_t gid[GY_QSPGS_GID_LEN])
{
    if (store == NULL || store->remove == NULL || gid == NULL)
        return GY_ERR_ARG;

    return store->remove(store->ctx, GY_QREC_JOIN_LINK, gid, GY_QSPGS_GID_LEN);
}

/* ---- format version + removal -------------------------------------------- */

int
gy_qspgs_format_version_load(const struct gy_qspgs_store *store,
                             enum gy_qspgs_rec_kind kind, const uint8_t *id,
                             size_t id_len, uint16_t *out_version)
{
    uint8_t blob[GY_QSPGS_REC_BLOB_MAX];
    size_t blen = 0;
    int rc;

    if (store == NULL || store->load == NULL || id == NULL || id_len == 0 ||
        out_version == NULL)
        return GY_ERR_ARG;

    rc = store->load(store->ctx, kind, id, id_len, blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen < GY_QSPGS_REC_HDR_LEN || blob[0] != GY_QSPGS_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }
    *out_version = (uint16_t)(((uint16_t)blob[1] << 8) | blob[2]);
    gy_secure_zero(blob, sizeof(blob));
    /* SEC-v1.5.0 INFO-2: refuse a stored epoch outside the supported window
     * (same D-QGS-12 rule as load_keyed and header_decode). */
    if (*out_version < GY_QSPGS_MIN_SUPPORTED_FORMAT_VERSION ||
        *out_version > GY_QSPGS_MAX_SUPPORTED_FORMAT_VERSION)
        return GY_ERR_UNSUPPORTED;
    return GY_OK;
}

int
gy_qspgs_user_delete_stored(const struct gy_qspgs_store *store,
                            const uint8_t *uid, size_t uid_len)
{
    int rc;

    if (store == NULL || store->remove == NULL || !uid_ok(uid, uid_len))
        return GY_ERR_ARG;

    /* base and muk are independent (section 2.1); remove is idempotent, so a
     * retried delete converges regardless of order. */
    rc = store->remove(store->ctx, GY_QREC_BASE_KEY, uid, uid_len);
    if (rc != GY_OK)
        return rc;
    return store->remove(store->ctx, GY_QREC_MUK, uid, uid_len);
}

int
gy_qspgs_group_delete_stored(const struct gy_qspgs_store *store,
                             const uint8_t gid[GY_QSPGS_GID_LEN])
{
    int rc;

    if (store == NULL || store->remove == NULL || gid == NULL)
        return GY_ERR_ARG;

    /* gk, any staged gk, and the join-link secret are the group's at-rest
     * material; remove is idempotent, so dropping all converges regardless of
     * order. */
    rc = store->remove(store->ctx, GY_QREC_JOIN_LINK, gid, GY_QSPGS_GID_LEN);
    if (rc != GY_OK)
        return rc;
    rc = store->remove(store->ctx, GY_QREC_GROUP_KEY_PENDING, gid,
                       GY_QSPGS_GID_LEN);
    if (rc != GY_OK)
        return rc;
    return store->remove(store->ctx, GY_QREC_GROUP_KEY, gid, GY_QSPGS_GID_LEN);
}

/* ---- rederive-only open (task 2, D-GRP-7) -------------------------------- */

int
gy_qspgs_member_ctx_open_stored(struct gy_qspgs_member_ctx *ctx,
                                const struct gy_qspgs_store *store,
                                uint8_t suite_id,
                                const uint8_t gid[GY_QSPGS_GID_LEN],
                                const uint8_t *uid, size_t uidlen)
{
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t skb[GY_QSPGS_SKB_MAX], vkb[GY_QSPGS_VKB_MAX];
    size_t gk_len = 0;
    int rc;

    if (ctx == NULL || store == NULL || gid == NULL)
        return GY_ERR_ARG;

    /* At rest: gk (keyed on gid) and the member's own base pair (keyed on uid).
     * Everything else the ctx holds is rederived from these, never loaded. */
    rc = gy_qspgs_group_key_load(store, suite_id, gid, gk, sizeof(gk), &gk_len);
    if (rc != GY_OK)
        return rc;
    rc = gy_qspgs_base_key_load(store, suite_id, uid, uidlen, skb, vkb);
    if (rc != GY_OK) {
        gy_secure_zero(gk, sizeof(gk));
        return rc;
    }

    rc = gy_qspgs_member_ctx_open(ctx, suite_id, gk, skb, vkb, uid, uidlen);

    gy_secure_zero(gk, sizeof(gk));
    gy_secure_zero(skb, sizeof(skb));
    return rc;
}
