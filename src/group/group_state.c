/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_state.h"

#include "suite.h" /* gy_suite_desc, GY_HASH_MAX */
#include "util.h"  /* gy_secure_zero, gy_const_memcmp */

#include "error.h"

/*
 * Client-side group state (GROUP_SPEC section 10, D-GRP-7).  Rederive from the
 * GroupMasterKey, cache nothing; credentials and the own ProfileKey persist as
 * opaque app-sealed blobs.  Record blobs carry a leading version byte and are
 * fixed-layout (the same discipline as the section 9 wire objects).
 */

/* Store-key scratch: a GroupID, optionally followed by a target UID. */
#define GY_GROUP_RECKEY_MAX (GY_GROUP_ID_LEN + GY_GROUP_UID_BYTES)

static void
put_be64(uint8_t *p, uint64_t v)
{
    size_t i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

static uint64_t
get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

int
gy_group_id(const struct gy_group_tier *tier,
            const struct gy_group_public_params *pp, uint16_t format_version,
            uint8_t out[GY_GROUP_ID_LEN])
{
    const struct gy_suite_desc *desc;
    uint8_t buf[3 + 2 * GY_GROUP_POINT_MAX];
    uint8_t digest[GY_HASH_MAX];
    size_t plen;
    int rc;

    if (tier == NULL || pp == NULL || out == NULL)
        return GY_ERR_ARG;
    desc = gy_suite_desc(tier->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;

    buf[0] = tier->suite_id;
    buf[1] = (uint8_t)(format_version >> 8); /* format version, BE16 */
    buf[2] = (uint8_t)(format_version & 0xff);
    memcpy(buf + 3, pp->A, plen);
    memcpy(buf + 3 + plen, pp->B, plen);
    rc = desc->hash(digest, buf, 3 + 2 * plen);
    if (rc != GY_OK)
        return rc;
    memcpy(out, digest, GY_GROUP_ID_LEN);
    return GY_OK;
}

/*
 * Derive params from a GroupMasterKey and store the master-key record under the
 * derived GroupID.  Shared by create (fresh key) and install (received key).
 */
static int
derive_and_store_master(const struct gy_group_store *store,
                        const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        uint16_t format_version, const uint8_t *gmk,
                        size_t gmk_len, uint8_t out_group_id[GY_GROUP_ID_LEN],
                        struct gy_group_secret_params *out_sp,
                        struct gy_group_public_params *out_pp)
{
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    uint8_t id[GY_GROUP_ID_LEN];
    /* ver(1) || format_version(2, BE) || gmk (<= master_key_len). */
    uint8_t blob[3 + GY_GROUP_POINT_MAX];
    int rc;

    rc = gy_group_secret_derive(tier, gmk, gmk_len, &sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_public_derive(tier, gens, &sp, &pp);
    if (rc != GY_OK)
        goto out;
    rc = gy_group_id(tier, &pp, format_version, id);
    if (rc != GY_OK)
        goto out;

    blob[0] = GY_GROUP_REC_VERSION;
    blob[1] = (uint8_t)(format_version >> 8);
    blob[2] = (uint8_t)(format_version & 0xff);
    memcpy(blob + 3, gmk, gmk_len);
    rc = store->store(store->ctx, GY_GREC_MASTER_KEY, id, GY_GROUP_ID_LEN, blob,
                      3 + gmk_len);
    gy_secure_zero(blob, sizeof(blob));
    if (rc != GY_OK)
        goto out;

    memcpy(out_group_id, id, GY_GROUP_ID_LEN);
    memcpy(out_sp, &sp, sizeof(sp));
    memcpy(out_pp, &pp, sizeof(pp));

out:
    gy_group_secret_clear(&sp);
    return rc;
}

int
gy_group_create_stored(const struct gy_group_store *store,
                       const struct gy_group_tier *tier,
                       const struct gy_group_generators *gens,
                       uint8_t out_group_id[GY_GROUP_ID_LEN],
                       struct gy_group_secret_params *out_sp,
                       struct gy_group_public_params *out_pp)
{
    uint8_t gmk[GY_GROUP_POINT_MAX];
    int rc;

    if (store == NULL || store->store == NULL || tier == NULL || gens == NULL ||
        out_group_id == NULL || out_sp == NULL || out_pp == NULL)
        return GY_ERR_ARG;

    rc = gy_group_master_key(tier, gmk);
    if (rc != GY_OK)
        return rc;
    rc = derive_and_store_master(store, tier, gens, GY_GROUP_FORMAT_VERSION,
                                 gmk, tier->master_key_len, out_group_id,
                                 out_sp, out_pp);
    gy_secure_zero(gmk, sizeof(gmk));
    return rc;
}

int
gy_group_install_master_key(const struct gy_group_store *store,
                            const struct gy_group_tier *tier,
                            const struct gy_group_generators *gens,
                            const uint8_t *gmk, size_t gmk_len,
                            uint16_t format_version,
                            uint8_t out_group_id[GY_GROUP_ID_LEN],
                            struct gy_group_secret_params *out_sp,
                            struct gy_group_public_params *out_pp)
{
    if (store == NULL || store->store == NULL || tier == NULL || gens == NULL ||
        gmk == NULL || out_group_id == NULL || out_sp == NULL || out_pp == NULL)
        return GY_ERR_ARG;
    if (gmk_len != tier->master_key_len)
        return GY_ERR_ARG;
    /* Refuse a group whose capability epoch this build does not implement. */
    if (format_version < GY_GROUP_MIN_SUPPORTED_FORMAT_VERSION ||
        format_version > GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION)
        return GY_ERR_UNSUPPORTED;

    return derive_and_store_master(store, tier, gens, format_version, gmk,
                                   gmk_len, out_group_id, out_sp, out_pp);
}

int
gy_group_load(const struct gy_group_store *store,
              const struct gy_group_tier *tier,
              const struct gy_group_generators *gens,
              const uint8_t group_id[GY_GROUP_ID_LEN],
              struct gy_group_secret_params *out_sp,
              struct gy_group_public_params *out_pp)
{
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    uint8_t blob[3 + GY_GROUP_POINT_MAX];
    uint8_t id2[GY_GROUP_ID_LEN];
    uint16_t fmtver;
    size_t blen = 0, mklen;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL || gens == NULL ||
        group_id == NULL || out_sp == NULL || out_pp == NULL)
        return GY_ERR_ARG;
    mklen = tier->master_key_len;

    rc = store->load(store->ctx, GY_GREC_MASTER_KEY, group_id, GY_GROUP_ID_LEN,
                     blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != 3 + mklen || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }
    fmtver = (uint16_t)(((uint16_t)blob[1] << 8) | blob[2]);

    rc = gy_group_secret_derive(tier, blob + 3, mklen, &sp);
    gy_secure_zero(blob, sizeof(blob));
    if (rc != GY_OK)
        return rc;
    rc = gy_group_public_derive(tier, gens, &sp, &pp);
    if (rc != GY_OK)
        goto out;
    rc = gy_group_id(tier, &pp, fmtver, id2);
    if (rc != GY_OK)
        goto out;
    /* Integrity: the stored key AND its bound format version must rederive to
     * the GroupID it was filed under (a corrupted, wrong-suite, or
     * version-flipped record is rejected, no oracle). */
    if (gy_const_memcmp(id2, group_id, GY_GROUP_ID_LEN) != 0) {
        rc = GY_ERR_VERIFY;
        goto out;
    }

    memcpy(out_sp, &sp, sizeof(sp));
    memcpy(out_pp, &pp, sizeof(pp));

out:
    gy_group_secret_clear(&sp);
    return rc;
}

int
gy_group_master_key_load(const struct gy_group_store *store,
                         const struct gy_group_tier *tier,
                         const uint8_t group_id[GY_GROUP_ID_LEN], uint8_t *out,
                         size_t cap, size_t *out_len)
{
    uint8_t blob[3 + GY_GROUP_POINT_MAX];
    size_t blen = 0, mklen;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL ||
        group_id == NULL || out == NULL || out_len == NULL)
        return GY_ERR_ARG;
    mklen = tier->master_key_len;
    if (cap < mklen)
        return GY_ERR_TOOLONG;

    rc = store->load(store->ctx, GY_GREC_MASTER_KEY, group_id, GY_GROUP_ID_LEN,
                     blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != 3 + mklen || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }
    memcpy(out, blob + 3, mklen);
    *out_len = mklen;
    gy_secure_zero(blob, sizeof(blob));
    return GY_OK;
}

int
gy_group_format_version_load(const struct gy_group_store *store,
                             const struct gy_group_tier *tier,
                             const uint8_t group_id[GY_GROUP_ID_LEN],
                             uint16_t *out_version)
{
    uint8_t blob[3 + GY_GROUP_POINT_MAX];
    size_t blen = 0, mklen;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL ||
        group_id == NULL || out_version == NULL)
        return GY_ERR_ARG;
    mklen = tier->master_key_len;

    rc = store->load(store->ctx, GY_GREC_MASTER_KEY, group_id, GY_GROUP_ID_LEN,
                     blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != 3 + mklen || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }
    *out_version = (uint16_t)(((uint16_t)blob[1] << 8) | blob[2]);
    gy_secure_zero(blob, sizeof(blob));
    return GY_OK;
}

int
gy_group_delete_stored(const struct gy_group_store *store,
                       const struct gy_group_tier *tier,
                       const uint8_t group_id[GY_GROUP_ID_LEN])
{
    int rc;

    if (store == NULL || store->remove == NULL || tier == NULL ||
        group_id == NULL)
        return GY_ERR_ARG;

    /*
     * Safe removal order (D-SES-10 style): the derived-from records first, the
     * GroupMasterKey LAST.  A remove that fails mid-sequence then never leaves
     * an orphan record under an already-removed master key; the group stays
     * consistent (still openable, just missing some cached credentials, which
     * are re-acquired).  The master key is removed only once every dependent
     * record is gone.  Removes are idempotent, so a retried delete converges.
     */
    rc =
        store->remove(store->ctx, GY_GREC_AUTH_CRED, group_id, GY_GROUP_ID_LEN);
    if (rc != GY_OK)
        return rc;
    rc = store->remove(store->ctx, GY_GREC_OWN_PK, group_id, GY_GROUP_ID_LEN);
    if (rc != GY_OK)
        return rc;
    return store->remove(store->ctx, GY_GREC_MASTER_KEY, group_id,
                         GY_GROUP_ID_LEN);
}

/* ---- credential + own-ProfileKey records ------------------------------- */

int
gy_group_auth_cred_store(const struct gy_group_store *store,
                         const struct gy_group_tier *tier,
                         const uint8_t group_id[GY_GROUP_ID_LEN],
                         const struct gy_group_auth_credential *cred)
{
    uint8_t blob[GY_GROUP_REC_BLOB_MAX];
    size_t taglen = 0, off;
    int rc;

    if (store == NULL || store->store == NULL || tier == NULL ||
        group_id == NULL || cred == NULL)
        return GY_ERR_ARG;

    blob[0] = GY_GROUP_REC_VERSION;
    rc = gy_group_mac_tag_encode(tier, &cred->mac, blob + 1, sizeof(blob) - 1,
                                 &taglen);
    if (rc != GY_OK)
        return rc;
    off = 1 + taglen;
    put_be64(blob + off, cred->redemption_date);
    off += 8;
    rc = store->store(store->ctx, GY_GREC_AUTH_CRED, group_id, GY_GROUP_ID_LEN,
                      blob, off);
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_auth_cred_load(const struct gy_group_store *store,
                        const struct gy_group_tier *tier,
                        const uint8_t group_id[GY_GROUP_ID_LEN],
                        struct gy_group_auth_credential *out_cred)
{
    uint8_t blob[GY_GROUP_REC_BLOB_MAX];
    size_t blen = 0, taglen;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL ||
        group_id == NULL || out_cred == NULL)
        return GY_ERR_ARG;
    taglen = tier->scalar_len + 2 * tier->point_len;

    rc = store->load(store->ctx, GY_GREC_AUTH_CRED, group_id, GY_GROUP_ID_LEN,
                     blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != 1 + taglen + 8 || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }

    memset(out_cred, 0, sizeof(*out_cred));
    rc = gy_group_mac_tag_decode(tier, &out_cred->mac, blob + 1, taglen);
    if (rc == GY_OK)
        out_cred->redemption_date = get_be64(blob + 1 + taglen);
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_auth_cred_valid(const struct gy_group_auth_credential *cred,
                         uint64_t now_unix)
{
    if (cred == NULL)
        return 0;
    /* Valid only on the credential's redemption day (spec-true daily model). */
    return (now_unix / 86400ull) * 86400ull == cred->redemption_date;
}

static int
pk_cred_key(const uint8_t group_id[GY_GROUP_ID_LEN],
            const uint8_t target_uid[GY_GROUP_UID_BYTES],
            uint8_t out[GY_GROUP_RECKEY_MAX])
{
    memcpy(out, group_id, GY_GROUP_ID_LEN);
    memcpy(out + GY_GROUP_ID_LEN, target_uid, GY_GROUP_UID_BYTES);
    return GY_GROUP_ID_LEN + GY_GROUP_UID_BYTES;
}

int
gy_group_pk_cred_store(const struct gy_group_store *store,
                       const struct gy_group_tier *tier,
                       const uint8_t group_id[GY_GROUP_ID_LEN],
                       const uint8_t target_uid[GY_GROUP_UID_BYTES],
                       const struct gy_group_mac_tag *cred)
{
    uint8_t key[GY_GROUP_RECKEY_MAX];
    uint8_t blob[1 + GY_GROUP_MAC_TAG_ENC_MAX];
    size_t klen, taglen = 0;
    int rc;

    if (store == NULL || store->store == NULL || tier == NULL ||
        group_id == NULL || target_uid == NULL || cred == NULL)
        return GY_ERR_ARG;

    blob[0] = GY_GROUP_REC_VERSION;
    rc = gy_group_mac_tag_encode(tier, cred, blob + 1, sizeof(blob) - 1,
                                 &taglen);
    if (rc != GY_OK)
        return rc;
    klen = pk_cred_key(group_id, target_uid, key);
    rc = store->store(store->ctx, GY_GREC_PK_CRED, key, klen, blob, 1 + taglen);
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_pk_cred_load(const struct gy_group_store *store,
                      const struct gy_group_tier *tier,
                      const uint8_t group_id[GY_GROUP_ID_LEN],
                      const uint8_t target_uid[GY_GROUP_UID_BYTES],
                      struct gy_group_mac_tag *out_cred)
{
    uint8_t key[GY_GROUP_RECKEY_MAX];
    uint8_t blob[1 + GY_GROUP_MAC_TAG_ENC_MAX];
    size_t klen, blen = 0, taglen;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL ||
        group_id == NULL || target_uid == NULL || out_cred == NULL)
        return GY_ERR_ARG;
    taglen = tier->scalar_len + 2 * tier->point_len;

    klen = pk_cred_key(group_id, target_uid, key);
    rc = store->load(store->ctx, GY_GREC_PK_CRED, key, klen, blob, sizeof(blob),
                     &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != 1 + taglen || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }

    rc = gy_group_mac_tag_decode(tier, out_cred, blob + 1, taglen);
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_pk_cred_remove(const struct gy_group_store *store,
                        const struct gy_group_tier *tier,
                        const uint8_t group_id[GY_GROUP_ID_LEN],
                        const uint8_t target_uid[GY_GROUP_UID_BYTES])
{
    uint8_t key[GY_GROUP_RECKEY_MAX];
    size_t klen;

    if (store == NULL || store->remove == NULL || tier == NULL ||
        group_id == NULL || target_uid == NULL)
        return GY_ERR_ARG;
    klen = pk_cred_key(group_id, target_uid, key);
    return store->remove(store->ctx, GY_GREC_PK_CRED, key, klen);
}

int
gy_group_own_pk_store(const struct gy_group_store *store,
                      const struct gy_group_tier *tier,
                      const uint8_t group_id[GY_GROUP_ID_LEN],
                      const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES])
{
    uint8_t blob[1 + GY_GROUP_PROFILEKEY_BYTES];
    int rc;

    if (store == NULL || store->store == NULL || tier == NULL ||
        group_id == NULL || pk == NULL)
        return GY_ERR_ARG;

    blob[0] = GY_GROUP_REC_VERSION;
    memcpy(blob + 1, pk, GY_GROUP_PROFILEKEY_BYTES);
    rc = store->store(store->ctx, GY_GREC_OWN_PK, group_id, GY_GROUP_ID_LEN,
                      blob, sizeof(blob));
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_own_pk_load(const struct gy_group_store *store,
                     const struct gy_group_tier *tier,
                     const uint8_t group_id[GY_GROUP_ID_LEN],
                     uint8_t pk[GY_GROUP_PROFILEKEY_BYTES])
{
    uint8_t blob[1 + GY_GROUP_PROFILEKEY_BYTES];
    size_t blen = 0;
    int rc;

    if (store == NULL || store->load == NULL || tier == NULL ||
        group_id == NULL || pk == NULL)
        return GY_ERR_ARG;

    rc = store->load(store->ctx, GY_GREC_OWN_PK, group_id, GY_GROUP_ID_LEN,
                     blob, sizeof(blob), &blen);
    if (rc != GY_OK)
        return rc;
    if (blen == 0)
        return GY_ERR_NOT_FOUND;
    if (blen != sizeof(blob) || blob[0] != GY_GROUP_REC_VERSION) {
        gy_secure_zero(blob, sizeof(blob));
        return GY_ERR_VERIFY;
    }

    memcpy(pk, blob + 1, GY_GROUP_PROFILEKEY_BYTES);
    gy_secure_zero(blob, sizeof(blob));
    return GY_OK;
}

void
gy_group_auth_credential_clear(struct gy_group_auth_credential *cred)
{
    if (cred != NULL)
        gy_secure_zero(cred, sizeof(*cred));
}

/* ---- store-integrated operation wrappers (increment 3) ----------------- */

int
gy_group_get_auth_credential_stored(const struct gy_group_store *store,
                                    const struct gy_group_tier *tier,
                                    const struct gy_group_generators *gens,
                                    const struct gy_group_server_public *pp_A,
                                    const uint8_t group_id[GY_GROUP_ID_LEN],
                                    const uint8_t uid[GY_GROUP_UID_BYTES],
                                    uint64_t date,
                                    const struct gy_group_auth_response *resp,
                                    struct gy_group_mac_tag *out_cred)
{
    struct gy_group_auth_credential ac;
    int rc;

    if (store == NULL || group_id == NULL || out_cred == NULL)
        return GY_ERR_ARG;

    rc = gy_group_get_auth_credential(tier, gens, pp_A, uid, date, resp,
                                      out_cred);
    if (rc != GY_OK)
        return rc;

    memset(&ac, 0, sizeof(ac));
    ac.mac = *out_cred;
    ac.redemption_date = date;
    rc = gy_group_auth_cred_store(store, tier, group_id, &ac);
    gy_group_auth_credential_clear(&ac);
    if (rc != GY_OK)
        gy_secure_zero(out_cred,
                       sizeof(*out_cred)); /* atomic: no usable output */
    return rc;
}

int
gy_group_get_pk_credential_finish_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_server_public *pp_P,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const struct gy_group_pk_request *req, const uint8_t y[GY_GROUP_SCALAR_MAX],
    const struct gy_group_pk_blind_response *resp,
    struct gy_group_mac_tag *out_cred)
{
    int rc;

    if (store == NULL || group_id == NULL || uid == NULL || out_cred == NULL)
        return GY_ERR_ARG;

    rc = gy_group_get_pk_credential_finish(tier, gens, pp_P, uid, req, y, resp,
                                           out_cred);
    if (rc != GY_OK)
        return rc;

    rc = gy_group_pk_cred_store(store, tier, group_id, uid, out_cred);
    if (rc != GY_OK)
        gy_secure_zero(out_cred, sizeof(*out_cred));
    return rc;
}

int
gy_group_commit_to_profile_key_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
    struct gy_group_pk_commitment *out_commit)
{
    int rc;

    if (store == NULL || group_id == NULL || out_version == NULL ||
        out_commit == NULL)
        return GY_ERR_ARG;

    rc = gy_group_commit_to_profile_key(tier, gens, uid, pk, out_version,
                                        out_commit);
    if (rc != GY_OK)
        return rc;

    rc = gy_group_own_pk_store(store, tier, group_id, pk);
    if (rc != GY_OK) {
        gy_secure_zero(out_version, GY_GROUP_PK_VERSION_BYTES);
        memset(out_commit, 0, sizeof(*out_commit));
    }
    return rc;
}

int
gy_group_update_profile_key_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_secret_params *sp,
    const struct gy_group_public_params *pp_pub,
    const struct gy_group_server_public *pp_srv_P,
    const struct gy_group_mac_tag *own_cred,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t own_uid[GY_GROUP_UID_BYTES],
    const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
    struct gy_group_pk_presentation *out_pres)
{
    int rc;

    if (store == NULL || group_id == NULL || own_uid == NULL ||
        out_pres == NULL)
        return GY_ERR_ARG;

    rc = gy_group_update_profile_key(tier, gens, sp, pp_pub, pp_srv_P, own_cred,
                                     own_uid, new_pk, out_pres);
    if (rc != GY_OK)
        return rc;

    /* Safe order (D-SES-10): store the new own ProfileKey first (fatal on
     * failure), then best-effort obsolete the now-stale own credential. */
    rc = gy_group_own_pk_store(store, tier, group_id, new_pk);
    if (rc != GY_OK) {
        memset(out_pres, 0, sizeof(*out_pres));
        return rc;
    }
    /* A leftover stale credential is harmless (fails verification, re-acquired),
     * so a remove failure here does not fail the update (D-SES-10 deferred
     * deletion). */
    (void)gy_group_pk_cred_remove(store, tier, group_id, own_uid);
    return GY_OK;
}

int
gy_group_auth_as_member_stored(const struct gy_group_store *store,
                               const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               const struct gy_group_secret_params *sp,
                               const struct gy_group_public_params *pp_pub,
                               const struct gy_group_server_public *pp_srv_A,
                               const uint8_t group_id[GY_GROUP_ID_LEN],
                               const uint8_t uid[GY_GROUP_UID_BYTES],
                               uint64_t now_unix,
                               struct gy_group_auth_presentation *out_pres)
{
    struct gy_group_auth_credential ac;
    int rc;

    if (store == NULL || group_id == NULL || out_pres == NULL)
        return GY_ERR_ARG;

    rc = gy_group_auth_cred_load(store, tier, group_id, &ac);
    if (rc != GY_OK)
        return rc; /* GY_ERR_NOT_FOUND if none stored */
    /* D-GRP-7 item 3: never present an expired credential. */
    if (!gy_group_auth_cred_valid(&ac, now_unix)) {
        gy_group_auth_credential_clear(&ac);
        return GY_ERR_EXPIRED;
    }

    rc = gy_group_auth_as_member(tier, gens, sp, pp_pub, pp_srv_A, &ac.mac, uid,
                                 ac.redemption_date, out_pres);
    gy_group_auth_credential_clear(&ac);
    return rc;
}

int
gy_group_add_member_stored(const struct gy_group_store *store,
                           const struct gy_group_tier *tier,
                           const struct gy_group_generators *gens,
                           const struct gy_group_secret_params *sp,
                           const struct gy_group_public_params *pp_pub,
                           const struct gy_group_server_public *pp_srv_P,
                           const uint8_t group_id[GY_GROUP_ID_LEN],
                           const uint8_t new_uid[GY_GROUP_UID_BYTES],
                           const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                           struct gy_group_pk_presentation *out_pres)
{
    struct gy_group_mac_tag new_cred;
    int rc;

    if (store == NULL || group_id == NULL || new_uid == NULL ||
        out_pres == NULL)
        return GY_ERR_ARG;

    rc = gy_group_pk_cred_load(store, tier, group_id, new_uid, &new_cred);
    if (rc != GY_OK)
        return rc; /* GY_ERR_NOT_FOUND if none stored for new_uid */

    rc = gy_group_add_member(tier, gens, sp, pp_pub, pp_srv_P, &new_cred,
                             new_uid, new_pk, out_pres);
    gy_secure_zero(&new_cred, sizeof(new_cred));
    return rc;
}

int
gy_group_delete_member_stored(const struct gy_group_store *store,
                              const struct gy_group_tier *tier,
                              const struct gy_group_secret_params *sp,
                              const uint8_t group_id[GY_GROUP_ID_LEN],
                              const uint8_t target_uid[GY_GROUP_UID_BYTES],
                              struct gy_group_uid_ct *out_uid_ct)
{
    int rc;

    if (store == NULL || group_id == NULL || target_uid == NULL ||
        out_uid_ct == NULL)
        return GY_ERR_ARG;

    rc = gy_group_delete_member(tier, sp, target_uid, out_uid_ct);
    if (rc != GY_OK)
        return rc;
    /* Best-effort: the target's cached ProfileKeyCredential is now obsolete;
     * a leftover is harmless, so a remove failure does not fail the call. */
    (void)gy_group_pk_cred_remove(store, tier, group_id, target_uid);
    return GY_OK;
}
