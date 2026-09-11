/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * group_facade_client.c - the public client API (include/geryon_group.h) over
 * the internal group operations.  The group client extends the custodian: group
 * secret state (GroupMasterKey, credentials, own ProfileKey) seals into the
 * custodian's existing store, alongside identity/prekey/session records, under
 * record kinds reserved to the group vertical (GY_GROUP_STORE_KIND_MIN..MAX).
 * A small gy_group_store adapter forwards to c->sealed_store (which seals under
 * the custodian KEK), remapping the group record kinds into that reserved band.
 * Nothing derived from the GroupMasterKey is cached: params are rederived on
 * every call and zeroized after use (D-GRP-7).
 *
 * Every call requires a CLASSICAL-suite, unlocked custodian; a hybrid-suite
 * custodian's group type is a different construction, so its calls return
 * GY_ERR_UNSUPPORTED (gy_group_tier_for is NULL for a hybrid suite).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "geryon_group.h"

#include "custodian.h" /* struct gy_custodian: sealed_store, suite_id, self_uid */

#include "util.h" /* gy_secure_alloc / _free / _zero, gy_core_init */

#include "talos_schnorr.h" /* talos_schnorr_init */

#include "group_cred.h"
#include "group_issue.h"
#include "group_params.h"
#include "group_pres.h"
#include "group_state.h" /* pulls group_ops / _store / _mac / _tier / _attr */
#include "group_venc.h"
#include "group_wire.h"

#define FACADE_SCRATCH 4096

/* The internal wire-role bound (group_ops.h) must track the public role enum:
 * the decoder rejects role > GY_GROUP_ROLE_MAX, and callers validate against
 * GY_GROUP_ROLE_COUNT, so the two must agree. */
_Static_assert(GY_GROUP_ROLE_MAX == GY_GROUP_ROLE_COUNT - 1,
               "GY_GROUP_ROLE_MAX must track the public GY_GROUP_ROLE_COUNT");

/* The public GROUP_KEY_DISTRIBUTION envelope bounds (geryon_group.h) must cover
 * the actual frame - header + format version + GroupMasterKey - at each tier, so
 * a caller sizing a fixed buffer from the constant never truncates. A future
 * envelope-payload change that outgrows a bound fails the build here. */
_Static_assert(
    GY_GROUP_KEY_ENVELOPE_MAX_255 >= GY_GROUP_ENVELOPE_HDR_LEN +
                                         GY_GROUP_ENVELOPE_FMTVER_LEN +
                                         GY_GROUP_MASTER_KEY_255,
    "GY_GROUP_KEY_ENVELOPE_MAX_255 too small for the envelope frame");
_Static_assert(
    GY_GROUP_KEY_ENVELOPE_MAX_448 >= GY_GROUP_ENVELOPE_HDR_LEN +
                                         GY_GROUP_ENVELOPE_FMTVER_LEN +
                                         GY_GROUP_MASTER_KEY_448,
    "GY_GROUP_KEY_ENVELOPE_MAX_448 too small for the envelope frame");

/* Facade-internal record kinds, within the reserved band but ABOVE the four
 * gy_group_rec_kind records (which map to KIND_MIN + 0..3). */
#define FAC_KIND_SERVER_PARAMS (GY_GROUP_STORE_KIND_MIN + 4) /* 0x44 */
#define FAC_KIND_BLIND_STATE (GY_GROUP_STORE_KIND_MIN + 5)   /* 0x45 */

/* Fixed key for the per-custodian ServerPublicParams record (not per-group). */
static const uint8_t FAC_SRV_ID[1] = {0x00};

/* Copy-out per the OpenSSL-style size-query convention (out == NULL reports the
 * required size in *out_len). */
static int
emit(const uint8_t *src, size_t n, uint8_t *out, size_t *out_len)
{
    if (out_len == NULL)
        return GY_ERR_ARG;
    if (out == NULL) {
        *out_len = n;
        return GY_OK;
    }
    if (*out_len < n)
        return GY_ERR_TOOLONG;
    memcpy(out, src, n);
    *out_len = n;
    return GY_OK;
}

/* ---- custodian-store adapter (group records -> sealed_store) ------------- */

static int
adap_load(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
          size_t id_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_custodian *c = ctx;
    return c->sealed_store.load_record(c->sealed_store.ctx,
                                       GY_GROUP_STORE_KIND_MIN + (int)kind - 1,
                                       id, id_len, out, cap, out_len);
}

static int
adap_store(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
           size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct gy_custodian *c = ctx;
    return c->sealed_store.store_record(c->sealed_store.ctx,
                                        GY_GROUP_STORE_KIND_MIN + (int)kind - 1,
                                        id, id_len, blob, blob_len);
}

static int
adap_remove(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
            size_t id_len)
{
    struct gy_custodian *c = ctx;
    return c->sealed_store.delete_record(
        c->sealed_store.ctx, GY_GROUP_STORE_KIND_MIN + (int)kind - 1, id,
        id_len);
}

static void
mk_store(struct gy_custodian *c, struct gy_group_store *st)
{
    st->ctx = c;
    st->load = adap_load;
    st->store = adap_store;
    st->remove = adap_remove;
}

/* ---- shared guards / loaders -------------------------------------------- */

static int
group_guard(gy_custodian *c, const struct gy_group_tier **tier_out)
{
    const struct gy_group_tier *tier;

    if (c == NULL)
        return GY_ERR_ARG;
    if (!c->unlocked)
        return GY_ERR_STATE;
    /* The custodian initialized core, but the group crypto also needs schnorr;
     * both inits are idempotent. */
    if (gy_core_init() != GY_OK || talos_schnorr_init() != 0)
        return GY_ERR_CRYPTO;
    tier = gy_group_tier_for(c->suite_id);
    if (tier == NULL)
        return GY_ERR_UNSUPPORTED; /* hybrid/unknown: not the classical type */
    *tier_out = tier;
    return GY_OK;
}

static int
self_uid(gy_custodian *c, const uint8_t **uid)
{
    if (c->self_uid_len != GY_GROUP_UID_BYTES)
        return GY_ERR_STATE; /* a group custodian must name itself with 16 bytes */
    *uid = c->self_uid;
    return GY_OK;
}

/* Load the installed ServerPublicParams (iparams_A, iparams_P). */
static int
load_srv(gy_custodian *c, const struct gy_group_tier *tier,
         struct gy_group_server_public *pp_A,
         struct gy_group_server_public *pp_P)
{
    uint8_t buf[2 * (GY_GROUP_OBJ_HDR_LEN + 2 * GY_GROUP_POINT_MAX)];
    size_t n = 0, one;
    int rc;

    one = GY_GROUP_OBJ_HDR_LEN + 2 * tier->point_len;
    rc = c->sealed_store.load_record(c->sealed_store.ctx,
                                     FAC_KIND_SERVER_PARAMS, FAC_SRV_ID,
                                     sizeof(FAC_SRV_ID), buf, sizeof(buf), &n);
    if (rc != GY_OK)
        return rc;
    if (n == 0)
        return GY_ERR_STATE; /* server params not installed yet */
    if (n != 2 * one)
        return GY_ERR_VERIFY;
    rc = gy_group_server_public_decode(tier, pp_A, buf, one);
    if (rc != GY_OK)
        return rc;
    return gy_group_server_public_decode(tier, pp_P, buf + one, one);
}

/* Derive generators and load the group's params from the sealed master key. */
static int
load_group(gy_custodian *c, const struct gy_group_tier *tier,
           struct gy_group_store *st, const uint8_t group_id[GY_GROUP_ID_LEN],
           struct gy_group_generators *gens, struct gy_group_secret_params *sp,
           struct gy_group_public_params *pp)
{
    int rc;

    mk_store(c, st);
    rc = gy_group_generators_derive(tier, gens);
    if (rc != GY_OK)
        return rc;
    return gy_group_load(st, tier, gens, group_id, sp, pp);
}

/* ---- lifecycle ---------------------------------------------------------- */

int
gy_custodian_group_open(gy_custodian **out, const gy_store_callbacks *store,
                        const uint8_t *cred, size_t cred_len, gy_clock_fn clock,
                        void *clock_ctx)
{
    gy_custodian *c = NULL;
    int rc;

    if (out == NULL)
        return GY_ERR_ARG;
    /* gy_custodian_open validates store/cred and rebuilds the unlocked handle;
     * we only add the clock the group credential path needs (open takes none,
     * and a live callback cannot be sealed to disk). */
    rc = gy_custodian_open(&c, store, cred, cred_len);
    if (rc != GY_OK)
        return rc;
    c->clock = clock;
    c->clock_ctx = clock_ctx;
    *out = c;
    return GY_OK;
}

/* ---- accessors ---------------------------------------------------------- */

int
gy_custodian_group_self_uid(gy_custodian *c,
                            uint8_t out_uid[GY_GROUP_UID_BYTES])
{
    const struct gy_group_tier *tier;
    const uint8_t *uid;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (out_uid == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;
    memcpy(out_uid, uid, GY_GROUP_UID_BYTES);
    return GY_OK;
}

int
gy_custodian_group_profile_key_version(
    gy_custodian *c, const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES])
{
    const struct gy_group_tier *tier;
    const uint8_t *uid;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (profile_key == NULL || out_version == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;
    return gy_group_profile_key_version(tier, uid, profile_key, out_version);
}

int
gy_custodian_group_format_version(gy_custodian *c,
                                  const uint8_t group_id[GY_GROUP_ID_LEN],
                                  uint16_t *out_version)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || out_version == NULL)
        return GY_ERR_ARG;
    mk_store(c, &st);
    return gy_group_format_version_load(&st, tier, group_id, out_version);
}

/* ---- setup -------------------------------------------------------------- */

int
gy_custodian_group_install_server_params(gy_custodian *c, const uint8_t *params,
                                         size_t params_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_server_public pp_A, pp_P;
    size_t one;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (params == NULL)
        return GY_ERR_ARG;
    one = GY_GROUP_OBJ_HDR_LEN + 2 * tier->point_len;
    if (params_len != 2 * one)
        return GY_ERR_VERIFY;
    rc = gy_group_server_public_decode(tier, &pp_A, params, one);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_server_public_decode(tier, &pp_P, params + one, one);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    return c->sealed_store.store_record(c->sealed_store.ctx,
                                        FAC_KIND_SERVER_PARAMS, FAC_SRV_ID,
                                        sizeof(FAC_SRV_ID), params, params_len);
}

/* ---- group creation and key distribution -------------------------------- */

int
gy_custodian_group_create(gy_custodian *c,
                          uint8_t out_group_id[GY_GROUP_ID_LEN])
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (out_group_id == NULL)
        return GY_ERR_ARG;

    mk_store(c, &st);
    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_create_stored(&st, tier, &gens, out_group_id, &sp, &pp);
    gy_group_secret_clear(&sp);
    return rc;
}

int
gy_custodian_group_export_group_public_params(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN], uint8_t *out,
    size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_public_params_encode(tier, &pp, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_export_key_envelope(gy_custodian *c,
                                       const uint8_t group_id[GY_GROUP_ID_LEN],
                                       uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    uint8_t frame[GY_GROUP_ENVELOPE_HDR_LEN + GY_GROUP_ENVELOPE_FMTVER_LEN +
                  GY_GROUP_MASTER_KEY_MAX];
    uint16_t fmtver = 0;
    size_t gmklen = 0, fn = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || out_len == NULL)
        return GY_ERR_ARG;

    mk_store(c, &st);
    rc = gy_group_format_version_load(&st, tier, group_id, &fmtver);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_master_key_load(&st, tier, group_id, gmk, sizeof(gmk),
                                  &gmklen);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_key_distribution_encode(tier, fmtver, gmk, gmklen, frame,
                                          sizeof(frame), &fn);
    gy_secure_zero(gmk, sizeof(gmk));
    if (rc != GY_OK)
        return rc;
    rc = emit(frame, fn, out, out_len);
    gy_secure_zero(frame, sizeof(frame));
    return rc;
}

int
gy_custodian_group_install_key_envelope(gy_custodian *c, const uint8_t *env,
                                        size_t env_len,
                                        uint8_t out_group_id[GY_GROUP_ID_LEN])
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    uint16_t fmtver = 0;
    size_t gmklen = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (env == NULL || out_group_id == NULL)
        return GY_ERR_ARG;

    rc = gy_group_key_distribution_decode(tier, env, env_len, &fmtver, gmk,
                                          sizeof(gmk), &gmklen);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    mk_store(c, &st);
    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK) {
        gy_secure_zero(gmk, sizeof(gmk));
        return rc;
    }
    /* install checks the version window: an unsupported epoch is
     * GY_ERR_UNSUPPORTED, propagated (not masked to VERIFY). */
    rc = gy_group_install_master_key(&st, tier, &gens, gmk, gmklen, fmtver,
                                     out_group_id, &sp, &pp);
    gy_secure_zero(gmk, sizeof(gmk));
    gy_group_secret_clear(&sp);
    return rc;
}

int
gy_custodian_group_forget(gy_custodian *c,
                          const uint8_t group_id[GY_GROUP_ID_LEN])
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL)
        return GY_ERR_ARG;

    mk_store(c, &st);
    rc = gy_group_delete_stored(&st, tier, group_id);
    /* Best-effort drop of any outstanding blind-issuance state for the group. */
    (void)c->sealed_store.delete_record(
        c->sealed_store.ctx, FAC_KIND_BLIND_STATE, group_id, GY_GROUP_ID_LEN);
    return rc;
}

/* ---- credentials -------------------------------------------------------- */

int
gy_custodian_group_receive_auth_credential(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t redemption_date,
    const uint8_t *resp, size_t resp_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_auth_response ar;
    struct gy_group_mac_tag out_cred;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || uid == NULL || resp == NULL)
        return GY_ERR_ARG;

    rc = gy_group_auth_response_decode(tier, &ar, resp, resp_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK)
        return rc;
    rc = load_srv(c, tier, &pp_A, &pp_P);
    if (rc != GY_OK)
        return rc;
    mk_store(c, &st);
    return gy_group_get_auth_credential_stored(&st, tier, &gens, &pp_A,
                                               group_id, uid, redemption_date,
                                               &ar, &out_cred);
}

int
gy_custodian_group_profile_key_commit(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_pk_commitment commit;
    uint8_t version[GY_GROUP_PK_VERSION_BYTES];
    uint8_t scratch[FACADE_SCRATCH];
    const uint8_t *uid;
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || profile_key == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;

    mk_store(c, &st);
    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_commit_to_profile_key_stored(&st, tier, &gens, group_id, uid,
                                               profile_key, version, &commit);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_commit_encode(tier, &commit, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_pk_credential_request(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_generators gens;
    struct gy_group_pk_request req;
    uint8_t y[GY_GROUP_SCALAR_MAX];
    uint8_t version[GY_GROUP_PK_VERSION_BYTES];
    uint8_t scratch[FACADE_SCRATCH];
    uint8_t stblob[sizeof(struct gy_group_pk_request) + GY_GROUP_SCALAR_MAX];
    const uint8_t *uid;
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || profile_key == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;

    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_get_pk_credential_request(tier, &gens, uid, profile_key,
                                            version, &req, y);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_request_encode(tier, &req, scratch, sizeof(scratch), &n);
    if (rc != GY_OK) {
        gy_secure_zero(y, sizeof(y));
        return rc;
    }
    /* Seal the transient blinding state (req || y) for the matching finish. */
    memcpy(stblob, &req, sizeof(req));
    memcpy(stblob + sizeof(req), y, sizeof(y));
    gy_secure_zero(y, sizeof(y));
    rc = c->sealed_store.store_record(c->sealed_store.ctx, FAC_KIND_BLIND_STATE,
                                      group_id, GY_GROUP_ID_LEN, stblob,
                                      sizeof(stblob));
    gy_secure_zero(stblob, sizeof(stblob));
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_pk_credential_finish(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], const uint8_t *resp,
    size_t resp_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_pk_request req;
    struct gy_group_pk_blind_response br;
    struct gy_group_mac_tag out_cred;
    uint8_t y[GY_GROUP_SCALAR_MAX];
    uint8_t stblob[sizeof(struct gy_group_pk_request) + GY_GROUP_SCALAR_MAX];
    const uint8_t *uid;
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || profile_key == NULL || resp == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;

    rc = c->sealed_store.load_record(c->sealed_store.ctx, FAC_KIND_BLIND_STATE,
                                     group_id, GY_GROUP_ID_LEN, stblob,
                                     sizeof(stblob), &n);
    if (rc != GY_OK)
        return rc;
    if (n == 0)
        return GY_ERR_STATE; /* no outstanding request */
    if (n != sizeof(stblob)) {
        gy_secure_zero(stblob, sizeof(stblob));
        return GY_ERR_VERIFY;
    }
    memcpy(&req, stblob, sizeof(req));
    memcpy(y, stblob + sizeof(req), sizeof(y));
    gy_secure_zero(stblob, sizeof(stblob));

    rc = gy_group_pk_response_decode(tier, &br, resp, resp_len);
    if (rc != GY_OK) {
        gy_secure_zero(y, sizeof(y));
        return GY_ERR_VERIFY;
    }
    rc = gy_group_generators_derive(tier, &gens);
    if (rc != GY_OK) {
        gy_secure_zero(y, sizeof(y));
        return rc;
    }
    rc = load_srv(c, tier, &pp_A, &pp_P);
    if (rc != GY_OK) {
        gy_secure_zero(y, sizeof(y));
        return rc;
    }
    mk_store(c, &st);
    rc = gy_group_get_pk_credential_finish_stored(
        &st, tier, &gens, &pp_P, group_id, uid, &req, y, &br, &out_cred);
    gy_secure_zero(y, sizeof(y));
    if (rc == GY_OK)
        (void)c->sealed_store.delete_record(c->sealed_store.ctx,
                                            FAC_KIND_BLIND_STATE, group_id,
                                            GY_GROUP_ID_LEN);
    return rc;
}

/* ---- presentations ------------------------------------------------------ */

int
gy_custodian_group_auth_present(gy_custodian *c,
                                const uint8_t group_id[GY_GROUP_ID_LEN],
                                uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_auth_presentation pres;
    uint8_t scratch[FACADE_SCRATCH];
    const uint8_t *uid;
    uint64_t now;
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (c->clock == NULL)
        return GY_ERR_STATE; /* daily credentials need the D-SES-7 clock */
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;
    now = c->clock(c->clock_ctx);

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = load_srv(c, tier, &pp_A, &pp_P);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = gy_group_auth_as_member_stored(&st, tier, &gens, &sp, &pp, &pp_A,
                                        group_id, uid, now, &pres);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_auth_pres_encode(tier, &pres, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_add_member(gy_custodian *c,
                              const uint8_t group_id[GY_GROUP_ID_LEN],
                              const uint8_t new_uid[GY_GROUP_UID_BYTES],
                              const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                              uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_pk_presentation pres;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || new_uid == NULL || new_pk == NULL ||
        out_len == NULL)
        return GY_ERR_ARG;

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = load_srv(c, tier, &pp_A, &pp_P);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = gy_group_add_member_stored(&st, tier, &gens, &sp, &pp, &pp_P, group_id,
                                    new_uid, new_pk, &pres);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_pres_encode(tier, &pres, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_add_invited_member(gy_custodian *c,
                                      const uint8_t group_id[GY_GROUP_ID_LEN],
                                      const uint8_t new_uid[GY_GROUP_UID_BYTES],
                                      uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_uid_ct uct;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || new_uid == NULL || out_len == NULL)
        return GY_ERR_ARG;

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = gy_group_add_invited_member(tier, &sp, new_uid, &uct);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_uid_ct_encode(tier, &uct, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_update_profile_key(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_mac_tag own_cred;
    struct gy_group_pk_presentation pres;
    uint8_t scratch[FACADE_SCRATCH];
    const uint8_t *uid;
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || new_pk == NULL || out_len == NULL)
        return GY_ERR_ARG;
    rc = self_uid(c, &uid);
    if (rc != GY_OK)
        return rc;

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = load_srv(c, tier, &pp_A, &pp_P);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = gy_group_pk_cred_load(&st, tier, group_id, uid, &own_cred);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc; /* GY_ERR_NOT_FOUND: acquire a ProfileKeyCredential first */
    }
    rc = gy_group_update_profile_key_stored(&st, tier, &gens, &sp, &pp, &pp_P,
                                            &own_cred, group_id, uid, new_pk,
                                            &pres);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_pres_encode(tier, &pres, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_custodian_group_delete_member(gy_custodian *c,
                                 const uint8_t group_id[GY_GROUP_ID_LEN],
                                 const uint8_t target_uid[GY_GROUP_UID_BYTES],
                                 uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_uid_ct uct;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || target_uid == NULL || out_len == NULL)
        return GY_ERR_ARG;

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }
    rc = gy_group_delete_member_stored(&st, tier, &sp, group_id, target_uid,
                                       &uct);
    gy_group_secret_clear(&sp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_uid_ct_encode(tier, &uct, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

/* ---- roster read -------------------------------------------------------- */

int
gy_custodian_group_fetch_members(gy_custodian *c,
                                 const uint8_t group_id[GY_GROUP_ID_LEN],
                                 const uint8_t *member_list_wire,
                                 size_t wire_len, gy_group_member_view *out,
                                 size_t max, size_t *out_count)
{
    const struct gy_group_tier *tier;
    struct gy_group_store st;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    struct gy_group_member_ct *cts = NULL;
    struct gy_group_member *mem = NULL;
    size_t nct = 0, dec = 0, i;
    int rc;

    rc = group_guard(c, &tier);
    if (rc != GY_OK)
        return rc;
    if (group_id == NULL || member_list_wire == NULL || out_count == NULL)
        return GY_ERR_ARG;

    rc = load_group(c, tier, &st, group_id, &gens, &sp, &pp);
    if (rc != GY_OK) {
        gy_group_secret_clear(&sp);
        return rc;
    }

    cts = calloc(GY_GROUP_MAX_ENTRIES, sizeof(*cts));
    if (cts == NULL) {
        gy_group_secret_clear(&sp);
        return GY_ERR_CRYPTO;
    }
    rc = gy_group_member_list_decode(tier, cts, GY_GROUP_MAX_ENTRIES, &nct,
                                     member_list_wire, wire_len);
    if (rc != GY_OK) {
        free(cts);
        gy_group_secret_clear(&sp);
        return GY_ERR_VERIFY;
    }

    if (out == NULL) {
        *out_count = nct;
        free(cts);
        gy_group_secret_clear(&sp);
        return GY_OK;
    }
    if (nct > max) {
        free(cts);
        gy_group_secret_clear(&sp);
        return GY_ERR_TOOLONG;
    }

    mem = gy_secure_alloc((nct ? nct : 1) * sizeof(*mem));
    if (mem == NULL) {
        free(cts);
        gy_group_secret_clear(&sp);
        return GY_ERR_CRYPTO;
    }
    rc = gy_group_fetch_members(tier, &sp, cts, nct, mem, nct, &dec);
    gy_group_secret_clear(&sp);
    free(cts);
    if (rc != GY_OK) {
        gy_secure_zero(mem, (nct ? nct : 1) * sizeof(*mem));
        gy_secure_free(mem);
        return GY_ERR_VERIFY;
    }

    for (i = 0; i < dec; i++) {
        memcpy(out[i].uid, mem[i].uid, GY_GROUP_UID_BYTES);
        memcpy(out[i].profile_key, mem[i].profile_key,
               GY_GROUP_PROFILEKEY_BYTES);
        out[i].role = mem[i].role;
        out[i].has_profile_key = mem[i].has_profile_key;
    }
    *out_count = dec;
    gy_secure_zero(mem, (nct ? nct : 1) * sizeof(*mem));
    gy_secure_free(mem);
    return GY_OK;
}
