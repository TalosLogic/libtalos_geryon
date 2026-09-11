/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * group_facade_server.c - the public server API (include/geryon_group_server.h)
 * over the internal group crypto.  A gy_group_server holds only the sealed
 * ServerSecretParams (sk_A + sk_P); it carries no user identity, no messaging,
 * and no per-group state.  Sealing composes core primitives directly
 * (gy_kekprot_wrap over the credential, gy_seal over the raw key structs), so
 * this target links only geryon_group_internal + core: it never reaches the
 * messaging custodian.  Every operation is a pure function of its inputs and
 * the key (GROUP_SPEC section 8.2); the per-group public key a verify needs is
 * a caller-supplied input, not held state.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "geryon_group_server.h"

#include "kekprot.h"
#include "pwhash.h"
#include "rng.h"
#include "seal.h"
#include "util.h"

#include "talos_schnorr.h" /* talos_schnorr_init */

#include "group_attr.h" /* GY_GROUP_ATTR_AUTH / _PROFILE */
#include "group_cred.h"
#include "group_issue.h"
#include "group_mac.h"
#include "group_ops.h" /* gy_group_member_ct, member_list_encode, MAX_ENTRIES */
#include "group_params.h"
#include "group_pres.h"
#include "group_tier.h"
#include "group_venc.h"

/* Scratch large enough for any single server-emitted object (the pk
 * presentation dominates; well under this). */
#define FACADE_SCRATCH 4096

/* Sealed-key blob framing: version || suite_id || wrap_len(2 BE) || wrap ||
 * sealed(sk_A || sk_P). */
#define FACADE_SRV_BLOB_VERSION 0x01

/* Domain-separation label for the server-key seal (suite_id appended at use). */
static const uint8_t SRV_KEY_AD[] = "geryon.group.server.key.v1";

struct gy_group_server {
    const struct gy_group_tier *tier;
    uint8_t suite_id;
    struct gy_group_generators gens;
    struct gy_group_server_secret sk_A; /* n_bound = GY_GROUP_ATTR_AUTH */
    struct gy_group_server_secret sk_P; /* n_bound = GY_GROUP_ATTR_PROFILE */
};

#define SRV_SK_PT_LEN (2 * sizeof(struct gy_group_server_secret))

/* Copy-out per the OpenSSL-style size-query convention: out == NULL reports the
 * required size in *out_len; otherwise *out_len is the capacity in / length
 * out. */
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

/* Build the seal AD = SRV_KEY_AD || suite_id into ad (cap >= sizeof SRV_KEY_AD),
 * returning its length. */
static size_t
srv_ad(uint8_t *ad, uint8_t suite_id)
{
    memcpy(ad, SRV_KEY_AD, sizeof(SRV_KEY_AD) - 1);
    ad[sizeof(SRV_KEY_AD) - 1] = suite_id;
    return sizeof(SRV_KEY_AD); /* (sizeof-1) label bytes + 1 suite byte */
}

static int
srv_persist(const struct gy_group_server *s,
            const struct gy_group_server_store *store, const uint8_t *cred,
            size_t cred_len)
{
    uint8_t ad[sizeof(SRV_KEY_AD)];
    uint8_t kek[GY_KEKPROT_KEK_LEN];
    uint8_t wrap[GY_KEKPROT_MAX_BLOB];
    uint8_t *pt = NULL;
    uint8_t sealed[SRV_SK_PT_LEN + GY_SEAL_MAX_OVERHEAD];
    uint8_t blob[GY_GROUP_SERVER_KEY_BLOB_MAX];
    size_t adlen, wrap_len = 0, sealed_len = 0, off;
    int rc;

    adlen = srv_ad(ad, s->suite_id);

    pt = gy_secure_alloc(SRV_SK_PT_LEN);
    if (pt == NULL)
        return GY_ERR_CRYPTO;

    rc = gy_random_bytes(kek, sizeof(kek));
    if (rc != GY_OK)
        goto out;
    wrap_len = sizeof(wrap); /* capacity in (gy_kekprot_wrap size convention) */
    rc = gy_kekprot_wrap(wrap, &wrap_len, GY_SEAL_ALG_XCHACHA20POLY1305,
                         GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN, cred,
                         cred_len, ad, adlen, kek);
    if (rc != GY_OK)
        goto out;

    memcpy(pt, &s->sk_A, sizeof(s->sk_A));
    memcpy(pt + sizeof(s->sk_A), &s->sk_P, sizeof(s->sk_P));
    sealed_len = sizeof(sealed); /* capacity in (gy_seal size convention) */
    rc = gy_seal(sealed, &sealed_len, kek, GY_SEAL_ALG_XCHACHA20POLY1305, ad,
                 adlen, pt, SRV_SK_PT_LEN);
    if (rc != GY_OK)
        goto out;

    off = 0;
    if (2 + 2 + wrap_len + sealed_len > sizeof(blob)) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    blob[off++] = FACADE_SRV_BLOB_VERSION;
    blob[off++] = s->suite_id;
    blob[off++] = (uint8_t)(wrap_len >> 8);
    blob[off++] = (uint8_t)(wrap_len & 0xff);
    memcpy(blob + off, wrap, wrap_len);
    off += wrap_len;
    memcpy(blob + off, sealed, sealed_len);
    off += sealed_len;

    rc = store->store(store->ctx, blob, off);

out:
    gy_secure_zero(kek, sizeof(kek));
    if (pt != NULL)
        gy_secure_free(pt);
    gy_secure_zero(sealed, sizeof(sealed));
    gy_secure_zero(blob, sizeof(blob));
    return rc;
}

int
gy_group_server_create(gy_group_server **out, uint8_t suite_id,
                       const gy_group_server_store *store, const uint8_t *cred,
                       size_t cred_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_server *s;
    int rc;

    if (out == NULL || store == NULL || store->store == NULL || cred == NULL)
        return GY_ERR_ARG;
    *out = NULL;
    tier = gy_group_tier_for(suite_id);
    if (tier == NULL)
        return GY_ERR_ARG; /* hybrid/unknown suite: no classical group server */
    if (gy_core_init() != GY_OK || talos_schnorr_init() != 0)
        return GY_ERR_CRYPTO;

    s = gy_secure_alloc(sizeof(*s));
    if (s == NULL)
        return GY_ERR_CRYPTO;
    memset(s, 0, sizeof(*s));
    s->tier = tier;
    s->suite_id = suite_id;

    rc = gy_group_generators_derive(tier, &s->gens);
    if (rc != GY_OK)
        goto fail;
    rc = gy_group_server_keygen(tier, &s->gens, GY_GROUP_ATTR_AUTH, &s->sk_A);
    if (rc != GY_OK)
        goto fail;
    rc =
        gy_group_server_keygen(tier, &s->gens, GY_GROUP_ATTR_PROFILE, &s->sk_P);
    if (rc != GY_OK)
        goto fail;
    rc = srv_persist(s, store, cred, cred_len);
    if (rc != GY_OK)
        goto fail;

    *out = s;
    return GY_OK;

fail:
    gy_group_server_secret_clear(&s->sk_A);
    gy_group_server_secret_clear(&s->sk_P);
    gy_secure_free(s);
    return rc;
}

int
gy_group_server_open(gy_group_server **out, const gy_group_server_store *store,
                     const uint8_t *cred, size_t cred_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_server *s;
    uint8_t ad[sizeof(SRV_KEY_AD)];
    uint8_t kek[GY_KEKPROT_KEK_LEN];
    uint8_t blob[GY_GROUP_SERVER_KEY_BLOB_MAX];
    uint8_t *pt = NULL;
    size_t adlen, blob_len = 0, wrap_len, off, ptlen = 0;
    uint8_t suite_id;
    int rc;

    if (out == NULL || store == NULL || store->load == NULL || cred == NULL)
        return GY_ERR_ARG;
    *out = NULL;
    if (gy_core_init() != GY_OK || talos_schnorr_init() != 0)
        return GY_ERR_CRYPTO;

    rc = store->load(store->ctx, blob, sizeof(blob), &blob_len);
    if (rc != GY_OK)
        return rc;
    if (blob_len == 0)
        return GY_ERR_STATE; /* nothing was ever stored */
    if (blob_len < 4)
        return GY_ERR_VERIFY;
    if (blob[0] != FACADE_SRV_BLOB_VERSION)
        return GY_ERR_VERIFY;
    suite_id = blob[1];
    tier = gy_group_tier_for(suite_id);
    if (tier == NULL)
        return GY_ERR_VERIFY;
    wrap_len = ((size_t)blob[2] << 8) | blob[3];
    off = 4;
    if (wrap_len > blob_len - off)
        return GY_ERR_VERIFY;

    adlen = srv_ad(ad, suite_id);
    rc =
        gy_kekprot_unwrap(kek, cred, cred_len, ad, adlen, blob + off, wrap_len);
    if (rc != GY_OK) {
        gy_secure_zero(kek, sizeof(kek));
        return GY_ERR_VERIFY; /* wrong credential or tampered blob: uniform */
    }
    off += wrap_len;

    pt = gy_secure_alloc(SRV_SK_PT_LEN);
    if (pt == NULL) {
        gy_secure_zero(kek, sizeof(kek));
        return GY_ERR_CRYPTO;
    }
    ptlen = SRV_SK_PT_LEN; /* capacity in (gy_unseal size convention) */
    rc = gy_unseal(pt, &ptlen, kek, ad, adlen, blob + off, blob_len - off);
    gy_secure_zero(kek, sizeof(kek));
    if (rc != GY_OK || ptlen != SRV_SK_PT_LEN) {
        gy_secure_free(pt);
        return GY_ERR_VERIFY;
    }

    s = gy_secure_alloc(sizeof(*s));
    if (s == NULL) {
        gy_secure_zero(pt, SRV_SK_PT_LEN);
        gy_secure_free(pt);
        return GY_ERR_CRYPTO;
    }
    memset(s, 0, sizeof(*s));
    s->tier = tier;
    s->suite_id = suite_id;
    memcpy(&s->sk_A, pt, sizeof(s->sk_A));
    memcpy(&s->sk_P, pt + sizeof(s->sk_A), sizeof(s->sk_P));
    gy_secure_zero(pt, SRV_SK_PT_LEN);
    gy_secure_free(pt);

    rc = gy_group_generators_derive(tier, &s->gens);
    if (rc != GY_OK) {
        gy_group_server_secret_clear(&s->sk_A);
        gy_group_server_secret_clear(&s->sk_P);
        gy_secure_free(s);
        return rc;
    }

    *out = s;
    return GY_OK;
}

void
gy_group_server_close(gy_group_server *s)
{
    if (s == NULL)
        return;
    gy_group_server_secret_clear(&s->sk_A);
    gy_group_server_secret_clear(&s->sk_P);
    gy_secure_free(s);
}

int
gy_group_server_export_public(gy_group_server *s, uint8_t *out, size_t *out_len)
{
    struct gy_group_server_public pp_A, pp_P;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n_a = 0, n_p = 0;
    int rc;

    if (s == NULL || out_len == NULL)
        return GY_ERR_ARG;

    rc = gy_group_server_public_from_secret(s->tier, &s->gens, &s->sk_A, &pp_A);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_server_public_from_secret(s->tier, &s->gens, &s->sk_P, &pp_P);
    if (rc != GY_OK)
        return rc;

    /* ServerPublicParams = (iparams_A, iparams_P): the two tagged objects
     * concatenated. */
    rc = gy_group_server_public_encode(s->tier, &pp_A, scratch, sizeof(scratch),
                                       &n_a);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_server_public_encode(s->tier, &pp_P, scratch + n_a,
                                       sizeof(scratch) - n_a, &n_p);
    if (rc != GY_OK)
        return rc;

    return emit(scratch, n_a + n_p, out, out_len);
}

int
gy_group_server_issue_auth(gy_group_server *s, const uint8_t uid[16],
                           uint64_t redemption_date, uint8_t *out,
                           size_t *out_len)
{
    struct gy_group_auth_response resp;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    if (s == NULL || uid == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (redemption_date % 86400ull != 0)
        return GY_ERR_ARG; /* day-aligned only, never rounded */

    rc = gy_group_auth_issue(s->tier, &s->gens, &s->sk_A, uid, redemption_date,
                             &resp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_auth_response_encode(s->tier, &resp, scratch, sizeof(scratch),
                                       &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_group_server_blind_issue_pk(gy_group_server *s, const uint8_t uid[16],
                               const uint8_t *commit, size_t commit_len,
                               const uint8_t *request, size_t request_len,
                               uint8_t *out, size_t *out_len)
{
    struct gy_group_pk_commitment commitment;
    struct gy_group_pk_request req;
    struct gy_group_pk_blind_response resp;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    if (s == NULL || uid == NULL || commit == NULL || request == NULL ||
        out_len == NULL)
        return GY_ERR_ARG;

    rc = gy_group_pk_commit_decode(s->tier, &commitment, commit, commit_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_pk_request_decode(s->tier, &req, request, request_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    rc = gy_group_pk_blind_issue(s->tier, &s->gens, &s->sk_P, uid, &commitment,
                                 &req, &resp);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_response_encode(s->tier, &resp, scratch, sizeof(scratch),
                                     &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out, out_len);
}

int
gy_group_server_verify_auth(gy_group_server *s, const uint8_t *group_pub,
                            size_t group_pub_len, const uint8_t *pres,
                            size_t pres_len, uint8_t *out_uid_ct,
                            size_t *out_uid_ct_len)
{
    struct gy_group_public_params pp_pub;
    struct gy_group_auth_presentation ap;
    struct gy_group_uid_ct uct;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    if (s == NULL || group_pub == NULL || pres == NULL)
        return GY_ERR_ARG;

    rc = gy_group_public_params_decode(s->tier, &pp_pub, group_pub,
                                       group_pub_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_auth_pres_decode(s->tier, &ap, pres, pres_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    rc =
        gy_group_auth_present_verify(s->tier, &s->gens, &s->sk_A, &pp_pub, &ap);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    if (out_uid_ct == NULL && out_uid_ct_len == NULL)
        return GY_OK; /* caller does not want the ciphertext */

    memset(&uct, 0, sizeof(uct));
    memcpy(uct.E_A1, ap.E_A1, s->tier->point_len);
    memcpy(uct.E_A2, ap.E_A2, s->tier->point_len);
    rc = gy_group_uid_ct_encode(s->tier, &uct, scratch, sizeof(scratch), &n);
    if (rc != GY_OK)
        return rc;
    return emit(scratch, n, out_uid_ct, out_uid_ct_len);
}

int
gy_group_server_verify_pk(gy_group_server *s, const uint8_t *group_pub,
                          size_t group_pub_len, const uint8_t *pres,
                          size_t pres_len, uint8_t *out_uid_ct,
                          size_t *out_uid_ct_len, uint8_t *out_pk_ct,
                          size_t *out_pk_ct_len)
{
    struct gy_group_public_params pp_pub;
    struct gy_group_pk_presentation pp;
    struct gy_group_uid_ct uct;
    struct gy_group_pk_ct pct;
    uint8_t scratch[FACADE_SCRATCH];
    size_t n = 0;
    int rc;

    if (s == NULL || group_pub == NULL || pres == NULL)
        return GY_ERR_ARG;

    rc = gy_group_public_params_decode(s->tier, &pp_pub, group_pub,
                                       group_pub_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_pk_pres_decode(s->tier, &pp, pres, pres_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    rc = gy_group_pk_present_verify(s->tier, &s->gens, &s->sk_P, &pp_pub, &pp);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    if (out_uid_ct != NULL || out_uid_ct_len != NULL) {
        memset(&uct, 0, sizeof(uct));
        memcpy(uct.E_A1, pp.E_A1, s->tier->point_len);
        memcpy(uct.E_A2, pp.E_A2, s->tier->point_len);
        rc =
            gy_group_uid_ct_encode(s->tier, &uct, scratch, sizeof(scratch), &n);
        if (rc != GY_OK)
            return rc;
        rc = emit(scratch, n, out_uid_ct, out_uid_ct_len);
        if (rc != GY_OK)
            return rc;
    }
    if (out_pk_ct != NULL || out_pk_ct_len != NULL) {
        memset(&pct, 0, sizeof(pct));
        memcpy(pct.E_B1, pp.E_B1, s->tier->point_len);
        memcpy(pct.E_B2, pp.E_B2, s->tier->point_len);
        rc = gy_group_pk_ct_encode(s->tier, &pct, scratch, sizeof(scratch), &n);
        if (rc != GY_OK)
            return rc;
        rc = emit(scratch, n, out_pk_ct, out_pk_ct_len);
        if (rc != GY_OK)
            return rc;
    }
    return GY_OK;
}

int
gy_group_server_member_list_encode(uint8_t suite_id,
                                   const struct gy_group_server_member *members,
                                   size_t n, uint8_t *out, size_t *out_len)
{
    const struct gy_group_tier *tier;
    struct gy_group_member_ct *cts;
    uint8_t *scratch;
    size_t i, need, sc_len = 0;
    int rc;

    if (out_len == NULL || (members == NULL && n != 0))
        return GY_ERR_ARG;
    tier = gy_group_tier_for(suite_id);
    if (tier == NULL)
        return GY_ERR_ARG;
    if (n > GY_GROUP_MAX_ENTRIES)
        return GY_ERR_TOOLONG;

    cts = calloc(n ? n : 1, sizeof(*cts));
    if (cts == NULL)
        return GY_ERR_CRYPTO;
    for (i = 0; i < n; i++) {
        rc = gy_group_uid_ct_decode(tier, &cts[i].uid_ct, members[i].uid_ct,
                                    members[i].uid_ct_len);
        if (rc != GY_OK) {
            free(cts);
            return GY_ERR_VERIFY;
        }
        cts[i].role = members[i].role;
        cts[i].has_profile_key = members[i].has_profile_key;
        if (members[i].has_profile_key) {
            if (members[i].pk_ct == NULL) {
                free(cts);
                return GY_ERR_ARG;
            }
            rc = gy_group_pk_ct_decode(tier, &cts[i].pk_ct, members[i].pk_ct,
                                       members[i].pk_ct_len);
            if (rc != GY_OK) {
                free(cts);
                return GY_ERR_VERIFY;
            }
        }
        /* invited: cts[i].pk_ct stays all-zero (calloc), as the wire requires */
    }

    need = 3 + n * (2 + 4 * tier->point_len) + 16;
    scratch = calloc(1, need);
    if (scratch == NULL) {
        free(cts);
        return GY_ERR_CRYPTO;
    }
    rc = gy_group_member_list_encode(tier, cts, n, scratch, need, &sc_len);
    free(cts);
    if (rc != GY_OK) {
        free(scratch);
        return rc;
    }
    rc = emit(scratch, sc_len, out, out_len);
    free(scratch);
    return rc;
}
