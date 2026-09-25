/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_join.h"

#include "qspgs_keys.h" /* gy_qspgs_master_key_len */
#include "qspgs_labels.h"

#include "aead.h"
#include "encode.h" /* gy_info */
#include "error.h"
#include "mlkem512.h"
#include "suite.h" /* gy_suite_desc, struct gy_iov, GY_HASH_MAX */
#include "util.h"

/*
 * The QSPGS join keypair and its hybrid KEM-DEM public-key
 * encryption.  Deterministic keygen from gk goes through the suite curve
 * (a scalar-mult of the RFC 7748 base point, via desc->dh) and the production
 * derandomized ML-KEM keygen; the per-seal fusion is the HYBRID_SPEC PQ-first
 * combiner over the tier HKDF.  No arithmetic lives here.
 */

/* Longest gy_info domain here: "geryon.1." (9) + "geryon_h448_1024" (16) +
 * "." (1) + "qspgs-join-mlkem" (16) = 42; rounded up. */
#define QSPGS_JOIN_DOMAIN_MAX 48

/* AEAD for the DEM: the mandatory-to-implement default (project policy). */
#define QSPGS_JOIN_AEAD GY_AEAD_CHACHA20POLY1305

/*
 * RFC 7748 base points (little-endian u-coordinate): u = 9 for X25519, u = 5
 * for X448.  desc->dh(pk, sk, base) computes the public key sk * base, the
 * scalar-mult-base the curve wrappers do not expose separately.
 */
static const uint8_t qspgs_x25519_base[32] = {9};
static const uint8_t qspgs_x448_base[56] = {5};

/*
 * Resolve a hybrid descriptor, or GY_ERR_ARG.  When basep is non-NULL, also
 * resolve the curve base point (needed only by the keygen path).
 */
static int
join_prepare(uint8_t suite_id, const struct gy_suite_desc **descp,
             const uint8_t **basep)
{
    const struct gy_suite_desc *desc;

    if (gy_qspgs_master_key_len(suite_id) == 0)
        return GY_ERR_ARG;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;

    if (basep != NULL) {
        switch (desc->curve_type) {
        case GY_CURVE_TYPE_25519:
            *basep = qspgs_x25519_base;
            break;
        case GY_CURVE_TYPE_448:
            *basep = qspgs_x448_base;
            break;
        default:
            return GY_ERR_ARG;
        }
    }
    *descp = desc;
    return GY_OK;
}

/* One HKDF branch off gk: PRK = Extract(salt = domain, gk); out = Expand(PRK,
 * info = domain).  domain is gy_info(suite_id, purpose). */
static int
join_kdf_gk(const struct gy_suite_desc *desc, uint8_t suite_id,
            const char *purpose, const uint8_t *gk, size_t gklen, uint8_t *out,
            size_t outlen)
{
    uint8_t domain[QSPGS_JOIN_DOMAIN_MAX];
    uint8_t prk[GY_HASH_MAX];
    struct gy_iov ikm;
    size_t dlen;
    int rc;

    rc = gy_info(domain, sizeof(domain), &dlen, suite_id, purpose);
    if (rc != GY_OK)
        return rc;

    ikm.p = gk;
    ikm.len = gklen;
    rc = desc->hkdf_extract(prk, domain, dlen, &ikm, 1);
    if (rc == GY_OK)
        rc = desc->hkdf_expand(out, outlen, prk, domain, dlen);

    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

/* The DEM key: PRK = Extract(domain, kem_ss || dh) PQ-first; key = Expand(PRK,
 * domain, 32).  domain = gy_info(suite_id, "qspgs-join-kem"). */
static int
join_dem_key(const struct gy_suite_desc *desc, uint8_t suite_id,
             const uint8_t *kem_ss, size_t sslen, const uint8_t *dh,
             size_t dhlen, uint8_t key[GY_AEAD_KEY_LEN])
{
    uint8_t domain[QSPGS_JOIN_DOMAIN_MAX];
    uint8_t prk[GY_HASH_MAX];
    struct gy_iov ikm[2];
    size_t dlen;
    int rc;

    rc =
        gy_info(domain, sizeof(domain), &dlen, suite_id, GY_QSPGS_LBL_JOIN_KEM);
    if (rc != GY_OK)
        return rc;

    /* PQ-first: the ML-KEM secret precedes the ECDH output (HYBRID_SPEC). */
    ikm[0].p = kem_ss;
    ikm[0].len = sslen;
    ikm[1].p = dh;
    ikm[1].len = dhlen;
    rc = desc->hkdf_extract(prk, domain, dlen, ikm, 2);
    if (rc == GY_OK)
        rc = desc->hkdf_expand(key, GY_AEAD_KEY_LEN, prk, domain, dlen);

    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

/* Deterministic ML-KEM keygen from a 64-byte seed, dispatched by suite. */
static int
join_kem_keypair_seed(uint8_t suite_id, uint8_t *ek, uint8_t *dk,
                      const uint8_t *seed)
{
    switch (suite_id) {
    case GY_SUITE_H25519_512:
        return gy_mlkem512_keypair_derand(ek, dk, seed);
    case GY_SUITE_H448_1024:
        return gy_mlkem1024_keypair_derand(ek, dk, seed);
    default:
        return GY_ERR_ARG;
    }
}

int
gy_qspgs_join_derive(uint8_t suite_id, const uint8_t *gk,
                     gy_qspgs_join_pk_t *ipk, gy_qspgs_join_sk_t *isk)
{
    const struct gy_suite_desc *desc;
    const uint8_t *base;
    uint8_t kem_seed[GY_MLKEM1024_KEYPAIR_SEED];
    size_t gklen;
    int rc;

    if (gk == NULL || ipk == NULL || isk == NULL)
        return GY_ERR_ARG;
    rc = join_prepare(suite_id, &desc, &base);
    if (rc != GY_OK)
        return rc;
    gklen = gy_qspgs_master_key_len(suite_id);

    memset(ipk, 0, sizeof(*ipk));
    memset(isk, 0, sizeof(*isk));

    /* Curve branch: scalar from gk, public key = scalar * base. */
    rc = join_kdf_gk(desc, suite_id, GY_QSPGS_LBL_JOIN_EC, gk, gklen,
                     isk->curve_sk, desc->curve_sk_len);
    if (rc != GY_OK)
        goto err;
    rc = desc->dh(ipk->curve_pk, isk->curve_sk, base);
    if (rc != GY_OK)
        goto err;

    /* ML-KEM branch: independent seed from gk, then deterministic keygen. */
    rc = join_kdf_gk(desc, suite_id, GY_QSPGS_LBL_JOIN_MLKEM, gk, gklen,
                     kem_seed, sizeof(kem_seed));
    if (rc != GY_OK)
        goto err;
    rc =
        join_kem_keypair_seed(suite_id, ipk->mlkem_ek, isk->mlkem_dk, kem_seed);
    if (rc != GY_OK)
        goto err;

    ipk->suite_id = suite_id;
    isk->suite_id = suite_id;
    gy_secure_zero(kem_seed, sizeof(kem_seed));
    return GY_OK;

err:
    gy_secure_zero(kem_seed, sizeof(kem_seed));
    gy_qspgs_join_sk_clear(isk);
    memset(ipk, 0, sizeof(*ipk));
    return rc;
}

void
gy_qspgs_join_sk_clear(gy_qspgs_join_sk_t *isk)
{
    if (isk == NULL)
        return;
    gy_secure_zero(isk, sizeof(*isk));
}

size_t
gy_qspgs_join_overhead(uint8_t suite_id)
{
    const struct gy_suite_desc *desc;

    if (gy_qspgs_master_key_len(suite_id) == 0)
        return 0;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL || !desc->is_hybrid)
        return 0;
    return desc->curve_pk_len + desc->kem_ct_len +
           gy_aead_tag_len(QSPGS_JOIN_AEAD);
}

int
gy_qspgs_join_seal(const gy_qspgs_join_pk_t *ipk, const uint8_t *pt,
                   size_t ptlen, uint8_t *out, size_t cap, size_t *outlen)
{
    const struct gy_suite_desc *desc;
    uint8_t eph_sk[GY_QSPGS_JOIN_CURVE_MAX];
    uint8_t dh[GY_QSPGS_JOIN_CURVE_MAX];
    uint8_t kem_ss[GY_MLKEM1024_SS];
    uint8_t key[GY_AEAD_KEY_LEN];
    uint8_t nonce[GY_AEAD_MAX_NONCE];
    size_t off, adlen, nlen, ctcap, ctlen, need;
    int rc;

    if (ipk == NULL || pt == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    rc = join_prepare(ipk->suite_id, &desc, NULL);
    if (rc != GY_OK)
        return rc;

    need = desc->curve_pk_len + desc->kem_ct_len +
           gy_aead_tag_len(QSPGS_JOIN_AEAD) + ptlen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    memset(dh, 0, sizeof(dh));
    memset(kem_ss, 0, sizeof(kem_ss));
    memset(key, 0, sizeof(key));

    /* Fresh ephemeral curve pair; ship the public part, agree on dh. */
    rc = desc->keypair(out, eph_sk); /* eph public written at out[0..]. */
    if (rc != GY_OK)
        goto out;
    rc = desc->dh(dh, eph_sk, ipk->curve_pk);
    if (rc != GY_OK)
        goto out;

    /* ML-KEM encapsulation to ipk (fresh randomness), ct after the eph pk. */
    off = desc->curve_pk_len;
    rc = desc->kem_encap(out + off, kem_ss, ipk->mlkem_ek);
    if (rc != GY_OK)
        goto out;
    off += desc->kem_ct_len;

    rc = join_dem_key(desc, ipk->suite_id, kem_ss, desc->kem_ss_len, dh,
                      desc->dh_len, key);
    if (rc != GY_OK)
        goto out;

    /* AEAD-seal the payload; the KEM transcript (eph pk || ct) is the AD. */
    adlen = off;
    nlen = gy_aead_nonce_len(QSPGS_JOIN_AEAD);
    memset(nonce, 0, nlen); /* single-use key (fresh ephemerals) => zero IV. */
    ctcap = cap - off;
    ctlen = ctcap;
    rc = gy_aead_encrypt(QSPGS_JOIN_AEAD, out + off, &ctlen, key, nonce, nlen,
                         out, adlen, pt, ptlen);
    if (rc != GY_OK)
        goto out;
    *outlen = off + ctlen;

out:
    gy_secure_zero(eph_sk, sizeof(eph_sk));
    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(kem_ss, sizeof(kem_ss));
    gy_secure_zero(key, sizeof(key));
    return rc;
}

int
gy_qspgs_join_open(const gy_qspgs_join_sk_t *isk, const uint8_t *in,
                   size_t inlen, uint8_t *pt, size_t cap, size_t *ptlen)
{
    const struct gy_suite_desc *desc;
    uint8_t dh[GY_QSPGS_JOIN_CURVE_MAX];
    uint8_t kem_ss[GY_MLKEM1024_SS];
    uint8_t key[GY_AEAD_KEY_LEN];
    uint8_t nonce[GY_AEAD_MAX_NONCE];
    size_t off, adlen, nlen, taglen, ptcap;
    int rc;

    if (isk == NULL || in == NULL || pt == NULL || ptlen == NULL)
        return GY_ERR_ARG;
    rc = join_prepare(isk->suite_id, &desc, NULL);
    if (rc != GY_OK)
        return rc;

    taglen = gy_aead_tag_len(QSPGS_JOIN_AEAD);
    off = desc->curve_pk_len + desc->kem_ct_len;
    if (inlen < off + taglen)
        return GY_ERR_TOOLONG;

    memset(dh, 0, sizeof(dh));
    memset(kem_ss, 0, sizeof(kem_ss));
    memset(key, 0, sizeof(key));

    /* Ephemeral pk is in[0..curve_pk_len); agree on the same dh. */
    rc = desc->dh(dh, isk->curve_sk, in);
    if (rc != GY_OK)
        goto out;

    /* Decapsulate the ML-KEM ct; implicit rejection yields a pseudorandom ss,
     * so a forged ct fails only at the AEAD tag (no decapsulation oracle). */
    rc = desc->kem_decap(kem_ss, in + desc->curve_pk_len, isk->mlkem_dk);
    if (rc != GY_OK)
        goto out;

    rc = join_dem_key(desc, isk->suite_id, kem_ss, desc->kem_ss_len, dh,
                      desc->dh_len, key);
    if (rc != GY_OK)
        goto out;

    adlen = off;
    nlen = gy_aead_nonce_len(QSPGS_JOIN_AEAD);
    memset(nonce, 0, nlen);
    ptcap = cap;
    rc = gy_aead_decrypt(QSPGS_JOIN_AEAD, pt, &ptcap, key, nonce, nlen, in,
                         adlen, in + off, inlen - off);
    if (rc == GY_OK)
        *ptlen = ptcap;

out:
    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(kem_ss, sizeof(kem_ss));
    gy_secure_zero(key, sizeof(key));
    return rc;
}
