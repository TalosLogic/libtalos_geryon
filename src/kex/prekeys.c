/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "prekeys.h"

#ifdef GY_TEST_HOOKS
struct gy_kex_counters gy_kex_ctr;
#endif

/* Largest EncodeEC output across suites: curve_type byte + curve public key. */
#define GY_ENCODED_KEY_MAX (1 + GY_CURVE_PK_MAX)

/* signed_data = EncodeEC(pub) || timestamp_be64 (D-X3DH-4). */
#define GY_SPK_SIGNED_MAX (GY_ENCODED_KEY_MAX + 8)

/*
 * Recompute the PKID over EncodeEC(pub) and confirm it is present (non-zero,
 * constant-time) and matches the carried value (D-GEN-2, D-X3DH-14 step b).
 * Returns GY_OK on a match, GY_ERR_VERIFY on a zero or mismatched PKID.
 */
static int
check_pkid(const struct gy_suite_desc *desc, const struct gy_public_key *key)
{
    uint8_t enc[GY_ENCODED_KEY_MAX];
    uint32_t recomputed;
    int n, rc;

    if (!gy_pkid_is_present(key->pkid))
        return GY_ERR_VERIFY;

    n = gy_encode_ec(enc, sizeof(enc), key->curve_type, key->pk);
    if (n < 0)
        return n;

    GY_KEX_COUNT(hash);
    rc = gy_pkid(&recomputed, desc->suite_id, enc, (size_t)n);
    if (rc != GY_OK)
        return rc;

    /* PKID is public wire structure, so a plain comparison is fine here. */
    if (recomputed != key->pkid)
        return GY_ERR_VERIFY;
    return GY_OK;
}

/* Build EncodeEC(pub) || timestamp_be64 into out; store its length. */
static int
spk_signed_data(const struct gy_public_key *pub, uint64_t timestamp,
                uint8_t *out, size_t cap, size_t *outlen)
{
    int n;

    n = gy_encode_ec(out, cap, pub->curve_type, pub->pk);
    if (n < 0)
        return n;
    if (cap < (size_t)n + 8)
        return GY_ERR_ARG;

    gy_be64_put(out + n, timestamp);
    *outlen = (size_t)n + 8;
    return GY_OK;
}

/* True if pkid appears in existing[] or the first nbatch entries of batch[]. */
static int
pkid_forbidden(uint32_t pkid, const uint32_t *existing, size_t n_existing,
               const struct gy_keypair *batch, size_t nbatch)
{
    size_t i;

    for (i = 0; i < n_existing; i++) {
        if (existing[i] == pkid)
            return 1;
    }
    for (i = 0; i < nbatch; i++) {
        if (batch[i].pub.pkid == pkid)
            return 1;
    }
    return 0;
}

/*
 * Generate one key pair whose PKID is present and not forbidden, regenerating
 * on the zero sentinel or a collision.  Zeroizes out on any error.
 */
static int
gen_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out,
            const uint32_t *existing, size_t n_existing,
            const struct gy_keypair *batch, size_t nbatch)
{
    uint8_t enc[GY_ENCODED_KEY_MAX];
    uint32_t pkid;
    int n, rc;

    for (;;) {
        GY_KEX_COUNT(keypair);
        rc = desc->keypair(out->pub.pk, out->sk);
        if (rc != GY_OK)
            goto err;
        out->pub.curve_type = desc->curve_type;

        n = gy_encode_ec(enc, sizeof(enc), desc->curve_type, out->pub.pk);
        if (n < 0) {
            rc = n;
            goto err;
        }
        rc = gy_pkid(&pkid, desc->suite_id, enc, (size_t)n);
        if (rc != GY_OK)
            goto err;

        /* Regenerate on the zero sentinel or any collision (D-GEN-2). */
        if (!gy_pkid_is_present(pkid))
            continue;
        if (pkid_forbidden(pkid, existing, n_existing, batch, nbatch))
            continue;

        out->pub.pkid = pkid;
        return GY_OK;
    }

err:
    gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_keypair_generate(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    return gen_keypair(desc, out, NULL, 0, NULL, 0);
}

int
gy_spk_create(const struct gy_suite_desc *desc, struct gy_signed_prekey *out,
              const uint8_t *identity_sk, uint64_t timestamp)
{
    uint8_t signed_data[GY_SPK_SIGNED_MAX];
    size_t signed_len;
    int rc;

    if (desc == NULL || out == NULL || identity_sk == NULL)
        return GY_ERR_ARG;

    rc = gen_keypair(desc, &out->kp, NULL, 0, NULL, 0);
    if (rc != GY_OK)
        return rc;

    rc = spk_signed_data(&out->kp.pub, timestamp, signed_data,
                         sizeof(signed_data), &signed_len);
    if (rc != GY_OK)
        goto err;

    GY_KEX_COUNT(sign);
    rc = desc->sign(out->sig, identity_sk, signed_data, signed_len);
    if (rc != GY_OK)
        goto err;

    out->timestamp = timestamp;
    return GY_OK;

err:
    gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_opk_batch(const struct gy_suite_desc *desc, struct gy_keypair *out, size_t n,
             const uint32_t *existing, size_t n_existing)
{
    size_t i;
    int rc;

    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    if (n == 0 || n > GY_OPK_BATCH_MAX)
        return GY_ERR_ARG;
    if (existing == NULL && n_existing != 0)
        return GY_ERR_ARG;

    for (i = 0; i < n; i++) {
        rc = gen_keypair(desc, &out[i], existing, n_existing, out, i);
        if (rc != GY_OK) {
            gy_secure_zero(out, n * sizeof(*out));
            return rc;
        }
    }
    return GY_OK;
}

int
gy_bundle_validate(const struct gy_suite_desc *desc,
                   const struct gy_prekey_bundle *bundle)
{
    uint8_t signed_data[GY_SPK_SIGNED_MAX];
    size_t signed_len;
    int opk_present, rc;

    if (desc == NULL || bundle == NULL)
        return GY_ERR_ARG;

    /* (a) curve_type consistency: any mismatch is a cross-suite abort. */
    if (bundle->ik.curve_type != desc->curve_type)
        return GY_ERR_STATE;
    if (bundle->spk.curve_type != desc->curve_type)
        return GY_ERR_STATE;
    opk_present = gy_pkid_is_present(bundle->opk.pkid);
    if (opk_present && bundle->opk.curve_type != desc->curve_type)
        return GY_ERR_STATE;

    /* (b) PKID present and matches recomputation for every present key. */
    rc = check_pkid(desc, &bundle->ik);
    if (rc != GY_OK)
        return rc;
    rc = check_pkid(desc, &bundle->spk);
    if (rc != GY_OK)
        return rc;
    if (opk_present) {
        rc = check_pkid(desc, &bundle->opk);
        if (rc != GY_OK)
            return rc;
    }

    /* (c) SPK signature over the full signed_data, under the identity key. */
    rc = spk_signed_data(&bundle->spk, bundle->spk_timestamp, signed_data,
                         sizeof(signed_data), &signed_len);
    if (rc != GY_OK)
        return rc;

    GY_KEX_COUNT(verify);
    if (desc->verify(bundle->spk_sig, bundle->ik.pk, signed_data, signed_len) !=
        GY_OK)
        return GY_ERR_VERIFY;

    return GY_OK;
}

int
gy_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
               const struct gy_public_key *ik)
{
    uint8_t enc[GY_ENCODED_KEY_MAX];
    int n;

    if (desc == NULL || out == NULL || ik == NULL)
        return GY_ERR_ARG;

    n = gy_encode_ec(enc, sizeof(enc), ik->curve_type, ik->pk);
    if (n < 0)
        return n;

    GY_KEX_COUNT(hash);
    return desc->hash(out, enc, (size_t)n);
}

#ifdef GY_TEST_HOOKS
int
gy_kex_pkid_needs_regen(uint32_t pkid, const uint32_t *existing,
                        size_t n_existing)
{
    if (!gy_pkid_is_present(pkid))
        return 1;
    return pkid_forbidden(pkid, existing, n_existing, NULL, 0);
}
#endif

/* ------------------------------------------------------------------------- *
 * Hybrid suites (HYBRID_SPEC sections 4, 5).
 * ------------------------------------------------------------------------- */

/* Encoded hybrid public key (from curve_type): curve_type || curve_pk || ek. */
#define GY_HYBRID_PUB_ENC_MAX (1 + GY_CURVE_PK_MAX + GY_KEM_EK_MAX)
/* Encoded hybrid identity public key: adds mldsa_pk. */
#define GY_HYBRID_ID_ENC_MAX (GY_HYBRID_PUB_ENC_MAX + GY_DSA_PK_MAX)
/* signed_data = encoded_public_key || timestamp_be64 || flags_be64. */
#define GY_HYBRID_SIGNED_MAX (GY_HYBRID_PUB_ENC_MAX + 16)
/* ctx = INFO("prekey"), e.g. "geryon.1.h25519_512.prekey". */
#define GY_PREKEY_CTX_MAX 64

/* Encode a hybrid public key: curve_type || curve_pk || mlkem_ek (section 4.1). */
int
gy_hybrid_encode_pub(const struct gy_suite_desc *desc,
                     const struct gy_hybrid_public_key *pub, uint8_t *out,
                     size_t cap, size_t *outlen)
{
    int n;

    n = gy_encode_ec(out, cap, pub->curve.curve_type, pub->curve.pk);
    if (n < 0)
        return n;
    if (cap < (size_t)n + desc->kem_pk_len)
        return GY_ERR_ARG;
    memcpy(out + n, pub->mlkem_ek, desc->kem_pk_len);
    *outlen = (size_t)n + desc->kem_pk_len;
    return GY_OK;
}

/* Encode a hybrid identity public key: ... || mldsa_pk (section 4.2). */
int
gy_hybrid_encode_identity(const struct gy_suite_desc *desc,
                          const struct gy_hybrid_identity_public_key *pub,
                          uint8_t *out, size_t cap, size_t *outlen)
{
    size_t base;
    int rc;

    rc = gy_hybrid_encode_pub(desc, &pub->base, out, cap, &base);
    if (rc != GY_OK)
        return rc;
    if (cap < base + desc->dsa_pk_len)
        return GY_ERR_ARG;
    memcpy(out + base, pub->mldsa_pk, desc->dsa_pk_len);
    *outlen = base + desc->dsa_pk_len;
    return GY_OK;
}

/*
 * Recompute the PKID over an already-encoded hybrid key and confirm it is
 * present and matches the carried value (D-GEN-2, D-X3DH-14 step b).
 */
static int
hybrid_check_pkid(const struct gy_suite_desc *desc, const uint8_t *enc,
                  size_t enclen, uint32_t pkid)
{
    uint32_t recomputed;
    int rc;

    if (!gy_pkid_is_present(pkid))
        return GY_ERR_VERIFY;
    GY_KEX_COUNT(hash);
    rc = gy_pkid(&recomputed, desc->suite_id, enc, enclen);
    if (rc != GY_OK)
        return rc;
    if (recomputed != pkid)
        return GY_ERR_VERIFY;
    return GY_OK;
}

/* Build encoded_public_key || timestamp_be64 || flags_be64 (section 5.2). */
static int
hybrid_signed_data(const struct gy_suite_desc *desc,
                   const struct gy_hybrid_public_key *pub, uint64_t timestamp,
                   uint64_t flags, uint8_t *out, size_t cap, size_t *outlen)
{
    size_t enclen;
    int rc;

    rc = gy_hybrid_encode_pub(desc, pub, out, cap, &enclen);
    if (rc != GY_OK)
        return rc;
    if (cap < enclen + 16)
        return GY_ERR_ARG;
    gy_be64_put(out + enclen, timestamp);
    gy_be64_put(out + enclen + 8, flags);
    *outlen = enclen + 16;
    return GY_OK;
}

#ifdef GY_TEST_HOOKS
/* KAT-only exposures of the signed_data builders (prekeys.h; §11.2, D-GEN-6). */
int
gy_kex_spk_signed_data(const struct gy_public_key *pub, uint64_t timestamp,
                       uint8_t *out, size_t cap, size_t *outlen)
{
    return spk_signed_data(pub, timestamp, out, cap, outlen);
}

int
gy_kex_hybrid_signed_data(const struct gy_suite_desc *desc,
                          const struct gy_hybrid_public_key *pub,
                          uint64_t timestamp, uint64_t flags, uint8_t *out,
                          size_t cap, size_t *outlen)
{
    return hybrid_signed_data(desc, pub, timestamp, flags, out, cap, outlen);
}
#endif

/* The ML-DSA context string for prekey signing: INFO("prekey") (D-PQ-1). */
static int
prekey_ctx(const struct gy_suite_desc *desc, uint8_t *out, size_t cap,
           size_t *outlen)
{
    return gy_info(out, cap, outlen, desc->suite_id, "prekey");
}

/* True if pkid appears in existing[] or the first nbatch entries of batch[]. */
static int
hybrid_pkid_forbidden(uint32_t pkid, const uint32_t *existing,
                      size_t n_existing, const struct gy_hybrid_keypair *batch,
                      size_t nbatch)
{
    size_t i;

    for (i = 0; i < n_existing; i++) {
        if (existing[i] == pkid)
            return 1;
    }
    for (i = 0; i < nbatch; i++) {
        if (batch[i].pub.curve.pkid == pkid)
            return 1;
    }
    return 0;
}

/*
 * Generate one hybrid key pair (curve + ML-KEM) whose PKID is present and not
 * forbidden, regenerating on the zero sentinel or a collision.  Zeroizes out on
 * any error.
 */
static int
gen_hybrid_keypair(const struct gy_suite_desc *desc,
                   struct gy_hybrid_keypair *out, const uint32_t *existing,
                   size_t n_existing, const struct gy_hybrid_keypair *batch,
                   size_t nbatch)
{
    uint8_t enc[GY_HYBRID_PUB_ENC_MAX];
    size_t enclen;
    uint32_t pkid;
    int rc;

    for (;;) {
        GY_KEX_COUNT(keypair);
        rc = desc->keypair(out->pub.curve.pk, out->curve_sk);
        if (rc != GY_OK)
            goto err;
        out->pub.curve.curve_type = desc->curve_type;

        rc = desc->kem_keypair(out->pub.mlkem_ek, out->mlkem_dk);
        if (rc != GY_OK)
            goto err;

        rc = gy_hybrid_encode_pub(desc, &out->pub, enc, sizeof(enc), &enclen);
        if (rc != GY_OK)
            goto err;
        rc = gy_pkid(&pkid, desc->suite_id, enc, enclen);
        if (rc != GY_OK)
            goto err;

        if (!gy_pkid_is_present(pkid))
            continue;
        if (hybrid_pkid_forbidden(pkid, existing, n_existing, batch, nbatch))
            continue;

        out->pub.curve.pkid = pkid;
        return GY_OK;
    }

err:
    gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_hybrid_keypair_generate(const struct gy_suite_desc *desc,
                           struct gy_hybrid_keypair *out)
{
    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid)
        return GY_ERR_STATE;
    return gen_hybrid_keypair(desc, out, NULL, 0, NULL, 0);
}

int
gy_hybrid_identity_keypair_generate(const struct gy_suite_desc *desc,
                                    struct gy_hybrid_identity_keypair *out)
{
    uint8_t enc[GY_HYBRID_ID_ENC_MAX];
    size_t enclen;
    uint32_t pkid;
    int rc;

    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid)
        return GY_ERR_STATE;

    for (;;) {
        GY_KEX_COUNT(keypair);
        rc = desc->keypair(out->pub.base.curve.pk, out->curve_sk);
        if (rc != GY_OK)
            goto err;
        out->pub.base.curve.curve_type = desc->curve_type;

        rc = desc->kem_keypair(out->pub.base.mlkem_ek, out->mlkem_dk);
        if (rc != GY_OK)
            goto err;
        rc = desc->dsa_keypair(out->pub.mldsa_pk, out->mldsa_sk);
        if (rc != GY_OK)
            goto err;

        rc = gy_hybrid_encode_identity(desc, &out->pub, enc, sizeof(enc),
                                       &enclen);
        if (rc != GY_OK)
            goto err;
        rc = gy_pkid(&pkid, desc->suite_id, enc, enclen);
        if (rc != GY_OK)
            goto err;

        if (!gy_pkid_is_present(pkid))
            continue;

        out->pub.base.curve.pkid = pkid;
        return GY_OK;
    }

err:
    gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_hybrid_flags_validate(uint64_t flags)
{
    uint16_t mn = (uint16_t)(flags & 0xFFFF);
    uint16_t mx = (uint16_t)((flags >> 16) & 0xFFFF);

    if ((flags & (UINT64_C(1) << 32)) ==
        0) /* ChaCha20-Poly1305 MTI (section 5.3) */
        return GY_ERR_VERIFY;
    if ((flags >> 35) != 0) /* reserved bits 35..63 must be zero */
        return GY_ERR_VERIFY;
    if (mn < 1 || mn > mx || mx > 100)
        return GY_ERR_VERIFY;
    return GY_OK;
}

int
gy_hybrid_spk_create(const struct gy_suite_desc *desc,
                     struct gy_hybrid_signed_prekey *out,
                     const struct gy_hybrid_identity_keypair *ik,
                     uint64_t timestamp, uint64_t flags)
{
    uint8_t signed_data[GY_HYBRID_SIGNED_MAX];
    uint8_t ctx[GY_PREKEY_CTX_MAX];
    size_t signed_len, ctxlen;
    int rc;

    if (desc == NULL || out == NULL || ik == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid)
        return GY_ERR_STATE;

    rc = gy_hybrid_flags_validate(flags);
    if (rc != GY_OK)
        return rc;

    rc = gen_hybrid_keypair(desc, &out->kp, NULL, 0, NULL, 0);
    if (rc != GY_OK)
        return rc;

    rc = hybrid_signed_data(desc, &out->kp.pub, timestamp, flags, signed_data,
                            sizeof(signed_data), &signed_len);
    if (rc != GY_OK)
        goto err;

    /* Classical signature (XEdDSA) under the identity curve key. */
    GY_KEX_COUNT(sign);
    rc = desc->sign(out->ed_sig, ik->curve_sk, signed_data, signed_len);
    if (rc != GY_OK)
        goto err;

    /* PQ signature (ML-DSA) under the identity ML-DSA key, ctx = INFO("prekey"). */
    rc = prekey_ctx(desc, ctx, sizeof(ctx), &ctxlen);
    if (rc != GY_OK)
        goto err;
    GY_KEX_COUNT(sign);
    rc = desc->dsa_sign(out->mldsa_sig, ik->mldsa_sk, signed_data, signed_len,
                        ctx, ctxlen);
    if (rc != GY_OK)
        goto err;

    out->timestamp = timestamp;
    out->flags = flags;
    out->ik_id = ik->pub.base.curve.pkid;
    return GY_OK;

err:
    gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_hybrid_opk_batch(const struct gy_suite_desc *desc,
                    struct gy_hybrid_keypair *out, size_t n,
                    const uint32_t *existing, size_t n_existing)
{
    size_t i;
    int rc;

    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid)
        return GY_ERR_STATE;
    if (n == 0 || n > GY_OPK_BATCH_MAX)
        return GY_ERR_ARG;
    if (existing == NULL && n_existing != 0)
        return GY_ERR_ARG;

    for (i = 0; i < n; i++) {
        rc = gen_hybrid_keypair(desc, &out[i], existing, n_existing, out, i);
        if (rc != GY_OK) {
            gy_secure_zero(out, n * sizeof(*out));
            return rc;
        }
    }
    return GY_OK;
}

int
gy_hybrid_bundle_validate(const struct gy_suite_desc *desc,
                          const struct gy_hybrid_prekey_bundle *bundle,
                          uint8_t *diag_out)
{
    uint8_t enc[GY_HYBRID_ID_ENC_MAX];
    uint8_t signed_data[GY_HYBRID_SIGNED_MAX];
    uint8_t ctx[GY_PREKEY_CTX_MAX];
    size_t enclen, signed_len, ctxlen;
    uint32_t ik_pkid;
    int opk_present, ed_ok, pq_ok, rc;

    if (desc == NULL || bundle == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid)
        return GY_ERR_STATE;

    /* (a) suite/curve consistency: any mismatch is a cross-suite abort. */
    if (bundle->ik.base.curve.curve_type != desc->curve_type)
        return GY_ERR_STATE;
    if (bundle->spk.curve.curve_type != desc->curve_type)
        return GY_ERR_STATE;
    opk_present = gy_pkid_is_present(bundle->opk.curve.pkid);
    if (opk_present && bundle->opk.curve.curve_type != desc->curve_type)
        return GY_ERR_STATE;

    /* (b) PKID present and matches recomputation for every present key. */
    rc =
        gy_hybrid_encode_identity(desc, &bundle->ik, enc, sizeof(enc), &enclen);
    if (rc != GY_OK)
        return rc;
    rc = hybrid_check_pkid(desc, enc, enclen, bundle->ik.base.curve.pkid);
    if (rc != GY_OK)
        return rc;
    ik_pkid = bundle->ik.base.curve.pkid;

    rc = gy_hybrid_encode_pub(desc, &bundle->spk, enc, sizeof(enc), &enclen);
    if (rc != GY_OK)
        return rc;
    rc = hybrid_check_pkid(desc, enc, enclen, bundle->spk.curve.pkid);
    if (rc != GY_OK)
        return rc;

    /* The signed prekey names its signer; it must be this IK. */
    if (bundle->spk_ik_id != ik_pkid)
        return GY_ERR_VERIFY;

    if (opk_present) {
        rc =
            gy_hybrid_encode_pub(desc, &bundle->opk, enc, sizeof(enc), &enclen);
        if (rc != GY_OK)
            return rc;
        rc = hybrid_check_pkid(desc, enc, enclen, bundle->opk.curve.pkid);
        if (rc != GY_OK)
            return rc;
    }

    /* (c) flags well-formed BEFORE the expensive dual verify (D-X3DH-14). */
    rc = gy_hybrid_flags_validate(bundle->spk_flags);
    if (rc != GY_OK)
        return rc;

    /* (d) BOTH signatures over the full signed_data; both must pass. */
    rc = hybrid_signed_data(desc, &bundle->spk, bundle->spk_timestamp,
                            bundle->spk_flags, signed_data, sizeof(signed_data),
                            &signed_len);
    if (rc != GY_OK)
        return rc;

    GY_KEX_COUNT(verify);
    ed_ok = desc->verify(bundle->spk_ed_sig, bundle->ik.base.curve.pk,
                         signed_data, signed_len) == GY_OK;

    rc = prekey_ctx(desc, ctx, sizeof(ctx), &ctxlen);
    if (rc != GY_OK)
        return rc;
    GY_KEX_COUNT(verify);
    pq_ok = desc->dsa_verify(bundle->spk_mldsa_sig, bundle->ik.mldsa_pk,
                             signed_data, signed_len, ctx, ctxlen) == GY_OK;

    if (!ed_ok || !pq_ok) {
        if (diag_out != NULL) {
            uint8_t d = 0;

            if (!ed_ok)
                d |= GY_DIAG_CLASSICAL_FAILED;
            if (!pq_ok)
                d |= GY_DIAG_PQ_FAILED;
            *diag_out = d;
        }
        return GY_ERR_VERIFY;
    }
    return GY_OK;
}

int
gy_hybrid_ikhash(const struct gy_suite_desc *desc,
                 const struct gy_hybrid_identity_public_key *ik, uint8_t *out)
{
    uint8_t enc[GY_HYBRID_ID_ENC_MAX];
    size_t enclen;
    int rc;

    if (desc == NULL || ik == NULL || out == NULL)
        return GY_ERR_ARG;
    rc = gy_hybrid_encode_identity(desc, ik, enc, sizeof(enc), &enclen);
    if (rc != GY_OK)
        return rc;
    GY_KEX_COUNT(hash);
    return desc->hash(out, enc, enclen);
}
