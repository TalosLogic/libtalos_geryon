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
