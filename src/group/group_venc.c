/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_venc.h"

#include "group_hash.h" /* gy_group_hash_to_g, gy_group_hash_to_g1 */

#include "error.h"
#include "util.h"

/*
 * Frozen attribute-map domains (GROUP_SPEC section 2.2 label registry), the
 * same strings the attribute layer uses: M1 = HashToG("grp-m1", .),
 * M3 = HashToG1("grp-m3", .).
 */
#define GY_GROUP_M1_PURPOSE "grp-m1"
#define GY_GROUP_M3_PURPOSE "grp-m3"

/* out = E2 / E1^k  =  E2 - k.E1  (the Elgamal-style unmasking, section 6.3/6.4). */
static int
group_unmask(const struct gy_group_tier *tier, uint8_t *out, const uint8_t *E2,
             const uint8_t *E1, const uint8_t *k)
{
    uint8_t t[GY_GROUP_POINT_MAX];
    int rc;

    rc = tier->point_scalarmul(t, k, E1);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_sub(out, E2, t);
    gy_secure_zero(t, sizeof(t));
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}

/* Constant-time conditional copy: dst = flag ? src : dst, over n bytes. */
static void
ct_select(uint8_t *dst, const uint8_t *src, size_t n, uint8_t flag)
{
    uint8_t mask = (uint8_t)(-(int)(flag & 1u)); /* 0x00 or 0xff */
    size_t i;

    for (i = 0; i < n; i++)
        dst[i] = (uint8_t)(dst[i] ^ ((dst[i] ^ src[i]) & mask));
}

int
gy_group_uid_encrypt(const struct gy_group_tier *tier,
                     const struct gy_group_secret_params *sp,
                     const uint8_t uid[GY_GROUP_UID_BYTES],
                     struct gy_group_uid_ct *out)
{
    uint8_t M1[GY_GROUP_POINT_MAX], M2[GY_GROUP_POINT_MAX];
    uint8_t t[GY_GROUP_POINT_MAX];
    int rc;

    if (tier == NULL || sp == NULL || uid == NULL || out == NULL)
        return GY_ERR_ARG;

    memset(out, 0, sizeof(*out));

    rc = gy_group_hash_to_g(tier, GY_GROUP_M1_PURPOSE, uid, GY_GROUP_UID_BYTES,
                            M1);
    if (rc != GY_OK)
        return rc;
    rc = tier->encode_uid(M2, uid);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* E_A1 = M1^a1. */
    rc = tier->point_scalarmul(out->E_A1, sp->a1, M1);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    /* E_A2 = E_A1^a2 M2. */
    rc = tier->point_scalarmul(t, sp->a2, out->E_A1);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_add(out->E_A2, t, M2);
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_uid_decrypt(const struct gy_group_tier *tier,
                     const struct gy_group_secret_params *sp,
                     const struct gy_group_uid_ct *ct,
                     uint8_t uid[GY_GROUP_UID_BYTES])
{
    uint8_t m2[GY_GROUP_POINT_MAX];
    uint8_t m1[GY_GROUP_POINT_MAX], m1_a1[GY_GROUP_POINT_MAX];
    uint8_t uid2[GY_GROUP_UID_BYTES];
    size_t plen;
    int rc, rc_dec, e1_nonzero, eq, accept, ops_ok;

    if (tier == NULL || sp == NULL || ct == NULL || uid == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;

    /* Every ciphertext-processing failure - identity E_A1, a malformed point, a
     * decode miss, or a failed check - collapses to the SAME GY_ERR_VERIFY (no
     * decryption oracle, section 6.3).  We never early-return a distinct code;
     * failures fold into `accept`, and the decode/check run regardless so their
     * timing does not separate a bad point from a valid-but-wrong one. */
    e1_nonzero = !gy_is_zero(ct->E_A1, plen);

    /* m2 stays identity (all-zero) if the unmask fails, so decode still runs. */
    memset(m2, 0, sizeof(m2));
    ops_ok = (group_unmask(tier, m2, ct->E_A2, ct->E_A1, sp->a2) == GY_OK);

    rc_dec = tier->decode_uid(uid2, m2);

    /* Recompute M1' = HashToG(UID') and the check unconditionally. */
    if (gy_group_hash_to_g(tier, GY_GROUP_M1_PURPOSE, uid2, GY_GROUP_UID_BYTES,
                           m1) != GY_OK)
        ops_ok = 0;
    if (tier->point_scalarmul(m1_a1, sp->a1, m1) != 0)
        ops_ok = 0;
    eq = (gy_const_memcmp(ct->E_A1, m1_a1, plen) == 0);

    accept = e1_nonzero && ops_ok && (rc_dec == 0) && eq;
    if (accept) {
        memcpy(uid, uid2, GY_GROUP_UID_BYTES);
        rc = GY_OK;
    } else {
        gy_secure_zero(uid, GY_GROUP_UID_BYTES);
        rc = GY_ERR_VERIFY;
    }

    gy_secure_zero(uid2, sizeof(uid2));
    gy_secure_zero(m2, sizeof(m2));
    return rc;
}

int
gy_group_pk_encrypt(const struct gy_group_tier *tier,
                    const struct gy_group_secret_params *sp,
                    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                    const uint8_t uid[GY_GROUP_UID_BYTES],
                    struct gy_group_pk_ct *out)
{
    uint8_t input[GY_GROUP_PROFILEKEY_BYTES + GY_GROUP_UID_BYTES];
    uint8_t M3[GY_GROUP_POINT_MAX], M4[GY_GROUP_POINT_MAX];
    uint8_t t[GY_GROUP_POINT_MAX];
    int rc;

    if (tier == NULL || sp == NULL || pk == NULL || uid == NULL || out == NULL)
        return GY_ERR_ARG;

    memset(out, 0, sizeof(*out));

    /* M3 = HashToG1("grp-m3", ProfileKey || UID). */
    memcpy(input, pk, GY_GROUP_PROFILEKEY_BYTES);
    memcpy(input + GY_GROUP_PROFILEKEY_BYTES, uid, GY_GROUP_UID_BYTES);
    rc = gy_group_hash_to_g1(tier, GY_GROUP_M3_PURPOSE, input, sizeof(input),
                             M3);
    if (rc != GY_OK)
        return rc;
    /* M4 = EncodeToG(ProfileKey). */
    rc = tier->encode_pk(M4, pk);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* E_B1 = M3^b1. */
    rc = tier->point_scalarmul(out->E_B1, sp->b1, M3);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    /* E_B2 = E_B1^b2 M4. */
    rc = tier->point_scalarmul(t, sp->b2, out->E_B1);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_add(out->E_B2, t, M4);
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_pk_decrypt(const struct gy_group_tier *tier,
                    const struct gy_group_secret_params *sp,
                    const struct gy_group_pk_ct *ct,
                    const uint8_t uid[GY_GROUP_UID_BYTES],
                    uint8_t pk[GY_GROUP_PROFILEKEY_BYTES])
{
    uint8_t m4[GY_GROUP_POINT_MAX];
    uint8_t cand[GY_GROUP_PK_MAX_CANDIDATES][GY_GROUP_PROFILEKEY_BYTES];
    uint8_t winner[GY_GROUP_PROFILEKEY_BYTES];
    uint8_t input[GY_GROUP_PROFILEKEY_BYTES + GY_GROUP_UID_BYTES];
    uint8_t m3c[GY_GROUP_POINT_MAX], m3c_b1[GY_GROUP_POINT_MAX];
    size_t plen, cap, count, c;
    int rc, rc_dec, e1_nonzero, accept, ops_ok;
    size_t matches = 0;

    if (tier == NULL || sp == NULL || ct == NULL || uid == NULL || pk == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    cap = tier->pk_max_candidates;

    /* As in the UID scheme, every ciphertext-processing failure collapses to
     * the SAME GY_ERR_VERIFY (no decryption oracle, section 6.4 / 6.3); we fold
     * failures into `accept` rather than early-returning a distinct code. */
    e1_nonzero = !gy_is_zero(ct->E_B1, plen);

    /* M4' = E_B2 / E_B1^b2; m4 stays identity if the unmask fails. */
    memset(m4, 0, sizeof(m4));
    ops_ok = (group_unmask(tier, m4, ct->E_B2, ct->E_B1, sp->b2) == GY_OK);

    /* Provider enumerates the candidate ProfileKeys; count is public. */
    count = 0;
    rc_dec = tier->decode_pk(cand, &count, cap, m4);
    if (rc_dec != 0)
        count = 0;

    /* Constant-time test over the FULL fixed candidate count (no early exit,
     * CT select of the unique match; D-GRP-8, section 6.1 item 6). */
    memset(winner, 0, sizeof(winner));
    memcpy(input + GY_GROUP_PROFILEKEY_BYTES, uid, GY_GROUP_UID_BYTES);
    for (c = 0; c < cap; c++) {
        int valid = (c < count); /* count is a public function of the point */
        uint8_t hit;
        memcpy(input, cand[c], GY_GROUP_PROFILEKEY_BYTES);
        if (gy_group_hash_to_g1(tier, GY_GROUP_M3_PURPOSE, input, sizeof(input),
                                m3c) != GY_OK) {
            ops_ok = 0;
            continue;
        }
        if (tier->point_scalarmul(m3c_b1, sp->b1, m3c) != 0) {
            ops_ok = 0;
            continue;
        }
        hit =
            (uint8_t)(valid && (gy_const_memcmp(ct->E_B1, m3c_b1, plen) == 0));
        matches += hit;
        ct_select(winner, cand[c], GY_GROUP_PROFILEKEY_BYTES, hit);
    }

    accept = e1_nonzero && ops_ok && (matches == 1);
    if (accept) {
        memcpy(pk, winner, GY_GROUP_PROFILEKEY_BYTES);
        rc = GY_OK;
    } else {
        gy_secure_zero(pk, GY_GROUP_PROFILEKEY_BYTES);
        rc = GY_ERR_VERIFY;
    }

    gy_secure_zero(winner, sizeof(winner));
    gy_secure_zero(cand, sizeof(cand));
    gy_secure_zero(m4, sizeof(m4));
    gy_secure_zero(input, sizeof(input));
    gy_secure_zero(m3c, sizeof(m3c));
    gy_secure_zero(m3c_b1, sizeof(m3c_b1));
    return rc;
}

/* ------------------------------------------------------------------------- *
 * Canonical encodings (GROUP_SPEC section 9): 2 group elements, untagged.
 * ------------------------------------------------------------------------- */

static int
ct2_encode(const struct gy_group_tier *tier, const uint8_t *E1,
           const uint8_t *E2, uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen = tier->point_len;

    if (cap < 2 * plen)
        return GY_ERR_TOOLONG;
    memcpy(out, E1, plen);
    memcpy(out + plen, E2, plen);
    *outlen = 2 * plen;
    return GY_OK;
}

static int
ct2_decode(const struct gy_group_tier *tier, uint8_t *E1, uint8_t *E2,
           const uint8_t *in, size_t len)
{
    size_t plen = tier->point_len;

    if (len != 2 * plen)
        return GY_ERR_VERIFY;
    memset(E1, 0, GY_GROUP_POINT_MAX);
    memset(E2, 0, GY_GROUP_POINT_MAX);
    memcpy(E1, in, plen);
    memcpy(E2, in + plen, plen);
    return GY_OK;
}

int
gy_group_uid_ct_encode(const struct gy_group_tier *tier,
                       const struct gy_group_uid_ct *ct, uint8_t *out,
                       size_t cap, size_t *outlen)
{
    if (tier == NULL || ct == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    return ct2_encode(tier, ct->E_A1, ct->E_A2, out, cap, outlen);
}

int
gy_group_uid_ct_decode(const struct gy_group_tier *tier,
                       struct gy_group_uid_ct *ct, const uint8_t *in,
                       size_t len)
{
    if (tier == NULL || ct == NULL || in == NULL)
        return GY_ERR_ARG;
    return ct2_decode(tier, ct->E_A1, ct->E_A2, in, len);
}

int
gy_group_pk_ct_encode(const struct gy_group_tier *tier,
                      const struct gy_group_pk_ct *ct, uint8_t *out, size_t cap,
                      size_t *outlen)
{
    if (tier == NULL || ct == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    return ct2_encode(tier, ct->E_B1, ct->E_B2, out, cap, outlen);
}

int
gy_group_pk_ct_decode(const struct gy_group_tier *tier,
                      struct gy_group_pk_ct *ct, const uint8_t *in, size_t len)
{
    if (tier == NULL || ct == NULL || in == NULL)
        return GY_ERR_ARG;
    return ct2_decode(tier, ct->E_B1, ct->E_B2, in, len);
}
