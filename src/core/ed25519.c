/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <monocypher.h>
#include <sodium.h>
#include <string.h>

#include "ed25519.h"
#include "error.h"
#include "hash.h"
#include "rng.h"
#include "util.h"

/*
 * hash_1 prefix (D-XED-4): the 32-byte little-endian encoding of
 * 2^256 - 1 - 1, i.e. 0xFE followed by 31 bytes of 0xFF.  Domain-separates the
 * nonce hash from the challenge hash, which uses no prefix.
 */
static const uint8_t hash1_prefix[32] = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/*
 * Constant-time conditional move over 32 bytes: out = flag ? b : a, with no
 * branch or memory access dependent on flag (which is 0 or 1).
 */
static void
ct_cmov32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32],
          uint8_t flag)
{
    uint8_t mask;
    int i;

    mask = (uint8_t)(-(int)(flag & 1)); /* 0xff if flag, else 0x00 */
    for (i = 0; i < 32; i++)
        out[i] = (uint8_t)((a[i] & (uint8_t)~mask) | (b[i] & mask));
}

int
gy_xeddsa_calculate_key_pair(uint8_t ed_pk[32], uint8_t scalar_a[32],
                             const uint8_t mont_sk[32])
{
    uint8_t e[32], k_neg[32];
    uint8_t sign_bit;
    int rc = GY_OK;

    /* E = k * B in Edwards form; k is already clamped (D-XED-10), so noclamp. */
    if (crypto_scalarmult_ed25519_base_noclamp(e, mont_sk) != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* Always compute -k mod L; select in constant time on the sign bit. */
    crypto_core_ed25519_scalar_negate(k_neg, mont_sk);
    sign_bit = (uint8_t)(e[31] >> 7);
    ct_cmov32(scalar_a, mont_sk, k_neg, sign_bit);

    /* A = E with the sign bit forced to 0. */
    memcpy(ed_pk, e, 32);
    ed_pk[31] &= 0x7f;

out:
    gy_secure_zero(e, sizeof(e));
    gy_secure_zero(k_neg, sizeof(k_neg));
    return rc;
}

int
gy_xeddsa_sign_z(uint8_t sig[64], const uint8_t mont_sk[32], const uint8_t *msg,
                 size_t msg_len, const uint8_t z[64])
{
    uint8_t ed_pk[32], a[32];
    uint8_t r_hash[64], r[32];
    uint8_t h_hash[64], h[32], ha[32];
    gy_sha512_state st;
    int rc;

    if (msg_len > GY_XEDDSA_MAX_MSG)
        return GY_ERR_TOOLONG;

    rc = gy_xeddsa_calculate_key_pair(ed_pk, a, mont_sk);
    if (rc != GY_OK)
        goto out;

    /* r = hash_1(prefix || a || M || Z) mod L. */
    gy_sha512_init(&st);
    gy_sha512_update(&st, hash1_prefix, sizeof(hash1_prefix));
    gy_sha512_update(&st, a, sizeof(a));
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_update(&st, z, 64);
    gy_sha512_final(&st, r_hash);
    crypto_core_ed25519_scalar_reduce(r, r_hash);

    /* R = r * B, written into the first half of the signature. */
    if (crypto_scalarmult_ed25519_base_noclamp(sig, r) != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* h = SHA-512(R || A || M) mod L (no prefix on the challenge hash). */
    gy_sha512_init(&st);
    gy_sha512_update(&st, sig, 32);
    gy_sha512_update(&st, ed_pk, sizeof(ed_pk));
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_final(&st, h_hash);
    crypto_core_ed25519_scalar_reduce(h, h_hash);

    /* s = r + h * a mod L, written into the second half of the signature. */
    crypto_core_ed25519_scalar_mul(ha, h, a);
    crypto_core_ed25519_scalar_add(sig + 32, r, ha);
    rc = GY_OK;

out:
    gy_secure_zero(a, sizeof(a));
    gy_secure_zero(r, sizeof(r));
    gy_secure_zero(r_hash, sizeof(r_hash));
    gy_secure_zero(h, sizeof(h));
    gy_secure_zero(h_hash, sizeof(h_hash));
    gy_secure_zero(ha, sizeof(ha));
    gy_secure_zero(ed_pk, sizeof(ed_pk));
    if (rc != GY_OK)
        gy_secure_zero(sig, 64);
    return rc;
}

int
gy_xeddsa_sign(uint8_t sig[64], const uint8_t mont_sk[32], const uint8_t *msg,
               size_t msg_len)
{
    uint8_t z[64];
    int rc;

    if (msg_len > GY_XEDDSA_MAX_MSG)
        return GY_ERR_TOOLONG;

    rc = gy_random_bytes(z, sizeof(z));
    if (rc != GY_OK)
        return rc;

    rc = gy_xeddsa_sign_z(sig, mont_sk, msg, msg_len, z);
    gy_secure_zero(z, sizeof(z));
    return rc;
}

/*
 * Reject a non-canonical Montgomery u-coordinate: return 1 if the 32-byte
 * little-endian value is >= p = 2^255 - 19 (D-XED-5).  The key is public, so
 * constant time is not required; written branch-simple.
 */
static int
u_ge_p(const uint8_t u[32])
{
    static const uint8_t p[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    };
    int i;

    for (i = 31; i >= 0; i--) {
        if (u[i] > p[i])
            return 1;
        if (u[i] < p[i])
            return 0;
    }
    return 1; /* u == p is also >= p */
}

/*
 * The ONLY monocypher call in geryon: the Montgomery-to-Edwards birational
 * map on the XEdDSA verify path (D-XED-5).  It yields an Edwards key with sign
 * bit 0, matching how gy_xeddsa_calculate_key_pair encodes A.  Kept isolated
 * in this one function.
 */
static void
mont_to_ed(uint8_t ed_pk[32], const uint8_t mont_pk[32])
{
    crypto_x25519_to_eddsa(ed_pk, mont_pk);
}

int
gy_xeddsa_verify(const uint8_t sig[64], const uint8_t mont_pk[32],
                 const uint8_t *msg, size_t msg_len)
{
    uint8_t ed_pk[32];

    if (msg_len > GY_XEDDSA_MAX_MSG)
        return GY_ERR_TOOLONG;
    if (u_ge_p(mont_pk))
        return GY_ERR_VERIFY;

    mont_to_ed(ed_pk, mont_pk);
    if (crypto_sign_verify_detached(sig, msg, msg_len, ed_pk) != 0)
        return GY_ERR_VERIFY;
    return GY_OK;
}
