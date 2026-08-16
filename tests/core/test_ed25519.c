/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/ed25519.c (XEdDSA sign and calculate_key_pair).  Full
 * verification is covered separately; oracle KATs run against libsignal; here each
 * signature is self-checked against the equation sB = R + hA using libsodium
 * point operations directly.
 */

#include <sodium.h>

#include <stdint.h>
#include <string.h>

#include "ed25519.h"
#include "error.h"
#include "hash.h"
#include "rng.h"
#include "util.h"
#include "x25519.h"

#include "gy_test.h"

/* Verify sB == R + hA with h = SHA-512(R || A || M) mod L.  Returns 0 if the
 * signature satisfies the XEdDSA equation, -1 otherwise. */
static int
selfcheck(const uint8_t sig[64], const uint8_t ed_pk[32], const uint8_t *msg,
          size_t msg_len)
{
    uint8_t h_hash[64], h[32], sb[32], ha[32], sum[32];
    gy_sha512_state st;

    gy_sha512_init(&st);
    gy_sha512_update(&st, sig, 32);
    gy_sha512_update(&st, ed_pk, 32);
    gy_sha512_update(&st, msg, msg_len);
    gy_sha512_final(&st, h_hash);
    crypto_core_ed25519_scalar_reduce(h, h_hash);

    if (crypto_scalarmult_ed25519_base_noclamp(sb, sig + 32) != 0)
        return -1;
    if (crypto_scalarmult_ed25519_noclamp(ha, h, ed_pk) != 0)
        return -1;
    if (crypto_core_ed25519_add(sum, sig, ha) != 0)
        return -1;
    return memcmp(sb, sum, 32) == 0 ? 0 : -1;
}

TEST(sign_selfcheck_roundtrip)
{
    uint8_t pk[32], sk[32], ed_pk[32], a[32], sig[64];
    const uint8_t *msg = (const uint8_t *)"geryon xeddsa test message";
    size_t msg_len = 26;

    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_calculate_key_pair(ed_pk, a, sk), GY_OK);
    /* The public key always encodes with sign bit 0. */
    ASSERT_EQ(ed_pk[31] & 0x80, 0);

    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, msg_len), GY_OK);
    ASSERT_EQ(selfcheck(sig, ed_pk, msg, msg_len), 0);
    gy_secure_zero(a, sizeof(a));
}

TEST(determinism_and_nonce)
{
    uint8_t pk[32], sk[32], ed_pk[32], a[32];
    uint8_t z1[64], z2[64], s1[64], s2[64], s3[64];
    const uint8_t *msg = (const uint8_t *)"nonce test";
    size_t msg_len = 10;

    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_calculate_key_pair(ed_pk, a, sk), GY_OK);

    ASSERT_EQ(gy_random_bytes(z1, sizeof(z1)), GY_OK);
    memcpy(z2, z1, sizeof(z2));
    z2[0] ^= 0x01;

    /* Same (sk, msg, Z) is fully deterministic. */
    ASSERT_EQ(gy_xeddsa_sign_z(s1, sk, msg, msg_len, z1), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign_z(s2, sk, msg, msg_len, z1), GY_OK);
    ASSERT_MEMEQ(s1, s2, 64);

    /* A different Z changes R but still yields a valid signature. */
    ASSERT_EQ(gy_xeddsa_sign_z(s3, sk, msg, msg_len, z2), GY_OK);
    ASSERT_TRUE(memcmp(s1, s3, 32) != 0, "R differs with a different Z");
    ASSERT_EQ(selfcheck(s1, ed_pk, msg, msg_len), 0);
    ASSERT_EQ(selfcheck(s3, ed_pk, msg, msg_len), 0);
    gy_secure_zero(a, sizeof(a));
}

TEST(sign_bit_branches)
{
    uint8_t pk[32], sk[32], e[32], sig[64], ed_pk[32], a[32];
    uint8_t sk0[32], sk1[32];
    const uint8_t *msg = (const uint8_t *)"branch";
    size_t msg_len = 6;
    int have0 = 0, have1 = 0, j;

    /* Collect one key whose kB has sign bit 0 and one with sign bit 1. */
    while (!have0 || !have1) {
        ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
        ASSERT_EQ(crypto_scalarmult_ed25519_base_noclamp(e, sk), 0);
        if ((e[31] >> 7) == 0 && !have0) {
            memcpy(sk0, sk, 32);
            have0 = 1;
        } else if ((e[31] >> 7) == 1 && !have1) {
            memcpy(sk1, sk, 32);
            have1 = 1;
        }
    }

    for (j = 0; j < 2; j++) {
        const uint8_t *key = j == 0 ? sk0 : sk1;
        ASSERT_EQ(gy_xeddsa_calculate_key_pair(ed_pk, a, key), GY_OK);
        ASSERT_EQ(ed_pk[31] & 0x80, 0);
        ASSERT_EQ(gy_xeddsa_sign(sig, key, msg, msg_len), GY_OK);
        ASSERT_EQ(selfcheck(sig, ed_pk, msg, msg_len), 0);
    }
    gy_secure_zero(a, sizeof(a));
}

TEST(message_length_bound)
{
    static uint8_t big[GY_XEDDSA_MAX_MSG + 1];
    uint8_t pk[32], sk[32], sig[64];

    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, big, GY_XEDDSA_MAX_MSG), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, big, GY_XEDDSA_MAX_MSG + 1),
              GY_ERR_TOOLONG);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(sign_selfcheck_roundtrip),
            GY_TEST(determinism_and_nonce),
            GY_TEST(sign_bit_branches),
            GY_TEST(message_length_bound),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
