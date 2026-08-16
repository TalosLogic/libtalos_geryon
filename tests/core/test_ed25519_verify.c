/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for gy_xeddsa_verify: round-trip acceptance, tamper
 * rejection, non-canonical public-key and scalar rejection, and degenerate
 * inputs.  Oracle KATs against libsignal.
 */

#include <stdint.h>
#include <string.h>

#include "ed25519.h"
#include "error.h"
#include "util.h"
#include "x25519.h"

#include "gy_test.h"

/* Group order L, little-endian, for constructing a non-canonical s = s + L. */
static const uint8_t order_l[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

TEST(verify_accepts_valid)
{
    uint8_t pk[32], sk[32], sig[64];
    uint8_t msg[13];

    memcpy(msg, "verify me now", 13);
    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, sizeof(msg)), GY_OK);
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, msg, sizeof(msg)), GY_OK);
}

TEST(verify_rejects_tampering)
{
    uint8_t pk[32], sk[32], pk2[32], sk2[32], sig[64], tmp[64];
    uint8_t msg[13];

    memcpy(msg, "verify me now", 13);
    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_x25519_keypair(pk2, sk2), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, sizeof(msg)), GY_OK);

    /* Flipped message bit. */
    msg[0] ^= 0x01;
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, msg, sizeof(msg)), GY_ERR_VERIFY);
    msg[0] ^= 0x01;

    /* Flipped R bit (first half). */
    memcpy(tmp, sig, 64);
    tmp[0] ^= 0x01;
    ASSERT_EQ(gy_xeddsa_verify(tmp, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Flipped s bit (second half). */
    memcpy(tmp, sig, 64);
    tmp[32] ^= 0x01;
    ASSERT_EQ(gy_xeddsa_verify(tmp, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Swapped R and s halves. */
    memcpy(tmp, sig + 32, 32);
    memcpy(tmp + 32, sig, 32);
    ASSERT_EQ(gy_xeddsa_verify(tmp, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Wrong public key. */
    ASSERT_EQ(gy_xeddsa_verify(sig, pk2, msg, sizeof(msg)), GY_ERR_VERIFY);
}

TEST(verify_noncanonical_pubkey)
{
    uint8_t pk[32], sk[32], sig[64], badpk[32];
    uint8_t msg[4];
    size_t i;
    /* u = p, p + 1, and 2^255 - 1 are all >= p and must be rejected. */
    static const char *bad[] = {
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };

    memcpy(msg, "abcd", 4);
    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, sizeof(msg)), GY_OK);

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        (void)gy_hex_decode(badpk, 32, bad[i]);
        ASSERT_EQ(gy_xeddsa_verify(sig, badpk, msg, sizeof(msg)),
                  GY_ERR_VERIFY);
    }

    /* u = p - 1 is canonical (< p) and takes the verify path, but the
     * signature was not made under it, so it still fails. */
    (void)gy_hex_decode(
        badpk, 32,
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    ASSERT_EQ(gy_xeddsa_verify(sig, badpk, msg, sizeof(msg)), GY_ERR_VERIFY);
}

TEST(verify_noncanonical_scalar)
{
    uint8_t pk[32], sk[32], sig[64];
    uint8_t msg[4];
    unsigned int carry;
    int i;

    memcpy(msg, "abcd", 4);
    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, sizeof(msg)), GY_OK);
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, msg, sizeof(msg)), GY_OK);

    /* s + L is a non-canonical scalar (>= L); libsodium's verify rejects it. */
    carry = 0;
    for (i = 0; i < 32; i++) {
        carry += (unsigned int)sig[32 + i] + order_l[i];
        sig[32 + i] = (uint8_t)(carry & 0xff);
        carry >>= 8;
    }
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, msg, sizeof(msg)), GY_ERR_VERIFY);
}

TEST(verify_degenerate_inputs)
{
    uint8_t pk[32], sk[32], sig[64], zero_pk[32], zero_sig[64];
    uint8_t msg[4];

    memcpy(msg, "abcd", 4);
    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, msg, sizeof(msg)), GY_OK);

    /* All-zero public key: canonical (u = 0) but not a valid signer. */
    memset(zero_pk, 0, sizeof(zero_pk));
    ASSERT_EQ(gy_xeddsa_verify(sig, zero_pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* All-zero signature under a valid key. */
    memset(zero_sig, 0, sizeof(zero_sig));
    ASSERT_EQ(gy_xeddsa_verify(zero_sig, pk, msg, sizeof(msg)), GY_ERR_VERIFY);
}

TEST(verify_message_bound)
{
    static uint8_t big[GY_XEDDSA_MAX_MSG + 1];
    uint8_t pk[32], sk[32], sig[64];

    ASSERT_EQ(gy_x25519_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xeddsa_sign(sig, sk, big, GY_XEDDSA_MAX_MSG), GY_OK);
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, big, GY_XEDDSA_MAX_MSG), GY_OK);
    ASSERT_EQ(gy_xeddsa_verify(sig, pk, big, GY_XEDDSA_MAX_MSG + 1),
              GY_ERR_TOOLONG);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(verify_accepts_valid),
            GY_TEST(verify_rejects_tampering),
            GY_TEST(verify_noncanonical_pubkey),
            GY_TEST(verify_noncanonical_scalar),
            GY_TEST(verify_degenerate_inputs),
            GY_TEST(verify_message_bound),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
