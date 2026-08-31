/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/ed448.c (XEd448, XEdDSA spec section 6, D-XED-13), built
 * with -DGY_TEST_HOOKS so the deterministic gy_xed448_sign_z seam is live.
 *
 * There is NO external XEd448 oracle (the XEdDSA spec is vectorless, RFC 8032
 * Ed448 is a different scheme, and libsignal is 25519-only; see D-XED-13).
 * Correctness is therefore anchored INTERNALLY:
 *   - cross_check ties the in-house Edwards point layer to the RFC-7748-
 *     validated X448 ladder: the sign-path A = k*B must byte-match the
 *     verify-path A = u_to_y(x448_pub(k)) (the 448 analog of the D-XED-5
 *     25519 check);
 *   - round-trip + tamper matrix over both Edwards sign classes;
 *   - a regression-pinned self-KAT (fixed k, M, Z -> signature bytes), captured
 *     from the first trusted run once cross_check and round_trip pass.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ed448.h"
#include "error.h"
#include "util.h"
#include "x448.h"

#include "gy_test.h"

static const uint8_t basepoint[56] = {5};

/*
 * THE correctness anchor: the sign path derives A = k*B on the in-house §6
 * Edwards curve; the verify path derives A = u_to_y(X448(k)) from the RFC-7748
 * X448 public key.  These must be byte-identical, tying the untrusted point
 * layer to the trusted ladder across the whole scalar range.
 */
TEST(cross_check_sign_A_equals_verify_A)
{
    uint8_t pk[56], sk[56], a[57], ed_sign[57], ed_verify[57];
    int i;

    for (i = 0; i < 8; i++) {
        ASSERT_EQ(gy_x448_keypair(pk, sk), GY_OK);
        ASSERT_EQ(gy_xed448_calculate_key_pair(ed_sign, a, sk), GY_OK);
        ASSERT_EQ(gy_xed448_mont_to_ed(ed_verify, pk), GY_OK);
        ASSERT_MEMEQ(ed_sign, ed_verify, 57);
        /* A is defined with sign bit 0. */
        ASSERT_EQ(ed_sign[56] & 0x80, 0);
    }
}

TEST(sign_verify_round_trip)
{
    uint8_t pk[56], sk[56], sig[114], msg[64];
    int i;

    for (i = 0; i < 16; i++) {
        ASSERT_EQ(gy_x448_keypair(pk, sk), GY_OK);
        memset(msg, (uint8_t)(0x30 + i), sizeof(msg));
        ASSERT_EQ(gy_xed448_sign(sig, sk, msg, sizeof(msg)), GY_OK);
        ASSERT_EQ(gy_xed448_verify(sig, pk, msg, sizeof(msg)), GY_OK);
        /* s is canonical: its 57th byte (bits 448..455) is zero. */
        ASSERT_EQ(sig[113], 0);
    }
}

TEST(empty_message_round_trip)
{
    uint8_t pk[56], sk[56], sig[114];

    ASSERT_EQ(gy_x448_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_xed448_sign(sig, sk, NULL, 0), GY_OK);
    ASSERT_EQ(gy_xed448_verify(sig, pk, NULL, 0), GY_OK);
}

TEST(tamper_matrix_rejected)
{
    uint8_t pk[56], sk[56], sig[114], bad[114], msg[32], badpk[56];

    ASSERT_EQ(gy_x448_keypair(pk, sk), GY_OK);
    memset(msg, 0x5a, sizeof(msg));
    ASSERT_EQ(gy_xed448_sign(sig, sk, msg, sizeof(msg)), GY_OK);
    ASSERT_EQ(gy_xed448_verify(sig, pk, msg, sizeof(msg)), GY_OK);

    /* Flip a byte in R. */
    memcpy(bad, sig, 114);
    bad[0] ^= 0x01;
    ASSERT_EQ(gy_xed448_verify(bad, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Flip a byte in s. */
    memcpy(bad, sig, 114);
    bad[57] ^= 0x01;
    ASSERT_EQ(gy_xed448_verify(bad, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Non-canonical s: set the top (57th) s byte nonzero. */
    memcpy(bad, sig, 114);
    bad[113] = 0x01;
    ASSERT_EQ(gy_xed448_verify(bad, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* s >= q: all-ones low 56 bytes, top byte 0 (decode must reject). */
    memcpy(bad, sig, 114);
    memset(bad + 57, 0xff, 56);
    bad[113] = 0x00;
    ASSERT_EQ(gy_xed448_verify(bad, pk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Tamper the message. */
    msg[0] ^= 0x01;
    ASSERT_EQ(gy_xed448_verify(sig, pk, msg, sizeof(msg)), GY_ERR_VERIFY);
    msg[0] ^= 0x01;

    /* Wrong public key. */
    memcpy(badpk, pk, 56);
    badpk[0] ^= 0x01;
    ASSERT_EQ(gy_xed448_verify(sig, badpk, msg, sizeof(msg)), GY_ERR_VERIFY);

    /* Non-canonical u (>= p): all-ones u is not canonical. */
    memset(badpk, 0xff, 56);
    ASSERT_EQ(gy_xed448_verify(sig, badpk, msg, sizeof(msg)), GY_ERR_VERIFY);
}

TEST(sign_is_deterministic_in_z)
{
    uint8_t sk[56], sig1[114], sig2[114], msg[16], z[64];

    memset(sk, 0x11, sizeof(sk));
    sk[0] &= 252;
    sk[55] |= 128;
    memset(msg, 0x24, sizeof(msg));
    memset(z, 0x77, sizeof(z));

    ASSERT_EQ(gy_xed448_sign_z(sig1, sk, msg, sizeof(msg), z), GY_OK);
    ASSERT_EQ(gy_xed448_sign_z(sig2, sk, msg, sizeof(msg), z), GY_OK);
    ASSERT_MEMEQ(sig1, sig2, 114);
}

/*
 * Regression-pinned self-KAT.  With no external oracle, the expected bytes are
 * captured from the first run that passes cross_check + round_trip, then frozen
 * here.  While expected_sig is all-zero (the sentinel), the test verifies the
 * produced signature and PRINTS it for pinning; once pinned it enforces byte
 * equality.  Pin the bytes below and rebuild.
 */
static int
all_zero(const uint8_t *p, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (p[i] != 0)
            return 0;
    return 1;
}

TEST(pinned_kat)
{
    /* Fixed, clamped Montgomery private key. */
    static const uint8_t k[56] = {
        0xa8, 0x1b, 0x2e, 0x8a, 0x70, 0xa5, 0xac, 0x94, 0xff, 0xdb, 0xcc, 0x7d,
        0x0b, 0x9f, 0x3b, 0x2e, 0x2e, 0x39, 0x8f, 0x0e, 0x2c, 0x5f, 0x2a, 0x9c,
        0x1e, 0x0b, 0x77, 0x4a, 0x2b, 0x63, 0x0d, 0x8f, 0x4c, 0x2c, 0x1e, 0x83,
        0x9f, 0x2b, 0x8a, 0x0e, 0x5f, 0x2c, 0x1e, 0x0b, 0x77, 0x4a, 0x2b, 0x63,
        0x0d, 0x8f, 0x4c, 0x2c, 0x1e, 0x83, 0x9f, 0x2b,
    };
    static const uint8_t msg[5] = {'g', 'e', 'r', 'y', 'o'};
    static const uint8_t z[64] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    };
    /* PIN AFTER FIRST TRUSTED RUN: replace this all-zero sentinel. */
    static const uint8_t expected_sig[114] = {
        0x2c, 0x6f, 0xd3, 0xfa, 0xc8, 0x86, 0x53, 0xa0, 0xb4, 0x2f, 0x7b, 0x77,
        0x5f, 0x92, 0x10, 0xfc, 0xa5, 0x0d, 0x0d, 0x61, 0xcf, 0x71, 0x6c, 0x8d,
        0x77, 0x01, 0xc3, 0x8e, 0x2d, 0x78, 0xaf, 0xb5, 0x5f, 0x81, 0xd3, 0xbf,
        0xac, 0x04, 0x54, 0x45, 0x32, 0xab, 0xaa, 0xd1, 0x92, 0xbf, 0xb7, 0xae,
        0x69, 0xa5, 0x0f, 0x5b, 0xa2, 0xce, 0xa8, 0xd7, 0x00, 0x9d, 0x6c, 0x1c,
        0xf8, 0x4a, 0x80, 0x8f, 0x84, 0x9e, 0xd0, 0x41, 0xa5, 0xc6, 0x1a, 0xc9,
        0x96, 0x4f, 0x5d, 0x07, 0x2e, 0x5b, 0xe9, 0xbf, 0x81, 0xeb, 0xab, 0x09,
        0x67, 0xd5, 0xcc, 0x6f, 0x1f, 0x53, 0x03, 0xd5, 0xb7, 0xe3, 0x92, 0x68,
        0xc5, 0x12, 0xe3, 0x98, 0x71, 0x42, 0x18, 0x12, 0x03, 0xb2, 0xa0, 0xb7,
        0x47, 0x35, 0x1b, 0xb2, 0x0a, 0x00};

    uint8_t k_clamped[56], sk_pk[56], pk[56], sig[114];

    memcpy(k_clamped, k, 56);
    k_clamped[0] &= 252;
    k_clamped[55] |= 128;
    memcpy(sk_pk, k_clamped, 56);

    ASSERT_EQ(gy_xed448_sign_z(sig, k_clamped, msg, sizeof(msg), z), GY_OK);

    /* Self-verify under the matching public key. */
    ASSERT_EQ(gy_x448(pk, sk_pk, basepoint), GY_OK);
    ASSERT_EQ(gy_xed448_verify(sig, pk, msg, sizeof(msg)), GY_OK);
    ASSERT_EQ(sig[113], 0);

    if (all_zero(expected_sig, 114)) {
        size_t i;

        printf("  [pinned_kat] NOT YET PINNED - capture this signature:\n  ");
        for (i = 0; i < 114; i++)
            printf("%02x", sig[i]);
        printf("\n");
    } else {
        ASSERT_MEMEQ(sig, expected_sig, 114);
    }
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(cross_check_sign_A_equals_verify_A),
            GY_TEST(sign_verify_round_trip),
            GY_TEST(empty_message_round_trip),
            GY_TEST(tamper_matrix_rejected),
            GY_TEST(sign_is_deterministic_in_z),
            GY_TEST(pinned_kat),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
