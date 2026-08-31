/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/x448.c (the gy_x448 wrapper over libdecaf's RFC 7748
 * X448).  Vectors from RFC 7748 section 5.2 (scalar multiplication) and section
 * 6.2 (Diffie-Hellman), run through geryon's wrapper (the gate test exercises
 * decaf directly; this pins the wrapper's plumbing and the D-X3DH-8 all-zero
 * rejection).  Base u-coordinate for X448 is 5.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "util.h"
#include "x448.h"

#include "gy_test.h"

static const uint8_t basepoint[56] = {5};

static void
hxfix(uint8_t out[56], const char *hex)
{
    (void)gy_hex_decode(out, 56, hex);
}

/* RFC 7748 section 5.2, X448 scalar multiplication (decaf clamps internally). */
TEST(rfc7748_5_2_scalarmult)
{
    uint8_t sk[56], u[56], out[56], want[56];

    hxfix(sk, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
              "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    hxfix(u, "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
             "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    hxfix(want, "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
                "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
    ASSERT_EQ(gy_x448(out, sk, u), GY_OK);
    ASSERT_MEMEQ(out, want, 56);

    hxfix(sk, "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
              "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
    hxfix(u, "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b1"
             "65d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
    hxfix(want, "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
                "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");
    ASSERT_EQ(gy_x448(out, sk, u), GY_OK);
    ASSERT_MEMEQ(out, want, 56);
}

/* RFC 7748 section 6.2, X448 Diffie-Hellman. */
TEST(rfc7748_6_2_diffie_hellman)
{
    uint8_t apriv[56], apub[56], bpriv[56], bpub[56], out[56];
    uint8_t awant[56], bwant[56], kwant[56];

    hxfix(apriv, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
                 "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    hxfix(awant, "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                 "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
    hxfix(bpriv, "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
                 "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    hxfix(bwant, "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                 "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    hxfix(kwant, "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
                 "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    /* Public keys derive from private keys via the base point. */
    ASSERT_EQ(gy_x448(apub, apriv, basepoint), GY_OK);
    ASSERT_MEMEQ(apub, awant, 56);
    ASSERT_EQ(gy_x448(bpub, bpriv, basepoint), GY_OK);
    ASSERT_MEMEQ(bpub, bwant, 56);

    /* Both parties reach the same shared secret. */
    ASSERT_EQ(gy_x448(out, apriv, bpub), GY_OK);
    ASSERT_MEMEQ(out, kwant, 56);
    ASSERT_EQ(gy_x448(out, bpriv, apub), GY_OK);
    ASSERT_MEMEQ(out, kwant, 56);
}

TEST(low_order_rejected)
{
    uint8_t sk[56], peer[56], out[56];

    memset(sk, 0x11, sizeof(sk));
    sk[0] &= 252;
    sk[55] |= 128;

    /* All-zero peer yields an all-zero shared secret: rejected and zeroized. */
    memset(peer, 0, sizeof(peer));
    memset(out, 0x5a, sizeof(out));
    ASSERT_EQ(gy_x448(out, sk, peer), GY_ERR_WEAK_KEY);
    ASSERT_EQ(gy_is_zero(out, 56), 1);

    /* u = 1 is also small-order. */
    memset(peer, 0, sizeof(peer));
    peer[0] = 1;
    memset(out, 0x5a, sizeof(out));
    ASSERT_EQ(gy_x448(out, sk, peer), GY_ERR_WEAK_KEY);
    ASSERT_EQ(gy_is_zero(out, 56), 1);
}

TEST(keypair_invariants)
{
    uint8_t pk1[56], sk1[56], pk2[56], sk2[56], derived[56];

    ASSERT_EQ(gy_x448_keypair(pk1, sk1), GY_OK);
    ASSERT_EQ(gy_x448_keypair(pk2, sk2), GY_OK);

    /* Private key is stored already clamped (RFC 7748 X448). */
    ASSERT_EQ(sk1[0] & 0x03, 0);
    ASSERT_EQ(sk1[55] & 0x80, 0x80);

    /* Public key matches base-point scalar multiplication of the private. */
    ASSERT_EQ(gy_x448(derived, sk1, basepoint), GY_OK);
    ASSERT_MEMEQ(derived, pk1, 56);

    /* Two generations differ. */
    ASSERT_TRUE(memcmp(sk1, sk2, 56) != 0, "two private keys differ");
    ASSERT_TRUE(memcmp(pk1, pk2, 56) != 0, "two public keys differ");
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(rfc7748_5_2_scalarmult),
            GY_TEST(rfc7748_6_2_diffie_hellman),
            GY_TEST(low_order_rejected),
            GY_TEST(keypair_invariants),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
