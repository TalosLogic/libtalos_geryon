/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/x25519.c.  Vectors from RFC 7748: section 5.2 scalar
 * multiplication, section 6.1 Diffie-Hellman, and the iterated test (1,000
 * iterations here; 1,000,000 lives in test_x25519_slow.c under the `slow`
 * label).  Plus small-order rejection and key-generation invariants.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "util.h"
#include "x25519.h"

#include "gy_test.h"

static const uint8_t basepoint[32] = {9};

static void
hxfix(uint8_t out[32], const char *hex)
{
    (void)gy_hex_decode(out, 32, hex);
}

TEST(rfc7748_5_2_scalarmult)
{
    uint8_t sk[32], u[32], out[32], want[32];

    hxfix(sk,
          "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    hxfix(u,
          "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    hxfix(want,
          "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    ASSERT_EQ(gy_x25519(out, sk, u), GY_OK);
    ASSERT_MEMEQ(out, want, 32);

    hxfix(sk,
          "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    hxfix(u,
          "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    hxfix(want,
          "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    ASSERT_EQ(gy_x25519(out, sk, u), GY_OK);
    ASSERT_MEMEQ(out, want, 32);
}

TEST(rfc7748_6_1_diffie_hellman)
{
    uint8_t apriv[32], apub[32], bpriv[32], bpub[32], shared[32], out[32];

    hxfix(apriv,
          "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    hxfix(apub,
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    hxfix(bpriv,
          "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    hxfix(bpub,
          "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    hxfix(shared,
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /* Public keys derive from private keys via the base point. */
    ASSERT_EQ(gy_x25519(out, apriv, basepoint), GY_OK);
    ASSERT_MEMEQ(out, apub, 32);
    ASSERT_EQ(gy_x25519(out, bpriv, basepoint), GY_OK);
    ASSERT_MEMEQ(out, bpub, 32);

    /* Both parties reach the same shared secret. */
    ASSERT_EQ(gy_x25519(out, apriv, bpub), GY_OK);
    ASSERT_MEMEQ(out, shared, 32);
    ASSERT_EQ(gy_x25519(out, bpriv, apub), GY_OK);
    ASSERT_MEMEQ(out, shared, 32);
}

/* RFC 7748 iterated test: k = u = basepoint, then (k, u) = (X25519(k,u), k). */
static void
iterate(uint8_t out[32], unsigned int iterations)
{
    uint8_t k[32] = {9};
    uint8_t u[32] = {9};
    uint8_t r[32];
    unsigned int i;

    for (i = 0; i < iterations; i++) {
        ASSERT_EQ(gy_x25519(r, k, u), GY_OK);
        memcpy(u, k, 32);
        memcpy(k, r, 32);
    }
    memcpy(out, k, 32);
}

TEST(rfc7748_iterated_1000)
{
    uint8_t out[32], want1[32], want1000[32];

    hxfix(want1,
          "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079");
    hxfix(want1000,
          "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");

    iterate(out, 1);
    ASSERT_MEMEQ(out, want1, 32);
    iterate(out, 1000);
    ASSERT_MEMEQ(out, want1000, 32);
}

TEST(small_order_rejected)
{
    /* A representative set of small-order / degenerate encodings. */
    static const char *bad[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    };
    uint8_t sk[32], peer[32], out[32];
    size_t i;

    memset(sk, 0x11, sizeof(sk));
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        hxfix(peer, bad[i]);
        memset(out, 0x5a, sizeof(out));
        ASSERT_EQ(gy_x25519(out, sk, peer), GY_ERR_WEAK_KEY);
        ASSERT_EQ(gy_is_zero(out, 32), 1); /* out zeroized on reject */
    }
}

TEST(keypair_invariants)
{
    uint8_t pk1[32], sk1[32], pk2[32], sk2[32], derived[32];

    ASSERT_EQ(gy_x25519_keypair(pk1, sk1), GY_OK);
    ASSERT_EQ(gy_x25519_keypair(pk2, sk2), GY_OK);

    /* Private key is stored already clamped. */
    ASSERT_EQ(sk1[0] & 0x07, 0);
    ASSERT_EQ(sk1[31] & 0x80, 0);
    ASSERT_EQ(sk1[31] & 0x40, 0x40);

    /* Public key matches base-point scalar multiplication of the private. */
    ASSERT_EQ(gy_x25519(derived, sk1, basepoint), GY_OK);
    ASSERT_MEMEQ(derived, pk1, 32);

    /* Two generations differ. */
    ASSERT_TRUE(memcmp(sk1, sk2, 32) != 0, "two private keys differ");
    ASSERT_TRUE(memcmp(pk1, pk2, 32) != 0, "two public keys differ");
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(rfc7748_5_2_scalarmult),
            GY_TEST(rfc7748_6_1_diffie_hellman),
            GY_TEST(rfc7748_iterated_1000),
            GY_TEST(small_order_rejected),
            GY_TEST(keypair_invariants),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
