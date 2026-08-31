/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * 448 validation gate (D-XED-12): exercise the vendored libdecaf
 * (ed448goldilocks) 448 primitives DIRECTLY against the official standards
 * vectors, BEFORE any geryon 448 code trusts their arithmetic.
 *
 *   - RFC 7748 section 5.2 (X448 scalar multiplication) and section 6.2
 *     (X448 Diffie-Hellman), vectors from RFC 7748.
 *   - RFC 8032 section 7.4 (Ed448 sign/verify), vectors from RFC 8032.
 *
 * These are the ONLY call sites of decaf_ed448_sign / decaf_ed448_verify in
 * the tree (D-XED-12 scope: geryon's own code never references the RFC 8032
 * Ed448 scheme, only XEd448). The iterated X448 vectors live in
 * test_gate_448_slow.c under the `slow` label.
 *
 * decaf_error_t: DECAF_SUCCESS == -1, DECAF_FAILURE == 0 (decaf/common.h).
 */

#include <stdint.h>
#include <string.h>

#include <decaf.h>
#include <decaf/ed448.h>

#include "gy_test.h"

static void
hx56(uint8_t out[56], const char *hex)
{
    (void)gy_hex_decode(out, 56, hex);
}

static void
hx57(uint8_t out[57], const char *hex)
{
    (void)gy_hex_decode(out, 57, hex);
}

/* RFC 7748 section 5.2, X448 scalar multiplication, both vectors. */
TEST(rfc7748_x448_scalarmult)
{
    uint8_t scalar[56], u[56], out[56], want[56];

    hx56(scalar, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121"
                 "700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
    hx56(u, "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9"
            "814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
    hx56(want, "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f"
               "e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
    ASSERT_EQ(decaf_x448(out, u, scalar), DECAF_SUCCESS);
    ASSERT_MEMEQ(out, want, 56);

    hx56(scalar, "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5"
                 "38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
    hx56(u, "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b1"
            "65d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
    hx56(want, "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7"
               "ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");
    ASSERT_EQ(decaf_x448(out, u, scalar), DECAF_SUCCESS);
    ASSERT_MEMEQ(out, want, 56);
}

/* RFC 7748 section 6.2, X448 Diffie-Hellman. Base u-coordinate is 5. */
TEST(rfc7748_x448_diffie_hellman)
{
    static const uint8_t five[56] = {5};
    uint8_t apriv[56], apub[56], bpriv[56], bpub[56];
    uint8_t awant[56], bwant[56], shared[56], kwant[56];

    hx56(apriv, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
                "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    hx56(awant, "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c"
                "22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
    hx56(bpriv, "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d"
                "6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
    hx56(bwant, "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430"
                "27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
    hx56(kwant, "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b"
                "b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");

    ASSERT_EQ(decaf_x448(apub, five, apriv), DECAF_SUCCESS);
    ASSERT_MEMEQ(apub, awant, 56);
    ASSERT_EQ(decaf_x448(bpub, five, bpriv), DECAF_SUCCESS);
    ASSERT_MEMEQ(bpub, bwant, 56);

    ASSERT_EQ(decaf_x448(shared, bpub, apriv), DECAF_SUCCESS);
    ASSERT_MEMEQ(shared, kwant, 56);
    ASSERT_EQ(decaf_x448(shared, apub, bpriv), DECAF_SUCCESS);
    ASSERT_MEMEQ(shared, kwant, 56);
}

/* decaf_x448_derive_public_key must equal X448(scalar, 5). */
TEST(x448_derive_matches_base_mult)
{
    static const uint8_t five[56] = {5};
    uint8_t priv[56], via_op[56], via_derive[56];

    hx56(priv, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d"
               "d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
    ASSERT_EQ(decaf_x448(via_op, five, priv), DECAF_SUCCESS);
    decaf_x448_derive_public_key(via_derive, priv);
    ASSERT_MEMEQ(via_derive, via_op, 56);
}

/* RFC 8032 section 7.4, Ed448 sign/verify (empty context, not prehashed). */
static void
ed448_kat(const char *sk_hex, const char *pk_hex, const uint8_t *msg,
          size_t msg_len, const char *sig_hex)
{
    uint8_t sk[57], pk[57], sig[114];
    uint8_t got_pk[57], got_sig[114], tampered[114];
    uint8_t empty[1] = {0};

    hx57(sk, sk_hex);
    hx57(pk, pk_hex);
    (void)gy_hex_decode(sig, 114, sig_hex);

    /*
     * libdecaf's Ed448 sign/verify feed the message straight into a SHAKE
     * hash_update whose buffer argument is __attribute__((nonnull)); an empty
     * RFC 8032 message (msg == NULL, msg_len == 0) trips UBSan's nonnull check
     * inside the vendored code even though zero bytes are read. Substitute a
     * valid non-NULL pointer for the empty case (libdecaf is not modified).
     */
    if (msg == NULL) {
        msg = empty;
        msg_len = 0;
    }

    /* Public key derivation. */
    decaf_ed448_derive_public_key(got_pk, sk);
    ASSERT_MEMEQ(got_pk, pk, 57);

    /* Deterministic signature matches the KAT. */
    decaf_ed448_sign(got_sig, sk, pk, msg, msg_len, 0, NULL, 0);
    ASSERT_MEMEQ(got_sig, sig, 114);

    /* Valid signature verifies. */
    ASSERT_EQ(decaf_ed448_verify(sig, pk, msg, msg_len, 0, NULL, 0),
              DECAF_SUCCESS);

    /* A single flipped signature byte is rejected. */
    memcpy(tampered, sig, 114);
    tampered[0] ^= 0x01;
    ASSERT_EQ(decaf_ed448_verify(tampered, pk, msg, msg_len, 0, NULL, 0),
              DECAF_FAILURE);
}

TEST(rfc8032_ed448_blank)
{
    ed448_kat("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3"
              "528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b",
              "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778"
              "edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180",
              NULL, 0,
              "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f"
              "2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a"
              "9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4db"
              "b61149f05a7363268c71d95808ff2e652600");
}

TEST(rfc8032_ed448_one_octet)
{
    static const uint8_t msg[1] = {0x03};

    ed448_kat("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463a"
              "fbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
              "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c086"
              "6aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
              msg, sizeof msg,
              "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f435"
              "2541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cb"
              "cee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0f"
              "f3348ab21aa4adafd1d234441cf807c03a00");
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(rfc7748_x448_scalarmult),
        GY_TEST(rfc7748_x448_diffie_hellman),
        GY_TEST(x448_derive_matches_base_mult),
        GY_TEST(rfc8032_ed448_blank),
        GY_TEST(rfc8032_ed448_one_octet),
    };
    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
