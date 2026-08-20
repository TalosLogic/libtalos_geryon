/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/mldsa.c (ML-DSA-44, FIPS 204), built with -DGY_TEST_HOOKS
 * so the pqinit RNG draw-count hook is live.
 *
 * Scope (D-PQ-3, amended 2026-08-17): WRAPPER-conformance, mirroring
 * test_ed25519 (NOT test_x25519) because ML-DSA sign is hedged.  The sigVer
 * known-answer (mldsa44_kat.h, from the NIST ACVP FIPS 204 vectors) pins the
 * VERIFY path to FIPS 204 independent of liboqs; the randomized SIGN path is
 * covered by round-trip + hedged smoke, not an output KAT.  The ctx-negative
 * matrix pins the D-PQ-1 context as load-bearing; the draw-count invariant
 * confirms hedged sign draws exactly one 32-byte rnd through geryon's shim.
 *
 * Signatures are sig-first (sig, key, msg, mlen, ctx, ctxlen), matching
 * gy_xeddsa_* and the descriptor sign/verify convention.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "mldsa.h"
#include "pqinit.h"
#include "util.h"

#include "gy_test.h"
#include "mldsa44_kat.h"

#define MSG_CAP 8192

static void
kat_hex(uint8_t *out, size_t n, const char *hex)
{
    ASSERT_TRUE(gy_hex_decode(out, n, hex) == (int)n, "KAT vector decoded");
}

/* keypair -> sign (with ctx) -> verify succeeds; a tampered message fails. */
TEST(roundtrip)
{
    uint8_t pk[GY_MLDSA44_PK], sk[GY_MLDSA44_SK], sig[GY_MLDSA44_SIG];
    static const uint8_t msg[] = "geryon ML-DSA-44 round-trip message";
    static const uint8_t ctx[] = "geryon:prekey";
    uint8_t bad[sizeof(msg)];

    ASSERT_EQ(gy_mldsa_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_mldsa_sign(sig, sk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
    ASSERT_EQ(gy_mldsa_verify(sig, pk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);

    memcpy(bad, msg, sizeof(msg));
    bad[0] ^= 0x01;
    ASSERT_EQ(gy_mldsa_verify(sig, pk, bad, sizeof(bad), ctx, sizeof(ctx) - 1),
              GY_ERR_VERIFY);
}

/* Two fresh generations differ; NULL arguments are rejected. */
TEST(keypair_invariants)
{
    uint8_t pk1[GY_MLDSA44_PK], sk1[GY_MLDSA44_SK];
    uint8_t pk2[GY_MLDSA44_PK], sk2[GY_MLDSA44_SK];

    ASSERT_EQ(gy_mldsa_keypair(pk1, sk1), GY_OK);
    ASSERT_EQ(gy_mldsa_keypair(pk2, sk2), GY_OK);
    ASSERT_TRUE(memcmp(pk1, pk2, GY_MLDSA44_PK) != 0, "public keys differ");
    ASSERT_TRUE(memcmp(sk1, sk2, GY_MLDSA44_SK) != 0, "secret keys differ");

    ASSERT_EQ(gy_mldsa_keypair(NULL, sk1), GY_ERR_ARG);
    ASSERT_EQ(gy_mldsa_keypair(pk1, NULL), GY_ERR_ARG);
}

/*
 * The context is load-bearing (D-PQ-1): a signature made under one ctx must not
 * verify under a different ctx, and empty vs nonempty ctx must not cross-verify.
 */
TEST(ctx_negative)
{
    uint8_t pk[GY_MLDSA44_PK], sk[GY_MLDSA44_SK], sig[GY_MLDSA44_SIG];
    static const uint8_t msg[] = "same message, different context";
    static const uint8_t ctx_a[] = "ctx-A";
    static const uint8_t ctx_b[] = "ctx-B";

    ASSERT_EQ(gy_mldsa_keypair(pk, sk), GY_OK);

    /* Nonempty ctx A: verifies under A, fails under B and under empty. */
    ASSERT_EQ(
        gy_mldsa_sign(sig, sk, msg, sizeof(msg), ctx_a, sizeof(ctx_a) - 1),
        GY_OK);
    ASSERT_EQ(
        gy_mldsa_verify(sig, pk, msg, sizeof(msg), ctx_a, sizeof(ctx_a) - 1),
        GY_OK);
    ASSERT_EQ(
        gy_mldsa_verify(sig, pk, msg, sizeof(msg), ctx_b, sizeof(ctx_b) - 1),
        GY_ERR_VERIFY);
    ASSERT_EQ(gy_mldsa_verify(sig, pk, msg, sizeof(msg), NULL, 0),
              GY_ERR_VERIFY);

    /* Empty ctx: verifies empty, fails under a nonempty ctx. */
    ASSERT_EQ(gy_mldsa_sign(sig, sk, msg, sizeof(msg), NULL, 0), GY_OK);
    ASSERT_EQ(gy_mldsa_verify(sig, pk, msg, sizeof(msg), NULL, 0), GY_OK);
    ASSERT_EQ(
        gy_mldsa_verify(sig, pk, msg, sizeof(msg), ctx_a, sizeof(ctx_a) - 1),
        GY_ERR_VERIFY);

    /* ctxlen over the FIPS 204 bound is rejected before the provider. */
    {
        uint8_t big[GY_MLDSA_CTX_MAX + 1] = {0};
        ASSERT_EQ(gy_mldsa_sign(sig, sk, msg, sizeof(msg), big, sizeof(big)),
                  GY_ERR_TOOLONG);
    }
}

/* Hedged signing: two signatures over identical (msg, ctx) differ; both verify. */
TEST(hedged_smoke)
{
    uint8_t pk[GY_MLDSA44_PK], sk[GY_MLDSA44_SK];
    uint8_t sig1[GY_MLDSA44_SIG], sig2[GY_MLDSA44_SIG];
    static const uint8_t msg[] = "hedged signing draws fresh randomness";
    static const uint8_t ctx[] = "prekey";

    ASSERT_EQ(gy_mldsa_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_mldsa_sign(sig1, sk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
    ASSERT_EQ(gy_mldsa_sign(sig2, sk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
    ASSERT_TRUE(memcmp(sig1, sig2, GY_MLDSA44_SIG) != 0,
                "hedged signatures differ");
    ASSERT_EQ(gy_mldsa_verify(sig1, pk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
    ASSERT_EQ(gy_mldsa_verify(sig2, pk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
}

/*
 * FIPS 204 hedged sign draws EXACTLY one 32-byte rnd per signature: the
 * rejection loop re-expands deterministically (counter kappa), it does not pull
 * fresh entropy.  Op-count the draws inside one sign to pin that the wrapper
 * neither adds nor loses a draw.
 */
TEST(sign_draws_one_rnd)
{
    uint8_t pk[GY_MLDSA44_PK], sk[GY_MLDSA44_SK], sig[GY_MLDSA44_SIG];
    static const uint8_t msg[] = "draw-count";
    static const uint8_t ctx[] = "prekey";

    ASSERT_EQ(gy_mldsa_keypair(pk, sk), GY_OK);
    gy_pq_rng_reset_draw_count();
    ASSERT_EQ(gy_mldsa_sign(sig, sk, msg, sizeof(msg), ctx, sizeof(ctx) - 1),
              GY_OK);
    ASSERT_EQ(gy_pq_rng_draw_count(), 32);
}

/*
 * sigVer known-answer: a valid ACVP ML-DSA-44 case must verify, a tampered case
 * must be rejected - binding the verify path to FIPS 204 independent of liboqs.
 */
TEST(kat_sigver_valid)
{
    uint8_t pk[GY_MLDSA44_PK], sig[GY_MLDSA44_SIG];
    uint8_t msg[MSG_CAP], ctx[GY_MLDSA_CTX_MAX];

    kat_hex(pk, sizeof(pk), GY_DSA_VER_PK);
    kat_hex(sig, sizeof(sig), GY_DSA_VER_SIG);
    kat_hex(msg, GY_DSA_VER_MSG_LEN, GY_DSA_VER_MSG);
    kat_hex(ctx, GY_DSA_VER_CTX_LEN, GY_DSA_VER_CTX);
    ASSERT_EQ(gy_mldsa_verify(sig, pk, msg, GY_DSA_VER_MSG_LEN, ctx,
                              GY_DSA_VER_CTX_LEN),
              GY_OK);
}

TEST(kat_sigver_reject)
{
    uint8_t pk[GY_MLDSA44_PK], sig[GY_MLDSA44_SIG];
    uint8_t msg[MSG_CAP], ctx[GY_MLDSA_CTX_MAX];

    kat_hex(pk, sizeof(pk), GY_DSA_REJ_PK);
    kat_hex(sig, sizeof(sig), GY_DSA_REJ_SIG);
    kat_hex(msg, GY_DSA_REJ_MSG_LEN, GY_DSA_REJ_MSG);
    kat_hex(ctx, GY_DSA_REJ_CTX_LEN, GY_DSA_REJ_CTX);
    ASSERT_EQ(gy_mldsa_verify(sig, pk, msg, GY_DSA_REJ_MSG_LEN, ctx,
                              GY_DSA_REJ_CTX_LEN),
              GY_ERR_VERIFY);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(roundtrip),          GY_TEST(keypair_invariants),
            GY_TEST(ctx_negative),       GY_TEST(hedged_smoke),
            GY_TEST(sign_draws_one_rnd), GY_TEST(kat_sigver_valid),
            GY_TEST(kat_sigver_reject),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
