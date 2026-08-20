/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/mlkem.c (ML-KEM-512, FIPS 203), built with
 * -DGY_TEST_HOOKS so the _derand seams and the pqinit RNG hooks are live.
 *
 * Scope (D-PQ-3, amended 2026-08-17): these are WRAPPER-conformance checks, not
 * a re-validation of liboqs's ML-KEM arithmetic (liboqs validates that
 * upstream, exactly as geryon runs only a few RFC 7748 vectors through the
 * libsodium X25519 wrapper, not an exhaustive suite - see test_x25519.c). They
 * pin the three things a round-trip alone does not: seed plumbing (d||z, m),
 * implicit-rejection passthrough, and - via the known-answer block
 * (mlkem512_kat.h, from the NIST ACVP FIPS 203 vectors) - the parameter set
 * and exact FIPS 203 conformance, independent of liboqs.
 *
 * Also carries the two RNG-shim tests deferred from GER-M5-02 (they need a real
 * PQ keypair call): draw-routing and the fault-injection death test.
 */

#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "error.h"
#include "mlkem.h"
#include "pqinit.h"
#include "util.h"

#include "gy_test.h"
#include "mlkem512_kat.h"

/* keypair -> encaps -> decaps agree; a second, independent keypair does not. */
TEST(roundtrip_agreement)
{
    uint8_t pk[GY_MLKEM512_PK], sk[GY_MLKEM512_SK];
    uint8_t ct[GY_MLKEM512_CT];
    uint8_t ss_enc[GY_MLKEM512_SS], ss_dec[GY_MLKEM512_SS];
    uint8_t pk2[GY_MLKEM512_PK], sk2[GY_MLKEM512_SK];
    uint8_t ss_other[GY_MLKEM512_SS];

    ASSERT_EQ(gy_mlkem_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_mlkem_encaps(ct, ss_enc, pk), GY_OK);
    ASSERT_EQ(gy_mlkem_decaps(ss_dec, ct, sk), GY_OK);
    ASSERT_MEMEQ(ss_enc, ss_dec, GY_MLKEM512_SS);

    /* A different secret key decapsulates the same ct to a different secret. */
    ASSERT_EQ(gy_mlkem_keypair(pk2, sk2), GY_OK);
    ASSERT_EQ(gy_mlkem_decaps(ss_other, ct, sk2), GY_OK);
    ASSERT_TRUE(memcmp(ss_enc, ss_other, GY_MLKEM512_SS) != 0,
                "wrong sk yields a different shared secret");
}

/* Two fresh generations differ; NULL arguments are rejected. */
TEST(keypair_invariants)
{
    uint8_t pk1[GY_MLKEM512_PK], sk1[GY_MLKEM512_SK];
    uint8_t pk2[GY_MLKEM512_PK], sk2[GY_MLKEM512_SK];

    ASSERT_EQ(gy_mlkem_keypair(pk1, sk1), GY_OK);
    ASSERT_EQ(gy_mlkem_keypair(pk2, sk2), GY_OK);
    ASSERT_TRUE(memcmp(pk1, pk2, GY_MLKEM512_PK) != 0, "public keys differ");
    ASSERT_TRUE(memcmp(sk1, sk2, GY_MLKEM512_SK) != 0, "secret keys differ");

    ASSERT_EQ(gy_mlkem_keypair(NULL, sk1), GY_ERR_ARG);
    ASSERT_EQ(gy_mlkem_keypair(pk1, NULL), GY_ERR_ARG);
}

/*
 * Seed plumbing: the derand seams are deterministic in their seed.  Identical
 * seeds must reproduce identical outputs (d||z for keypair, m for encaps); a
 * one-bit seed change must not.  This catches a wrapper that truncates,
 * reorders, or drops the seed without needing an external known answer.
 */
TEST(derand_seed_plumbing)
{
    uint8_t seed[GY_MLKEM512_KEYPAIR_SEED];
    uint8_t pk_a[GY_MLKEM512_PK], sk_a[GY_MLKEM512_SK];
    uint8_t pk_b[GY_MLKEM512_PK], sk_b[GY_MLKEM512_SK];
    uint8_t m[GY_MLKEM512_ENCAPS_SEED];
    uint8_t ct_a[GY_MLKEM512_CT], ss_a[GY_MLKEM512_SS];
    uint8_t ct_b[GY_MLKEM512_CT], ss_b[GY_MLKEM512_SS];

    memset(seed, 0x42, sizeof(seed));
    ASSERT_EQ(gy_mlkem_keypair_derand(pk_a, sk_a, seed), GY_OK);
    ASSERT_EQ(gy_mlkem_keypair_derand(pk_b, sk_b, seed), GY_OK);
    ASSERT_MEMEQ(pk_a, pk_b, GY_MLKEM512_PK);
    ASSERT_MEMEQ(sk_a, sk_b, GY_MLKEM512_SK);

    /*
     * Flip a bit in d (the first 32 bytes): ek derives from d, so pk must
     * change.  z (the trailing 32 bytes) feeds only the implicit-rejection
     * secret in dk, not ek, so a flip there would NOT change pk - the exact
     * d/z split is pinned by kat_keygen.
     */
    seed[0] ^= 0x01;
    ASSERT_EQ(gy_mlkem_keypair_derand(pk_b, sk_b, seed), GY_OK);
    ASSERT_TRUE(memcmp(pk_a, pk_b, GY_MLKEM512_PK) != 0,
                "a one-bit change in d changes the public key");

    memset(m, 0x24, sizeof(m));
    ASSERT_EQ(gy_mlkem_encaps_derand(ct_a, ss_a, pk_a, m), GY_OK);
    ASSERT_EQ(gy_mlkem_encaps_derand(ct_b, ss_b, pk_a, m), GY_OK);
    ASSERT_MEMEQ(ct_a, ct_b, GY_MLKEM512_CT);
    ASSERT_MEMEQ(ss_a, ss_b, GY_MLKEM512_SS);

    /* The derand ct/ss still round-trips through production decaps. */
    ASSERT_EQ(gy_mlkem_decaps(ss_b, ct_a, sk_a), GY_OK);
    ASSERT_MEMEQ(ss_a, ss_b, GY_MLKEM512_SS);
}

/*
 * FIPS 203 implicit rejection: a corrupt ciphertext yields GY_OK with a
 * deterministic pseudorandom secret (never an error, never the honest secret).
 * This asserts the wrapper preserves the property structurally; the exact
 * pseudorandom value is pinned by kat_decaps_implicit_reject below.
 */
TEST(implicit_rejection)
{
    uint8_t pk[GY_MLKEM512_PK], sk[GY_MLKEM512_SK];
    uint8_t ct[GY_MLKEM512_CT];
    uint8_t ss_honest[GY_MLKEM512_SS];
    uint8_t ss_rej1[GY_MLKEM512_SS], ss_rej2[GY_MLKEM512_SS];

    ASSERT_EQ(gy_mlkem_keypair(pk, sk), GY_OK);
    ASSERT_EQ(gy_mlkem_encaps(ct, ss_honest, pk), GY_OK);

    ct[0] ^= 0x01; /* corrupt one byte */

    ASSERT_EQ(gy_mlkem_decaps(ss_rej1, ct, sk), GY_OK);
    ASSERT_EQ(gy_mlkem_decaps(ss_rej2, ct, sk), GY_OK);
    ASSERT_TRUE(memcmp(ss_rej1, ss_honest, GY_MLKEM512_SS) != 0,
                "implicit rejection secret differs from the honest secret");
    ASSERT_MEMEQ(ss_rej1, ss_rej2, GY_MLKEM512_SS); /* deterministic */
}

/*
 * GER-M5-02 task 6a: a real keypair call draws through geryon's registered RNG
 * shim (D-PQ-2).  Runs on both the DIST and pure-C configs (the build matrix),
 * proving neither backend bypasses OQS_randombytes.
 */
TEST(rng_draws_through_shim)
{
    uint8_t pk[GY_MLKEM512_PK], sk[GY_MLKEM512_SK];

    gy_pq_rng_reset_draw_count();
    ASSERT_EQ(gy_mlkem_keypair(pk, sk), GY_OK);
    ASSERT_TRUE(gy_pq_rng_draw_count() > 0,
                "keypair drew random bytes through the shim");
}

/*
 * GER-M5-02 task 6b: the shim ABORTS on a fault-injected RNG failure rather
 * than returning an unfilled buffer.  Forked so the abort() does not kill the
 * test runner; the parent asserts the child died on SIGABRT.
 */
TEST(rng_failure_aborts)
{
    pid_t pid;
    int status;

    pid = fork();
    ASSERT_TRUE(pid >= 0, "fork succeeded");
    if (pid == 0) {
        uint8_t pk[GY_MLKEM512_PK], sk[GY_MLKEM512_SK];

        gy_pq_rng_set_force_fail(1);
        (void)gy_mlkem_keypair(pk, sk); /* must not return */
        _exit(0); /* reached only if it wrongly returned */
    }
    ASSERT_TRUE(waitpid(pid, &status, 0) == pid, "child reaped");
    ASSERT_TRUE(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
                "child aborted on the injected RNG failure");
}

/*
 * Known-answer tests binding gy_mlkem_* to FIPS 203, independent of liboqs
 * (mlkem512_kat.h, from the NIST ACVP FIPS 203 vectors).  A known ML-KEM-512
 * answer fails if the wrapper is ever wired to a different parameter set or
 * backing library that diverges from the standard - the same role the RFC 7748
 * vectors play for the X25519 wrapper.  Uses the GY_TEST_HOOKS _derand seams
 * for the generation cases; decaps runs the production path.
 */
static void
kat_hex(uint8_t *out, size_t n, const char *hex)
{
    ASSERT_TRUE(gy_hex_decode(out, n, hex) == (int)n, "KAT vector decoded");
}

TEST(kat_keygen)
{
    uint8_t seed[GY_MLKEM512_KEYPAIR_SEED];
    uint8_t pk[GY_MLKEM512_PK], sk[GY_MLKEM512_SK];
    uint8_t want_pk[GY_MLKEM512_PK], want_sk[GY_MLKEM512_SK];

    kat_hex(seed, sizeof(seed), GY_KAT_KG_SEED);
    kat_hex(want_pk, sizeof(want_pk), GY_KAT_KG_EK);
    kat_hex(want_sk, sizeof(want_sk), GY_KAT_KG_DK);
    ASSERT_EQ(gy_mlkem_keypair_derand(pk, sk, seed), GY_OK);
    ASSERT_MEMEQ(pk, want_pk, GY_MLKEM512_PK);
    ASSERT_MEMEQ(sk, want_sk, GY_MLKEM512_SK);
}

TEST(kat_encaps)
{
    uint8_t pk[GY_MLKEM512_PK], m[GY_MLKEM512_ENCAPS_SEED];
    uint8_t ct[GY_MLKEM512_CT], ss[GY_MLKEM512_SS];
    uint8_t want_ct[GY_MLKEM512_CT], want_ss[GY_MLKEM512_SS];

    kat_hex(pk, sizeof(pk), GY_KAT_ENC_EK);
    kat_hex(m, sizeof(m), GY_KAT_ENC_M);
    kat_hex(want_ct, sizeof(want_ct), GY_KAT_ENC_C);
    kat_hex(want_ss, sizeof(want_ss), GY_KAT_ENC_K);
    ASSERT_EQ(gy_mlkem_encaps_derand(ct, ss, pk, m), GY_OK);
    ASSERT_MEMEQ(ct, want_ct, GY_MLKEM512_CT);
    ASSERT_MEMEQ(ss, want_ss, GY_MLKEM512_SS);
}

TEST(kat_decaps_valid)
{
    uint8_t sk[GY_MLKEM512_SK], ct[GY_MLKEM512_CT];
    uint8_t ss[GY_MLKEM512_SS], want_ss[GY_MLKEM512_SS];

    kat_hex(sk, sizeof(sk), GY_KAT_DEC_DK);
    kat_hex(ct, sizeof(ct), GY_KAT_DEC_C);
    kat_hex(want_ss, sizeof(want_ss), GY_KAT_DEC_K);
    ASSERT_EQ(gy_mlkem_decaps(ss, ct, sk), GY_OK);
    ASSERT_MEMEQ(ss, want_ss, GY_MLKEM512_SS);
}

/*
 * Implicit rejection as a known answer: the ACVP "modified ciphertext" case.
 * Decaps of the tampered ct must succeed (GY_OK) and yield the FIPS 203
 * implicit-rejection secret - the exact expected value, not just "not the
 * honest secret".
 */
TEST(kat_decaps_implicit_reject)
{
    uint8_t sk[GY_MLKEM512_SK], ct[GY_MLKEM512_CT];
    uint8_t ss[GY_MLKEM512_SS], want_ss[GY_MLKEM512_SS];

    kat_hex(sk, sizeof(sk), GY_KAT_REJ_DK);
    kat_hex(ct, sizeof(ct), GY_KAT_REJ_C);
    kat_hex(want_ss, sizeof(want_ss), GY_KAT_REJ_K);
    ASSERT_EQ(gy_mlkem_decaps(ss, ct, sk), GY_OK);
    ASSERT_MEMEQ(ss, want_ss, GY_MLKEM512_SS);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(roundtrip_agreement),
            GY_TEST(keypair_invariants),
            GY_TEST(derand_seed_plumbing),
            GY_TEST(implicit_rejection),
            GY_TEST(rng_draws_through_shim),
            GY_TEST(rng_failure_aborts),
            GY_TEST(kat_keygen),
            GY_TEST(kat_encaps),
            GY_TEST(kat_decaps_valid),
            GY_TEST(kat_decaps_implicit_reject),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
