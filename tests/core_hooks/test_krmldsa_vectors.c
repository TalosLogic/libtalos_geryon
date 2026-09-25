/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen self-KAT check for KR-ML-DSA-44/87 (QSPGS_SPEC.md section 12,
 * D-QGS-10), built with -DGY_TEST_HOOKS so it links the recompiled
 * core slice + the per-backend krmldsa OBJECT tables.
 *
 * For each parameter set it recomputes, from fixed inputs, the base keypair
 * (deterministic keygen from a seed), the rerandomized verifying key
 * (RandVK(rho)), and a signature (RandSK(rho) + the deterministic sign core
 * gy_kr<set>_sign_rnd with a fixed rnd), and asserts they reproduce the
 * committed bytes in krmldsa_kat.h.  Each committed signature is also verified
 * with the UNMODIFIED public liboqs verifier (gy_mldsa<set>_verify via
 * gy_kr<set>_verify), and rho_A is checked to be the first 32 bytes of vkb.
 *
 * There is no external oracle (no [CFG+] authors' implementation);
 * the vectors are geryon's own, UNFROZEN until the [CFG+] revision pin.  Because
 * vkb / vkr / sig are byte-standard, the same committed vectors must reproduce
 * on every backend, so running this test built for each backend is the
 * cross-backend agreement check.
 *
 * Until the vectors are captured (KRMLDSA_KAT_POPULATED == 0) this test SKIPs
 * (exit 77).  To capture, run with --dump and redirect over
 * tests/core_hooks/krmldsa_kat.h, review, and rebuild.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "mldsa44.h"
#include "mldsa87.h"
#include "util.h"

#include "gy_test.h"

#include "krmldsa_kat.h"

/* Fixed KAT inputs, shared by every set (see krmldsa_kat.h header comment). */
static const uint8_t kat_msg[] = "geryon KR-ML-DSA KAT message";
static const uint8_t kat_ctx[] = "geryon:qspgs:psdn";
#define KAT_MLEN (sizeof(kat_msg) - 1)
#define KAT_CLEN (sizeof(kat_ctx) - 1)

/* out[i] = base + i (mod 256): the deterministic seed / rho / rnd patterns. */
static void
fill_seq(uint8_t *out, size_t n, unsigned base)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(base + i);
}

/* Emit one hex #define, 32 bytes (64 hex chars) per continuation line. */
static void
emit_hex(const char *name, const uint8_t *p, size_t n)
{
    size_t i;

    printf("#define %s \\\n    \"", name);
    for (i = 0; i < n; i++) {
        printf("%02X", p[i]);
        if ((i + 1) % 32 == 0 && i + 1 < n)
            printf("\"   \\\n    \"");
    }
    printf("\"\n");
}

/*
 * Generate the per-set compute / check / dump routines.  set = 44 | 87 as a
 * token for the gy_kr<set>_* / gy_mldsa<set>_* symbols and the GY_KR<set>_*
 * size macros; both sets stay in lockstep by construction (the "both tiers"
 * requirement).  compute returns 0 on success, -1 on any provider error.
 */
#define GEN_SET(set)                                                           \
    static int kr##set##_compute(uint8_t *vkb, uint8_t *skb, uint8_t *vkr,     \
                                 uint8_t *sig)                                 \
    {                                                                          \
        uint8_t seed[GY_KR##set##_SEED];                                       \
        uint8_t rho[GY_KR##set##_RAND];                                        \
        uint8_t rnd[GY_KR##set##_SIGN_RND];                                    \
        gy_kr##set##_rsk_t rsk;                                                \
        int rc;                                                                \
                                                                               \
        fill_seq(seed, sizeof(seed), 1);                                       \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        fill_seq(rnd, sizeof(rnd), 0x80);                                      \
                                                                               \
        if (gy_kr##set##_keygen_base_seed(vkb, skb, seed) != GY_OK)            \
            return -1;                                                         \
        if (gy_kr##set##_randvk(vkr, vkb, rho) != GY_OK)                       \
            return -1;                                                         \
        if (gy_kr##set##_randsk(&rsk, skb, vkb, rho) != GY_OK)                 \
            return -1;                                                         \
        rc = gy_kr##set##_sign_rnd(sig, &rsk, kat_msg, KAT_MLEN, kat_ctx,      \
                                   KAT_CLEN, rnd);                             \
        gy_kr##set##_rsk_clear(&rsk);                                          \
        return rc == GY_OK ? 0 : -1;                                           \
    }                                                                          \
                                                                               \
    static void kr##set##_check(void)                                          \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
        uint8_t evkb[GY_KR##set##_VKB], eskb[GY_KR##set##_SKB];                \
        uint8_t evkr[GY_KR##set##_VKR], esig[GY_KR##set##_SIG];                \
        uint8_t rho_a[32];                                                     \
                                                                               \
        ASSERT_EQ(kr##set##_compute(vkb, skb, vkr, sig), 0);                   \
                                                                               \
        ASSERT_EQ(gy_hex_decode(evkb, sizeof(evkb), GY_KR##set##_KAT_VKB),     \
                  (int)sizeof(evkb));                                          \
        ASSERT_EQ(gy_hex_decode(eskb, sizeof(eskb), GY_KR##set##_KAT_SKB),     \
                  (int)sizeof(eskb));                                          \
        ASSERT_EQ(gy_hex_decode(evkr, sizeof(evkr), GY_KR##set##_KAT_VKR),     \
                  (int)sizeof(evkr));                                          \
        ASSERT_EQ(gy_hex_decode(esig, sizeof(esig), GY_KR##set##_KAT_SIG),     \
                  (int)sizeof(esig));                                          \
        ASSERT_EQ(gy_hex_decode(rho_a, sizeof(rho_a), GY_KR##set##_KAT_RHO_A), \
                  (int)sizeof(rho_a));                                         \
                                                                               \
        ASSERT_MEMEQ(vkb, evkb, sizeof(vkb));                                  \
        ASSERT_MEMEQ(skb, eskb, sizeof(skb));                                  \
        ASSERT_MEMEQ(vkr, evkr, sizeof(vkr));                                  \
        ASSERT_MEMEQ(sig, esig, sizeof(sig));                                  \
        /* rho_A is the first 32 bytes of the base verifying key. */           \
        ASSERT_MEMEQ(vkb, rho_a, sizeof(rho_a));                               \
        /* The signature verifies under the UNMODIFIED public verifier. */     \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr, kat_msg, KAT_MLEN, kat_ctx,    \
                                      KAT_CLEN),                               \
                  GY_OK);                                                      \
    }                                                                          \
                                                                               \
    static int kr##set##_dump(void)                                            \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
                                                                               \
        if (kr##set##_compute(vkb, skb, vkr, sig) != 0)                        \
            return -1;                                                         \
        printf("\n/* KR-ML-DSA-" #set                                          \
               " (fixed inputs: seed[i]=i+1, rho[i]=0x40+i,\n"                 \
               " * rnd[i]=0x80+i, msg=\"%s\", ctx=\"%s\"). */\n",              \
               kat_msg, kat_ctx);                                              \
        emit_hex("GY_KR" #set "_KAT_RHO_A", vkb, 32);                          \
        emit_hex("GY_KR" #set "_KAT_VKB", vkb, sizeof(vkb));                   \
        emit_hex("GY_KR" #set "_KAT_SKB", skb, sizeof(skb));                   \
        emit_hex("GY_KR" #set "_KAT_VKR", vkr, sizeof(vkr));                   \
        emit_hex("GY_KR" #set "_KAT_SIG", sig, sizeof(sig));                   \
        return 0;                                                              \
    }

GEN_SET(44)
GEN_SET(87)

static void
dump(void)
{
    printf(
        "/*\n"
        " * Copyright (c) 2026 Jason Crawford\n"
        " * SPDX-License-Identifier: AGPL-3.0-only\n"
        " *\n"
        " * KR-ML-DSA-44/87 self-KAT vectors (QSPGS_SPEC.md section 12,\n"
        " * D-QGS-10).  geryon's own constants (no oracle).  FROZEN\n"
        " * 2026-09-16 (v1.5.0 close-out): pinned to geryon's reading of\n"
        " * the [CFG+] 2026/453 preprint; no longer regenerated on\n"
        " * refactor.  A later [CFG+] revision is a D-QGS-12 format_version\n"
        " * bump with a deliberate re-cut.\n"
        " *\n"
        " * GENERATED, do not edit by hand.\n"
        " */\n\n");
    printf("#ifndef GY_KRMLDSA_KAT_H\n#define GY_KRMLDSA_KAT_H\n\n");
    printf("#define KRMLDSA_KAT_POPULATED 1\n");
    if (kr44_dump() != 0 || kr87_dump() != 0) {
        fprintf(stderr, "dump: compute failed\n");
        return;
    }
    printf("\n#endif /* GY_KRMLDSA_KAT_H */\n");
}

int
main(int argc, char **argv)
{
    /* Custom main (for --dump / SKIP) instead of GY_TEST_MAIN, so gy_test_run
     * is otherwise unused; mark it referenced to satisfy -Werror. */
    (void)gy_test_run;

    if (gy_core_init() != GY_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        dump();
        return 0;
    }

    if (!KRMLDSA_KAT_POPULATED) {
        fprintf(stderr, "KR-ML-DSA vectors not captured; SKIP.\n"
                        "  Capture: ./tests/test_krmldsa_vectors --dump > \\\n"
                        "    tests/core_hooks/krmldsa_kat.h\n");
        return 77;
    }

    kr44_check();
    kr87_check();

    printf("\n%d assertions, %d failures\n", gy_test_asserts, gy_test_failures);
    return gy_test_failures == 0 ? 0 : 1;
}
