/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * KR-ML-DSA-44/87 sign/verify benchmark (QSPGS_SPEC.md section 12, D-QGS-10).
 * This is the number the D-QGS-7 wire freeze
 * waits on: it must land before the wire format freezes so the layout is not
 * chosen on unmeasured cost assumptions (the design cost model records the
 * failed cost assumption that drove the whole reversal; do not repeat it).
 *
 * Not a CTest case: it is a standalone, manually-run report (the libtalos_
 * voleith examples/ model, using the same bench_util.h methodology), because
 * timings are advisory and machine-specific.  It links geryon_core to reach
 * the INTERNAL gy_kr<set>_* primitive directly, below the public QSPGS API.
 *
 * Record the numbers (this machine, min/median) against the design cost model
 * and cross-check them.  Signing cost is dominated by
 * the 2*beta rejection loop (about 18 / 15 expected attempts at 44 / 87 per
 * [CFG+] Table 1), so the sign distribution is deliberately wide; min is the
 * best-case single-attempt cost, mean the practical per-signature cost.
 *
 * Usage: bench_krmldsa [iters]   (default 200, plus a fixed warmup).
 */

#define _POSIX_C_SOURCE 199309L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "util.h"

#define BENCH_WARMUP 8
#define BENCH_MAX_ITERS 5000

static const uint8_t bmsg[] = "geryon KR-ML-DSA benchmark message";
static const uint8_t bctx[] = "geryon:qspgs:psdn";
#define BMLEN (sizeof(bmsg) - 1)
#define BCLEN (sizeof(bctx) - 1)

static void
fill_seq(uint8_t *out, size_t n, unsigned base)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(base + i);
}

/*
 * One timed loop.  op runs a single operation for iteration i (return 0 on
 * success); the wall-clock ms of each call is recorded and summarized.  A
 * failed op aborts the run (a benchmark over a broken primitive is noise).
 */
#define GEN_BENCH(set)                                                         \
    static int bench_kr##set(size_t iters, double *samples)                    \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
        uint8_t seed[GY_KR##set##_SEED], rho[GY_KR##set##_RAND];               \
        gy_kr##set##_rsk_t rsk;                                                \
        bench_stats_t st;                                                      \
        uint64_t t0;                                                           \
        size_t i;                                                              \
                                                                               \
        fill_seq(seed, sizeof(seed), 1);                                       \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
                                                                               \
        printf("KR-ML-DSA-" #set " (%zu iters):\n", iters);                    \
                                                                               \
        /* keygen_base (hedged). */                                            \
        for (i = 0; i < BENCH_WARMUP; i++)                                     \
            if (gy_kr##set##_keygen_base(vkb, skb) != GY_OK)                   \
                return -1;                                                     \
        for (i = 0; i < iters; i++) {                                          \
            t0 = bench_now_ns();                                               \
            if (gy_kr##set##_keygen_base(vkb, skb) != GY_OK)                   \
                return -1;                                                     \
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;                  \
        }                                                                      \
        bench_print("keygen", bench_compute(samples, iters));                  \
                                                                               \
        /* Fix a base keypair for the remaining ops. */                        \
        if (gy_kr##set##_keygen_base_seed(vkb, skb, seed) != GY_OK)            \
            return -1;                                                         \
                                                                               \
        /* RandVK. */                                                          \
        for (i = 0; i < iters; i++) {                                          \
            t0 = bench_now_ns();                                               \
            if (gy_kr##set##_randvk(vkr, vkb, rho) != GY_OK)                   \
                return -1;                                                     \
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;                  \
        }                                                                      \
        bench_print("randvk", bench_compute(samples, iters));                  \
                                                                               \
        /* RandSK. */                                                          \
        for (i = 0; i < iters; i++) {                                          \
            t0 = bench_now_ns();                                               \
            if (gy_kr##set##_randsk(&rsk, skb, vkb, rho) != GY_OK)             \
                return -1;                                                     \
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;                  \
            gy_kr##set##_rsk_clear(&rsk);                                      \
        }                                                                      \
        bench_print("randsk", bench_compute(samples, iters));                  \
                                                                               \
        /* Sign (hedged): the 2*beta rejection loop dominates. */              \
        if (gy_kr##set##_randsk(&rsk, skb, vkb, rho) != GY_OK)                 \
            return -1;                                                         \
        for (i = 0; i < iters; i++) {                                          \
            t0 = bench_now_ns();                                               \
            if (gy_kr##set##_sign(sig, &rsk, bmsg, BMLEN, bctx, BCLEN) !=      \
                GY_OK)                                                         \
                return -1;                                                     \
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;                  \
        }                                                                      \
        st = bench_compute(samples, iters);                                    \
        bench_print("sign", st);                                               \
                                                                               \
        /* Verify (the unmodified public verifier). */                         \
        if (gy_kr##set##_sign(sig, &rsk, bmsg, BMLEN, bctx, BCLEN) != GY_OK)   \
            return -1;                                                         \
        for (i = 0; i < iters; i++) {                                          \
            t0 = bench_now_ns();                                               \
            if (gy_kr##set##_verify(sig, vkr, bmsg, BMLEN, bctx, BCLEN) !=     \
                GY_OK) {                                                       \
                /* vkr matches rho; sig is under the same rho: must verify. */ \
                gy_kr##set##_rsk_clear(&rsk);                                  \
                return -1;                                                     \
            }                                                                  \
            samples[i] = (double)(bench_now_ns() - t0) / 1e6;                  \
        }                                                                      \
        bench_print("verify", bench_compute(samples, iters));                  \
                                                                               \
        gy_kr##set##_rsk_clear(&rsk);                                          \
        return 0;                                                              \
    }

GEN_BENCH(44)
GEN_BENCH(87)

int
main(int argc, char **argv)
{
    static double samples[BENCH_MAX_ITERS];
    size_t iters = 200;

    if (gy_core_init() != GY_OK) {
        fprintf(stderr, "gy_core_init failed\n");
        return 1;
    }

    if (argc > 1) {
        long v = strtol(argv[1], NULL, 10);
        if (v < 1 || v > BENCH_MAX_ITERS) {
            fprintf(stderr, "iters must be in [1, %d]\n", BENCH_MAX_ITERS);
            return 1;
        }
        iters = (size_t)v;
    }

    if (bench_kr44(iters, samples) != 0 || bench_kr87(iters, samples) != 0) {
        fprintf(stderr, "benchmark: a primitive call failed\n");
        return 1;
    }
    return 0;
}
