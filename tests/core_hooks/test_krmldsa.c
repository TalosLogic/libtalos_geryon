/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Property and negative tests for KR-ML-DSA-44/87 (QSPGS_SPEC.md section 3.3,
 * D-QGS-11), built with -DGY_TEST_HOOKS so it links the recompiled
 * core slice + the per-backend krmldsa OBJECT tables.  These need no committed
 * vectors and run on whatever backend the process selected; the byte KATs and
 * cross-backend agreement live in test_krmldsa_vectors.c.
 *
 * Covered per set (kept in lockstep by the GEN_PROP macro):
 *   - roundtrip: Gen -> RandVK -> RandSK -> Sgn verifies; tampered msg fails.
 *   - deterministic core: gy_kr<set>_sign_rnd is a pure function of its inputs
 *     (same rnd => same bytes); the hedged gy_kr<set>_sign differs per call;
 *     both verify.
 *   - verify is the public API: a KR signature verifies under the UNMODIFIED
 *     gy_mldsa<set>_verify exactly as under gy_kr<set>_verify ([CFG+] 2.2).
 *   - foreign rho rejected: a base key whose rho_A field is corrupted is
 *     rejected by RandVK and RandSK (GY_ERR_ARG), the D-QGS-11 item 5 policy.
 *   - attribution: a signature under vk_psdn(rho) does NOT verify under
 *     vk_psdn(rho'); a tampered signature is rejected.
 *   - NULL argument checks.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "mldsa44.h"
#include "mldsa87.h"
#include "util.h"

#include "gy_test.h"

static void
fill_seq(uint8_t *out, size_t n, unsigned base)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(base + i);
}

static const uint8_t pmsg[] = "KR-ML-DSA property message";
static const uint8_t pctx[] = "geryon:qspgs:psdn";
#define PMLEN (sizeof(pmsg) - 1)
#define PCLEN (sizeof(pctx) - 1)

#define GEN_PROP(set)                                                          \
    /* Full valid setup for rho: vkb, skb, rsk, vkr. */                        \
    static int kr##set##_setup(uint8_t *vkb, uint8_t *skb,                     \
                               gy_kr##set##_rsk_t *rsk, uint8_t *vkr,          \
                               const uint8_t *rho)                             \
    {                                                                          \
        if (gy_kr##set##_keygen_base(vkb, skb) != GY_OK)                       \
            return -1;                                                         \
        if (gy_kr##set##_randvk(vkr, vkb, rho) != GY_OK)                       \
            return -1;                                                         \
        if (gy_kr##set##_randsk(rsk, skb, vkb, rho) != GY_OK)                  \
            return -1;                                                         \
        return 0;                                                              \
    }                                                                          \
                                                                               \
    TEST(kr##set##_roundtrip)                                                  \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
        uint8_t rho[GY_KR##set##_RAND], bad[PMLEN];                            \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        ASSERT_EQ(kr##set##_setup(vkb, skb, &rsk, vkr, rho), 0);               \
        ASSERT_EQ(gy_kr##set##_sign(sig, &rsk, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr, pmsg, PMLEN, pctx, PCLEN),     \
                  GY_OK);                                                      \
        memcpy(bad, pmsg, PMLEN);                                              \
        bad[0] ^= 0x01;                                                        \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr, bad, PMLEN, pctx, PCLEN),      \
                  GY_ERR_VERIFY);                                              \
        gy_kr##set##_rsk_clear(&rsk);                                          \
    }                                                                          \
                                                                               \
    TEST(kr##set##_sign_rnd_deterministic)                                     \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], rho[GY_KR##set##_RAND];                 \
        uint8_t rnd[GY_KR##set##_SIGN_RND];                                    \
        uint8_t s1[GY_KR##set##_SIG], s2[GY_KR##set##_SIG];                    \
        uint8_t h1[GY_KR##set##_SIG], h2[GY_KR##set##_SIG];                    \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        fill_seq(rnd, sizeof(rnd), 0x80);                                      \
        ASSERT_EQ(kr##set##_setup(vkb, skb, &rsk, vkr, rho), 0);               \
        /* Same rnd => byte-identical signature (pure deterministic core). */  \
        ASSERT_EQ(                                                             \
            gy_kr##set##_sign_rnd(s1, &rsk, pmsg, PMLEN, pctx, PCLEN, rnd),    \
            GY_OK);                                                            \
        ASSERT_EQ(                                                             \
            gy_kr##set##_sign_rnd(s2, &rsk, pmsg, PMLEN, pctx, PCLEN, rnd),    \
            GY_OK);                                                            \
        ASSERT_MEMEQ(s1, s2, sizeof(s1));                                      \
        /* Hedged path draws fresh rnd => two signatures differ; both OK. */   \
        ASSERT_EQ(gy_kr##set##_sign(h1, &rsk, pmsg, PMLEN, pctx, PCLEN),       \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_kr##set##_sign(h2, &rsk, pmsg, PMLEN, pctx, PCLEN),       \
                  GY_OK);                                                      \
        ASSERT_TRUE(memcmp(h1, h2, sizeof(h1)) != 0,                           \
                    "hedged signatures differ");                               \
        ASSERT_EQ(gy_kr##set##_verify(h1, vkr, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_kr##set##_verify(h2, vkr, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_OK);                                                      \
        gy_kr##set##_rsk_clear(&rsk);                                          \
    }                                                                          \
                                                                               \
    TEST(kr##set##_verify_is_public)                                           \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
        uint8_t rho[GY_KR##set##_RAND];                                        \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        ASSERT_EQ(kr##set##_setup(vkb, skb, &rsk, vkr, rho), 0);               \
        ASSERT_EQ(gy_kr##set##_sign(sig, &rsk, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_OK);                                                      \
        /* vkr is a byte-standard ML-DSA pk; the stock verifier accepts it. */ \
        ASSERT_EQ(gy_mldsa##set##_verify(sig, vkr, pmsg, PMLEN, pctx, PCLEN),  \
                  GY_OK);                                                      \
        gy_kr##set##_rsk_clear(&rsk);                                          \
    }                                                                          \
                                                                               \
    TEST(kr##set##_foreign_rho_rejected)                                       \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], rho[GY_KR##set##_RAND];                 \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        ASSERT_EQ(gy_kr##set##_keygen_base(vkb, skb), GY_OK);                  \
        /* Corrupt the rho_A field (vkb[0..32)): RandVK/RandSK must reject. */ \
        vkb[0] ^= 0x01;                                                        \
        ASSERT_EQ(gy_kr##set##_randvk(vkr, vkb, rho), GY_ERR_ARG);             \
        ASSERT_EQ(gy_kr##set##_randsk(&rsk, skb, vkb, rho), GY_ERR_ARG);       \
    }                                                                          \
                                                                               \
    TEST(kr##set##_attribution)                                                \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], vkr2[GY_KR##set##_VKR];                 \
        uint8_t sig[GY_KR##set##_SIG];                                         \
        uint8_t rho[GY_KR##set##_RAND], rho2[GY_KR##set##_RAND];               \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        fill_seq(rho2, sizeof(rho2), 0x11);                                    \
        ASSERT_EQ(kr##set##_setup(vkb, skb, &rsk, vkr, rho), 0);               \
        ASSERT_EQ(gy_kr##set##_randvk(vkr2, vkb, rho2), GY_OK);                \
        ASSERT_EQ(gy_kr##set##_sign(sig, &rsk, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_OK);                                                      \
        /* A signature under vk_psdn(rho) must not verify under rho'. */       \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr2, pmsg, PMLEN, pctx, PCLEN),    \
                  GY_ERR_VERIFY);                                              \
        /* A single-byte tamper in the signature is rejected. */               \
        sig[0] ^= 0x01;                                                        \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr, pmsg, PMLEN, pctx, PCLEN),     \
                  GY_ERR_VERIFY);                                              \
        gy_kr##set##_rsk_clear(&rsk);                                          \
    }                                                                          \
                                                                               \
    TEST(kr##set##_null_args)                                                  \
    {                                                                          \
        uint8_t vkb[GY_KR##set##_VKB], skb[GY_KR##set##_SKB];                  \
        uint8_t vkr[GY_KR##set##_VKR], sig[GY_KR##set##_SIG];                  \
        uint8_t rho[GY_KR##set##_RAND];                                        \
        uint8_t rnd[GY_KR##set##_SIGN_RND];                                    \
        gy_kr##set##_rsk_t rsk;                                                \
                                                                               \
        fill_seq(rho, sizeof(rho), 0x40);                                      \
        fill_seq(rnd, sizeof(rnd), 0x80);                                      \
        ASSERT_EQ(kr##set##_setup(vkb, skb, &rsk, vkr, rho), 0);               \
        ASSERT_EQ(gy_kr##set##_keygen_base(NULL, skb), GY_ERR_ARG);            \
        ASSERT_EQ(gy_kr##set##_keygen_base_seed(vkb, skb, NULL), GY_ERR_ARG);  \
        ASSERT_EQ(gy_kr##set##_randvk(NULL, vkb, rho), GY_ERR_ARG);            \
        ASSERT_EQ(gy_kr##set##_randsk(&rsk, skb, NULL, rho), GY_ERR_ARG);      \
        ASSERT_EQ(gy_kr##set##_sign(sig, NULL, pmsg, PMLEN, pctx, PCLEN),      \
                  GY_ERR_ARG);                                                 \
        ASSERT_EQ(                                                             \
            gy_kr##set##_sign_rnd(sig, &rsk, pmsg, PMLEN, pctx, PCLEN, NULL),  \
            GY_ERR_ARG);                                                       \
        gy_kr##set##_rsk_clear(&rsk);                                          \
    }

GEN_PROP(44)
GEN_PROP(87)

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(kr44_roundtrip),
            GY_TEST(kr44_sign_rnd_deterministic),
            GY_TEST(kr44_verify_is_public),
            GY_TEST(kr44_foreign_rho_rejected),
            GY_TEST(kr44_attribution),
            GY_TEST(kr44_null_args),
            GY_TEST(kr87_roundtrip),
            GY_TEST(kr87_sign_rnd_deterministic),
            GY_TEST(kr87_verify_is_public),
            GY_TEST(kr87_foreign_rho_rejected),
            GY_TEST(kr87_attribution),
            GY_TEST(kr87_null_args),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
