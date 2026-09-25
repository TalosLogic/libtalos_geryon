/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS key-hierarchy property / negative tests, both tiers.
 *
 * Covered per suite (kept in lockstep by the GEN macro):
 *   - derivations are deterministic and input-separated (uk varies with ep,
 *     rho varies with UID; acq / expKey / ek / rrs reproducible);
 *   - the base pair is INDEPENDENT of muk (section 2.1): a fixed seed fixes
 *     vkbase regardless of any muk derivation;
 *   - the pseudonym pair round-trips: RandVK(rho) + RandSK(rho) sign / verify,
 *     and vkpsdn is a deterministic function of rho;
 *   - skpers signs / verifies under BOTH schemes, with tamper and wrong-context
 *     rejection and no single-signature accept;
 *   - non-hybrid suites and NULL arguments are rejected.
 *
 * The frozen byte KATs live in test_qspgs_vectors.c (SKIP until captured).
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "qspgs_keys.h"
#include "qspgs_labels.h"
#include "qspgs_pers.h"
#include "qspgs_server.h" /* gy_qspgs_server_fetch_check (both facades linked) */
#include "qspgs_wire.h"   /* struct gy_qspgs_core, GY_QSPGS_FET_LEN */
#include "suite.h"
#include "util.h"

#include "gy_test.h"

static const uint8_t sample_uid[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                       0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                       0xdd, 0xee, 0xff, 0x01};
static const uint8_t sample_uid2[16] = {0x22, 0x22, 0x33, 0x44, 0x55, 0x66,
                                        0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                                        0xdd, 0xee, 0xff, 0x01};

/*
 * Per-suite block.  set = 44 / 87 (the KR-ML-DSA parameter set for the tier),
 * suite = the GY_SUITE_* id.  The pseudonym round-trip reaches gy_kr<set>_*
 * directly (there is no QSPGS wrapper for signing under skpsdn yet; that is
 * client operation code).
 */
#define GEN(set, suite)                                                          \
    TEST(q##set##_derivations)                                                   \
    {                                                                            \
        uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], gk[GY_QSPGS_MASTER_KEY_MAX];       \
        uint8_t uk1[GY_QSPGS_MASTER_KEY_MAX], uk2[GY_QSPGS_MASTER_KEY_MAX];      \
        uint8_t acq1[GY_QSPGS_MASTER_KEY_MAX], acq2[GY_QSPGS_MASTER_KEY_MAX];    \
        uint8_t exp1[GY_QSPGS_EXPKEY_BYTES], exp2[GY_QSPGS_EXPKEY_BYTES];        \
        uint8_t ek1[GY_QSPGS_EK_BYTES], ek2[GY_QSPGS_EK_BYTES];                  \
        uint8_t rrs1[GY_QSPGS_RRS_BYTES], rrs2[GY_QSPGS_RRS_BYTES];              \
        uint8_t rho1[GY_QSPGS_RHO_BYTES], rho2[GY_QSPGS_RHO_BYTES];              \
        size_t mk = gy_qspgs_master_key_len(suite);                              \
        memset(muk, 0x5a, sizeof(muk));                                          \
        memset(gk, 0xa5, sizeof(gk));                                            \
                                                                                 \
        /* uk: deterministic, and separated by epoch. */                         \
        ASSERT_EQ(gy_qspgs_derive_uk(suite, muk, 1, uk1), GY_OK);                \
        ASSERT_EQ(gy_qspgs_derive_uk(suite, muk, 1, uk2), GY_OK);                \
        ASSERT_MEMEQ(uk1, uk2, mk);                                              \
        ASSERT_EQ(gy_qspgs_derive_uk(suite, muk, 2, uk2), GY_OK);                \
        ASSERT_TRUE(memcmp(uk1, uk2, mk) != 0, "uk must vary with epoch");       \
                                                                                 \
        /* acq / expKey: deterministic from uk. */                               \
        ASSERT_EQ(gy_qspgs_derive_acq(suite, uk1, acq1), GY_OK);                 \
        ASSERT_EQ(gy_qspgs_derive_acq(suite, uk1, acq2), GY_OK);                 \
        ASSERT_MEMEQ(acq1, acq2, mk);                                            \
        ASSERT_EQ(gy_qspgs_derive_exp_key(suite, uk1, exp1), GY_OK);             \
        ASSERT_EQ(gy_qspgs_derive_exp_key(suite, uk1, exp2), GY_OK);             \
        ASSERT_MEMEQ(exp1, exp2, sizeof(exp1));                                  \
        ASSERT_TRUE(memcmp(acq1, exp1, GY_QSPGS_EXPKEY_BYTES) != 0,              \
                    "acq and expKey must differ (label separation)");            \
                                                                                 \
        /* sub-key: deterministic split ek || rrs. */                            \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek1, rrs1), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek2, rrs2), GY_OK);         \
        ASSERT_MEMEQ(ek1, ek2, sizeof(ek1));                                     \
        ASSERT_MEMEQ(rrs1, rrs2, sizeof(rrs1));                                  \
        ASSERT_TRUE(memcmp(ek1, rrs1, GY_QSPGS_EK_BYTES) != 0,                   \
                    "ek and rrs must differ");                                   \
                                                                                 \
        /* rho: deterministic, separated by UID. */                              \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, rrs1, sample_uid, 16, rho1),        \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, rrs1, sample_uid, 16, rho2),        \
                  GY_OK);                                                        \
        ASSERT_MEMEQ(rho1, rho2, sizeof(rho1));                                  \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, rrs1, sample_uid2, 16, rho2),       \
                  GY_OK);                                                        \
        ASSERT_TRUE(memcmp(rho1, rho2, sizeof(rho1)) != 0,                       \
                    "rho must vary with UID");                                   \
    }                                                                            \
                                                                                 \
    TEST(q##set##_base_independence)                                             \
    {                                                                            \
        uint8_t seed[32];                                                        \
        uint8_t vkb1[GY_QSPGS_VKB_MAX], skb1[GY_QSPGS_SKB_MAX];                  \
        uint8_t vkb2[GY_QSPGS_VKB_MAX], skb2[GY_QSPGS_SKB_MAX];                  \
        uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], uk[GY_QSPGS_MASTER_KEY_MAX];       \
        size_t vkblen = (set == 44) ? GY_KR44_VKB : GY_KR87_VKB;                 \
        size_t skblen = (set == 44) ? GY_KR44_SKB : GY_KR87_SKB;                 \
        memset(seed, 0x07, sizeof(seed));                                        \
                                                                                 \
        /* Fixed seed => fixed base pair. */                                     \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb1, skb1, seed), GY_OK);    \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb2, skb2, seed), GY_OK);    \
        ASSERT_MEMEQ(vkb1, vkb2, vkblen);                                        \
        ASSERT_MEMEQ(skb1, skb2, skblen);                                        \
                                                                                 \
        /* Section 2.1: vkbase does not depend on muk.  Deriving user keys     \
         * from any muk leaves the seed-derived base pair identical. */ \
        memset(muk, 0x33, sizeof(muk));                                          \
        ASSERT_EQ(gy_qspgs_derive_uk(suite, muk, 1, uk), GY_OK);                 \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb2, skb2, seed), GY_OK);    \
        ASSERT_MEMEQ(vkb1, vkb2, vkblen);                                        \
    }                                                                            \
                                                                                 \
    TEST(q##set##_pseudonym_roundtrip)                                           \
    {                                                                            \
        uint8_t seed[32], rho[GY_QSPGS_RHO_BYTES], rhob[GY_QSPGS_RHO_BYTES];     \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                    \
        uint8_t vkr[GY_QSPGS_VKR_MAX], vkr2[GY_QSPGS_VKR_MAX];                   \
        uint8_t sig[GY_KR##set##_SIG];                                           \
        gy_qspgs_psdn_sk_t sk;                                                   \
        const uint8_t msg[] = "geryon QSPGS pseudonym message";                  \
        const uint8_t ctx[] = "geryon:qspgs:psdn";                               \
        size_t vkrlen = GY_KR##set##_VKR;                                        \
        memset(seed, 0x11, sizeof(seed));                                        \
                                                                                 \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);      \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, sample_uid, 16, rho),         \
                  GY_OK);                                                        \
                                                                                 \
        /* vkpsdn is a deterministic function of rho. */                         \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr2, vkb, rho), GY_OK);        \
        ASSERT_MEMEQ(vkr, vkr2, vkrlen);                                         \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, sample_uid2, 16, rhob),       \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr2, vkb, rhob), GY_OK);       \
        ASSERT_TRUE(memcmp(vkr, vkr2, vkrlen) != 0,                              \
                    "distinct rho => distinct vkpsdn");                          \
                                                                                 \
        /* RandSK(rho) signs; the matching RandVK(rho) verifies. */              \
        ASSERT_EQ(gy_qspgs_derive_sk_psdn(suite, &sk, skb, vkb, rho), GY_OK);    \
        ASSERT_EQ(sk.suite_id, suite);                                           \
        ASSERT_EQ(gy_kr##set##_sign(sig, &sk.rsk.k##set, msg, sizeof(msg) - 1,   \
                                    ctx, sizeof(ctx) - 1),                       \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_kr##set##_verify(sig, vkr, msg, sizeof(msg) - 1, ctx,       \
                                      sizeof(ctx) - 1),                          \
                  GY_OK);                                                        \
        gy_qspgs_psdn_sk_clear(&sk);                                             \
        ASSERT_EQ(sk.suite_id, 0);                                               \
        /* Zeroization: the in-memory skpsdn is wiped on clear. */               \
        {                                                                        \
            uint8_t zero[GY_KR##set##_RSK_BYTES] = {0};                          \
            ASSERT_MEMEQ(sk.rsk.k##set.opaque, zero, GY_KR##set##_RSK_BYTES);    \
        }                                                                        \
    }                                                                            \
                                                                                 \
    TEST(q##set##_pers_dual)                                                     \
    {                                                                            \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                    \
        uint8_t cpk[GY_CURVE_PK_MAX], csk[GY_CURVE_SK_MAX];                      \
        uint8_t mpk[GY_DSA_PK_MAX], msk[GY_DSA_SK_MAX];                          \
        uint8_t ed[GY_QSPGS_PERS_ED_SIG_MAX];                                    \
        uint8_t ml[GY_QSPGS_PERS_MLDSA_SIG_MAX];                                 \
        uint8_t obj[128];                                                        \
        memset(obj, 0x42, sizeof(obj));                                          \
                                                                                 \
        ASSERT_EQ(d->keypair(cpk, csk), GY_OK);                                  \
        ASSERT_EQ(d->dsa_keypair(mpk, msk), GY_OK);                              \
                                                                                 \
        ASSERT_EQ(gy_qspgs_pers_sign(suite, csk, msk, GY_QSPGS_CTX_REGUSER,      \
                                     obj, sizeof(obj), ed, ml),                  \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_pers_verify(suite, cpk, mpk, GY_QSPGS_CTX_REGUSER,    \
                                       obj, sizeof(obj), ed, ml),                \
                  GY_OK);                                                        \
                                                                                 \
        /* Wrong context => reject (both halves are context-bound). */           \
        ASSERT_EQ(gy_qspgs_pers_verify(suite, cpk, mpk,                          \
                                       GY_QSPGS_CTX_INVACCEPT, obj,              \
                                       sizeof(obj), ed, ml),                     \
                  GY_ERR_VERIFY);                                                \
        /* Tampered object => reject. */                                         \
        obj[0] ^= 0x01;                                                          \
        ASSERT_EQ(gy_qspgs_pers_verify(suite, cpk, mpk, GY_QSPGS_CTX_REGUSER,    \
                                       obj, sizeof(obj), ed, ml),                \
                  GY_ERR_VERIFY);                                                \
        obj[0] ^= 0x01;                                                          \
        /* Corrupt EITHER signature => reject (no single-scheme accept). */      \
        ed[0] ^= 0x01;                                                           \
        ASSERT_EQ(gy_qspgs_pers_verify(suite, cpk, mpk, GY_QSPGS_CTX_REGUSER,    \
                                       obj, sizeof(obj), ed, ml),                \
                  GY_ERR_VERIFY);                                                \
        ed[0] ^= 0x01;                                                           \
        ml[0] ^= 0x01;                                                           \
        ASSERT_EQ(gy_qspgs_pers_verify(suite, cpk, mpk, GY_QSPGS_CTX_REGUSER,    \
                                       obj, sizeof(obj), ed, ml),                \
                  GY_ERR_VERIFY);                                                \
        ml[0] ^= 0x01;                                                           \
                                                                                 \
        /* Unknown context purpose => argument error, not a signature. */        \
        ASSERT_EQ(gy_qspgs_pers_sign(suite, csk, msk, "qspgs-bogus", obj,        \
                                     sizeof(obj), ed, ml),                       \
                  GY_ERR_ARG);                                                   \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)

/*
 * Section 6.5 send / fetch token derivation: reproducible
 * from a fixed gk on both tiers, the two labels give distinct tokens, and the
 * derived fet is accepted by gy_qspgs_server_fetch_check (the server-side compare) -
 * proving the derivation and the server check agree on the bytes.
 */
TEST(token_derivation)
{
    static const uint8_t suites[] = {GY_SUITE_H25519_512, GY_SUITE_H448_1024};
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t fet1[GY_QSPGS_FET_BYTES], fet2[GY_QSPGS_FET_BYTES];
        uint8_t snd1[GY_QSPGS_SEND_BYTES], snd2[GY_QSPGS_SEND_BYTES];
        uint8_t presented[GY_QSPGS_FET_LEN];
        struct gy_qspgs_core core;

        memset(gk, 0x5c, sizeof(gk));

        /* Reproducible from a fixed gk. */
        ASSERT_EQ(gy_qspgs_derive_fet(suite, gk, fet1), GY_OK);
        ASSERT_EQ(gy_qspgs_derive_fet(suite, gk, fet2), GY_OK);
        ASSERT_MEMEQ(fet1, fet2, sizeof(fet1));
        ASSERT_EQ(gy_qspgs_derive_send(suite, gk, snd1), GY_OK);
        ASSERT_EQ(gy_qspgs_derive_send(suite, gk, snd2), GY_OK);
        ASSERT_MEMEQ(snd1, snd2, sizeof(snd1));

        /* Distinct labels give distinct tokens. */
        ASSERT_TRUE(memcmp(fet1, snd1, GY_QSPGS_FET_BYTES) != 0,
                    "fet and send must differ (label separation)");

        /* The derived fet is accepted by the server fetch check; a flipped byte
         * is rejected.  fet width == GY_QSPGS_FET_LEN (the wire field). */
        memset(&core, 0, sizeof(core));
        core.suite_id = suite;
        ASSERT_EQ(gy_qspgs_derive_fet(suite, gk, core.fet), GY_OK);
        ASSERT_EQ(gy_qspgs_derive_fet(suite, gk, presented), GY_OK);
        ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, presented), GY_OK);
        presented[0] ^= 0x01;
        ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, presented),
                  GY_ERR_VERIFY);

        /* NULL / classical-suite rejection on the derivations. */
        ASSERT_EQ(gy_qspgs_derive_fet(suite, NULL, fet1), GY_ERR_ARG);
        ASSERT_EQ(gy_qspgs_derive_send(GY_SUITE_C25519, gk, snd1), GY_ERR_ARG);

        gy_secure_zero(gk, sizeof(gk));
    }
}

TEST(reject_classical_and_null)
{
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    uint8_t ed[GY_QSPGS_PERS_ED_SIG_MAX], ml[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    uint8_t obj[16];
    memset(muk, 0, sizeof(muk));
    memset(obj, 0, sizeof(obj));

    /* Hybrid-only: classical suites have no QSPGS key hierarchy. */
    ASSERT_EQ(gy_qspgs_master_key_len(GY_SUITE_C25519), 0);
    ASSERT_EQ(gy_qspgs_master_key_len(GY_SUITE_C448), 0);
    ASSERT_EQ(gy_qspgs_derive_uk(GY_SUITE_C25519, muk, 1, uk), GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_pers_sign(GY_SUITE_C448, muk, muk, GY_QSPGS_CTX_REGUSER,
                                 obj, sizeof(obj), ed, ml),
              GY_ERR_ARG);

    /* NULL arguments. */
    ASSERT_EQ(gy_qspgs_derive_uk(GY_SUITE_H25519_512, NULL, 1, uk), GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_derive_rho(GY_SUITE_H25519_512, muk, NULL, 16, rho),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_base_keygen(GY_SUITE_H25519_512, NULL, uk), GY_ERR_ARG);
    /* rho rejects any UID that is not exactly GY_QSPGS_UID_LEN (SEC-v1.5.0
     * LOW-2): empty and over-long are both wrong-width. */
    ASSERT_EQ(gy_qspgs_derive_rho(GY_SUITE_H25519_512, muk, obj, 0, rho),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_derive_rho(GY_SUITE_H25519_512, muk, obj,
                                  GY_QSPGS_UID_MAX + 1, rho),
              GY_ERR_ARG);

    /* psdn_sk_clear is NULL-safe. */
    gy_qspgs_psdn_sk_clear(NULL);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(q44_derivations),
            GY_TEST(q44_base_independence),
            GY_TEST(q44_pseudonym_roundtrip),
            GY_TEST(q44_pers_dual),
            GY_TEST(q87_derivations),
            GY_TEST(q87_base_independence),
            GY_TEST(q87_pseudonym_roundtrip),
            GY_TEST(q87_pers_dual),
            GY_TEST(token_derivation),
            GY_TEST(reject_classical_and_null),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
