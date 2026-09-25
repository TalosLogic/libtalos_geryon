/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS join keypair + hybrid KEM-DEM tests, both tiers.
 *
 * Covered per suite (GEN macro keeps the tiers in lockstep):
 *   - derive is deterministic: the same gk yields the identical (ipk, isk), so
 *     every member reconstructs the group-wide join key (section 2.2);
 *   - a distinct gk yields a distinct ipk (both halves);
 *   - seal-to-ipk then open-with-a-freshly-rederived-isk round-trips (the
 *     inviter and the approving member share only gk);
 *   - tampering any ciphertext region (ephemeral pk, ML-KEM ct, AEAD tag) is
 *     rejected with GY_ERR_VERIFY (no decapsulation oracle: implicit rejection
 *     folds into the tag check);
 *   - non-hybrid suites and NULL arguments are rejected.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "qspgs_join.h"
#include "qspgs_keys.h"
#include "suite.h"
#include "util.h"

#include "gy_test.h"

#define GEN(set, suite)                                                        \
    TEST(q##set##_join_derive_deterministic)                                   \
    {                                                                          \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                  \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        gy_qspgs_join_pk_t ipk1, ipk2;                                         \
        gy_qspgs_join_sk_t isk1, isk2;                                         \
        memset(gk, 0x5c, sizeof(gk));                                          \
                                                                               \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk1, &isk1), GY_OK);       \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk2, &isk2), GY_OK);       \
        ASSERT_EQ(ipk1.suite_id, suite);                                       \
        ASSERT_EQ(isk1.suite_id, suite);                                       \
        ASSERT_MEMEQ(ipk1.curve_pk, ipk2.curve_pk, d->curve_pk_len);           \
        ASSERT_MEMEQ(ipk1.mlkem_ek, ipk2.mlkem_ek, d->kem_pk_len);             \
        ASSERT_MEMEQ(isk1.curve_sk, isk2.curve_sk, d->curve_sk_len);           \
        ASSERT_MEMEQ(isk1.mlkem_dk, isk2.mlkem_dk, d->kem_sk_len);             \
                                                                               \
        /* A distinct gk => a distinct ipk (both halves move). */              \
        gk[0] ^= 0x01;                                                         \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk2, &isk2), GY_OK);       \
        ASSERT_TRUE(memcmp(ipk1.curve_pk, ipk2.curve_pk, d->curve_pk_len) !=   \
                        0,                                                     \
                    "curve ipk must vary with gk");                            \
        ASSERT_TRUE(memcmp(ipk1.mlkem_ek, ipk2.mlkem_ek, d->kem_pk_len) != 0,  \
                    "ML-KEM ipk must vary with gk");                           \
        gy_qspgs_join_sk_clear(&isk1);                                         \
        gy_qspgs_join_sk_clear(&isk2);                                         \
    }                                                                          \
                                                                               \
    TEST(q##set##_join_seal_roundtrip)                                         \
    {                                                                          \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        gy_qspgs_join_pk_t ipk;                                                \
        gy_qspgs_join_sk_t isk;                                                \
        const uint8_t pt[] = "invite: UID || uk || skpers-sig-blob";           \
        uint8_t ct[4096];                                                      \
        uint8_t out[256];                                                      \
        size_t ctlen = sizeof(ct), outlen = sizeof(out);                       \
        memset(gk, 0x3e, sizeof(gk));                                          \
                                                                               \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk, &isk), GY_OK);         \
        ASSERT_EQ(                                                             \
            gy_qspgs_join_seal(&ipk, pt, sizeof(pt) - 1, ct, ctlen, &ctlen),   \
            GY_OK);                                                            \
        ASSERT_EQ(ctlen, gy_qspgs_join_overhead(suite) + (sizeof(pt) - 1));    \
                                                                               \
        /* Approving member re-derives isk from the same gk and opens. */      \
        {                                                                      \
            gy_qspgs_join_sk_t isk_b;                                          \
            gy_qspgs_join_pk_t ipk_b;                                          \
            ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk_b, &isk_b), GY_OK); \
            ASSERT_EQ(gy_qspgs_join_open(&isk_b, ct, ctlen, out, sizeof(out),  \
                                         &outlen),                             \
                      GY_OK);                                                  \
            ASSERT_EQ(outlen, sizeof(pt) - 1);                                 \
            ASSERT_MEMEQ(out, pt, sizeof(pt) - 1);                             \
            gy_qspgs_join_sk_clear(&isk_b);                                    \
        }                                                                      \
                                                                               \
        /* Two fresh seals differ (fresh ephemerals => sender-unlinkable). */  \
        {                                                                      \
            uint8_t ct2[4096];                                                 \
            size_t ct2len = sizeof(ct2);                                       \
            ASSERT_EQ(gy_qspgs_join_seal(&ipk, pt, sizeof(pt) - 1, ct2,        \
                                         ct2len, &ct2len),                     \
                      GY_OK);                                                  \
            ASSERT_EQ(ct2len, ctlen);                                          \
            ASSERT_TRUE(memcmp(ct, ct2, ctlen) != 0,                           \
                        "fresh seals must differ");                            \
        }                                                                      \
        gy_qspgs_join_sk_clear(&isk);                                          \
    }                                                                          \
                                                                               \
    TEST(q##set##_join_tamper)                                                 \
    {                                                                          \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                  \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        gy_qspgs_join_pk_t ipk;                                                \
        gy_qspgs_join_sk_t isk;                                                \
        const uint8_t pt[] = "tamper target";                                  \
        uint8_t ct[4096];                                                      \
        uint8_t out[256];                                                      \
        size_t ctlen = sizeof(ct), outlen;                                     \
        size_t probes[3];                                                      \
        size_t i;                                                              \
        memset(gk, 0x71, sizeof(gk));                                          \
                                                                               \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk, &isk), GY_OK);         \
        ASSERT_EQ(                                                             \
            gy_qspgs_join_seal(&ipk, pt, sizeof(pt) - 1, ct, ctlen, &ctlen),   \
            GY_OK);                                                            \
                                                                               \
        /* One probe per region: ephemeral pk, ML-KEM ct, AEAD tag. */         \
        probes[0] = 0;                                                         \
        probes[1] = d->curve_pk_len;                                           \
        probes[2] = ctlen - 1;                                                 \
        for (i = 0; i < 3; i++) {                                              \
            outlen = sizeof(out);                                              \
            ct[probes[i]] ^= 0x01;                                             \
            ASSERT_EQ(gy_qspgs_join_open(&isk, ct, ctlen, out, sizeof(out),    \
                                         &outlen),                             \
                      GY_ERR_VERIFY);                                          \
            ct[probes[i]] ^= 0x01;                                             \
        }                                                                      \
        /* Undamaged ciphertext still opens. */                                \
        outlen = sizeof(out);                                                  \
        ASSERT_EQ(                                                             \
            gy_qspgs_join_open(&isk, ct, ctlen, out, sizeof(out), &outlen),    \
            GY_OK);                                                            \
        gy_qspgs_join_sk_clear(&isk);                                          \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)

TEST(reject_join_null_classical)
{
    uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
    gy_qspgs_join_pk_t ipk;
    gy_qspgs_join_sk_t isk;
    memset(gk, 0, sizeof(gk));

    /* Hybrid-only. */
    ASSERT_EQ(gy_qspgs_join_overhead(GY_SUITE_C25519), 0);
    ASSERT_EQ(gy_qspgs_join_derive(GY_SUITE_C448, gk, &ipk, &isk), GY_ERR_ARG);

    /* NULL arguments. */
    ASSERT_EQ(gy_qspgs_join_derive(GY_SUITE_H25519_512, NULL, &ipk, &isk),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_join_derive(GY_SUITE_H25519_512, gk, NULL, &isk),
              GY_ERR_ARG);

    /* clear is NULL-safe. */
    gy_qspgs_join_sk_clear(NULL);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(q44_join_derive_deterministic),
            GY_TEST(q44_join_seal_roundtrip),
            GY_TEST(q44_join_tamper),
            GY_TEST(q87_join_derive_deterministic),
            GY_TEST(q87_join_seal_roundtrip),
            GY_TEST(q87_join_tamper),
            GY_TEST(reject_join_null_classical),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
