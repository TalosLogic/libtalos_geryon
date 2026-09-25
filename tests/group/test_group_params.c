/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the classical group system parameters (GROUP_SPEC section 2):
 * tier binding, the 20 NUMS generators, GroupMasterKey -> Derive ->
 * GroupSecretParams, and GroupPublicParams (A, B), on both classical tiers.
 *
 * There is no external oracle for these constructions (they are geryon's own
 * composition over libtalos_schnorr, D-GRP-9), so this suite validates the
 * spec-required PROPERTIES: determinism (reproducible from a fixed
 * GroupMasterKey), structural distinctness of the generator set, per-suite
 * separation, and input sensitivity. The byte-exact frozen vectors (section 2.2
 * "frozen at first published KATs") are pinned separately once the constructions
 * are blessed, exactly as libtalos_schnorr froze its encode vectors at
 * SCH-ENC-08.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_hash.h"
#include "group_params.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

/* The two classical suites under test. */
static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* A fixed GroupMasterKey for a tier: master_key_len bytes 0x01, 0x02, ... */
static void
fixed_gmk(const struct gy_group_tier *tier,
          uint8_t out[GY_GROUP_MASTER_KEY_MAX])
{
    size_t i;

    for (i = 0; i < tier->master_key_len; i++)
        out[i] = (uint8_t)(i + 1);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(tier_lookup)
{
    const struct gy_group_tier *t25 = gy_group_tier_for(GY_SUITE_C25519);
    const struct gy_group_tier *t448 = gy_group_tier_for(GY_SUITE_C448);

    ASSERT_TRUE(t25 != NULL, "c25519 tier present");
    ASSERT_TRUE(t448 != NULL, "c448 tier present");
    ASSERT_EQ(t25->point_len, 32);
    ASSERT_EQ(t25->scalar_len, 32);
    ASSERT_EQ(t25->master_key_len, 32);
    ASSERT_EQ(t25->pk_max_candidates, 64);
    ASSERT_EQ(t448->point_len, 56);
    ASSERT_EQ(t448->master_key_len, 56);
    ASSERT_EQ(t448->pk_max_candidates, 8);

    /* Hybrid suites and unknown bytes hold no objects of this system. */
    ASSERT_TRUE(gy_group_tier_for(GY_SUITE_H25519_512) == NULL, "hybrid 25519");
    ASSERT_TRUE(gy_group_tier_for(GY_SUITE_H448_1024) == NULL, "hybrid 448");
    ASSERT_TRUE(gy_group_tier_for(0x00) == NULL, "reserved 0x00");
    ASSERT_TRUE(gy_group_tier_for(0xff) == NULL, "unknown byte");
}

TEST(nums_deterministic_distinct)
{
    struct gy_group_generators a, b;
    size_t s, i, j;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        ASSERT_TRUE(tier != NULL, "tier");

        ASSERT_EQ(gy_group_generators_derive(tier, &a), GY_OK);
        ASSERT_EQ(gy_group_generators_derive(tier, &b), GY_OK);

        /* Deterministic: same suite -> identical generator set. */
        ASSERT_MEMEQ(&a, &b, sizeof(a));

        /* Distinct: no two generators collide, and none is all-zero. */
        for (i = 0; i < GY_GROUP_GEN_COUNT; i++) {
            ASSERT_TRUE(!gy_is_zero(a.g[i], tier->point_len), "gen nonzero");
            for (j = i + 1; j < GY_GROUP_GEN_COUNT; j++)
                ASSERT_TRUE(tier->point_eq(a.g[i], a.g[j]) != 0,
                            "generators distinct");
        }
    }

    /* Per-suite separation: c25519 and c448 have structurally distinct sets.
     * (Different point widths, so compare the shared leading 32 bytes of the
     * first generator only as a sanity signal.) */
    {
        struct gy_group_generators g25, g448;
        const struct gy_group_tier *t25 = gy_group_tier_for(GY_SUITE_C25519);
        const struct gy_group_tier *t448 = gy_group_tier_for(GY_SUITE_C448);
        ASSERT_EQ(gy_group_generators_derive(t25, &g25), GY_OK);
        ASSERT_EQ(gy_group_generators_derive(t448, &g448), GY_OK);
        ASSERT_TRUE(memcmp(g25.g[GY_GEN_W], g448.g[GY_GEN_W], 32) != 0,
                    "cross-suite generators differ");
    }
}

TEST(derive_deterministic)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_secret_params sp1, sp2, spx;
        uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];

        fixed_gmk(tier, gmk);

        ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, &sp1),
                  GY_OK);
        ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, &sp2),
                  GY_OK);
        /* Deterministic: fixed GroupMasterKey -> identical GroupSecretParams. */
        ASSERT_MEMEQ(&sp1, &sp2, sizeof(sp1));

        /* The four scalars are distinct (independent derivation slots). */
        ASSERT_TRUE(tier->scalar_eq(sp1.a1, sp1.a2) != 0, "a1 != a2");
        ASSERT_TRUE(tier->scalar_eq(sp1.b1, sp1.b2) != 0, "b1 != b2");
        ASSERT_TRUE(tier->scalar_eq(sp1.a1, sp1.b1) != 0, "a1 != b1");

        /* Input sensitivity: flip one GroupMasterKey byte -> different params. */
        gmk[0] ^= 0x01;
        ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, &spx),
                  GY_OK);
        ASSERT_TRUE(memcmp(&sp1, &spx, sizeof(sp1)) != 0,
                    "gmk change alters params");

        /* Wrong length is rejected. */
        ASSERT_EQ(
            gy_group_secret_derive(tier, gmk, tier->master_key_len - 1, &spx),
            GY_ERR_ARG);

        gy_group_secret_clear(&sp1);
        gy_group_secret_clear(&sp2);
        gy_group_secret_clear(&spx);
    }
}

TEST(public_params)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp1, pp2, ppx;
        uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];

        fixed_gmk(tier, gmk);
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, &sp),
                  GY_OK);

        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp1), GY_OK);
        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp2), GY_OK);
        /* Deterministic and non-degenerate. */
        ASSERT_MEMEQ(&pp1, &pp2, sizeof(pp1));
        ASSERT_TRUE(!gy_is_zero(pp1.A, tier->point_len), "A nonzero");
        ASSERT_TRUE(!gy_is_zero(pp1.B, tier->point_len), "B nonzero");
        ASSERT_TRUE(tier->point_eq(pp1.A, pp1.B) != 0, "A != B");

        /* Independent recomputation of A = G_a1^a1 * G_a2^a2. */
        {
            uint8_t t0[GY_GROUP_POINT_MAX], t1[GY_GROUP_POINT_MAX];
            uint8_t a[GY_GROUP_POINT_MAX];
            ASSERT_EQ(tier->point_scalarmul(t0, sp.a1, gens.g[GY_GEN_A1]), 0);
            ASSERT_EQ(tier->point_scalarmul(t1, sp.a2, gens.g[GY_GEN_A2]), 0);
            ASSERT_EQ(tier->point_add(a, t0, t1), 0);
            ASSERT_TRUE(tier->point_eq(a, pp1.A) == 0, "A recomputes");
        }

        /* Input sensitivity: a different GroupMasterKey -> different (A, B). */
        gmk[0] ^= 0x01;
        {
            struct gy_group_secret_params spx;
            ASSERT_EQ(
                gy_group_secret_derive(tier, gmk, tier->master_key_len, &spx),
                GY_OK);
            ASSERT_EQ(gy_group_public_derive(tier, &gens, &spx, &ppx), GY_OK);
            ASSERT_TRUE(memcmp(&pp1, &ppx, sizeof(pp1)) != 0,
                        "gmk change alters public params");
            gy_group_secret_clear(&spx);
        }

        gy_group_secret_clear(&sp);
    }
}

TEST(hash_conventions)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        const uint8_t in[16] = {0};
        uint8_t g_a[GY_GROUP_POINT_MAX], g_b[GY_GROUP_POINT_MAX];
        uint8_t g1_a[GY_GROUP_POINT_MAX], g1_b[GY_GROUP_POINT_MAX];
        uint8_t zq_a[GY_GROUP_SCALAR_MAX], zq_b[GY_GROUP_SCALAR_MAX];

        /* HashToG (M1 two-map) deterministic. */
        ASSERT_EQ(gy_group_hash_to_g(tier, "grp-m1", in, sizeof(in), g_a),
                  GY_OK);
        ASSERT_EQ(gy_group_hash_to_g(tier, "grp-m1", in, sizeof(in), g_b),
                  GY_OK);
        ASSERT_MEMEQ(g_a, g_b, tier->point_len);

        /* HashToG1 (M3 single-map) deterministic and distinct from HashToG. */
        ASSERT_EQ(gy_group_hash_to_g1(tier, "grp-m3", in, sizeof(in), g1_a),
                  GY_OK);
        ASSERT_EQ(gy_group_hash_to_g1(tier, "grp-m3", in, sizeof(in), g1_b),
                  GY_OK);
        ASSERT_MEMEQ(g1_a, g1_b, tier->point_len);
        ASSERT_TRUE(memcmp(g_a, g1_a, tier->point_len) != 0,
                    "two-map and single-map differ");

        /* HashToZq (j3) deterministic. */
        ASSERT_EQ(gy_group_hash_to_zq(tier, "grp-j3", in, sizeof(in), zq_a),
                  GY_OK);
        ASSERT_EQ(gy_group_hash_to_zq(tier, "grp-j3", in, sizeof(in), zq_b),
                  GY_OK);
        ASSERT_MEMEQ(zq_a, zq_b, tier->scalar_len);
    }
}

TEST(domain_string)
{
    uint8_t out[GY_GROUP_DOMAIN_MAX];
    size_t n;
    const char *expect = "geryon.1.c25519.sysparams.w";

    ASSERT_EQ(
        gy_group_domain(GY_SUITE_C25519, "sysparams.w", out, sizeof(out), &n),
        GY_OK);
    ASSERT_EQ(n, strlen(expect));
    ASSERT_TRUE(memcmp(out, expect, n) == 0, "domain string matches D-GEN-3");
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(tier_lookup),
             GY_TEST(nums_deterministic_distinct),
             GY_TEST(derive_deterministic), GY_TEST(public_params),
             GY_TEST(hash_conventions), GY_TEST(domain_string))
