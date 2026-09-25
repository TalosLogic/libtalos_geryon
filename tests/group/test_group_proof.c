/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the conjunction-proof wiring (GROUP_SPEC section 5): the
 * gy_group_tier gen_prove_conj / gen_verify_conj adapters over libtalos_schnorr's
 * sound conjunction primitive, on both classical tiers.  Exercises the width
 * normalization (the 255 adapter repacks 56 -> 32, the 448 adapter casts
 * through) with a pi_I-shaped statement (k = 5 witnesses, m = 3 equations, the
 * shared witness w in equations 0 and 2).  Soundness of the underlying primitive
 * is proven in the schnorr suite; here we confirm honest proofs verify and a
 * tampered target is rejected through geryon's normalized API.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* acc = acc + gen^scalar (or acc = gen^scalar when first). */
static void
mul_add(const struct gy_group_tier *tier, uint8_t *acc, const uint8_t *gen,
        const uint8_t *scalar, int first)
{
    uint8_t term[GY_GROUP_POINT_MAX];
    uint8_t sum[GY_GROUP_POINT_MAX];

    (void)tier->point_scalarmul(term, scalar, gen);
    if (first) {
        memcpy(acc, term, GY_GROUP_POINT_MAX);
        return;
    }
    (void)tier->point_add(sum, acc, term);
    memcpy(acc, sum, GY_GROUP_POINT_MAX);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(conj_roundtrip_and_reject)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        uint8_t gens[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
        uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
        uint8_t w[GY_GROUP_MAX_K][GY_GROUP_SCALAR_MAX];
        uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
        uint8_t V[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
        uint8_t r[GY_GROUP_MAX_K][GY_GROUP_SCALAR_MAX];
        static const uint8_t seed[8] = {'c', 'o', 'n', 'j', 'w', 'i', 'r', 'e'};
        static const uint8_t uid[] = "geryon-group-server";
        static const uint8_t oi[] = "pi_I";
        const size_t k = 5, m = 3;

        ASSERT_TRUE(tier != NULL, "tier");

        memset(gens, 0, sizeof(gens));
        memset(mask, 0, sizeof(mask));
        memset(w, 0, sizeof(w));

        /* Five base generators G_w, G_wp, G_x0, G_x1, G_y1 (index-separated),
         * placed per the pi_I mask: eq0 {w,wp}, eq1 {x0,x1,y1},
         * eq2 {w,x0,x1,y1} - w shared between eq0 and eq2. */
        {
            uint8_t G[5][GY_GROUP_POINT_MAX];
            size_t i;
            for (i = 0; i < 5; i++)
                ASSERT_EQ(
                    tier->hash_to_group(G[i], seed, sizeof(seed), (uint32_t)i),
                    0);
            memcpy(gens[0][0], G[0], GY_GROUP_POINT_MAX); /* G_w */
            memcpy(gens[0][1], G[1], GY_GROUP_POINT_MAX); /* G_wp */
            memcpy(gens[1][2], G[2], GY_GROUP_POINT_MAX); /* G_x0 */
            memcpy(gens[1][3], G[3], GY_GROUP_POINT_MAX); /* G_x1 */
            memcpy(gens[1][4], G[4], GY_GROUP_POINT_MAX); /* G_y1 */
            memcpy(gens[2][0], G[0], GY_GROUP_POINT_MAX); /* G_w (shared) */
            memcpy(gens[2][2], G[2], GY_GROUP_POINT_MAX);
            memcpy(gens[2][3], G[3], GY_GROUP_POINT_MAX);
            memcpy(gens[2][4], G[4], GY_GROUP_POINT_MAX);
        }
        mask[0][0] = mask[0][1] = 1;
        mask[1][2] = mask[1][3] = mask[1][4] = 1;
        mask[2][0] = mask[2][2] = mask[2][3] = mask[2][4] = 1;

        {
            size_t i;
            for (i = 0; i < k; i++)
                tier->scalar_random(w[i]);
        }

        /* Honest, consistent targets. */
        mul_add(tier, P[0], gens[0][0], w[0], 1);
        mul_add(tier, P[0], gens[0][1], w[1], 0);
        mul_add(tier, P[1], gens[1][2], w[2], 1);
        mul_add(tier, P[1], gens[1][3], w[3], 0);
        mul_add(tier, P[1], gens[1][4], w[4], 0);
        mul_add(tier, P[2], gens[2][0], w[0], 1);
        mul_add(tier, P[2], gens[2][2], w[2], 0);
        mul_add(tier, P[2], gens[2][3], w[3], 0);
        mul_add(tier, P[2], gens[2][4], w[4], 0);

        /* Prove and verify through the tier adapters. */
        ASSERT_EQ(
            tier->gen_prove_conj(
                V, r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
                (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gens,
                (const uint8_t(*)[GY_GROUP_POINT_MAX])P,
                (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, k, m, uid,
                sizeof(uid) - 1, oi, sizeof(oi) - 1),
            0);
        ASSERT_EQ(
            tier->gen_verify_conj(
                (const uint8_t(*)[GY_GROUP_POINT_MAX])V,
                (const uint8_t(*)[GY_GROUP_SCALAR_MAX])r,
                (const uint8_t(*)[GY_GROUP_MAX_K])mask,
                (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gens,
                (const uint8_t(*)[GY_GROUP_POINT_MAX])P, k, m, uid,
                sizeof(uid) - 1, oi, sizeof(oi) - 1),
            0);

        /* Transcript binding / malleability (GROUP_SPEC section 12): the same
         * statement and proof under a DIFFERENT Fiat-Shamir label verifies
         * false - relabeling (a transcript change) alters the challenge.  This
         * exercises the OtherInfo and UserID binding directly, not just via the
         * oracle's independent challenge recompute. */
        {
            static const uint8_t oi2[] = "pi_A"; /* wrong proof-type label */
            static const uint8_t uid2[] =
                "geryon-group-member"; /* wrong role */
            ASSERT_TRUE(
                tier->gen_verify_conj(
                    (const uint8_t(*)[GY_GROUP_POINT_MAX])V,
                    (const uint8_t(*)[GY_GROUP_SCALAR_MAX])r,
                    (const uint8_t(*)[GY_GROUP_MAX_K])mask,
                    (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gens,
                    (const uint8_t(*)[GY_GROUP_POINT_MAX])P, k, m, uid,
                    sizeof(uid) - 1, oi2, sizeof(oi2) - 1) != 0,
                "different OtherInfo rejected");
            ASSERT_TRUE(
                tier->gen_verify_conj(
                    (const uint8_t(*)[GY_GROUP_POINT_MAX])V,
                    (const uint8_t(*)[GY_GROUP_SCALAR_MAX])r,
                    (const uint8_t(*)[GY_GROUP_MAX_K])mask,
                    (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gens,
                    (const uint8_t(*)[GY_GROUP_POINT_MAX])P, k, m, uid2,
                    sizeof(uid2) - 1, oi, sizeof(oi) - 1) != 0,
                "different UserID rejected");
        }

        /* Tampered target rejected. */
        mul_add(tier, P[2], gens[2][0], w[1], 0); /* add G_w^w1: wrong */
        ASSERT_TRUE(
            tier->gen_verify_conj(
                (const uint8_t(*)[GY_GROUP_POINT_MAX])V,
                (const uint8_t(*)[GY_GROUP_SCALAR_MAX])r,
                (const uint8_t(*)[GY_GROUP_MAX_K])mask,
                (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gens,
                (const uint8_t(*)[GY_GROUP_POINT_MAX])P, k, m, uid,
                sizeof(uid) - 1, oi, sizeof(oi) - 1) != 0,
            "tampered target rejected");

        {
            size_t i;
            for (i = 0; i < k; i++)
                gy_secure_zero(w[i], sizeof(w[i]));
        }
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(conj_roundtrip_and_reject))
