/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for credential attribute assembly (GROUP_SPEC section 3.2/3.3): the
 * redemption-date scalar and auth M3 = G_m3^m3, and the
 * AuthCredential (M1, M2, M3) and ProfileKeyCredential (M1, M2, M3, M4)
 * attribute vectors, on both classical tiers.  Also checks that the assembled
 * vectors MAC and verify through the algebraic MAC.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* A fixed UID and ProfileKey. */
static const uint8_t UID[GY_GROUP_UID_BYTES] = {1, 2,  3,  4,  5,  6,  7,  8,
                                                9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

/* Eight fixed canonical scalars for a MAC key (mirrors test_group_mac). */
static void
fixed_scalars(uint8_t s[8][GY_GROUP_SCALAR_MAX], uint8_t base)
{
    size_t j, k;

    memset(s, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++)
        for (k = 0; k < 12; k++)
            s[j][k] = (uint8_t)(base + j * 13 + k + 1);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

/* Redemption scalar: day-aligned encodes little-endian; non-aligned rejected. */
TEST(redemption_scalar)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        uint64_t date = 20097u * GY_GROUP_DAY_SECS; /* some whole UTC day */
        uint8_t m3[GY_GROUP_SCALAR_MAX];
        size_t i;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_redemption_scalar(tier, date, m3), GY_OK);

        /* Low 8 bytes are the little-endian date; the rest are zero. */
        for (i = 0; i < 8; i++)
            ASSERT_EQ(m3[i], (uint8_t)(date >> (8 * i)));
        for (i = 8; i < tier->scalar_len; i++)
            ASSERT_EQ(m3[i], 0);

        /* Non-day-aligned rejected, never rounded. */
        ASSERT_EQ(gy_group_redemption_scalar(tier, date + 1, m3), GY_ERR_ARG);
        ASSERT_EQ(gy_group_redemption_scalar(tier, date + 86399, m3),
                  GY_ERR_ARG);
        /* Epoch (0) is day-aligned. */
        ASSERT_EQ(gy_group_redemption_scalar(tier, 0, m3), GY_OK);
        ASSERT_TRUE(gy_is_zero(m3, tier->scalar_len), "date 0 -> zero scalar");
    }
}

/* Auth M3 = G_m3^m3 recomputes independently, and rejects bad dates. */
TEST(auth_m3)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint64_t date = 20097u * GY_GROUP_DAY_SECS;
        uint8_t m3[GY_GROUP_SCALAR_MAX];
        uint8_t M3[GY_GROUP_POINT_MAX], chk[GY_GROUP_POINT_MAX];

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        ASSERT_EQ(gy_group_auth_m3(tier, &gens, date, M3), GY_OK);

        ASSERT_EQ(gy_group_redemption_scalar(tier, date, m3), GY_OK);
        ASSERT_EQ(tier->point_scalarmul(chk, m3, gens.g[GY_GEN_M3]), 0);
        ASSERT_TRUE(tier->point_eq(chk, M3) == 0, "M3 = G_m3^m3");

        ASSERT_EQ(gy_group_auth_m3(tier, &gens, date + 1, M3), GY_ERR_ARG);
    }
}

/* Auth attribute vector: distinct maps, and it MACs/verifies (n' = 3). */
TEST(attr_auth_vector)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret sk;
        struct gy_group_mac_tag tag;
        uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
        uint64_t date = 20097u * GY_GROUP_DAY_SECS;

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        ASSERT_EQ(gy_group_attr_auth(tier, &gens, UID, date, M), GY_OK);

        /* M1 (HashToG) and M2 (EncodeToG) are distinct and nonzero. */
        ASSERT_TRUE(!gy_is_zero(M[0], tier->point_len), "M1 nonzero");
        ASSERT_TRUE(!gy_is_zero(M[1], tier->point_len), "M2 nonzero");
        ASSERT_TRUE(tier->point_eq(M[0], M[1]) != 0, "M1 != M2");

        /* The vector MACs and verifies under an n' = 3 key. */
        fixed_scalars(sc, 0xa0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 3, sc, &sk),
                  GY_OK);
        ASSERT_EQ(gy_group_mac(tier, &sk,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 3,
                               &tag),
                  GY_OK);
        ASSERT_EQ(gy_group_verify(tier, &sk,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 3,
                                  &tag),
                  GY_OK);

        /* A different redemption date changes M3, so verification fails. */
        {
            uint8_t M2[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
            ASSERT_EQ(gy_group_attr_auth(tier, &gens, UID,
                                         date + GY_GROUP_DAY_SECS, M2),
                      GY_OK);
            ASSERT_EQ(gy_group_verify(tier, &sk,
                                      (const uint8_t(*)[GY_GROUP_POINT_MAX])M2,
                                      3, &tag),
                      GY_ERR_VERIFY);
        }

        /* Non-day-aligned date rejected at assembly. */
        ASSERT_EQ(gy_group_attr_auth(tier, &gens, UID, date + 1, M),
                  GY_ERR_ARG);

        gy_group_server_secret_clear(&sk);
    }
}

/* Profile attribute vector: four distinct maps, and it MACs/verifies (n' = 4). */
TEST(attr_profile_vector)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret sk;
        struct gy_group_mac_tag tag;
        uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];
        size_t i, j;

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        ASSERT_EQ(gy_group_attr_profile(tier, UID, PK, M), GY_OK);

        /* M1, M2 match the auth vector's UID maps (same UID). */
        {
            uint8_t A[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
            ASSERT_EQ(gy_group_attr_auth(tier, &gens, UID,
                                         20097u * GY_GROUP_DAY_SECS, A),
                      GY_OK);
            ASSERT_TRUE(tier->point_eq(M[0], A[0]) == 0, "M1 shared");
            ASSERT_TRUE(tier->point_eq(M[1], A[1]) == 0, "M2 shared");
        }

        /* All four attributes distinct and nonzero. */
        for (i = 0; i < GY_GROUP_ATTR_PROFILE; i++) {
            ASSERT_TRUE(!gy_is_zero(M[i], tier->point_len), "Mi nonzero");
            for (j = i + 1; j < GY_GROUP_ATTR_PROFILE; j++)
                ASSERT_TRUE(tier->point_eq(M[i], M[j]) != 0, "Mi distinct");
        }

        /* The vector MACs and verifies under an n' = 4 key. */
        fixed_scalars(sc, 0xb0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &sk),
                  GY_OK);
        ASSERT_EQ(gy_group_mac(tier, &sk,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4,
                               &tag),
                  GY_OK);
        ASSERT_EQ(gy_group_verify(tier, &sk,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4,
                                  &tag),
                  GY_OK);

        /* A different ProfileKey changes M3/M4, so verification fails. */
        {
            uint8_t pk2[GY_GROUP_PROFILEKEY_BYTES];
            uint8_t M2[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];
            memcpy(pk2, PK, sizeof(pk2));
            pk2[0] ^= 0x01;
            ASSERT_EQ(gy_group_attr_profile(tier, UID, pk2, M2), GY_OK);
            ASSERT_EQ(gy_group_verify(tier, &sk,
                                      (const uint8_t(*)[GY_GROUP_POINT_MAX])M2,
                                      4, &tag),
                      GY_ERR_VERIFY);
        }

        gy_group_server_secret_clear(&sk);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(redemption_scalar), GY_TEST(auth_m3),
             GY_TEST(attr_auth_vector), GY_TEST(attr_profile_vector))
