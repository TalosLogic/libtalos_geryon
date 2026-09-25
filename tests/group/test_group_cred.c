/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for AuthCredential issuance and the pi_I proof (GROUP_SPEC section
 * 5.1), both classical tiers: an honest issuance verifies; a wrong UID,
 * wrong redemption date, tampered proof, or tampered MAC is rejected; and the
 * AuthCredentialResponse encoding round-trips at the expected size.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_cred.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_tier.h"
#include "group_wire.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

static const uint8_t UID[GY_GROUP_UID_BYTES] = {1, 2,  3,  4,  5,  6,  7,  8,
                                                9, 10, 11, 12, 13, 14, 15, 16};

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

TEST(auth_issue_verify)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_A;
        struct gy_group_server_public pp_A;
        struct gy_group_auth_response resp;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        uint64_t date = 20097u * GY_GROUP_DAY_SECS;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xa0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens,
                                                 GY_GROUP_ATTR_AUTH, sc, &sk_A),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_A),
                  GY_OK);

        /* Honest issuance verifies. */
        ASSERT_EQ(gy_group_auth_issue(tier, &gens, &sk_A, UID, date, &resp),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_verify(tier, &gens, &pp_A, UID, date, &resp),
                  GY_OK);

        /* Wrong UID rejected (M1/M2 differ). */
        {
            uint8_t uid2[GY_GROUP_UID_BYTES];
            memcpy(uid2, UID, sizeof(uid2));
            uid2[0] ^= 0x01;
            ASSERT_EQ(
                gy_group_auth_verify(tier, &gens, &pp_A, uid2, date, &resp),
                GY_ERR_VERIFY);
        }

        /* Wrong redemption date rejected (M3 differs). */
        ASSERT_EQ(gy_group_auth_verify(tier, &gens, &pp_A, UID,
                                       date + GY_GROUP_DAY_SECS, &resp),
                  GY_ERR_VERIFY);

        /* Non-day-aligned date rejected at attribute assembly. */
        ASSERT_EQ(
            gy_group_auth_verify(tier, &gens, &pp_A, UID, date + 1, &resp),
            GY_ERR_ARG);

        /* Tampered proof response rejected. */
        {
            struct gy_group_auth_response bad = resp;
            bad.proof_r[0][0] ^= 0x01;
            ASSERT_EQ(gy_group_auth_verify(tier, &gens, &pp_A, UID, date, &bad),
                      GY_ERR_VERIFY);
        }

        /* Tampered MAC rejected (changes eq2 target V). */
        {
            struct gy_group_auth_response bad = resp;
            bad.mac.V[0] ^= 0x01;
            ASSERT_EQ(gy_group_auth_verify(tier, &gens, &pp_A, UID, date, &bad),
                      GY_ERR_VERIFY);
        }

        /* Non-day-aligned date rejected at issuance. */
        {
            struct gy_group_auth_response r2;
            ASSERT_EQ(
                gy_group_auth_issue(tier, &gens, &sk_A, UID, date + 1, &r2),
                GY_ERR_ARG);
        }

        gy_group_server_secret_clear(&sk_A);
    }
}

TEST(auth_response_encoding)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_A;
        struct gy_group_server_public pp_A;
        struct gy_group_auth_response resp, resp2;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        uint8_t buf[GY_GROUP_AUTH_RESPONSE_ENC_MAX];
        uint64_t date = 20097u * GY_GROUP_DAY_SECS;
        size_t n, plen, slen, expect;

        plen = tier->point_len;
        slen = tier->scalar_len;

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xb0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens,
                                                 GY_GROUP_ATTR_AUTH, sc, &sk_A),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_A),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_issue(tier, &gens, &sk_A, UID, date, &resp),
                  GY_OK);

        /* header + t + U + V + 3 proof points + 7 proof scalars. */
        expect = GY_GROUP_OBJ_HDR_LEN + slen + 2 * plen +
                 GY_GROUP_PI_I_M * plen + GY_GROUP_PI_I_K * slen;
        ASSERT_EQ(
            gy_group_auth_response_encode(tier, &resp, buf, sizeof(buf), &n),
            GY_OK);
        ASSERT_EQ(n, expect);
        ASSERT_EQ(buf[0], GY_GOBJ_AUTH_RESPONSE);

        ASSERT_EQ(gy_group_auth_response_decode(tier, &resp2, buf, n), GY_OK);
        /* The decoded response verifies and matches the mac/proof bytes. */
        ASSERT_EQ(gy_group_auth_verify(tier, &gens, &pp_A, UID, date, &resp2),
                  GY_OK);
        ASSERT_MEMEQ(&resp.mac, &resp2.mac, sizeof(resp.mac));
        ASSERT_MEMEQ(resp.proof_V, resp2.proof_V, sizeof(resp.proof_V));
        ASSERT_MEMEQ(resp.proof_r, resp2.proof_r, sizeof(resp.proof_r));

        /* Strict parse: trailing byte rejected. */
        ASSERT_EQ(gy_group_auth_response_decode(tier, &resp2, buf, n + 1),
                  GY_ERR_VERIFY);

        gy_group_server_secret_clear(&sk_A);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(auth_issue_verify),
             GY_TEST(auth_response_encoding))
