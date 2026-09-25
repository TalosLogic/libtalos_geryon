/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for blind issuance of ProfileKeyCredentials (GROUP_SPEC section 5.3),
 * both classical tiers.  End to end: commit -> request (pi_BR) ->
 * blind issue (pi_BI) -> receive -> the recovered credential (t,U,V) is a valid
 * ProfileKeyCredential, confirmed by presenting it through pi_P.  A forged
 * pi_BR, a wrong commitment, a forged pi_BI, and a tampered response are each
 * rejected.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_issue.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_pres.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

static const uint8_t UID[GY_GROUP_UID_BYTES] = {1, 2,  3,  4,  5,  6,  7,  8,
                                                9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

static void
fixed_scalars(uint8_t s[8][GY_GROUP_SCALAR_MAX], uint8_t base)
{
    size_t j, k;

    memset(s, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++)
        for (k = 0; k < 12; k++)
            s[j][k] = (uint8_t)(base + j * 13 + k + 1);
}

static void
derive_sp(const struct gy_group_tier *tier, struct gy_group_secret_params *sp)
{
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    size_t i;

    for (i = 0; i < tier->master_key_len; i++)
        gmk[i] = (uint8_t)(i + 1);
    ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, sp),
              GY_OK);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(blind_issue_flow)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_P;
        struct gy_group_server_public pp_srv;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp_pub;
        struct gy_group_pk_commitment cm;
        struct gy_group_pk_request req;
        struct gy_group_pk_blind_response resp;
        struct gy_group_mac_tag cred;
        struct gy_group_pk_presentation pres;
        uint8_t y[GY_GROUP_SCALAR_MAX];
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xc0);
        ASSERT_EQ(gy_group_server_keygen_scalars(
                      tier, &gens, GY_GROUP_ATTR_PROFILE, sc, &sk_P),
                  GY_OK);
        ASSERT_EQ(
            gy_group_server_public_from_secret(tier, &gens, &sk_P, &pp_srv),
            GY_OK);
        derive_sp(tier, &sp);
        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp_pub), GY_OK);

        /* Full blind-issuance flow. */
        ASSERT_EQ(gy_group_pk_commit(tier, &gens, UID, PK, &cm), GY_OK);
        ASSERT_EQ(gy_group_pk_request(tier, &gens, UID, PK, &req, y), GY_OK);
        ASSERT_EQ(
            gy_group_pk_blind_issue(tier, &gens, &sk_P, UID, &cm, &req, &resp),
            GY_OK);
        ASSERT_EQ(gy_group_pk_blind_receive(tier, &gens, &pp_srv, UID, &req, y,
                                            &resp, &cred),
                  GY_OK);

        /* The recovered credential is a valid ProfileKeyCredential: present it
         * through pi_P and verify. */
        ASSERT_EQ(gy_group_pk_present(tier, &gens, &sp, &pp_pub, &pp_srv, &cred,
                                      UID, PK, &pres),
                  GY_OK);
        ASSERT_EQ(
            gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &pres),
            GY_OK);

        /* Forged pi_BR rejected by the server. */
        {
            struct gy_group_pk_request bad = req;
            struct gy_group_pk_blind_response r2;
            bad.proof_r[0][0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_blind_issue(tier, &gens, &sk_P, UID, &cm,
                                              &bad, &r2),
                      GY_ERR_VERIFY);
        }

        /* Wrong commitment (different ProfileKey) rejected. */
        {
            struct gy_group_pk_commitment cm2;
            struct gy_group_pk_blind_response r2;
            uint8_t pk2[GY_GROUP_PROFILEKEY_BYTES];
            memcpy(pk2, PK, sizeof(pk2));
            pk2[0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_commit(tier, &gens, UID, pk2, &cm2), GY_OK);
            ASSERT_EQ(gy_group_pk_blind_issue(tier, &gens, &sk_P, UID, &cm2,
                                              &req, &r2),
                      GY_ERR_VERIFY);
        }

        /* Forged pi_BI rejected by the requester. */
        {
            struct gy_group_pk_blind_response bad = resp;
            struct gy_group_mac_tag c2;
            bad.proof_r[0][0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_blind_receive(tier, &gens, &pp_srv, UID, &req,
                                                y, &bad, &c2),
                      GY_ERR_VERIFY);
        }

        /* Tampered response ciphertext rejected. */
        {
            struct gy_group_pk_blind_response bad = resp;
            struct gy_group_mac_tag c2;
            bad.S2[0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_blind_receive(tier, &gens, &pp_srv, UID, &req,
                                                y, &bad, &c2),
                      GY_ERR_VERIFY);
        }

        gy_group_server_secret_clear(&sk_P);
        gy_group_secret_clear(&sp);
        gy_secure_zero(y, sizeof(y));
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(blind_issue_flow))
