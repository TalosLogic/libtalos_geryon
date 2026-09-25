/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Standalone server-target test (GROUP_SPEC section 8.2 / 8.5): links
 * ONLY geryon_groups_server (plus the shared internal it pulls in), NOT the
 * client facade geryon_group.  It therefore proves two things at once:
 *   1. Link-time: no server-role function reaches into client-only code (if it
 *      did, this target would fail to link) - the structural complement to the
 *      nm_scope_server audit, which checks the client archive.
 *   2. Behaviour: the shipped server operations (KeyGen, iparams, the algebraic
 *      MAC round-trip, issuance, and the blind-issue reject path) run correctly
 *      as pure stateless functions, on both classical tiers.
 *
 * Client<->server round-trips (a client-built presentation verified by the
 * server, a client request blind-issued) are covered by test_group_ops, which
 * links both facades; here we deliberately use no client symbol.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_cred.h"
#include "group_issue.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_tier.h"
#include "util.h" /* gy_core_init, gy_secure_zero */

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

static const uint8_t SRV_UID[GY_GROUP_UID_BYTES] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00};

#define SRV_DATE 1704067200ull /* day-aligned */

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(server_standalone)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_A, sk_P;
        struct gy_group_server_public pp_A, pp_P;
        struct gy_group_mac_tag tag;
        struct gy_group_auth_response resp;
        struct gy_group_pk_commitment commit;
        struct gy_group_pk_request req;
        struct gy_group_pk_blind_response bresp;
        uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);

        /* KeyGen + iparams (section 8.1 op 1). */
        ASSERT_EQ(
            gy_group_server_keygen(tier, &gens, GY_GROUP_ATTR_AUTH, &sk_A),
            GY_OK);
        ASSERT_EQ(
            gy_group_server_keygen(tier, &gens, GY_GROUP_ATTR_PROFILE, &sk_P),
            GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_A),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_P, &pp_P),
                  GY_OK);

        /* Algebraic MAC round-trip (section 4): honest verify accepts, a
         * tampered tag is rejected - all server-side. */
        ASSERT_EQ(gy_group_attr_auth(tier, &gens, SRV_UID, SRV_DATE, M), GY_OK);
        ASSERT_EQ(gy_group_mac(tier, &sk_A,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                               GY_GROUP_ATTR_AUTH, &tag),
                  GY_OK);
        ASSERT_EQ(gy_group_verify(tier, &sk_A,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                                  GY_GROUP_ATTR_AUTH, &tag),
                  GY_OK);
        tag.V[0] ^= 0x01;
        ASSERT_EQ(gy_group_verify(tier, &sk_A,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                                  GY_GROUP_ATTR_AUTH, &tag),
                  GY_ERR_VERIFY);

        /* Issuance completes and is well-formed (section 8.1 op 2). */
        ASSERT_EQ(
            gy_group_auth_issue(tier, &gens, &sk_A, SRV_UID, SRV_DATE, &resp),
            GY_OK);

        /* Blind issuance rejects a garbage request (section 8.1 op 3, the pi_BR
         * verify path) - exercisable with no client-built request. */
        memset(&commit, 0, sizeof(commit));
        memset(&req, 0, sizeof(req));
        ASSERT_EQ(gy_group_pk_blind_issue(tier, &gens, &sk_P, SRV_UID, &commit,
                                          &req, &bresp),
                  GY_ERR_VERIFY);

        gy_group_server_secret_clear(&sk_A);
        gy_group_server_secret_clear(&sk_P);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(server_standalone))
