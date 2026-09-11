/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the AuthCredentialPresentation pi_A (GROUP_SPEC section 5.2.1,
 * GER-M8-04), both classical tiers: an honest presentation of a valid
 * credential verifies; a tampered proof/commitment, a lied-about redemption
 * date, and a wrong UID are rejected; the attached UidCiphertext decrypts to the
 * presenter's UID; and the presentation encoding round-trips.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_cred.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_pres.h"
#include "group_tier.h"
#include "group_venc.h"
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

TEST(auth_present_verify)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_A;
        struct gy_group_server_public pp_srv;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp_pub;
        struct gy_group_auth_response resp;
        struct gy_group_auth_presentation pres;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        uint64_t date = 20097u * GY_GROUP_DAY_SECS;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xa0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens,
                                                 GY_GROUP_ATTR_AUTH, sc, &sk_A),
                  GY_OK);
        ASSERT_EQ(
            gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_srv),
            GY_OK);
        derive_sp(tier, &sp);
        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp_pub), GY_OK);

        /* Issue a credential, then present it. */
        ASSERT_EQ(gy_group_auth_issue(tier, &gens, &sk_A, UID, date, &resp),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_present(tier, &gens, &sp, &pp_pub, &pp_srv,
                                        &resp.mac, UID, date, &pres),
                  GY_OK);
        ASSERT_EQ(
            gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &pres),
            GY_OK);

        /* The attached UidCiphertext decrypts to the presenter's UID. */
        {
            struct gy_group_uid_ct ct;
            uint8_t uid_out[GY_GROUP_UID_BYTES];
            memcpy(ct.E_A1, pres.E_A1, sizeof(ct.E_A1));
            memcpy(ct.E_A2, pres.E_A2, sizeof(ct.E_A2));
            ASSERT_EQ(gy_group_uid_decrypt(tier, &sp, &ct, uid_out), GY_OK);
            ASSERT_MEMEQ(uid_out, UID, GY_GROUP_UID_BYTES);
        }

        /* Tampered proof rejected. */
        {
            struct gy_group_auth_presentation bad = pres;
            bad.proof_r[0][0] ^= 0x01;
            ASSERT_EQ(
                gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &bad),
                GY_ERR_VERIFY);
        }

        /* Tampered commitment rejected. */
        {
            struct gy_group_auth_presentation bad = pres;
            bad.C_V[0] ^= 0x01;
            ASSERT_EQ(
                gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &bad),
                GY_ERR_VERIFY);
        }

        /* Lied-about redemption date rejected (credential valid for one day). */
        {
            struct gy_group_auth_presentation bad = pres;
            bad.date = date + GY_GROUP_DAY_SECS;
            ASSERT_EQ(
                gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &bad),
                GY_ERR_VERIFY);
        }

        /* A presentation of the credential under a different UID fails. */
        {
            uint8_t uid2[GY_GROUP_UID_BYTES];
            struct gy_group_auth_presentation p2;
            memcpy(uid2, UID, sizeof(uid2));
            uid2[0] ^= 0x01;
            ASSERT_EQ(gy_group_auth_present(tier, &gens, &sp, &pp_pub, &pp_srv,
                                            &resp.mac, uid2, date, &p2),
                      GY_OK);
            ASSERT_EQ(
                gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &p2),
                GY_ERR_VERIFY);
        }

        /* Encoding round-trips and the decoded presentation verifies. */
        {
            uint8_t buf[GY_GROUP_AUTH_PRES_ENC_MAX];
            struct gy_group_auth_presentation dec;
            size_t n, plen = tier->point_len, slen = tier->scalar_len, expect;
            expect = GY_GROUP_OBJ_HDR_LEN + 8 * plen + 8 +
                     GY_GROUP_PI_A_M * plen + GY_GROUP_PI_A_K * slen;
            ASSERT_EQ(
                gy_group_auth_pres_encode(tier, &pres, buf, sizeof(buf), &n),
                GY_OK);
            ASSERT_EQ(n, expect);
            ASSERT_EQ(buf[0], GY_GOBJ_AUTH_PRESENTATION);
            ASSERT_EQ(gy_group_auth_pres_decode(tier, &dec, buf, n), GY_OK);
            ASSERT_EQ(dec.date, date);
            ASSERT_EQ(
                gy_group_auth_present_verify(tier, &gens, &sk_A, &pp_pub, &dec),
                GY_OK);
            ASSERT_EQ(gy_group_auth_pres_decode(tier, &dec, buf, n - 1),
                      GY_ERR_VERIFY);
        }

        gy_group_server_secret_clear(&sk_A);
        gy_group_secret_clear(&sp);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(auth_present_verify))
