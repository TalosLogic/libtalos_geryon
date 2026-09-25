/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the ProfileKeyCredentialPresentation pi_P (GROUP_SPEC section
 * 5.2.2), both classical tiers.  The ProfileKeyCredential MAC is produced
 * directly here (blind issuance, section 5.3, is a separate ticket); pi_P then
 * presents it with all four attributes hidden and both encryption predicates.
 * Honest presentations verify; a tampered proof/commitment and a wrong
 * ProfileKey are rejected; the attached ciphertexts decrypt to the presenter's
 * UID and ProfileKey; and the encoding round-trips.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
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

/* Produce a valid ProfileKeyCredential MAC over (M1..M4) under sk_P. */
static void
make_credential(const struct gy_group_tier *tier,
                const struct gy_group_server_secret *sk_P, const uint8_t *uid,
                const uint8_t *pk, struct gy_group_mac_tag *cred)
{
    uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];

    ASSERT_EQ(gy_group_attr_profile(tier, uid, pk, M), GY_OK);
    ASSERT_EQ(gy_group_mac(tier, sk_P, (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                           GY_GROUP_ATTR_PROFILE, cred),
              GY_OK);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(pk_present_verify)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_P;
        struct gy_group_server_public pp_srv;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp_pub;
        struct gy_group_mac_tag cred;
        struct gy_group_pk_presentation pres;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xb0);
        ASSERT_EQ(gy_group_server_keygen_scalars(
                      tier, &gens, GY_GROUP_ATTR_PROFILE, sc, &sk_P),
                  GY_OK);
        ASSERT_EQ(
            gy_group_server_public_from_secret(tier, &gens, &sk_P, &pp_srv),
            GY_OK);
        derive_sp(tier, &sp);
        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp_pub), GY_OK);

        make_credential(tier, &sk_P, UID, PK, &cred);

        ASSERT_EQ(gy_group_pk_present(tier, &gens, &sp, &pp_pub, &pp_srv, &cred,
                                      UID, PK, &pres),
                  GY_OK);
        ASSERT_EQ(
            gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &pres),
            GY_OK);

        /* Both ciphertexts decrypt to the presenter's UID and ProfileKey. */
        {
            struct gy_group_uid_ct uct;
            struct gy_group_pk_ct pct;
            uint8_t uid_out[GY_GROUP_UID_BYTES];
            uint8_t pk_out[GY_GROUP_PROFILEKEY_BYTES];
            memcpy(uct.E_A1, pres.E_A1, GY_GROUP_POINT_MAX);
            memcpy(uct.E_A2, pres.E_A2, GY_GROUP_POINT_MAX);
            memcpy(pct.E_B1, pres.E_B1, GY_GROUP_POINT_MAX);
            memcpy(pct.E_B2, pres.E_B2, GY_GROUP_POINT_MAX);
            ASSERT_EQ(gy_group_uid_decrypt(tier, &sp, &uct, uid_out), GY_OK);
            ASSERT_MEMEQ(uid_out, UID, GY_GROUP_UID_BYTES);
            ASSERT_EQ(gy_group_pk_decrypt(tier, &sp, &pct, uid_out, pk_out),
                      GY_OK);
            ASSERT_MEMEQ(pk_out, PK, GY_GROUP_PROFILEKEY_BYTES);
        }

        /* Tampered proof rejected. */
        {
            struct gy_group_pk_presentation bad = pres;
            bad.proof_r[0][0] ^= 0x01;
            ASSERT_EQ(
                gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &bad),
                GY_ERR_VERIFY);
        }

        /* Tampered commitment rejected. */
        {
            struct gy_group_pk_presentation bad = pres;
            bad.C_V[0] ^= 0x01;
            ASSERT_EQ(
                gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &bad),
                GY_ERR_VERIFY);
        }

        /* A presentation of the credential under a different ProfileKey fails
         * (M3/M4 differ from what the credential MAC'd). */
        {
            uint8_t pk2[GY_GROUP_PROFILEKEY_BYTES];
            struct gy_group_pk_presentation p2;
            memcpy(pk2, PK, sizeof(pk2));
            pk2[0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_present(tier, &gens, &sp, &pp_pub, &pp_srv,
                                          &cred, UID, pk2, &p2),
                      GY_OK);
            ASSERT_EQ(
                gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &p2),
                GY_ERR_VERIFY);
        }

        /* Encoding round-trips and the decoded presentation verifies. */
        {
            uint8_t buf[GY_GROUP_PK_PRES_ENC_MAX];
            struct gy_group_pk_presentation dec;
            size_t n, plen = tier->point_len, slen = tier->scalar_len, expect;
            expect = GY_GROUP_OBJ_HDR_LEN + 11 * plen + GY_GROUP_PI_P_M * plen +
                     GY_GROUP_PI_P_K * slen;
            ASSERT_EQ(
                gy_group_pk_pres_encode(tier, &pres, buf, sizeof(buf), &n),
                GY_OK);
            ASSERT_EQ(n, expect);
            ASSERT_EQ(buf[0], GY_GOBJ_PK_PRESENTATION);
            ASSERT_EQ(gy_group_pk_pres_decode(tier, &dec, buf, n), GY_OK);
            ASSERT_EQ(
                gy_group_pk_present_verify(tier, &gens, &sk_P, &pp_pub, &dec),
                GY_OK);
            ASSERT_EQ(gy_group_pk_pres_decode(tier, &dec, buf, n - 1),
                      GY_ERR_VERIFY);
        }

        gy_group_server_secret_clear(&sk_P);
        gy_group_secret_clear(&sp);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(pk_present_verify))
