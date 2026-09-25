/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Object-size cross-check (GROUP_SPEC section 9, credential-layer acceptance:
 * "sizes match Table 1"), both classical tiers.  Every encodable credential-layer
 * object is produced, encoded, and its byte length asserted against the exact
 * element-count formula
 *
 *     bytes = header + pts*point_len + scalars*scalar_len + dates*8
 *
 * (header = GY_GROUP_OBJ_HDR_LEN for a top-level tagged object, 0 for a nested
 * one), which pins the wire footprint deterministically.
 *
 * External cross-check vs the [CPZ] paper Table 1 (2019/1416, ristretto255,
 * 32-byte elements):
 *
 *     Object                            paper   geryon(255)   delta
 *     UidCiphertext                       64        64          0    (exact)
 *     ProfileKeyCiphertext                64        64          0    (exact)
 *     AuthCredentialResponse             361       419        +58
 *     AuthCredentialPresentation         493       651       +158
 *     ProfileKeyCredentialPresentation   713       899       +186
 *
 * The CIPHERTEXTS match the paper exactly (2 group elements = 64 bytes): these
 * are the structurally identical KVAC primitive, so the 255-tier assert below
 * cites the paper's 64.  The credential/presentation objects are LARGER by
 * design and are NOT expected to match the paper: geryon's clean-room
 * gen_*_conj serializes the UNCOMPRESSED proof (the commitments V_j AND the
 * responses r_i), whereas zkgroup/poksho stores the Fiat-Shamir-compressed form
 * (challenge + responses); geryon also prepends a 3-byte object header
 * (D-GRP-4/D-GRP-6).  Different serialization of the same construction, not a
 * size regression - so those objects are pinned to geryon's own formula.  The
 * paper is ristretto255-only, so the 448 tier has no external figure and is
 * pinned by the formula alone.
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
#include "group_venc.h"
#include "group_wire.h" /* GY_GROUP_OBJ_HDR_LEN */
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

#define SIZE_DATE 1704067200ull /* day-aligned */

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

/* Expected encoded byte length from element counts and the tier widths. */
static size_t
sz(const struct gy_group_tier *tier, size_t hdr, size_t pts, size_t scalars,
   size_t dates)
{
    return hdr + pts * tier->point_len + scalars * tier->scalar_len + dates * 8;
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(object_sizes)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        struct gy_group_server_secret sk_A, sk_P;
        struct gy_group_server_public pp_A, pp_P;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp_pub;
        struct gy_group_mac_tag cred_a, cred_p;
        struct gy_group_auth_response resp;
        struct gy_group_auth_presentation apres;
        struct gy_group_pk_presentation ppres;
        struct gy_group_uid_ct uct;
        struct gy_group_pk_ct pct;
        uint8_t Ma[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
        uint8_t Mp[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        uint8_t buf[2048];
        size_t n;
        int is255 = (suites[s] == GY_SUITE_C25519);

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(sc, 0xa0);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens,
                                                 GY_GROUP_ATTR_AUTH, sc, &sk_A),
                  GY_OK);
        fixed_scalars(sc, 0xb0);
        ASSERT_EQ(gy_group_server_keygen_scalars(
                      tier, &gens, GY_GROUP_ATTR_PROFILE, sc, &sk_P),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_A),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk_P, &pp_P),
                  GY_OK);
        derive_sp(tier, &sp);
        ASSERT_EQ(gy_group_public_derive(tier, &gens, &sp, &pp_pub), GY_OK);

        /* ---- UidCiphertext / ProfileKeyCiphertext: 2 elements, untagged. ---- */
        ASSERT_EQ(gy_group_uid_encrypt(tier, &sp, UID, &uct), GY_OK);
        ASSERT_EQ(gy_group_uid_ct_encode(tier, &uct, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, sz(tier, 0, 2, 0, 0));
        if (is255)
            ASSERT_EQ(n, 64); /* [CPZ] Table 1: UidCiphertext = 64 bytes. */

        ASSERT_EQ(gy_group_pk_encrypt(tier, &sp, PK, UID, &pct), GY_OK);
        ASSERT_EQ(gy_group_pk_ct_encode(tier, &pct, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, sz(tier, 0, 2, 0, 0));
        if (is255)
            ASSERT_EQ(n, 64); /* [CPZ] Table 1: ProfileKeyCiphertext = 64. */

        /* ---- AuthCredentialResponse (pi_I): tagged; 5 pts, 8 scalars. ---- */
        ASSERT_EQ(
            gy_group_auth_issue(tier, &gens, &sk_A, UID, SIZE_DATE, &resp),
            GY_OK);
        ASSERT_EQ(
            gy_group_auth_response_encode(tier, &resp, buf, sizeof(buf), &n),
            GY_OK);
        ASSERT_EQ(n, sz(tier, GY_GROUP_OBJ_HDR_LEN, 2 + GY_GROUP_PI_I_M,
                        1 + GY_GROUP_PI_I_K, 0));

        /* ---- AuthCredentialPresentation (pi_A): tagged; 14 pts, 6 sc, 1 date. */
        ASSERT_EQ(gy_group_attr_auth(tier, &gens, UID, SIZE_DATE, Ma), GY_OK);
        ASSERT_EQ(gy_group_mac(tier, &sk_A,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])Ma,
                               GY_GROUP_ATTR_AUTH, &cred_a),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_present(tier, &gens, &sp, &pp_pub, &pp_A,
                                        &cred_a, UID, SIZE_DATE, &apres),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_pres_encode(tier, &apres, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, sz(tier, GY_GROUP_OBJ_HDR_LEN, 8 + GY_GROUP_PI_A_M,
                        GY_GROUP_PI_A_K, 1));

        /* ---- ProfileKeyCredentialPresentation (pi_P): tagged; 19 pts, 9 sc. */
        ASSERT_EQ(gy_group_attr_profile(tier, UID, PK, Mp), GY_OK);
        ASSERT_EQ(gy_group_mac(tier, &sk_P,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])Mp,
                               GY_GROUP_ATTR_PROFILE, &cred_p),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_present(tier, &gens, &sp, &pp_pub, &pp_P, &cred_p,
                                      UID, PK, &ppres),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_pres_encode(tier, &ppres, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, sz(tier, GY_GROUP_OBJ_HDR_LEN, 11 + GY_GROUP_PI_P_M,
                        GY_GROUP_PI_P_K, 0));

        gy_group_server_secret_clear(&sk_A);
        gy_group_server_secret_clear(&sk_P);
        gy_group_secret_clear(&sp);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(object_sizes))
