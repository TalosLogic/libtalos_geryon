/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for verifiable encryption of UID and ProfileKey (GROUP_SPEC section
 * 6), both classical tiers: Enc/Dec round-trip, deterministic
 * unique-ciphertext, and rejection of the wrong key, a tampered ciphertext, an
 * identity E1, and (for ProfileKey) the wrong UID.  Also the ciphertext object
 * encodings.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_params.h"
#include "group_tier.h"
#include "group_venc.h"
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
derive_sp(const struct gy_group_tier *tier, uint8_t seed,
          struct gy_group_secret_params *sp)
{
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    size_t i;

    for (i = 0; i < tier->master_key_len; i++)
        gmk[i] = (uint8_t)(seed + i);
    ASSERT_EQ(gy_group_secret_derive(tier, gmk, tier->master_key_len, sp),
              GY_OK);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(uid_roundtrip_reject)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_secret_params sp, sp2;
        struct gy_group_uid_ct ct, ct_b;
        uint8_t uid_out[GY_GROUP_UID_BYTES];

        ASSERT_TRUE(tier != NULL, "tier");
        derive_sp(tier, 0x01, &sp);

        ASSERT_EQ(gy_group_uid_encrypt(tier, &sp, UID, &ct), GY_OK);
        ASSERT_EQ(gy_group_uid_decrypt(tier, &sp, &ct, uid_out), GY_OK);
        ASSERT_MEMEQ(uid_out, UID, GY_GROUP_UID_BYTES);

        /* Deterministic, unique ciphertext: same inputs -> same bytes. */
        ASSERT_EQ(gy_group_uid_encrypt(tier, &sp, UID, &ct_b), GY_OK);
        ASSERT_MEMEQ(&ct, &ct_b, sizeof(ct));

        /* Wrong key rejected. */
        derive_sp(tier, 0x80, &sp2);
        ASSERT_EQ(gy_group_uid_decrypt(tier, &sp2, &ct, uid_out),
                  GY_ERR_VERIFY);

        /* Cross-group unlinkability (GROUP_SPEC section 11.3): the SAME UID
         * under a different group's params yields a different ciphertext, so an
         * honest-but-curious server cannot link a UID across groups. */
        {
            struct gy_group_uid_ct ct2;
            ASSERT_EQ(gy_group_uid_encrypt(tier, &sp2, UID, &ct2), GY_OK);
            ASSERT_TRUE(memcmp(&ct, &ct2, sizeof(ct)) != 0,
                        "same UID unlinkable across groups");
        }

        /* Tampered ciphertext rejected. */
        {
            struct gy_group_uid_ct bad = ct;
            bad.E_A2[0] ^= 0x01;
            ASSERT_EQ(gy_group_uid_decrypt(tier, &sp, &bad, uid_out),
                      GY_ERR_VERIFY);
        }

        /* Identity E_A1 rejected. */
        {
            struct gy_group_uid_ct bad = ct;
            memset(bad.E_A1, 0, sizeof(bad.E_A1));
            ASSERT_EQ(gy_group_uid_decrypt(tier, &sp, &bad, uid_out),
                      GY_ERR_VERIFY);
        }

        gy_group_secret_clear(&sp);
        gy_group_secret_clear(&sp2);
    }
}

TEST(pk_roundtrip_reject)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_secret_params sp, sp2;
        struct gy_group_pk_ct ct, ct_b;
        uint8_t pk_out[GY_GROUP_PROFILEKEY_BYTES];

        derive_sp(tier, 0x11, &sp);

        ASSERT_EQ(gy_group_pk_encrypt(tier, &sp, PK, UID, &ct), GY_OK);
        ASSERT_EQ(gy_group_pk_decrypt(tier, &sp, &ct, UID, pk_out), GY_OK);
        ASSERT_MEMEQ(pk_out, PK, GY_GROUP_PROFILEKEY_BYTES);

        /* Deterministic. */
        ASSERT_EQ(gy_group_pk_encrypt(tier, &sp, PK, UID, &ct_b), GY_OK);
        ASSERT_MEMEQ(&ct, &ct_b, sizeof(ct));

        /* Wrong key rejected. */
        derive_sp(tier, 0x90, &sp2);
        ASSERT_EQ(gy_group_pk_decrypt(tier, &sp2, &ct, UID, pk_out),
                  GY_ERR_VERIFY);

        /* Wrong UID rejected (candidate test binds UID). */
        {
            uint8_t uid2[GY_GROUP_UID_BYTES];
            memcpy(uid2, UID, sizeof(uid2));
            uid2[0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_decrypt(tier, &sp, &ct, uid2, pk_out),
                      GY_ERR_VERIFY);
        }

        /* Tampered ciphertext rejected. */
        {
            struct gy_group_pk_ct bad = ct;
            bad.E_B2[0] ^= 0x01;
            ASSERT_EQ(gy_group_pk_decrypt(tier, &sp, &bad, UID, pk_out),
                      GY_ERR_VERIFY);
        }

        /* Identity E_B1 rejected. */
        {
            struct gy_group_pk_ct bad = ct;
            memset(bad.E_B1, 0, sizeof(bad.E_B1));
            ASSERT_EQ(gy_group_pk_decrypt(tier, &sp, &bad, UID, pk_out),
                      GY_ERR_VERIFY);
        }

        gy_group_secret_clear(&sp);
        gy_group_secret_clear(&sp2);
    }
}

TEST(ct_encoding)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_secret_params sp;
        struct gy_group_uid_ct uct, uct2;
        struct gy_group_pk_ct pct, pct2;
        uint8_t buf[GY_GROUP_UID_CT_ENC_MAX];
        size_t n, plen = tier->point_len;

        derive_sp(tier, 0x21, &sp);
        ASSERT_EQ(gy_group_uid_encrypt(tier, &sp, UID, &uct), GY_OK);
        ASSERT_EQ(gy_group_pk_encrypt(tier, &sp, PK, UID, &pct), GY_OK);

        ASSERT_EQ(gy_group_uid_ct_encode(tier, &uct, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, 2 * plen);
        ASSERT_EQ(gy_group_uid_ct_decode(tier, &uct2, buf, n), GY_OK);
        ASSERT_MEMEQ(&uct, &uct2, sizeof(uct));
        ASSERT_EQ(gy_group_uid_ct_decode(tier, &uct2, buf, n - 1),
                  GY_ERR_VERIFY);

        ASSERT_EQ(gy_group_pk_ct_encode(tier, &pct, buf, sizeof(buf), &n),
                  GY_OK);
        ASSERT_EQ(n, 2 * plen);
        ASSERT_EQ(gy_group_pk_ct_decode(tier, &pct2, buf, n), GY_OK);
        ASSERT_MEMEQ(&pct, &pct2, sizeof(pct));

        gy_group_secret_clear(&sp);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(uid_roundtrip_reject),
             GY_TEST(pk_roundtrip_reject), GY_TEST(ct_encoding))
