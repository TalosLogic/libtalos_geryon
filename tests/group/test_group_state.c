/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * GER-M8-09 state/storage tests (GROUP_SPEC section 10, D-GRP-7): GroupID
 * determinism, rederive-from-GroupMasterKey (nothing derived cached), the
 * invitee install path reproducing identical params, credential / own-ProfileKey
 * record round-trips, the spec-true redemption-day validity predicate,
 * not-found and delete behavior, and rejection of a corrupted master-key
 * record.  Both classical tiers, over a small in-memory mock store.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_mock_store.h"
#include "group_params.h"
#include "group_state.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* The in-memory mock gy_group_store lives in group_mock_store.h (shared). */

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(state_lifecycle)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_generators gens;
        struct mock_store m;
        struct gy_group_store store;
        struct gy_group_secret_params sp, sp2;
        struct gy_group_public_params pp, pp2;
        uint8_t gid[GY_GROUP_ID_LEN], gid2[GY_GROUP_ID_LEN];
        struct mock_rec *mk;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        mock_init(&m, &store);

        /* Create + persist; only the master key is stored (nothing derived). */
        ASSERT_EQ(gy_group_create_stored(&store, tier, &gens, gid, &sp, &pp),
                  GY_OK);
        ASSERT_EQ(mock_count(&m), 1);
        mk = mock_find(&m, GY_GREC_MASTER_KEY, gid, GY_GROUP_ID_LEN);
        ASSERT_TRUE(mk != NULL, "master key stored");
        ASSERT_EQ(mk->blob_len,
                  3 + tier->master_key_len); /* ver || fmtver(2) || gmk */

        /* GroupID is the deterministic hash of the public params AND the bound
         * format version (GER-GRPVER). */
        ASSERT_EQ(gy_group_id(tier, &pp, GY_GROUP_FORMAT_VERSION, gid2), GY_OK);
        ASSERT_MEMEQ(gid, gid2, GY_GROUP_ID_LEN);

        /* The stored format version reads back. */
        {
            uint16_t fv = 0;
            ASSERT_EQ(gy_group_format_version_load(&store, tier, gid, &fv),
                      GY_OK);
            ASSERT_EQ(fv, GY_GROUP_FORMAT_VERSION);
        }

        /* Reopen: rederive identical params, and no new record is written. */
        ASSERT_EQ(gy_group_load(&store, tier, &gens, gid, &sp2, &pp2), GY_OK);
        ASSERT_MEMEQ(&sp, &sp2, sizeof(sp));
        ASSERT_MEMEQ(&pp, &pp2, sizeof(pp));
        ASSERT_EQ(mock_count(&m), 1);

        /* Invitee install path: the same GroupMasterKey reproduces GroupID and
         * params in a fresh store (read the gmk back out of the mock record). */
        {
            struct mock_store m2;
            struct gy_group_store store2;
            struct gy_group_secret_params spi;
            struct gy_group_public_params ppi;
            uint8_t gidi[GY_GROUP_ID_LEN];

            mock_init(&m2, &store2);
            ASSERT_EQ(gy_group_install_master_key(
                          &store2, tier, &gens, mk->blob + 3,
                          tier->master_key_len, GY_GROUP_FORMAT_VERSION, gidi,
                          &spi, &ppi),
                      GY_OK);
            ASSERT_MEMEQ(gid, gidi, GY_GROUP_ID_LEN);
            ASSERT_MEMEQ(&sp, &spi, sizeof(sp));
            ASSERT_MEMEQ(&pp, &ppi, sizeof(pp));
            gy_group_secret_clear(&spi);
        }

        /* An out-of-window format version is refused, nothing stored
         * (GER-GRPVER: an old client declines a newer group). */
        {
            struct mock_store m3;
            struct gy_group_store store3;
            struct gy_group_secret_params spu;
            struct gy_group_public_params ppu;
            uint8_t gidu[GY_GROUP_ID_LEN];

            mock_init(&m3, &store3);
            ASSERT_EQ(gy_group_install_master_key(
                          &store3, tier, &gens, mk->blob + 3,
                          tier->master_key_len,
                          GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION + 1, gidu, &spu,
                          &ppu),
                      GY_ERR_UNSUPPORTED);
            ASSERT_EQ(mock_count(&m3), 0);
        }

        /* A corrupted master-key record fails to reopen (rederived GroupID no
         * longer matches the lookup key).  blob[1] is the high byte of the bound
         * format version, so this also exercises version tamper-evidence. */
        mk->blob[1] ^= 0x01;
        ASSERT_EQ(gy_group_load(&store, tier, &gens, gid, &sp2, &pp2),
                  GY_ERR_VERIFY);
        mk->blob[1] ^= 0x01; /* restore */

        gy_group_secret_clear(&sp);
        gy_group_secret_clear(&sp2);
    }
}

TEST(state_credentials)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_generators gens;
        struct mock_store m;
        struct gy_group_store store;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp;
        uint8_t gid[GY_GROUP_ID_LEN];
        struct gy_group_auth_credential ac, ac2;
        struct gy_group_mac_tag pc, pc2;
        uint8_t uid_a[GY_GROUP_UID_BYTES], uid_b[GY_GROUP_UID_BYTES];
        uint8_t opk[GY_GROUP_PROFILEKEY_BYTES], opk2[GY_GROUP_PROFILEKEY_BYTES];
        const uint64_t day = 1704067200ull; /* day-aligned */
        size_t i;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        mock_init(&m, &store);
        ASSERT_EQ(gy_group_create_stored(&store, tier, &gens, gid, &sp, &pp),
                  GY_OK);

        for (i = 0; i < GY_GROUP_UID_BYTES; i++) {
            uid_a[i] = (uint8_t)(0x10 + i);
            uid_b[i] = (uint8_t)(0xA0 + i);
        }

        /* AuthCredential round-trip + redemption-day validity. */
        memset(&ac, 0, sizeof(ac));
        for (i = 0; i < tier->scalar_len; i++)
            ac.mac.t[i] = (uint8_t)(i + 1);
        for (i = 0; i < tier->point_len; i++) {
            ac.mac.U[i] = (uint8_t)(i + 2);
            ac.mac.V[i] = (uint8_t)(i + 3);
        }
        ac.redemption_date = day;
        ASSERT_EQ(gy_group_auth_cred_load(&store, tier, gid, &ac2),
                  GY_ERR_NOT_FOUND); /* absent before store */
        ASSERT_EQ(gy_group_auth_cred_store(&store, tier, gid, &ac), GY_OK);
        ASSERT_EQ(gy_group_auth_cred_load(&store, tier, gid, &ac2), GY_OK);
        ASSERT_MEMEQ(&ac, &ac2, sizeof(ac));
        ASSERT_EQ(gy_group_auth_cred_valid(&ac2, day), 1);        /* on day */
        ASSERT_EQ(gy_group_auth_cred_valid(&ac2, day + 3600), 1); /* same day */
        ASSERT_EQ(gy_group_auth_cred_valid(&ac2, day + 86400),
                  0);                                          /* next day */
        ASSERT_EQ(gy_group_auth_cred_valid(&ac2, day - 1), 0); /* prior day */

        /* ProfileKeyCredential keyed per target UID. */
        memset(&pc, 0, sizeof(pc));
        for (i = 0; i < tier->scalar_len; i++)
            pc.t[i] = (uint8_t)(i + 9);
        for (i = 0; i < tier->point_len; i++) {
            pc.U[i] = (uint8_t)(i + 11);
            pc.V[i] = (uint8_t)(i + 13);
        }
        ASSERT_EQ(gy_group_pk_cred_store(&store, tier, gid, uid_a, &pc), GY_OK);
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, uid_a, &pc2), GY_OK);
        ASSERT_MEMEQ(&pc, &pc2, sizeof(pc));
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, uid_b, &pc2),
                  GY_ERR_NOT_FOUND); /* different UID */
        ASSERT_EQ(gy_group_pk_cred_remove(&store, tier, gid, uid_a), GY_OK);
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, uid_a, &pc2),
                  GY_ERR_NOT_FOUND); /* removed */

        /* Own ProfileKey. */
        for (i = 0; i < GY_GROUP_PROFILEKEY_BYTES; i++)
            opk[i] = (uint8_t)(i + 0x40);
        ASSERT_EQ(gy_group_own_pk_load(&store, tier, gid, opk2),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(gy_group_own_pk_store(&store, tier, gid, opk), GY_OK);
        ASSERT_EQ(gy_group_own_pk_load(&store, tier, gid, opk2), GY_OK);
        ASSERT_MEMEQ(opk, opk2, sizeof(opk));

        /* Delete removes the group-keyed records; reopen is not-found. */
        ASSERT_EQ(gy_group_delete_stored(&store, tier, gid), GY_OK);
        ASSERT_EQ(gy_group_load(&store, tier, &gens, gid, &sp, &pp),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(gy_group_auth_cred_load(&store, tier, gid, &ac2),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(gy_group_own_pk_load(&store, tier, gid, opk2),
                  GY_ERR_NOT_FOUND);

        gy_group_secret_clear(&sp);
        gy_group_auth_credential_clear(&ac);
    }
}

/*
 * Fault-injection (D-SES-10 style, D-GRP-7 validation): a store failure during
 * create persists nothing, and a delete whose removes fail mid-sequence leaves
 * the group consistent because the GroupMasterKey is removed last (a partial
 * delete never orphans records under a missing master key).
 */
TEST(state_transactional)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_generators gens;
        struct mock_store m;
        struct gy_group_store store;
        struct gy_group_secret_params sp, sp2;
        struct gy_group_public_params pp, pp2;
        uint8_t gid[GY_GROUP_ID_LEN];
        struct gy_group_auth_credential ac;
        uint8_t opk[GY_GROUP_PROFILEKEY_BYTES];
        size_t i;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);

        /* A store failure during create persists nothing (snapshot intact). */
        mock_init(&m, &store);
        m.fail_store = 1;
        ASSERT_EQ(gy_group_create_stored(&store, tier, &gens, gid, &sp, &pp),
                  GY_ERR_NO_SPACE);
        ASSERT_EQ(mock_count(&m), 0);

        /* Build a full group: master key + auth cred + own ProfileKey. */
        mock_init(&m, &store);
        ASSERT_EQ(gy_group_create_stored(&store, tier, &gens, gid, &sp, &pp),
                  GY_OK);
        memset(&ac, 0, sizeof(ac));
        ac.redemption_date = 1704067200ull;
        ASSERT_EQ(gy_group_auth_cred_store(&store, tier, gid, &ac), GY_OK);
        for (i = 0; i < GY_GROUP_PROFILEKEY_BYTES; i++)
            opk[i] = (uint8_t)i;
        ASSERT_EQ(gy_group_own_pk_store(&store, tier, gid, opk), GY_OK);
        ASSERT_EQ(mock_count(&m), 3);

        /* Delete whose FIRST remove (a credential) fails: the master key,
         * removed last, is untouched, so the group stays openable. */
        m.fail_remove_at = 1;
        m.remove_calls = 0;
        ASSERT_EQ(gy_group_delete_stored(&store, tier, gid), GY_ERR_NO_SPACE);
        ASSERT_TRUE(mock_find(&m, GY_GREC_MASTER_KEY, gid, GY_GROUP_ID_LEN) !=
                        NULL,
                    "master key survives a failed credential removal");
        ASSERT_EQ(gy_group_load(&store, tier, &gens, gid, &sp2, &pp2), GY_OK);
        gy_group_secret_clear(&sp2);

        /* Delete whose LAST remove (the master key) fails: dependent records
         * are gone, the master key remains, the group is still consistent. */
        mock_init(&m, &store);
        ASSERT_EQ(gy_group_create_stored(&store, tier, &gens, gid, &sp2, &pp2),
                  GY_OK);
        ASSERT_EQ(gy_group_own_pk_store(&store, tier, gid, opk), GY_OK);
        m.fail_remove_at =
            3; /* AUTH_CRED(1), OWN_PK(2) ok; MASTER_KEY(3) fails */
        m.remove_calls = 0;
        ASSERT_EQ(gy_group_delete_stored(&store, tier, gid), GY_ERR_NO_SPACE);
        ASSERT_TRUE(mock_find(&m, GY_GREC_MASTER_KEY, gid, GY_GROUP_ID_LEN) !=
                        NULL,
                    "master key remains when its own removal fails");

        gy_group_secret_clear(&sp);
        gy_group_secret_clear(&sp2);
    }
}

/*
 * Zeroization sweep (D-GRP-7): a poisoned GroupSecretParams / AuthCredential is
 * fully zeroed by its clear function (part of the protocol, not cleanup).
 */
TEST(state_zeroize)
{
    struct gy_group_secret_params sp;
    struct gy_group_auth_credential ac;

    memset(&sp, 0xAA, sizeof(sp));
    gy_group_secret_clear(&sp);
    ASSERT_EQ(gy_is_zero(&sp, sizeof(sp)), 1);

    memset(&ac, 0xAA, sizeof(ac));
    gy_group_auth_credential_clear(&ac);
    ASSERT_EQ(gy_is_zero(&ac, sizeof(ac)), 1);
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(state_lifecycle),
             GY_TEST(state_credentials), GY_TEST(state_transactional),
             GY_TEST(state_zeroize))
