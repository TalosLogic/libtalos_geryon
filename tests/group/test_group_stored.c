/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The store-integrated operation wrappers (the group
 * analogue of how gy_send / gy_recv persist records at their success point).
 * A real client<->server flow drives each wrapper, then the store is inspected
 * to confirm the output was persisted; a fault-injected store confirms the
 * atomic contract (on store failure the output is zeroized and nothing is
 * left behind).  Both classical tiers, over the shared mock store.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h" /* GY_GROUP_ATTR_AUTH / _PROFILE */
#include "group_mock_store.h"
#include "group_state.h"
#include "group_tier.h"
#include "util.h" /* gy_is_zero, gy_core_init */

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

static const uint8_t UID[GY_GROUP_UID_BYTES] = {
    0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
static const uint8_t NEW_PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
    0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

static const uint8_t UID_B[GY_GROUP_UID_BYTES] = {
    0xb0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t UID_C[GY_GROUP_UID_BYTES] = {
    0xc0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

#define STORED_DATE 1704067200ull /* day-aligned */

struct srv {
    struct gy_group_generators gens;
    struct gy_group_server_secret sk_A, sk_P;
    struct gy_group_server_public pp_A, pp_P;
};

static int
srv_init(const struct gy_group_tier *tier, struct srv *s)
{
    int rc;
    rc = gy_group_generators_derive(tier, &s->gens);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_server_keygen(tier, &s->gens, GY_GROUP_ATTR_AUTH, &s->sk_A);
    if (rc != GY_OK)
        return rc;
    rc =
        gy_group_server_keygen(tier, &s->gens, GY_GROUP_ATTR_PROFILE, &s->sk_P);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_server_public_from_secret(tier, &s->gens, &s->sk_A, &s->pp_A);
    if (rc != GY_OK)
        return rc;
    return gy_group_server_public_from_secret(tier, &s->gens, &s->sk_P,
                                              &s->pp_P);
}

/* Full GetProfileKeyCredential for (uid, pk); does NOT persist. */
static int
run_pk_cred(const struct gy_group_tier *tier, struct srv *s,
            const uint8_t uid[GY_GROUP_UID_BYTES],
            const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
            struct gy_group_mac_tag *out_cred)
{
    struct gy_group_pk_commitment commit;
    struct gy_group_pk_request req;
    struct gy_group_pk_blind_response resp;
    uint8_t version[GY_GROUP_PK_VERSION_BYTES];
    uint8_t y[GY_GROUP_SCALAR_MAX];
    int rc;

    rc = gy_group_get_pk_credential_request(tier, &s->gens, uid, pk, version,
                                            &req, y);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_commit(tier, &s->gens, uid, pk, &commit);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_blind_issue(tier, &s->gens, &s->sk_P, uid, &commit, &req,
                                 &resp);
    if (rc != GY_OK)
        return rc;
    return gy_group_get_pk_credential_finish(tier, &s->gens, &s->pp_P, uid,
                                             &req, y, &resp, out_cred);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(stored_wrappers)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct srv s;
        struct mock_store m;
        struct gy_group_store store;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp;
        struct gy_group_auth_response auth_resp;
        struct gy_group_auth_credential ac2;
        struct gy_group_pk_commitment commit;
        struct gy_group_pk_presentation pres;
        struct gy_group_mac_tag cred, cred2, credNew;
        uint8_t gid[GY_GROUP_ID_LEN];
        uint8_t version[GY_GROUP_PK_VERSION_BYTES];
        uint8_t opk[GY_GROUP_PROFILEKEY_BYTES];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(srv_init(tier, &s), GY_OK);
        mock_init(&m, &store);
        ASSERT_EQ(gy_group_create_stored(&store, tier, &s.gens, gid, &sp, &pp),
                  GY_OK);

        /* GetAuthCredential + persist: verify, then AUTH_CRED is stored. */
        ASSERT_EQ(gy_group_auth_issue(tier, &s.gens, &s.sk_A, UID, STORED_DATE,
                                      &auth_resp),
                  GY_OK);
        ASSERT_EQ(gy_group_get_auth_credential_stored(
                      &store, tier, &s.gens, &s.pp_A, gid, UID, STORED_DATE,
                      &auth_resp, &cred),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_cred_load(&store, tier, gid, &ac2), GY_OK);
        ASSERT_EQ(ac2.redemption_date, STORED_DATE);
        ASSERT_MEMEQ(&cred, &ac2.mac, sizeof(cred));

        /* Atomic contract: a store failure zeroizes the output and persists
         * nothing (checked on a fresh store). */
        {
            struct mock_store mf;
            struct gy_group_store storef;
            struct gy_group_mac_tag credf;

            mock_init(&mf, &storef);
            mf.fail_store = 1;
            memset(&credf, 0xAA, sizeof(credf));
            ASSERT_EQ(gy_group_get_auth_credential_stored(
                          &storef, tier, &s.gens, &s.pp_A, gid, UID,
                          STORED_DATE, &auth_resp, &credf),
                      GY_ERR_NO_SPACE);
            ASSERT_EQ(gy_is_zero(&credf, sizeof(credf)), 1);
            ASSERT_EQ(mock_count(&mf), 0);
        }

        /* CommitToProfileKey + persist: OWN_PK is stored. */
        ASSERT_EQ(gy_group_commit_to_profile_key_stored(
                      &store, tier, &s.gens, gid, UID, PK, version, &commit),
                  GY_OK);
        ASSERT_EQ(gy_group_own_pk_load(&store, tier, gid, opk), GY_OK);
        ASSERT_MEMEQ(opk, PK, sizeof(opk));

        /* GetProfileKeyCredential finish + persist: PK_CRED[uid] is stored. */
        {
            struct gy_group_pk_commitment commit2;
            struct gy_group_pk_request req;
            struct gy_group_pk_blind_response resp;
            uint8_t ver2[GY_GROUP_PK_VERSION_BYTES];
            uint8_t y[GY_GROUP_SCALAR_MAX];

            ASSERT_EQ(gy_group_get_pk_credential_request(tier, &s.gens, UID, PK,
                                                         ver2, &req, y),
                      GY_OK);
            ASSERT_EQ(gy_group_pk_commit(tier, &s.gens, UID, PK, &commit2),
                      GY_OK);
            ASSERT_EQ(gy_group_pk_blind_issue(tier, &s.gens, &s.sk_P, UID,
                                              &commit2, &req, &resp),
                      GY_OK);
            ASSERT_EQ(gy_group_get_pk_credential_finish_stored(
                          &store, tier, &s.gens, &s.pp_P, gid, UID, &req, y,
                          &resp, &cred),
                      GY_OK);
        }
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, UID, &cred2), GY_OK);
        ASSERT_MEMEQ(&cred, &cred2, sizeof(cred));

        /* UpdateProfileKey + persist: OWN_PK becomes NEW_PK and the stale own
         * ProfileKeyCredential is obsoleted (removed).  own_cred is a fresh
         * credential over NEW_PK (the update presents that). */
        ASSERT_EQ(run_pk_cred(tier, &s, UID, NEW_PK, &credNew), GY_OK);
        ASSERT_EQ(gy_group_update_profile_key_stored(&store, tier, &s.gens, &sp,
                                                     &pp, &s.pp_P, &credNew,
                                                     gid, UID, NEW_PK, &pres),
                  GY_OK);
        ASSERT_EQ(gy_group_own_pk_load(&store, tier, gid, opk), GY_OK);
        ASSERT_MEMEQ(opk, NEW_PK, sizeof(opk));
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, UID, &cred2),
                  GY_ERR_NOT_FOUND);

        gy_group_secret_clear(&sp);
        gy_group_server_secret_clear(&s.sk_A);
        gy_group_server_secret_clear(&s.sk_P);
    }
}

/*
 * The load-integrated / cleanup wrappers: AuthAsGroupMember loads its stored
 * credential and REFUSES an expired one (D-GRP-7 item 3); AddGroupMember loads
 * the target's stored ProfileKeyCredential; DeleteGroupMember removes the
 * target's now-obsolete cached credential.
 */
TEST(stored_consumers)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct srv s;
        struct mock_store m;
        struct gy_group_store store;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp;
        struct gy_group_auth_response auth_resp;
        struct gy_group_auth_presentation apres;
        struct gy_group_pk_presentation ppres;
        struct gy_group_uid_ct uidct;
        struct gy_group_mac_tag cred, credB, tmp;
        uint8_t gid[GY_GROUP_ID_LEN];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(srv_init(tier, &s), GY_OK);
        mock_init(&m, &store);
        ASSERT_EQ(gy_group_create_stored(&store, tier, &s.gens, gid, &sp, &pp),
                  GY_OK);

        /* Store the caller's own AuthCredential. */
        ASSERT_EQ(gy_group_auth_issue(tier, &s.gens, &s.sk_A, UID, STORED_DATE,
                                      &auth_resp),
                  GY_OK);
        ASSERT_EQ(gy_group_get_auth_credential_stored(
                      &store, tier, &s.gens, &s.pp_A, gid, UID, STORED_DATE,
                      &auth_resp, &cred),
                  GY_OK);

        /* AuthAsGroupMember_stored: presents on the redemption day, refuses off
         * it, and reports not-found when no credential is stored. */
        ASSERT_EQ(gy_group_auth_as_member_stored(&store, tier, &s.gens, &sp,
                                                 &pp, &s.pp_A, gid, UID,
                                                 STORED_DATE, &apres),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_as_member_stored(&store, tier, &s.gens, &sp,
                                                 &pp, &s.pp_A, gid, UID,
                                                 STORED_DATE + 86400, &apres),
                  GY_ERR_EXPIRED);
        {
            struct mock_store me;
            struct gy_group_store storee;
            mock_init(&me, &storee);
            ASSERT_EQ(gy_group_auth_as_member_stored(&storee, tier, &s.gens,
                                                     &sp, &pp, &s.pp_A, gid,
                                                     UID, STORED_DATE, &apres),
                      GY_ERR_NOT_FOUND);
        }

        /* AddGroupMember_stored: loads the target's stored ProfileKeyCredential
         * (keyed by new_uid); not-found when none is stored. */
        ASSERT_EQ(run_pk_cred(tier, &s, UID_B, PK, &credB), GY_OK);
        ASSERT_EQ(gy_group_pk_cred_store(&store, tier, gid, UID_B, &credB),
                  GY_OK);
        ASSERT_EQ(gy_group_add_member_stored(&store, tier, &s.gens, &sp, &pp,
                                             &s.pp_P, gid, UID_B, PK, &ppres),
                  GY_OK);
        ASSERT_EQ(gy_group_add_member_stored(&store, tier, &s.gens, &sp, &pp,
                                             &s.pp_P, gid, UID_C, PK, &ppres),
                  GY_ERR_NOT_FOUND);

        /* DeleteGroupMember_stored: removes the target's cached credential. */
        ASSERT_EQ(gy_group_delete_member_stored(&store, tier, &sp, gid, UID_B,
                                                &uidct),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_cred_load(&store, tier, gid, UID_B, &tmp),
                  GY_ERR_NOT_FOUND);

        gy_group_secret_clear(&sp);
        gy_group_server_secret_clear(&s.sk_A);
        gy_group_server_secret_clear(&s.sk_P);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(stored_wrappers), GY_TEST(stored_consumers))
