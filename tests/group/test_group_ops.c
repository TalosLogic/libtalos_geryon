/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Property tests: the ten client-side group operations (GROUP_SPEC
 * section 7), driven as a two-party lifecycle (a member "client" and a stateful
 * test "server" holding ServerSecretParams and the authoritative member list) on
 * BOTH classical tiers.  Exercises every operation round-trip and the negative
 * cases (forged/tampered credential, wrong identity, tampered proof,
 * non-day-aligned date, malformed fetch entry, over-cap fetch).
 *
 * The server-side crypto (issue / verify / blind-issue) is the existing
 * credential surface, called directly here; the server target
 * repackages it as a standalone target.  Membership state is held
 * in this test (the library never
 * stores it, section 10); the member-list container here is the provisional
 * client-side view (Split A).
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_mac.h"
#include "group_ops.h"
#include "group_params.h"
#include "util.h" /* gy_secure_zero */

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* Three members: A creates, B is added, C is invited (ProfileKey unknown). */
static const uint8_t UID_A[GY_GROUP_UID_BYTES] = {
    0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t UID_B[GY_GROUP_UID_BYTES] = {
    0xb0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t UID_C[GY_GROUP_UID_BYTES] = {
    0xc0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static const uint8_t PK_A[GY_GROUP_PROFILEKEY_BYTES] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
static const uint8_t PK_B[GY_GROUP_PROFILEKEY_BYTES] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
    0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f};
static const uint8_t PK_A2[GY_GROUP_PROFILEKEY_BYTES] = {
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
    0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
    0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};

#define OPS_DATE 1704067200ull /* day-aligned */

/* One test "server" for a group: the two MAC keys and their public params. */
struct test_server {
    struct gy_group_generators gens;
    struct gy_group_server_secret sk_A;
    struct gy_group_server_secret sk_P;
    struct gy_group_server_public pp_A;
    struct gy_group_server_public pp_P;
};

static int
server_init(const struct gy_group_tier *tier, struct test_server *s)
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

static void
server_clear(struct test_server *s)
{
    gy_group_server_secret_clear(&s->sk_A);
    gy_group_server_secret_clear(&s->sk_P);
}

/*
 * Full GetProfileKeyCredential (7.3) round-trip for (uid, pk): client requests,
 * server blind-issues against the freshly recomputed commitment, client
 * finishes.  Returns the ProfileKeyCredential in out_cred.  (The commitment is
 * deterministic, section 3.3, so the server recomputes it exactly as
 * CommitToProfileKey stored it.)
 */
static int
run_get_pk_credential(const struct gy_group_tier *tier, struct test_server *s,
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
    /* Server: look up the stored commitment (here, recompute it) and issue. */
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

/* Store a full (uid, pk) member entry from a verified ProfileKey presentation. */
static void
store_full(struct gy_group_member_ct *e,
           const struct gy_group_pk_presentation *p, uint8_t role)
{
    memset(e, 0, sizeof(*e));
    memcpy(e->uid_ct.E_A1, p->E_A1, GY_GROUP_POINT_MAX);
    memcpy(e->uid_ct.E_A2, p->E_A2, GY_GROUP_POINT_MAX);
    memcpy(e->pk_ct.E_B1, p->E_B1, GY_GROUP_POINT_MAX);
    memcpy(e->pk_ct.E_B2, p->E_B2, GY_GROUP_POINT_MAX);
    e->role = role;
    e->has_profile_key = 1;
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(lifecycle)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct test_server srv;
        struct gy_group_secret_params sp;
        struct gy_group_public_params pp;
        struct gy_group_auth_response auth_resp;
        struct gy_group_auth_presentation auth_pres;
        struct gy_group_pk_presentation pk_pres;
        struct gy_group_pk_commitment commit;
        struct gy_group_mac_tag authcred, credA, credB, credA2;
        struct gy_group_member_ct store[4];
        struct gy_group_member view[4];
        struct gy_group_uid_ct del_ct;
        uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
        uint8_t version[GY_GROUP_PK_VERSION_BYTES];
        size_t nstore = 0, count = 0, i;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(server_init(tier, &srv), GY_OK);

        /* 7.6 CreateGroup: A generates the group. */
        ASSERT_EQ(gy_group_create(tier, &srv.gens, gmk, &sp, &pp), GY_OK);

        /* 7.1 GetAuthCredential: server issues, A verifies + stores. */
        ASSERT_EQ(gy_group_auth_issue(tier, &srv.gens, &srv.sk_A, UID_A,
                                      OPS_DATE, &auth_resp),
                  GY_OK);
        ASSERT_EQ(gy_group_get_auth_credential(tier, &srv.gens, &srv.pp_A,
                                               UID_A, OPS_DATE, &auth_resp,
                                               &authcred),
                  GY_OK);

        /* 7.2 CommitToProfileKey: A commits to its own ProfileKey. */
        ASSERT_EQ(gy_group_commit_to_profile_key(tier, &srv.gens, UID_A, PK_A,
                                                 version, &commit),
                  GY_OK);

        /* 7.3 GetProfileKeyCredential: A (own), and A obtains B's credential. */
        ASSERT_EQ(run_get_pk_credential(tier, &srv, UID_A, PK_A, &credA),
                  GY_OK);
        ASSERT_EQ(run_get_pk_credential(tier, &srv, UID_B, PK_B, &credB),
                  GY_OK);

        /* 7.4 AuthAsGroupMember: A authenticates; server verifies. */
        ASSERT_EQ(gy_group_auth_as_member(tier, &srv.gens, &sp, &pp, &srv.pp_A,
                                          &authcred, UID_A, OPS_DATE,
                                          &auth_pres),
                  GY_OK);
        ASSERT_EQ(gy_group_auth_present_verify(tier, &srv.gens, &srv.sk_A, &pp,
                                               &auth_pres),
                  GY_OK);

        /* 7.6 self-add: A adds its own entry (server skips the Role check). */
        ASSERT_EQ(gy_group_add_member(tier, &srv.gens, &sp, &pp, &srv.pp_P,
                                      &credA, UID_A, PK_A, &pk_pres),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_present_verify(tier, &srv.gens, &srv.sk_P, &pp,
                                             &pk_pres),
                  GY_OK);
        store_full(&store[nstore++], &pk_pres, 0x01);

        /* 7.5 AddGroupMember: A adds B with B's credential. */
        ASSERT_EQ(gy_group_add_member(tier, &srv.gens, &sp, &pp, &srv.pp_P,
                                      &credB, UID_B, PK_B, &pk_pres),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_present_verify(tier, &srv.gens, &srv.sk_P, &pp,
                                             &pk_pres),
                  GY_OK);
        store_full(&store[nstore++], &pk_pres, 0x01); /* a defined role */

        /* 7.9 AddInvitedGroupMember: A invites C (no ProfileKey). */
        memset(&store[nstore], 0, sizeof(store[nstore]));
        ASSERT_EQ(gy_group_add_invited_member(tier, &sp, UID_C,
                                              &store[nstore].uid_ct),
                  GY_OK);
        store[nstore].role =
            0x00; /* a defined role (values are wire-validated) */
        store[nstore].has_profile_key = 0;
        nstore++;

        /* 7.7 FetchGroupMembers: decrypt the roster and check it. */
        ASSERT_EQ(gy_group_fetch_members(tier, &sp, store, nstore, view,
                                         (size_t)4, &count),
                  GY_OK);
        ASSERT_EQ(count, nstore);
        ASSERT_MEMEQ(view[0].uid, UID_A, GY_GROUP_UID_BYTES);
        ASSERT_EQ(view[0].has_profile_key, 1u);
        ASSERT_MEMEQ(view[0].profile_key, PK_A, GY_GROUP_PROFILEKEY_BYTES);
        ASSERT_MEMEQ(view[1].uid, UID_B, GY_GROUP_UID_BYTES);
        ASSERT_MEMEQ(view[1].profile_key, PK_B, GY_GROUP_PROFILEKEY_BYTES);
        ASSERT_MEMEQ(view[2].uid, UID_C, GY_GROUP_UID_BYTES);
        ASSERT_EQ(view[2].has_profile_key, 0u); /* invited: UID only */

        /* 7.10 UpdateProfileKey: A rotates its ProfileKey (needs a fresh
         * credential over the new key), server replaces A's entry only. */
        ASSERT_EQ(run_get_pk_credential(tier, &srv, UID_A, PK_A2, &credA2),
                  GY_OK);
        ASSERT_EQ(gy_group_update_profile_key(tier, &srv.gens, &sp, &pp,
                                              &srv.pp_P, &credA2, UID_A, PK_A2,
                                              &pk_pres),
                  GY_OK);
        ASSERT_EQ(gy_group_pk_present_verify(tier, &srv.gens, &srv.sk_P, &pp,
                                             &pk_pres),
                  GY_OK);
        store_full(&store[0], &pk_pres, 0x01); /* A's entry updated in place */
        ASSERT_EQ(gy_group_fetch_members(tier, &sp, store, nstore, view,
                                         (size_t)4, &count),
                  GY_OK);
        ASSERT_MEMEQ(view[0].uid, UID_A, GY_GROUP_UID_BYTES);
        ASSERT_MEMEQ(view[0].profile_key, PK_A2, GY_GROUP_PROFILEKEY_BYTES);

        /* 7.8 DeleteGroupMember: A deletes B; the delete key is B's
         * deterministic UidCiphertext, which matches the stored entry. */
        ASSERT_EQ(gy_group_delete_member(tier, &sp, UID_B, &del_ct), GY_OK);
        ASSERT_MEMEQ(del_ct.E_A1, store[1].uid_ct.E_A1, tier->point_len);
        ASSERT_MEMEQ(del_ct.E_A2, store[1].uid_ct.E_A2, tier->point_len);
        /* Server removes the matching entry; roster now A, C. */
        store[1] = store[2];
        nstore--;
        ASSERT_EQ(gy_group_fetch_members(tier, &sp, store, nstore, view,
                                         (size_t)4, &count),
                  GY_OK);
        ASSERT_EQ(count, (size_t)2);
        ASSERT_MEMEQ(view[1].uid, UID_C, GY_GROUP_UID_BYTES);

        for (i = 0; i < 4; i++)
            gy_secure_zero(&view[i], sizeof(view[i]));
        gy_group_secret_clear(&sp);
        gy_secure_zero(gmk, sizeof(gmk));
        server_clear(&srv);
    }
}

TEST(negatives)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct test_server srv;
        struct gy_group_secret_params sp, sp2;
        struct gy_group_public_params pp, pp2;
        struct gy_group_auth_response resp;
        struct gy_group_mac_tag cred;
        struct gy_group_member_ct entry;
        struct gy_group_member view[2];
        uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
        uint8_t gmk2[GY_GROUP_MASTER_KEY_MAX];
        size_t count;

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(server_init(tier, &srv), GY_OK);
        ASSERT_EQ(gy_group_create(tier, &srv.gens, gmk, &sp, &pp), GY_OK);
        ASSERT_EQ(gy_group_create(tier, &srv.gens, gmk2, &sp2, &pp2), GY_OK);
        ASSERT_EQ(gy_group_auth_issue(tier, &srv.gens, &srv.sk_A, UID_A,
                                      OPS_DATE, &resp),
                  GY_OK);

        /* Honest verify succeeds. */
        ASSERT_EQ(gy_group_get_auth_credential(tier, &srv.gens, &srv.pp_A,
                                               UID_A, OPS_DATE, &resp, &cred),
                  GY_OK);
        /* Wrong identity: verifying against B's UID is rejected. */
        ASSERT_EQ(gy_group_get_auth_credential(tier, &srv.gens, &srv.pp_A,
                                               UID_B, OPS_DATE, &resp, &cred),
                  GY_ERR_VERIFY);
        /* Tampered proof: flip one response byte. */
        resp.proof_r[0][0] ^= 0x01;
        ASSERT_EQ(gy_group_get_auth_credential(tier, &srv.gens, &srv.pp_A,
                                               UID_A, OPS_DATE, &resp, &cred),
                  GY_ERR_VERIFY);
        resp.proof_r[0][0] ^= 0x01;
        /* Non-day-aligned redemption date is rejected at issuance. */
        ASSERT_EQ(gy_group_auth_issue(tier, &srv.gens, &srv.sk_A, UID_A,
                                      OPS_DATE + 1, &resp),
                  GY_ERR_ARG);

        /* An entry encrypted under a DIFFERENT group key does not decrypt under
         * this group: a genuine (non-identity) but inconsistent UidCiphertext. */
        memset(&entry, 0, sizeof(entry));
        ASSERT_EQ(gy_group_uid_encrypt(tier, &sp2, UID_A, &entry.uid_ct),
                  GY_OK);
        entry.has_profile_key = 0;

        /* Fetch that would overrun the caller's view buffer is rejected
         * (D-SES-4 bound): one input entry, zero output capacity. */
        ASSERT_EQ(gy_group_fetch_members(tier, &sp, &entry, 1, view, 0, &count),
                  GY_ERR_ARG);

        /* The inconsistent entry fails the whole fetch (transactional). */
        ASSERT_EQ(gy_group_fetch_members(tier, &sp, &entry, 1, view, 2, &count),
                  GY_ERR_VERIFY);
        ASSERT_EQ(count, (size_t)0);

        gy_group_secret_clear(&sp);
        gy_group_secret_clear(&sp2);
        gy_secure_zero(gmk, sizeof(gmk));
        gy_secure_zero(gmk2, sizeof(gmk2));
        server_clear(&srv);
    }
}

TEST(pkv_properties)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        uint8_t v1[GY_GROUP_PK_VERSION_BYTES];
        uint8_t v2[GY_GROUP_PK_VERSION_BYTES];

        ASSERT_TRUE(tier != NULL, "tier");

        /* Deterministic in (ProfileKey, UID). */
        ASSERT_EQ(gy_group_profile_key_version(tier, UID_A, PK_A, v1), GY_OK);
        ASSERT_EQ(gy_group_profile_key_version(tier, UID_A, PK_A, v2), GY_OK);
        ASSERT_MEMEQ(v1, v2, GY_GROUP_PK_VERSION_BYTES);

        /* UID-bound: same ProfileKey, different UID -> different version. */
        ASSERT_EQ(gy_group_profile_key_version(tier, UID_B, PK_A, v2), GY_OK);
        ASSERT_TRUE(memcmp(v1, v2, GY_GROUP_PK_VERSION_BYTES) != 0,
                    "version binds UID");

        /* Different ProfileKey -> different version. */
        ASSERT_EQ(gy_group_profile_key_version(tier, UID_A, PK_B, v2), GY_OK);
        ASSERT_TRUE(memcmp(v1, v2, GY_GROUP_PK_VERSION_BYTES) != 0,
                    "version binds ProfileKey");
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(lifecycle), GY_TEST(negatives),
             GY_TEST(pkv_properties))
