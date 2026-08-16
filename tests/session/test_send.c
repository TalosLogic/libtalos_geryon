/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * send path: OpenSSL-style size queries, an initiation message that a
 * real responder (gy_sim) decrypts (the embedded DR frame is complete), an
 * established-session send the peer's ratchet decrypts, staged-commit-only-on-
 * accept (D-SES-10), the fan-out markers with self-device exclusion, the
 * D-SES-7 stale interplay, and the D-SES-8 re-initiate demotion.  Runs on a
 * persistent in-memory store with the two-party harness as the peer.
 */

#include <string.h>

#include "send.h"

#include "gy_sim.h"
#include "gy_test.h"

static const struct gy_suite_desc *D;

/* ---- persistent in-memory mock store (shared shape with test_lifecycle) - */

#define MOCK_MAX 48

struct mock_rec {
    int in_use;
    int kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    size_t blob_len;
    uint8_t blob[GY_SESSION_BLOB_MAX];
};

struct mock {
    struct mock_rec recs[MOCK_MAX];
};

static struct mock_rec *
mock_find(struct mock *m, int kind, const uint8_t *id, size_t id_len)
{
    int i;

    for (i = 0; i < MOCK_MAX; i++)
        if (m->recs[i].in_use && m->recs[i].kind == kind &&
            m->recs[i].id_len == id_len &&
            memcmp(m->recs[i].id, id, id_len) == 0)
            return &m->recs[i];
    return NULL;
}

static int
mock_count(struct mock *m, int kind)
{
    int i, n = 0;

    for (i = 0; i < MOCK_MAX; i++)
        if (m->recs[i].in_use && m->recs[i].kind == kind)
            n++;
    return n;
}

static int
m_load(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len,
       uint8_t *out, size_t cap, size_t *out_len)
{
    struct mock *m = ctx;
    struct mock_rec *r = mock_find(m, (int)kind, id, id_len);

    if (r == NULL) {
        *out_len = 0;
        return GY_OK;
    }
    if (r->blob_len > cap)
        return GY_ERR_ARG;
    memcpy(out, r->blob, r->blob_len);
    *out_len = r->blob_len;
    return GY_OK;
}

static int
m_store(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len,
        const uint8_t *blob, size_t blob_len)
{
    struct mock *m = ctx;
    struct mock_rec *r = mock_find(m, (int)kind, id, id_len);

    if (r == NULL) {
        int i;

        for (i = 0; i < MOCK_MAX; i++)
            if (!m->recs[i].in_use) {
                r = &m->recs[i];
                break;
            }
        if (r == NULL)
            return GY_ERR_STATE;
        r->in_use = 1;
        r->kind = (int)kind;
        r->id_len = id_len;
        memcpy(r->id, id, id_len);
    }
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static int
m_delete(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len)
{
    struct mock *m = ctx;
    struct mock_rec *r = mock_find(m, (int)kind, id, id_len);

    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK;
}

static int
m_consume(void *ctx, uint32_t pkid)
{
    (void)ctx;
    (void)pkid;
    return GY_OK;
}

static int
m_load_identity(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    (void)ctx;
    (void)out;
    (void)cap;
    *out_len = 0;
    return GY_OK;
}

static int
m_store_identity(void *ctx, const uint8_t *blob, size_t blob_len)
{
    (void)ctx;
    (void)blob;
    (void)blob_len;
    return GY_OK;
}

static int
m_load_prekey(void *ctx, enum gy_prekey_kind kind, uint32_t pkid, uint8_t *out,
              size_t cap, size_t *out_len)
{
    (void)ctx;
    (void)kind;
    (void)pkid;
    (void)out;
    (void)cap;
    *out_len = 0;
    return GY_OK;
}

static void
mock_reset(struct mock *m, struct gy_store *st)
{
    memset(m, 0, sizeof(*m));
    st->ctx = m;
    st->load_record = m_load;
    st->store_record = m_store;
    st->delete_record = m_delete;
    st->load_identity = m_load_identity;
    st->store_identity = m_store_identity;
    st->load_prekey = m_load_prekey;
    st->consume_opk = m_consume;
}

/* ---- fixtures ---------------------------------------------------------- */

static struct mock g_mock;
static struct gy_store g_store;
static struct gy_send_ctx g_ctx; /* large: gy_op arena inside */

static const uint8_t BOB_UID[4] = {0xB0, 0xB0, 0xB0, 0xB0};
static const uint8_t BOB_DID[4] = {0xD0, 0xD1, 0xD2, 0xD3};
/* A distinct sender-self UserID that reuses Bob's DeviceID string (D-SES-12). */
static const uint8_t SELF_UID[4] = {0x5E, 0x1F, 0x00, 0x00};

/* Build a fresh sender ctx (Alice) over the reset store; caller keeps ik. */
static void
ctx_fresh(struct gy_keypair *alice_ik, const struct gy_expiry_cfg *expiry,
          const uint8_t *self_did, size_t self_dl)
{
    mock_reset(&g_mock, &g_store);
    ASSERT_EQ(gy_keypair_generate(D, alice_ik), GY_OK);
    /*
     * These fixtures never configure a self device (self_did is always NULL),
     * so the self (UserID, DeviceID) pair is empty (D-SES-12).  The self-
     * exclusion path is exercised by the fan_out test's direct init below.
     */
    ASSERT_EQ(gy_send_ctx_init(&g_ctx, &g_store, D, alice_ik,
                               GY_AEAD_CHACHA20POLY1305, expiry, NULL, 0,
                               self_did, self_dl),
              GY_OK);
}

static void
load_bob_device(struct gy_device_record *dev)
{
    uint8_t dk[GY_DEVKEY_LEN];
    int found;

    /* D-SES-12: DeviceRecords key on gy_devrec_key over (UserID, DeviceID). */
    ASSERT_EQ(
        gy_devrec_key(BOB_UID, sizeof(BOB_UID), BOB_DID, sizeof(BOB_DID), dk),
        GY_OK);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_op_load_device(&g_ctx.op, dk, GY_DEVKEY_LEN, dev, &found),
              GY_OK);
    ASSERT_EQ(found, 1);
    gy_send_abort(&g_ctx);
}

/* ---- tests ------------------------------------------------------------- */

TEST(size_query)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    size_t est = 0, ini = 0;
    uint8_t pt[5] = "hello";

    ctx_fresh(&ik, NULL, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    /* out == NULL reports an upper bound; initiation is the larger class. */
    ASSERT_EQ(gy_send_encrypt(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                              sizeof(BOB_DID), pt, sizeof(pt), NULL, &est),
              GY_OK);
    ASSERT_TRUE(est > sizeof(pt), "established size above plaintext");
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, NULL, &ini),
              GY_OK);
    ASSERT_TRUE(ini > est, "initiation size above established");
    gy_sim_free(&sim);
}

TEST(initiate_roundtrip)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    uint8_t msg[4096], back[512];
    size_t mlen = sizeof(msg), blen = sizeof(back);
    uint8_t pt[11] = "first-frame";

    ctx_fresh(&ik, NULL, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);

    /* Records landed; the responder decrypts the embedded first DR frame. */
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 1);
    ASSERT_EQ(
        gy_sim_bob_recv_initial(&sim, msg, mlen, back, sizeof(back), &blen),
        GY_OK);
    ASSERT_EQ(blen, sizeof(pt));
    ASSERT_TRUE(memcmp(back, pt, sizeof(pt)) == 0, "responder recovered pt");
    gy_sim_free(&sim);
}

TEST(established_encrypt_roundtrip)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    uint8_t msg[4096], msg2[4096], back[512];
    size_t mlen = sizeof(msg), m2 = sizeof(msg2), blen = sizeof(back);
    uint8_t pt1[3] = "one", pt2[3] = "two";

    ctx_fresh(&ik, NULL, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt1, sizeof(pt1),
                               NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);
    ASSERT_EQ(
        gy_sim_bob_recv_initial(&sim, msg, mlen, back, sizeof(back), &blen),
        GY_OK);

    /* A second message on the now-established session; Bob's ratchet reads it. */
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_encrypt(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                              sizeof(BOB_DID), pt2, sizeof(pt2), msg2, &m2),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);

    blen = sizeof(back);
    ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, back, sizeof(back), &blen, msg2, m2,
                            sim.ad, sim.adl),
              GY_OK);
    ASSERT_EQ(blen, sizeof(pt2));
    ASSERT_TRUE(memcmp(back, pt2, sizeof(pt2)) == 0, "peer read 2nd message");
    gy_sim_free(&sim);
}

TEST(commit_only_on_accept)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    uint8_t msg[4096];
    size_t mlen = sizeof(msg);
    uint8_t pt[2] = "hi";

    ctx_fresh(&ik, NULL, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    /* Abort discards the staged fan-out: the store stays empty. */
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, msg, &mlen),
              GY_OK);
    gy_send_abort(&g_ctx);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 0);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 0);

    /* A committed run persists. */
    mlen = sizeof(msg);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 1);
    gy_sim_free(&sim);
}

TEST(prepare_markers_and_self_exclusion)
{
    struct gy_keypair ik;
    struct gy_public_key peer_ik;
    struct gy_keypair peer;
    struct gy_send_target tgt;
    struct gy_send_desc descs[4];
    size_t count = 0;

    ctx_fresh(&ik, NULL, NULL, 0);

    /* A known device with no session: conditional-update it into the store. */
    ASSERT_EQ(gy_keypair_generate(D, &peer), GY_OK);
    peer_ik = peer.pub;
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_conditional_update(&g_ctx.op, D->suite_id, BOB_UID,
                                    sizeof(BOB_UID), BOB_DID, sizeof(BOB_DID),
                                    &peer_ik, NULL),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);

    tgt.user_id = BOB_UID;
    tgt.user_id_len = sizeof(BOB_UID);

    /* No session yet -> NEEDS_BUNDLE. */
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    count = 4;
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, descs, &count), GY_OK);
    ASSERT_EQ(count, 1u);
    ASSERT_EQ(descs[0].status, GY_SEND_NEEDS_BUNDLE);
    ASSERT_TRUE(memcmp(descs[0].device_id, BOB_DID, sizeof(BOB_DID)) == 0,
                "device surfaced");
    gy_send_abort(&g_ctx);

    /* Size query on the count: descs == NULL reports the needed count. */
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    count = 0;
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, NULL, &count), GY_OK);
    ASSERT_EQ(count, 1u);
    gy_send_abort(&g_ctx);

    /*
     * With that (UserID, DeviceID) pair marked as our own sending device, it
     * is excluded.  Self-exclusion is by the pair (D-SES-12): the sender's own
     * user is BOB_UID and its own device is BOB_DID here.
     */
    ASSERT_EQ(gy_send_ctx_init(&g_ctx, &g_store, D, &ik,
                               GY_AEAD_CHACHA20POLY1305, NULL, BOB_UID,
                               sizeof(BOB_UID), BOB_DID, sizeof(BOB_DID)),
              GY_OK);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    count = 4;
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, descs, &count), GY_OK);
    ASSERT_EQ(count, 0u);
    gy_send_abort(&g_ctx);
}

/*
 * D-SES-12: a peer whose DeviceID string equals the sender's own
 * self_device_id, but under a DIFFERENT UserID, must NOT be swallowed by
 * self-exclusion; only the sender's own (UserID, DeviceID) pair is excluded.
 */
TEST(fanout_same_did_different_user)
{
    struct gy_keypair ik;
    struct gy_public_key peer_ik, self_ik;
    struct gy_keypair peer, selfdev;
    struct gy_send_target tgt;
    struct gy_send_desc descs[4];
    size_t count = 0;

    mock_reset(&g_mock, &g_store);
    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    /* Self device is (SELF_UID, BOB_DID): same DeviceID string as the peer. */
    ASSERT_EQ(gy_send_ctx_init(&g_ctx, &g_store, D, &ik,
                               GY_AEAD_CHACHA20POLY1305, NULL, SELF_UID,
                               sizeof(SELF_UID), BOB_DID, sizeof(BOB_DID)),
              GY_OK);

    /* Seed the peer (BOB_UID, BOB_DID) and the sender's own (SELF_UID, BOB_DID). */
    ASSERT_EQ(gy_keypair_generate(D, &peer), GY_OK);
    peer_ik = peer.pub;
    ASSERT_EQ(gy_keypair_generate(D, &selfdev), GY_OK);
    self_ik = selfdev.pub;
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_conditional_update(&g_ctx.op, D->suite_id, BOB_UID,
                                    sizeof(BOB_UID), BOB_DID, sizeof(BOB_DID),
                                    &peer_ik, NULL),
              GY_OK);
    ASSERT_EQ(gy_conditional_update(&g_ctx.op, D->suite_id, SELF_UID,
                                    sizeof(SELF_UID), BOB_DID, sizeof(BOB_DID),
                                    &self_ik, NULL),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);
    /* Two distinct DeviceRecords despite the shared DeviceID string. */
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 2);

    /* Fan-out to Bob: the peer surfaces (NEEDS_BUNDLE), it is NOT self. */
    tgt.user_id = BOB_UID;
    tgt.user_id_len = sizeof(BOB_UID);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    count = 4;
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, descs, &count), GY_OK);
    ASSERT_EQ(count, 1u);
    ASSERT_EQ(descs[0].status, GY_SEND_NEEDS_BUNDLE);
    ASSERT_TRUE(memcmp(descs[0].device_id, BOB_DID, sizeof(BOB_DID)) == 0,
                "peer device surfaced");
    gy_send_abort(&g_ctx);

    /* Fan-out to our own user: the own (SELF_UID, BOB_DID) pair IS excluded. */
    tgt.user_id = SELF_UID;
    tgt.user_id_len = sizeof(SELF_UID);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    count = 4;
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, descs, &count), GY_OK);
    ASSERT_EQ(count, 0u);
    gy_send_abort(&g_ctx);
}

TEST(stale_not_sent)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    struct gy_expiry_cfg expiry;
    struct gy_send_target tgt;
    struct gy_send_desc descs[2];
    uint8_t msg[4096], msg2[4096];
    size_t mlen = sizeof(msg), m2 = sizeof(msg2), count = 2;
    uint8_t pt[2] = "hi";

    /* max_send = 1: the first message already puts nsend at the bound. */
    ASSERT_EQ(gy_expiry_cfg_init(&expiry, 1, 10, 1), GY_OK);
    ctx_fresh(&ik, &expiry, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);

    /* prepare now marks the device STALE and encrypt refuses. */
    tgt.user_id = BOB_UID;
    tgt.user_id_len = sizeof(BOB_UID);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_prepare(&g_ctx, &tgt, 1, descs, &count), GY_OK);
    ASSERT_EQ(count, 1u);
    ASSERT_EQ(descs[0].status, GY_SEND_STALE);
    ASSERT_EQ(gy_send_encrypt(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                              sizeof(BOB_DID), pt, sizeof(pt), msg2, &m2),
              GY_ERR_EXPIRED);
    gy_send_abort(&g_ctx);
    gy_sim_free(&sim);
}

TEST(reinitiate_demotes)
{
    struct gy_keypair ik;
    struct gy_sim sim;
    struct gy_device_record dev;
    uint8_t msg[4096];
    size_t mlen = sizeof(msg);
    uint8_t first_active[GY_SESSION_ID_LEN];
    uint8_t pt[2] = "hi";

    ctx_fresh(&ik, NULL, NULL, 0);
    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &sim.bundle, pt, sizeof(pt),
                               NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);
    load_bob_device(&dev);
    memcpy(first_active, dev.active, GY_SESSION_ID_LEN);

    /* Re-initiate: a fresh session becomes active, the first is demoted. */
    mlen = sizeof(msg);
    ASSERT_EQ(gy_send_begin(&g_ctx), GY_OK);
    ASSERT_EQ(gy_session_reinitiate(&g_ctx, BOB_UID, sizeof(BOB_UID), BOB_DID,
                                    sizeof(BOB_DID), &sim.bundle, pt,
                                    sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_ctx), GY_OK);

    load_bob_device(&dev);
    ASSERT_EQ(dev.n_inactive, 1u);
    ASSERT_TRUE(memcmp(dev.inactive[0], first_active, GY_SESSION_ID_LEN) == 0,
                "first session demoted to inactive head");
    ASSERT_TRUE(memcmp(dev.active, first_active, GY_SESSION_ID_LEN) != 0,
                "a fresh session is active");
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 2);
    gy_sim_free(&sim);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_C25519);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(size_query),
            GY_TEST(initiate_roundtrip),
            GY_TEST(established_encrypt_roundtrip),
            GY_TEST(commit_only_on_accept),
            GY_TEST(prepare_markers_and_self_exclusion),
            GY_TEST(fanout_same_did_different_user),
            GY_TEST(stale_not_sent),
            GY_TEST(reinitiate_demotes),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
