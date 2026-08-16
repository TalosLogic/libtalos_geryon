/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * receive path: initiation and established-session round-trips
 * (geryon send -> geryon recv), base-key dedupe of a re-sent initial (D-SES-6.1,
 * one session / one plaintext / no double OPK burn), inactive-session
 * association with activation and the D-SES-6 session-order count, and the
 * uniform-failure rule (D-SES-6.2: garbage and a tampered frame yield the same
 * error, store untouched).  Alice is the send path; Bob is the receive path;
 * both run on their own persistent in-memory store.
 */

#include <string.h>

#include "recv.h"
#include "send.h"

#include "gy_sim.h"
#include "gy_test.h"

static const struct gy_suite_desc *D;

/* ---- persistent in-memory mock store ----------------------------------- */

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
    int n_consumed;
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
    struct mock *m = ctx;

    (void)pkid;
    m->n_consumed++;
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

static struct mock g_smock, g_rmock; /* Alice (send), Bob (recv) stores */
static struct gy_store g_sstore, g_rstore;
static struct gy_send_ctx g_send;
static struct gy_recv_ctx g_recv;
static struct gy_sim g_sim; /* source of Bob's identity/prekeys + bundle */

/* Alice's identity as Bob records it; Bob's device as Alice targets it. */
static const uint8_t ALICE_UID[4] = {0xA1, 0xA2, 0xA3, 0xA4};
static const uint8_t ALICE_DID[4] = {0xAD, 0xAE, 0xAF, 0xB0};
static const uint8_t BOB_UID[4] = {0xB1, 0xB2, 0xB3, 0xB4};
static const uint8_t BOB_DID[4] = {0xBD, 0xBE, 0xBF, 0xC0};

static void
setup_pair(struct gy_keypair *alice_ik)
{
    mock_reset(&g_smock, &g_sstore);
    mock_reset(&g_rmock, &g_rstore);
    ASSERT_EQ(gy_sim_setup(&g_sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, alice_ik), GY_OK);
    ASSERT_EQ(gy_send_ctx_init(&g_send, &g_sstore, D, alice_ik,
                               GY_AEAD_CHACHA20POLY1305, NULL, NULL, 0, NULL,
                               0),
              GY_OK);
    ASSERT_EQ(gy_recv_ctx_init(&g_recv, &g_rstore, D, &g_sim.bob_ik,
                               &g_sim.bob_spk.kp, 1, g_sim.opk_stock,
                               g_sim.opk_count, GY_AEAD_CHACHA20POLY1305, NULL,
                               NULL, NULL),
              GY_OK);
}

static size_t
wrap(uint8_t *env, uint8_t type, const uint8_t *inner, size_t inner_len)
{
    env[0] = GY_WIRE_VERSION;
    env[1] = D->suite_id;
    env[2] = type;
    memcpy(env + 3, inner, inner_len);
    return inner_len + 3;
}

/* Alice initiates to Bob; returns the enveloped initial message length. */
static size_t
alice_initiate(const uint8_t *pt, size_t ptlen, uint8_t *env)
{
    uint8_t inner[4096];
    size_t ilen = sizeof(inner);

    ASSERT_EQ(gy_send_begin(&g_send), GY_OK);
    ASSERT_EQ(gy_send_initiate(&g_send, BOB_UID, sizeof(BOB_UID), BOB_DID,
                               sizeof(BOB_DID), &g_sim.bundle, pt, ptlen, NULL,
                               inner, &ilen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_send), GY_OK);
    return wrap(env, GY_MSG_INIT, inner, ilen);
}

static size_t
alice_reinitiate(const uint8_t *pt, size_t ptlen, uint8_t *env)
{
    uint8_t inner[4096];
    size_t ilen = sizeof(inner);

    ASSERT_EQ(gy_send_begin(&g_send), GY_OK);
    ASSERT_EQ(gy_session_reinitiate(&g_send, BOB_UID, sizeof(BOB_UID), BOB_DID,
                                    sizeof(BOB_DID), &g_sim.bundle, pt, ptlen,
                                    NULL, inner, &ilen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_send), GY_OK);
    return wrap(env, GY_MSG_INIT, inner, ilen);
}

static size_t
alice_encrypt(const uint8_t *pt, size_t ptlen, uint8_t *env)
{
    uint8_t inner[4096];
    size_t ilen = sizeof(inner);

    ASSERT_EQ(gy_send_begin(&g_send), GY_OK);
    ASSERT_EQ(gy_send_encrypt(&g_send, BOB_UID, sizeof(BOB_UID), BOB_DID,
                              sizeof(BOB_DID), pt, ptlen, inner, &ilen),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&g_send), GY_OK);
    return wrap(env, GY_MSG_DR, inner, ilen);
}

static int
bob_recv(const uint8_t *env, size_t elen, uint8_t *out, size_t *olen)
{
    return gy_recv(&g_recv, ALICE_UID, sizeof(ALICE_UID), ALICE_DID,
                   sizeof(ALICE_DID), env, elen, out, olen);
}

static void
load_bob_alice_device(struct gy_device_record *dev)
{
    uint8_t dk[GY_DEVKEY_LEN];
    int found;

    /* D-SES-12: DeviceRecords key on gy_devrec_key over (UserID, DeviceID). */
    ASSERT_EQ(gy_devrec_key(ALICE_UID, sizeof(ALICE_UID), ALICE_DID,
                            sizeof(ALICE_DID), dk),
              GY_OK);
    ASSERT_EQ(gy_op_begin(&g_recv.op, &g_rstore), GY_OK);
    ASSERT_EQ(gy_op_load_device(&g_recv.op, dk, GY_DEVKEY_LEN, dev, &found),
              GY_OK);
    ASSERT_EQ(found, 1);
    gy_op_abort(&g_recv.op);
}

/* ---- tests ------------------------------------------------------------- */

TEST(initiation_recv_roundtrip)
{
    struct gy_keypair ik;
    uint8_t env[4200], out[512];
    size_t elen, olen = sizeof(out);
    uint8_t pt[11] = "first-frame";

    setup_pair(&ik);
    elen = alice_initiate(pt, sizeof(pt), env);

    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_OK);
    ASSERT_EQ(olen, sizeof(pt));
    ASSERT_TRUE(memcmp(out, pt, sizeof(pt)) == 0,
                "recovered initial plaintext");
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_USER), 1);
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_DEVICE), 1);
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_SESSION), 1);
    ASSERT_EQ(g_rmock.n_consumed, 1); /* the OPK burned exactly once */
    gy_sim_free(&g_sim);
}

TEST(established_recv_roundtrip)
{
    struct gy_keypair ik;
    uint8_t env[4200], out[512];
    size_t elen, olen;
    uint8_t pt1[3] = "one", pt2[3] = "two";

    setup_pair(&ik);
    elen = alice_initiate(pt1, sizeof(pt1), env);
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_OK);

    elen = alice_encrypt(pt2, sizeof(pt2), env);
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_OK);
    ASSERT_EQ(olen, sizeof(pt2));
    ASSERT_TRUE(memcmp(out, pt2, sizeof(pt2)) == 0, "recovered 2nd plaintext");
    ASSERT_EQ(g_recv.last_sessions_tried, 1u); /* active session owns it */
    gy_sim_free(&g_sim);
}

TEST(inactive_association_and_activation)
{
    struct gy_keypair ik;
    struct gy_device_record dev;
    uint8_t env_a[4200], env_dr[4200], env_b[4200], out[512];
    size_t ela, eldr, elb, olen;
    uint8_t sid_a[GY_SESSION_ID_LEN];
    uint8_t pt[4] = "msg", pt0[2] = "x";

    setup_pair(&ik);

    /* Session A: initiate + one DR message (captured, sent later). */
    ela = alice_initiate(pt0, sizeof(pt0), env_a);
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env_a, ela, out, &olen), GY_OK);
    load_bob_alice_device(&dev);
    memcpy(sid_a, dev.active, GY_SESSION_ID_LEN);
    eldr = alice_encrypt(pt, sizeof(pt), env_dr);

    /* Session B: re-initiate. Bob makes B active and demotes A to inactive. */
    elb = alice_reinitiate(pt0, sizeof(pt0), env_b);
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env_b, elb, out, &olen), GY_OK);
    load_bob_alice_device(&dev);
    ASSERT_EQ(dev.n_inactive, 1u);
    ASSERT_TRUE(memcmp(dev.inactive[0], sid_a, GY_SESSION_ID_LEN) == 0,
                "A demoted to inactive");

    /* The held DR message decrypts on inactive A and re-activates it. */
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env_dr, eldr, out, &olen), GY_OK);
    ASSERT_EQ(olen, sizeof(pt));
    ASSERT_TRUE(memcmp(out, pt, sizeof(pt)) == 0, "inactive session decrypted");
    ASSERT_EQ(g_recv.last_sessions_tried,
              2u); /* active B miss, inactive A hit */
    load_bob_alice_device(&dev);
    ASSERT_TRUE(memcmp(dev.active, sid_a, GY_SESSION_ID_LEN) == 0,
                "A re-activated (D-SES-5)");
    gy_sim_free(&g_sim);
}

TEST(dedupe_resend)
{
    struct gy_keypair ik;
    uint8_t env[4200], out[512];
    size_t elen, olen;
    uint8_t pt[5] = "hello";

    setup_pair(&ik);
    elen = alice_initiate(pt, sizeof(pt), env);

    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_OK);
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_SESSION), 1);
    ASSERT_EQ(g_rmock.n_consumed, 1);

    /* The identical initial re-sent: dedupe routes to the live session, where
     * the already-consumed first frame no longer decrypts.  No new session, no
     * second OPK burn (D-SES-6.1 / D-X3DH-10). */
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_ERR_VERIFY);
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_SESSION), 1);
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_DEVICE), 1);
    ASSERT_EQ(g_rmock.n_consumed, 1);
    gy_sim_free(&g_sim);
}

TEST(uniform_failure)
{
    struct gy_keypair ik;
    uint8_t env[4200], junk[64], out[512];
    size_t elen, jlen, olen;
    int sessions_before;
    uint8_t pt[3] = "abc";

    setup_pair(&ik);
    elen = alice_initiate(pt, sizeof(pt), env);
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_OK);
    sessions_before = mock_count(&g_rmock, GY_REC_SESSION);

    /* Garbage DR frame (valid envelope, junk body): nothing associates. */
    memset(junk, 0x5a, sizeof(junk));
    junk[0] = GY_WIRE_VERSION;
    junk[1] = D->suite_id;
    jlen = wrap(env, GY_MSG_DR, junk, sizeof(junk));
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, jlen, out, &olen), GY_ERR_VERIFY);

    /* A real DR frame with one payload byte flipped: same uniform error. */
    elen = alice_encrypt(pt, sizeof(pt), env);
    env[elen - 1] ^= 0x01;
    olen = sizeof(out);
    ASSERT_EQ(bob_recv(env, elen, out, &olen), GY_ERR_VERIFY);

    /* Store untouched by either rejected message. */
    ASSERT_EQ(mock_count(&g_rmock, GY_REC_SESSION), sessions_before);
    ASSERT_EQ(g_rmock.n_consumed, 1);
    gy_sim_free(&g_sim);
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
            GY_TEST(initiation_recv_roundtrip),
            GY_TEST(established_recv_roundtrip),
            GY_TEST(inactive_association_and_activation),
            GY_TEST(dedupe_resend),
            GY_TEST(uniform_failure),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
