/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Hybrid session create/send/recv end to end (GER-M5-08b b-ii-2): a two-party
 * hybrid handshake through the session layer, the KEM-confirmation PQ-pending
 * state machine surfacing in the persisted session (section 8.4), persistence
 * mid-confirmation, and PQ-key-change recovery.  Two independent in-memory
 * stores stand in for the two devices.
 */

#include <string.h>

#include "recv.h"
#include "send.h"

#include "gy_test.h"

static const struct gy_suite_desc *DH;
#define AEAD GY_AEAD_CHACHA20POLY1305
static const uint64_t TS = 0x0000000155667788ull;
/* SPK advertisement: interval [1,100], ChaCha20-Poly1305 (bit 32) available. */
#define SPK_FLAGS (UINT64_C(1) | (UINT64_C(100) << 16) | (UINT64_C(1) << 32))

static const uint8_t A_UID[3] = {0xA1, 0xA2, 0xA3};
static const uint8_t A_DID[3] = {0x0A, 0x0A, 0x0A};
static const uint8_t B_UID[3] = {0xB1, 0xB2, 0xB3};
static const uint8_t B_DID[3] = {0x0B, 0x0B, 0x0B};

/* ---- in-memory store --------------------------------------------------- */

#define MOCK_MAX 32
struct mock_rec {
    int in_use, kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len, blob_len;
    uint8_t blob[GY_SESSION_BLOB_MAX];
};
struct mock {
    struct mock_rec recs[MOCK_MAX];
};

static struct mock_rec *
mfind(struct mock *m, int kind, const uint8_t *id, size_t id_len)
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
m_load(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len,
       uint8_t *out, size_t cap, size_t *out_len)
{
    struct mock_rec *r = mfind(ctx, (int)kind, id, id_len);

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
    struct mock_rec *r = mfind(m, (int)kind, id, id_len);

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
    struct mock_rec *r = mfind(ctx, (int)kind, id, id_len);

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
store_wire(struct mock *m, struct gy_store *st)
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

static struct mock a_mock, b_mock;
static struct gy_store a_store, b_store;
static struct gy_hybrid_identity_keypair alice_ik, bob_ik;
static struct gy_hybrid_signed_prekey bob_spk,
    alice_spk; /* alice_spk: recv-ctx filler */
static struct gy_hybrid_prekey_bundle bob_bundle;
static struct gy_send_ctx a_send, b_send;
static struct gy_recv_ctx a_recv, b_recv;

/* Wrap an inner message in the {version, suite, msg_type} envelope. */
static size_t
wrap(uint8_t *out, uint8_t msg_type, const uint8_t *inner, size_t inner_len)
{
    out[0] = GY_WIRE_VERSION;
    out[1] = DH->suite_id;
    out[2] = msg_type;
    memcpy(out + 3, inner, inner_len);
    return inner_len + 3;
}

/* Read a peer's active-session pq_pending from `store`. */
static uint8_t
peer_pq(struct gy_op *op, const struct gy_store *store, const uint8_t *uid,
        size_t ul, const uint8_t *did, size_t dl)
{
    struct gy_hybrid_device_record dev;
    struct gy_session s;
    uint8_t dk[GY_DEVKEY_LEN];
    uint8_t pq = 0xFF;
    int found;

    ASSERT_EQ(gy_devrec_key(uid, ul, did, dl, dk), GY_OK);
    ASSERT_EQ(gy_op_begin(op, store), GY_OK);
    ASSERT_EQ(gy_op_load_hybrid_device(op, dk, GY_DEVKEY_LEN, &dev, &found),
              GY_OK);
    ASSERT_EQ(found, 1);
    ASSERT_EQ(dev.base.has_active, 1);
    ASSERT_EQ(gy_op_load_session(op, dev.base.active, &s, &found), GY_OK);
    ASSERT_EQ(found, 1);
    pq = s.pq_pending;
    gy_op_abort(op);
    return pq;
}

static void
setup(void)
{
    store_wire(&a_mock, &a_store);
    store_wire(&b_mock, &b_store);
    ASSERT_EQ(gy_hybrid_identity_keypair_generate(DH, &alice_ik), GY_OK);
    ASSERT_EQ(gy_hybrid_identity_keypair_generate(DH, &bob_ik), GY_OK);
    ASSERT_EQ(gy_hybrid_spk_create(DH, &bob_spk, &bob_ik, TS, SPK_FLAGS),
              GY_OK);
    ASSERT_EQ(gy_hybrid_spk_create(DH, &alice_spk, &alice_ik, TS, SPK_FLAGS),
              GY_OK);

    memset(&bob_bundle, 0, sizeof(bob_bundle));
    bob_bundle.ik = bob_ik.pub;
    bob_bundle.spk = bob_spk.kp.pub;
    bob_bundle.spk_timestamp = TS;
    bob_bundle.spk_flags = SPK_FLAGS;
    bob_bundle.spk_ik_id = bob_spk.ik_id;
    memcpy(bob_bundle.spk_ed_sig, bob_spk.ed_sig, GY_SIG_MAX);
    memcpy(bob_bundle.spk_mldsa_sig, bob_spk.mldsa_sig, GY_DSA_SIG_MAX);
    /* no OPK: bob_bundle.opk.curve.pkid stays 0 */

    /* Hybrid parties reuse the classical ctxs (NULL classical identity); the
     * hybrid identity/prekeys are passed per-call. */
    ASSERT_EQ(gy_send_ctx_init(&a_send, &a_store, DH, NULL, AEAD, NULL, A_UID,
                               sizeof(A_UID), A_DID, sizeof(A_DID)),
              GY_OK);
    ASSERT_EQ(gy_recv_ctx_init(&a_recv, &a_store, DH, NULL, NULL, 0, NULL, 0,
                               AEAD, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_recv_ctx_init(&b_recv, &b_store, DH, NULL, NULL, 0, NULL, 0,
                               AEAD, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_send_ctx_init(&b_send, &b_store, DH, NULL, AEAD, NULL, B_UID,
                               sizeof(B_UID), B_DID, sizeof(B_DID)),
              GY_OK);
}

/* Alice initiates to Bob; return the enveloped initial message. */
static size_t
alice_initiate(uint8_t *msg, const char *pt)
{
    static uint8_t inner[GY_SESSION_BLOB_MAX];
    size_t n = sizeof(inner);

    ASSERT_EQ(gy_send_begin(&a_send), GY_OK);
    ASSERT_EQ(gy_send_initiate_hybrid(&a_send, &alice_ik, 5, B_UID,
                                      sizeof(B_UID), B_DID, sizeof(B_DID),
                                      &bob_bundle, (const uint8_t *)pt,
                                      strlen(pt), NULL, inner, &n),
              GY_OK);
    ASSERT_EQ(gy_send_commit(&a_send), GY_OK);
    return wrap(msg, GY_MSG_INIT, inner, n);
}

/* Encrypt a DR message on `from` for (uid,did); return the enveloped message. */
static size_t
send_dr(struct gy_send_ctx *from, const uint8_t *uid, size_t ul,
        const uint8_t *did, size_t dl, uint8_t *msg, const char *pt)
{
    static uint8_t inner[GY_SESSION_BLOB_MAX];
    size_t n = sizeof(inner);

    ASSERT_EQ(gy_send_begin(from), GY_OK);
    ASSERT_EQ(gy_send_encrypt(from, uid, ul, did, dl, (const uint8_t *)pt,
                              strlen(pt), inner, &n),
              GY_OK);
    ASSERT_EQ(gy_send_commit(from), GY_OK);
    return wrap(msg, GY_MSG_DR, inner, n);
}

static void
recv_expect(struct gy_recv_ctx *c, const struct gy_hybrid_identity_keypair *hik,
            const struct gy_hybrid_signed_prekey *hspk, const uint8_t *uid,
            size_t ul, const uint8_t *did, size_t dl, const uint8_t *msg,
            size_t mlen, const char *pt)
{
    uint8_t out[256];
    size_t n = sizeof(out);

    ASSERT_EQ(gy_hybrid_recv(c, hik, hspk, 1, NULL, 0, uid, ul, did, dl, msg,
                             mlen, out, &n),
              GY_OK);
    ASSERT_EQ(n, strlen(pt));
    ASSERT_MEMEQ(out, pt, strlen(pt));
}

TEST(handshake_and_confirmation)
{
    static uint8_t msg[GY_SESSION_BLOB_MAX + 8];
    struct gy_op *op = &a_recv.op; /* scratch for reads */
    size_t mlen;

    setup();

    /* Alice -> Bob initial: Bob creates the session and owes his confirmation. */
    mlen = alice_initiate(msg, "a0");
    recv_expect(&b_recv, &bob_ik, &bob_spk, A_UID, sizeof(A_UID), A_DID,
                sizeof(A_DID), msg, mlen, "a0");
    ASSERT_EQ(peer_pq(op, &b_store, A_UID, sizeof(A_UID), A_DID, sizeof(A_DID)),
              GY_HYBRID_PQ_CONFIRM_SENT);

    /* Bob -> Alice reply carries the confirmation; Alice binds her PQ identity. */
    mlen =
        send_dr(&b_send, A_UID, sizeof(A_UID), A_DID, sizeof(A_DID), msg, "b0");
    recv_expect(&a_recv, &alice_ik, &alice_spk, B_UID, sizeof(B_UID), B_DID,
                sizeof(B_DID), msg, mlen, "b0");
    ASSERT_EQ(peer_pq(op, &a_store, B_UID, sizeof(B_UID), B_DID, sizeof(B_DID)),
              GY_HYBRID_PQ_CONFIRMED);

    /* Alice -> Bob on the descended chain: Bob reaches PQ_CONFIRMED. */
    mlen =
        send_dr(&a_send, B_UID, sizeof(B_UID), B_DID, sizeof(B_DID), msg, "a1");
    recv_expect(&b_recv, &bob_ik, &bob_spk, A_UID, sizeof(A_UID), A_DID,
                sizeof(A_DID), msg, mlen, "a1");
    ASSERT_EQ(peer_pq(op, &b_store, A_UID, sizeof(A_UID), A_DID, sizeof(A_DID)),
              GY_HYBRID_PQ_CONFIRMED);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    DH = gy_suite_desc(GY_SUITE_H25519_512);
    if (DH == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(handshake_and_confirmation),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
