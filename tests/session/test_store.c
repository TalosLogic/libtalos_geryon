/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * staging engine: commit order (D-SES-10 phase one records, phase
 * two deferred), fault injection (a failing callback stops the commit and
 * zeroizes the stage; a pre-commit load failure leaves the store untouched),
 * the debug re-entrancy guard (D-GEN-8), and the no-allocation footprint.
 */

#include <string.h>

#include "store.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;

/* ---- instrumented in-memory mock store --------------------------------- */

#define MOCK_MAX 16

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
    /* Write-callback instrumentation. */
    int n_writes;      /* store/delete/consume invocations so far */
    int fail_at;       /* invocation index to fail (-1 = never) */
    char log[64];      /* one char per write callback: s / d / c */
    int fail_load;     /* if 1, load_record returns an error */
    uint32_t consumed; /* last consumed OPK pkid */
    int n_consumed;
    struct gy_op *op; /* for the re-entrancy-guard check */
    int guard_fail;   /* set if op->active was not armed in a callback */
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

static void
guard_check(struct mock *m)
{
#ifndef NDEBUG
    if (m->op != NULL && m->op->active != 1)
        m->guard_fail = 1;
#else
    (void)m;
#endif
}

static int
m_load(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len,
       uint8_t *out, size_t cap, size_t *out_len)
{
    struct mock *m = ctx;
    struct mock_rec *r;

    guard_check(m);
    if (m->fail_load)
        return GY_ERR_CRYPTO;
    r = mock_find(m, (int)kind, id, id_len);
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
m_write_gate(struct mock *m, char tag)
{
    m->log[m->n_writes] = tag;
    if (m->n_writes == m->fail_at) {
        m->n_writes++;
        return GY_ERR_CRYPTO;
    }
    m->n_writes++;
    return GY_OK;
}

static int
m_store(void *ctx, enum gy_rec_kind kind, const uint8_t *id, size_t id_len,
        const uint8_t *blob, size_t blob_len)
{
    struct mock *m = ctx;
    struct mock_rec *r;
    int rc;

    guard_check(m);
    rc = m_write_gate(m, 's');
    if (rc != GY_OK)
        return rc;
    r = mock_find(m, (int)kind, id, id_len);
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
    struct mock_rec *r;
    int rc;

    guard_check(m);
    rc = m_write_gate(m, 'd');
    if (rc != GY_OK)
        return rc;
    r = mock_find(m, (int)kind, id, id_len);
    if (r != NULL)
        r->in_use = 0;
    return GY_OK;
}

static int
m_consume(void *ctx, uint32_t pkid)
{
    struct mock *m = ctx;
    int rc;

    guard_check(m);
    rc = m_write_gate(m, 'c');
    if (rc != GY_OK)
        return rc;
    m->consumed = pkid;
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
mock_reset(struct mock *m, struct gy_store *st, struct gy_op *op)
{
    memset(m, 0, sizeof(*m));
    m->fail_at = -1;
    m->op = op;

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
static struct gy_op g_op; /* ~3 MB; kept out of the stack */

static void
build_user(struct gy_user_record *u, uint32_t tag)
{
    uint8_t uid[4];

    gy_be32_put(uid, tag);
    ASSERT_EQ(gy_user_record_init(u, D->suite_id, uid, sizeof(uid)), GY_OK);
}

static void
build_device(struct gy_device_record *d, uint32_t tag)
{
    struct gy_keypair ik;
    uint8_t fp[GY_HASH_MAX];
    uint8_t did[4];

    gy_be32_put(did, tag);
    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_fingerprint(D, fp, &ik.pub), GY_OK);
    ASSERT_EQ(gy_device_record_init(d, D->suite_id, did, sizeof(did), &ik.pub,
                                    fp, D->hash_len),
              GY_OK);
}

/*
 * D-SES-12: DeviceRecords are keyed by gy_devrec_key over the (UserID,
 * DeviceID) pair.  These plumbing tests bind every device under one fixed
 * test UserID; the key just has to be derived consistently for put/delete.
 */
static const uint8_t g_test_uid[4] = {0, 0, 0, 42};

static void
dev_key(const struct gy_device_record *d, uint8_t out[GY_DEVKEY_LEN])
{
    ASSERT_EQ(gy_devrec_key(g_test_uid, sizeof(g_test_uid), d->device_id,
                            d->device_id_len, out),
              GY_OK);
}

static void
build_session(struct gy_session *s, uint32_t tag)
{
    struct gy_keypair ik, ek;

    memset(s, 0, sizeof(*s));
    s->ratchet.base.desc = D;
    s->ratchet.base.aead_id = GY_AEAD_CHACHA20POLY1305;
    ASSERT_EQ(gy_keypair_generate(D, &s->ratchet.base.dhs), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_session_id(s, D, &ik.pub, &ek.pub), GY_OK);
    /* Perturb the id so distinct tags do not alias in the mock. */
    gy_be32_put(s->id, tag);
}

/* ---- tests ------------------------------------------------------------- */

TEST(commit_order_and_persist)
{
    struct gy_user_record u;
    struct gy_device_record d;
    struct gy_session s, back;
    uint8_t sid[GY_SESSION_ID_LEN];
    uint8_t dk[GY_DEVKEY_LEN];
    int found;

    mock_reset(&g_mock, &g_store, &g_op);
    build_user(&u, 1);
    build_device(&d, 2);
    build_session(&s, 3);
    dev_key(&d, dk);

    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_put_user(&g_op, &u), GY_OK);
    ASSERT_EQ(gy_op_put_device(&g_op, &d, dk, GY_DEVKEY_LEN), GY_OK);
    ASSERT_EQ(gy_op_put_session(&g_op, &s), GY_OK);
    ASSERT_EQ(gy_op_delete(&g_op, GY_REC_DEVICE, dk, GY_DEVKEY_LEN), GY_OK);
    ASSERT_EQ(gy_op_consume_opk(&g_op, 0x11223344), GY_OK);
    ASSERT_EQ(gy_op_commit(&g_op), GY_OK);

    /* Phase one (three stores) precedes phase two (delete, consume). */
    ASSERT_TRUE(strncmp(g_mock.log, "sssdc", 5) == 0, "records then deferred");
    ASSERT_EQ(g_mock.n_writes, 5);
    ASSERT_EQ(g_mock.n_consumed, 1);
    ASSERT_TRUE(g_mock.consumed == 0x11223344, "opk consumed value");
    ASSERT_EQ(g_mock.guard_fail, 0);

    /* The session persisted and round-trips back through a load. */
    memcpy(sid, s.id, GY_SESSION_ID_LEN);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_session(&g_op, sid, &back, &found), GY_OK);
    ASSERT_EQ(found, 1);
    ASSERT_TRUE(memcmp(&s, &back, sizeof(s)) == 0, "session persisted exact");

    /* Staging is zeroized after a successful commit. */
    gy_op_abort(&g_op);
}

TEST(commit_stops_at_failure)
{
    struct gy_user_record u;
    struct gy_device_record d;
    struct gy_session s;
    uint8_t dk[GY_DEVKEY_LEN];

    mock_reset(&g_mock, &g_store, &g_op);
    build_user(&u, 1);
    build_device(&d, 2);
    build_session(&s, 3);
    dev_key(&d, dk);

    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_put_user(&g_op, &u), GY_OK);
    ASSERT_EQ(gy_op_put_device(&g_op, &d, dk, GY_DEVKEY_LEN), GY_OK);
    ASSERT_EQ(gy_op_put_session(&g_op, &s), GY_OK);
    ASSERT_EQ(gy_op_consume_opk(&g_op, 7), GY_OK);

    /* Fail the second store: the third store and the consume must not run. */
    g_mock.fail_at = 1;
    ASSERT_EQ(gy_op_commit(&g_op), GY_ERR_CRYPTO);
    ASSERT_EQ(g_mock.n_writes, 2); /* one success, one failure, then stop */
    ASSERT_EQ(g_mock.n_consumed, 0);
    ASSERT_EQ(g_mock.guard_fail, 0);
}

TEST(precommit_load_failure_untouched)
{
    struct gy_user_record u, back;
    uint8_t uid[4];
    int found;

    mock_reset(&g_mock, &g_store, &g_op);
    /* Seed one committed record so we can prove the store is untouched. */
    build_user(&u, 1);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_put_user(&g_op, &u), GY_OK);
    ASSERT_EQ(gy_op_commit(&g_op), GY_OK);
    ASSERT_EQ(g_mock.n_writes, 1);

    /* A load failure aborts before any write callback fires. */
    g_mock.fail_load = 1;
    gy_be32_put(uid, 1);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_user(&g_op, uid, sizeof(uid), &back, &found),
              GY_ERR_CRYPTO);
    gy_op_abort(&g_op);
    ASSERT_EQ(g_mock.n_writes, 1); /* no new write callbacks */

    /* And the seeded record is still there and intact. */
    g_mock.fail_load = 0;
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_user(&g_op, uid, sizeof(uid), &back, &found), GY_OK);
    ASSERT_EQ(found, 1);
    ASSERT_TRUE(memcmp(&u, &back, sizeof(u)) == 0, "seeded record intact");
    gy_op_abort(&g_op);
}

TEST(staging_full_rejected)
{
    struct gy_session s;
    int i, rc = GY_OK;

    mock_reset(&g_mock, &g_store, &g_op);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    /* One past the session staging capacity must be rejected, not overrun. */
    for (i = 0; i < GY_OP_MAX_SESSIONS + 1; i++) {
        build_session(&s, (uint32_t)(1000 + i));
        rc = gy_op_put_session(&g_op, &s);
        if (rc != GY_OK)
            break;
    }
    ASSERT_EQ(rc, GY_ERR_STATE);
    ASSERT_EQ(i, GY_OP_MAX_SESSIONS);
    gy_op_abort(&g_op);
}

TEST(no_dynamic_allocation_footprint)
{
    /* The staging arena is part of the struct (D-SES-10), so its footprint is
     * fixed and bounded; the _Static_assert in store.h ties the session slot
     * count to the D-SES-4 fan-out. Document the ceiling here too. */
    ASSERT_TRUE(sizeof(struct gy_op) < 8u * 1024u * 1024u,
                "op context within an 8 MB fixed ceiling");
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
            GY_TEST(commit_order_and_persist),
            GY_TEST(commit_stops_at_failure),
            GY_TEST(precommit_load_failure_untouched),
            GY_TEST(staging_full_rejected),
            GY_TEST(no_dynamic_allocation_footprint),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
