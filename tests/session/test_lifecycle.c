/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * lifecycle state machine: conditional update with trust-on-first-use
 * and fail-closed key change (D-SES-9 / D-X3DH-11), the section 3.2 accept
 * replacement, insert/activate list-order semantics (D-SES-5), expiration
 * config validation and counter/rollback behavior (D-SES-7), and device/user
 * deletion with zeroization (D-SES-2).  Runs on a persistent in-memory store.
 */

#include <string.h>

#include "lifecycle.h"

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

    if (r != NULL) {
        memset(r, 0, sizeof(*r)); /* zeroize on delete (D-SES-2) */
    }
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

static struct mock g_mock;
static struct gy_store g_store;
static struct gy_op g_op; /* ~3 MB; kept out of the stack */

static const uint8_t UID[4] = {0xAA, 0xBB, 0xCC, 0xDD};
static const uint8_t DID[4] = {0x01, 0x02, 0x03, 0x04};
/* A second user that reuses DID's byte string, for the D-SES-12 tests. */
static const uint8_t UID2[4] = {0x11, 0x22, 0x33, 0x44};

static void
make_ik(struct gy_public_key *ik)
{
    struct gy_keypair kp;

    ASSERT_EQ(gy_keypair_generate(D, &kp), GY_OK);
    *ik = kp.pub;
}

/* Commit whatever the callback staged on g_op; returns the callback's rc. */
#define STAGE_AND_COMMIT(expr)                                                 \
    do {                                                                       \
        ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);                        \
        ASSERT_EQ((expr), GY_OK);                                              \
        ASSERT_EQ(gy_op_commit(&g_op), GY_OK);                                 \
    } while (0)

static void
load_device(struct gy_device_record *d)
{
    uint8_t dk[GY_DEVKEY_LEN];
    int found;

    /* D-SES-12: DeviceRecords key on gy_devrec_key over (UserID, DeviceID). */
    ASSERT_EQ(gy_devrec_key(UID, sizeof(UID), DID, sizeof(DID), dk), GY_OK);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_device(&g_op, dk, GY_DEVKEY_LEN, d, &found), GY_OK);
    ASSERT_EQ(found, 1);
    gy_op_abort(&g_op);
}

/* Load the DeviceRecord for an arbitrary (user_id, device_id); returns found. */
static int
load_pair(const uint8_t *uid, size_t ul, const uint8_t *did, size_t dl,
          struct gy_device_record *d)
{
    uint8_t dk[GY_DEVKEY_LEN];
    int found;

    ASSERT_EQ(gy_devrec_key(uid, ul, did, dl, dk), GY_OK);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_device(&g_op, dk, GY_DEVKEY_LEN, d, &found), GY_OK);
    gy_op_abort(&g_op);
    return found;
}

/* Put a bare SessionRecord under sid so deletion has something to remove. */
static void
seed_session(const uint8_t sid[GY_SESSION_ID_LEN])
{
    struct gy_session s;
    struct gy_keypair ik, ek;

    memset(&s, 0, sizeof(s));
    s.dr.desc = D;
    s.dr.aead_id = GY_AEAD_CHACHA20POLY1305;
    ASSERT_EQ(gy_keypair_generate(D, &s.dr.dhs), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_session_id(&s, D, &ik.pub, &ek.pub), GY_OK);
    memcpy(s.id, sid, GY_SESSION_ID_LEN);
    STAGE_AND_COMMIT(gy_op_put_session(&g_op, &s));
}

/* ---- conditional update / key change ----------------------------------- */

TEST(conditional_update_tofu)
{
    struct gy_public_key ik;
    struct gy_device_record d;

    mock_reset(&g_mock, &g_store);
    make_ik(&ik);

    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));

    /* One UserRecord, one DeviceRecord created; the device carries ik. */
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);
    load_device(&d);
    ASSERT_TRUE(memcmp(d.ik.pk, ik.pk, D->curve_pk_len) == 0,
                "tofu key stored");
}

TEST(conditional_update_same_key_noop)
{
    struct gy_public_key ik;

    mock_reset(&g_mock, &g_store);
    make_ik(&ik);

    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));
    /* A second update with the same key succeeds and adds no records. */
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);
}

TEST(key_change_fail_closed)
{
    struct gy_public_key ik1, ik2;
    struct gy_key_change chg;
    struct gy_device_record d;

    mock_reset(&g_mock, &g_store);
    make_ik(&ik1);
    make_ik(&ik2);

    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik1, NULL));

    /* A different key surfaces the change and mutates NOTHING. */
    memset(&chg, 0, sizeof(chg));
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID), DID,
                                    sizeof(DID), &ik2, &chg),
              GY_ERR_KEY_CHANGED);
    ASSERT_EQ(gy_op_commit(&g_op), GY_OK); /* nothing was staged */

    ASSERT_EQ(chg.fp_len, D->hash_len);
    ASSERT_TRUE(memcmp(chg.old_fp, chg.new_fp, chg.fp_len) != 0,
                "old and new fingerprints differ");
    load_device(&d);
    ASSERT_TRUE(memcmp(d.ik.pk, ik1.pk, D->curve_pk_len) == 0,
                "stored key unchanged before accept");
}

TEST(accept_key_change_replaces)
{
    struct gy_public_key ik1, ik2;
    struct gy_device_record d;
    uint8_t sid[GY_SESSION_ID_LEN] = {9, 9, 9, 9};

    mock_reset(&g_mock, &g_store);
    make_ik(&ik1);
    make_ik(&ik2);

    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik1, NULL));
    seed_session(sid);
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID, sizeof(UID), DID,
                                              sizeof(DID), sid));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 1);

    /* Accept the new key: sessions of the old key are gone, key is replaced. */
    STAGE_AND_COMMIT(gy_accept_key_change(&g_op, D->suite_id, UID, sizeof(UID),
                                          DID, sizeof(DID), &ik2));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 0);
    load_device(&d);
    ASSERT_TRUE(memcmp(d.ik.pk, ik2.pk, D->curve_pk_len) == 0, "key replaced");
    ASSERT_EQ(d.has_active, 0);
    ASSERT_EQ(d.n_inactive, 0u);
}

/* ---- insert / activate list order (D-SES-5) ---------------------------- */

TEST(insert_activate_semantics)
{
    struct gy_public_key ik;
    struct gy_device_record d;
    uint8_t a[GY_SESSION_ID_LEN] = {1, 0, 0, 0};
    uint8_t b[GY_SESSION_ID_LEN] = {2, 0, 0, 0};

    mock_reset(&g_mock, &g_store);
    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));

    /* Insert a: it becomes active. */
    STAGE_AND_COMMIT(
        gy_device_insert_session(&g_op, UID, sizeof(UID), DID, sizeof(DID), a));
    load_device(&d);
    ASSERT_EQ(d.has_active, 1);
    ASSERT_TRUE(memcmp(d.active, a, GY_SESSION_ID_LEN) == 0, "a active");
    ASSERT_EQ(d.n_inactive, 0u);

    /* Insert b: b active, a pushed to the inactive head. */
    STAGE_AND_COMMIT(
        gy_device_insert_session(&g_op, UID, sizeof(UID), DID, sizeof(DID), b));
    load_device(&d);
    ASSERT_TRUE(memcmp(d.active, b, GY_SESSION_ID_LEN) == 0, "b active");
    ASSERT_EQ(d.n_inactive, 1u);
    ASSERT_TRUE(memcmp(d.inactive[0], a, GY_SESSION_ID_LEN) == 0, "a inactive");

    /* Activate a: a active again, b pushed to the inactive head. */
    STAGE_AND_COMMIT(gy_device_activate_session(&g_op, UID, sizeof(UID), DID,
                                                sizeof(DID), a));
    load_device(&d);
    ASSERT_TRUE(memcmp(d.active, a, GY_SESSION_ID_LEN) == 0, "a re-activated");
    ASSERT_EQ(d.n_inactive, 1u);
    ASSERT_TRUE(memcmp(d.inactive[0], b, GY_SESSION_ID_LEN) == 0, "b inactive");
}

/* ---- expiration (D-SES-7) ---------------------------------------------- */

TEST(expiry_config_validation)
{
    struct gy_expiry_cfg cfg;
    struct gy_session s;

    /* A zeroed cfg is disabled: nothing expires. */
    memset(&cfg, 0, sizeof(cfg));
    memset(&s, 0, sizeof(s));
    s.nsend = 1000000;
    ASSERT_EQ(gy_session_expired(&cfg, &s), 0);

    /* Inequality max_recv > max_send + 2*max_latency must hold. */
    ASSERT_EQ(gy_expiry_cfg_init(&cfg, 100, 100, 10), GY_ERR_ARG);
    ASSERT_EQ(cfg.enabled, 0);
    ASSERT_EQ(gy_expiry_cfg_init(&cfg, 100, 120, 10), GY_ERR_ARG); /* == */
    ASSERT_EQ(gy_expiry_cfg_init(&cfg, 0, 200, 10), GY_ERR_ARG);   /* zero */
    ASSERT_EQ(gy_expiry_cfg_init(&cfg, 100, 200, 10), GY_OK);
    ASSERT_EQ(cfg.enabled, 1);
}

TEST(expiry_counters_and_rollback)
{
    struct gy_expiry_cfg cfg;
    struct gy_session s;

    ASSERT_EQ(gy_expiry_cfg_init(&cfg, 100, 200, 10), GY_OK);
    memset(&s, 0, sizeof(s));

    /* Boundary at max_send / max_recv. */
    s.nsend = 99;
    ASSERT_EQ(gy_session_expired(&cfg, &s), 0);
    s.nsend = 100;
    ASSERT_EQ(gy_session_expired(&cfg, &s), 1);
    s.nsend = 0;
    s.nrecv = 200;
    ASSERT_EQ(gy_session_expired(&cfg, &s), 1);

    /* Staleness is wall-clock; a rollback cannot un-stale via counters. */
    memset(&s, 0, sizeof(s));
    s.last_recv_at = 1000;
    ASSERT_EQ(gy_session_stale(&cfg, &s, 1005), 0); /* within latency */
    ASSERT_EQ(gy_session_stale(&cfg, &s, 1011), 1); /* past latency */
    ASSERT_EQ(gy_session_stale(&cfg, &s, 500), 0);  /* clock rolled back */
    /* Counter expiry ignores the rollback entirely. */
    s.nsend = 100;
    ASSERT_EQ(gy_session_expired(&cfg, &s), 1);
}

/* ---- device / user deletion (D-SES-2) ---------------------------------- */

TEST(delete_device_zeroizes)
{
    struct gy_public_key ik;
    uint8_t sid[GY_SESSION_ID_LEN] = {7, 7, 7, 7};
    struct gy_user_record u;
    int found;

    mock_reset(&g_mock, &g_store);
    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));
    seed_session(sid);
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID, sizeof(UID), DID,
                                              sizeof(DID), sid));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);

    STAGE_AND_COMMIT(
        gy_delete_device(&g_op, UID, sizeof(UID), DID, sizeof(DID)));

    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 0);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 0);
    /* The UserRecord survives but no longer indexes the device. */
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 1);
    ASSERT_EQ(gy_op_begin(&g_op, &g_store), GY_OK);
    ASSERT_EQ(gy_op_load_user(&g_op, UID, sizeof(UID), &u, &found), GY_OK);
    ASSERT_EQ(found, 1);
    ASSERT_EQ(u.n_devices, 0u);
    gy_op_abort(&g_op);
}

TEST(delete_user_all_gone)
{
    struct gy_public_key ik;
    uint8_t did2[4] = {0x05, 0x06, 0x07, 0x08};
    uint8_t s1[GY_SESSION_ID_LEN] = {3, 0, 0, 0};
    uint8_t s2[GY_SESSION_ID_LEN] = {4, 0, 0, 0};

    mock_reset(&g_mock, &g_store);

    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));
    seed_session(s1);
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID, sizeof(UID), DID,
                                              sizeof(DID), s1));

    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           did2, sizeof(did2), &ik, NULL));
    seed_session(s2);
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID, sizeof(UID), did2,
                                              sizeof(did2), s2));

    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 2);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 2);

    ASSERT_EQ(gy_delete_user(&g_store, &g_op, UID, sizeof(UID)), GY_OK);

    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 0);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 0);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_SESSION), 0);
}

/* ---- D-SES-12: per-(UserID, DeviceID) keying --------------------------- */

TEST(devkey_pair_isolation)
{
    struct gy_public_key ik1, ik2;
    struct gy_device_record d1, d2;
    uint8_t s1[GY_SESSION_ID_LEN] = {0x11, 0, 0, 0};
    uint8_t s2[GY_SESSION_ID_LEN] = {0x22, 0, 0, 0};

    mock_reset(&g_mock, &g_store);
    make_ik(&ik1);
    make_ik(&ik2);

    /* The same DeviceID string under two different users: two records. */
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik1, NULL));
    STAGE_AND_COMMIT(gy_conditional_update(
        &g_op, D->suite_id, UID2, sizeof(UID2), DID, sizeof(DID), &ik2, NULL));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 2);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 2);

    seed_session(s1);
    seed_session(s2);
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID, sizeof(UID), DID,
                                              sizeof(DID), s1));
    STAGE_AND_COMMIT(gy_device_insert_session(&g_op, UID2, sizeof(UID2), DID,
                                              sizeof(DID), s2));

    /* Each record keeps its own identity key and its own active session. */
    ASSERT_EQ(load_pair(UID, sizeof(UID), DID, sizeof(DID), &d1), 1);
    ASSERT_EQ(load_pair(UID2, sizeof(UID2), DID, sizeof(DID), &d2), 1);
    ASSERT_TRUE(memcmp(d1.ik.pk, ik1.pk, D->curve_pk_len) == 0, "user1 key");
    ASSERT_TRUE(memcmp(d2.ik.pk, ik2.pk, D->curve_pk_len) == 0, "user2 key");
    ASSERT_TRUE(memcmp(d1.ik.pk, d2.ik.pk, D->curve_pk_len) != 0,
                "records do not cross");
    ASSERT_TRUE(memcmp(d1.active, s1, GY_SESSION_ID_LEN) == 0, "user1 session");
    ASSERT_TRUE(memcmp(d2.active, s2, GY_SESSION_ID_LEN) == 0, "user2 session");
}

TEST(purge_device_leaves_other_user)
{
    struct gy_public_key ik1, ik2;
    struct gy_device_record d;

    mock_reset(&g_mock, &g_store);
    make_ik(&ik1);
    make_ik(&ik2);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik1, NULL));
    STAGE_AND_COMMIT(gy_conditional_update(
        &g_op, D->suite_id, UID2, sizeof(UID2), DID, sizeof(DID), &ik2, NULL));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 2);

    /* Purge (UID, DID): only that pair's record goes; (UID2, DID) survives. */
    STAGE_AND_COMMIT(
        gy_delete_device(&g_op, UID, sizeof(UID), DID, sizeof(DID)));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);
    ASSERT_EQ(load_pair(UID, sizeof(UID), DID, sizeof(DID), &d), 0);
    ASSERT_EQ(load_pair(UID2, sizeof(UID2), DID, sizeof(DID), &d), 1);
    ASSERT_TRUE(memcmp(d.ik.pk, ik2.pk, D->curve_pk_len) == 0, "user2 intact");
}

TEST(purge_user_leaves_other_user)
{
    struct gy_public_key ik;
    struct gy_device_record d;
    uint8_t did2[4] = {0x05, 0x06, 0x07, 0x08};

    mock_reset(&g_mock, &g_store);
    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           DID, sizeof(DID), &ik, NULL));
    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(&g_op, D->suite_id, UID, sizeof(UID),
                                           did2, sizeof(did2), &ik, NULL));
    make_ik(&ik);
    STAGE_AND_COMMIT(gy_conditional_update(
        &g_op, D->suite_id, UID2, sizeof(UID2), DID, sizeof(DID), &ik, NULL));
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 3);

    /* Delete UID: both of its devices go; UID2's same-DeviceID device stays. */
    ASSERT_EQ(gy_delete_user(&g_store, &g_op, UID, sizeof(UID)), GY_OK);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_USER), 1);
    ASSERT_EQ(mock_count(&g_mock, GY_REC_DEVICE), 1);
    ASSERT_EQ(load_pair(UID, sizeof(UID), DID, sizeof(DID), &d), 0);
    ASSERT_EQ(load_pair(UID, sizeof(UID), did2, sizeof(did2), &d), 0);
    ASSERT_EQ(load_pair(UID2, sizeof(UID2), DID, sizeof(DID), &d), 1);
}

TEST(devrec_key_domain_separation)
{
    static const uint8_t abc[3] = {'a', 'b', 'c'};
    uint8_t k1[GY_DEVKEY_LEN], k2[GY_DEVKEY_LEN];

    /* Deterministic over the same pair. */
    ASSERT_EQ(gy_devrec_key(UID, sizeof(UID), DID, sizeof(DID), k1), GY_OK);
    ASSERT_EQ(gy_devrec_key(UID, sizeof(UID), DID, sizeof(DID), k2), GY_OK);
    ASSERT_MEMEQ(k1, k2, GY_DEVKEY_LEN);

    /* A different user over the same device yields a different key. */
    ASSERT_EQ(gy_devrec_key(UID2, sizeof(UID2), DID, sizeof(DID), k2), GY_OK);
    ASSERT_TRUE(memcmp(k1, k2, GY_DEVKEY_LEN) != 0, "user distinguishes key");

    /* be32 length prefixes bind the split: ("ab","c") != ("a","bc"). */
    ASSERT_EQ(gy_devrec_key(abc, 2, abc + 2, 1, k1), GY_OK);
    ASSERT_EQ(gy_devrec_key(abc, 1, abc + 1, 2, k2), GY_OK);
    ASSERT_TRUE(memcmp(k1, k2, GY_DEVKEY_LEN) != 0, "length prefix binds");

    /* Rejects empty inputs and a NULL output. */
    ASSERT_EQ(gy_devrec_key(UID, 0, DID, sizeof(DID), k1), GY_ERR_ARG);
    ASSERT_EQ(gy_devrec_key(UID, sizeof(UID), DID, 0, k1), GY_ERR_ARG);
    ASSERT_EQ(gy_devrec_key(UID, sizeof(UID), DID, sizeof(DID), NULL),
              GY_ERR_ARG);
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
            GY_TEST(conditional_update_tofu),
            GY_TEST(conditional_update_same_key_noop),
            GY_TEST(key_change_fail_closed),
            GY_TEST(accept_key_change_replaces),
            GY_TEST(insert_activate_semantics),
            GY_TEST(expiry_config_validation),
            GY_TEST(expiry_counters_and_rollback),
            GY_TEST(delete_device_zeroizes),
            GY_TEST(delete_user_all_gone),
            GY_TEST(devkey_pair_isolation),
            GY_TEST(purge_device_leaves_other_user),
            GY_TEST(purge_user_leaves_other_user),
            GY_TEST(devrec_key_domain_separation),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
