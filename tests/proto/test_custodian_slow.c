/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/proto/custodian.c: the gy_custodian object, lifecycle, and
 * handle model.  create/open/change_credential each run a
 * real Argon2id derivation at the compiled MODERATE-tier floor (via
 * gy_keystore_*), so this file is tagged _slow.
 */

#include <stdint.h>
#include <string.h>

#include "custodian.h"
#include "geryon.h"

#include "gy_test.h"

/* ---- minimal mock store (public gy_store_callbacks, int kind) ---------- */

#define MOCK_MAX 8
#define MOCK_BLOB 512

struct mrec {
    int in_use;
    int kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    size_t blob_len;
    uint8_t blob[MOCK_BLOB];
};

struct mstore {
    struct mrec recs[MOCK_MAX];
    uint8_t identity[MOCK_BLOB];
    size_t identity_len;
    struct gy_custodian *c; /* set by a test once create/open has run, so
                             * guard_check can inspect c->active (D-GEN-8) */
    int guard_fail;
};

static struct mrec *
mfind(struct mstore *m, int kind, const uint8_t *id, size_t id_len)
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
guard_check(struct mstore *m)
{
#ifndef NDEBUG
    if (m->c != NULL && m->c->active != 1)
        m->guard_fail = 1;
#else
    (void)m;
#endif
}

static int
m_load(void *ctx, int kind, const uint8_t *id, size_t id_len, uint8_t *out,
       size_t cap, size_t *out_len)
{
    struct mrec *r = mfind(ctx, kind, id, id_len);

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
m_store(void *ctx, int kind, const uint8_t *id, size_t id_len,
        const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;
    struct mrec *r = mfind(m, kind, id, id_len);
    int i;

    if (blob_len > MOCK_BLOB)
        return GY_ERR_ARG;
    if (r == NULL) {
        for (i = 0; i < MOCK_MAX; i++)
            if (!m->recs[i].in_use) {
                r = &m->recs[i];
                break;
            }
        if (r == NULL)
            return GY_ERR_STATE;
        r->in_use = 1;
        r->kind = kind;
        r->id_len = id_len;
        memcpy(r->id, id, id_len);
    }
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static int
m_delete(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct mrec *r = mfind(ctx, kind, id, id_len);

    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK;
}

static int
m_load_identity(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    struct mstore *m = ctx;

    guard_check(m);
    if (m->identity_len == 0) {
        *out_len = 0;
        return GY_OK;
    }
    if (m->identity_len > cap)
        return GY_ERR_ARG;
    memcpy(out, m->identity, m->identity_len);
    *out_len = m->identity_len;
    return GY_OK;
}

static int
m_store_identity(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;

    guard_check(m);
    if (blob_len > MOCK_BLOB)
        return GY_ERR_ARG;
    if (blob_len > 0)
        memcpy(m->identity, blob, blob_len);
    m->identity_len = blob_len;
    return GY_OK;
}

static int
m_load_prekey(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
              size_t *out_len)
{
    (void)ctx;
    (void)kind;
    (void)pkid;
    (void)out;
    (void)cap;
    *out_len = 0;
    return GY_OK;
}

static int
m_consume_opk(void *ctx, uint32_t pkid)
{
    (void)ctx;
    (void)pkid;
    return GY_OK;
}

static void
mstore_bind(struct mstore *m, gy_store_callbacks *cb)
{
    memset(m, 0, sizeof(*m));
    cb->ctx = m;
    cb->load_record = m_load;
    cb->store_record = m_store;
    cb->delete_record = m_delete;
    cb->load_identity = m_load_identity;
    cb->store_identity = m_store_identity;
    cb->load_prekey = m_load_prekey;
    cb->consume_opk = m_consume_opk;
}

/* ---- tests --------------------------------------------------------------*/

TEST(create_close_open_roundtrip_recovers_material)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "correct horse battery staple";
    static const uint8_t uid[] = "user-1";
    static const uint8_t did[] = "device-1";
    static const uint8_t rec_id[4] = {1, 2, 3, 4};
    static const uint8_t plaintext[16] = "custodian data!!";
    uint8_t recovered[64];
    size_t ptlen;

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(
                  &c, GY_SUITE_C25519, &cb, (const uint8_t *)cred, strlen(cred),
                  uid, sizeof(uid) - 1, did, sizeof(did) - 1, NULL, NULL, NULL),
              GY_OK);
    ASSERT_TRUE(c != NULL, "created custodian");

    /* Seal something through the sealed-store wrapper (what a later step's
     * record traffic will use) before closing: proves open recovers the
     * SAME KEK, not just any KEK. */
    ASSERT_EQ(c->sealed_store.store_record(c->sealed_store.ctx, 1, rec_id,
                                           sizeof(rec_id), plaintext,
                                           sizeof(plaintext)),
              GY_OK);

    gy_custodian_close(c);

    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred, strlen(cred)),
              GY_OK);
    ASSERT_TRUE(c != NULL, "reopened custodian");
    ASSERT_EQ(c->suite_id, GY_SUITE_C25519);
    ASSERT_EQ(c->self_uid_len, sizeof(uid) - 1);
    ASSERT_MEMEQ(c->self_uid, uid, sizeof(uid) - 1);
    ASSERT_EQ(c->self_did_len, sizeof(did) - 1);
    ASSERT_MEMEQ(c->self_did, did, sizeof(did) - 1);

    ptlen = sizeof(recovered);
    ASSERT_EQ(c->sealed_store.load_record(c->sealed_store.ctx, 1, rec_id,
                                          sizeof(rec_id), recovered, ptlen,
                                          &ptlen),
              GY_OK);
    ASSERT_EQ(ptlen, sizeof(plaintext));
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));

    gy_custodian_close(c);
}

TEST(wrong_credential_open_is_uniform_error)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "right credential";
    const char *wrong = "wrong credential";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred, strlen(cred), NULL, 0,
                                  NULL, 0, NULL, NULL, NULL),
              GY_OK);
    gy_custodian_close(c);

    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)wrong, strlen(wrong)),
              GY_ERR_VERIFY);
}

TEST(reset_wipes_and_returns_to_absent)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "reset test credential";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred, strlen(cred), NULL, 0,
                                  NULL, 0, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_reset(c), GY_OK);
    ASSERT_EQ(m.identity_len, 0);

    /* absent: opening with the (previously correct) credential now fails,
     * since there is no persisted header left to unwrap. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred, strlen(cred)),
              GY_ERR_STATE);
}

TEST(change_credential_rewraps_and_preserves_material)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred1 = "original credential";
    const char *cred2 = "replacement credential";
    static const uint8_t rec_id[4] = {9, 9, 9, 9};
    static const uint8_t plaintext[10] = "still here";
    uint8_t recovered[64];
    size_t ptlen;

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred1, strlen(cred1), NULL,
                                  0, NULL, 0, NULL, NULL, NULL),
              GY_OK);

    ASSERT_EQ(c->sealed_store.store_record(c->sealed_store.ctx, 1, rec_id,
                                           sizeof(rec_id), plaintext,
                                           sizeof(plaintext)),
              GY_OK);

    ASSERT_EQ(gy_custodian_change_credential(c, (const uint8_t *)cred2,
                                             strlen(cred2)),
              GY_OK);

    /* Material sealed BEFORE the change still opens under the SAME live
     * KEK, without having been re-touched. */
    ptlen = sizeof(recovered);
    ASSERT_EQ(c->sealed_store.load_record(c->sealed_store.ctx, 1, rec_id,
                                          sizeof(rec_id), recovered, ptlen,
                                          &ptlen),
              GY_OK);
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));

    gy_custodian_close(c);

    /* The custodian header is a single overwritten slot (unlike the
     * keystore-level wrap blob, which the caller holds independently): the
     * OLD credential no longer opens it. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred1, strlen(cred1)),
              GY_ERR_VERIFY);

    /* The NEW credential opens it and recovers the same material. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred2, strlen(cred2)),
              GY_OK);
    ptlen = sizeof(recovered);
    ASSERT_EQ(c->sealed_store.load_record(c->sealed_store.ctx, 1, rec_id,
                                          sizeof(rec_id), recovered, ptlen,
                                          &ptlen),
              GY_OK);
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));
    gy_custodian_close(c);
}

TEST(handle_opacity_zero_invalid_and_stale_after_close)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "slot test credential";
    gy_key_handle h_id, h_spk, h_sak;
    int type;
    uint32_t key_id;

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred, strlen(cred), NULL, 0,
                                  NULL, 0, NULL, NULL, NULL),
              GY_OK);

    /* 0 is always invalid. */
    ASSERT_EQ(gy_custodian_slot_get(c, GY_KEY_HANDLE_INVALID, &type, &key_id),
              GY_ERR_NOT_FOUND);

    ASSERT_EQ(gy_custodian_slot_alloc(c, GY_SLOT_IDENTITY, 0, &h_id), GY_OK);
    ASSERT_EQ(gy_custodian_slot_alloc(c, GY_SLOT_SPK, 7, &h_spk), GY_OK);
    ASSERT_EQ(gy_custodian_slot_alloc(c, GY_SLOT_SAK, 0, &h_sak), GY_OK);

    /* Opacity: three DIFFERENT slot types allocated back-to-back get plain
     * consecutive handle values (D-CUST-1 item 1), not a value derived from
     * GY_SLOT_*. */
    ASSERT_EQ(h_id, 1);
    ASSERT_EQ(h_spk, 2);
    ASSERT_EQ(h_sak, 3);

    ASSERT_EQ(gy_custodian_slot_get(c, h_spk, &type, &key_id), GY_OK);
    ASSERT_EQ(type, GY_SLOT_SPK);
    ASSERT_EQ(key_id, 7);

    gy_custodian_slot_free(c, h_spk);
    ASSERT_EQ(gy_custodian_slot_get(c, h_spk, &type, &key_id),
              GY_ERR_NOT_FOUND);

    gy_custodian_close(c);

    /* Stale handle after close: a freshly reopened custodian's slot table
     * starts empty, so a handle from the CLOSED instance names nothing. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred, strlen(cred)),
              GY_OK);
    ASSERT_EQ(gy_custodian_slot_get(c, h_id, &type, &key_id), GY_ERR_NOT_FOUND);
    gy_custodian_close(c);
}

TEST(slot_table_exhausted)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "exhaustion test credential";
    gy_key_handle h;
    int i;

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred, strlen(cred), NULL, 0,
                                  NULL, 0, NULL, NULL, NULL),
              GY_OK);

    for (i = 0; i < GY_CUSTODIAN_MAX_SLOTS; i++)
        ASSERT_EQ(gy_custodian_slot_alloc(c, GY_SLOT_OPK, (uint32_t)i, &h),
                  GY_OK);

    ASSERT_EQ(gy_custodian_slot_alloc(c, GY_SLOT_OPK, 999, &h),
              GY_ERR_NO_SPACE);

    gy_custodian_close(c);
}

TEST(reentrancy_guard_is_armed_during_store_identity_callback)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const char *cred = "guard test credential";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &cb,
                                  (const uint8_t *)cred, strlen(cred), NULL, 0,
                                  NULL, 0, NULL, NULL, NULL),
              GY_OK);
    m.c = c; /* arm the check: guard_check now inspects c->active */

    ASSERT_EQ(
        gy_custodian_change_credential(c, (const uint8_t *)cred, strlen(cred)),
        GY_OK);
    ASSERT_TRUE(!m.guard_fail,
                "c->active was 1 while store_identity ran (D-GEN-8)");
    ASSERT_EQ(c->active, 0);

    gy_custodian_close(c);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(create_close_open_roundtrip_recovers_material),
            GY_TEST(wrong_credential_open_is_uniform_error),
            GY_TEST(reset_wipes_and_returns_to_absent),
            GY_TEST(change_credential_rewraps_and_preserves_material),
            GY_TEST(handle_opacity_zero_invalid_and_stale_after_close),
            GY_TEST(slot_table_exhausted),
            GY_TEST(reentrancy_guard_is_armed_during_store_identity_callback),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
