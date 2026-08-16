/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/proto/sealed_store.c: the gy_store_callbacks sealing wrapper.
 * The keystore under test is opened directly (a
 * random KEK, no Argon2id) since these tests are about the wrapper's AD
 * construction and pass-through behavior, not the KEK-protector seam
 * (covered by tests/session/test_keystore_slow.c).
 */

#include <stdint.h>
#include <string.h>

#include "geryon.h"
#include "sealed_store.h"
#include "store.h" /* enum gy_rec_kind: GY_REC_USER/DEVICE, int-compatible */

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

struct mprekey {
    int in_use;
    int kind;
    uint32_t pkid;
    size_t blob_len;
    uint8_t blob[MOCK_BLOB];
};

struct mstore {
    struct mrec recs[MOCK_MAX];
    struct mprekey prekeys[MOCK_MAX];
    uint8_t identity[MOCK_BLOB];
    size_t identity_len;
    int n_consumed;
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

    if (blob_len > MOCK_BLOB)
        return GY_ERR_ARG;
    memcpy(m->identity, blob, blob_len);
    m->identity_len = blob_len;
    return GY_OK;
}

static int
m_load_prekey(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
              size_t *out_len)
{
    struct mstore *m = ctx;
    int i;

    for (i = 0; i < MOCK_MAX; i++) {
        struct mprekey *p = &m->prekeys[i];

        if (p->in_use && p->kind == kind && p->pkid == pkid) {
            if (p->blob_len > cap)
                return GY_ERR_ARG;
            memcpy(out, p->blob, p->blob_len);
            *out_len = p->blob_len;
            return GY_OK;
        }
    }
    *out_len = 0;
    return GY_OK;
}

static int
m_consume_opk(void *ctx, uint32_t pkid)
{
    struct mstore *m = ctx;

    (void)pkid;
    m->n_consumed++;
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

/* Seed a prekey slot directly with a blob ALREADY sealed under ks, mirroring
 * the AD scheme ss_load_prekey expects (tag 0x03 || kind || pkid_be32): there
 * is no store_prekey callback in the public contract, so this is the only
 * way to exercise the load_prekey unseal path. */
static void
seed_prekey(struct mstore *m, struct gy_keystore *ks, int kind, uint32_t pkid,
            const uint8_t *pt, size_t ptlen)
{
    struct mprekey *p = &m->prekeys[0];
    uint8_t ad[6];
    size_t sealedlen;

    ad[0] = 0x03;
    ad[1] = (uint8_t)kind;
    ad[2] = (uint8_t)(pkid >> 24);
    ad[3] = (uint8_t)(pkid >> 16);
    ad[4] = (uint8_t)(pkid >> 8);
    ad[5] = (uint8_t)pkid;

    p->in_use = 1;
    p->kind = kind;
    p->pkid = pkid;
    sealedlen = sizeof(p->blob);
    ASSERT_EQ(gy_keystore_seal(ks, GY_SEAL_ALG_AEGIS256, ad, sizeof(ad), pt,
                               ptlen, p->blob, &sealedlen),
              GY_OK);
    p->blob_len = sealedlen;
}

static void
open_test_keystore(struct gy_keystore *ks)
{
    memset(ks, 0, sizeof(*ks));
    ks->kek = gy_secure_alloc(GY_KEKPROT_KEK_LEN);
    ASSERT_TRUE(ks->kek != NULL, "kek alloc");
    ASSERT_EQ(gy_random_bytes(ks->kek, GY_KEKPROT_KEK_LEN), GY_OK);
    ks->unlocked = 1;
}

/* ---- tests --------------------------------------------------------------*/

TEST(record_roundtrip_and_genuinely_sealed)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t id[4] = {1, 2, 3, 4};
    static const uint8_t plaintext[16] = "a user record!!";
    uint8_t recovered[MOCK_BLOB];
    struct mrec *raw;
    size_t outlen;

    open_test_keystore(&ks);
    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    ASSERT_EQ(cb.store_record(cb.ctx, GY_REC_USER, id, sizeof(id), plaintext,
                              sizeof(plaintext)),
              GY_OK);

    /* What actually reached the application's store is sealed, not the
     * plaintext bytes: different length (header/nonce/tag overhead) and
     * does not contain the plaintext. */
    raw = mfind(&m, GY_REC_USER, id, sizeof(id));
    ASSERT_TRUE(raw != NULL, "record reached the real store");
    ASSERT_TRUE(raw->blob_len != sizeof(plaintext), "sealed length differs");
    ASSERT_TRUE(memcmp(raw->blob, plaintext, sizeof(plaintext)) != 0,
                "sealed bytes are not the plaintext");

    outlen = sizeof(recovered);
    ASSERT_EQ(cb.load_record(cb.ctx, GY_REC_USER, id, sizeof(id), recovered,
                             outlen, &outlen),
              GY_OK);
    ASSERT_EQ(outlen, sizeof(plaintext));
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));

    gy_keystore_close(&ks);
}

TEST(load_of_absent_record_is_not_found_not_error)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t id[4] = {9, 9, 9, 9};
    uint8_t out[64];
    size_t outlen;

    open_test_keystore(&ks);
    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    outlen = sizeof(out);
    ASSERT_EQ(cb.load_record(cb.ctx, GY_REC_USER, id, sizeof(id), out, outlen,
                             &outlen),
              GY_OK);
    ASSERT_EQ(outlen, 0);

    gy_keystore_close(&ks);
}

TEST(identity_roundtrip)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t plaintext[20] = "an identity blob!!!";
    uint8_t recovered[MOCK_BLOB];
    size_t outlen;

    open_test_keystore(&ks);
    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    ASSERT_EQ(cb.store_identity(cb.ctx, plaintext, sizeof(plaintext)), GY_OK);
    ASSERT_TRUE(memcmp(m.identity, plaintext, sizeof(plaintext)) != 0,
                "stored identity bytes are sealed, not plaintext");

    outlen = sizeof(recovered);
    ASSERT_EQ(cb.load_identity(cb.ctx, recovered, outlen, &outlen), GY_OK);
    ASSERT_EQ(outlen, sizeof(plaintext));
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));

    gy_keystore_close(&ks);
}

TEST(prekey_unseal)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t plaintext[8] = "spk-priv";
    uint8_t recovered[MOCK_BLOB];
    size_t outlen;

    open_test_keystore(&ks);
    mstore_bind(&m, &cb); /* zeroes m and sets cb.ctx = &m */
    seed_prekey(&m, &ks, 1, 0xAABBCCDD, plaintext, sizeof(plaintext));
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    outlen = sizeof(recovered);
    ASSERT_EQ(cb.load_prekey(cb.ctx, 1, 0xAABBCCDD, recovered, outlen, &outlen),
              GY_OK);
    ASSERT_EQ(outlen, sizeof(plaintext));
    ASSERT_MEMEQ(recovered, plaintext, sizeof(plaintext));

    gy_keystore_close(&ks);
}

TEST(delete_and_consume_pass_through_unchanged)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t id[4] = {5, 6, 7, 8};
    static const uint8_t plaintext[8] = "deleteme";

    open_test_keystore(&ks);
    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    ASSERT_EQ(cb.store_record(cb.ctx, GY_REC_DEVICE, id, sizeof(id), plaintext,
                              sizeof(plaintext)),
              GY_OK);
    ASSERT_TRUE(mfind(&m, GY_REC_DEVICE, id, sizeof(id)) != NULL,
                "record present before delete");
    ASSERT_EQ(cb.delete_record(cb.ctx, GY_REC_DEVICE, id, sizeof(id)), GY_OK);
    ASSERT_TRUE(mfind(&m, GY_REC_DEVICE, id, sizeof(id)) == NULL,
                "record gone after delete");

    ASSERT_EQ(m.n_consumed, 0);
    ASSERT_EQ(cb.consume_opk(cb.ctx, 42), GY_OK);
    ASSERT_EQ(m.n_consumed, 1);

    gy_keystore_close(&ks);
}

TEST(ad_binding_rejects_a_kind_substitution)
{
    struct gy_keystore ks;
    static struct gy_sealed_store ss;
    static struct mstore m;
    gy_store_callbacks cb;
    static const uint8_t id[4] = {1, 1, 1, 1};
    static const uint8_t plaintext[8] = "u-or-dev";
    uint8_t out[64];
    struct mrec *r;
    size_t outlen;

    open_test_keystore(&ks);
    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_sealed_store_bind(&ss, &ks, &cb, GY_SEAL_ALG_AEGIS256, &cb),
              GY_OK);

    ASSERT_EQ(cb.store_record(cb.ctx, GY_REC_USER, id, sizeof(id), plaintext,
                              sizeof(plaintext)),
              GY_OK);

    /* Relabel the same sealed bytes under a DIFFERENT kind in the real
     * store, simulating a substitution.  The AD binds the kind byte
     * (D-CUST-1 item 5), so loading it back under the new kind must fail,
     * not silently decode as a DeviceRecord. */
    r = mfind(&m, GY_REC_USER, id, sizeof(id));
    ASSERT_TRUE(r != NULL, "seeded record present");
    r->kind = GY_REC_DEVICE;

    outlen = sizeof(out);
    ASSERT_EQ(cb.load_record(cb.ctx, GY_REC_DEVICE, id, sizeof(id), out, outlen,
                             &outlen),
              GY_ERR_VERIFY);

    gy_keystore_close(&ks);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(record_roundtrip_and_genuinely_sealed),
            GY_TEST(load_of_absent_record_is_not_found_not_error),
            GY_TEST(identity_roundtrip),
            GY_TEST(prekey_unseal),
            GY_TEST(delete_and_consume_pass_through_unchanged),
            GY_TEST(ad_binding_rejects_a_kind_substitution),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
