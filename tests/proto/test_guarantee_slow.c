/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The custody guarantee (D-CUST-1, CUSTODY_SPEC section
 * 1): no public entry point returns cleartext private key material.  This is
 * partly a review-enforced property (walking the exported symbol list is
 * a later step's job), but the byte-content half is mechanically checkable: run
 * a real handshake through include/geryon.h and confirm none of the bytes it
 * hands back to the caller (the published bundle, the fingerprint, and both
 * directions' ciphertext) contain the raw private scalars this file can see
 * because it includes custodian.h (white-box).  create/generate_identity run
 * a real Argon2id derivation, so this file is tagged _slow.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "custodian.h"
#include "geryon.h"

#include "gy_test.h"

/* ---- minimal two-party mock store (public int-kind callbacks) ---------- */

#define MOCK_MAX 16
#define MOCK_BLOB 90000 /* GY_SESSION_BLOB_MAX-sized, per session.h */
#define MOCK_IDENTITY_BLOB 16384

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
    uint8_t identity[MOCK_IDENTITY_BLOB];
    size_t identity_len;
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
m_consume(void *ctx, uint32_t pkid)
{
    (void)ctx;
    (void)pkid;
    return GY_OK;
}

static int
m_load_id(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
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
m_store_id(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;

    if (blob_len > MOCK_IDENTITY_BLOB)
        return GY_ERR_ARG;
    if (blob_len > 0)
        memcpy(m->identity, blob, blob_len);
    m->identity_len = blob_len;
    return GY_OK;
}

static int
m_load_pk(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
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

static void
mstore_bind(struct mstore *m, gy_store_callbacks *cb)
{
    memset(m, 0, sizeof(*m));
    cb->ctx = m;
    cb->load_record = m_load;
    cb->store_record = m_store;
    cb->delete_record = m_delete;
    cb->load_identity = m_load_id;
    cb->store_identity = m_store_id;
    cb->load_prekey = m_load_pk;
    cb->consume_opk = m_consume;
}

/* ---- substring scan: does needle appear anywhere in haystack? ---------- */

static int
contains(const uint8_t *hay, size_t hay_len, const uint8_t *needle,
         size_t needle_len)
{
    size_t i;

    if (needle_len == 0 || needle_len > hay_len)
        return 0;
    for (i = 0; i + needle_len <= hay_len; i++)
        if (memcmp(hay + i, needle, needle_len) == 0)
            return 1;
    return 0;
}

/* Assert none of a custodian's live private scalars appear in buf. */
static void
assert_no_secrets(struct gy_custodian *c, const uint8_t *buf, size_t len,
                  const char *where)
{
    char msg[128];
    size_t i;

    ASSERT_TRUE(!contains(buf, len, c->ik.sk, sizeof(c->ik.sk)), where);
    for (i = 0; i < c->n_spks; i++) {
        (void)snprintf(msg, sizeof(msg), "%s (spks[%zu].sk)", where, i);
        ASSERT_TRUE(
            !contains(buf, len, c->spks[i].kp.sk, sizeof(c->spks[i].kp.sk)),
            msg);
    }
    for (i = 0; i < c->n_opks; i++) {
        if (!c->opk_used[i])
            continue; /* freed slot (delete-on-use): sk is already zeroized */
        (void)snprintf(msg, sizeof(msg), "%s (opk[%zu].sk)", where, i);
        ASSERT_TRUE(!contains(buf, len, c->opks[i].sk, sizeof(c->opks[i].sk)),
                    msg);
    }
}

/* ---- the guarantee test -------------------------------------------------*/

TEST(no_public_output_carries_a_private_scalar)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    static const uint8_t auid[4] = {0xA1, 1, 1, 1}, adid[4] = {0xA1, 2, 2, 2};
    static const uint8_t buid[4] = {0xB2, 1, 1, 1}, bdid[4] = {0xB2, 2, 2, 2};
    static const uint8_t acred[] = "guarantee test credential A";
    static const uint8_t bcred[] = "guarantee test credential B";
    uint8_t bundle[1024], fp[GY_FINGERPRINT_MAX], m1[2048], out[256];
    static const uint8_t pt1[5] = "abcde";
    size_t blen, fplen, mlen, olen;

    mstore_bind(&am, &acb);
    mstore_bind(&bm, &bcb);
    ASSERT_EQ(gy_custodian_create(&a, GY_SUITE_C25519, &acb, acred,
                                  sizeof(acred) - 1, auid, sizeof(auid), adid,
                                  sizeof(adid), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_create(&b, GY_SUITE_C25519, &bcb, bcred,
                                  sizeof(bcred) - 1, buid, sizeof(buid), bdid,
                                  sizeof(bdid), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(a, 1000, 2), GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(b, 1000, 2), GY_OK);

    /* The published bundle and fingerprint are public-key-only outputs. */
    blen = sizeof(bundle);
    ASSERT_EQ(gy_publish_bundle(b, bundle, &blen), GY_OK);
    assert_no_secrets(b, bundle, blen, "b's own bundle carries a's secret");
    assert_no_secrets(a, bundle, blen, "b's bundle carries a's secret");

    fplen = sizeof(fp);
    ASSERT_EQ(gy_self_fingerprint(a, fp, &fplen), GY_OK);
    assert_no_secrets(a, fp, fplen, "fingerprint carries a's own secret");

    /* The initiation ciphertext (X3DH init + first DR frame). */
    ASSERT_EQ(gy_send_open(a), GY_OK);
    mlen = sizeof(m1);
    ASSERT_EQ(gy_initiate(a, buid, sizeof(buid), bdid, sizeof(bdid), bundle,
                          blen, pt1, sizeof(pt1), NULL, m1, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(a), GY_OK);
    assert_no_secrets(a, m1, mlen, "initiation ciphertext carries a's secret");
    assert_no_secrets(b, m1, mlen, "initiation ciphertext carries b's secret");

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, auid, sizeof(auid), adid, sizeof(adid), m1, mlen,
                         out, &olen),
              GY_OK);
    assert_no_secrets(a, out, olen, "recovered plaintext carries a's secret");
    assert_no_secrets(b, out, olen, "recovered plaintext carries b's secret");

    /* An established-session message, the other direction. */
    ASSERT_EQ(gy_send_open(b), GY_OK);
    mlen = sizeof(m1);
    ASSERT_EQ(gy_encrypt(b, auid, sizeof(auid), adid, sizeof(adid), pt1,
                         sizeof(pt1), m1, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(b), GY_OK);
    assert_no_secrets(a, m1, mlen, "reply ciphertext carries a's secret");
    assert_no_secrets(b, m1, mlen, "reply ciphertext carries b's secret");

    gy_custodian_close(a);
    gy_custodian_close(b);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(no_public_output_carries_a_private_scalar),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
