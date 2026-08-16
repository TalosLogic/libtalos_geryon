/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * public API (re-hosted on gy_custodian): drive a
 * full initiation + established exchange through include/geryon.h ONLY (no
 * internal headers), exercising gy_custodian_create/generate_identity,
 * bundle generation, the staged send transaction, self-committing receive,
 * fingerprint and PQ-pending surfaces, and device purge.  This also stands as
 * the header's standalone-compile check under the strict warning flags.
 */

#include <string.h>

#include "geryon.h"

#include "gy_test.h"

/* ---- public-callback mock store (int kind, per geryon.h) ---------------- */

#define MOCK_MAX 32
#define MOCK_BLOB 8192

struct mrec {
    int in_use;
    int kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    size_t blob_len;
    uint8_t blob[MOCK_BLOB];
};

/* Identity slot capacity: the custodian's bootstrap header plus sealed
 * identity/prekey material; not tied to custodian.h's
 * internal GY_CUST_BLOB_MAX since this file stays within geryon.h only. */
#define MOCK_IDENTITY_BLOB 16384

struct mstore {
    struct mrec recs[MOCK_MAX];
    uint8_t identity[MOCK_IDENTITY_BLOB];
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
mcount(struct mstore *m, int kind)
{
    int i, n = 0;

    for (i = 0; i < MOCK_MAX; i++)
        if (m->recs[i].in_use && m->recs[i].kind == kind)
            n++;
    return n;
}

static int
s_load(void *ctx, int kind, const uint8_t *id, size_t id_len, uint8_t *out,
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
s_store(void *ctx, int kind, const uint8_t *id, size_t id_len,
        const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;
    struct mrec *r = mfind(m, kind, id, id_len);

    if (blob_len > MOCK_BLOB)
        return GY_ERR_ARG;
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
        r->kind = kind;
        r->id_len = id_len;
        memcpy(r->id, id, id_len);
    }
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static int
s_delete(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct mrec *r = mfind(ctx, kind, id, id_len);

    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK;
}

static int
s_consume(void *ctx, uint32_t pkid)
{
    struct mstore *m = ctx;

    (void)pkid;
    m->n_consumed++;
    return GY_OK;
}

static int
s_load_id(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
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
s_store_id(void *ctx, const uint8_t *blob, size_t blob_len)
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
s_load_pk(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
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
    cb->load_record = s_load;
    cb->store_record = s_store;
    cb->delete_record = s_delete;
    cb->load_identity = s_load_id;
    cb->store_identity = s_store_id;
    cb->load_prekey = s_load_pk;
    cb->consume_opk = s_consume;
}

/* ---- fixtures ---------------------------------------------------------- */

static struct mstore g_am, g_bm;
static gy_store_callbacks g_acb, g_bcb;

static const uint8_t AUID[4] = {0xA1, 0xA2, 0xA3, 0xA4};
static const uint8_t ADID[4] = {0xAD, 0xAE, 0xAF, 0xB0};
static const uint8_t BUID[4] = {0xB1, 0xB2, 0xB3, 0xB4};
static const uint8_t BDID[4] = {0xBD, 0xBE, 0xBF, 0xC0};

static const uint8_t ACRED[] = "alice test credential";
static const uint8_t BCRED[] = "bob test credential";

/* Bring up an Alice (send) and Bob (recv) pair with identities generated. */
static void
bring_up(gy_custodian **alice, gy_custodian **bob, uint8_t *bundle,
         size_t *blen)
{
    mstore_bind(&g_am, &g_acb);
    mstore_bind(&g_bm, &g_bcb);

    ASSERT_EQ(gy_custodian_create(alice, GY_SUITE_C25519, &g_acb, ACRED,
                                  sizeof(ACRED) - 1, AUID, sizeof(AUID), ADID,
                                  sizeof(ADID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_create(bob, GY_SUITE_C25519, &g_bcb, BCRED,
                                  sizeof(BCRED) - 1, BUID, sizeof(BUID), BDID,
                                  sizeof(BDID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(*alice, 1000, 4), GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(*bob, 1000, 4), GY_OK);

    /* Bob publishes his bundle (size query, then serialize). */
    *blen = 0;
    ASSERT_EQ(gy_publish_bundle(*bob, NULL, blen), GY_OK);
    ASSERT_TRUE(*blen > 0, "bundle has a size");
    ASSERT_EQ(gy_publish_bundle(*bob, bundle, blen), GY_OK);
}

/* ---- tests ------------------------------------------------------------- */

TEST(api_end_to_end)
{
    gy_custodian *alice, *bob;
    uint8_t bundle[1024], msg[1024], out[256];
    size_t blen = 0, mlen, olen;
    uint8_t pt1[6] = "hello!", pt2[3] = "hi", fp[GY_FINGERPRINT_MAX];
    size_t fplen = 0;

    bring_up(&alice, &bob, bundle, &blen);

    /* Initiation: Alice starts a session to Bob and sends the first message. */
    ASSERT_EQ(gy_send_open(alice), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(alice, BUID, sizeof(BUID), BDID, sizeof(BDID), bundle,
                          blen, pt1, sizeof(pt1), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(alice), GY_OK);

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(bob, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_EQ(olen, sizeof(pt1));
    ASSERT_TRUE(memcmp(out, pt1, sizeof(pt1)) == 0, "initiation plaintext");
    ASSERT_EQ(g_bm.n_consumed, 1); /* one OPK burned */

    /* Established: a second message over the same session. */
    ASSERT_EQ(gy_send_open(alice), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_encrypt(alice, BUID, sizeof(BUID), BDID, sizeof(BDID), pt2,
                         sizeof(pt2), msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(alice), GY_OK);

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(bob, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_EQ(olen, sizeof(pt2));
    ASSERT_TRUE(memcmp(out, pt2, sizeof(pt2)) == 0, "established plaintext");

    /* Fingerprint surface (size query then write) and PQ-pending. */
    ASSERT_EQ(gy_self_fingerprint(alice, NULL, &fplen), GY_OK);
    ASSERT_TRUE(fplen > 0 && fplen <= GY_FINGERPRINT_MAX, "fp size");
    ASSERT_EQ(gy_self_fingerprint(alice, fp, &fplen), GY_OK);
    ASSERT_EQ(gy_pq_pending(bob, AUID, sizeof(AUID), ADID, sizeof(ADID)),
              GY_PQ_NOT_APPLICABLE);

    gy_custodian_close(alice);
    gy_custodian_close(bob);
}

TEST(api_rollback_and_purge)
{
    gy_custodian *alice, *bob;
    uint8_t bundle[1024], msg[1024], out[256];
    size_t blen = 0, mlen, olen;
    uint8_t pt[3] = "yo";

    bring_up(&alice, &bob, bundle, &blen);

    /* A rolled-back initiation stages nothing on Alice's store. */
    ASSERT_EQ(gy_send_open(alice), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(alice, BUID, sizeof(BUID), BDID, sizeof(BDID), bundle,
                          blen, pt, sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    gy_rollback(alice);
    ASSERT_EQ(mcount(&g_am, GY_RECORD_SESSION), 0);

    /* A committed initiation lands, then Bob receives and Alice purges. */
    ASSERT_EQ(gy_send_open(alice), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(alice, BUID, sizeof(BUID), BDID, sizeof(BDID), bundle,
                          blen, pt, sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(alice), GY_OK);
    ASSERT_EQ(mcount(&g_am, GY_RECORD_SESSION), 1);

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(bob, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_EQ(mcount(&g_bm, GY_RECORD_SESSION), 1);

    /* Bob purges Alice's device: sessions and the device record are gone. */
    ASSERT_EQ(gy_purge_device(bob, AUID, sizeof(AUID), ADID, sizeof(ADID)),
              GY_OK);
    ASSERT_EQ(mcount(&g_bm, GY_RECORD_SESSION), 0);
    ASSERT_EQ(mcount(&g_bm, GY_RECORD_DEVICE), 0);

    gy_custodian_close(alice);
    gy_custodian_close(bob);
}

TEST(api_size_queries_and_errors)
{
    gy_custodian *c = NULL;
    size_t need = 0;
    uint8_t pt[3] = "hi";

    mstore_bind(&g_am, &g_acb);

    /* Unknown suite and NULL out are rejected. */
    ASSERT_EQ(gy_custodian_create(&c, 0x7F, &g_acb, ACRED, sizeof(ACRED) - 1,
                                  AUID, sizeof(AUID), ADID, sizeof(ADID), NULL,
                                  NULL, NULL),
              GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_create(NULL, GY_SUITE_C25519, &g_acb, ACRED,
                                  sizeof(ACRED) - 1, AUID, sizeof(AUID), ADID,
                                  sizeof(ADID), NULL, NULL, NULL),
              GY_ERR_ARG);

    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_C25519, &g_acb, ACRED,
                                  sizeof(ACRED) - 1, AUID, sizeof(AUID), ADID,
                                  sizeof(ADID), NULL, NULL, NULL),
              GY_OK);
    /* Publishing/sending before identity generation is a state error. */
    ASSERT_EQ(gy_publish_bundle(c, NULL, &need), GY_ERR_STATE);
    ASSERT_EQ(gy_send_open(c), GY_ERR_STATE);

    ASSERT_EQ(gy_custodian_generate_identity(c, 1000, 1), GY_OK);
    ASSERT_EQ(gy_send_open(c), GY_OK);
    /* Encrypt size query does not require the buffer. */
    need = 0;
    ASSERT_EQ(gy_encrypt(c, BUID, sizeof(BUID), BDID, sizeof(BDID), pt,
                         sizeof(pt), NULL, &need),
              GY_OK);
    ASSERT_TRUE(need > sizeof(pt), "enveloped size exceeds plaintext");
    gy_rollback(c);

    gy_custodian_close(c);
    gy_custodian_close(NULL); /* safe on NULL */
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(api_end_to_end),
        GY_TEST(api_rollback_and_purge),
        GY_TEST(api_size_queries_and_errors),
    };

    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
