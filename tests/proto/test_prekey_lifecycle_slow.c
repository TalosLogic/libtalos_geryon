/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Prekey lifecycle: SPK rotation with bounded history and
 * old-SPK-still-receives, OPK replenishment/stats, granular publish
 * (registration-only / OPK-batch-only), PKID discovery/deletion, and the
 * gy_bundle_assemble round trip against a real custodian.  create/
 * generate_identity run a real Argon2id derivation, so this file is tagged
 * _slow.
 */

#include <stdint.h>
#include <string.h>

#include "custodian.h"
#include "envelope.h"
#include "geryon.h"

#include "gy_test.h"

/* ---- minimal two-party mock store (public int-kind callbacks) ---------- */

#define MOCK_MAX 16
#define MOCK_BLOB 90000
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
m_consume(void *ctx, uint32_t pkid)
{
    struct mstore *m = ctx;

    (void)pkid;
    m->n_consumed++;
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

static const uint8_t AUID[4] = {0xA1, 1, 1, 1}, ADID[4] = {0xA1, 2, 2, 2};
static const uint8_t BUID[4] = {0xB2, 1, 1, 1}, BDID[4] = {0xB2, 2, 2, 2};
static const uint8_t ACRED[] = "prekey lifecycle credential A";
static const uint8_t BCRED[] = "prekey lifecycle credential B";

static void
bring_up(struct gy_custodian **a, struct mstore *am, gy_store_callbacks *acb,
         struct gy_custodian **b, struct mstore *bm, gy_store_callbacks *bcb,
         size_t n_opks)
{
    mstore_bind(am, acb);
    mstore_bind(bm, bcb);
    ASSERT_EQ(gy_custodian_create(a, GY_SUITE_C25519, acb, ACRED,
                                  sizeof(ACRED) - 1, AUID, sizeof(AUID), ADID,
                                  sizeof(ADID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_create(b, GY_SUITE_C25519, bcb, BCRED,
                                  sizeof(BCRED) - 1, BUID, sizeof(BUID), BDID,
                                  sizeof(BDID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(*a, 1000, n_opks), GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(*b, 1000, n_opks), GY_OK);
}

/* ---- tests --------------------------------------------------------------*/

TEST(rotate_retains_history_and_old_bundle_still_receives)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    uint8_t old_bundle[1024], msg[2048], out[256];
    size_t old_blen, mlen, olen;
    static const uint8_t pt[5] = "hello";
    gy_key_handle h_old_spk;

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 0);

    /* Bob's bundle carries SPK v1. */
    old_blen = sizeof(old_bundle);
    ASSERT_EQ(gy_publish_bundle(b, old_bundle, &old_blen), GY_OK);

    /* Bob rotates: v2 is now active, v1 retained in history. */
    ASSERT_EQ(gy_custodian_rotate_signed_prekey(b, 2000), GY_OK);

    /* Alice initiates using the STALE (v1) bundle; Bob still receives it. */
    ASSERT_EQ(gy_send_open(a), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(a, BUID, sizeof(BUID), BDID, sizeof(BDID), old_bundle,
                          old_blen, pt, sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(a), GY_OK);

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_EQ(olen, sizeof(pt));
    ASSERT_MEMEQ(out, pt, sizeof(pt));

    /* The superseded SPK (v1) is still a live, findable handle. */
    h_old_spk = gy_custodian_find_prekey(b, GY_PK_SPK, b->spks[1].kp.pub.pkid);
    ASSERT_TRUE(h_old_spk != GY_KEY_HANDLE_INVALID, "v1 SPK still findable");

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(rotate_evicts_oldest_once_history_is_full)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    uint32_t first_pkid;
    int i;

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 0);

    first_pkid = b->spks[0].kp.pub.pkid;
    ASSERT_TRUE(gy_custodian_find_prekey(b, GY_PK_SPK, first_pkid) !=
                    GY_KEY_HANDLE_INVALID,
                "the first SPK starts out findable");

    /* Rotate enough times to push the very first SPK out of history. */
    for (i = 0; i < GY_CUSTODIAN_SPK_HISTORY_MAX; i++)
        ASSERT_EQ(gy_custodian_rotate_signed_prekey(b, 1000 + (uint64_t)i + 1),
                  GY_OK);

    ASSERT_EQ(gy_custodian_find_prekey(b, GY_PK_SPK, first_pkid),
              GY_KEY_HANDLE_INVALID);
    ASSERT_EQ(b->n_spks, GY_CUSTODIAN_SPK_HISTORY_MAX);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(opk_replenish_consume_and_stats)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    uint8_t bundle[1024], msg[2048], out[256];
    size_t blen, mlen, olen, total, used, unused;
    static const uint8_t pt[5] = "hello";

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 2);

    ASSERT_EQ(gy_custodian_opk_stats(b, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 2);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(unused, 2);

    /* Publishing a one-shot bundle RESERVES its OPK (reserve-on-export): the
     * emitted one-time key is marked used so it is never handed out again,
     * though its private key is retained for the pending handshake. */
    blen = sizeof(bundle);
    ASSERT_EQ(gy_publish_bundle(b, bundle, &blen), GY_OK);
    ASSERT_EQ(gy_custodian_opk_stats(b, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 2);
    ASSERT_EQ(used, 1); /* reserved by the publish */
    ASSERT_EQ(unused, 1);

    ASSERT_EQ(gy_send_open(a), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(a, BUID, sizeof(BUID), BDID, sizeof(BDID), bundle,
                          blen, pt, sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(a), GY_OK);
    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);

    /* Delete-on-use: the OPK that established the session is destroyed, so it
     * drops out of the pool entirely (total falls), not merely flagged. */
    ASSERT_EQ(gy_custodian_opk_stats(b, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 1);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(unused, 1);

    /* Replenish: pool grows, new keys are unused (the freed slot is reused). */
    ASSERT_EQ(gy_custodian_generate_onetime_prekeys(b, 3), GY_OK);
    ASSERT_EQ(gy_custodian_opk_stats(b, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 4);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(unused, 4);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(publish_opk_batch_is_parseable_and_registration_never_carries_one)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    const struct gy_suite_desc *desc;
    uint8_t reg[512], batch[1024];
    struct gy_public_key parsed[8];
    size_t reglen, batchlen, n;
    struct gy_prekey_bundle parsed_reg;

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 2);
    desc = b->desc;

    reglen = sizeof(reg);
    ASSERT_EQ(gy_custodian_publish_registration(b, reg, &reglen), GY_OK);
    ASSERT_EQ(gy_bundle_parse(&parsed_reg, desc, reg, reglen), GY_OK);
    ASSERT_EQ(parsed_reg.opk.pkid, 0);

    batchlen = sizeof(batch);
    ASSERT_EQ(gy_custodian_publish_opk_batch(b, batch, &batchlen), GY_OK);
    ASSERT_EQ(gy_opk_batch_parse(parsed, 8, &n, desc, batch, batchlen), GY_OK);
    ASSERT_EQ(n, 2);
    ASSERT_TRUE(parsed[0].pkid != 0 && parsed[1].pkid != 0,
                "batch entries carry real PKIDs");

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(find_and_delete_prekey)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    gy_key_handle h_active_spk, h_opk;
    uint32_t opk_pkid;

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 1);

    h_active_spk =
        gy_custodian_find_prekey(b, GY_PK_SPK, b->spks[0].kp.pub.pkid);
    ASSERT_TRUE(h_active_spk != GY_KEY_HANDLE_INVALID, "active SPK findable");
    ASSERT_EQ(gy_custodian_delete_prekey(b, h_active_spk), GY_ERR_STATE);

    opk_pkid = b->opks[0].pub.pkid;
    h_opk = gy_custodian_find_prekey(b, GY_PK_OPK, opk_pkid);
    ASSERT_TRUE(h_opk != GY_KEY_HANDLE_INVALID, "OPK findable");
    ASSERT_EQ(gy_custodian_delete_prekey(b, h_opk), GY_OK);
    ASSERT_EQ(gy_custodian_find_prekey(b, GY_PK_OPK, opk_pkid),
              GY_KEY_HANDLE_INVALID);

    /* An unknown/stale handle is rejected. */
    ASSERT_EQ(gy_custodian_delete_prekey(b, h_opk), GY_ERR_NOT_FOUND);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(bundle_assemble_roundtrip_against_a_real_custodian)
{
    static struct mstore am, bm;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *a, *b;
    const struct gy_suite_desc *desc;
    uint8_t reg[512], batch[1024], assembled[1024], msg[2048], out[256];
    size_t reglen, batchlen, asmlen, mlen, olen, total, used, unused;
    struct gy_public_key opks[8];
    size_t n_opks;
    size_t kw;
    static const uint8_t pt[5] = "howdy";

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 2);
    desc = b->desc;
    kw = 4 + 1 + desc->curve_pk_len;

    reglen = sizeof(reg);
    ASSERT_EQ(gy_custodian_publish_registration(b, reg, &reglen), GY_OK);
    batchlen = sizeof(batch);
    ASSERT_EQ(gy_custodian_publish_opk_batch(b, batch, &batchlen), GY_OK);
    ASSERT_EQ(gy_opk_batch_parse(opks, 8, &n_opks, desc, batch, batchlen),
              GY_OK);
    ASSERT_TRUE(n_opks > 0, "batch has at least one OPK");

    /* "Server" slices one raw per-key entry (4-byte batch header, then
     * kw-byte entries) and assembles the fetch bundle. */
    asmlen = sizeof(assembled);
    ASSERT_EQ(
        gy_bundle_assemble(reg, reglen, batch + 4, kw, assembled, &asmlen),
        GY_OK);

    ASSERT_EQ(gy_send_open(a), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(a, BUID, sizeof(BUID), BDID, sizeof(BDID), assembled,
                          asmlen, pt, sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(a), GY_OK);

    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_MEMEQ(out, pt, sizeof(pt));

    /* The OPK the assembled bundle used is destroyed on receipt (delete-on-use),
     * so it leaves the pool entirely; the granular publish_opk_batch path does
     * not reserve, so the OTHER OPK is still unused and available. */
    ASSERT_EQ(gy_custodian_opk_stats(b, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 1);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(unused, 1);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

TEST(publish_bundle_reserves_distinct_opks_and_delete_on_use)
{
    static struct mstore am, bm, cm;
    gy_store_callbacks acb, bcb, ccb;
    struct gy_custodian *a, *b, *cinit;
    const struct gy_suite_desc *desc;
    struct gy_prekey_bundle pb1, pb2, pb3;
    struct gy_public_key batch_opks[8];
    static const uint8_t CUID[4] = {0xC3, 1, 1, 1}, CDID[4] = {0xC3, 2, 2, 2};
    static const uint8_t CCRED[] = "prekey lifecycle credential C";
    uint8_t b1[1024], b2[1024], b3[1024], batch[1024];
    uint8_t msg[2048], msg2[2048], out[256];
    size_t l1, l2, l3, batchlen, n_batch, mlen, mlen2, olen;
    static const uint8_t pt[5] = "hello";

    bring_up(&a, &am, &acb, &b, &bm, &bcb, 2); /* Bob starts with 2 OPKs */
    desc = b->desc;

    /* Reserve-on-export: each one-shot publish hands out a DISTINCT OPK. */
    l1 = sizeof(b1);
    ASSERT_EQ(gy_publish_bundle(b, b1, &l1), GY_OK);
    ASSERT_EQ(gy_bundle_parse(&pb1, desc, b1, l1), GY_OK);
    l2 = sizeof(b2);
    ASSERT_EQ(gy_publish_bundle(b, b2, &l2), GY_OK);
    ASSERT_EQ(gy_bundle_parse(&pb2, desc, b2, l2), GY_OK);
    ASSERT_TRUE(pb1.opk.pkid != 0 && pb2.opk.pkid != 0,
                "each one-shot bundle carries an OPK");
    ASSERT_TRUE(pb1.opk.pkid != pb2.opk.pkid,
                "a distinct OPK per publish (no reuse across bundles)");

    /* Both originals are now reserved, so the granular batch excludes them. */
    batchlen = sizeof(batch);
    ASSERT_EQ(gy_custodian_publish_opk_batch(b, batch, &batchlen), GY_OK);
    ASSERT_EQ(
        gy_opk_batch_parse(batch_opks, 8, &n_batch, desc, batch, batchlen),
        GY_OK);
    ASSERT_EQ(n_batch, 0);

    /* Pool spent: the next one-shot publish auto-generates a fresh OPK. */
    l3 = sizeof(b3);
    ASSERT_EQ(gy_publish_bundle(b, b3, &l3), GY_OK);
    ASSERT_EQ(gy_bundle_parse(&pb3, desc, b3, l3), GY_OK);
    ASSERT_TRUE(pb3.opk.pkid != 0 && pb3.opk.pkid != pb1.opk.pkid &&
                    pb3.opk.pkid != pb2.opk.pkid,
                "auto-generated a fresh distinct OPK when the pool was spent");

    /* Delete-on-use: Alice establishes a session from bundle 1; Bob destroys
     * that OPK, so it is no longer findable. */
    ASSERT_EQ(gy_send_open(a), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(a, BUID, sizeof(BUID), BDID, sizeof(BDID), b1, l1, pt,
                          sizeof(pt), NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(a), GY_OK);
    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, AUID, sizeof(AUID), ADID, sizeof(ADID), msg, mlen,
                         out, &olen),
              GY_OK);
    ASSERT_EQ(gy_custodian_find_prekey(b, GY_PK_OPK, pb1.opk.pkid),
              GY_KEY_HANDLE_INVALID);

    /* Reuse is impossible: a DIFFERENT initiator using the same bundle (hence
     * the same, now-deleted OPK) cannot establish a second session. */
    mstore_bind(&cm, &ccb);
    ASSERT_EQ(gy_custodian_create(&cinit, GY_SUITE_C25519, &ccb, CCRED,
                                  sizeof(CCRED) - 1, CUID, sizeof(CUID), CDID,
                                  sizeof(CDID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(cinit, 1000, 1), GY_OK);
    ASSERT_EQ(gy_send_open(cinit), GY_OK);
    mlen2 = sizeof(msg2);
    ASSERT_EQ(gy_initiate(cinit, BUID, sizeof(BUID), BDID, sizeof(BDID), b1, l1,
                          pt, sizeof(pt), NULL, msg2, &mlen2),
              GY_OK);
    ASSERT_EQ(gy_commit(cinit), GY_OK);
    olen = sizeof(out);
    ASSERT_EQ(gy_receive(b, CUID, sizeof(CUID), CDID, sizeof(CDID), msg2, mlen2,
                         out, &olen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
    gy_custodian_close(cinit);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(rotate_retains_history_and_old_bundle_still_receives),
            GY_TEST(rotate_evicts_oldest_once_history_is_full),
            GY_TEST(opk_replenish_consume_and_stats),
            GY_TEST(
                publish_opk_batch_is_parseable_and_registration_never_carries_one),
            GY_TEST(find_and_delete_prekey),
            GY_TEST(bundle_assemble_roundtrip_against_a_real_custodian),
            GY_TEST(publish_bundle_reserves_distinct_opks_and_delete_on_use),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
