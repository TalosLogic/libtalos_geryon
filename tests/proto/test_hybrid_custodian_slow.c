/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Hybrid custodian identity material (GER-M5-08b b-iii-1): a hybrid-suite
 * custodian generates its hybrid identity + signed prekey + OPK batch, seals
 * them as the hybrid idmat, and recovers them across a close/open round-trip.
 * create/open run real Argon2id (via gy_keystore_*), so this file is _slow.
 * Uses the internal custodian.h to inspect the composed gy_hybrid_custodian.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "custodian.h"
#include "envelope.h"
#include "geryon.h"

#include "gy_test.h"

/* ---- in-memory store: identity blob sized to the (large) hybrid material --- */

#define MOCK_MAX 16
/* Hybrid session records are large (GY_SESSION_BLOB_MAX), plus sealed-store
 * overhead; the two-party end-to-end test persists them through this store. */
#define MOCK_REC_BLOB (GY_SESSION_BLOB_MAX + 2048)
#define MOCK_IDENT_BLOB GY_CUST_BLOB_MAX /* header + sealed hybrid idmat */

struct mrec {
    int in_use, kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len, blob_len;
    uint8_t blob[MOCK_REC_BLOB];
};

struct mstore {
    struct mrec recs[MOCK_MAX];
    uint8_t identity[MOCK_IDENT_BLOB];
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

    if (blob_len > MOCK_REC_BLOB)
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

    if (blob_len > MOCK_IDENT_BLOB)
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

/* ---- test -------------------------------------------------------------- */

TEST(hybrid_identity_roundtrip)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    struct gy_hybrid_custodian *hc;
    struct gy_hybrid_identity_public_key saved_ik;
    uint32_t saved_spk_pkid, saved_opk_pkid;
    const char *cred = "correct horse battery staple";
    static const uint8_t uid[] = "user-1";
    static const uint8_t did[] = "device-1";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_H25519_512, &cb,
                                  (const uint8_t *)cred, strlen(cred), uid,
                                  sizeof(uid) - 1, did, sizeof(did) - 1, NULL,
                                  NULL, NULL),
              GY_OK);
    ASSERT_TRUE(c != NULL, "created hybrid custodian");
    ASSERT_TRUE(c->desc->is_hybrid, "custodian is hybrid");

    ASSERT_EQ(gy_custodian_generate_identity(c, 0x11223344, 3), GY_OK);
    ASSERT_EQ(c->have_identity, 1);

    hc = (struct gy_hybrid_custodian *)c;
    ASSERT_EQ(hc->n_hspks, 1);
    ASSERT_EQ(hc->n_hopks, 3);
    saved_ik = hc->hik.pub;
    saved_spk_pkid = hc->hspks[0].kp.pub.curve.pkid;
    saved_opk_pkid = hc->hopks[0].pub.curve.pkid;
    /* The classical base identity stays unused (zero) for a hybrid custodian. */
    ASSERT_EQ(hc->base.ik.pub.curve_type, 0);

    gy_custodian_close(c);

    /* Reopen recovers the sealed hybrid identity material exactly. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred, strlen(cred)),
              GY_OK);
    ASSERT_TRUE(c != NULL, "reopened hybrid custodian");
    ASSERT_EQ(c->suite_id, GY_SUITE_H25519_512);
    ASSERT_EQ(c->have_identity, 1);

    hc = (struct gy_hybrid_custodian *)c;
    ASSERT_EQ(hc->n_hspks, 1);
    ASSERT_EQ(hc->n_hopks, 3);
    ASSERT_TRUE(memcmp(&hc->hik.pub, &saved_ik, sizeof(saved_ik)) == 0,
                "hybrid identity key recovered");
    ASSERT_EQ(hc->hspks[0].kp.pub.curve.pkid, saved_spk_pkid);
    ASSERT_EQ(hc->hopks[0].pub.curve.pkid, saved_opk_pkid);

    gy_custodian_close(c);
}

/*
 * Hybrid prekey lifecycle (b-iii-2a): SPK rotation pushes a fresh signed prekey
 * to the front and retains history; OPK replenishment fills free slots; both
 * survive a persistence round-trip.
 */
TEST(hybrid_prekey_lifecycle)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    struct gy_hybrid_custodian *hc;
    uint32_t first_spk_pkid, rotated_spk_pkid;
    size_t total, used, unused;
    const char *cred = "correct horse battery staple";
    static const uint8_t uid[] = "u";
    static const uint8_t did[] = "d";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_H25519_512, &cb,
                                  (const uint8_t *)cred, strlen(cred), uid,
                                  sizeof(uid) - 1, did, sizeof(did) - 1, NULL,
                                  NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(c, 100, 2), GY_OK);
    hc = (struct gy_hybrid_custodian *)c;
    first_spk_pkid = hc->hspks[0].kp.pub.curve.pkid;

    ASSERT_EQ(gy_custodian_opk_stats(c, &total, &used, &unused), GY_OK);
    ASSERT_EQ(total, 2);
    ASSERT_EQ(used, 0);
    ASSERT_EQ(unused, 2);

    /* Rotate: new SPK at front, previous retained (history depth 2). */
    ASSERT_EQ(gy_custodian_rotate_signed_prekey(c, 200), GY_OK);
    ASSERT_EQ(hc->n_hspks, 2);
    rotated_spk_pkid = hc->hspks[0].kp.pub.curve.pkid;
    ASSERT_TRUE(rotated_spk_pkid != first_spk_pkid, "rotation changed the SPK");
    ASSERT_EQ(hc->hspks[1].kp.pub.curve.pkid, first_spk_pkid);

    /* Replenish OPKs: 2 + 3 = 5 held. */
    ASSERT_EQ(gy_custodian_generate_onetime_prekeys(c, 3), GY_OK);
    ASSERT_EQ(hc->n_hopks, 5);
    ASSERT_EQ(gy_custodian_opk_stats(c, &total, NULL, NULL), GY_OK);
    ASSERT_EQ(total, 5);

    gy_custodian_close(c);

    /* Persistence preserves the rotated SPK history and the OPK pool. */
    ASSERT_EQ(gy_custodian_open(&c, &cb, (const uint8_t *)cred, strlen(cred)),
              GY_OK);
    hc = (struct gy_hybrid_custodian *)c;
    ASSERT_EQ(hc->n_hspks, 2);
    ASSERT_EQ(hc->hspks[0].kp.pub.curve.pkid, rotated_spk_pkid);
    ASSERT_EQ(hc->hspks[1].kp.pub.curve.pkid, first_spk_pkid);
    ASSERT_EQ(hc->n_hopks, 5);
    ASSERT_EQ(gy_custodian_opk_stats(c, &total, NULL, NULL), GY_OK);
    ASSERT_EQ(total, 5);

    gy_custodian_close(c);
}

/*
 * Hybrid publish (b-iii-2b): a published bundle round-trips through the §5.4
 * wire format and passes full dual-signature validation; registration carries
 * no OPK; the OPK batch enumerates the unconsumed pool.
 */
TEST(hybrid_publish)
{
    static struct mstore m;
    gy_store_callbacks cb;
    struct gy_custodian *c;
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle pb;
    static struct gy_hybrid_public_key opks[GY_OPK_BATCH_MAX];
    uint8_t *buf;
    size_t blen, n, batch_n;
    uint8_t diag;
    const char *cred = "correct horse battery staple";
    static const uint8_t uid[] = "u";
    static const uint8_t did[] = "d";

    mstore_bind(&m, &cb);
    ASSERT_EQ(gy_custodian_create(&c, GY_SUITE_H25519_512, &cb,
                                  (const uint8_t *)cred, strlen(cred), uid,
                                  sizeof(uid) - 1, did, sizeof(did) - 1, NULL,
                                  NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(c, 100, 2), GY_OK);

    /* One-shot bundle: reserves an OPK, round-trips, validates (both sigs). */
    blen = 0;
    ASSERT_EQ(gy_custodian_publish_bundle(c, NULL, &blen), GY_OK);
    ASSERT_EQ(blen, gy_hybrid_bundle_wire_len(desc));
    buf = malloc(blen);
    ASSERT_TRUE(buf != NULL, "alloc bundle buf");
    n = blen;
    ASSERT_EQ(gy_custodian_publish_bundle(c, buf, &n), GY_OK);
    ASSERT_EQ(n, blen);
    ASSERT_EQ(gy_hybrid_bundle_parse(&pb, desc, buf, n), GY_OK);
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &pb, &diag), GY_OK);
    ASSERT_TRUE(pb.opk.curve.pkid != 0, "bundle carries an OPK");

    /* Registration: same wire size, OPK all-zeros, still validates. */
    n = blen;
    ASSERT_EQ(gy_custodian_publish_registration(c, buf, &n), GY_OK);
    ASSERT_EQ(gy_hybrid_bundle_parse(&pb, desc, buf, n), GY_OK);
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &pb, &diag), GY_OK);
    ASSERT_EQ(pb.opk.curve.pkid, 0);
    free(buf);

    /* OPK batch: one OPK is reserved (exported), so one unconsumed remains. */
    blen = 0;
    ASSERT_EQ(gy_custodian_publish_opk_batch(c, NULL, &blen), GY_OK);
    buf = malloc(blen);
    ASSERT_TRUE(buf != NULL, "alloc batch buf");
    n = blen;
    ASSERT_EQ(gy_custodian_publish_opk_batch(c, buf, &n), GY_OK);
    ASSERT_EQ(gy_hybrid_opk_batch_parse(opks, GY_OPK_BATCH_MAX, &batch_n, desc,
                                        buf, n),
              GY_OK);
    ASSERT_EQ(batch_n, 1);
    free(buf);

    gy_custodian_close(c);
}

/* device / user identifiers for the two-party exchange. */
static const uint8_t E_AUID[] = "alice";
static const uint8_t E_ADID[] = "alice-dev";
static const uint8_t E_BUID[] = "bob";
static const uint8_t E_BDID[] = "bob-dev";

/*
 * Full hybrid exchange through the PUBLIC API (b-iii-3): two hybrid custodians
 * complete an initiation and a reply, plaintext round-trips both directions, and
 * gy_pq_pending advances from PENDING to CONFIRMED as the responder's KEM
 * confirmation reaches the initiator (HYBRID_SPEC section 8.4).  gy_encrypt /
 * gy_receive dispatch on the session suite; gy_initiate routes to the hybrid
 * send path; gy_self_fingerprint reports each hybrid IKhash.
 */
TEST(hybrid_api_end_to_end)
{
    static struct mstore ma, mb;
    gy_store_callbacks acb, bcb;
    struct gy_custodian *alice, *bob;
    const char *acred = "alice hybrid credential";
    const char *bcred = "bob hybrid credential";
    static uint8_t bundle[16384];
    static uint8_t msg[16384];
    uint8_t pt[128], fp_a[GY_HASH_MAX], fp_b[GY_HASH_MAX];
    static const uint8_t m1[] = "alice to bob, first hybrid message";
    static const uint8_t m2[] = "bob to alice, hybrid reply";
    size_t blen, mlen, ptlen, fplen_a, fplen_b;

    mstore_bind(&ma, &acb);
    mstore_bind(&mb, &bcb);

    ASSERT_EQ(gy_custodian_create(&alice, GY_SUITE_H25519_512, &acb,
                                  (const uint8_t *)acred, strlen(acred), E_AUID,
                                  sizeof(E_AUID) - 1, E_ADID,
                                  sizeof(E_ADID) - 1, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_create(&bob, GY_SUITE_H25519_512, &bcb,
                                  (const uint8_t *)bcred, strlen(bcred), E_BUID,
                                  sizeof(E_BUID) - 1, E_BDID,
                                  sizeof(E_BDID) - 1, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(alice, 1000, 4), GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(bob, 1000, 4), GY_OK);

    /* bob publishes a one-shot hybrid bundle. */
    blen = sizeof(bundle);
    ASSERT_EQ(gy_publish_bundle(bob, bundle, &blen), GY_OK);

    /* alice initiates to bob and sends the first message. */
    ASSERT_EQ(gy_send_open(alice), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_initiate(alice, E_BUID, sizeof(E_BUID) - 1, E_BDID,
                          sizeof(E_BDID) - 1, bundle, blen, m1, sizeof(m1) - 1,
                          NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(alice), GY_OK);

    /* alice is PQ-pending until bob's confirmation returns. */
    ASSERT_EQ(gy_pq_pending(alice, E_BUID, sizeof(E_BUID) - 1, E_BDID,
                            sizeof(E_BDID) - 1),
              GY_PQ_PENDING);

    /* bob receives it. */
    ptlen = sizeof(pt);
    ASSERT_EQ(gy_receive(bob, E_AUID, sizeof(E_AUID) - 1, E_ADID,
                         sizeof(E_ADID) - 1, msg, mlen, pt, &ptlen),
              GY_OK);
    ASSERT_EQ(ptlen, sizeof(m1) - 1);
    ASSERT_TRUE(memcmp(pt, m1, ptlen) == 0, "bob recovers m1");

    /* bob replies; its first send carries the KEM confirmation. */
    ASSERT_EQ(gy_send_open(bob), GY_OK);
    mlen = sizeof(msg);
    ASSERT_EQ(gy_encrypt(bob, E_AUID, sizeof(E_AUID) - 1, E_ADID,
                         sizeof(E_ADID) - 1, m2, sizeof(m2) - 1, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(bob), GY_OK);

    /* alice receives the reply and processes the confirmation. */
    ptlen = sizeof(pt);
    ASSERT_EQ(gy_receive(alice, E_BUID, sizeof(E_BUID) - 1, E_BDID,
                         sizeof(E_BDID) - 1, msg, mlen, pt, &ptlen),
              GY_OK);
    ASSERT_EQ(ptlen, sizeof(m2) - 1);
    ASSERT_TRUE(memcmp(pt, m2, ptlen) == 0, "alice recovers m2");

    /* alice's PQ authentication of bob is now confirmed. */
    ASSERT_EQ(gy_pq_pending(alice, E_BUID, sizeof(E_BUID) - 1, E_BDID,
                            sizeof(E_BDID) - 1),
              GY_PQ_CONFIRMED);

    /* self-fingerprints: size query then fill; the two identities differ. */
    fplen_a = 0;
    ASSERT_EQ(gy_self_fingerprint(alice, NULL, &fplen_a), GY_OK);
    ASSERT_TRUE(fplen_a > 0 && fplen_a <= GY_HASH_MAX, "fp size sane");
    ASSERT_EQ(gy_self_fingerprint(alice, fp_a, &fplen_a), GY_OK);
    fplen_b = sizeof(fp_b);
    ASSERT_EQ(gy_self_fingerprint(bob, fp_b, &fplen_b), GY_OK);
    ASSERT_EQ(fplen_a, fplen_b);
    ASSERT_TRUE(memcmp(fp_a, fp_b, fplen_a) != 0, "distinct hybrid identities");

    gy_custodian_close(alice);
    gy_custodian_close(bob);
}

int
main(void)
{
    if (gy_suite_desc(GY_SUITE_H25519_512) == NULL)
        return 1;
    {
        static const struct gy_test_case cases[] = {
            GY_TEST(hybrid_identity_roundtrip),
            GY_TEST(hybrid_prekey_lifecycle),
            GY_TEST(hybrid_publish),
            GY_TEST(hybrid_api_end_to_end),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
