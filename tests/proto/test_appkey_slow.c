/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Application signing key: generation, certificate export,
 * domain-separated signing, verification round-trip (gy_appkey_verify),
 * rotation with bounded history (old SAK still signs/verifies until
 * evicted), and the guarantee that gy_custodian_sign never returns the SAK
 * private key.  create/generate_identity run a real Argon2id derivation, so
 * this file is tagged _slow.
 */

#include <stdint.h>
#include <string.h>

#include "custodian.h"
#include "geryon.h"

#include "gy_test.h"

/* ---- minimal mock store (public int-kind callbacks) --------------------- */

#define MOCK_MAX 8
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

static const uint8_t AUID[4] = {0xA1, 1, 1, 1}, ADID[4] = {0xA1, 2, 2, 2};
static const uint8_t ACRED[] = "appkey test credential";

static void
bring_up(struct gy_custodian **a, struct mstore *am, gy_store_callbacks *acb)
{
    mstore_bind(am, acb);
    ASSERT_EQ(gy_custodian_create(a, GY_SUITE_C25519, acb, ACRED,
                                  sizeof(ACRED) - 1, AUID, sizeof(AUID), ADID,
                                  sizeof(ADID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(*a, 1000, 0), GY_OK);
}

/* ---- tests --------------------------------------------------------------*/

TEST(generate_export_sign_and_verify_roundtrip)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h;
    uint8_t cert[512], sig[GY_SIG_MAX];
    size_t certlen, siglen;
    static const uint8_t app_ctx[] = "rest-api-v1";
    static const uint8_t msg[] = "nonce=deadbeef;ts=1000";

    bring_up(&a, &am, &acb);

    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h), GY_OK);
    ASSERT_TRUE(h != GY_KEY_HANDLE_INVALID, "generate returns a real handle");

    certlen = sizeof(cert);
    ASSERT_EQ(gy_custodian_export_appkey_cert(a, h, cert, &certlen), GY_OK);

    siglen = sizeof(sig);
    ASSERT_EQ(gy_custodian_sign(a, h, app_ctx, sizeof(app_ctx) - 1, msg,
                                sizeof(msg) - 1, sig, &siglen),
              GY_OK);
    ASSERT_EQ(siglen, a->desc->sig_len);

    ASSERT_EQ(gy_appkey_verify(a->ik.pub.pk, a->desc->curve_pk_len, cert,
                               certlen, app_ctx, sizeof(app_ctx) - 1, msg,
                               sizeof(msg) - 1, sig, siglen, 500),
              GY_OK);

    gy_custodian_close(a);
}

TEST(generate_twice_is_rejected_rotate_needs_one_first)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h;

    bring_up(&a, &am, &acb);

    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h), GY_OK);
    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h), GY_ERR_STATE);

    gy_custodian_close(a);

    bring_up(&a, &am, &acb);
    ASSERT_EQ(gy_custodian_rotate_appkey(a, 0, &h), GY_ERR_STATE);
    gy_custodian_close(a);
}

TEST(rotate_retains_history_and_old_sak_still_works)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h1, h2;
    uint8_t cert1[512], sig1[GY_SIG_MAX];
    size_t cert1len, sig1len;
    static const uint8_t app_ctx[] = "ctx";
    static const uint8_t msg[] = "msg";

    bring_up(&a, &am, &acb);

    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h1), GY_OK);
    cert1len = sizeof(cert1);
    ASSERT_EQ(gy_custodian_export_appkey_cert(a, h1, cert1, &cert1len), GY_OK);

    ASSERT_EQ(gy_custodian_rotate_appkey(a, 0, &h2), GY_OK);
    ASSERT_TRUE(h2 != h1, "rotation returns a different handle");

    /* The OLD (now superseded) SAK still signs and its OLD cert still
     * verifies against it - retained history. */
    sig1len = sizeof(sig1);
    ASSERT_EQ(gy_custodian_sign(a, h1, app_ctx, sizeof(app_ctx) - 1, msg,
                                sizeof(msg) - 1, sig1, &sig1len),
              GY_OK);
    ASSERT_EQ(gy_appkey_verify(a->ik.pub.pk, a->desc->curve_pk_len, cert1,
                               cert1len, app_ctx, sizeof(app_ctx) - 1, msg,
                               sizeof(msg) - 1, sig1, sig1len, 500),
              GY_OK);

    gy_custodian_close(a);
}

TEST(rotate_evicts_oldest_once_history_is_full)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h, first_h;
    uint32_t first_pkid;
    int type, i;

    bring_up(&a, &am, &acb);

    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &first_h), GY_OK);
    first_pkid = a->saks[0].kp.pub.pkid;

    for (i = 0; i < GY_CUSTODIAN_SAK_HISTORY_MAX; i++)
        ASSERT_EQ(gy_custodian_rotate_appkey(a, 0, &h), GY_OK);

    ASSERT_EQ(a->n_saks, GY_CUSTODIAN_SAK_HISTORY_MAX);
    {
        size_t j;
        int found = 0;

        for (j = 0; j < a->n_saks; j++)
            if (a->saks[j].kp.pub.pkid == first_pkid)
                found = 1;
        ASSERT_TRUE(!found, "the original SAK was evicted from history");
    }
    /* The evicted SAK's slot is freed and its handle number is eligible for
     * immediate reuse (lowest-free-index allocation, cust_slot_register):
     * first_h now resolves to whatever SAK was registered next, never to
     * the evicted key.  first_h stays a VALID handle (slot recycling, not a
     * dangling one), so what is checked is that it names a different key,
     * not that the handle itself goes stale. */
    ASSERT_EQ(gy_custodian_slot_get(a, first_h, &type, NULL), GY_OK);
    ASSERT_EQ(type, GY_SLOT_SAK);
    ASSERT_TRUE(a->saks[0].kp.pub.pkid != first_pkid,
                "the recycled handle now names the current SAK, not the "
                "evicted one");

    gy_custodian_close(a);
}

TEST(domain_separation_rejects_wrong_context_and_unframed_signatures)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h;
    uint8_t cert[512], sig[GY_SIG_MAX];
    size_t certlen, siglen;
    static const uint8_t ctx_a[] = "ctx-a";
    static const uint8_t ctx_b[] = "ctx-b";
    static const uint8_t msg[] = "msg";

    bring_up(&a, &am, &acb);
    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h), GY_OK);
    certlen = sizeof(cert);
    ASSERT_EQ(gy_custodian_export_appkey_cert(a, h, cert, &certlen), GY_OK);

    siglen = sizeof(sig);
    ASSERT_EQ(gy_custodian_sign(a, h, ctx_a, sizeof(ctx_a) - 1, msg,
                                sizeof(msg) - 1, sig, &siglen),
              GY_OK);

    /* Verifying under a DIFFERENT app_ctx fails. */
    ASSERT_EQ(gy_appkey_verify(a->ik.pub.pk, a->desc->curve_pk_len, cert,
                               certlen, ctx_b, sizeof(ctx_b) - 1, msg,
                               sizeof(msg) - 1, sig, siglen, 500),
              GY_ERR_VERIFY);

    /* A raw (unframed) signature over just app_ctx||msg, bypassing the
     * gy_suite_info("appkey") domain-separation prefix, does not validate. */
    {
        uint8_t raw[sizeof(ctx_a) - 1 + sizeof(msg) - 1];
        uint8_t rawsig[GY_SIG_MAX];

        memcpy(raw, ctx_a, sizeof(ctx_a) - 1);
        memcpy(raw + sizeof(ctx_a) - 1, msg, sizeof(msg) - 1);
        ASSERT_EQ(a->desc->sign(rawsig, a->saks[0].kp.sk, raw, sizeof(raw)),
                  GY_OK);
        ASSERT_EQ(gy_appkey_verify(a->ik.pub.pk, a->desc->curve_pk_len, cert,
                                   certlen, ctx_a, sizeof(ctx_a) - 1, msg,
                                   sizeof(msg) - 1, rawsig, a->desc->sig_len,
                                   500),
                  GY_ERR_VERIFY);
    }

    gy_custodian_close(a);
}

TEST(sign_never_returns_the_sak_private_key)
{
    static struct mstore am;
    gy_store_callbacks acb;
    struct gy_custodian *a;
    gy_key_handle h;
    uint8_t cert[512], sig[GY_SIG_MAX];
    size_t certlen, siglen, i;
    static const uint8_t app_ctx[] = "ctx";
    static const uint8_t msg[] = "msg";

    bring_up(&a, &am, &acb);
    ASSERT_EQ(gy_custodian_generate_appkey(a, 0, &h), GY_OK);
    certlen = sizeof(cert);
    ASSERT_EQ(gy_custodian_export_appkey_cert(a, h, cert, &certlen), GY_OK);
    siglen = sizeof(sig);
    ASSERT_EQ(gy_custodian_sign(a, h, app_ctx, sizeof(app_ctx) - 1, msg,
                                sizeof(msg) - 1, sig, &siglen),
              GY_OK);

    /* Neither the certificate nor the signature is long enough to embed the
     * SAK's own private scalar, and a direct substring scan confirms it is
     * not present in either. */
    for (i = 0; i + sizeof(a->saks[0].kp.sk) <= certlen; i++)
        ASSERT_TRUE(
            memcmp(cert + i, a->saks[0].kp.sk, sizeof(a->saks[0].kp.sk)) != 0,
            "cert carries the SAK private key");
    for (i = 0; i + sizeof(a->saks[0].kp.sk) <= siglen; i++)
        ASSERT_TRUE(
            memcmp(sig + i, a->saks[0].kp.sk, sizeof(a->saks[0].kp.sk)) != 0,
            "signature carries the SAK private key");

    gy_custodian_close(a);
}

TEST(appkey_domain_labels_are_distinct_from_each_other_and_from_x3dh)
{
    uint8_t cert_info[64], sign_info[64], x3dh_info[64];
    size_t cert_len, sign_len, x3dh_len;

    /* The two SAK-purpose labels ("appkey-cert": the identity's signature
     * over a cert; "appkey": a per-request SAK signature) must never
     * collide with each other or with an unrelated existing purpose
     * ("x3dh", kex/x3dh.c) - each gy_suite_info output differs in length
     * or content, so no signature produced under one purpose can be
     * replayed as valid under another. */
    ASSERT_EQ(gy_suite_info(cert_info, sizeof(cert_info), &cert_len,
                            GY_SUITE_C25519, "appkey-cert"),
              GY_OK);
    ASSERT_EQ(gy_suite_info(sign_info, sizeof(sign_info), &sign_len,
                            GY_SUITE_C25519, "appkey"),
              GY_OK);
    ASSERT_EQ(gy_suite_info(x3dh_info, sizeof(x3dh_info), &x3dh_len,
                            GY_SUITE_C25519, "x3dh"),
              GY_OK);

    ASSERT_TRUE(cert_len != sign_len ||
                    memcmp(cert_info, sign_info, cert_len) != 0,
                "appkey-cert and appkey labels are distinct");
    ASSERT_TRUE(cert_len != x3dh_len ||
                    memcmp(cert_info, x3dh_info, cert_len) != 0,
                "appkey-cert and x3dh labels are distinct");
    ASSERT_TRUE(sign_len != x3dh_len ||
                    memcmp(sign_info, x3dh_info, sign_len) != 0,
                "appkey and x3dh labels are distinct");

    /* The identity's OTHER signing surface, gy_spk_create (kex/prekeys.c),
     * signs raw EncodeEC(pub) || timestamp_be64 with no gy_info prefix at
     * all; its first byte is always a small curve_type constant (1 or 3),
     * never the 'g' that opens every gy_suite_info-framed appkey-cert
     * signing input below, so the two signing inputs cannot collide. */
    ASSERT_TRUE(cert_info[0] == 'g', "appkey-cert input is info-prefixed");
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(generate_export_sign_and_verify_roundtrip),
            GY_TEST(generate_twice_is_rejected_rotate_needs_one_first),
            GY_TEST(rotate_retains_history_and_old_sak_still_works),
            GY_TEST(rotate_evicts_oldest_once_history_is_full),
            GY_TEST(
                domain_separation_rejects_wrong_context_and_unframed_signatures),
            GY_TEST(sign_never_returns_the_sak_private_key),
            GY_TEST(
                appkey_domain_labels_are_distinct_from_each_other_and_from_x3dh),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
