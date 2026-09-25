/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The public QSPGS client facade (geryon_qspgs.h),
 * which EXTENDS the custodian (its records ride the custodian's sealed store, a
 * band above the classical group's).  Stands up a hybrid custodian over an
 * in-memory messaging store and checks the facade accessors: self-UID round
 * trip (size query + fetch, sourced from the custodian's self_user_id),
 * format-version NOT_FOUND for an unknown group, argument validation, and the
 * classical-custodian rejection (GY_ERR_UNSUPPORTED; QSPGS is hybrid only).
 * The client operations and their end-to-end round-trips follow in later
 * increments.  Driven through the PUBLIC geryon.h / geryon_qspgs.h surfaces;
 * util.h is for gy_core_init and custodian.h only for the hybrid identity-blob
 * size bound the in-memory mock must hold.
 */

#include <stdint.h>
#include <string.h>

#include "geryon.h"
#include "geryon_qsgroups_server.h" /* the server checks the accessors feed */
#include "geryon_qspgs.h"

#include "custodian.h" /* GY_CUST_BLOB_MAX + the identity dual-pub getter. */
#include "qspgs_ops.h" /* gy_qspgs_acct_verify (verify-compat round-trip). */
#include "util.h"      /* gy_core_init */

#include "gy_test.h"

/* ---- in-memory messaging store (for the custodian) ---------------------- */

#define MSTORE_MAX 32
#define MSTORE_BLOB 8192
#define MSTORE_IDENTITY GY_CUST_BLOB_MAX

struct mrec {
    int in_use;
    int kind;
    uint8_t id[64];
    size_t id_len;
    uint8_t blob[MSTORE_BLOB];
    size_t blob_len;
};

struct mstore {
    struct mrec recs[MSTORE_MAX];
    uint8_t identity[MSTORE_IDENTITY];
    size_t identity_len;
};

static struct mrec *
mfind(struct mstore *m, int kind, const uint8_t *id, size_t id_len)
{
    int i;

    for (i = 0; i < MSTORE_MAX; i++)
        if (m->recs[i].in_use && m->recs[i].kind == kind &&
            m->recs[i].id_len == id_len &&
            memcmp(m->recs[i].id, id, id_len) == 0)
            return &m->recs[i];
    return NULL;
}

static int
ms_load(void *ctx, int kind, const uint8_t *id, size_t id_len, uint8_t *out,
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
ms_store(void *ctx, int kind, const uint8_t *id, size_t id_len,
         const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;
    struct mrec *r = mfind(m, kind, id, id_len);

    if (blob_len > MSTORE_BLOB)
        return GY_ERR_ARG;
    if (r == NULL) {
        int i;

        for (i = 0; i < MSTORE_MAX; i++)
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
ms_delete(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct mrec *r = mfind(ctx, kind, id, id_len);

    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK;
}

static int
ms_load_id(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
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
ms_store_id(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct mstore *m = ctx;

    if (blob_len > MSTORE_IDENTITY)
        return GY_ERR_ARG;
    if (blob_len > 0)
        memcpy(m->identity, blob, blob_len);
    m->identity_len = blob_len;
    return GY_OK;
}

static int
ms_load_pk(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
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
ms_consume(void *ctx, uint32_t pkid)
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
    cb->load_record = ms_load;
    cb->store_record = ms_store;
    cb->delete_record = ms_delete;
    cb->load_identity = ms_load_id;
    cb->store_identity = ms_store_id;
    cb->load_prekey = ms_load_pk;
    cb->consume_opk = ms_consume;
}

/* ---- fixtures ----------------------------------------------------------- */

static const uint8_t CRED[] = "qsgroup test credential";
static const uint8_t SELF_UID[GY_QSGROUP_UID_LEN] = {0xa1, 0xa2, 0xa3, 0xa4,
                                                     0xa5, 0xa6, 0xa7, 0xa8};
static const uint8_t DID[4] = {0xd1, 0xd2, 0xd3, 0xd4};
static const uint8_t UNKNOWN_GID[GY_QSGROUP_GID_LEN] = {
    0x77, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

static gy_custodian *
bring_up_as(uint8_t suite, struct mstore *m, gy_store_callbacks *cb,
            const uint8_t *uid, size_t uidlen)
{
    gy_custodian *c = NULL;

    mstore_bind(m, cb);
    ASSERT_EQ(gy_custodian_create(&c, suite, cb, CRED, sizeof(CRED) - 1, uid,
                                  uidlen, DID, sizeof(DID), NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(c, 1000, 2), GY_OK);
    return c;
}

static gy_custodian *
bring_up(uint8_t suite, struct mstore *m, gy_store_callbacks *cb)
{
    return bring_up_as(suite, m, cb, SELF_UID, sizeof(SELF_UID));
}

/*
 * Fetch with no retained prior view and no extra ACCTs: the existing lifecycle
 * scenarios are single-custodian, so every member's base key resolves from the
 * custodian's own pair or an acquaintance record (E5 all-member recompute), and
 * the anti-rollback lineage (which needs a prior view) is exercised separately
 * in TEST(fetch_lineage_and_vklst).  A thin adapter over the full API.
 */
static int
qsg_fetch_np(gy_custodian *c, const uint8_t *h, size_t hn, const uint8_t *m,
             size_t mn, const uint8_t *v, size_t vn, const uint8_t *s,
             size_t sn, struct gy_qsgroup_member_view *out, size_t max,
             size_t *cnt)
{
    return gy_custodian_qsgroup_fetch(c, h, hn, m, mn, v, vn, s, sn, NULL, 0,
                                      NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, out,
                                      max, cnt, NULL, 0, NULL, NULL, 0, NULL);
}

TEST(init)
{
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(self_uid_and_format_version)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *c = bring_up(GY_SUITE_H25519_512, &m, &cb);
    uint8_t uid_out[GY_QSGROUP_UID_MAX];
    size_t uid_len;
    uint16_t ver = 0;

    /* Argument validation. */
    ASSERT_EQ(gy_custodian_qsgroup_self_uid(c, uid_out, NULL), GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_qsgroup_self_uid(NULL, uid_out, &uid_len),
              GY_ERR_ARG);

    /* Self-UID: size query then fetch. */
    ASSERT_EQ(gy_custodian_qsgroup_self_uid(c, NULL, &uid_len), GY_OK);
    ASSERT_EQ(uid_len, sizeof(SELF_UID));
    uid_len = sizeof(uid_out);
    ASSERT_EQ(gy_custodian_qsgroup_self_uid(c, uid_out, &uid_len), GY_OK);
    ASSERT_EQ(uid_len, sizeof(SELF_UID));
    ASSERT_MEMEQ(uid_out, SELF_UID, sizeof(SELF_UID));

    /* A short buffer is rejected. */
    uid_len = sizeof(SELF_UID) - 1;
    ASSERT_EQ(gy_custodian_qsgroup_self_uid(c, uid_out, &uid_len), GY_ERR_ARG);

    /* An unknown group has no stored format version. */
    ASSERT_EQ(gy_custodian_qsgroup_format_version(c, UNKNOWN_GID, &ver),
              GY_ERR_NOT_FOUND);
    ASSERT_EQ(gy_custodian_qsgroup_format_version(NULL, UNKNOWN_GID, &ver),
              GY_ERR_ARG);

    gy_custodian_close(c);
}

TEST(reject_classical_custodian)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *c = bring_up(GY_SUITE_C25519, &m, &cb);
    uint8_t uid_out[GY_QSGROUP_UID_MAX];
    size_t uid_len = sizeof(uid_out);
    uint16_t ver = 0;

    ASSERT_EQ(gy_custodian_qsgroup_self_uid(c, uid_out, &uid_len),
              GY_ERR_UNSUPPORTED);
    ASSERT_EQ(gy_custodian_qsgroup_format_version(c, UNKNOWN_GID, &ver),
              GY_ERR_UNSUPPORTED);
    gy_custodian_close(c);
}

/*
 * LOW-6: the identity key signs only the two certification objects the
 * custodian builds itself, so the typed signers reject malformed input by
 * construction (there is no generic blob / purpose entry point).  A NULL field
 * or a non-canonical invaccept UID length is GY_ERR_ARG; a classical custodian,
 * which has no QSPGS certification tier, is GY_ERR_UNSUPPORTED.
 */
TEST(identity_signers_reject_malformed)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *c = bring_up(GY_SUITE_H25519_512, &m, &cb);
    uint8_t vkb[GY_QSPGS_VKB_MAX], acq[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t uid[GY_QSPGS_UID_LEN], uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t gid[GY_QSPGS_GID_LEN];
    uint8_t ed[GY_QSPGS_PERS_ED_SIG_MAX], ml[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    size_t edn, mln;

    memset(vkb, 0x11, sizeof(vkb));
    memset(acq, 0x22, sizeof(acq));
    memset(uid, 0x33, sizeof(uid));
    memset(uk, 0x44, sizeof(uk));
    memset(gid, 0x55, sizeof(gid));

    /* NULL field pointers are rejected before any signing. */
    ASSERT_EQ(gy_custodian_qspgs_sign_reguser(c, NULL, acq, ed, &edn, ml, &mln),
              GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_qspgs_sign_invaccept(c, uid, GY_QSPGS_UID_LEN, NULL,
                                                gid, ed, &edn, ml, &mln),
              GY_ERR_ARG);

    /* invaccept enforces the fixed UID width, so the object it certifies can
     * only be the canonical shape (SEC-v1.5.0 LOW-2 / LOW-6). */
    ASSERT_EQ(gy_custodian_qspgs_sign_invaccept(c, uid, GY_QSPGS_UID_LEN - 1,
                                                uk, gid, ed, &edn, ml, &mln),
              GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_qspgs_sign_invaccept(c, uid, GY_QSPGS_UID_LEN + 1,
                                                uk, gid, ed, &edn, ml, &mln),
              GY_ERR_ARG);
    gy_custodian_close(c);

    /* A classical custodian has no QSPGS identity-certification tier. */
    c = bring_up(GY_SUITE_C25519, &m, &cb);
    ASSERT_EQ(gy_custodian_qspgs_sign_reguser(c, vkb, acq, ed, &edn, ml, &mln),
              GY_ERR_UNSUPPORTED);
    ASSERT_EQ(gy_custodian_qspgs_sign_invaccept(c, uid, GY_QSPGS_UID_LEN, uk,
                                                gid, ed, &edn, ml, &mln),
              GY_ERR_UNSUPPORTED);
    gy_custodian_close(c);
}

/*
 * RegisterUser + GrantAcquaintance over the public facade (increment
 * 3a).  Proves the identity-sign seam end to end: the registration record is
 * signed THROUGH the custodian (no identity secret key leaves it), and the
 * seam-produced signatures verify under the same identity's public keys via the
 * standalone client verifier (the deferred verify-compat round-trip).  Then a
 * second custodian accepts that record as an acquaintance (verify + seal), and
 * a tampered record is rejected.
 */
TEST(register_and_accept_roundtrip)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b = bring_up(GY_SUITE_H25519_512, &mB, &cbB);
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    const uint8_t *a_curve_pk, *a_mldsa_pk, *vkb, *acq;
    uint64_t ep_out = 0;
    size_t acct_len, qlen = 0;

    /* Size query touches nothing and matches the emitted length. */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 7, NULL, &qlen), GY_OK);
    ASSERT_TRUE(qlen > 0 && qlen <= sizeof(acct), "acct size sane");

    acct_len = sizeof(acct);
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 7, acct, &acct_len), GY_OK);
    ASSERT_EQ(acct_len, qlen);

    /* Verify-compat: the seam's XEdDSA + ML-DSA signatures verify under A's own
     * identity public keys through the standalone client verifier. */
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve_pk, &a_mldsa_pk),
              GY_OK);
    ASSERT_EQ(gy_qspgs_acct_verify(GY_SUITE_H25519_512, a_curve_pk, a_mldsa_pk,
                                   acct, acct_len, &vkb, &acq, &ep_out),
              GY_OK);
    ASSERT_EQ(ep_out, 7);

    /* B accepts A as an acquaintance (verify + acq check + seal into B's
     * store), using A's conveyed uk for epoch 7. */
    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t a_uklen = sizeof(a_uk);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 7, a_uk, &a_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve_pk, a_mldsa_pk, acct,
                  acct_len, a_uk, a_uklen),
              GY_OK);

    /* A validly-signed record but a uk that does NOT open acq is rejected
     * (IsCorrectUserKey, D-QGS-13 E4). */
    uint8_t bad_uk[GY_QSGROUP_USER_KEY_MAX];
    memcpy(bad_uk, a_uk, a_uklen);
    bad_uk[0] ^= 0x01;
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve_pk, a_mldsa_pk, acct,
                  acct_len, bad_uk, a_uklen),
              GY_ERR_VERIFY);

    /* A second register loads the already-provisioned hierarchy (no error). */
    acct_len = sizeof(acct);
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 7, acct, &acct_len), GY_OK);
    ASSERT_EQ(acct_len, qlen);

    /* A tampered record is rejected on accept (signature fails before the acq
     * check). */
    acct[acct_len - 1] ^= 0x01;
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve_pk, a_mldsa_pk, acct,
                  acct_len, a_uk, a_uklen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/* Register on a classical-suite custodian is unsupported (QSPGS is hybrid). */
TEST(register_rejects_classical)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *c = bring_up(GY_SUITE_C25519, &m, &cb);
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    size_t n = sizeof(acct);

    ASSERT_EQ(gy_custodian_qsgroup_register(c, 0, acct, &n),
              GY_ERR_UNSUPPORTED);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  c, SELF_UID, sizeof(SELF_UID), acct, acct, acct, sizeof(acct),
                  acct, sizeof(acct)),
              GY_ERR_UNSUPPORTED);
    gy_custodian_close(c);
}

/*
 * Create + Fetch round-trip over the public facade: a
 * founding member creates a group (mint gk, seal it, emit the admin-signed
 * core), then fetches it back - verifying the admin core signature and
 * decrypting the roster to the sole self member.  Also exercises the two size
 * queries and rejects a tampered core signature.
 */
TEST(create_and_fetch_roundtrip)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &m, &cb);
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xc0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t hdr[256], ml[512], vk[256], sig[8192];
    size_t hn = sizeof(hdr), mn = sizeof(ml), vn = sizeof(vk), sn = sizeof(sig);
    size_t qh = 0, qm = 0, qv = 0, qs = 0, count = 0, cn = 0;
    struct gy_qsgroup_member_view views[4];
    uint16_t ver = 0;

    /* Size query: any NULL out reports all four sizes, seals nothing. */
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 3, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, NULL, &qh, NULL,
                  &qm, NULL, &qv, NULL, &qs, NULL),
              GY_OK);
    ASSERT_TRUE(qh > 0 && qm > 0 && qv > 0 && qs > 0, "create sizes sane");

    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 3, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, hdr, &hn, ml, &mn,
                  vk, &vn, sig, &sn, NULL),
              GY_OK);
    ASSERT_EQ(hn, qh);
    ASSERT_EQ(mn, qm);
    ASSERT_EQ(vn, qv);
    ASSERT_EQ(sn, qs);

    /* The group's format version is now known from its sealed record. */
    ASSERT_EQ(gy_custodian_qsgroup_format_version(a, GID, &ver), GY_OK);
    ASSERT_EQ(ver, GY_QSGROUP_FORMAT_VERSION);

    /* Fetch: verify the admin signature and decrypt the roster (self only). */
    ASSERT_EQ(
        qsg_fetch_np(a, hdr, hn, ml, mn, vk, vn, sig, sn, views, 4, &count),
        GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(views[0].uidlen, sizeof(SELF_UID));
    ASSERT_MEMEQ(views[0].uid, SELF_UID, sizeof(SELF_UID));
    ASSERT_EQ(views[0].admn, 1);

    /* Roster-size query. */
    ASSERT_EQ(qsg_fetch_np(a, hdr, hn, ml, mn, vk, vn, sig, sn, NULL, 0, &cn),
              GY_OK);
    ASSERT_EQ(cn, 1);

    /* A tampered core signature is rejected. */
    sig[sn - 1] ^= 0x01;
    ASSERT_EQ(
        qsg_fetch_np(a, hdr, hn, ml, mn, vk, vn, sig, sn, views, 4, &count),
        GY_ERR_VERIFY);

    gy_custodian_close(a);
}

/*
 * SEC-v1.5.0 INFO-6: the admin pins the group field AEAD at Create.  An
 * unapproved id (AES-256-GCM, which is hardware-gated, or an unknown byte) is
 * rejected up front, and a group created under the AEGIS-256 option round-trips
 * through Fetch exactly as the ChaCha20-Poly1305 default does (the pinned id
 * rides the signed header and drives every field open).
 */
TEST(create_aead_pin)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &m, &cb);
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xc7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t hdr[256], ml[512], vk[256], sig[8192];
    size_t hn = sizeof(hdr), mn = sizeof(ml), vn = sizeof(vk), sn = sizeof(sig);
    size_t qh = 0, qm = 0, qv = 0, qs = 0, count = 0;
    struct gy_qsgroup_member_view views[4];

    /* AES-256-GCM (0x02, hardware-gated) is not a group-approved AEAD. */
    ASSERT_EQ(gy_custodian_qsgroup_create(a, GID, 3, GY_QSGROUP_SETTING_ADD,
                                          0x02, NULL, 0, NULL, &qh, NULL, &qm,
                                          NULL, &qv, NULL, &qs, NULL),
              GY_ERR_ARG);
    /* An unknown AEAD byte is rejected too. */
    ASSERT_EQ(gy_custodian_qsgroup_create(a, GID, 3, GY_QSGROUP_SETTING_ADD,
                                          0xff, NULL, 0, NULL, &qh, NULL, &qm,
                                          NULL, &qv, NULL, &qs, NULL),
              GY_ERR_ARG);

    /* AEGIS-256 is approved: create and fetch round-trip to the self member. */
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 3, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_AEGIS256, NULL, 0, hdr, &hn, ml, &mn, vk, &vn,
                  sig, &sn, NULL),
              GY_OK);
    ASSERT_EQ(
        qsg_fetch_np(a, hdr, hn, ml, mn, vk, vn, sig, sn, views, 4, &count),
        GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(views[0].uidlen, sizeof(SELF_UID));
    ASSERT_MEMEQ(views[0].uid, SELF_UID, sizeof(SELF_UID));
    ASSERT_EQ(views[0].admn, 1);

    gy_custodian_close(a);
}

/* Find a member view by UID, or -1. */
static int
find_uid(const struct gy_qsgroup_member_view *v, size_t n, const uint8_t *uid,
         size_t uidlen)
{
    size_t i;

    for (i = 0; i < n; i++)
        if (v[i].uidlen == uidlen && memcmp(v[i].uid, uid, uidlen) == 0)
            return (int)i;
    return -1;
}

/*
 * Admin core edits: A creates a group, accepts B as an
 * acquaintance, adds B, promotes B to admin, rotates the group key, and removes
 * B - fetching and checking the roster after each edit.  B's user key is
 * supplied directly here (the invite flow delivers it in 4b).
 */
TEST(admin_edits_roundtrip)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb0, 0xb1, 0xb2,
                                                      0xb3, 0xb4, 0xb5};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xd0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    const uint8_t *b_curve, *b_mldsa;
    uint8_t acctB[GY_QSGROUP_ACCT_MAX];
    size_t acctB_len = sizeof(acctB);
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t b_uk[GY_QSGROUP_USER_KEY_MAX];
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;
    int bi, ai;

    /* Two ping-pong core-object buffer sets. */
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;

    size_t b_uklen = sizeof(b_uk);

    /* B registers; A accepts B with B's conveyed uk (acq check), sealing B's
     * base key + uk in A's store. */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB, &acctB_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk, &b_uklen),
              GY_OK);
    ASSERT_EQ(b_uklen, mklen);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB, acctB_len,
                  b_uk, b_uklen),
              GY_OK);

    /* A creates the group into set X (self as sole admin). */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    /* AddMember B -> set Y. */
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(a, &cur, B_UID, sizeof(B_UID), &next),
        GY_OK);

    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 2);
    bi = find_uid(views, count, B_UID, sizeof(B_UID));
    ai = find_uid(views, count, SELF_UID, sizeof(SELF_UID));
    ASSERT_TRUE(bi >= 0 && ai >= 0, "A and B present");
    ASSERT_EQ(views[bi].admn, 0);
    ASSERT_EQ(views[ai].admn, 1);
    ASSERT_EQ(views[bi].uk_len, mklen);
    ASSERT_MEMEQ(views[bi].uk, b_uk, mklen);

    /*
     * Anti-rollback lineage (D-QGS-13 E2), against the validly-signed 2-member
     * core (vMaj 2, signed by the admin A at index ai).  The E5 all-member
     * recompute already ran on every fetch above (A via own base key, B via A's
     * acquaintance record); here we drive the prior-view checks.
     */
    {
        struct gy_qsgroup_member_view pv[8];
        size_t j, c2 = 0;

        for (j = 0; j < count; j++)
            pv[j] = views[j];
        /* Rollback: a prior version newer than the fetched one is refused.
         * (The fetched core is vMaj 2 with folded last-vMin 0.) */
        ASSERT_EQ(gy_custodian_qsgroup_fetch(
                      a, next.hdr, next.hdr_len, next.member_list,
                      next.member_list_len, next.vk_lst, next.vk_lst_len,
                      next.sig, next.sig_len, NULL, 0, NULL, 0, 9, 0, 0, pv,
                      count, NULL, 0, views, 8, &c2, NULL, 0, NULL, NULL, 0,
                      NULL),
                  GY_ERR_STATE);
        /* Exact next major, signer an admin in the prior view, and the folded
         * last-vMin (0) matches the appendix vMin the caller last saw (0):
         * accepted (D-QGS-14 E11). */
        ASSERT_EQ(gy_custodian_qsgroup_fetch(
                      a, next.hdr, next.hdr_len, next.member_list,
                      next.member_list_len, next.vk_lst, next.vk_lst_len,
                      next.sig, next.sig_len, NULL, 0, NULL, 0, 1, 0, 0, pv,
                      count, NULL, 0, views, 8, &c2, NULL, 0, NULL, NULL, 0,
                      NULL),
                  GY_OK);
        /* A skip forward past the next major is now REFUSED (Fig. 15 "version
         * skipped"): prior major 0, fetched major 2. */
        ASSERT_EQ(gy_custodian_qsgroup_fetch(
                      a, next.hdr, next.hdr_len, next.member_list,
                      next.member_list_len, next.vk_lst, next.vk_lst_len,
                      next.sig, next.sig_len, NULL, 0, NULL, 0, 0, 0, 0, pv,
                      count, NULL, 0, views, 8, &c2, NULL, 0, NULL, NULL, 0,
                      NULL),
                  GY_ERR_STATE);
        /* Min version skipped (Fig. 15): exact next major, but the caller last
         * saw 1 appendix line (prior_apx_line_count 1) while the fetched core
         * folded last-vMin 0, so an admin hid a line the caller saw: refused. */
        ASSERT_EQ(gy_custodian_qsgroup_fetch(
                      a, next.hdr, next.hdr_len, next.member_list,
                      next.member_list_len, next.vk_lst, next.vk_lst_len,
                      next.sig, next.sig_len, NULL, 0, NULL, 0, 1, 0, 1, pv,
                      count, NULL, 0, views, 8, &c2, NULL, 0, NULL, NULL, 0,
                      NULL),
                  GY_ERR_STATE);
        /* Signer not an admin in the prior view (exact next major): refused. */
        pv[ai].admn = 0;
        ASSERT_EQ(gy_custodian_qsgroup_fetch(
                      a, next.hdr, next.hdr_len, next.member_list,
                      next.member_list_len, next.vk_lst, next.vk_lst_len,
                      next.sig, next.sig_len, NULL, 0, NULL, 0, 1, 0, 0, pv,
                      count, NULL, 0, views, 8, &c2, NULL, 0, NULL, NULL, 0,
                      NULL),
                  GY_ERR_VERIFY);
    }
    /* Restore the roster view clobbered by the accepted lineage fetches. */
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);

    /* SetAdminRights B -> admin, into set X. */
    cur = next; /* Y is now the current core. */
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(
        gy_custodian_qsgroup_set_admin(a, &cur, B_UID, sizeof(B_UID), 1, &next),
        GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 2);
    bi = find_uid(views, count, B_UID, sizeof(B_UID));
    ASSERT_TRUE(bi >= 0, "B present");
    ASSERT_EQ(views[bi].admn, 1);

    /* RotateGroupKey -> set Y; the roster is unchanged, fetch still works. */
    cur = next;
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(a, &cur, &next), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID),
              GY_OK); /* server accepted. */
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 2);

    /* RemoveMember B -> set X; only A remains. */
    cur = next;
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_remove_member(a, &cur, B_UID, sizeof(B_UID),
                                                 &next),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID),
              GY_OK); /* server accepted. */
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_TRUE(find_uid(views, count, SELF_UID, sizeof(SELF_UID)) >= 0,
                "A remains");
    ASSERT_TRUE(find_uid(views, count, B_UID, sizeof(B_UID)) < 0, "B gone");

    /* The signer cannot remove itself. */
    cur = next;
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_remove_member(a, &cur, SELF_UID,
                                                 sizeof(SELF_UID), &next),
              GY_ERR_ARG);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/*
 * SEC-v1.5.0 LOW-4: a rotating edit STAGES the fresh group key instead of
 * committing it, so a rejected submission cannot strand the admin on a key the
 * group no longer uses.  While staged, the staged key is operative
 * (read-your-writes): the new core fetches and the pre-edit core does not.
 * Rollback reverts to the current key (the pre-edit core fetches again, no
 * lockout); commit promotes the staged key and retires the old one.  Also
 * covers the commit / rollback edge returns and the one-unresolved-edit guard.
 */
TEST(rotating_edit_stages_group_key)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &m, &cb);
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xd4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    /* core 0 = create; core 1 = a rotation later rolled back; core 2 = the
     * rotation that commits. */
    uint8_t h0[256], m0[512], v0[256], s0[8192];
    uint8_t h1[256], m1[512], v1[256], s1[8192];
    uint8_t h2[256], m2[512], v2[256], s2[8192];
    struct gy_qsgroup_core c0, c1, c2, thr;
    struct gy_qsgroup_member_view views[4];
    size_t count = 0;

    /* Create the single-member group as core 0. */
    c0.hdr = h0;
    c0.hdr_len = sizeof(h0);
    c0.member_list = m0;
    c0.member_list_len = sizeof(m0);
    c0.vk_lst = v0;
    c0.vk_lst_len = sizeof(v0);
    c0.sig = s0;
    c0.sig_len = sizeof(s0);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, c0.hdr,
                  &c0.hdr_len, c0.member_list, &c0.member_list_len, c0.vk_lst,
                  &c0.vk_lst_len, c0.sig, &c0.sig_len, NULL),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, c0.hdr, c0.hdr_len, c0.member_list,
                           c0.member_list_len, c0.vk_lst, c0.vk_lst_len, c0.sig,
                           c0.sig_len, views, 4, &count),
              GY_OK);
    ASSERT_EQ(count, 1);

    /* Nothing staged yet: commit is GY_ERR_NOT_FOUND, rollback is a no-op, and
     * the argument guards fire. */
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID), GY_ERR_NOT_FOUND);
    ASSERT_EQ(gy_custodian_qsgroup_rollback(a, GID), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(NULL, GID), GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, NULL), GY_ERR_ARG);
    ASSERT_EQ(gy_custodian_qsgroup_rollback(a, NULL), GY_ERR_ARG);

    /* Rotate -> core 1, staging its fresh gk (current gk untouched). */
    c1.hdr = h1;
    c1.hdr_len = sizeof(h1);
    c1.member_list = m1;
    c1.member_list_len = sizeof(m1);
    c1.vk_lst = v1;
    c1.vk_lst_len = sizeof(v1);
    c1.sig = s1;
    c1.sig_len = sizeof(s1);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(a, &c0, &c1), GY_OK);

    /* Read-your-writes: the staged gk is operative, so the new core fetches and
     * the pre-edit core no longer opens under it. */
    ASSERT_EQ(qsg_fetch_np(a, c1.hdr, c1.hdr_len, c1.member_list,
                           c1.member_list_len, c1.vk_lst, c1.vk_lst_len, c1.sig,
                           c1.sig_len, views, 4, &count),
              GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(qsg_fetch_np(a, c0.hdr, c0.hdr_len, c0.member_list,
                           c0.member_list_len, c0.vk_lst, c0.vk_lst_len, c0.sig,
                           c0.sig_len, views, 4, &count),
              GY_ERR_VERIFY);

    /* Rollback (server rejected): the current gk is restored, the pre-edit core
     * fetches again (no lockout), and the staged core no longer opens. */
    ASSERT_EQ(gy_custodian_qsgroup_rollback(a, GID), GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, c0.hdr, c0.hdr_len, c0.member_list,
                           c0.member_list_len, c0.vk_lst, c0.vk_lst_len, c0.sig,
                           c0.sig_len, views, 4, &count),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, c1.hdr, c1.hdr_len, c1.member_list,
                           c1.member_list_len, c1.vk_lst, c1.vk_lst_len, c1.sig,
                           c1.sig_len, views, 4, &count),
              GY_ERR_VERIFY);

    /* Rotate again from the (still-current) core 0 -> core 2, staging its gk. */
    c2.hdr = h2;
    c2.hdr_len = sizeof(h2);
    c2.member_list = m2;
    c2.member_list_len = sizeof(m2);
    c2.vk_lst = v2;
    c2.vk_lst_len = sizeof(v2);
    c2.sig = s2;
    c2.sig_len = sizeof(s2);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(a, &c0, &c2), GY_OK);

    /* One unresolved edit at a time: a second rotation (from the staged core 2)
     * is refused until the first is committed or rolled back.  Buffers h1.. are
     * reused as a throwaway sink. */
    thr.hdr = h1;
    thr.hdr_len = sizeof(h1);
    thr.member_list = m1;
    thr.member_list_len = sizeof(m1);
    thr.vk_lst = v1;
    thr.vk_lst_len = sizeof(v1);
    thr.sig = s1;
    thr.sig_len = sizeof(s1);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(a, &c2, &thr),
              GY_ERR_STATE);

    /* Commit (server accepted): the staged gk is promoted, the old one retired.
     * Core 2 fetches; core 0 no longer opens. */
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID), GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, c2.hdr, c2.hdr_len, c2.member_list,
                           c2.member_list_len, c2.vk_lst, c2.vk_lst_len, c2.sig,
                           c2.sig_len, views, 4, &count),
              GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_EQ(qsg_fetch_np(a, c0.hdr, c0.hdr_len, c0.member_list,
                           c0.member_list_len, c0.vk_lst, c0.vk_lst_len, c0.sig,
                           c0.sig_len, views, 4, &count),
              GY_ERR_VERIFY);
    /* And after commit the slot is empty again. */
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID), GY_ERR_NOT_FOUND);

    gy_custodian_close(a);
}

/*
 * Invite flow: A creates a group and accepts C as an
 * acquaintance, invites C (minting C's user key), accepts the invite (verifying
 * A's voucher), approves the join, fetches the roster, then revokes an invite
 * from a queue.
 */
TEST(invite_flow_roundtrip)
{
    struct mstore mA, mC;
    gy_store_callbacks cbA, cbC;
    static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc1, 0xc2, 0xc3, 0xc4,
                                                      0xc5};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    const uint8_t *c_curve, *c_mldsa, *a_curve, *a_mldsa;
    uint8_t acctC[GY_QSGROUP_ACCT_MAX];
    size_t acctC_len = sizeof(acctC);
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t gkp[GY_QSGROUP_USER_KEY_MAX];
    size_t gkp_len = sizeof(gkp);
    uint8_t entry[GY_QSGROUP_INVITE_MAX];
    size_t entry_len = sizeof(entry);
    struct gy_qsgroup_invite_view iv;
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;
    int cidx;
    struct gy_qspgs_invite_entry qent, decoded[4];
    uint8_t queue[GY_QSGROUP_INVITE_MAX + 64], outq[GY_QSGROUP_INVITE_MAX + 64];
    size_t qlen = sizeof(queue), outqlen = sizeof(outq), dn = 0, dcons = 0;
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    uint8_t hz[256], mz[2048], vz[512], sz[8192];
    struct gy_qsgroup_core cur, next, rvq;

    /* C registers; A accepts C (with C's conveyed uk) so A holds C's base key. */
    uint8_t c_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t c_uklen = sizeof(c_uk);
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC, &acctC_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC, acctC_len,
                  c_uk, c_uklen),
              GY_OK);

    /* A creates the group into set X. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    /* A invites C: append a PENDING entry (A is acquainted with C, so no ACCT),
     * emitting gk' to share with C -> set Y. */
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_invite(a, &cur, C_UID, sizeof(C_UID), NULL,
                                          gkp, &gkp_len, &next),
              GY_OK);
    ASSERT_EQ(gkp_len, mklen);

    /* Fetching Y: C is present but PENDING (uk_len 0, no user key yet). */
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 2);
    cidx = find_uid(views, count, C_UID, sizeof(C_UID));
    ASSERT_TRUE(cidx >= 0, "C present as pending");
    ASSERT_EQ(views[cidx].uk_len, 0);

    /* C accepts: derives its own uk from muk at ep 1, signs with its own
     * identity, seals to ipk from gk'. */
    ASSERT_EQ(gy_custodian_qsgroup_accept_invitation(cc, GID, gkp, gkp_len, 1,
                                                     entry, &entry_len),
              GY_OK);

    /* A opens the acceptance, verifying against C's OWN identity. */
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve, &a_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_open_invitation(a, GID, gkp, gkp_len, entry,
                                                   entry_len, c_curve, c_mldsa,
                                                   &iv),
              GY_OK);
    ASSERT_EQ(iv.uidlen, sizeof(C_UID));
    ASSERT_MEMEQ(iv.uid, C_UID, sizeof(C_UID));
    ASSERT_EQ(iv.uk_len, mklen);

    /* Opening against the wrong (non-invitee) identity is rejected. */
    ASSERT_EQ(gy_custodian_qsgroup_open_invitation(a, GID, gkp, gkp_len, entry,
                                                   entry_len, a_curve, a_mldsa,
                                                   &iv),
              GY_ERR_VERIFY);

    /* RevokeInvitation queue scrub (while C is still PENDING in Y): a one-entry
     * queue for C revokes to empty.  The entry is opaque, so revoke opens it
     * with the isk from C's pending gk' in the Y core.  Query-mode core output
     * (rvq all-NULL) exercises the scrub without committing the rotation, so Y
     * stays intact for the completion below; the committing core edit and its
     * anti-re-accept property are covered by TEST(revoke_blocks_reaccept). */
    memset(&rvq, 0, sizeof(rvq));
    qent.ct = entry;
    qent.ct_len = entry_len;
    ASSERT_EQ(gy_qspgs_invite_queue_encode(GY_SUITE_H25519_512, &qent, 1, queue,
                                           sizeof(queue), &qlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_revoke_invitation(a, &next, queue, qlen,
                                                     C_UID, sizeof(C_UID), &rvq,
                                                     outq, &outqlen),
              GY_OK);
    ASSERT_EQ(gy_qspgs_invite_queue_decode(GY_SUITE_H25519_512, decoded, 4,
                                           outq, outqlen, &dn, &dcons),
              GY_OK);
    ASSERT_EQ(dn, 0);

    /* The public queue-assembly path: append the entry to an empty queue and
     * confirm it decodes to one entry and revokes to empty. */
    qlen = sizeof(queue);
    ASSERT_EQ(gy_custodian_qsgroup_invite_queue_append(a, NULL, 0, entry,
                                                       entry_len, queue, &qlen),
              GY_OK);
    dn = 0;
    ASSERT_EQ(gy_qspgs_invite_queue_decode(GY_SUITE_H25519_512, decoded, 4,
                                           queue, qlen, &dn, &dcons),
              GY_OK);
    ASSERT_EQ(dn, 1);
    outqlen = sizeof(outq);
    memset(&rvq, 0, sizeof(rvq));
    ASSERT_EQ(gy_custodian_qsgroup_revoke_invitation(a, &next, queue, qlen,
                                                     C_UID, sizeof(C_UID), &rvq,
                                                     outq, &outqlen),
              GY_OK);
    ASSERT_TRUE(outqlen < qlen, "revoke shrinks the queue");
    dn = 0;
    ASSERT_EQ(gy_qspgs_invite_queue_decode(GY_SUITE_H25519_512, decoded, 4,
                                           outq, outqlen, &dn, &dcons),
              GY_OK);
    ASSERT_EQ(dn, 0);

    /* CompleteInvitation: A settles C's pending entry with the accepted uk.
     * cur = Y, result -> set Z. */
    cur = next;
    next.hdr = hz;
    next.hdr_len = sizeof(hz);
    next.member_list = mz;
    next.member_list_len = sizeof(mz);
    next.vk_lst = vz;
    next.vk_lst_len = sizeof(vz);
    next.sig = sz;
    next.sig_len = sizeof(sz);
    ASSERT_EQ(gy_custodian_qsgroup_complete_invitation(
                  a, &cur, C_UID, sizeof(C_UID), iv.uk, iv.uk_len, &next),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 2);
    cidx = find_uid(views, count, C_UID, sizeof(C_UID));
    ASSERT_TRUE(cidx >= 0, "C joined");
    ASSERT_EQ(views[cidx].uk_len, mklen);
    ASSERT_MEMEQ(views[cidx].uk, iv.uk, mklen);

    gy_custodian_close(a);
    gy_custodian_close(cc);
}

/*
 * D-QGS-14 E10: RevokeInvitation is a committing core edit that removes the
 * pending entry (Fig. 17), so a revoked invitee who still holds gk' cannot
 * re-accept and be settled back in.  On the pre-E10 code (queue scrub only) the
 * re-accepted entry settles the member; here Fetch reports no such member and
 * Consolidate does not settle it.
 */
TEST(revoke_blocks_reaccept)
{
    struct mstore mA, mC;
    gy_store_callbacks cbA, cbC;
    static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc1, 0xc2, 0xc3, 0xc4,
                                                      0xc5};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    const uint8_t *c_curve, *c_mldsa;
    uint8_t acctC[GY_QSGROUP_ACCT_MAX];
    size_t acctC_len = sizeof(acctC);
    uint8_t c_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t c_uklen = sizeof(c_uk);
    uint8_t gkp[GY_QSGROUP_USER_KEY_MAX];
    size_t gkp_len = sizeof(gkp);
    uint8_t entry[GY_QSGROUP_INVITE_MAX];
    size_t entry_len = sizeof(entry);
    uint8_t queue[GY_QSGROUP_INVITE_MAX + 64], outq[GY_QSGROUP_INVITE_MAX + 64];
    size_t qlen, outqlen = sizeof(outq);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    uint8_t hz[256], mz[2048], vz[512], sz[8192];
    uint8_t hw[256], mw[2048], vw[512], sw[8192];
    struct gy_qsgroup_core cur, inv1, rvk, cons;
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;

    /* A acquaints C so it can resolve C's base key at invite time. */
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC, &acctC_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC, acctC_len,
                  c_uk, c_uklen),
              GY_OK);

    /* A creates the group and invites C (pending, gk' emitted to C). */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);
    inv1.hdr = hy;
    inv1.hdr_len = sizeof(hy);
    inv1.member_list = my;
    inv1.member_list_len = sizeof(my);
    inv1.vk_lst = vy;
    inv1.vk_lst_len = sizeof(vy);
    inv1.sig = sy;
    inv1.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_invite(a, &cur, C_UID, sizeof(C_UID), NULL,
                                          gkp, &gkp_len, &inv1),
              GY_OK);

    /* C accepts; queue the acceptance. */
    ASSERT_EQ(gy_custodian_qsgroup_accept_invitation(cc, GID, gkp, gkp_len, 1,
                                                     entry, &entry_len),
              GY_OK);
    qlen = sizeof(queue);
    ASSERT_EQ(gy_custodian_qsgroup_invite_queue_append(a, NULL, 0, entry,
                                                       entry_len, queue, &qlen),
              GY_OK);

    /* A revokes C: a committing core edit that drops the pending entry and
     * rotates gk, draining C's queued acceptance -> core R. */
    rvk.hdr = hz;
    rvk.hdr_len = sizeof(hz);
    rvk.member_list = mz;
    rvk.member_list_len = sizeof(mz);
    rvk.vk_lst = vz;
    rvk.vk_lst_len = sizeof(vz);
    rvk.sig = sz;
    rvk.sig_len = sizeof(sz);
    ASSERT_EQ(gy_custodian_qsgroup_revoke_invitation(a, &inv1, queue, qlen,
                                                     C_UID, sizeof(C_UID), &rvk,
                                                     outq, &outqlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID),
              GY_OK); /* server accepted. */
    ASSERT_EQ(qsg_fetch_np(a, rvk.hdr, rvk.hdr_len, rvk.member_list,
                           rvk.member_list_len, rvk.vk_lst, rvk.vk_lst_len,
                           rvk.sig, rvk.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 1); /* only A; C's pending entry is gone. */
    ASSERT_TRUE(find_uid(views, count, C_UID, sizeof(C_UID)) < 0,
                "C is not in the revoked core");

    /* C re-accepts with the same gk' it still holds; A queues it. */
    entry_len = sizeof(entry);
    ASSERT_EQ(gy_custodian_qsgroup_accept_invitation(cc, GID, gkp, gkp_len, 1,
                                                     entry, &entry_len),
              GY_OK);
    qlen = sizeof(queue);
    ASSERT_EQ(gy_custodian_qsgroup_invite_queue_append(a, NULL, 0, entry,
                                                       entry_len, queue, &qlen),
              GY_OK);

    /* Fetch R with the re-acceptance in the queue: C is still not a member,
     * because R holds no pending entry to settle. */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, rvk.hdr, rvk.hdr_len, rvk.member_list, rvk.member_list_len,
                  rvk.vk_lst, rvk.vk_lst_len, rvk.sig, rvk.sig_len, NULL, 0,
                  queue, qlen, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  NULL, 0, NULL, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_TRUE(find_uid(views, count, C_UID, sizeof(C_UID)) < 0,
                "re-acceptance does not resurrect C at Fetch");

    /* Consolidate R with the re-acceptance queue: C is not settled. */
    cons.hdr = hw;
    cons.hdr_len = sizeof(hw);
    cons.member_list = mw;
    cons.member_list_len = sizeof(mw);
    cons.vk_lst = vw;
    cons.vk_lst_len = sizeof(vw);
    cons.sig = sw;
    cons.sig_len = sizeof(sw);
    outqlen = sizeof(outq);
    ASSERT_EQ(gy_custodian_qsgroup_consolidate(a, &rvk, NULL, 0, queue, qlen,
                                               NULL, 0, NULL, 0, &cons, outq,
                                               &outqlen),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, cons.hdr, cons.hdr_len, cons.member_list,
                           cons.member_list_len, cons.vk_lst, cons.vk_lst_len,
                           cons.sig, cons.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 1);
    ASSERT_TRUE(find_uid(views, count, C_UID, sizeof(C_UID)) < 0,
                "re-acceptance does not resurrect C at Consolidate");

    gy_custodian_close(a);
    gy_custodian_close(cc);
}

/* Decode a single-line appendix object and assert its line type. */
static void
assert_apx_line(uint8_t suite, const uint8_t *obj, size_t len, uint8_t type)
{
    struct gy_qspgs_appendix apx;
    struct gy_qspgs_apx_line lines[4];
    size_t consumed = 0;

    memset(&apx, 0, sizeof(apx));
    apx.suite_id = suite;
    ASSERT_EQ(gy_qspgs_appendix_decode(&apx, lines, 4, obj, len, &consumed),
              GY_OK);
    ASSERT_EQ(apx.n_lines, (size_t)1);
    ASSERT_EQ(lines[0].line_type, type);
}

/*
 * Merge n single-line appendix objects (as the builders emit) into one
 * multi-line appendix object, the way a deployer accumulates lines at one
 * (vMaj, vMin) before serving them to fetch / consolidate.  The source objects
 * must stay alive: the merged lines' payload / sig point into them.
 */
static void
merge_appendix(uint8_t suite, uint8_t *const *objs, const size_t *lens,
               size_t n, uint8_t *out, size_t out_cap, size_t *outlen)
{
    struct gy_qspgs_appendix apx, one;
    struct gy_qspgs_apx_line lines[8], tmp[4];
    size_t i, consumed;

    ASSERT_TRUE(n <= 8, "appendix line count fits");
    memset(&apx, 0, sizeof(apx));
    apx.suite_id = suite;
    for (i = 0; i < n; i++) {
        memset(&one, 0, sizeof(one));
        one.suite_id = suite;
        ASSERT_EQ(
            gy_qspgs_appendix_decode(&one, tmp, 4, objs[i], lens[i], &consumed),
            GY_OK);
        ASSERT_EQ(one.n_lines, (size_t)1);
        if (i == 0) {
            memcpy(apx.gid, one.gid, sizeof(apx.gid));
            apx.vmaj = one.vmaj;
            apx.vmin = one.vmin;
        }
        lines[i] = tmp[0]; /* payload / sig point into objs[i]. */
    }
    apx.lines = lines;
    apx.n_lines = n;
    ASSERT_EQ(gy_qspgs_appendix_encode(&apx, out, out_cap, outlen), GY_OK);
}

/*
 * Settings, non-admin appendix ops, and the join link:
 * A creates a group, changes settings, emits each appendix line kind, opens a
 * join link, and D joins via the link (recovering the group key and emitting a
 * JOIN line).
 */
TEST(settings_appendix_joinlink)
{
    struct mstore mA, mD;
    gy_store_callbacks cbA, cbD;
    static const uint8_t D_UID[GY_QSGROUP_UID_LEN] = {0xda, 0xdb, 0xdc, 0xdd,
                                                      0xde, 0xdf, 0xe0};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *d =
        bring_up_as(GY_SUITE_H25519_512, &mD, &cbD, D_UID, sizeof(D_UID));
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    size_t llen;
    uint8_t secret[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t d_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_uk_len = sizeof(d_uk), jlen;
    uint8_t acctD[GY_QSGROUP_ACCT_MAX];
    size_t acctD_len = sizeof(acctD);
    uint8_t acctA[GY_QSGROUP_ACCT_MAX];
    size_t acctA_len = sizeof(acctA);
    const uint8_t *d_curve, *d_mldsa;
    uint8_t d_acq_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_acq_uklen = sizeof(d_acq_uk);
    uint8_t d_vkhash[64];
    size_t d_vkhashlen = sizeof(d_vkhash);
    uint8_t jline[GY_QSGROUP_APPENDIX_MAX];
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;
    uint16_t ver = 0;
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;

    /* D registers; A accepts D so A holds D's base key (UserAdd needs it to
     * compute the newcomer's H(vkpsdn), and E4 attests D's uk). */
    ASSERT_EQ(gy_custodian_qsgroup_register(d, 1, acctD, &acctD_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(d, &d_curve, &d_mldsa), GY_OK);
    ASSERT_EQ(
        gy_custodian_qsgroup_export_user_key(d, 1, d_acq_uk, &d_acq_uklen),
        GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, D_UID, sizeof(D_UID), d_curve, d_mldsa, acctD, acctD_len,
                  d_acq_uk, d_acq_uklen),
              GY_OK);

    /* A creates the group into set X. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    /* ChangeSettings -> set Y, then fetch verifies the re-signed core. */
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_change_settings(
                  a, &cur, GY_QSGROUP_SETTING_ATTR,
                  (const uint8_t *)"hello-settings", 14, &next),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, next.hdr, next.hdr_len, next.member_list,
                           next.member_list_len, next.vk_lst, next.vk_lst_len,
                           next.sig, next.sig_len, views, 8, &count),
              GY_OK);
    ASSERT_EQ(count, 1);

    /* Non-admin appendix lines over the changed core (Y). */
    llen = sizeof(line);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_leave(a, &next, 1, line, &llen),
              GY_OK);
    assert_apx_line(GY_SUITE_H25519_512, line, llen, GY_QAPX_LEAVE);

    llen = sizeof(line);
    ASSERT_EQ(
        gy_custodian_qsgroup_appendix_refresh(a, &next, 1, 2, line, &llen),
        GY_OK);
    assert_apx_line(GY_SUITE_H25519_512, line, llen, GY_QAPX_REFRESH);

    llen = sizeof(line);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_mod_attr(
                  a, &next, 1, (const uint8_t *)"attrs", 5, line, &llen),
              GY_OK);
    assert_apx_line(GY_SUITE_H25519_512, line, llen, GY_QAPX_MODATTR);

    llen = sizeof(line);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_add_user(
                  a, &next, 1, D_UID, sizeof(D_UID), d_acq_uk, mklen, line,
                  &llen, d_vkhash, &d_vkhashlen),
              GY_OK);
    assert_apx_line(GY_SUITE_H25519_512, line, llen, GY_QAPX_ADDUSER);
    ASSERT_TRUE(d_vkhashlen > 0, "UserAdd emits H(vkpsdn)");

    /* ToggleJoinLink -> set X; D joins via the link. */
    cur = next; /* Y is now current. */
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);

    /* D verifies next's admin signature against A's ACCT before adopting gk. */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    jlen = sizeof(jline);
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(d, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uk_len,
                                                 jline, &jlen),
              GY_OK);
    ASSERT_EQ(d_uk_len, mklen);
    assert_apx_line(GY_SUITE_H25519_512, jline, jlen, GY_QAPX_JOIN);

    /* D sealed the recovered group key: its format version is now readable. */
    ASSERT_EQ(gy_custodian_qsgroup_format_version(d, GID, &ver), GY_OK);
    ASSERT_EQ(ver, GY_QSGROUP_FORMAT_VERSION);

    gy_custodian_close(a);
    gy_custodian_close(d);
}

/*
 * The server-interaction accessors: a member's published pseudonym
 * key (self_vkr) and fetch token feed the standalone section-7.3 server checks
 * directly, so a deploying server can accept an admin core edit and a fetch.
 * This closes the gap that a server needs the full vkr (the vk-lst stores only
 * H(vkr)) and the fetch token, neither of which the rest of the API exposes.
 */
TEST(server_checks_via_accessors)
{
    struct mstore m;
    gy_store_callbacks cb;
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &m, &cb);
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xa0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    size_t hn = sizeof(hx), mn = sizeof(mx), vn = sizeof(vx), sn = sizeof(sx);
    uint8_t vkr[GY_QSGROUP_VKR_MAX];
    size_t vkrlen = sizeof(vkr);
    uint8_t token[GY_QSGROUP_FET_LEN];
    size_t toklen = sizeof(token);
    uint8_t fet[GY_QSGROUP_FET_LEN]; /* the separate server record, LOW-1. */
    uint8_t ltok[GY_QSGROUP_APPENDIX_MAX];
    size_t ltoklen = sizeof(ltok);

    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, hx, &hn, mx, &mn,
                  vx, &vn, sx, &sn, fet),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_self_vkr(a, GID, vkr, &vkrlen), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_fetch_token(a, GID, token, &toklen), GY_OK);
    ASSERT_EQ(toklen, (size_t)GY_QSGROUP_FET_LEN);

    /* The server accepts the founder's core under the published vkr, and the
     * fetch token passes the server's token check against the SEPARATE fet
     * record the admin emitted (SEC-v1.5.0 LOW-1: not from the header). */
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_CREATE, NULL, 0, NULL, 0,
                  NULL, 0, hx, hn, mx, mn, vx, vn, sx, sn, vkr, vkrlen),
              GY_OK);
    ASSERT_EQ(gy_qsgroups_server_fetch_check(GY_SUITE_H25519_512, fet, token),
              GY_OK);

    /* Leaver fetch token ([CFG+] Fig. 10): the founder (index 0) signs
     * (GID, 0); the server verifies it under the published vkr against the
     * vk-lst.  A tampered token and an out-of-range index are rejected. */
    ASSERT_EQ(gy_custodian_qsgroup_leave_fetch_token(a, GID, 0, ltok, &ltoklen),
              GY_OK);
    ASSERT_EQ(gy_qsgroups_server_leave_fetch_check(GY_SUITE_H25519_512, vx, vn,
                                                   GID, 0, ltok, ltoklen, vkr,
                                                   vkrlen),
              GY_OK);
    ltok[0] ^= 0x01;
    ASSERT_EQ(gy_qsgroups_server_leave_fetch_check(GY_SUITE_H25519_512, vx, vn,
                                                   GID, 0, ltok, ltoklen, vkr,
                                                   vkrlen),
              GY_ERR_VERIFY);
    ltok[0] ^= 0x01;
    ASSERT_EQ(gy_qsgroups_server_leave_fetch_check(GY_SUITE_H25519_512, vx, vn,
                                                   GID, 1, ltok, ltoklen, vkr,
                                                   vkrlen),
              GY_ERR_ARG);

    /* A tampered vkr no longer resolves to the stored H(vkr). */
    vkr[0] ^= 0x01;
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_CREATE, NULL, 0, NULL, 0,
                  NULL, 0, hx, hn, mx, mn, vx, vn, sx, sn, vkr, vkrlen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
}

/*
 * The public identity-key accessor: a member's own hybrid identity
 * public keys, published so a peer can accept its registration record - the
 * public path for what the internal dual-pub getter did in
 * register_and_accept_roundtrip.  Closes the gap that accept-acquaintance needs
 * the granter's raw identity keys with no public way to obtain them.
 */
TEST(identity_public_enables_accept)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb1, 0xb2, 0xb3, 0xb4};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    size_t acct_len = sizeof(acct);
    uint8_t curve[GY_QSGROUP_ID_CURVE_MAX], mldsa[GY_QSGROUP_ID_MLDSA_MAX];
    size_t curve_len = sizeof(curve), mldsa_len = sizeof(mldsa);

    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t a_uklen = sizeof(a_uk);
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acct, &acct_len), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_identity_public(a, curve, &curve_len, mldsa,
                                                   &mldsa_len),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 1, a_uk, &a_uklen),
              GY_OK);
    /* B accepts A's ACCT using A's published identity keys and conveyed uk. */
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), curve, mldsa, acct, acct_len,
                  a_uk, a_uklen),
              GY_OK);
    /* A tampered identity key fails the ACCT signature verification. */
    mldsa[0] ^= 0x01;
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), curve, mldsa, acct, acct_len,
                  a_uk, a_uklen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/*
 * The group-key envelope: an admin exports the group key opaquely
 * and a member being added installs it (delivered over a confidential pairwise
 * channel in the demo), so the member can then fetch and operate.  Closes the
 * gap that an added member has no public way to install a delivered group key
 * (create mints it; join-via-link recovers it from a slot).
 */
TEST(group_key_envelope_roundtrip)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb1, 0xb2, 0xb3, 0xb4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xc5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    size_t hn = sizeof(hx), mn = sizeof(mx), vn = sizeof(vx), sn = sizeof(sx);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen = sizeof(env);
    uint8_t gid_out[GY_QSGROUP_GID_LEN];
    uint8_t ta[GY_QSGROUP_FET_LEN], tb[GY_QSGROUP_FET_LEN];
    size_t la = sizeof(ta), lb = sizeof(tb);
    uint16_t ver = 0;

    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, hx, &hn, mx, &mn,
                  vx, &vn, sx, &sn, NULL),
              GY_OK);
    /* A exports the group key; B (added out of band) installs it. */
    ASSERT_EQ(gy_custodian_qsgroup_export_group_key(a, GID, env, &envlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_install_group_key(b, env, envlen, gid_out),
              GY_OK);
    ASSERT_MEMEQ(gid_out, GID, GY_QSGROUP_GID_LEN);

    /* INFO-4 typed frame: install rejects a tampered object header (wrong
     * kind / wire version / suite -> GY_ERR_VERIFY) and a wrong length
     * (GY_ERR_ARG), so a foreign or stale-version envelope cannot overwrite. */
    {
        uint8_t bad[GY_QSGROUP_KEY_ENVELOPE_MAX];
        size_t bi;

        for (bi = 0; bi < 3; bi++) {
            memcpy(bad, env, envlen);
            bad[bi] ^= 0xff;
            ASSERT_EQ(
                gy_custodian_qsgroup_install_group_key(b, bad, envlen, gid_out),
                GY_ERR_VERIFY);
        }
        ASSERT_EQ(
            gy_custodian_qsgroup_install_group_key(b, env, envlen - 1, gid_out),
            GY_ERR_ARG);
    }

    /* B now holds the group: its record and its fetch token match A's. */
    ASSERT_EQ(gy_custodian_qsgroup_format_version(b, GID, &ver), GY_OK);
    ASSERT_EQ(ver, GY_QSGROUP_FORMAT_VERSION);
    ASSERT_EQ(gy_custodian_qsgroup_fetch_token(a, GID, ta, &la), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_fetch_token(b, GID, tb, &lb), GY_OK);
    ASSERT_EQ(la, lb);
    ASSERT_MEMEQ(ta, tb, la);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/*
 * Fetch-time IsCorrectUserKey ([CFG+] Fig. 15, D-QGS-13 E4 task 3): a member
 * the fetcher has no acquaintance record for is trusted only when a supplied
 * ACCT attests its roster uk (identity signature verifies AND acq == KDF(uk)).
 * A (the fetcher) is acquainted with B but NOT with C; B (a second admin) adds
 * C using B's acquaintance with C.  A then fetches, resolving C purely from C's
 * server-served ACCT, and the acq check must run on C's uk.
 */
TEST(fetch_iscorrect_userkey)
{
    struct mstore mA, mB, mC;
    gy_store_callbacks cbA, cbB, cbC;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb0, 0xb1, 0xb2,
                                                      0xb3, 0xb4, 0xb5};
    static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3,
                                                      0xc4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    const uint8_t *a_curve, *a_mldsa, *b_curve, *b_mldsa, *c_curve, *c_mldsa;
    uint8_t acctA[GY_QSGROUP_ACCT_MAX], acctB[GY_QSGROUP_ACCT_MAX];
    uint8_t acctC1[GY_QSGROUP_ACCT_MAX], acctC2[GY_QSGROUP_ACCT_MAX];
    size_t acctA_len = sizeof(acctA), acctB_len = sizeof(acctB);
    size_t acctC1_len = sizeof(acctC1), acctC2_len = sizeof(acctC2);
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX], b_uk[GY_QSGROUP_USER_KEY_MAX];
    uint8_t c_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t a_uklen = sizeof(a_uk), b_uklen = sizeof(b_uk);
    size_t c_uklen = sizeof(c_uk);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen = sizeof(env);
    uint8_t gid_out[GY_QSGROUP_GID_LEN];
    struct gy_qsgroup_acct_ref refs[1];
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;
    int ci;

    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;

    /* Registrations and symmetric A<->B acquaintance (B edits A's core, so it
     * needs A's base key; A reads B's entry, so it needs B's). */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB, &acctB_len), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC1, &acctC1_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve, &a_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 1, a_uk, &a_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk, &b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB, acctB_len,
                  b_uk, b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve, a_mldsa, acctA,
                  acctA_len, a_uk, a_uklen),
              GY_OK);
    /* B is acquainted with C; A deliberately is NOT. */
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC1, acctC1_len,
                  c_uk, c_uklen),
              GY_OK);

    /* A creates the group (self admin), adds B, promotes B to admin. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(a, &cur, B_UID, sizeof(B_UID), &next),
        GY_OK);

    cur = next;
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(
        gy_custodian_qsgroup_set_admin(a, &cur, B_UID, sizeof(B_UID), 1, &next),
        GY_OK);

    /* A hands B the group key so B can edit. */
    ASSERT_EQ(gy_custodian_qsgroup_export_group_key(a, GID, env, &envlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_install_group_key(b, env, envlen, gid_out),
              GY_OK);

    /* B (admin) adds C, sealing C's uk from B's acquaintance record. */
    cur = next; /* the B-promotes core, signed by A. */
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(b, &cur, C_UID, sizeof(C_UID), &next),
        GY_OK);

    /* A fetches the 3-member core (signed by admin B): A resolves itself and B
     * (acquaintance), and C only from the server-served ACCT.  IsCorrectUserKey
     * runs on C's uk against acctC1 (acq == KDF(c_uk)) and passes. */
    refs[0].uid = C_UID;
    refs[0].uid_len = sizeof(C_UID);
    refs[0].acct = acctC1;
    refs[0].acct_len = acctC1_len;
    refs[0].curve_pk = c_curve;
    refs[0].mldsa_pk = c_mldsa;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, refs, 1,
                  views, 8, &count, NULL, 0, NULL, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(count, 3);
    ci = find_uid(views, count, C_UID, sizeof(C_UID));
    ASSERT_TRUE(ci >= 0, "C present");
    ASSERT_EQ(views[ci].uk_len, mklen);
    ASSERT_MEMEQ(views[ci].uk, c_uk, mklen);

    /* Negative: a validly-signed ACCT for C at a DIFFERENT epoch attests a uk
     * that does not match the roster's; the vkbase is unchanged (E5 still
     * resolves), so the acq mismatch is what fails the version. */
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 2, acctC2, &acctC2_len), GY_OK);
    refs[0].acct = acctC2;
    refs[0].acct_len = acctC2_len;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, refs, 1,
                  views, 8, &count, NULL, 0, NULL, NULL, 0, NULL),
              GY_ERR_VERIFY);

    /* Negative: no identity keys for a non-acquainted member cannot be checked
     * and is refused. */
    refs[0].acct = acctC1;
    refs[0].acct_len = acctC1_len;
    refs[0].curve_pk = NULL;
    refs[0].mldsa_pk = NULL;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, refs, 1,
                  views, 8, &count, NULL, 0, NULL, NULL, 0, NULL),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
    gy_custodian_close(cc);
}

/*
 * D-QGS-14 E12: IsCorrectUserKey runs over the EFFECTIVE roster (after the
 * appendix folds), and an AcqRec exempts a member only on an exact (UID, uk)
 * match.  B is acquainted (uk@ep1) then refreshes to ep2 via an appendix line;
 * the refreshed uk no longer matches A's AcqRec, so it must be attested by B's
 * new-epoch ACCT.  Without that ACCT the fetch is refused (on the pre-E12 code
 * the refreshed uk was never re-checked and the fetch succeeded); with B's ep2
 * ACCT it passes.
 */
TEST(refresh_rechecks_acquainted_userkey)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb5, 0xb6, 0xb7, 0xb8,
                                                      0xb9};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    const uint8_t *b_curve, *b_mldsa, *a_curve, *a_mldsa;
    uint8_t acctB1[GY_QSGROUP_ACCT_MAX], acctB2[GY_QSGROUP_ACCT_MAX];
    uint8_t acctA[GY_QSGROUP_ACCT_MAX];
    size_t acctB1_len = sizeof(acctB1), acctB2_len = sizeof(acctB2);
    size_t acctA_len = sizeof(acctA);
    uint8_t b_uk1[GY_QSGROUP_USER_KEY_MAX], b_uk2[GY_QSGROUP_USER_KEY_MAX];
    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t b_uk1len = sizeof(b_uk1), b_uk2len = sizeof(b_uk2);
    size_t a_uklen = sizeof(a_uk);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen = sizeof(env);
    uint8_t gid_out[GY_QSGROUP_GID_LEN];
    uint8_t lref[GY_QSGROUP_APPENDIX_MAX], apxobj[16384];
    size_t lref_l = sizeof(lref), apxlen;
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;
    struct gy_qsgroup_acct_ref refs[1];
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;
    uint8_t *objs[1];
    size_t lens[1];
    int bi;

    /* A acquaints B at ep1 (AcqRec stores uk@ep1). */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB1, &acctB1_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk1, &b_uk1len),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB1, acctB1_len,
                  b_uk1, b_uk1len),
              GY_OK);

    /* B accepts A so B can verify A's admin-signed core when it refreshes. */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve, &a_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 1, a_uk, &a_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve, a_mldsa, acctA,
                  acctA_len, a_uk, a_uklen),
              GY_OK);

    /* A creates and adds B; hand B the group key so it can sign an appendix. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(a, &cur, B_UID, sizeof(B_UID), &next),
        GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_group_key(a, GID, env, &envlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_install_group_key(b, env, envlen, gid_out),
              GY_OK);

    /* B refreshes to ep2 (uk@ep2); build a one-line appendix. */
    ASSERT_EQ(
        gy_custodian_qsgroup_appendix_refresh(b, &next, 1, 2, lref, &lref_l),
        GY_OK);
    objs[0] = lref;
    lens[0] = lref_l;
    merge_appendix(GY_SUITE_H25519_512, objs, lens, 1, apxobj, sizeof(apxobj),
                   &apxlen);

    /* Negative: A has only its stale AcqRec (uk@ep1); the refreshed uk@ep2 is
     * not exempt and has no ACCT to attest it, so the fetch is refused. */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0, NULL,
                  0, views, 8, &count, reps, 4, &nreps, NULL, 0, NULL),
              GY_ERR_VERIFY);

    /* Positive: B's ep2 ACCT attests uk@ep2 (acq == KDF(uk@ep2)); accepted. */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 2, acctB2, &acctB2_len), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 2, b_uk2, &b_uk2len),
              GY_OK);
    refs[0].uid = B_UID;
    refs[0].uid_len = sizeof(B_UID);
    refs[0].acct = acctB2;
    refs[0].acct_len = acctB2_len;
    refs[0].curve_pk = b_curve;
    refs[0].mldsa_pk = b_mldsa;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0, refs,
                  1, views, 8, &count, reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(count, 2);
    bi = find_uid(views, count, B_UID, sizeof(B_UID));
    ASSERT_TRUE(bi >= 0, "B present after refresh");
    ASSERT_EQ(views[bi].uk_len, mklen);
    ASSERT_MEMEQ(views[bi].uk, b_uk2, mklen);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/*
 * D-QGS-13 E6: the join link must survive group-key rotation (App. B.8).
 * A creator opens a link, rotates the group key, and the ORIGINAL out-of-band
 * secret still opens the rotated slot and recovers the NEW group key (the old
 * slot bytes are gone).  Then the creator disables the link and a join fails.
 */
TEST(joinlink_survives_rotation)
{
    struct mstore mA, mD, mE;
    gy_store_callbacks cbA, cbD, cbE;
    static const uint8_t D_UID[GY_QSGROUP_UID_LEN] = {0xd0, 0xd1, 0xd2, 0xd3};
    static const uint8_t E_UID[GY_QSGROUP_UID_LEN] = {0xe1, 0xe2, 0xe3, 0xe4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0x11, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *d =
        bring_up_as(GY_SUITE_H25519_512, &mD, &cbD, D_UID, sizeof(D_UID));
    gy_custodian *e =
        bring_up_as(GY_SUITE_H25519_512, &mE, &cbE, E_UID, sizeof(E_UID));
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t secret[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t d_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_uklen = sizeof(d_uk), jlen;
    uint8_t jline[GY_QSGROUP_APPENDIX_MAX];
    uint8_t acctA[GY_QSGROUP_ACCT_MAX];
    size_t acctA_len = sizeof(acctA);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;

    /* A creates the group (self sole member/admin) into set X. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    /* ToggleJoinLink (enable) -> set Y; the secret is minted and persisted. */
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);

    /* RotateGroupKey -> set X; A holds jls, so the slot is re-sealed. */
    cur = next;
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(a, &cur, &next), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID),
              GY_OK); /* server accepted. */

    /* The ORIGINAL secret opens the rotated slot and recovers the new gk;
     * the joiner verifies the rotated core against A's ACCT first. */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    jlen = sizeof(jline);
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(d, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uklen,
                                                 jline, &jlen),
              GY_OK);
    ASSERT_EQ(d_uklen, mklen);
    assert_apx_line(GY_SUITE_H25519_512, jline, jlen, GY_QAPX_JOIN);

    /* ToggleJoinLink (disable) -> set Y; the slot is dropped, secret retired. */
    cur = next;
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);

    /* A fresh joiner cannot open the disabled core: no slot -> GY_ERR_VERIFY
     * (the missing join slot is caught before the signature check). */
    d_uklen = sizeof(d_uk);
    jlen = sizeof(jline);
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(e, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uklen,
                                                 jline, &jlen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(d);
    gy_custodian_close(e);
}

/*
 * D-QGS-13 E6: an admin who does NOT hold the link secret (it was generated
 * by another admin) rotates a group with an open link.  Rather than re-seal a
 * slot it cannot produce, the rotation drops the slot and returns the positive
 * GY_QSGROUP_JOIN_LINK_DROPPED; the emitted core carries no link.
 */
TEST(joinlink_dropped_by_foreign_admin)
{
    struct mstore mA, mB, mD;
    gy_store_callbacks cbA, cbB, cbD;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb0, 0xb1, 0xb2,
                                                      0xb3, 0xb4, 0xb5};
    static const uint8_t D_UID[GY_QSGROUP_UID_LEN] = {0xd4, 0xd5, 0xd6, 0xd7};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0x22, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    gy_custodian *d =
        bring_up_as(GY_SUITE_H25519_512, &mD, &cbD, D_UID, sizeof(D_UID));
    const uint8_t *a_curve, *a_mldsa, *b_curve, *b_mldsa;
    uint8_t acctA[GY_QSGROUP_ACCT_MAX], acctB[GY_QSGROUP_ACCT_MAX];
    size_t acctA_len = sizeof(acctA), acctB_len = sizeof(acctB);
    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX], b_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t a_uklen = sizeof(a_uk), b_uklen = sizeof(b_uk);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen = sizeof(env);
    uint8_t gid_out[GY_QSGROUP_GID_LEN];
    uint8_t secret[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t d_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_uklen = sizeof(d_uk), jlen;
    uint8_t jline[GY_QSGROUP_APPENDIX_MAX];
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;

    /* Registrations and symmetric A<->B acquaintance (B rebuilds A on rotate). */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB, &acctB_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve, &a_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 1, a_uk, &a_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk, &b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB, acctB_len,
                  b_uk, b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve, a_mldsa, acctA,
                  acctA_len, a_uk, a_uklen),
              GY_OK);

    /* A creates, adds B, promotes B to admin, and hands B the group key. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(a, &cur, B_UID, sizeof(B_UID), &next),
        GY_OK);

    cur = next;
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(
        gy_custodian_qsgroup_set_admin(a, &cur, B_UID, sizeof(B_UID), 1, &next),
        GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_group_key(a, GID, env, &envlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_install_group_key(b, env, envlen, gid_out),
              GY_OK);

    /* A (the creator) opens the join link -> set Y; only A holds jls. */
    cur = next;
    next.hdr = hy;
    next.hdr_len = sizeof(hy);
    next.member_list = my;
    next.member_list_len = sizeof(my);
    next.vk_lst = vy;
    next.vk_lst_len = sizeof(vy);
    next.sig = sy;
    next.sig_len = sizeof(sy);
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);

    /* B (an admin without jls) rotates: the slot is dropped, not re-sealed. */
    cur = next;
    next.hdr = hx;
    next.hdr_len = sizeof(hx);
    next.member_list = mx;
    next.member_list_len = sizeof(mx);
    next.vk_lst = vx;
    next.vk_lst_len = sizeof(vx);
    next.sig = sx;
    next.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_rotate_group_key(b, &cur, &next),
              GY_QSGROUP_JOIN_LINK_DROPPED);
    ASSERT_EQ(gy_custodian_qsgroup_commit(b, GID),
              GY_OK); /* server accepted. */

    /* The emitted core has no link: even the original secret cannot join
     * (the missing slot is caught before the signature check). */
    jlen = sizeof(jline);
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(d, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uklen,
                                                 jline, &jlen),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
    gy_custodian_close(d);
}

/*
 * Consolidate consistency: an admin folds an appendix (refresh, modAttr, addUser,
 * leave) and the roster Consolidate produces equals the effective roster Fetch
 * computes from (core + appendix), applied in the paper's kind order (Fig. 15 /
 * Fig. 18).  A folded leave rotates the group key.  A tampered line is reported
 * invalid and not applied.  (The forging-harness negatives - a genuine-but-bad
 * commitment addUser and the malicious-admin E5 core - land with task 9.)
 */
TEST(appendix_fold_and_consolidate)
{
    struct mstore mA, mB, mC;
    gy_store_callbacks cbA, cbB, cbC;
    static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb0, 0xb1, 0xb2, 0xb3,
                                                      0xb4};
    static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3,
                                                      0xc4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    const uint8_t *b_curve, *b_mldsa, *c_curve, *c_mldsa, *a_curve, *a_mldsa;
    uint8_t acctB[GY_QSGROUP_ACCT_MAX], acctC[GY_QSGROUP_ACCT_MAX];
    uint8_t acctA[GY_QSGROUP_ACCT_MAX], acctB2[GY_QSGROUP_ACCT_MAX];
    size_t acctB_len = sizeof(acctB), acctC_len = sizeof(acctC);
    size_t acctA_len = sizeof(acctA), acctB2_len = sizeof(acctB2);
    struct gy_qsgroup_acct_ref brefs[1];
    uint8_t b_uk[GY_QSGROUP_USER_KEY_MAX], c_uk[GY_QSGROUP_USER_KEY_MAX];
    uint8_t a_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t b_uklen = sizeof(b_uk), c_uklen = sizeof(c_uk);
    size_t a_uklen = sizeof(a_uk);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen = sizeof(env);
    uint8_t gid_out[GY_QSGROUP_GID_LEN];
    uint8_t h0[256], m0[2048], v0[512], s0[8192];
    uint8_t h1[256], m1[2048], v1[512], s1[8192];
    uint8_t h2[256], m2[2048], v2[512], s2[8192];
    struct gy_qsgroup_core cur, next, cons;
    uint8_t lref[GY_QSGROUP_APPENDIX_MAX], lattr[GY_QSGROUP_APPENDIX_MAX];
    uint8_t ladd[GY_QSGROUP_APPENDIX_MAX], lleave[GY_QSGROUP_APPENDIX_MAX];
    size_t lref_l, lattr_l, ladd_l, lleave_l;
    uint8_t apxobj[16384];
    size_t apxlen;
    uint8_t c_vkhash[64];
    size_t c_vkhashlen = sizeof(c_vkhash);
    struct gy_qsgroup_member_view fv[8], cv[8];
    size_t fcount = 0, ccount = 0;
    struct gy_qsgroup_apx_report reps[8];
    size_t nreps = 0;
    uint8_t attr[64];
    size_t attrlen = sizeof(attr);
    uint8_t *objs[4];
    size_t lens[4];
    size_t i;
    int ai, bi, ci;

    /* A acquaints B and C (registration records + conveyed uks). */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB, &acctB_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk, &b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB, acctB_len,
                  b_uk, b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC, &acctC_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC, acctC_len,
                  c_uk, c_uklen),
              GY_OK);

    /* B accepts A, so B can verify A's admin-signed core (open_current resolves
     * the signer's base key from B's acquaintance record). */
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(a, &a_curve, &a_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(a, 1, a_uk, &a_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  b, SELF_UID, sizeof(SELF_UID), a_curve, a_mldsa, acctA,
                  acctA_len, a_uk, a_uklen),
              GY_OK);

    /* A creates (b_add | b_attr), adds B, and hands B the group key. */
    cur.hdr = h0;
    cur.hdr_len = sizeof(h0);
    cur.member_list = m0;
    cur.member_list_len = sizeof(m0);
    cur.vk_lst = v0;
    cur.vk_lst_len = sizeof(v0);
    cur.sig = s0;
    cur.sig_len = sizeof(s0);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);
    next.hdr = h1;
    next.hdr_len = sizeof(h1);
    next.member_list = m1;
    next.member_list_len = sizeof(m1);
    next.vk_lst = v1;
    next.vk_lst_len = sizeof(v1);
    next.sig = s1;
    next.sig_len = sizeof(s1);
    ASSERT_EQ(
        gy_custodian_qsgroup_add_member(a, &cur, B_UID, sizeof(B_UID), &next),
        GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_group_key(a, GID, env, &envlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_install_group_key(b, env, envlen, gid_out),
              GY_OK);

    /* Appendix over the 2-member core (vMin 1): B refresh, A modAttr, A addUser
     * C, B leave.  B refresh then B leave exercises the paper's same-member
     * ordering (refresh applies, then the leave removes). */
    lref_l = sizeof(lref);
    ASSERT_EQ(
        gy_custodian_qsgroup_appendix_refresh(b, &next, 1, 2, lref, &lref_l),
        GY_OK);
    lattr_l = sizeof(lattr);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_mod_attr(
                  a, &next, 1, (const uint8_t *)"attrs2", 6, lattr, &lattr_l),
              GY_OK);
    ladd_l = sizeof(ladd);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_add_user(
                  a, &next, 1, C_UID, sizeof(C_UID), c_uk, mklen, ladd, &ladd_l,
                  c_vkhash, &c_vkhashlen),
              GY_OK);
    lleave_l = sizeof(lleave);
    ASSERT_EQ(
        gy_custodian_qsgroup_appendix_leave(b, &next, 1, lleave, &lleave_l),
        GY_OK);
    objs[0] = lref;
    objs[1] = lattr;
    objs[2] = ladd;
    objs[3] = lleave;
    lens[0] = lref_l;
    lens[1] = lattr_l;
    lens[2] = ladd_l;
    lens[3] = lleave_l;
    merge_appendix(GY_SUITE_H25519_512, objs, lens, 4, apxobj, sizeof(apxobj),
                   &apxlen);

    /* Fetch computes the effective roster from (core + appendix). */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0, NULL,
                  0, fv, 8, &fcount, reps, 8, &nreps, attr, sizeof(attr),
                  &attrlen),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)4);
    for (i = 0; i < 4; i++)
        ASSERT_EQ(reps[i].valid, 1);
    ASSERT_EQ(fcount, (size_t)2); /* A + C; B left. */
    ai = find_uid(fv, fcount, SELF_UID, sizeof(SELF_UID));
    bi = find_uid(fv, fcount, B_UID, sizeof(B_UID));
    ci = find_uid(fv, fcount, C_UID, sizeof(C_UID));
    ASSERT_TRUE(ai >= 0 && ci >= 0, "A and C present");
    ASSERT_TRUE(bi < 0, "B left");
    ASSERT_EQ(fv[ai].admn, 1);
    ASSERT_MEMEQ(fv[ci].uk, c_uk, mklen);
    ASSERT_EQ(attrlen, (size_t)6);
    ASSERT_MEMEQ(attr, "attrs2", 6);

    /*
     * A tampered line signature is reported invalid and not applied: corrupt
     * the leave line's signature, re-merge, and B stays in the roster.  Done
     * before Consolidate, while A still holds the pre-rotation group key that
     * decrypts this core.
     */
    lleave[lleave_l - 1] ^= 0x01;
    merge_appendix(GY_SUITE_H25519_512, objs, lens, 4, apxobj, sizeof(apxobj),
                   &apxlen);
    attrlen = sizeof(attr);
    /*
     * B stays in this roster (its leave is invalid) but the valid refresh line
     * already advanced B to ep2, so IsCorrectUserKey (D-QGS-14 E12) needs B's
     * new-epoch ACCT to attest the refreshed uk; supply it.
     */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 2, acctB2, &acctB2_len), GY_OK);
    brefs[0].uid = B_UID;
    brefs[0].uid_len = sizeof(B_UID);
    brefs[0].acct = acctB2;
    brefs[0].acct_len = acctB2_len;
    brefs[0].curve_pk = b_curve;
    brefs[0].mldsa_pk = b_mldsa;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0,
                  brefs, 1, fv, 8, &fcount, reps, 8, &nreps, attr, sizeof(attr),
                  &attrlen),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)4);
    ASSERT_EQ(reps[3].valid, 0); /* the corrupted leave line. */
    ASSERT_EQ(reps[0].valid, 1);
    ASSERT_EQ(fcount, (size_t)3); /* B not removed: A + B + C. */
    ASSERT_TRUE(find_uid(fv, fcount, B_UID, sizeof(B_UID)) >= 0, "B remains");

    /* Restore the leave signature and re-merge the valid appendix. */
    lleave[lleave_l - 1] ^= 0x01;
    merge_appendix(GY_SUITE_H25519_512, objs, lens, 4, apxobj, sizeof(apxobj),
                   &apxlen);

    /* Consolidate folds the valid appendix; the folded leave rotates gk. */
    cons.hdr = h2;
    cons.hdr_len = sizeof(h2);
    cons.member_list = m2;
    cons.member_list_len = sizeof(m2);
    cons.vk_lst = v2;
    cons.vk_lst_len = sizeof(v2);
    cons.sig = s2;
    cons.sig_len = sizeof(s2);
    ASSERT_EQ(gy_custodian_qsgroup_consolidate(a, &next, apxobj, apxlen, NULL,
                                               0, NULL, 0, NULL, 0, &cons, NULL,
                                               NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_commit(a, GID), GY_OK); /* leave folded ->
                                                            * gk rotated. */

    /* Fetching the consolidated core yields the roster Fetch computed above. */
    attrlen = sizeof(attr);
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cons.hdr, cons.hdr_len, cons.member_list,
                  cons.member_list_len, cons.vk_lst, cons.vk_lst_len, cons.sig,
                  cons.sig_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, cv,
                  8, &ccount, NULL, 0, NULL, attr, sizeof(attr), &attrlen),
              GY_OK);
    ASSERT_EQ(ccount, (size_t)2);
    ai = find_uid(cv, ccount, SELF_UID, sizeof(SELF_UID));
    bi = find_uid(cv, ccount, B_UID, sizeof(B_UID));
    ci = find_uid(cv, ccount, C_UID, sizeof(C_UID));
    ASSERT_TRUE(ai >= 0 && ci >= 0 && bi < 0,
                "consolidated roster equals the fetch-computed roster");
    ASSERT_EQ(cv[ai].admn, 1);
    ASSERT_MEMEQ(cv[ci].uk, c_uk, mklen);
    ASSERT_EQ(attrlen, (size_t)6);
    ASSERT_MEMEQ(attr, "attrs2", 6);

    gy_custodian_close(a);
    gy_custodian_close(b);
    gy_custodian_close(cc);
}

/*
 * D-QGS-14 E9 ApproveJoin gate: a group created with b_adm set requires an
 * admin to approve link joiners.  A valid JOIN line is reported pending
 * approval and kept out of the Fetch roster; Consolidate without approval
 * leaves the joiner out, and Consolidate with the line's index in the approval
 * array folds it in ([CFG+] App. B.8, Fig. 22 AJ.3).
 */
TEST(gated_join_requires_approval)
{
    struct mstore mA, mD;
    gy_store_callbacks cbA, cbD;
    static const uint8_t D_UID[GY_QSGROUP_UID_LEN] = {0xda, 0xdb, 0xdc, 0xdd,
                                                      0xde, 0xdf, 0xe0};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *d =
        bring_up_as(GY_SUITE_H25519_512, &mD, &cbD, D_UID, sizeof(D_UID));
    size_t mklen = gy_qspgs_master_key_len(GY_SUITE_H25519_512);
    uint8_t secret[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t d_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_uk_len = sizeof(d_uk), jlen;
    uint8_t acctD[GY_QSGROUP_ACCT_MAX], acctA[GY_QSGROUP_ACCT_MAX];
    size_t acctD_len = sizeof(acctD), acctA_len = sizeof(acctA);
    const uint8_t *d_curve, *d_mldsa;
    uint8_t d_acq_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_acq_uklen = sizeof(d_acq_uk);
    uint8_t jline[GY_QSGROUP_APPENDIX_MAX];
    uint8_t apxobj[16384];
    size_t apxlen;
    uint8_t h0[256], m0[2048], v0[512], s0[8192];
    uint8_t h1[256], m1[2048], v1[512], s1[8192];
    uint8_t h2[256], m2[2048], v2[512], s2[8192];
    struct gy_qsgroup_core cur, next, cons;
    struct gy_qsgroup_member_view fv[8];
    size_t fcount = 0;
    struct gy_qsgroup_apx_report reps[8];
    size_t nreps = 0;
    uint8_t *objs[1];
    size_t lens[1];
    uint32_t approve0 = 0;

    /* A acquaints D so it can resolve D's base key for the JOIN line. */
    ASSERT_EQ(gy_custodian_qsgroup_register(d, 1, acctD, &acctD_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(d, &d_curve, &d_mldsa), GY_OK);
    ASSERT_EQ(
        gy_custodian_qsgroup_export_user_key(d, 1, d_acq_uk, &d_acq_uklen),
        GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, D_UID, sizeof(D_UID), d_curve, d_mldsa, acctD, acctD_len,
                  d_acq_uk, d_acq_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_register(a, 1, acctA, &acctA_len), GY_OK);

    /* A creates a group that REQUIRES admin approval of link joiners (b_adm). */
    cur.hdr = h0;
    cur.hdr_len = sizeof(h0);
    cur.member_list = m0;
    cur.member_list_len = sizeof(m0);
    cur.vk_lst = v0;
    cur.vk_lst_len = sizeof(v0);
    cur.sig = s0;
    cur.sig_len = sizeof(s0);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADM,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);

    /* A opens a join link; D joins via it, producing a JOIN appendix line. */
    next.hdr = h1;
    next.hdr_len = sizeof(h1);
    next.member_list = m1;
    next.member_list_len = sizeof(m1);
    next.vk_lst = v1;
    next.vk_lst_len = sizeof(v1);
    next.sig = s1;
    next.sig_len = sizeof(s1);
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);
    jlen = sizeof(jline);
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(d, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uk_len,
                                                 jline, &jlen),
              GY_OK);
    assert_apx_line(GY_SUITE_H25519_512, jline, jlen, GY_QAPX_JOIN);
    objs[0] = jline;
    lens[0] = jlen;
    merge_appendix(GY_SUITE_H25519_512, objs, lens, 1, apxobj, sizeof(apxobj),
                   &apxlen);

    /* Fetch: the JOIN line is held pending approval, not applied. */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0, NULL,
                  0, fv, 8, &fcount, reps, 8, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].line_type, GY_QAPX_JOIN);
    ASSERT_EQ(reps[0].valid, 0);
    ASSERT_EQ(reps[0].pending_approval, 1);
    ASSERT_EQ(fcount, (size_t)1); /* only A; D held for approval. */
    ASSERT_TRUE(find_uid(fv, fcount, D_UID, sizeof(D_UID)) < 0,
                "D is not yet a member");

    /* Consolidate WITHOUT approval leaves D out. */
    cons.hdr = h2;
    cons.hdr_len = sizeof(h2);
    cons.member_list = m2;
    cons.member_list_len = sizeof(m2);
    cons.vk_lst = v2;
    cons.vk_lst_len = sizeof(v2);
    cons.sig = s2;
    cons.sig_len = sizeof(s2);
    ASSERT_EQ(gy_custodian_qsgroup_consolidate(a, &next, apxobj, apxlen, NULL,
                                               0, NULL, 0, NULL, 0, &cons, NULL,
                                               NULL),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, cons.hdr, cons.hdr_len, cons.member_list,
                           cons.member_list_len, cons.vk_lst, cons.vk_lst_len,
                           cons.sig, cons.sig_len, fv, 8, &fcount),
              GY_OK);
    ASSERT_EQ(fcount, (size_t)1); /* still just A. */

    /* Consolidate WITH the line approved folds D in. */
    cons.hdr_len = sizeof(h2);
    cons.member_list_len = sizeof(m2);
    cons.vk_lst_len = sizeof(v2);
    cons.sig_len = sizeof(s2);
    ASSERT_EQ(gy_custodian_qsgroup_consolidate(a, &next, apxobj, apxlen, NULL,
                                               0, NULL, 0, &approve0, 1, &cons,
                                               NULL, NULL),
              GY_OK);
    ASSERT_EQ(qsg_fetch_np(a, cons.hdr, cons.hdr_len, cons.member_list,
                           cons.member_list_len, cons.vk_lst, cons.vk_lst_len,
                           cons.sig, cons.sig_len, fv, 8, &fcount),
              GY_OK);
    ASSERT_EQ(fcount, (size_t)2); /* A + D. */
    ASSERT_TRUE(find_uid(fv, fcount, D_UID, sizeof(D_UID)) >= 0,
                "D is a member after approval");
    (void)mklen;

    gy_custodian_close(a);
    gy_custodian_close(d);
}

/*
 * Settings gating (harness-free): a UserAdd line is reported
 * invalid when the group's b_add bit is clear, and a ModAttr line when b_attr
 * is clear ([CFG+] Fig. 16).  The lines are genuinely signed (built by the
 * public API); Fetch rejects them purely on the settings gate.
 */
TEST(gated_off_adduser)
{
    struct mstore mA, mC;
    gy_store_callbacks cbA, cbC;
    static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3,
                                                      0xc4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    const uint8_t *c_curve, *c_mldsa;
    uint8_t acctC[GY_QSGROUP_ACCT_MAX];
    size_t acctC_len = sizeof(acctC);
    uint8_t c_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t c_uklen = sizeof(c_uk);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    struct gy_qsgroup_core cur;
    uint8_t line[GY_QSGROUP_APPENDIX_MAX], vkhash[64];
    size_t linelen = sizeof(line), vkhashlen = sizeof(vkhash);
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;

    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC, &acctC_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC, acctC_len,
                  c_uk, c_uklen),
              GY_OK);

    /* Group with b_attr only: b_add is clear, so a UserAdd line is gated off. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ATTR,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_add_user(
                  a, &cur, 0, C_UID, sizeof(C_UID), c_uk, c_uklen, line,
                  &linelen, vkhash, &vkhashlen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, line,
                  linelen, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0); /* b_add clear: UserAdd ignored. */
    ASSERT_EQ(count, (size_t)1);

    gy_custodian_close(a);
    gy_custodian_close(cc);
}

TEST(gated_off_modattr)
{
    struct mstore mA;
    gy_store_callbacks cbA;
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xe2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a = bring_up(GY_SUITE_H25519_512, &mA, &cbA);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    struct gy_qsgroup_core cur;
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    uint8_t attr[64];
    size_t linelen = sizeof(line), attrlen = sizeof(attr);
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;

    /* Group with b_add only: b_attr is clear, so a ModAttr line is gated off. */
    cur.hdr = hx;
    cur.hdr_len = sizeof(hx);
    cur.member_list = mx;
    cur.member_list_len = sizeof(mx);
    cur.vk_lst = vx;
    cur.vk_lst_len = sizeof(vx);
    cur.sig = sx;
    cur.sig_len = sizeof(sx);
    ASSERT_EQ(gy_custodian_qsgroup_create(
                  a, GID, 1, GY_QSGROUP_SETTING_ADD,
                  GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, cur.hdr,
                  &cur.hdr_len, cur.member_list, &cur.member_list_len,
                  cur.vk_lst, &cur.vk_lst_len, cur.sig, &cur.sig_len, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_appendix_mod_attr(
                  a, &cur, 0, (const uint8_t *)"nope", 4, line, &linelen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, line,
                  linelen, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  reps, 4, &nreps, attr, sizeof(attr), &attrlen),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0);   /* b_attr clear: ModAttr ignored. */
    ASSERT_EQ(attrlen, (size_t)0); /* attributes unchanged (created empty). */

    gy_custodian_close(a);
}

GY_TEST_MAIN(
    GY_TEST(init), GY_TEST(self_uid_and_format_version),
    GY_TEST(reject_classical_custodian),
    GY_TEST(identity_signers_reject_malformed),
    GY_TEST(register_and_accept_roundtrip), GY_TEST(register_rejects_classical),
    GY_TEST(create_and_fetch_roundtrip), GY_TEST(create_aead_pin),
    GY_TEST(admin_edits_roundtrip), GY_TEST(rotating_edit_stages_group_key),
    GY_TEST(invite_flow_roundtrip), GY_TEST(revoke_blocks_reaccept),
    GY_TEST(settings_appendix_joinlink), GY_TEST(server_checks_via_accessors),
    GY_TEST(identity_public_enables_accept),
    GY_TEST(group_key_envelope_roundtrip), GY_TEST(fetch_iscorrect_userkey),
    GY_TEST(refresh_rechecks_acquainted_userkey),
    GY_TEST(joinlink_survives_rotation),
    GY_TEST(joinlink_dropped_by_foreign_admin),
    GY_TEST(appendix_fold_and_consolidate),
    GY_TEST(gated_join_requires_approval), GY_TEST(gated_off_adduser),
    GY_TEST(gated_off_modattr))
