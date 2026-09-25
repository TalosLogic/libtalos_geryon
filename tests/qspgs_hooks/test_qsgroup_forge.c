/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * D-QGS-13 E5 (malicious-admin forge): a malicious admin signs a
 * core whose vk-lst carries a foreign / wrong H(vkpsdn) at a NON-signer index.
 * The admin signature is genuine, so the signer's own entry resolves and the
 * core signature verifies; only Fetch's E5 all-member vk-lst recompute
 * (gy_custodian_qsgroup_fetch, D-QGS-13 E5) catches the substitution, at the
 * offending index, with GY_ERR_VERIFY.  The forged signature is minted through
 * the GY_TEST_HOOKS seam gy_custodian_qsgroup_hook_sign_core (qspgs_hooks.h),
 * which no production build carries; this harness recompiles the QSPGS client
 * stack with -DGY_TEST_HOOKS.  A build that dropped the E5 recompute would
 * ACCEPT this core (GY_OK), so this test is what pins the recompute in place.
 */

#include <stdint.h>
#include <string.h>

#include "geryon.h"
#include "geryon_qspgs.h"

#include "custodian.h"   /* GY_CUST_BLOB_MAX + gy_custodian_identity_dual_pub */
#include "qspgs_hooks.h" /* the GY_TEST_HOOKS forging seams */
#include "qspgs_wire.h"  /* appendix decode + GY_QAPX_* line kinds */
#include "util.h"        /* gy_core_init */

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

static const uint8_t CRED[] = "qsgroup forge credential";
static const uint8_t SELF_UID[GY_QSGROUP_UID_LEN] = {0xa1, 0xa2, 0xa3, 0xa4,
                                                     0xa5, 0xa6, 0xa7, 0xa8};
static const uint8_t B_UID[GY_QSGROUP_UID_LEN] = {0xb0, 0xb1, 0xb2,
                                                  0xb3, 0xb4, 0xb5};
static const uint8_t C_UID[GY_QSGROUP_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4};
static const uint8_t DID[4] = {0xd1, 0xd2, 0xd3, 0xd4};

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

TEST(init)
{
    ASSERT_EQ(gy_core_init(), GY_OK);
}

/*
 * A creates a group and adds B (a 2-member core, A the admin at index 0, B at
 * index 1).  The real core fetches cleanly.  Then A (a malicious admin) flips
 * B's stored H(vkpsdn) and RE-SIGNS the core through the forging seam: the
 * signature is genuine and A's own vk-lst entry is untouched, so the signer
 * check passes, but the E5 all-member recompute rejects B's substituted entry.
 */
TEST(malicious_admin_foreign_vkhash_e5)
{
    struct mstore mA, mB;
    gy_store_callbacks cbA, cbB;
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf5, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a =
        bring_up_as(GY_SUITE_H25519_512, &mA, &cbA, SELF_UID, sizeof(SELF_UID));
    gy_custodian *b =
        bring_up_as(GY_SUITE_H25519_512, &mB, &cbB, B_UID, sizeof(B_UID));
    const uint8_t *b_curve, *b_mldsa;
    uint8_t acctB[GY_QSGROUP_ACCT_MAX];
    size_t acctB_len = sizeof(acctB);
    uint8_t b_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t b_uklen = sizeof(b_uk);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;
    uint8_t vtamper[512], forged[8192];
    size_t forged_len = sizeof(forged);
    struct gy_qsgroup_member_view views[8];
    size_t count = 0;

    /* A acquaints B (registration record + conveyed uk). */
    ASSERT_EQ(gy_custodian_qsgroup_register(b, 1, acctB, &acctB_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(b, &b_curve, &b_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(b, 1, b_uk, &b_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, B_UID, sizeof(B_UID), b_curve, b_mldsa, acctB, acctB_len,
                  b_uk, b_uklen),
              GY_OK);

    /* A creates the group (set X), then adds B (set Y). */
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

    /* Control: the honest 2-member core fetches and decrypts cleanly. */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0,
                  views, 8, &count, NULL, 0, NULL, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(count, (size_t)2);

    /*
     * Substitute B's vk-lst entry (the last byte of the packed hashes is in
     * B's H(vkpsdn) at index 1; A, the signer, is at index 0 and untouched),
     * then re-sign the tampered core with A's genuine pseudonym signature.
     */
    ASSERT_TRUE(next.vk_lst_len <= sizeof(vtamper), "vk-lst fits");
    memcpy(vtamper, next.vk_lst, next.vk_lst_len);
    vtamper[next.vk_lst_len - 1] ^= 0x01;
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_core(
                  a, GID, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, vtamper, next.vk_lst_len, 0, 0, forged,
                  &forged_len),
              GY_OK);

    /*
     * The forged core carries a genuine admin signature over the tampered
     * vk-lst, so the signer (index 0) still resolves; the E5 all-member
     * recompute rejects B's substituted entry (index 1).
     */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, vtamper, next.vk_lst_len, forged,
                  forged_len, NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0,
                  views, 8, &count, NULL, 0, NULL, NULL, 0, NULL),
              GY_ERR_VERIFY);

    gy_custodian_close(a);
    gy_custodian_close(b);
}

/*
 * CheckAppendixLine ([CFG+] Fig. 16): a UserAdd line whose C_UID' does NOT open
 * to (UID', r') is reported invalid and not applied, even though its author
 * signature is genuine.  A valid line is built through the public API, its
 * commitment byte is corrupted, and the line is RE-SIGNED via the forging seam
 * (so the signature covers the corrupted payload and the check reaches the
 * commitment test rather than failing at the signature).
 */
TEST(adduser_bad_commitment)
{
    struct mstore mA, mC;
    gy_store_callbacks cbA, cbC;
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a =
        bring_up_as(GY_SUITE_H25519_512, &mA, &cbA, SELF_UID, sizeof(SELF_UID));
    gy_custodian *cc =
        bring_up_as(GY_SUITE_H25519_512, &mC, &cbC, C_UID, sizeof(C_UID));
    const uint8_t *c_curve, *c_mldsa;
    uint8_t acctC[GY_QSGROUP_ACCT_MAX];
    size_t acctC_len = sizeof(acctC);
    uint8_t c_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t c_uklen = sizeof(c_uk);
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    struct gy_qsgroup_core cur;
    uint8_t line[GY_QSGROUP_APPENDIX_MAX], forged[GY_QSGROUP_APPENDIX_MAX];
    uint8_t payload[GY_QSGROUP_APPENDIX_MAX], vkhash[64];
    size_t linelen = sizeof(line), forged_len = sizeof(forged);
    size_t vkhashlen = sizeof(vkhash), consumed, payload_len;
    struct gy_qspgs_appendix apx;
    struct gy_qspgs_apx_line lines[4];
    uint32_t author_index;
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;

    /* A acquaints C (UserAdd computes the newcomer's H(vkpsdn) from the AcqRec). */
    ASSERT_EQ(gy_custodian_qsgroup_register(cc, 1, acctC, &acctC_len), GY_OK);
    ASSERT_EQ(gy_custodian_identity_dual_pub(cc, &c_curve, &c_mldsa), GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_export_user_key(cc, 1, c_uk, &c_uklen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_accept_acquaintance(
                  a, C_UID, sizeof(C_UID), c_curve, c_mldsa, acctC, acctC_len,
                  c_uk, c_uklen),
              GY_OK);

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

    /* A valid UserAdd line (vMin 0), then corrupt C_UID' and re-sign it. */
    ASSERT_EQ(gy_custodian_qsgroup_appendix_add_user(
                  a, &cur, 0, C_UID, sizeof(C_UID), c_uk, c_uklen, line,
                  &linelen, vkhash, &vkhashlen),
              GY_OK);
    memset(&apx, 0, sizeof(apx));
    apx.suite_id = GY_SUITE_H25519_512;
    ASSERT_EQ(
        gy_qspgs_appendix_decode(&apx, lines, 4, line, linelen, &consumed),
        GY_OK);
    ASSERT_EQ(apx.n_lines, (size_t)1);
    payload_len = lines[0].payload_len;
    author_index = lines[0].author_index;
    ASSERT_TRUE(payload_len <= sizeof(payload), "payload fits");
    memcpy(payload, lines[0].payload, payload_len);
    payload[0] ^=
        0x01; /* corrupt C_UID' so it no longer opens to (UID', r'). */
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_line(
                  a, GID, apx.vmaj, apx.vmin, GY_QAPX_ADDUSER, author_index,
                  payload, payload_len, forged, &forged_len),
              GY_OK);

    /* Fetch reports the line invalid and does not add C (roster stays 1). */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, forged,
                  forged_len, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8,
                  &count, reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0);
    ASSERT_EQ(count, (size_t)1);

    gy_custodian_close(a);
    gy_custodian_close(cc);
}

/*
 * CheckAppendixLine ([CFG+] Fig. 16): a JOIN line is reported invalid when the
 * core has no open join link, regardless of the line's contents (the check
 * short-circuits before opening or verifying it).  A JOIN line is forged at the
 * created (link-closed) core's version and rejected.
 */
TEST(join_without_open_link)
{
    struct mstore mA;
    gy_store_callbacks cbA;
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a =
        bring_up_as(GY_SUITE_H25519_512, &mA, &cbA, SELF_UID, sizeof(SELF_UID));
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    struct gy_qsgroup_core cur;
    uint8_t dummy[16] = {0};
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    size_t linelen = sizeof(line);
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;

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

    /* Forge a JOIN line at the created core's version (vMaj 1); the group has
     * no open link, so the created core carries no join slot. */
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_line(a, GID, 1, 0, GY_QAPX_JOIN, 1,
                                                  dummy, sizeof(dummy), line,
                                                  &linelen),
              GY_OK);
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, line,
                  linelen, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0); /* no open link: the JOIN line is ignored. */
    ASSERT_EQ(count, (size_t)1);

    gy_custodian_close(a);
}

/*
 * CheckAppendixLine ([CFG+] Fig. 16, D-QGS-14 E14): a JOIN line now carries a
 * cleartext C_UID' commitment like addUser, so a JOIN line whose C_UID' does
 * NOT open to (UID', r') is reported invalid even with an open link and a
 * genuine author signature.  A valid join line is built via JoinViaLink, its
 * commitment byte is corrupted, and the line is RE-SIGNED via the forging seam
 * so the check reaches the commitment test rather than failing at the signature.
 */
TEST(join_bad_commitment)
{
    struct mstore mA, mD;
    gy_store_callbacks cbA, cbD;
    static const uint8_t D_UID[GY_QSGROUP_UID_LEN] = {0xd1, 0xd2, 0xd3, 0xd4};
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a =
        bring_up_as(GY_SUITE_H25519_512, &mA, &cbA, SELF_UID, sizeof(SELF_UID));
    gy_custodian *d =
        bring_up_as(GY_SUITE_H25519_512, &mD, &cbD, D_UID, sizeof(D_UID));
    const uint8_t *d_curve, *d_mldsa;
    uint8_t acctD[GY_QSGROUP_ACCT_MAX], acctA[GY_QSGROUP_ACCT_MAX];
    size_t acctD_len = sizeof(acctD), acctA_len = sizeof(acctA);
    uint8_t d_acq_uk[GY_QSGROUP_USER_KEY_MAX], d_uk[GY_QSGROUP_USER_KEY_MAX];
    size_t d_acq_uklen = sizeof(d_acq_uk), d_uklen = sizeof(d_uk);
    uint8_t secret[GY_QSGROUP_LINK_SECRET_LEN];
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    uint8_t hy[256], my[2048], vy[512], sy[8192];
    struct gy_qsgroup_core cur, next;
    uint8_t jline[GY_QSGROUP_APPENDIX_MAX], forged[GY_QSGROUP_APPENDIX_MAX];
    uint8_t payload[GY_QSGROUP_APPENDIX_MAX];
    size_t jlen = sizeof(jline), forged_len = sizeof(forged);
    size_t consumed, payload_len;
    struct gy_qspgs_appendix apx;
    struct gy_qspgs_apx_line lines[4];
    uint32_t author_index;
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count = 0, nreps = 0;

    /* A acquaints D so it can resolve the JOIN author's base key at fetch. */
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

    /* A creates, then opens a join link (set X -> set Y). */
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
    ASSERT_EQ(gy_custodian_qsgroup_toggle_join_link(a, &cur, secret, &next),
              GY_OK);

    /* D joins via the link, producing a valid JOIN line. */
    ASSERT_EQ(gy_custodian_qsgroup_join_via_link(d, &next, secret, 1, acctA,
                                                 acctA_len, d_uk, &d_uklen,
                                                 jline, &jlen),
              GY_OK);

    /* Corrupt the C_UID' prefix and re-sign the JOIN line as its author D. */
    memset(&apx, 0, sizeof(apx));
    apx.suite_id = GY_SUITE_H25519_512;
    ASSERT_EQ(gy_qspgs_appendix_decode(&apx, lines, 4, jline, jlen, &consumed),
              GY_OK);
    ASSERT_EQ(apx.n_lines, (size_t)1);
    payload_len = lines[0].payload_len;
    author_index = lines[0].author_index;
    ASSERT_TRUE(payload_len <= sizeof(payload), "payload fits");
    memcpy(payload, lines[0].payload, payload_len);
    payload[0] ^=
        0x01; /* corrupt C_UID' so it no longer opens to (UID', r'). */
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_line(
                  d, GID, apx.vmaj, apx.vmin, GY_QAPX_JOIN, author_index,
                  payload, payload_len, forged, &forged_len),
              GY_OK);

    /* Fetch reports the JOIN line invalid (commitment mismatch); D not added. */
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, next.hdr, next.hdr_len, next.member_list,
                  next.member_list_len, next.vk_lst, next.vk_lst_len, next.sig,
                  next.sig_len, forged, forged_len, NULL, 0, 0, 0, 0, NULL, 0,
                  NULL, 0, views, 8, &count, reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0);
    ASSERT_EQ(count, (size_t)1);

    gy_custodian_close(a);
    gy_custodian_close(d);
}

/*
 * CheckAppendixLine ([CFG+] Fig. 16, MED-1): a validly signed refresh or modAttr
 * line whose ek payload does not open must be reported invalid and skipped, NOT
 * abort the whole Fetch.  Both lines are authored by the (sole, admin) member
 * with a genuine author signature over a garbage payload; a build that opened
 * the payload only in the apply pass would return GY_ERR_VERIFY for everyone.
 */
TEST(undecryptable_refresh_modattr_skipped)
{
    struct mstore mA;
    gy_store_callbacks cbA;
    static const uint8_t GID[GY_QSGROUP_GID_LEN] = {
        0xf9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    gy_custodian *a =
        bring_up_as(GY_SUITE_H25519_512, &mA, &cbA, SELF_UID, sizeof(SELF_UID));
    uint8_t hx[256], mx[2048], vx[512], sx[8192];
    struct gy_qsgroup_core cur;
    uint8_t garbage[32];
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    size_t linelen;
    struct gy_qsgroup_member_view views[8];
    struct gy_qsgroup_apx_report reps[4];
    size_t count, nreps;

    memset(garbage, 0x5a, sizeof(garbage)); /* not a valid ek ciphertext. */

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

    /* Genuinely signed REFRESH over a garbage uk payload (author index 0). */
    linelen = sizeof(line);
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_line(a, GID, 1, 0, GY_QAPX_REFRESH,
                                                  0, garbage, sizeof(garbage),
                                                  line, &linelen),
              GY_OK);
    count = 0;
    nreps = 0;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, line,
                  linelen, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid,
              0); /* undecryptable refresh: skipped, not abort. */
    ASSERT_EQ(count, (size_t)1);

    /* Same for a genuinely signed MODATTR over a garbage payload (b_attr set). */
    linelen = sizeof(line);
    ASSERT_EQ(gy_custodian_qsgroup_hook_sign_line(a, GID, 1, 0, GY_QAPX_MODATTR,
                                                  0, garbage, sizeof(garbage),
                                                  line, &linelen),
              GY_OK);
    count = 0;
    nreps = 0;
    ASSERT_EQ(gy_custodian_qsgroup_fetch(
                  a, cur.hdr, cur.hdr_len, cur.member_list, cur.member_list_len,
                  cur.vk_lst, cur.vk_lst_len, cur.sig, cur.sig_len, line,
                  linelen, NULL, 0, 0, 0, 0, NULL, 0, NULL, 0, views, 8, &count,
                  reps, 4, &nreps, NULL, 0, NULL),
              GY_OK);
    ASSERT_EQ(nreps, (size_t)1);
    ASSERT_EQ(reps[0].valid, 0);
    ASSERT_EQ(count, (size_t)1);

    gy_custodian_close(a);
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(malicious_admin_foreign_vkhash_e5),
             GY_TEST(adduser_bad_commitment), GY_TEST(join_without_open_link),
             GY_TEST(join_bad_commitment),
             GY_TEST(undecryptable_refresh_modattr_skipped))
