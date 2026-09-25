/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Standalone server-target test (QSPGS_SPEC section 7.1): links ONLY
 * geryon_qsgroups_server (plus the sk-free shared internal it pulls in), NOT the
 * client facade geryon_qspgs.  It therefore proves two things at once:
 *   1. Link-time: no server-side function reaches into client-only code (if it
 *      did, this target would fail to link) - the structural complement to the
 *      nm_scope_qspgs_server audit, which checks the server archive statically.
 *   2. Behaviour: the shipped section 7.3 checks run correctly as pure
 *      stateless functions, using no client symbol.
 *
 * Increment 1 ships the section 7.3 item-5 bearer-token compare; later
 * increments add the core / appendix signature checks and version discipline.
 * Client<->server round-trips are covered by the client-linked tests.
 *
 * The PUBLIC handle-free server facade
 * (geryon_qsgroups_server.h) decodes the opaque wire objects internally
 * and forwards to those checks.  Its cases (public_*) also link server-only, so
 * they prove the public facade too carries no client symbol; they drive the
 * decode-internally plumbing and every gate to a definitive negative (a dummy
 * signature / stored hash never verifies).  The positive acceptance round-trip
 * needs a client-signed core and lives in the client-linked tests.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "geryon_qsgroups_server.h" /* the PUBLIC handle-free server facade */
#include "qspgs_server.h"
#include "qspgs_wire.h" /* GY_QSPGS_FET_LEN, struct gy_qspgs_core, encoders */
#include "suite.h"      /* gy_suite_desc: the tier vkr (dsa pk) length */
#include "util.h"       /* gy_core_init */

#include "gy_test.h"

TEST(init)
{
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(token_check)
{
    uint8_t stored[GY_QSPGS_FET_LEN];
    uint8_t presented[GY_QSPGS_FET_LEN];
    size_t i;

    for (i = 0; i < GY_QSPGS_FET_LEN; i++)
        stored[i] = (uint8_t)(0x40 + i);
    memcpy(presented, stored, sizeof(presented));

    /* Matching bearer token accepts. */
    ASSERT_EQ(gy_qspgs_server_token_check(presented, stored, sizeof(stored)),
              GY_OK);

    /* A single-byte difference (last byte, so a prefix match cannot mask it)
     * is rejected. */
    presented[GY_QSPGS_FET_LEN - 1] ^= 0x01;
    ASSERT_EQ(gy_qspgs_server_token_check(presented, stored, sizeof(stored)),
              GY_ERR_VERIFY);

    /* Argument checks: NULL either side, or a zero length. */
    ASSERT_EQ(gy_qspgs_server_token_check(NULL, stored, sizeof(stored)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_server_token_check(presented, NULL, sizeof(stored)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_server_token_check(presented, stored, 0), GY_ERR_ARG);
}

/*
 * The section 7.3 acceptance checks that need no real signature, exercised
 * standalone (no client symbol): argument validation, the hybrid-only suite
 * gate, the signer-index bound, and the item-1 admn gate (a non-admin signer is
 * rejected BEFORE any hash or signature work, so no client-built core is
 * needed).  The positive acceptance round-trip, which needs a client-signed
 * core, lives in test_qspgs_ops (which links both facades).
 */
TEST(server_checks_standalone)
{
    uint8_t vkr[GY_QSPGS_VKR_MAX], sig[GY_QSPGS_SIG_MAX];
    uint8_t vkhash[GY_QSPGS_HASH_MAX], scratch[4096];
    struct gy_qspgs_member mem[1];
    struct gy_qspgs_core core;

    memset(vkr, 0x5a, sizeof(vkr));
    memset(sig, 0x6b, sizeof(sig));
    memset(vkhash, 0x00, sizeof(vkhash));
    memset(mem, 0, sizeof(mem)); /* admn = 0 (non-admin). */

    memset(&core, 0, sizeof(core));
    core.suite_id = GY_SUITE_H25519_512;
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    core.members = mem;
    core.n_members = 1;
    core.vkhash = vkhash;
    core.n_vk = 1;

    /*
     * Item 1 admn gate (D-QGS-13 E2): the gate reads the PRIOR mem-lst, so a
     * non-admin prior signer is rejected before any crypto.  prior == next
     * here (a would-be UNCHANGED edit); members[0].admn is 0.
     */
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED, &core, 0,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_VERIFY);

    /* signer_index past the prior member / vk-lst entry. */
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED, &core, 1,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);

    /* A prior is required for any non-CREATE op. */
    ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_UNCHANGED, &core, 0,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);
    /* CREATE must NOT carry a prior. */
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_CREATE, &core, 0,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);
    /* An unknown operation kind is rejected. */
    ASSERT_EQ(gy_qspgs_server_core_check(&core, 0xFF, &core, 0, vkr, sig,
                                         sizeof(sig), scratch, sizeof(scratch)),
              GY_ERR_ARG);

    /* A classical suite has no QSPGS type: rejected (checked on next). */
    core.suite_id = GY_SUITE_C25519;
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED, &core, 0,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);
    core.suite_id = GY_SUITE_H25519_512;
    core.format_version = GY_QSPGS_FORMAT_VERSION;

    /* NULL next core and NULL signer_vkr. */
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED, NULL, 0,
                                         vkr, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED, &core, 0,
                                         NULL, sig, sizeof(sig), scratch,
                                         sizeof(scratch)),
              GY_ERR_ARG);
    /* NULL line (scratch stands in for a non-NULL gid) is rejected. */
    ASSERT_EQ(gy_qspgs_server_apx_check(GY_SUITE_H25519_512, scratch, 1, 0,
                                        NULL, vkr, vkhash, scratch,
                                        sizeof(scratch)),
              GY_ERR_ARG);
}

/*
 * Version discipline / compare-and-swap (section 7.3 item 4) and the fetch-token
 * check (item 5) - both pure, exercised standalone.
 */
TEST(server_version_and_fetch)
{
    uint8_t presented[GY_QSPGS_FET_LEN];
    struct gy_qspgs_core core;
    size_t i;

    /* Extends the head and strictly advances: a minor bump, then a major bump
     * from a fresh head, both accepted. */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 0, 1, 0, 1, 1), GY_OK);
    ASSERT_EQ(gy_qspgs_server_version_check(1, 5, 1, 5, 2, 0), GY_OK);

    /* A duplicate (new == cur) does not advance: conflict. */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 1, 1, 1, 1, 1), GY_ERR_STATE);

    /* A regression (new < cur) is rejected. */
    ASSERT_EQ(gy_qspgs_server_version_check(2, 0, 2, 0, 1, 9), GY_ERR_STATE);

    /* Stale writer: it extends (1,0) but the head is now (1,1) (a concurrent
     * write moved it), so even a strictly-greater new (2,0) is a conflict - the
     * server never merges. */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 1, 1, 0, 2, 0), GY_ERR_STATE);

    /* Fetch token: exact match accepts, a last-byte difference rejects. */
    memset(&core, 0, sizeof(core));
    for (i = 0; i < GY_QSPGS_FET_LEN; i++)
        core.fet[i] = (uint8_t)(0x90 + i);
    memcpy(presented, core.fet, sizeof(presented));
    ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, presented), GY_OK);
    presented[GY_QSPGS_FET_LEN - 1] ^= 0x01;
    ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, presented), GY_ERR_VERIFY);

    /* NULL arguments. */
    ASSERT_EQ(gy_qspgs_server_fetch_check(NULL, presented), GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, NULL), GY_ERR_ARG);
}

/* ---- public facade (geryon_qsgroups_server.h) --------------------------
 *
 * The handle-free public surface decodes the opaque wire objects internally and
 * forwards to the checks above.  These cases link ONLY the server target, so
 * they also prove the public facade reaches no client symbol.  The positive
 * acceptance round-trip needs a client-signed core and lives in test_qspgs_ops
 * (which links both facades); here we drive the decode-internally plumbing and
 * every gate to a definitive negative (the dummy signature / hash never
 * verifies), plus the argument and suite-gate paths.
 */

/* The three separately framed core objects the public checks consume. */
struct core_wire {
    uint8_t hdr[256];
    size_t hdr_len;
    uint8_t ml[256];
    size_t ml_len;
    uint8_t vk[256];
    size_t vk_len;
    uint8_t vkhash[GY_QSPGS_HASH_MAX];
};

/* Encode a minimal one-member, one-vk core (admn selects the member's flag)
 * into its header / member-list / vk-lst objects.  fet is all 0x33. */
static void
build_core(struct core_wire *w, uint8_t admn)
{
    struct gy_qspgs_core core;
    struct gy_qspgs_member mem[1];
    uint8_t mct[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t sa[4] = {9, 9, 9, 9};
    size_t n;

    memset(w, 0, sizeof(*w));
    memset(w->vkhash, 0x22, sizeof(w->vkhash));

    memset(&core, 0, sizeof(core));
    core.suite_id = GY_SUITE_H25519_512;
    memset(core.gid, 0xab, GY_QSPGS_GID_LEN);
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    core.vmaj = 1;
    memset(core.fet, 0x33, GY_QSPGS_FET_LEN);
    core.sa_ct = sa;
    core.sa_ct_len = sizeof(sa);

    memset(mem, 0, sizeof(mem));
    memset(mem[0].cuid, 0x11, GY_QSPGS_HASH_MAX);
    mem[0].admn = admn;
    mem[0].mct = mct;
    mem[0].mct_len = sizeof(mct);
    core.members = mem;
    core.n_members = 1;
    core.vkhash = w->vkhash;
    core.n_vk = 1;

    n = sizeof(w->hdr);
    ASSERT_EQ(gy_qspgs_header_encode(&core, w->hdr, sizeof(w->hdr), &n), GY_OK);
    w->hdr_len = n;
    n = sizeof(w->ml);
    ASSERT_EQ(gy_qspgs_member_list_encode(&core, w->ml, sizeof(w->ml), &n),
              GY_OK);
    w->ml_len = n;
    n = sizeof(w->vk);
    ASSERT_EQ(gy_qspgs_vk_lst_encode(&core, w->vk, sizeof(w->vk), &n), GY_OK);
    w->vk_len = n;
}

/* Encode a core-signature object over a dummy signature (signer index 0). */
static size_t
build_sig(uint8_t *out, size_t cap)
{
    uint8_t sig[8] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02};
    size_t n = cap;

    ASSERT_EQ(gy_qspgs_core_sig_encode(GY_SUITE_H25519_512, 0, 0, sig,
                                       sizeof(sig), out, cap, &n),
              GY_OK);
    return n;
}

/* Encode a one-line appendix object of the given line type with a full-length
 * dummy signature.  The line signature must be the tier's full width: the
 * verifier reads that many bytes from it (the resolve / newcomer path drives it
 * into the real verifier, which rejects the garbage bytes -> VERIFY). */
static size_t
build_apx_line(uint8_t *out, size_t cap, uint8_t line_type,
               uint32_t author_index)
{
    struct gy_qspgs_appendix apx;
    struct gy_qspgs_apx_line line;
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    uint8_t payload[4] = {1, 2, 3, 4};
    uint8_t sig[GY_QSPGS_SIG_MAX];
    size_t n = cap;

    memset(sig, 0x77, sizeof(sig));
    memset(&line, 0, sizeof(line));
    line.line_type = line_type;
    line.author_index = author_index;
    line.payload = payload;
    line.payload_len = sizeof(payload);
    line.sig = sig;
    line.sig_len = desc->dsa_sig_len; /* the tier's full signature width. */

    memset(&apx, 0, sizeof(apx));
    apx.suite_id = GY_SUITE_H25519_512;
    memset(apx.gid, 0xab, GY_QSPGS_GID_LEN);
    apx.vmaj = 1;
    apx.lines = &line;
    apx.n_lines = 1;

    ASSERT_EQ(gy_qspgs_appendix_encode(&apx, out, cap, &n), GY_OK);
    return n;
}

/* The tier's full pseudonym key (vkr) length == the ML-DSA public-key length. */
static size_t
tier_vkr_len(void)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);

    return desc != NULL ? desc->dsa_pk_len : 0;
}

TEST(public_passthroughs)
{
    uint8_t a[GY_QSPGS_FET_LEN], b[GY_QSPGS_FET_LEN];

    memset(a, 0x5c, sizeof(a));
    memcpy(b, a, sizeof(b));
    ASSERT_EQ(gy_qsgroups_server_token_check(a, b, sizeof(a)), GY_OK);
    b[sizeof(b) - 1] ^= 0x01;
    ASSERT_EQ(gy_qsgroups_server_token_check(a, b, sizeof(a)), GY_ERR_VERIFY);
    ASSERT_EQ(gy_qsgroups_server_token_check(NULL, b, sizeof(a)), GY_ERR_ARG);

    ASSERT_EQ(gy_qsgroups_server_version_check(1, 0, 1, 0, 1, 1), GY_OK);
    ASSERT_EQ(gy_qsgroups_server_version_check(1, 1, 1, 1, 1, 1), GY_ERR_STATE);
    ASSERT_EQ(gy_qsgroups_server_version_check(1, 1, 1, 0, 2, 0), GY_ERR_STATE);
}

TEST(public_fetch_check)
{
    /* SEC-v1.5.0 LOW-1: fet is a separate server record, not decoded from the
     * header; the check compares the presented token against it directly. */
    uint8_t fet[GY_QSPGS_FET_LEN];
    uint8_t pres[GY_QSPGS_FET_LEN];

    memset(fet, 0x33, sizeof(fet));
    memset(pres, 0x33, sizeof(pres)); /* matches the stored fet */
    ASSERT_EQ(gy_qsgroups_server_fetch_check(GY_SUITE_H25519_512, fet, pres),
              GY_OK);

    pres[GY_QSPGS_FET_LEN - 1] ^= 0x01;
    ASSERT_EQ(gy_qsgroups_server_fetch_check(GY_SUITE_H25519_512, fet, pres),
              GY_ERR_VERIFY);

    /* A classical suite has no QSPGS type. */
    ASSERT_EQ(gy_qsgroups_server_fetch_check(GY_SUITE_C25519, fet, pres),
              GY_ERR_UNSUPPORTED);

    ASSERT_EQ(gy_qsgroups_server_fetch_check(GY_SUITE_H25519_512, NULL, pres),
              GY_ERR_ARG);
}

TEST(public_core_check)
{
    struct core_wire w;
    uint8_t sigobj[64];
    uint8_t vkr[GY_QSPGS_VKR_MAX];
    size_t siglen, vkrlen = tier_vkr_len();

    memset(vkr, 0x5a, sizeof(vkr));
    siglen = build_sig(sigobj, sizeof(sigobj));

    /*
     * Item-1 admn gate (D-QGS-13 E2): the gate reads the PRIOR mem-lst.  A
     * would-be UNCHANGED edit whose PRIOR signer is a non-admin is rejected
     * before any crypto (prior == next == w here).
     */
    build_core(&w, 0);
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_UNCHANGED, w.hdr,
                  w.hdr_len, w.ml, w.ml_len, w.vk, w.vk_len, w.hdr, w.hdr_len,
                  w.ml, w.ml_len, w.vk, w.vk_len, sigobj, siglen, vkr, vkrlen),
              GY_ERR_VERIFY);

    /* Admin prior signer: passes the admn gate and the UNCHANGED vk-lst
     * equality, then the presented vkr cannot resolve to the dummy stored
     * H(vkpsdn) -> VERIFY at the hash check (proves the full prior + next
     * decode and resolve plumbing runs). */
    build_core(&w, 1);
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_UNCHANGED, w.hdr,
                  w.hdr_len, w.ml, w.ml_len, w.vk, w.vk_len, w.hdr, w.hdr_len,
                  w.ml, w.ml_len, w.vk, w.vk_len, sigobj, siglen, vkr, vkrlen),
              GY_ERR_VERIFY);

    /* A classical suite is unsupported here (checked on next, before prior). */
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_C25519, GY_QSGROUP_OP_CREATE, NULL, 0, NULL, 0, NULL,
                  0, w.hdr, w.hdr_len, w.ml, w.ml_len, w.vk, w.vk_len, sigobj,
                  siglen, vkr, vkrlen),
              GY_ERR_UNSUPPORTED);

    /* A vkr of the wrong tier length is rejected before decode. */
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_CREATE, NULL, 0, NULL, 0,
                  NULL, 0, w.hdr, w.hdr_len, w.ml, w.ml_len, w.vk, w.vk_len,
                  sigobj, siglen, vkr, vkrlen - 1),
              GY_ERR_ARG);

    /* A NULL next object is rejected. */
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_CREATE, NULL, 0, NULL, 0,
                  NULL, 0, NULL, 0, w.ml, w.ml_len, w.vk, w.vk_len, sigobj,
                  siglen, vkr, vkrlen),
              GY_ERR_ARG);

    /* A partial prior (some prior objects present, some NULL) is rejected. */
    ASSERT_EQ(gy_qsgroups_server_core_check(
                  GY_SUITE_H25519_512, GY_QSGROUP_OP_UNCHANGED, w.hdr,
                  w.hdr_len, NULL, 0, NULL, 0, w.hdr, w.hdr_len, w.ml, w.ml_len,
                  w.vk, w.vk_len, sigobj, siglen, vkr, vkrlen),
              GY_ERR_ARG);
}

TEST(public_apx_check)
{
    struct core_wire w;
    uint8_t joinobj[GY_QSPGS_SIG_MAX + 128], leaveobj[GY_QSPGS_SIG_MAX + 128];
    uint8_t apx2[GY_QSPGS_SIG_MAX + 128];
    uint8_t vkr[GY_QSPGS_VKR_MAX];
    size_t joinlen, leavelen, apx2len, vkrlen = tier_vkr_len();

    memset(vkr, 0x5a, sizeof(vkr));
    build_core(&w, 1); /* provides the vk-lst object (n_vk == 1). */
    joinlen = build_apx_line(joinobj, sizeof(joinobj), GY_QAPX_JOIN, 0);
    leavelen = build_apx_line(leaveobj, sizeof(leaveobj), GY_QAPX_LEAVE, 0);

    /* JOIN newcomer: no vk-lst resolution; reaches the signature verify, which
     * fails on the dummy signature -> VERIFY (proves the decode plumbing). */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, NULL, 0,
                                           joinobj, joinlen, 0, vkr, vkrlen, 1),
              GY_ERR_VERIFY);

    /* Existing author (a non-JOIN line, newcomer 0): the vk-lst resolves
     * author_index 0 against a dummy H(vkpsdn), whose mismatch -> VERIFY before
     * the signature. */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, w.vk, w.vk_len,
                                           leaveobj, leavelen, 0, vkr, vkrlen,
                                           0),
              GY_ERR_VERIFY);

    /* LOW-3: newcomer status is a property of the line, so a caller flag that
     * disagrees is rejected before any resolution or verify.  A JOIN submitted
     * as an existing author (newcomer 0): */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, w.vk, w.vk_len,
                                           joinobj, joinlen, 0, vkr, vkrlen, 0),
              GY_ERR_ARG);

    /* LOW-3 / INFO-8: a NON-JOIN line submitted as a newcomer (newcomer 1),
     * which the old code accepted (skipping the stored-hash gate for any line
     * kind).  Now GY_ERR_ARG regardless of the vk-lst argument. */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, NULL, 0,
                                           leaveobj, leavelen, 0, vkr, vkrlen,
                                           1),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, w.vk, w.vk_len,
                                           leaveobj, leavelen, 0, vkr, vkrlen,
                                           1),
              GY_ERR_ARG);

    /* line_index past the single line (JOIN, newcomer 1). */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, NULL, 0,
                                           joinobj, joinlen, 1, vkr, vkrlen, 1),
              GY_ERR_ARG);

    /* Existing author (non-JOIN) whose author_index is past the vk-lst. */
    apx2len = build_apx_line(apx2, sizeof(apx2), GY_QAPX_LEAVE, 5);
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, w.vk, w.vk_len,
                                           apx2, apx2len, 0, vkr, vkrlen, 0),
              GY_ERR_ARG);

    /* Existing author (non-JOIN) but a NULL vk-lst. */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, NULL, 0,
                                           leaveobj, leavelen, 0, vkr, vkrlen,
                                           0),
              GY_ERR_ARG);

    /* A classical suite is unsupported (checked before the appendix decode). */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_C25519, NULL, 0, joinobj,
                                           joinlen, 0, vkr, vkrlen, 1),
              GY_ERR_UNSUPPORTED);

    /* A vkr of the wrong tier length (checked before the appendix decode). */
    ASSERT_EQ(gy_qsgroups_server_apx_check(GY_SUITE_H25519_512, NULL, 0,
                                           joinobj, joinlen, 0, vkr, vkrlen - 1,
                                           1),
              GY_ERR_ARG);
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(token_check),
             GY_TEST(server_checks_standalone),
             GY_TEST(server_version_and_fetch), GY_TEST(public_passthroughs),
             GY_TEST(public_fetch_check), GY_TEST(public_core_check),
             GY_TEST(public_apx_check))
