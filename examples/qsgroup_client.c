/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon QUANTUM-SAFE GROUP (QSPGS) end-to-end example: the member process.
 *
 * Worked example (the member process), building toward classical
 * group_demo parity over five members.  Every member brings up a hybrid
 * custodian over a file-backed sealed store, RegisterUsers its ACCT and
 * publishes its identity keys to the untrusted coordinator, and grants
 * acquaintance both ways with the founder over a pairwise Double Ratchet session
 * (exchanging user keys uk with the acq check), so the founder's admin edits
 * resolve each member's base key and each member can fetch-verify the
 * founder-signed core.  The founder Creates the group and deposits the
 * admin-signed core; the coordinator, acting as the section-7.3 server, runs
 * version_check + core_check (using the submitter's transmitted vkr) before
 * accepting a write, and fetch_check on the presented token before serving.
 * The founder invites each member (a PENDING core write), delivers the group
 * key + gk' over the reused acquaintance session, and once the member accepts
 * (with its own identity) and deposits the acceptance, opens it and completes
 * (settles the entry); each member then fetch-verifies its membership.
 *
 * Driven through the PUBLIC geryon.h / geryon_qspgs.h surfaces plus the
 * demo-local IPC and filestore helpers.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geryon.h"
#include "geryon_qspgs.h"

#include "demo_ipc.h"
#include "demo_proto.h"
#include "filestore.h"
#include "qsgroup_client.h"
#include "qsgroup_demo_proto.h"

/* The group id every member agrees on for the demo (opaque, caller-supplied). */
static const uint8_t DEMO_GID[GY_QSGROUP_GID_LEN] = {
    'Q', 'S', 'G', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

/* The opaque attributes blob the phase-H ModAttr appendix line proposes; every
 * member confirms it after the line is applied, and the founder folds it. */
#define DEMO_APX_ATTR "qspgs-demo-attr"

static void
wr_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void
wr_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t
rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t
rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

/* Every demo member runs one device; the pairwise messaging session uses it. */
static const uint8_t QSG_DID[1] = {0x01};

static int
send_msg_to(int wfd, const char *from, const char *to, enum qsg_msg_type type,
            const uint8_t *payload, size_t plen)
{
    struct demo_frame_header h;

    memset(&h, 0, sizeof(h));
    h.type = (uint32_t)type;
    h.data_len = (uint32_t)plen;
    snprintf(h.from, sizeof(h.from), "%s", from);
    snprintf(h.to, sizeof(h.to), "%s", to);
    return demo_send_frame(wfd, &h, payload) == DEMO_IPC_OK ? 0 : -1;
}

/* Server RPCs address the coordinator; relay/bundle traffic names a peer. */
static int
send_msg(int wfd, const char *from, enum qsg_msg_type type,
         const uint8_t *payload, size_t plen)
{
    return send_msg_to(wfd, from, "coord", type, payload, plen);
}

/* An idle receive costs no CPU (the kernel sleeps for the poll interval), yet
 * the loop regains control every QSG_RECV_TIMEOUT_MS: it honors a bounded
 * liveness deadline, resumes cleanly across a caught signal (EINTR), and acts on
 * a hangup rather than parking forever on a dead pipe. */
#define QSG_RECV_TIMEOUT_MS 50
#define QSG_RECV_MAX_WAITS 1200 /* 1200 x 50ms = 60s liveness bound */

/* Wait (poll, short timeout) for one frame on rfd, then read it in full.
 * Returns 0, or -1 on error / hangup / after the liveness deadline. */
static int
recv_frame_polled(int rfd, struct demo_frame_header *rh, uint8_t *rbuf,
                  size_t rcap)
{
    struct pollfd pfd;
    int waits;

    pfd.fd = rfd;
    pfd.events = POLLIN;
    for (waits = 0; waits < QSG_RECV_MAX_WAITS; waits++) {
        int r;

        pfd.revents = 0;
        r = poll(&pfd, 1, QSG_RECV_TIMEOUT_MS);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (r == 0)
            continue; /* timeout: idle, retry within the deadline */
        /* Ready (data or a hangup): read the full frame or detect EOF. */
        return demo_recv_frame(rfd, rh, rbuf, rcap) == DEMO_IPC_OK ? 0 : -1;
    }
    return -1; /* exceeded the liveness bound */
}

/* Send one framed message to `to` and block for the coordinator's reply. */
static int
request_to(int rfd, int wfd, const char *from, const char *to,
           enum qsg_msg_type type, const uint8_t *payload, size_t plen,
           struct demo_frame_header *rh, uint8_t *rbuf, size_t rcap)
{
    if (send_msg_to(wfd, from, to, type, payload, plen) != 0)
        return -1;
    return recv_frame_polled(rfd, rh, rbuf, rcap);
}

/* Send one request to the coordinator and block for its single reply. */
static int
request(int rfd, int wfd, const char *from, enum qsg_msg_type type,
        const uint8_t *payload, size_t plen, struct demo_frame_header *rh,
        uint8_t *rbuf, size_t rcap)
{
    return request_to(rfd, wfd, from, "coord", type, payload, plen, rh, rbuf,
                      rcap);
}

static int
barrier(const char *from, int rfd, int wfd)
{
    struct demo_frame_header rh;
    uint8_t rbuf[DEMO_MAX_PAYLOAD];

    if (request(rfd, wfd, from, QSG_MSG_BARRIER, NULL, 0, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    return rh.type == (uint32_t)QSG_MSG_SRV_REPLY ? 0 : -1;
}

/* RegisterUser: emit the ACCT and deposit it (uid_len || uid || acct). */
static int
do_register(gy_custodian *c, const char *name, const uint8_t *uid,
            size_t uidlen, int rfd, int wfd)
{
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    uint8_t sbuf[1 + 64 + GY_QSGROUP_ACCT_MAX];
    struct demo_frame_header rh;
    uint8_t rbuf[256];
    size_t acctlen = sizeof(acct), off;

    if (gy_custodian_qsgroup_register(c, 1, acct, &acctlen) != GY_OK)
        return -1;
    sbuf[0] = (uint8_t)uidlen;
    memcpy(sbuf + 1, uid, uidlen);
    off = 1 + uidlen;
    memcpy(sbuf + off, acct, acctlen);
    off += acctlen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_REGISTER, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    return rh.type == (uint32_t)QSG_MSG_SRV_REPLY ? 0 : -1;
}

/* Publish this identity's public keys (uid_len || uid || clen || curve ||
 * mlen || mldsa) so peers can accept this member's ACCT. */
static int
do_publish_id(gy_custodian *c, const char *name, const uint8_t *uid,
              size_t uidlen, int rfd, int wfd)
{
    uint8_t curve[GY_QSGROUP_ID_CURVE_MAX];
    uint8_t mldsa[GY_QSGROUP_ID_MLDSA_MAX];
    uint8_t sbuf[1 + 64 + 2 + GY_QSGROUP_ID_CURVE_MAX + 2 +
                 GY_QSGROUP_ID_MLDSA_MAX];
    struct demo_frame_header rh;
    uint8_t rbuf[256];
    size_t clen = sizeof(curve), mlen = sizeof(mldsa), off;

    if (gy_custodian_qsgroup_identity_public(c, curve, &clen, mldsa, &mlen) !=
        GY_OK)
        return -1;
    sbuf[0] = (uint8_t)uidlen;
    memcpy(sbuf + 1, uid, uidlen);
    off = 1 + uidlen;
    wr_be16(sbuf + off, (uint16_t)clen);
    off += 2;
    memcpy(sbuf + off, curve, clen);
    off += clen;
    wr_be16(sbuf + off, (uint16_t)mlen);
    off += 2;
    memcpy(sbuf + off, mldsa, mlen);
    off += mlen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_PUBLISH_ID, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    return rh.type == (uint32_t)QSG_MSG_SRV_REPLY ? 0 : -1;
}

/* Fetch peer `peer`'s hybrid identity public keys (FETCH_ID), copying them into
 * the caller's curve and mldsa buffers (clen, mlen: capacity in, length out). */
static int
fetch_peer_id(const char *name, int peer, int rfd, int wfd, uint8_t *curve,
              size_t *clen, uint8_t *mldsa, size_t *mlen)
{
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t q[1 + GY_QSGROUP_UID_LEN];
    struct demo_frame_header rh;
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    size_t c_in = *clen, m_in = *mlen, o, cl, ml;

    q[0] = (uint8_t)pulen;
    memcpy(q + 1, puid, pulen);
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_ID, q, 1 + pulen, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY || rh.data_len < 4)
        return -1;
    o = 0;
    cl = rd_be16(rbuf + o);
    o += 2;
    if (o + cl + 2 > rh.data_len || cl > c_in)
        return -1;
    memcpy(curve, rbuf + o, cl);
    o += cl;
    ml = rd_be16(rbuf + o);
    o += 2;
    if (o + ml > rh.data_len || ml > m_in)
        return -1;
    memcpy(mldsa, rbuf + o, ml);
    *clen = cl;
    *mlen = ml;
    return 0;
}

static int send_over_session(gy_custodian *c, const char *name, int peer,
                             const uint8_t *pt, size_t ptlen, int rfd, int wfd);
static int recv_over_session(gy_custodian *c, const char *name, int rfd,
                             int wfd, uint8_t *pt, size_t *ptlen);

/* Fetch peer `peer`'s public ACCT and identity keys from the coordinator. */
static int
fetch_acct_and_id(const char *name, int peer, int rfd, int wfd, uint8_t *acct,
                  size_t *acctlen, uint8_t *curve, size_t *clen, uint8_t *mldsa,
                  size_t *mlen)
{
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t q[1 + GY_QSGROUP_UID_LEN];
    struct demo_frame_header rh;
    uint8_t rbuf[DEMO_MAX_PAYLOAD];

    q[0] = (uint8_t)pulen;
    memcpy(q + 1, puid, pulen);
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_ACCT, q, 1 + pulen, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY || rh.data_len == 0 ||
        rh.data_len > *acctlen)
        return -1;
    memcpy(acct, rbuf, rh.data_len);
    *acctlen = rh.data_len;
    return fetch_peer_id(name, peer, rfd, wfd, curve, clen, mldsa, mlen);
}

/*
 * GrantAcquaintance (founder side, [CFG+] Fig. 8): stand up the pairwise Double
 * Ratchet session to member `peer` (geryon's E2EE channel, QSPGS_SPEC.md
 * section 5), send our own uk as the session's first message, receive the
 * member's uk back over it, and accept the member (verify ACCT + acq ==
 * KDF(uk)).  The session persists and is REUSED for phase-D group-key delivery.
 */
static int
founder_acquaint_one(gy_custodian *c, const char *name, int peer, int rfd,
                     int wfd)
{
    char pname[DEMO_NAME_MAX];
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t bundle[DEMO_MAX_PAYLOAD], first[DEMO_MAX_PAYLOAD];
    uint8_t my_uk[GY_QSGROUP_USER_KEY_MAX], peer_uk[GY_QSGROUP_USER_KEY_MAX];
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    uint8_t curve[GY_QSGROUP_ID_CURVE_MAX], mldsa[GY_QSGROUP_ID_MLDSA_MAX];
    uint8_t rbuf[256];
    struct demo_frame_header rh;
    gy_keychange chg;
    size_t blen, flen = sizeof(first), acctlen = sizeof(acct);
    size_t my_uklen = sizeof(my_uk), peer_uklen = sizeof(peer_uk);
    size_t clen = sizeof(curve), mlen = sizeof(mldsa);

    if (fetch_acct_and_id(name, peer, rfd, wfd, acct, &acctlen, curve, &clen,
                          mldsa, &mlen) != 0)
        return -1;
    if (gy_custodian_qsgroup_export_user_key(c, 1, my_uk, &my_uklen) != GY_OK)
        return -1;

    snprintf(pname, sizeof(pname), "m%d", peer + 1);
    if (request_to(rfd, wfd, name, pname, QSG_MSG_FETCH_BUNDLE, NULL, 0, &rh,
                   bundle, sizeof(bundle)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_BUNDLE)
        return -1;
    blen = rh.data_len;
    if (gy_send_open(c) != GY_OK)
        return -1;
    memset(&chg, 0, sizeof(chg));
    if (gy_initiate(c, puid, pulen, QSG_DID, sizeof(QSG_DID), bundle, blen,
                    my_uk, my_uklen, &chg, first, &flen) != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    if (gy_commit(c) != GY_OK)
        return -1;
    if (request_to(rfd, wfd, name, pname, QSG_MSG_RELAY, first, flen, &rh, rbuf,
                   sizeof(rbuf)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;

    if (recv_over_session(c, name, rfd, wfd, peer_uk, &peer_uklen) != 0)
        return -1;
    return gy_custodian_qsgroup_accept_acquaintance(
               c, puid, pulen, curve, mldsa, acct, acctlen, peer_uk,
               peer_uklen) == GY_OK
               ? 0
               : -1;
}

/*
 * GrantAcquaintance (member side): publish a one-shot bundle, receive the
 * founder's uk over the session it initiates, accept the founder (verify ACCT +
 * acq check), and send our own uk back.  The session persists for phase D.
 */
static int
member_acquaint_founder(gy_custodian *c, const struct qsgroup_client_cfg *cfg,
                        int rfd, int wfd)
{
    uint8_t bundle[DEMO_MAX_PAYLOAD], ack[64], rbuf[DEMO_MAX_PAYLOAD];
    uint8_t founder_uk[GY_QSGROUP_USER_KEY_MAX], my_uk[GY_QSGROUP_USER_KEY_MAX];
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    uint8_t curve[GY_QSGROUP_ID_CURVE_MAX], mldsa[GY_QSGROUP_ID_MLDSA_MAX];
    uint8_t fuid[GY_QSGROUP_UID_LEN];
    struct demo_frame_header rh;
    size_t blen = sizeof(bundle), fuklen = sizeof(founder_uk);
    size_t my_uklen = sizeof(my_uk), acctlen = sizeof(acct);
    size_t clen = sizeof(curve), mlen = sizeof(mldsa),
           fuidlen = qsg_uid(0, fuid);

    if (gy_publish_bundle(c, bundle, &blen) != GY_OK)
        return -1;
    if (request_to(rfd, wfd, cfg->name, "m1", QSG_MSG_PUBLISH_BUNDLE, bundle,
                   blen, &rh, ack, sizeof(ack)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;
    if (request(rfd, wfd, cfg->name, QSG_MSG_RECV, NULL, 0, &rh, rbuf,
                sizeof(rbuf)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_DELIVER)
        return -1;
    if (gy_receive(c, fuid, fuidlen, QSG_DID, sizeof(QSG_DID), rbuf,
                   rh.data_len, founder_uk, &fuklen) != GY_OK)
        return -1;

    if (fetch_acct_and_id(cfg->name, 0, rfd, wfd, acct, &acctlen, curve, &clen,
                          mldsa, &mlen) != 0)
        return -1;
    if (gy_custodian_qsgroup_accept_acquaintance(c, fuid, fuidlen, curve, mldsa,
                                                 acct, acctlen, founder_uk,
                                                 fuklen) != GY_OK)
        return -1;
    if (gy_custodian_qsgroup_export_user_key(c, 1, my_uk, &my_uklen) != GY_OK)
        return -1;
    return send_over_session(c, cfg->name, 0, my_uk, my_uklen, rfd, wfd);
}

/*
 * The four canonical core objects, held between edits: create emits them, the
 * admin edits (complete_invitation) consume the current set and emit the
 * next.  Ample
 * for a three-member demo core over both hybrid tiers.
 */
struct core_buf {
    uint8_t hdr[512];
    uint8_t ml[8192];
    uint8_t vk[2048];
    uint8_t sig[8192];
    size_t hn, mn, vn, sn;
    /* Fetch token emitted alongside the four objects (SEC-v1.5.0 LOW-1): a
     * separate record for the server, NOT inside the signed header. */
    uint8_t fet[GY_QSGROUP_FET_LEN];
};

/* View a core_buf as the "current" IO bundle (lengths = the stored sizes). */
static void
core_as_cur(struct gy_qsgroup_core *v, struct core_buf *b)
{
    v->hdr = b->hdr;
    v->hdr_len = b->hn;
    v->member_list = b->ml;
    v->member_list_len = b->mn;
    v->vk_lst = b->vk;
    v->vk_lst_len = b->vn;
    v->sig = b->sig;
    v->sig_len = b->sn;
}

/* View a core_buf as the "next" IO bundle (lengths = buffer capacities). */
static void
core_as_next(struct gy_qsgroup_core *v, struct core_buf *b)
{
    v->hdr = b->hdr;
    v->hdr_len = sizeof(b->hdr);
    v->member_list = b->ml;
    v->member_list_len = sizeof(b->ml);
    v->vk_lst = b->vk;
    v->vk_lst_len = sizeof(b->vk);
    v->sig = b->sig;
    v->sig_len = sizeof(b->sig);
}

/*
 * SUBMIT_CORE: gid || new(4,4) || ext(4,4) || vkr_len(2)||vkr ||
 * 4x (len(4)||object) || fet(GY_QSGROUP_FET_LEN).  The coordinator runs
 * version_check + core_check and stores fet as a separate record.
 */
static int
submit_core(const char *name, uint8_t op_kind, uint32_t nvmaj, uint32_t nvmin,
            uint32_t evmaj, uint32_t evmin, const uint8_t *vkr, size_t vkrlen,
            const struct core_buf *b, int rfd, int wfd)
{
    uint8_t sbuf[DEMO_MAX_PAYLOAD];
    uint8_t rbuf[256];
    struct demo_frame_header rh;
    size_t off = 0;

    memcpy(sbuf + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    wr_be32(sbuf + off, nvmaj);
    off += 4;
    wr_be32(sbuf + off, nvmin);
    off += 4;
    wr_be32(sbuf + off, evmaj);
    off += 4;
    wr_be32(sbuf + off, evmin);
    off += 4;
    sbuf[off++] = op_kind; /* QSG_OP_*: the server's vk-lst rule. */
    wr_be16(sbuf + off, (uint16_t)vkrlen);
    off += 2;
    memcpy(sbuf + off, vkr, vkrlen);
    off += vkrlen;
    wr_be32(sbuf + off, (uint32_t)b->hn);
    off += 4;
    memcpy(sbuf + off, b->hdr, b->hn);
    off += b->hn;
    wr_be32(sbuf + off, (uint32_t)b->mn);
    off += 4;
    memcpy(sbuf + off, b->ml, b->mn);
    off += b->mn;
    wr_be32(sbuf + off, (uint32_t)b->vn);
    off += 4;
    memcpy(sbuf + off, b->vk, b->vn);
    off += b->vn;
    wr_be32(sbuf + off, (uint32_t)b->sn);
    off += 4;
    memcpy(sbuf + off, b->sig, b->sn);
    off += b->sn;
    /* SEC-v1.5.0 LOW-1: append the fetch token as a trailing separate record. */
    memcpy(sbuf + off, b->fet, GY_QSGROUP_FET_LEN);
    off += GY_QSGROUP_FET_LEN;
    if (request(rfd, wfd, name, QSG_MSG_SRV_SUBMIT_CORE, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    return rh.type == (uint32_t)QSG_MSG_SRV_REPLY ? 0 : -1;
}

/*
 * Submit one single-line appendix object to the coordinator (the [CFG+] Fig. 12
 * append path): gid || newcomer(1) || vkr || obj.  The coordinator runs
 * apx_check under the submitter's transmitted vkr (against the stored vk-lst for
 * an existing author, or as a newcomer for a JOIN / UserAdd line) and appends it
 * to the group's pending appendix.  Returns 0 on acceptance, -1 otherwise.
 */
static int
submit_appendix(const char *name, int newcomer, const uint8_t *vkr,
                size_t vkrlen, const uint8_t *obj, size_t objlen, int rfd,
                int wfd)
{
    uint8_t sbuf[DEMO_MAX_PAYLOAD];
    uint8_t rbuf[256];
    struct demo_frame_header rh;
    size_t off = 0;

    memcpy(sbuf + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    sbuf[off++] = (uint8_t)(newcomer ? 1 : 0);
    wr_be16(sbuf + off, (uint16_t)vkrlen);
    off += 2;
    memcpy(sbuf + off, vkr, vkrlen);
    off += vkrlen;
    wr_be32(sbuf + off, (uint32_t)objlen);
    off += 4;
    memcpy(sbuf + off, obj, objlen);
    off += objlen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_SUBMIT_APPENDIX, sbuf, off, &rh,
                rbuf, sizeof(rbuf)) != 0)
        return -1;
    return rh.type == (uint32_t)QSG_MSG_SRV_REPLY ? 0 : -1;
}

/* Fetch the group's accumulated appendix object into out[0..*outlen); *outlen
 * becomes 0 when the group has no pending lines. */
static int
fetch_appendix(const char *name, uint8_t *out, size_t *outlen, int rfd, int wfd)
{
    uint8_t sbuf[GY_QSGROUP_GID_LEN];
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    struct demo_frame_header rh;

    memcpy(sbuf, DEMO_GID, GY_QSGROUP_GID_LEN);
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_APPENDIX, sbuf,
                GY_QSGROUP_GID_LEN, &rh, rbuf, sizeof(rbuf)) != 0)
        return -1;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY || rh.data_len > *outlen)
        return -1;
    memcpy(out, rbuf, rh.data_len);
    *outlen = rh.data_len;
    return 0;
}

/*
 * Fetch one member's ACCT from the coordinator (QSG_MSG_SRV_FETCH_ACCT) into
 * out[0..*out_len).  This is the deployer half of [CFG+] GetPseudoVkBase: the
 * server-served registration record a fetching member needs to recover the base
 * key of a member it is not acquainted with.
 */
static int
fetch_member_acct(const char *name, int peer, int rfd, int wfd, uint8_t *out,
                  size_t *out_len)
{
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t q[1 + GY_QSGROUP_UID_LEN];
    struct demo_frame_header rh;
    uint8_t rbuf[GY_QSGROUP_ACCT_MAX];

    q[0] = (uint8_t)pulen;
    memcpy(q + 1, puid, pulen);
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_ACCT, q, 1 + pulen, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY || rh.data_len == 0 ||
        rh.data_len > *out_len)
        return -1;
    memcpy(out, rbuf, rh.data_len);
    *out_len = rh.data_len;
    return 0;
}

/* FETCH_CORE + Fetch: pull the stored core (fetch_check gates the token) and
 * decrypt the roster into views (count out).  The full [CFG+] Fig. 15
 * verification recomputes EVERY member's pseudonym key, so this member supplies
 * the whole demo membership's ACCTs (GetPseudoVkBase) for the peers it is not
 * acquainted with; own / acquaintance records take precedence.  A first fetch
 * passes no prior view (the anti-rollback lineage is exercised in the unit
 * tests); the deployer holding no prior is a documented, weaker mode. */
static int
fetch_core(gy_custodian *c, const char *name,
           struct gy_qsgroup_member_view *views, size_t maxv, size_t *count,
           int rfd, int wfd)
{
    uint8_t token[GY_QSGROUP_FET_LEN];
    size_t toklen = sizeof(token);
    uint8_t sbuf[GY_QSGROUP_GID_LEN + GY_QSGROUP_FET_LEN];
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    struct demo_frame_header rh;
    struct gy_qsgroup_acct_ref refs[QSG_NMEMBERS];
    uint8_t uids[QSG_NMEMBERS][GY_QSGROUP_UID_LEN];
    uint8_t curves[QSG_NMEMBERS][GY_QSGROUP_ID_CURVE_MAX];
    uint8_t mldsas[QSG_NMEMBERS][GY_QSGROUP_ID_MLDSA_MAX];
    uint8_t *store = NULL;
    const uint8_t *obj[4];
    size_t objl[4], off = 0, o;
    size_t n_refs = 0, i;
    int k, rc = -1;

    /* Collect every demo member's ACCT (GetPseudoVkBase inputs) first, before
     * the core reply reuses rbuf. */
    store = malloc((size_t)QSG_NMEMBERS * GY_QSGROUP_ACCT_MAX);
    if (store == NULL)
        return -1;
    for (i = 0; i < QSG_NMEMBERS; i++) {
        size_t alen = GY_QSGROUP_ACCT_MAX;
        size_t clen = GY_QSGROUP_ID_CURVE_MAX, mlen = GY_QSGROUP_ID_MLDSA_MAX;

        if (fetch_member_acct(name, (int)i, rfd, wfd,
                              store + i * GY_QSGROUP_ACCT_MAX, &alen) != 0)
            goto done;
        /* IsCorrectUserKey (Fig. 15, E4) needs the member's hybrid identity
         * public keys to verify the ACCT it attests uk against. */
        if (fetch_peer_id(name, (int)i, rfd, wfd, curves[i], &clen, mldsas[i],
                          &mlen) != 0)
            goto done;
        refs[n_refs].uid = uids[i];
        refs[n_refs].uid_len = qsg_uid((int)i, uids[i]);
        refs[n_refs].acct = store + i * GY_QSGROUP_ACCT_MAX;
        refs[n_refs].acct_len = alen;
        refs[n_refs].curve_pk = curves[i];
        refs[n_refs].mldsa_pk = mldsas[i];
        n_refs++;
    }

    if (gy_custodian_qsgroup_fetch_token(c, DEMO_GID, token, &toklen) != GY_OK)
        goto done;
    memcpy(sbuf + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    memcpy(sbuf + off, token, toklen);
    off += toklen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_CORE, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0)
        goto done;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        goto done;
    o = 0;
    for (k = 0; k < 4; k++) {
        if (o + 4 > rh.data_len)
            goto done;
        objl[k] = rd_be32(rbuf + o);
        o += 4;
        if (o + objl[k] > rh.data_len)
            goto done;
        obj[k] = rbuf + o;
        o += objl[k];
    }
    rc = gy_custodian_qsgroup_fetch(
             c, obj[0], objl[0], obj[1], objl[1], obj[2], objl[2], obj[3],
             objl[3], NULL, 0, NULL, 0, 0, 0, 0, NULL, 0, refs, n_refs, views,
             maxv, count, NULL, 0, NULL, NULL, 0, NULL) == GY_OK
             ? 0
             : -1;
done:
    free(store);
    return rc;
}

/* FETCH_CORE, retaining the four raw objects in b (an edit-ready "current" core)
 * rather than a decoded roster.  Used where a member needs the core objects to
 * sign against, e.g. a non-admin appendix line. */
static int
fetch_core_raw(gy_custodian *c, const char *name, struct core_buf *b, int rfd,
               int wfd)
{
    uint8_t token[GY_QSGROUP_FET_LEN];
    size_t toklen = sizeof(token);
    uint8_t sbuf[GY_QSGROUP_GID_LEN + GY_QSGROUP_FET_LEN];
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    struct demo_frame_header rh;
    const uint8_t *obj[4];
    uint8_t *dst[4];
    size_t objl[4], cap[4], off = 0, o;
    int k;

    if (gy_custodian_qsgroup_fetch_token(c, DEMO_GID, token, &toklen) != GY_OK)
        return -1;
    memcpy(sbuf + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    memcpy(sbuf + off, token, toklen);
    off += toklen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_CORE, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0)
        return -1;
    if (rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;
    o = 0;
    for (k = 0; k < 4; k++) {
        if (o + 4 > rh.data_len)
            return -1;
        objl[k] = rd_be32(rbuf + o);
        o += 4;
        if (o + objl[k] > rh.data_len)
            return -1;
        obj[k] = rbuf + o;
        o += objl[k];
    }
    dst[0] = b->hdr;
    cap[0] = sizeof(b->hdr);
    dst[1] = b->ml;
    cap[1] = sizeof(b->ml);
    dst[2] = b->vk;
    cap[2] = sizeof(b->vk);
    dst[3] = b->sig;
    cap[3] = sizeof(b->sig);
    for (k = 0; k < 4; k++) {
        if (objl[k] > cap[k])
            return -1;
        memcpy(dst[k], obj[k], objl[k]);
    }
    b->hn = objl[0];
    b->mn = objl[1];
    b->vn = objl[2];
    b->sn = objl[3];
    return 0;
}

/* Founder: Create the group, deposit the signed core (the coordinator runs
 * version_check + core_check under the transmitted vkr), fetch it back
 * (fetch_check on the token), and verify the sole self member.  The core and
 * the signer vkr are retained in b / vkr for the subsequent invite edits. */
static int
founder_create(gy_custodian *c, const char *name, struct core_buf *b,
               uint8_t *vkr, size_t *vkrlen, int rfd, int wfd)
{
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    uint8_t fuid[GY_QSGROUP_UID_LEN];
    size_t fuidlen, count = 0;

    b->hn = sizeof(b->hdr);
    b->mn = sizeof(b->ml);
    b->vn = sizeof(b->vk);
    b->sn = sizeof(b->sig);
    if (gy_custodian_qsgroup_create(
            c, DEMO_GID, 1, GY_QSGROUP_SETTING_ADD | GY_QSGROUP_SETTING_ATTR,
            GY_QSGROUP_AEAD_CHACHA20POLY1305, NULL, 0, b->hdr, &b->hn, b->ml,
            &b->mn, b->vk, &b->vn, b->sig, &b->sn, b->fet) != GY_OK)
        return -1;
    if (gy_custodian_qsgroup_self_vkr(c, DEMO_GID, vkr, vkrlen) != GY_OK)
        return -1;
    if (submit_core(name, QSG_OP_CREATE, 1, 0, 0, 0, vkr, *vkrlen, b, rfd,
                    wfd) != 0)
        return -1;
    if (fetch_core(c, name, views, QSG_NMEMBERS + 1, &count, rfd, wfd) != 0)
        return -1;

    fuidlen = qsg_uid(0, fuid);
    if (count != 1 || views[0].uidlen != fuidlen ||
        memcmp(views[0].uid, fuid, fuidlen) != 0 || views[0].admn != 1)
        return -1;
    return 0;
}

/*
 * Founder: Invite one member ([CFG+] App. B.7, corrected per D-QGS-13 E3).  This
 * is an admin CORE edit: append a PENDING entry for the member (the founder is
 * acquainted with it both ways from phase A, so no ACCT is needed) and re-sign,
 * minting NO user key.  The per-invite join-key basis gk' is written to
 * gkprime_out (gkprime_len: capacity in, length out) for the founder to share
 * with the member over the pairwise session in founder_settle_one; the member
 * derives the invite key from it.  The group key is unchanged, so the signer vkr
 * is unchanged.  *b and *vmaj advance to the new state (APPEND_ONE) on success.
 */
static int
founder_invite_one(gy_custodian *c, const char *name, struct core_buf *b,
                   const uint8_t *vkr, size_t vkrlen, int peer, uint32_t *vmaj,
                   uint8_t *gkprime_out, size_t *gkprime_len, int rfd, int wfd)
{
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    struct core_buf nb;
    struct gy_qsgroup_core cur, next;

    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_invite(c, &cur, puid, pulen, NULL, gkprime_out,
                                    gkprime_len, &next) != GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    if (submit_core(name, QSG_OP_APPEND_ONE, *vmaj + 1, 0, *vmaj, 0, vkr,
                    vkrlen, &nb, rfd, wfd) != 0)
        return -1;
    *b = nb;
    *vmaj += 1;
    return 0;
}

/*
 * Founder: deliver the group key + the per-invite gk' to one member and settle
 * its pending entry ([CFG+] App. B.7, D-QGS-13 E3).  REUSES the pairwise Double
 * Ratchet session stood up at acquaintance time (phase B): send, over that
 * session, the group-key envelope framed with gk' (be16 env_len || env || gk').
 * The member installs the key, accepts the invite with its OWN identity,
 * deposits the acceptance to the queue, and acks over the session.  On the ack
 * the founder fetches the acceptance, opens it against the MEMBER's identity
 * keys (OpenInvitation), fills the accepted uk into the member's pending entry
 * (CompleteInvitation, an UNCHANGED core write), submits it, and nudges the
 * member to confirm.  *b / *vmaj advance past the completion.
 */
static int
founder_settle_one(gy_custodian *c, const char *name, struct core_buf *b,
                   const uint8_t *vkr, size_t vkrlen, int peer, uint32_t *vmaj,
                   const uint8_t *gkprime, size_t gkprime_len, int rfd, int wfd)
{
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    uint8_t pt[GY_QSGROUP_KEY_ENVELOPE_MAX + 2 + GY_QSGROUP_USER_KEY_MAX];
    uint8_t entry[GY_QSGROUP_INVITE_MAX];
    uint8_t curve[GY_QSGROUP_ID_CURVE_MAX], mldsa[GY_QSGROUP_ID_MLDSA_MAX];
    uint8_t q[GY_QSGROUP_GID_LEN + 1 + GY_QSGROUP_UID_LEN];
    uint8_t ack[64];
    struct demo_frame_header rh;
    struct gy_qsgroup_invite_view iv;
    struct core_buf nb;
    struct gy_qsgroup_core cur, next;
    size_t envlen = sizeof(env), ptlen, off;
    size_t acklen = sizeof(ack), clen = sizeof(curve), mlen = sizeof(mldsa);

    /* First message = be16(env_len) || group-key env || gk', over the existing
     * acquaintance session. */
    if (gy_custodian_qsgroup_export_group_key(c, DEMO_GID, env, &envlen) !=
        GY_OK)
        return -1;
    pt[0] = (uint8_t)(envlen >> 8);
    pt[1] = (uint8_t)(envlen & 0xff);
    memcpy(pt + 2, env, envlen);
    memcpy(pt + 2 + envlen, gkprime, gkprime_len);
    ptlen = 2 + envlen + gkprime_len;
    if (send_over_session(c, name, peer, pt, ptlen, rfd, wfd) != 0)
        return -1;

    /* The member accepted + deposited; its ack tells us the entry is queued. */
    if (recv_over_session(c, name, rfd, wfd, ack, &acklen) != 0)
        return -1;

    /* Fetch the deposited acceptance and open it against the MEMBER's keys. */
    off = 0;
    memcpy(q + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    q[off++] = (uint8_t)pulen;
    memcpy(q + off, puid, pulen);
    off += pulen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_INVITE, q, off, &rh, entry,
                sizeof(entry)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;
    if (fetch_peer_id(name, peer, rfd, wfd, curve, &clen, mldsa, &mlen) != 0)
        return -1;
    if (gy_custodian_qsgroup_open_invitation(c, DEMO_GID, gkprime, gkprime_len,
                                             entry, rh.data_len, curve, mldsa,
                                             &iv) != GY_OK)
        return -1;

    /* CompleteInvitation: settle the pending entry with the accepted uk
     * (UNCHANGED core write). */
    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_complete_invitation(c, &cur, puid, pulen, iv.uk,
                                                 iv.uk_len, &next) != GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    if (submit_core(name, QSG_OP_UNCHANGED, *vmaj + 1, 0, *vmaj, 0, vkr, vkrlen,
                    &nb, rfd, wfd) != 0)
        return -1;
    *b = nb;
    *vmaj += 1;

    /* Nudge the member to fetch + confirm it is now a settled member. */
    return send_over_session(c, name, peer, (const uint8_t *)"ok", 2, rfd, wfd);
}

/*
 * Send one message to peer `peer` over the ALREADY-ESTABLISHED pairwise session
 * (gy_encrypt in a send transaction, then relay).  Used for the acquaintance uk
 * exchange, the phase-D group-key + gk' delivery, group-key redelivery after a
 * rotation, and the group message fan-out, all riding the pairwise sessions
 * stood up at acquaintance time (founder_acquaint_one / member_acquaint_founder).
 */
static int
send_over_session(gy_custodian *c, const char *name, int peer,
                  const uint8_t *pt, size_t ptlen, int rfd, int wfd)
{
    char pname[DEMO_NAME_MAX];
    uint8_t puid[GY_QSGROUP_UID_LEN];
    size_t pulen = qsg_uid(peer, puid);
    uint8_t out[DEMO_MAX_PAYLOAD];
    uint8_t rbuf[256];
    struct demo_frame_header rh;
    size_t olen = sizeof(out);

    snprintf(pname, sizeof(pname), "m%d", peer + 1);
    if (gy_send_open(c) != GY_OK)
        return -1;
    if (gy_encrypt(c, puid, pulen, QSG_DID, sizeof(QSG_DID), pt, ptlen, out,
                   &olen) != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    if (gy_commit(c) != GY_OK)
        return -1;
    if (request_to(rfd, wfd, name, pname, QSG_MSG_RELAY, out, olen, &rh, rbuf,
                   sizeof(rbuf)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;
    return 0;
}

/*
 * Receive one relayed message and decrypt it over the existing session with its
 * sender (identified by the frame's `from` name).  On success pt/ptlen hold the
 * plaintext.  Returns 0, or -1 on a bad frame or a decrypt failure.
 */
static int
recv_over_session(gy_custodian *c, const char *name, int rfd, int wfd,
                  uint8_t *pt, size_t *ptlen)
{
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    struct demo_frame_header rh;
    uint8_t suid[GY_QSGROUP_UID_LEN];
    size_t sulen;
    int sidx;

    if (request(rfd, wfd, name, QSG_MSG_RECV, NULL, 0, &rh, rbuf,
                sizeof(rbuf)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_DELIVER)
        return -1;
    sidx = (rh.from[0] == 'm') ? atoi(rh.from + 1) - 1 : -1;
    if (sidx < 0 || sidx >= QSG_NMEMBERS)
        return -1;
    sulen = qsg_uid(sidx, suid);
    return gy_receive(c, suid, sulen, QSG_DID, sizeof(QSG_DID), rbuf,
                      rh.data_len, pt, ptlen) == GY_OK
               ? 0
               : -1;
}

/*
 * Member: publish a one-shot bundle for the founder, receive its pairwise first
 * message (the group-key envelope framed with the per-invite gk'), install the
 * key, ACCEPT the invitation with our OWN identity (uk = KDF(muk, "uk@" || ep)),
 * deposit the acceptance to the queue, and ack the founder.  Wait for the
 * founder's settled nudge, then fetch the core and confirm we are now a settled
 * non-admin member ([CFG+] App. B.7, D-QGS-13 E3).
 */
static int
member_join(gy_custodian *c, const struct qsgroup_client_cfg *cfg, int rfd,
            int wfd)
{
    uint8_t pt[GY_QSGROUP_KEY_ENVELOPE_MAX + 2 + GY_QSGROUP_USER_KEY_MAX];
    uint8_t gid[GY_QSGROUP_GID_LEN];
    uint8_t entry[GY_QSGROUP_INVITE_MAX];
    uint8_t muid[GY_QSGROUP_UID_LEN];
    uint8_t dep[GY_QSGROUP_GID_LEN + 1 + GY_QSGROUP_UID_LEN +
                GY_QSGROUP_INVITE_MAX];
    uint8_t nudge[64];
    uint8_t ack[64];
    struct demo_frame_header rh;
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    size_t ptlen = sizeof(pt), envlen, gkplen;
    size_t entrylen = sizeof(entry), nudgelen = sizeof(nudge);
    size_t mulen = qsg_uid(cfg->index, muid);
    size_t count = 0, k, off;
    int found = 0;

    /* Receive the first message over the acquaintance session (phase B):
     * be16(env_len) || group-key env || gk'. */
    if (recv_over_session(c, cfg->name, rfd, wfd, pt, &ptlen) != 0)
        return -1;
    if (ptlen < 2)
        return -1;
    envlen = ((size_t)pt[0] << 8) | pt[1];
    if (2 + envlen > ptlen)
        return -1;
    gkplen = ptlen - 2 - envlen;
    if (gy_custodian_qsgroup_install_group_key(c, pt + 2, envlen, gid) != GY_OK)
        return -1;

    /* AcceptInvitation: sign (UID, uk, GID) with our own identity, seal to the
     * gk' the founder shared, and deposit the acceptance to the queue. */
    if (gy_custodian_qsgroup_accept_invitation(c, gid, pt + 2 + envlen, gkplen,
                                               1, entry, &entrylen) != GY_OK)
        return -1;
    off = 0;
    memcpy(dep + off, gid, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    dep[off++] = (uint8_t)mulen;
    memcpy(dep + off, muid, mulen);
    off += mulen;
    memcpy(dep + off, entry, entrylen);
    off += entrylen;
    if (request(rfd, wfd, cfg->name, QSG_MSG_SRV_DEPOSIT_INVITE, dep, off, &rh,
                ack, sizeof(ack)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        return -1;

    /* Ack the founder so it can open + approve, then await its settled nudge. */
    if (send_over_session(c, cfg->name, 0, (const uint8_t *)"ok", 2, rfd,
                          wfd) != 0)
        return -1;
    if (recv_over_session(c, cfg->name, rfd, wfd, nudge, &nudgelen) != 0)
        return -1;

    /* Fetch the group core and confirm we are now a settled non-admin member. */
    if (fetch_core(c, cfg->name, views, QSG_NMEMBERS + 1, &count, rfd, wfd) !=
        0)
        return -1;
    for (k = 0; k < count; k++)
        if (views[k].uidlen == mulen &&
            memcmp(views[k].uid, muid, mulen) == 0 && views[k].admn == 0 &&
            views[k].uk_len > 0)
            found = 1;
    return found ? 0 : -1;
}

/*
 * Founder lifecycle (phase D): create the group, then in a first pass Invite each
 * member (a PENDING core write extending the previous version, keeping that
 * member's gk'), and in a second pass deliver the group key + gk' to each over a
 * pairwise session and settle it (OpenInvitation + CompleteInvitation) once
 * the member
 * has accepted and deposited.  The core, signer vkr, and version are returned in
 * b / vkr / vmaj for the subsequent mutation phase.
 */
static int
founder_lifecycle(gy_custodian *c, const char *name, struct core_buf *b,
                  uint8_t *vkr, size_t *vkrlen, uint32_t *vmaj, int rfd,
                  int wfd)
{
    uint8_t gkp[QSG_NMEMBERS][GY_QSGROUP_USER_KEY_MAX];
    size_t gkplen[QSG_NMEMBERS];
    int peer;

    if (founder_create(c, name, b, vkr, vkrlen, rfd, wfd) != 0)
        return -1;
    *vmaj = 1;
    for (peer = 1; peer < QSG_NMEMBERS; peer++) {
        gkplen[peer] = sizeof(gkp[peer]);
        if (founder_invite_one(c, name, b, vkr, *vkrlen, peer, vmaj, gkp[peer],
                               &gkplen[peer], rfd, wfd) != 0)
            return -1;
    }
    for (peer = 1; peer < QSG_NMEMBERS; peer++)
        if (founder_settle_one(c, name, b, vkr, *vkrlen, peer, vmaj, gkp[peer],
                               gkplen[peer], rfd, wfd) != 0)
            return -1;
    return 0;
}

/*
 * Founder mutation (phase E): first ToggleJoinLink opens a join link (its secret
 * is persisted), then SetAdmin promotes m2 (no group-key change, so the signer
 * vkr is unchanged), then RemoveMember drops m4 and rotates the group key (the
 * signer vkr rotates with it, so it is re-fetched).  All three are server-checked
 * core writes extending the running version.  The link opened here SURVIVES the
 * removal rotation: RemoveMember re-seals the slot under the same secret (App.
 * B.8), so phase I redelivers this original secret rather than mint a new one.
 * b / vkr / vmaj advance to the post-removal state and link_secret receives the
 * out-of-band join secret; the caller then redelivers the rotated key to
 * survivors.
 */
static int
founder_mutate(gy_custodian *c, const char *name, struct core_buf *b,
               uint8_t *vkr, size_t *vkrlen, uint32_t *vmaj,
               uint8_t link_secret[GY_QSGROUP_LINK_SECRET_LEN], int rfd,
               int wfd)
{
    uint8_t tuid[GY_QSGROUP_UID_LEN];
    size_t tulen;
    struct core_buf nb;
    struct gy_qsgroup_core cur, next;

    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_toggle_join_link(c, &cur, link_secret, &next) !=
        GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    /* ToggleJoinLink changes only the header join slot: vk-lst is unchanged. */
    if (submit_core(name, QSG_OP_UNCHANGED, *vmaj + 1, 0, *vmaj, 0, vkr,
                    *vkrlen, &nb, rfd, wfd) != 0)
        return -1;
    *b = nb;
    *vmaj += 1;

    tulen = qsg_uid(QSG_PROMOTED_MEMBER, tuid);
    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_set_admin(c, &cur, tuid, tulen, 1, &next) != GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    /* SetAdminRights toggles an admn byte only: vk-lst is unchanged. */
    if (submit_core(name, QSG_OP_UNCHANGED, *vmaj + 1, 0, *vmaj, 0, vkr,
                    *vkrlen, &nb, rfd, wfd) != 0)
        return -1;
    *b = nb;
    *vmaj += 1;

    tulen = qsg_uid(QSG_REMOVED_MEMBER, tuid);
    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_remove_member(c, &cur, tuid, tulen, &next) !=
        GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    if (gy_custodian_qsgroup_self_vkr(c, DEMO_GID, vkr, vkrlen) != GY_OK)
        return -1; /* the rotated group key has a fresh signer vkr */
    /* RemoveMember rotates gk: every vkpsdn is republished (REPLACE). */
    if (submit_core(name, QSG_OP_REPLACE, *vmaj + 1, 0, *vmaj, 0, vkr, *vkrlen,
                    &nb, rfd, wfd) != 0)
        return -1;
    /* SEC-v1.5.0 LOW-4: the server accepted the rotated core, so commit the
     * staged group key (promote it and retire the old one). */
    if (gy_custodian_qsgroup_commit(c, DEMO_GID) != GY_OK)
        return -1;
    *b = nb;
    *vmaj += 1;
    return 0;
}

/* Founder: redeliver the rotated group key to every surviving member (skip the
 * removed one) over its existing pairwise session. */
static int
founder_redeliver(gy_custodian *c, const char *name, int rfd, int wfd)
{
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    size_t envlen;
    int peer;

    for (peer = 1; peer < QSG_NMEMBERS; peer++) {
        if (peer == QSG_REMOVED_MEMBER)
            continue;
        envlen = sizeof(env);
        if (gy_custodian_qsgroup_export_group_key(c, DEMO_GID, env, &envlen) !=
            GY_OK)
            return -1;
        if (send_over_session(c, name, peer, env, envlen, rfd, wfd) != 0)
            return -1;
    }
    return 0;
}

/*
 * Surviving member (phase E): receive and install the rotated group key, then
 * re-fetch the core and confirm the mutations: we are still a member, m2 is now
 * an admin, and m4 is gone.
 */
static int
member_resync(gy_custodian *c, const struct qsgroup_client_cfg *cfg, int rfd,
              int wfd)
{
    uint8_t env[GY_QSGROUP_KEY_ENVELOPE_MAX];
    uint8_t gid[GY_QSGROUP_GID_LEN];
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    uint8_t muid[GY_QSGROUP_UID_LEN], puid[GY_QSGROUP_UID_LEN],
        auid[GY_QSGROUP_UID_LEN];
    size_t mulen = qsg_uid(cfg->index, muid);
    size_t pulen = qsg_uid(QSG_REMOVED_MEMBER, puid);
    size_t aulen = qsg_uid(QSG_PROMOTED_MEMBER, auid);
    size_t envlen = sizeof(env), count = 0, k;
    int self_ok = 0, promoted_ok = 0, removed_absent = 1;

    if (recv_over_session(c, cfg->name, rfd, wfd, env, &envlen) != 0)
        return -1;
    if (gy_custodian_qsgroup_install_group_key(c, env, envlen, gid) != GY_OK)
        return -1;
    if (fetch_core(c, cfg->name, views, QSG_NMEMBERS + 1, &count, rfd, wfd) !=
        0)
        return -1;
    for (k = 0; k < count; k++) {
        if (views[k].uidlen == mulen && memcmp(views[k].uid, muid, mulen) == 0)
            self_ok = 1;
        if (views[k].uidlen == pulen && memcmp(views[k].uid, puid, pulen) == 0)
            removed_absent = 0;
        if (views[k].uidlen == aulen &&
            memcmp(views[k].uid, auid, aulen) == 0 && views[k].admn == 1)
            promoted_ok = 1;
    }
    return (self_ok && promoted_ok && removed_absent) ? 0 : -1;
}

/*
 * Removed member (phase E): confirm the removal took effect.  Its group key is
 * now stale, so the fetch is either rejected outright (a stale token, or a
 * roster it can no longer decrypt) or, if it decodes at all, must no longer list
 * it.  Either outcome is a pass; still appearing in the roster is the failure.
 */
static int
member_removed_check(gy_custodian *c, const struct qsgroup_client_cfg *cfg,
                     int rfd, int wfd)
{
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    uint8_t muid[GY_QSGROUP_UID_LEN];
    size_t mulen = qsg_uid(cfg->index, muid);
    size_t count = 0, k;

    if (fetch_core(c, cfg->name, views, QSG_NMEMBERS + 1, &count, rfd, wfd) !=
        0)
        return 0; /* rejected: the expected outcome for a removed member */
    for (k = 0; k < count; k++)
        if (views[k].uidlen == mulen && memcmp(views[k].uid, muid, mulen) == 0)
            return -1; /* still listed: removal did not take */
    return 0;
}

/*
 * Founder (phase F): fan a chain of QSG_FANOUT_MSGS group messages ("g1"..) out
 * to every surviving member over its pairwise session.  This is app-level
 * messaging over the sessions that carried the group key; QSPGS itself is a
 * roster protocol, so a "group message" is a pairwise-relayed payload, exactly
 * as in the classical group_demo fan-out.
 */
static int
founder_fanout(gy_custodian *c, const char *name, int rfd, int wfd)
{
    int peer, k;

    for (peer = 1; peer < QSG_NMEMBERS; peer++) {
        if (peer == QSG_REMOVED_MEMBER)
            continue;
        for (k = 1; k <= QSG_FANOUT_MSGS; k++) {
            uint8_t msg[2] = {'g', (uint8_t)('0' + k)};

            if (send_over_session(c, name, peer, msg, sizeof(msg), rfd, wfd) !=
                0)
                return -1;
        }
    }
    return 0;
}

/*
 * Surviving member (phase F): receive the founder's chain and confirm it is
 * QSG_FANOUT_MSGS distinct, valid "gN" messages.
 */
static int
member_fanout_recv(gy_custodian *c, const struct qsgroup_client_cfg *cfg,
                   int rfd, int wfd)
{
    uint8_t seen[QSG_FANOUT_MSGS];
    int i, j, nseen = 0;

    for (i = 0; i < QSG_FANOUT_MSGS; i++) {
        uint8_t pt[64];
        size_t ptlen = sizeof(pt);

        if (recv_over_session(c, cfg->name, rfd, wfd, pt, &ptlen) != 0)
            return -1;
        if (ptlen != 2 || pt[0] != 'g' || pt[1] < '1' ||
            pt[1] > (uint8_t)('0' + QSG_FANOUT_MSGS))
            return -1;
        for (j = 0; j < nseen; j++)
            if (seen[j] == pt[1])
                return -1; /* duplicate */
        seen[nseen++] = pt[1];
    }
    return 0;
}

/*
 * Founder (phase G): two admin operations exercised end to end.
 *   ChangeSettings   reseals the header's settings blob and re-signs; the
 *                    server accepts the new version (core_check passes).
 *   Tampered core    a copy with a corrupted signature must be REJECTED by the
 *                    server's core_check, leaving the stored head unchanged.
 * RevokeInvitation is exercised against a real pending invitee in
 * test_qsgroup_lifecycle (the spec-faithful path: a genuine pending entry with
 * its gk' and a deposited acceptance); the old phantom shortcut relied on the
 * pre-errata invite that minted a self-contained entry, which E3 removes.
 * b / vkr / vmaj advance only past the accepted ChangeSettings write.
 */
static int
founder_admin_ops(gy_custodian *c, const char *name, struct core_buf *b,
                  uint8_t *vkr, size_t *vkrlen, uint32_t *vmaj, int rfd,
                  int wfd)
{
    static const uint8_t settings[] = "qspgs-demo-settings-v1";
    struct core_buf nb, tb;
    struct gy_qsgroup_core cur, next;

    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    if (gy_custodian_qsgroup_change_settings(c, &cur, GY_QSGROUP_SETTING_ATTR,
                                             settings, sizeof(settings) - 1,
                                             &next) != GY_OK) {
        fprintf(stderr, "qsgroup-demo: %s: change_settings failed\n", name);
        return -1;
    }
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    /* ChangeSettings re-seals the header field only: vk-lst is unchanged. */
    if (submit_core(name, QSG_OP_UNCHANGED, *vmaj + 1, 0, *vmaj, 0, vkr,
                    *vkrlen, &nb, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: change_settings submit rejected\n",
                name);
        return -1;
    }
    *b = nb;
    *vmaj += 1;

    tb = *b;
    tb.sig[0] ^= 0xFF;
    if (submit_core(name, QSG_OP_UNCHANGED, *vmaj + 1, 0, *vmaj, 0, vkr,
                    *vkrlen, &tb, rfd, wfd) == 0) {
        fprintf(stderr, "qsgroup-demo: %s: server accepted a tampered core\n",
                name);
        return -1;
    }
    /* The rejected write left the head at *vmaj; do not advance. */
    return 0;
}

/*
 * Non-admin member (phase H): record an appendix line.  Fetch the current core
 * (retaining its raw objects), then emit a signed ModAttr appendix line against
 * it, the [CFG+] append-only path for a member that is not the editing admin.
 * Confirm the line is well-formed; an admin reconciles it into the core later.
 */
static int
member_appendix(gy_custodian *c, const struct qsgroup_client_cfg *cfg, int rfd,
                int wfd)
{
    struct core_buf b;
    struct gy_qsgroup_core cur;
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    uint8_t vkr[GY_QSGROUP_VKR_MAX];
    size_t linelen = sizeof(line), vkrlen = sizeof(vkr);

    if (fetch_core_raw(c, cfg->name, &b, rfd, wfd) != 0)
        return -1;
    core_as_cur(&cur, &b);
    /* vMin 0 to match the JoinViaLink line's appendix header, so both lines
     * share one accumulated appendix object at the coordinator. */
    if (gy_custodian_qsgroup_appendix_mod_attr(
            c, &cur, 0, (const uint8_t *)DEMO_APX_ATTR, strlen(DEMO_APX_ATTR),
            line, &linelen) != GY_OK)
        return -1;
    if (linelen == 0 || linelen > GY_QSGROUP_APPENDIX_MAX)
        return -1;
    /* Submit the line to the coordinator, which apx-checks it under our vkr. */
    if (gy_custodian_qsgroup_self_vkr(c, DEMO_GID, vkr, &vkrlen) != GY_OK)
        return -1;
    return submit_appendix(cfg->name, 0, vkr, vkrlen, line, linelen, rfd, wfd);
}

/*
 * Every member (phase H): fetch the core AND the pending appendix, run Fetch
 * over both, and confirm the modAttr line is applied - the returned attributes
 * equal DEMO_APX_ATTR.  This is the member-verified half of the appendix loop
 * ([CFG+] Fig. 15): the roster it computes is the effective (core + valid
 * lines) view.  Mirrors fetch_core's GetPseudoVkBase ACCT collection.
 */
static int
member_see_appendix(gy_custodian *c, const char *name, int rfd, int wfd)
{
    uint8_t token[GY_QSGROUP_FET_LEN];
    size_t toklen = sizeof(token);
    uint8_t sbuf[GY_QSGROUP_GID_LEN + GY_QSGROUP_FET_LEN];
    uint8_t rbuf[DEMO_MAX_PAYLOAD];
    uint8_t apxobj[DEMO_MAX_PAYLOAD];
    uint8_t attr[64];
    struct demo_frame_header rh;
    struct gy_qsgroup_acct_ref refs[QSG_NMEMBERS];
    uint8_t uids[QSG_NMEMBERS][GY_QSGROUP_UID_LEN];
    uint8_t curves[QSG_NMEMBERS][GY_QSGROUP_ID_CURVE_MAX];
    uint8_t mldsas[QSG_NMEMBERS][GY_QSGROUP_ID_MLDSA_MAX];
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    struct gy_qsgroup_apx_report reps[QSG_NMEMBERS + 4];
    uint8_t *store = NULL;
    const uint8_t *obj[4];
    size_t objl[4], off = 0, o, apxlen = sizeof(apxobj);
    size_t n_refs = 0, i, count = 0, nreps = 0, attrlen = sizeof(attr);
    int k, rc = -1;

    store = malloc((size_t)QSG_NMEMBERS * GY_QSGROUP_ACCT_MAX);
    if (store == NULL)
        return -1;
    for (i = 0; i < QSG_NMEMBERS; i++) {
        size_t alen = GY_QSGROUP_ACCT_MAX;
        size_t clen = GY_QSGROUP_ID_CURVE_MAX, mlen = GY_QSGROUP_ID_MLDSA_MAX;

        if (fetch_member_acct(name, (int)i, rfd, wfd,
                              store + i * GY_QSGROUP_ACCT_MAX, &alen) != 0)
            goto done;
        if (fetch_peer_id(name, (int)i, rfd, wfd, curves[i], &clen, mldsas[i],
                          &mlen) != 0)
            goto done;
        refs[n_refs].uid = uids[i];
        refs[n_refs].uid_len = qsg_uid((int)i, uids[i]);
        refs[n_refs].acct = store + i * GY_QSGROUP_ACCT_MAX;
        refs[n_refs].acct_len = alen;
        refs[n_refs].curve_pk = curves[i];
        refs[n_refs].mldsa_pk = mldsas[i];
        n_refs++;
    }
    if (gy_custodian_qsgroup_fetch_token(c, DEMO_GID, token, &toklen) != GY_OK)
        goto done;
    memcpy(sbuf + off, DEMO_GID, GY_QSGROUP_GID_LEN);
    off += GY_QSGROUP_GID_LEN;
    memcpy(sbuf + off, token, toklen);
    off += toklen;
    if (request(rfd, wfd, name, QSG_MSG_SRV_FETCH_CORE, sbuf, off, &rh, rbuf,
                sizeof(rbuf)) != 0 ||
        rh.type != (uint32_t)QSG_MSG_SRV_REPLY)
        goto done;
    o = 0;
    for (k = 0; k < 4; k++) {
        if (o + 4 > rh.data_len)
            goto done;
        objl[k] = rd_be32(rbuf + o);
        o += 4;
        if (o + objl[k] > rh.data_len)
            goto done;
        obj[k] = rbuf + o;
        o += objl[k];
    }
    if (fetch_appendix(name, apxobj, &apxlen, rfd, wfd) != 0 || apxlen == 0)
        goto done;
    if (gy_custodian_qsgroup_fetch(
            c, obj[0], objl[0], obj[1], objl[1], obj[2], objl[2], obj[3],
            objl[3], apxobj, apxlen, NULL, 0, 0, 0, 0, NULL, 0, refs, n_refs,
            views, QSG_NMEMBERS + 1, &count, reps, QSG_NMEMBERS + 4, &nreps,
            attr, sizeof(attr), &attrlen) != GY_OK)
        goto done;
    /* The modAttr line is applied: the effective attributes changed. */
    rc = (attrlen == strlen(DEMO_APX_ATTR) &&
          memcmp(attr, DEMO_APX_ATTR, attrlen) == 0)
             ? 0
             : -1;
done:
    free(store);
    return rc;
}

/*
 * Surviving member (phase H): prove the sealed group state persists across a
 * custodian close/reopen.  Close the handle, reopen it over the SAME on-disk
 * store (QSPGS needs no clock, so plain gy_custodian_open), and confirm the
 * group key survived by re-deriving the fetch token.  *c is replaced with the
 * reopened handle.
 */
static int
member_reopen(gy_custodian **c, const struct qsgroup_client_cfg *cfg,
              const gy_store_callbacks *store)
{
    uint8_t token[GY_QSGROUP_FET_LEN];
    size_t toklen = sizeof(token);

    gy_custodian_close(*c);
    *c = NULL;
    if (gy_custodian_open(c, store, (const uint8_t *)cfg->secret,
                          strlen(cfg->secret)) != GY_OK)
        return -1;
    return gy_custodian_qsgroup_fetch_token(*c, DEMO_GID, token, &toklen) ==
                   GY_OK
               ? 0
               : -1;
}

/*
 * Founder (phase I): resurrect the removed m4 via the join link opened back in
 * phase E.  That link SURVIVED the removal rotation (RemoveMember re-sealed the
 * slot under the same secret, App. B.8), so the founder mints NO fresh secret
 * and re-signs NO core here: it simply hands m4, over their still-live pairwise
 * session, the ORIGINAL secret plus the four current core objects, so m4 can
 * open the (rotated, re-sealed) slot without ever having held the key.
 */
static int
founder_relink(gy_custodian *c, const char *name, struct core_buf *b,
               const uint8_t link_secret[GY_QSGROUP_LINK_SECRET_LEN], int rfd,
               int wfd)
{
    uint8_t payload[DEMO_MAX_PAYLOAD];
    uint8_t acct[GY_QSGROUP_ACCT_MAX];
    size_t off = 0, acctlen = sizeof(acct);

    /* The founder signs the core, so the joiner must verify it against the
     * founder's ACCT: produce it here to deliver too. */
    if (gy_custodian_qsgroup_register(c, 1, acct, &acctlen) != GY_OK)
        return -1;

    /* secret || 4x (len(4)||object) || len(4)||acct: the join secret, the
     * current core, and the signing founder's registration object. */
    memcpy(payload + off, link_secret, GY_QSGROUP_LINK_SECRET_LEN);
    off += GY_QSGROUP_LINK_SECRET_LEN;
    wr_be32(payload + off, (uint32_t)b->hn);
    off += 4;
    memcpy(payload + off, b->hdr, b->hn);
    off += b->hn;
    wr_be32(payload + off, (uint32_t)b->mn);
    off += 4;
    memcpy(payload + off, b->ml, b->mn);
    off += b->mn;
    wr_be32(payload + off, (uint32_t)b->vn);
    off += 4;
    memcpy(payload + off, b->vk, b->vn);
    off += b->vn;
    wr_be32(payload + off, (uint32_t)b->sn);
    off += 4;
    memcpy(payload + off, b->sig, b->sn);
    off += b->sn;
    wr_be32(payload + off, (uint32_t)acctlen);
    off += 4;
    memcpy(payload + off, acct, acctlen);
    off += acctlen;
    if (send_over_session(c, name, QSG_REMOVED_MEMBER, payload, off, rfd,
                          wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: join-link delivery failed\n", name);
        return -1;
    }
    return 0;
}

/*
 * The removed member (phase I): rejoin via the link.  Receive the secret and the
 * current core over the session, open the join slot with JoinViaLink (which
 * recovers the group key into the store and mints our own user key), then prove
 * recovery by fetching and decrypting the current roster.  An admin reconciles
 * the emitted JOIN line into the core separately, so we need not appear in the
 * roster yet.
 */
static int
member_rejoin(gy_custodian *c, const struct qsgroup_client_cfg *cfg, int rfd,
              int wfd)
{
    uint8_t pt[DEMO_MAX_PAYLOAD];
    struct core_buf b;
    struct gy_qsgroup_core cur;
    struct gy_qsgroup_member_view views[QSG_NMEMBERS + 1];
    uint8_t uk[GY_QSGROUP_USER_KEY_MAX];
    uint8_t line[GY_QSGROUP_APPENDIX_MAX];
    const uint8_t *obj[4];
    const uint8_t *sacct;
    uint8_t *dst[4];
    size_t ptlen = sizeof(pt), uklen = sizeof(uk), linelen = sizeof(line);
    size_t objl[4], cap[4], o, count = 0, sacctlen;
    int k;

    if (recv_over_session(c, cfg->name, rfd, wfd, pt, &ptlen) != 0)
        return -1;
    if (ptlen < GY_QSGROUP_LINK_SECRET_LEN)
        return -1;
    o = GY_QSGROUP_LINK_SECRET_LEN;
    for (k = 0; k < 4; k++) {
        if (o + 4 > ptlen)
            return -1;
        objl[k] = rd_be32(pt + o);
        o += 4;
        if (o + objl[k] > ptlen)
            return -1;
        obj[k] = pt + o;
        o += objl[k];
    }
    dst[0] = b.hdr;
    cap[0] = sizeof(b.hdr);
    dst[1] = b.ml;
    cap[1] = sizeof(b.ml);
    dst[2] = b.vk;
    cap[2] = sizeof(b.vk);
    dst[3] = b.sig;
    cap[3] = sizeof(b.sig);
    for (k = 0; k < 4; k++) {
        if (objl[k] > cap[k])
            return -1;
        memcpy(dst[k], obj[k], objl[k]);
    }
    b.hn = objl[0];
    b.mn = objl[1];
    b.vn = objl[2];
    b.sn = objl[3];
    core_as_cur(&cur, &b);

    /* The trailing object is the signing founder's ACCT (item 5). */
    if (o + 4 > ptlen)
        return -1;
    sacctlen = rd_be32(pt + o);
    o += 4;
    if (o + sacctlen > ptlen)
        return -1;
    sacct = pt + o;

    if (gy_custodian_qsgroup_join_via_link(c, &cur, pt, 1, sacct, sacctlen, uk,
                                           &uklen, line, &linelen) != GY_OK)
        return -1;
    if (uklen == 0 || linelen == 0)
        return -1;
    /* Submit the JOIN line to the coordinator as a newcomer (its vkpsdn is not
     * yet in the vk-lst); an admin folds it at Consolidate. */
    {
        uint8_t vkr[GY_QSGROUP_VKR_MAX];
        size_t vkrlen = sizeof(vkr);

        if (gy_custodian_qsgroup_self_vkr(c, DEMO_GID, vkr, &vkrlen) != GY_OK)
            return -1;
        if (submit_appendix(cfg->name, 1, vkr, vkrlen, line, linelen, rfd,
                            wfd) != 0)
            return -1;
    }
    /* The link recovered the group key: we can now fetch and decrypt again. */
    if (fetch_core(c, cfg->name, views, QSG_NMEMBERS + 1, &count, rfd, wfd) !=
        0)
        return -1;
    return count >= 1 ? 0 : -1;
}

/*
 * Founder (phase I, reconciliation): fold the pending appendix (the phase-H
 * ModAttr and the phase-I JOIN) into the next core with Consolidate, then
 * submit it as a REPLACE core write ([CFG+] Fig. 18).  A folded JOIN adds the
 * rejoined member; the folded ModAttr carries the new attributes forward.  b is
 * the founder's current core; on success it holds the consolidated core.
 */
static int
founder_consolidate(gy_custodian *c, const char *name, struct core_buf *b,
                    uint8_t *vkr, size_t *vkrlen, uint32_t *vmaj, int rfd,
                    int wfd)
{
    struct gy_qsgroup_core cur, next;
    struct core_buf nb;
    uint8_t apxobj[DEMO_MAX_PAYLOAD];
    size_t apxlen = sizeof(apxobj);

    if (fetch_core_raw(c, name, b, rfd, wfd) != 0)
        return -1;
    if (fetch_appendix(name, apxobj, &apxlen, rfd, wfd) != 0 || apxlen == 0)
        return -1;
    core_as_cur(&cur, b);
    core_as_next(&next, &nb);
    /* Founder is acquainted with every member and the newcomer, so no ACCTs. */
    if (gy_custodian_qsgroup_consolidate(c, &cur, apxobj, apxlen, NULL, 0, NULL,
                                         0, NULL, 0, &next, NULL,
                                         NULL) != GY_OK)
        return -1;
    nb.hn = next.hdr_len;
    nb.mn = next.member_list_len;
    nb.vn = next.vk_lst_len;
    nb.sn = next.sig_len;
    memcpy(nb.fet, next.fet, GY_QSGROUP_FET_LEN);
    if (gy_custodian_qsgroup_self_vkr(c, DEMO_GID, vkr, vkrlen) != GY_OK)
        return -1;
    /*
     * This appendix folds a ModAttr and a JOIN (no leave), so gk is unchanged
     * and the vk-lst grows by the newcomer.  Submit as REPLACE, which the server
     * accepts for any vk-lst; the fetching clients re-verify in full.
     */
    if (submit_core(name, QSG_OP_REPLACE, *vmaj + 1, 0, *vmaj, 0, vkr, *vkrlen,
                    &nb, rfd, wfd) != 0)
        return -1;
    *b = nb;
    *vmaj += 1;
    return 0;
}

int
qsgroup_client_run(const struct qsgroup_client_cfg *cfg, int rfd, int wfd)
{
    struct filestore fs;
    gy_store_callbacks store;
    gy_custodian *c = NULL;
    uint8_t uid[GY_QSGROUP_UID_LEN];
    const uint8_t did[1] = {0x01};
    size_t uidlen;
    int rc = 0;
    /* Founder-only running state, carried across the lifecycle and mutation
     * phases: the current core, its signer vkr, and the state version. */
    struct core_buf fb;
    uint8_t fvkr[GY_QSGROUP_VKR_MAX];
    size_t fvkrlen = sizeof(fvkr);
    uint32_t fvmaj = 0;
    uint8_t flink_secret[GY_QSGROUP_LINK_SECRET_LEN];

    if (filestore_bind(&fs, cfg->dir, &store) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: store bind failed\n", cfg->name);
        return 1;
    }
    uidlen = qsg_uid(cfg->index, uid);

    if (gy_custodian_create(&c, cfg->suite, &store,
                            (const uint8_t *)cfg->secret, strlen(cfg->secret),
                            uid, uidlen, did, sizeof(did), NULL, NULL,
                            NULL) != GY_OK ||
        gy_custodian_generate_identity(c, 1000, 2) != GY_OK) {
        fprintf(stderr, "qsgroup-demo: %s: custodian bring-up failed\n",
                cfg->name);
        rc = 1;
        goto out;
    }

    /* RegisterUser + publish identity keys, then rendezvous. */
    if (do_register(c, cfg->name, uid, uidlen, rfd, wfd) != 0 ||
        do_publish_id(c, cfg->name, uid, uidlen, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: register/publish failed\n",
                cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * GrantAcquaintance (bidirectional, [CFG+] Fig. 8): the founder and each
     * member stand up a pairwise Double Ratchet session and exchange their user
     * keys uk over it (the E2EE channel), each accepting the other (ACCT verify
     * + acq == KDF(uk)).  The founder's acceptances give its admin edits
     * (Invite) each member's base verification key; the members' acceptance lets
     * them fetch-verify the founder-signed core.  The session persists and is
     * reused for the phase-D group-key delivery.  Every member's ACCT + identity
     * keys were published in phase A, so all are resolvable here.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        int peer;

        for (peer = 1; peer < QSG_NMEMBERS; peer++)
            if (founder_acquaint_one(c, cfg->name, peer, rfd, wfd) != 0) {
                fprintf(stderr, "qsgroup-demo: %s: accept m%d failed\n",
                        cfg->name, peer + 1);
                rc = 1;
                goto out;
            }
    } else if (member_acquaint_founder(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: accept founder failed\n", cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase D (lifecycle).  The founder creates the group, invites every member
     * (a PENDING core write), then over the reused acquaintance session delivers
     * the group key + that member's gk'; the member installs the key, accepts
     * the invitation with its own identity, deposits the acceptance, and acks;
     * the founder opens the acceptance and completes it (settles the entry), then
     * nudges the member to fetch-verify its own membership.  The pairwise relay
     * synchronizes the two sides.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        if (founder_lifecycle(c, cfg->name, &fb, fvkr, &fvkrlen, &fvmaj, rfd,
                              wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: founder lifecycle failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    } else if (member_join(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: join failed\n", cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase E (mutation).  The founder promotes m2 to admin and removes m4,
     * rotating the group key; the barrier ensures both server-checked core
     * writes land before anyone reads.
     */
    if (cfg->role == QSG_ROLE_FOUNDER &&
        founder_mutate(c, cfg->name, &fb, fvkr, &fvkrlen, &fvmaj, flink_secret,
                       rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: mutation failed\n", cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * The founder redelivers the rotated key to the survivors over their
     * existing sessions; each survivor reinstalls it and reverifies the roster
     * (m2 admin, m4 gone); the removed m4 confirms it can no longer read.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        if (founder_redeliver(c, cfg->name, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: redelivery failed\n", cfg->name);
            rc = 1;
            goto out;
        }
    } else if (cfg->index == QSG_REMOVED_MEMBER) {
        if (member_removed_check(c, cfg, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: removal check failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    } else if (member_resync(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: resync failed\n", cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase F (group message fan-out).  The founder fans a chain of messages out
     * to each surviving member over its pairwise session; each survivor confirms
     * it receives the full, distinct chain.  The removed m4 has no session and
     * only rejoins at the barrier.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        if (founder_fanout(c, cfg->name, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: fan-out failed\n", cfg->name);
            rc = 1;
            goto out;
        }
    } else if (cfg->index != QSG_REMOVED_MEMBER &&
               member_fanout_recv(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: fan-out receive failed\n",
                cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase G (admin ops).  The founder reseals the group settings, proves the
     * server rejects a tampered core, and revokes a pending invite.  These are
     * admin-only operations, so the other members simply rejoin at the barrier.
     */
    if (cfg->role == QSG_ROLE_FOUNDER &&
        founder_admin_ops(c, cfg->name, &fb, fvkr, &fvkrlen, &fvmaj, rfd,
                          wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: admin ops failed\n", cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase H (non-admin appendix + reopen persistence).  m3 records a non-admin
     * appendix line against the current core; m5 closes and reopens its
     * custodian and confirms the sealed group key survived.  Both are local,
     * per-member checks; the others rejoin at the barrier.
     */
    if (cfg->role == QSG_ROLE_MEMBER && cfg->index == QSG_APPENDIX_MEMBER) {
        if (member_appendix(c, cfg, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: appendix line failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    } else if (cfg->role == QSG_ROLE_MEMBER &&
               cfg->index == QSG_REOPEN_MEMBER) {
        if (member_reopen(&c, cfg, &store) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: reopen persistence failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase H (appendix verify): now that m3's ModAttr line is submitted and
     * apx-checked, every current member fetches the core AND the pending
     * appendix, runs Fetch over both, and confirms the line is applied (the
     * effective attributes changed).  The removed m4 holds no group key and
     * idles until phase I.
     */
    if (cfg->index != QSG_REMOVED_MEMBER) {
        if (member_see_appendix(c, cfg->name, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: appendix verify failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase I (join-link resurrection).  The founder redelivers the join link
     * opened in phase E (which survived the removal rotation, App. B.8): it
     * hands the removed m4 the ORIGINAL secret plus the current core over their
     * existing session; m4 opens the re-sealed join slot, recovers the current
     * group key without ever holding it, and reads the roster again.  The other
     * members idle.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        if (founder_relink(c, cfg->name, &fb, flink_secret, rfd, wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: join-link relink failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    } else if (cfg->index == QSG_REMOVED_MEMBER &&
               member_rejoin(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "qsgroup-demo: %s: join-link rejoin failed\n",
                cfg->name);
        rc = 1;
        goto out;
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    /*
     * Phase I (reconciliation): the founder folds the pending appendix (the
     * phase-H ModAttr and the phase-I JOIN, both apx-checked by the coordinator)
     * into the next core with Consolidate and submits it, so the rejoined member
     * becomes settled and the attribute change is durable.  The others idle.
     */
    if (cfg->role == QSG_ROLE_FOUNDER) {
        if (founder_consolidate(c, cfg->name, &fb, fvkr, &fvkrlen, &fvmaj, rfd,
                                wfd) != 0) {
            fprintf(stderr, "qsgroup-demo: %s: consolidate failed\n",
                    cfg->name);
            rc = 1;
            goto out;
        }
    }
    if (barrier(cfg->name, rfd, wfd) != 0) {
        rc = 1;
        goto out;
    }

    printf("qsgroup-demo: %s (%s) done\n", cfg->name,
           cfg->role == QSG_ROLE_FOUNDER ? "founder" : "member");
    (void)send_msg(wfd, cfg->name, QSG_MSG_GOODBYE, NULL, 0);
out:
    gy_custodian_close(c);
    return rc;
}
