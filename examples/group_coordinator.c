/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The untrusted coordinator for the group example: the group SERVER (holds
 * ServerSecretParams via geryon_group_server, answers the section 8.1 RPCs and
 * serves the roster it accumulates) and the RELAY (a per-member mailbox that
 * forwards opaque member<->member bytes - one-shot bundles for the pairwise
 * session mesh, then the GROUP_KEY_DISTRIBUTION envelopes and the fanned-out
 * group message - which it never parses).  It holds only ciphertexts and the
 * group's PUBLIC key; it never learns a UID or ProfileKey.
 *
 * Each member issues synchronous requests (send, block for one reply).  A
 * FETCH_BUNDLE for a peer that has not published yet, or a RECV with an empty
 * inbox, is DEFERRED: the coordinator keeps that member's single pending reply
 * and answers it when the awaited event arrives, while it keeps serving others.
 */

#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geryon_group_server.h"

#include "demo_ipc.h"
#include "group_coordinator.h"
#include "group_demo_proto.h"

#define GRP_POLL_TIMEOUT_MS 30000
#define ROSTER_MAX (GRP_NMEMBERS + 2)

#define MBOX_BUNDLES 6
#define MBOX_BUNDLE_SLOT 4096
#define MBOX_INBOX 12
#define MBOX_MSG_SLOT 8192

/* ---- server key store --------------------------------------------------- */

struct srv_store {
    uint8_t blob[GY_GROUP_SERVER_KEY_BLOB_MAX];
    size_t len;
    int have;
};

static int
srv_store_load(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    struct srv_store *s = ctx;
    if (!s->have) {
        *out_len = 0;
        return GY_OK;
    }
    if (s->len > cap)
        return GY_ERR_TOOLONG;
    memcpy(out, s->blob, s->len);
    *out_len = s->len;
    return GY_OK;
}

static int
srv_store_store(void *ctx, const uint8_t *blob, size_t len)
{
    struct srv_store *s = ctx;
    if (len > sizeof(s->blob))
        return GY_ERR_TOOLONG;
    memcpy(s->blob, blob, len);
    s->len = len;
    s->have = 1;
    return GY_OK;
}

/* ---- roster ------------------------------------------------------------- */

struct roster_entry {
    uint8_t uid_ct[GY_GROUP_UID_CT_MAX_448];
    size_t uid_ct_len;
    uint8_t pk_ct[GY_GROUP_PK_CT_MAX_448];
    size_t pk_ct_len;
    uint8_t role;
    uint8_t has_pk;
    int used;
};

struct roster {
    uint8_t group_pub[GY_GROUP_GROUP_PUBLIC_MAX_448];
    size_t group_pub_len;
    int have_group;
    struct roster_entry e[ROSTER_MAX];
    size_t n;
};

/* ---- per-member mailbox ------------------------------------------------- */

#define PEND_NONE 0
#define PEND_FETCH 1
#define PEND_RECV 2
#define PEND_BARRIER 3

struct inbox_item {
    uint8_t data[MBOX_MSG_SLOT];
    size_t len;
    char from[DEMO_NAME_MAX];
};

struct member_mbox {
    uint8_t bundle[MBOX_BUNDLES][MBOX_BUNDLE_SLOT];
    size_t blen[MBOX_BUNDLES];
    int bhead, bcount;
    struct inbox_item inbox[MBOX_INBOX];
    int ihead, icount;
    int pending;      /* PEND_* */
    int fetch_target; /* member index awaited when pending == PEND_FETCH */
    int reorder;      /* apply one out-of-order swap to this member's chain */
    int reordered;    /* the single swap has already been applied */
};

/* Coordinator state (single group, single process; children never run here). */
static struct roster g_roster;
static struct member_mbox g_mbox[GRP_NPROC];
static int
    g_barrier; /* count of members currently parked at the phase barrier */

static int
name_index(const char *name)
{
    if (name == NULL)
        return -1;
    /* The companion endpoint is its own process slot; check it before the
     * "m<N>" parse (atoi("2b") would otherwise fold it onto m2). */
    if (strcmp(name, GRP_MD_COMPANION_NAME) == 0)
        return GRP_MD_COMPANION_PROC;
    if (name[0] == 'm') {
        int v = atoi(name + 1);
        if (v >= 1 && v <= GRP_NMEMBERS)
            return v - 1;
    }
    return -1;
}

/* ---- roster helpers ----------------------------------------------------- */

static struct roster_entry *
roster_find(struct roster *r, const uint8_t *uid_ct, size_t len)
{
    size_t i;
    for (i = 0; i < r->n; i++)
        if (r->e[i].used && r->e[i].uid_ct_len == len &&
            memcmp(r->e[i].uid_ct, uid_ct, len) == 0)
            return &r->e[i];
    return NULL;
}

static struct roster_entry *
roster_slot(struct roster *r, const uint8_t *uid_ct, size_t len)
{
    struct roster_entry *e = roster_find(r, uid_ct, len);
    size_t i;
    if (e != NULL)
        return e;
    for (i = 0; i < r->n; i++)
        if (!r->e[i].used)
            return &r->e[i];
    if (r->n < ROSTER_MAX)
        return &r->e[r->n++];
    return NULL;
}

static uint64_t
be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/* ---- framed replies ----------------------------------------------------- */

static int
reply_from(int wfd, enum grp_msg_type type, const char *from,
           const uint8_t *data, size_t len)
{
    struct demo_frame_header h;
    memset(&h, 0, sizeof(h));
    h.type = type;
    h.data_len = (uint32_t)len;
    snprintf(h.from, sizeof(h.from), "%s", from ? from : "coord");
    return demo_send_frame(wfd, &h, len ? data : NULL) == DEMO_IPC_OK ? 0 : -1;
}

static int
reply(int wfd, enum grp_msg_type type, const uint8_t *data, size_t len)
{
    return reply_from(wfd, type, "coord", data, len);
}

/* ---- relay mailbox ------------------------------------------------------ */

/* Deliver one queued inbox item to member i (must have icount > 0). */
static int
deliver_inbox(struct member_mbox *m, int wfd)
{
    struct inbox_item *it = &m->inbox[m->ihead];
    int rc = reply_from(wfd, GRP_MSG_DELIVER, it->from, it->data, it->len);
    m->ihead = (m->ihead + 1) % MBOX_INBOX;
    m->icount--;
    return rc;
}

/* Serve member fi's pending FETCH from target t (must have a bundle). */
static int
serve_fetch(int fi, int wfd)
{
    struct member_mbox *t = &g_mbox[g_mbox[fi].fetch_target];
    int slot = t->bhead;
    int rc = reply(wfd, GRP_MSG_BUNDLE, t->bundle[slot], t->blen[slot]);
    t->bhead = (t->bhead + 1) % MBOX_BUNDLES;
    t->bcount--;
    g_mbox[fi].pending = PEND_NONE;
    return rc;
}

/*
 * Handle a relay-plane frame from member i.  wfd[] gives every member's write
 * end (a deferred reply may target a DIFFERENT member than the sender).  Returns
 * 0 to continue, -1 on a fatal IPC error.
 */
static int
handle_mailbox(int i, const int *wfd, const struct demo_frame_header *h,
               const uint8_t *buf)
{
    struct member_mbox *m = &g_mbox[i];

    switch (h->type) {
    case GRP_MSG_PUBLISH_BUNDLE: {
        int slot, fi;
        if (m->bcount >= MBOX_BUNDLES || h->data_len > MBOX_BUNDLE_SLOT)
            return reply(wfd[i], GRP_MSG_SRV_FAIL, NULL, 0);
        slot = (m->bhead + m->bcount) % MBOX_BUNDLES;
        memcpy(m->bundle[slot], buf, h->data_len);
        m->blen[slot] = h->data_len;
        m->bcount++;
        if (reply(wfd[i], GRP_MSG_SRV_REPLY, NULL, 0) != 0)
            return -1;
        /* Wake any member deferred fetching this publisher. */
        for (fi = 0; fi < GRP_NPROC; fi++)
            if (g_mbox[fi].pending == PEND_FETCH &&
                g_mbox[fi].fetch_target == i && m->bcount > 0)
                return serve_fetch(fi, wfd[fi]);
        return 0;
    }

    case GRP_MSG_FETCH_BUNDLE: {
        int t = name_index(h->to);
        if (t < 0)
            return reply(wfd[i], GRP_MSG_SRV_FAIL, NULL, 0);
        if (g_mbox[t].bcount > 0) {
            m->fetch_target = t;
            return serve_fetch(i, wfd[i]);
        }
        m->pending = PEND_FETCH; /* deferred until t publishes */
        m->fetch_target = t;
        return 0;
    }

    case GRP_MSG_RELAY: {
        int t = name_index(h->to);
        int slot;
        struct member_mbox *tm;
        if (t < 0 || h->data_len > MBOX_MSG_SLOT)
            return reply(wfd[i], GRP_MSG_SRV_FAIL, NULL, 0);
        tm = &g_mbox[t];
        if (tm->icount >= MBOX_INBOX)
            return reply(wfd[i], GRP_MSG_SRV_FAIL, NULL, 0);
        slot = (tm->ihead + tm->icount) % MBOX_INBOX;
        memcpy(tm->inbox[slot].data, buf, h->data_len);
        tm->inbox[slot].len = h->data_len;
        snprintf(tm->inbox[slot].from, sizeof(tm->inbox[slot].from), "%s",
                 h->from);
        tm->icount++;
        /* Out-of-order delivery (mirrors the 1:1 coordinator's single adjacent
         * swap): once a flagged member has two messages queued and none yet
         * delivered, swap the head pair so the receiver's ratchet skip store is
         * exercised.  A parked RECV means FIFO delivery already began, so leave
         * that stream in order. */
        if (tm->reorder && !tm->reordered && tm->pending != PEND_RECV &&
            tm->icount >= 2) {
            int a = tm->ihead, b = (tm->ihead + 1) % MBOX_INBOX;
            struct inbox_item swap = tm->inbox[a];
            tm->inbox[a] = tm->inbox[b];
            tm->inbox[b] = swap;
            tm->reordered = 1;
        }
        if (reply(wfd[i], GRP_MSG_SRV_REPLY, NULL, 0) != 0)
            return -1;
        if (tm->pending == PEND_RECV) {
            tm->pending = PEND_NONE;
            return deliver_inbox(tm, wfd[t]);
        }
        return 0;
    }

    case GRP_MSG_RECV:
        if (m->icount > 0)
            return deliver_inbox(m, wfd[i]);
        m->pending = PEND_RECV; /* deferred until a message arrives */
        return 0;

    default:
        return reply(wfd[i], GRP_MSG_SRV_FAIL, NULL, 0);
    }
}

/* ---- section 8.1 server RPCs -------------------------------------------- */

static int
handle_rpc(gy_group_server *server, uint8_t suite, struct roster *r, int wfd,
           uint32_t type, const uint8_t *buf, size_t len)
{
    uint8_t out[DEMO_MAX_PAYLOAD];
    size_t olen;
    int rc;

    switch (type) {
    case GRP_MSG_SRV_PUBLIC:
        olen = sizeof(out);
        if (gy_group_server_export_public(server, out, &olen) != GY_OK)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        return reply(wfd, GRP_MSG_SRV_REPLY, out, olen);

    case GRP_MSG_SRV_REGISTER:
        if (len == 0 || len > sizeof(r->group_pub))
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        memcpy(r->group_pub, buf, len);
        r->group_pub_len = len;
        r->have_group = 1;
        return reply(wfd, GRP_MSG_SRV_REPLY, NULL, 0);

    case GRP_MSG_SRV_ISSUE_AUTH:
        if (len != 16 + 8)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        olen = sizeof(out);
        if (gy_group_server_issue_auth(server, buf, be64(buf + 16), out,
                                       &olen) != GY_OK)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        return reply(wfd, GRP_MSG_SRV_REPLY, out, olen);

    case GRP_MSG_SRV_BLIND_ISSUE: {
        size_t clen, off;
        if (len < 16 + 2)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        clen = ((size_t)buf[16] << 8) | buf[17];
        off = 16 + 2;
        if (off + clen > len)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        olen = sizeof(out);
        if (gy_group_server_blind_issue_pk(server, buf, buf + off, clen,
                                           buf + off + clen, len - off - clen,
                                           out, &olen) != GY_OK)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        return reply(wfd, GRP_MSG_SRV_REPLY, out, olen);
    }

    case GRP_MSG_SRV_VERIFY_AUTH:
        if (!r->have_group)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        rc = gy_group_server_verify_auth(server, r->group_pub, r->group_pub_len,
                                         buf, len, NULL, NULL);
        return reply(wfd, rc == GY_OK ? GRP_MSG_SRV_REPLY : GRP_MSG_SRV_FAIL,
                     NULL, 0);

    case GRP_MSG_SRV_ADD_MEMBER: {
        uint8_t uid_ct[GY_GROUP_UID_CT_MAX_448];
        uint8_t pk_ct[GY_GROUP_PK_CT_MAX_448];
        size_t ulen = sizeof(uid_ct), plen = sizeof(pk_ct);
        struct roster_entry *e;
        if (!r->have_group)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        if (gy_group_server_verify_pk(server, r->group_pub, r->group_pub_len,
                                      buf, len, uid_ct, &ulen, pk_ct,
                                      &plen) != GY_OK)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        e = roster_slot(r, uid_ct, ulen);
        if (e == NULL)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        memcpy(e->uid_ct, uid_ct, ulen);
        e->uid_ct_len = ulen;
        memcpy(e->pk_ct, pk_ct, plen);
        e->pk_ct_len = plen;
        e->has_pk = 1;
        e->role = GY_GROUP_ROLE_DEFAULT;
        e->used = 1;
        return reply(wfd, GRP_MSG_SRV_REPLY, NULL, 0);
    }

    case GRP_MSG_SRV_ADD_INVITED: {
        struct roster_entry *e;
        if (len == 0 || len > GY_GROUP_UID_CT_MAX_448)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        e = roster_slot(r, buf, len);
        if (e == NULL)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        memcpy(e->uid_ct, buf, len);
        e->uid_ct_len = len;
        e->pk_ct_len = 0;
        e->has_pk = 0;
        e->role = GY_GROUP_ROLE_DEFAULT;
        e->used = 1;
        return reply(wfd, GRP_MSG_SRV_REPLY, NULL, 0);
    }

    case GRP_MSG_SRV_DELETE_MEMBER: {
        struct roster_entry *e;
        if (len == 0 || len > GY_GROUP_UID_CT_MAX_448)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        e = roster_find(r, buf, len);
        if (e != NULL)
            e->used = 0;
        return reply(wfd, GRP_MSG_SRV_REPLY, NULL, 0);
    }

    case GRP_MSG_SRV_FETCH_MEMBERS: {
        struct gy_group_server_member m[ROSTER_MAX];
        size_t i, cnt = 0;
        for (i = 0; i < r->n; i++) {
            if (!r->e[i].used)
                continue;
            m[cnt].uid_ct = r->e[i].uid_ct;
            m[cnt].uid_ct_len = r->e[i].uid_ct_len;
            m[cnt].pk_ct = r->e[i].has_pk ? r->e[i].pk_ct : NULL;
            m[cnt].pk_ct_len = r->e[i].has_pk ? r->e[i].pk_ct_len : 0;
            m[cnt].role = r->e[i].role;
            m[cnt].has_profile_key = r->e[i].has_pk;
            cnt++;
        }
        olen = sizeof(out);
        if (gy_group_server_member_list_encode(suite, m, cnt, out, &olen) !=
            GY_OK)
            return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
        return reply(wfd, GRP_MSG_SRV_REPLY, out, olen);
    }

    default:
        return reply(wfd, GRP_MSG_SRV_FAIL, NULL, 0);
    }
}

static int
is_mailbox(uint32_t type)
{
    return type == GRP_MSG_PUBLISH_BUNDLE || type == GRP_MSG_FETCH_BUNDLE ||
           type == GRP_MSG_RELAY || type == GRP_MSG_RECV;
}

/* Park member i at the barrier; once all n have arrived, release them all. */
static int
handle_barrier(int i, const int *wfd, int n)
{
    g_mbox[i].pending = PEND_BARRIER;
    g_barrier++;
    if (g_barrier >= n) {
        int j;
        for (j = 0; j < n; j++)
            if (g_mbox[j].pending == PEND_BARRIER) {
                g_mbox[j].pending = PEND_NONE;
                if (reply(wfd[j], GRP_MSG_SRV_REPLY, NULL, 0) != 0)
                    return -1;
            }
        g_barrier = 0;
    }
    return 0;
}

int
grp_coordinator_run(const int *rfd, const int *wfd, int n, uint8_t suite,
                    const char *base)
{
    struct srv_store store_ctx;
    struct gy_group_server_store store;
    gy_group_server *server = NULL;
    struct pollfd pfds[GRP_NPROC];
    uint8_t buf[DEMO_MAX_PAYLOAD];
    int i, ndone = 0, rc = 0, screate;

    (void)base;
    if (n > GRP_NPROC)
        return 1;

    memset(&store_ctx, 0, sizeof(store_ctx));
    memset(&g_roster, 0, sizeof(g_roster));
    memset(g_mbox, 0, sizeof(g_mbox));
    /* The fan-out targets (m2, m3) receive a multi-message chain; deliver each
     * reordered so the receiver exercises the ratchet skip store. */
    if (n > 1)
        g_mbox[1].reorder = 1;
    if (n > 2)
        g_mbox[2].reorder = 1;
    g_barrier = 0;
    store.ctx = &store_ctx;
    store.load = srv_store_load;
    store.store = srv_store_store;

    screate = gy_group_server_create(&server, suite, &store,
                                     (const uint8_t *)"srv", 3);
    if (screate != GY_OK) {
        fprintf(stderr, "coord: group server create failed (rc=%d)\n", screate);
        return 1;
    }
    printf("coord: group server up; serving %d process endpoints (%d members "
           "+ 1 companion device)\n",
           n, GRP_NMEMBERS);

    for (i = 0; i < n; i++) {
        pfds[i].fd = rfd[i];
        pfds[i].events = POLLIN;
        pfds[i].revents = 0;
    }

    while (ndone < n) {
        int pr = poll(pfds, (nfds_t)n, GRP_POLL_TIMEOUT_MS);
        if (pr < 0) {
            perror("poll");
            rc = 1;
            break;
        }
        if (pr == 0) {
            fprintf(stderr, "coord: timeout waiting on members\n");
            rc = 1;
            break;
        }
        for (i = 0; i < n; i++) {
            struct demo_frame_header h;
            int r;

            if (pfds[i].fd < 0 || pfds[i].revents == 0)
                continue;
            r = demo_recv_frame(pfds[i].fd, &h, buf, sizeof(buf));
            if (r == DEMO_IPC_EOF) {
                pfds[i].fd = -1;
                ndone++;
                continue;
            }
            if (r != DEMO_IPC_OK) {
                fprintf(stderr, "coord: recv error from member %d\n", i);
                rc = 1;
                goto out;
            }
            if (h.type == GRP_MSG_PING) {
                if (reply(wfd[i], GRP_MSG_PONG, NULL, 0) != 0) {
                    rc = 1;
                    goto out;
                }
            } else if (h.type == GRP_MSG_GOODBYE) {
                pfds[i].fd = -1;
                ndone++;
            } else if (h.type == GRP_MSG_BARRIER) {
                if (handle_barrier(i, wfd, n) != 0) {
                    rc = 1;
                    goto out;
                }
            } else if (is_mailbox(h.type)) {
                if (handle_mailbox(i, wfd, &h, buf) != 0) {
                    rc = 1;
                    goto out;
                }
            } else {
                if (handle_rpc(server, suite, &g_roster, wfd[i], h.type, buf,
                               h.data_len) != 0) {
                    rc = 1;
                    goto out;
                }
            }
        }
    }

out:
    gy_group_server_close(server);
    if (rc == 0)
        printf("coord: all members done\n");
    return rc;
}
