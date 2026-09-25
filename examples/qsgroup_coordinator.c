/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The untrusted coordinator for the QSPGS group example: the RELAY (a
 * per-member mailbox that forwards opaque member<->member bytes - one-shot
 * messaging bundles for the pairwise session mesh, then the group-key delivery
 * envelopes - which it never parses) and the SERVER (a keyed store of opaque
 * group objects; the section-7.3 acceptance checks are layered on later).
 *
 * Each member issues synchronous requests (send, block for one reply).  A
 * FETCH_BUNDLE for a peer that has not published, or a RECV with an empty
 * inbox, is DEFERRED: the coordinator keeps that member's single pending reply
 * and answers it when the awaited event arrives, while it keeps serving others.
 * A phase BARRIER is released to all members once every member has arrived.
 *
 * SCAFFOLD (first increment): the transport + barrier + opaque store
 * are complete; the QSPGS server-side checks (geryon_qsgroups_server.h) are
 * wired as the client lifecycle lands.
 */

#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geryon_qsgroups_server.h" /* the section-7.3 acceptance checks */

#include "demo_ipc.h"
#include "qsgroup_coordinator.h"
#include "qsgroup_demo_proto.h"

/* Parse widths (the server handles opaque objects; these frame the fixed
 * fields).  GY_QSGROUP_FET_LEN comes from geryon_qsgroups_server.h. */
#define QSG_GID_LEN 16
#define QSG_VKR_MAX 2592
#define QSG_OBJ_MAX 16384

/* Appendix-object framing for the newcomer derivation (SEC-v1.5.0 LOW-3): the
 * object is objhdr(3: type || wire ver || suite) || GID(16) || vMaj(4) ||
 * vMin(4) || count(2) || line, so the first line's type byte sits at
 * QSG_APX_HDR_LEN.  QSG_APX_JOIN mirrors the wire join line type
 * (GY_QSGROUP_APX_JOIN in the client header, which the server side deliberately
 * does not include). */
#define QSG_APX_HDR_LEN (3 + QSG_GID_LEN + 4 + 4 + 2)
#define QSG_APX_JOIN 0x05u

#define QSG_POLL_TIMEOUT_MS 30000

#define STORE_MAX 64
#define STORE_KEY_MAX 64
#define STORE_BLOB_MAX 16384

#define MBOX_ITEMS 8
/* A relayed message must fit one mailbox item.  The join-link relink message is
 * the largest: the join secret, the four current core objects, and the signing
 * founder's ACCT (delivered so the joiner can verify the core before adopting
 * gk).  On the h448_1024 tier the ML-DSA-87 core signature
 * (~4.6 KB) plus the ~10.7 KB ACCT push that past 16 KB, so size to 32 KB. */
#define MBOX_ITEM_MAX 32768

#define PEND_NONE 0
#define PEND_BARRIER 1
#define PEND_RECV 2
#define PEND_FETCH 3

/* ---- opaque keyed object store (the QSPGS "server" state) --------------- */

struct kv {
    int used;
    char key[STORE_KEY_MAX];
    uint8_t blob[STORE_BLOB_MAX];
    size_t len;
};

static struct kv *
kv_find(struct kv *s, const char *key)
{
    int i;

    for (i = 0; i < STORE_MAX; i++)
        if (s[i].used && strcmp(s[i].key, key) == 0)
            return &s[i];
    return NULL;
}

static int
kv_put(struct kv *s, const char *key, const uint8_t *blob, size_t len)
{
    struct kv *e = kv_find(s, key);
    int i;

    if (len > STORE_BLOB_MAX)
        return -1;
    if (e == NULL) {
        for (i = 0; i < STORE_MAX; i++)
            if (!s[i].used) {
                e = &s[i];
                break;
            }
        if (e == NULL)
            return -1;
        e->used = 1;
        snprintf(e->key, sizeof(e->key), "%s", key);
    }
    memcpy(e->blob, blob, len);
    e->len = len;
    return 0;
}

/* ---- group core store (the checked QSPGS "server" state) ---------------- */

#define MAX_GROUPS 2

struct group_state {
    int have;
    uint8_t gid[QSG_GID_LEN];
    uint8_t hdr[QSG_OBJ_MAX];
    size_t hlen;
    uint8_t ml[QSG_OBJ_MAX];
    size_t mlen;
    uint8_t vk[QSG_OBJ_MAX];
    size_t vlen;
    uint8_t sig[QSG_OBJ_MAX];
    size_t slen;
    /* Fetch token, stored as a SEPARATE server record (SEC-v1.5.0 LOW-1): it is
     * NOT part of the served header and is never sent back to a fetcher; the
     * coordinator only compares presented tokens against it. */
    uint8_t fet[GY_QSGROUP_FET_LEN];
    uint32_t vmaj, vmin;
    /* Accumulated multi-line appendix object for this core version, grown by
     * SUBMIT_APPENDIX and served by FETCH_APPENDIX; cleared when a core write
     * advances the version (its lines were folded by Consolidate). */
    uint8_t apx[QSG_OBJ_MAX];
    size_t apxlen;
};

static struct group_state *
group_find(struct group_state *g, const uint8_t *gid)
{
    int i;

    for (i = 0; i < MAX_GROUPS; i++)
        if (g[i].have && memcmp(g[i].gid, gid, QSG_GID_LEN) == 0)
            return &g[i];
    return NULL;
}

static struct group_state *
group_slot(struct group_state *g, const uint8_t *gid)
{
    struct group_state *e = group_find(g, gid);
    int i;

    if (e != NULL)
        return e;
    for (i = 0; i < MAX_GROUPS; i++)
        if (!g[i].have)
            return &g[i];
    return NULL;
}

/* ---- invite-queue store (gid's sealed invite entries) ------------------- */

#define INVITE_MAX 8
#define INVITE_UID_MAX 64

struct invite_entry {
    int used;
    uint8_t gid[QSG_GID_LEN];
    uint8_t uid[INVITE_UID_MAX];
    size_t uidlen;
    uint8_t entry[QSG_OBJ_MAX];
    size_t len;
};

static struct invite_entry *
invite_find(struct invite_entry *iv, const uint8_t *gid, const uint8_t *uid,
            size_t uidlen)
{
    int i;

    for (i = 0; i < INVITE_MAX; i++)
        if (iv[i].used && iv[i].uidlen == uidlen &&
            memcmp(iv[i].gid, gid, QSG_GID_LEN) == 0 &&
            memcmp(iv[i].uid, uid, uidlen) == 0)
            return &iv[i];
    return NULL;
}

static uint32_t
rd_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t
rd_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

/* ---- per-member mailbox ------------------------------------------------- */

struct mbox_item {
    uint8_t data[MBOX_ITEM_MAX];
    size_t len;
    char from[DEMO_NAME_MAX];
    int is_bundle; /* 1 = a published bundle, 0 = a relayed message */
};

struct member_mbox {
    struct mbox_item item[MBOX_ITEMS];
    int count;
    int pending;                    /* PEND_* */
    char fetch_from[DEMO_NAME_MAX]; /* awaited bundle publisher (PEND_FETCH) */
    int done;
};

/* Map a logical member name "mK" (1-based) to its 0-based index, or -1. */
static int
name_index(const char *name, int n)
{
    int k;

    if (name[0] != 'm')
        return -1;
    k = atoi(name + 1);
    if (k < 1 || k > n)
        return -1;
    return k - 1;
}

/* Enqueue an item at the tail of member t's mailbox; returns 0 or -1 if full. */
static int
mbox_push(struct member_mbox *m, const char *from, const uint8_t *data,
          size_t len, int is_bundle)
{
    struct mbox_item *it;

    if (m->count >= MBOX_ITEMS || len > MBOX_ITEM_MAX)
        return -1;
    it = &m->item[m->count++];
    it->len = len;
    it->is_bundle = is_bundle;
    memcpy(it->data, data, len);
    snprintf(it->from, sizeof(it->from), "%s", from);
    return 0;
}

/*
 * Pop the first matching item (a bundle from `from` when want_bundle, else the
 * first relayed message), removing it and preserving FIFO order of the rest.
 * The returned pointer is valid until the next mbox_pop; the caller delivers it
 * immediately.  Returns NULL when nothing matches.
 */
static struct mbox_item *
mbox_pop(struct member_mbox *m, int want_bundle, const char *from)
{
    static struct mbox_item popped;
    int k, j;

    for (k = 0; k < m->count; k++) {
        struct mbox_item *it = &m->item[k];
        int match = want_bundle ? (it->is_bundle && strcmp(it->from, from) == 0)
                                : (!it->is_bundle);

        if (!match)
            continue;
        popped = *it;
        for (j = k; j < m->count - 1; j++)
            m->item[j] = m->item[j + 1];
        m->count--;
        return &popped;
    }
    return NULL;
}

/* ---- framed replies ----------------------------------------------------- */

static int
reply(int wfd, enum qsg_msg_type type, const uint8_t *data, size_t len)
{
    struct demo_frame_header h;

    memset(&h, 0, sizeof(h));
    h.type = (uint32_t)type;
    h.data_len = (uint32_t)len;
    snprintf(h.from, sizeof(h.from), "%s", "coord");
    return demo_send_frame(wfd, &h, data) == DEMO_IPC_OK ? 0 : -1;
}

static int
deliver_item(int wfd, const struct mbox_item *it)
{
    struct demo_frame_header h;

    memset(&h, 0, sizeof(h));
    h.type = (uint32_t)(it->is_bundle ? QSG_MSG_BUNDLE : QSG_MSG_DELIVER);
    h.data_len = (uint32_t)it->len;
    snprintf(h.from, sizeof(h.from), "%s", it->from);
    return demo_send_frame(wfd, &h, it->data) == DEMO_IPC_OK ? 0 : -1;
}

/* ---- server RPC handlers ------------------------------------------------ */

/* Build a store key: kind byte || raw UID.  Demo UIDs carry no NUL, so a plain
 * C-string key is safe. */
static void
make_key(char *key, char kind, const uint8_t *uid, size_t ul)
{
    key[0] = kind;
    memcpy(key + 1, uid, ul);
    key[1 + ul] = '\0';
}

/* REGISTER / PUBLISH_ID: payload uid_len(1) || uid || blob -> store under kind. */
static void
srv_kv_put(struct kv *store, char kind, const uint8_t *p, size_t len, int wfd)
{
    char key[STORE_KEY_MAX];
    size_t ul;

    if (len < 1)
        goto fail;
    ul = p[0];
    if (ul == 0 || ul + 2 >= STORE_KEY_MAX || 1 + ul > len)
        goto fail;
    make_key(key, kind, p + 1, ul);
    if (kv_put(store, key, p + 1 + ul, len - 1 - ul) != 0)
        goto fail;
    (void)reply(wfd, QSG_MSG_SRV_REPLY, NULL, 0);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/* FETCH_ACCT / FETCH_ID: payload uid_len(1) || uid -> the stored blob (or
 * empty). */
static void
srv_kv_get(struct kv *store, char kind, const uint8_t *p, size_t len, int wfd)
{
    char key[STORE_KEY_MAX];
    struct kv *e;
    size_t ul;

    if (len < 1)
        goto fail;
    ul = p[0];
    if (ul == 0 || ul + 2 >= STORE_KEY_MAX || 1 + ul != len)
        goto fail;
    make_key(key, kind, p + 1, ul);
    e = kv_find(store, key);
    (void)reply(wfd, QSG_MSG_SRV_REPLY, e ? e->blob : NULL, e ? e->len : 0);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/* Read one length(4)-prefixed object from p at *off; advance *off.  0 or -1. */
static int
take_obj(const uint8_t *p, size_t len, size_t *off, const uint8_t **ptr,
         size_t *objlen)
{
    if (*off + 4 > len)
        return -1;
    *objlen = rd_be32(p + *off);
    *off += 4;
    if (*objlen > QSG_OBJ_MAX || *off + *objlen > len)
        return -1;
    *ptr = p + *off;
    *off += *objlen;
    return 0;
}

/* Append one length(4)-prefixed object to out at *off. */
static void
append_obj(uint8_t *out, size_t *off, const uint8_t *obj, size_t objlen)
{
    out[*off] = (uint8_t)(objlen >> 24);
    out[*off + 1] = (uint8_t)(objlen >> 16);
    out[*off + 2] = (uint8_t)(objlen >> 8);
    out[*off + 3] = (uint8_t)objlen;
    *off += 4;
    memcpy(out + *off, obj, objlen);
    *off += objlen;
}

/*
 * SUBMIT_CORE: the checked write path.  Parse the versions, the submitter's
 * vkr, and the four core objects, then run version_check (against the stored
 * head, if any) and core_check before storing.  Either check failing is
 * SRV_FAIL - the server bounds who may write.
 */
static void
srv_submit_core(struct group_state *groups, uint8_t suite, const uint8_t *p,
                size_t len, int wfd)
{
    struct group_state *g;
    const uint8_t *gid, *vkr, *hdr, *ml, *vk, *sig, *fet;
    const uint8_t *phdr = NULL, *pml = NULL, *pvk = NULL;
    size_t off, vkrlen, hlen, mlen, vlen, slen;
    size_t phlen = 0, pmlen = 0, pvlen = 0;
    uint32_t nvmaj, nvmin, evmaj, evmin;
    uint8_t op_kind;

    if (len < QSG_GID_LEN + 16 + 1 + 2)
        goto fail;
    gid = p;
    off = QSG_GID_LEN;
    nvmaj = rd_be32(p + off);
    off += 4;
    nvmin = rd_be32(p + off);
    off += 4;
    evmaj = rd_be32(p + off);
    off += 4;
    evmin = rd_be32(p + off);
    off += 4;
    op_kind = p[off];
    off += 1;
    vkrlen = rd_be16(p + off);
    off += 2;
    if (vkrlen == 0 || vkrlen > QSG_VKR_MAX || off + vkrlen > len)
        goto fail;
    vkr = p + off;
    off += vkrlen;
    if (take_obj(p, len, &off, &hdr, &hlen) ||
        take_obj(p, len, &off, &ml, &mlen) ||
        take_obj(p, len, &off, &vk, &vlen) ||
        take_obj(p, len, &off, &sig, &slen))
        goto fail;
    /* SEC-v1.5.0 LOW-1: the fetch token rides after the four signed objects as
     * a separate record; the coordinator stores it but never serves it back. */
    if (off + GY_QSGROUP_FET_LEN > len)
        goto fail;
    fet = p + off;
    off += GY_QSGROUP_FET_LEN;

    g = group_slot(groups, gid);
    if (g == NULL)
        goto fail;
    if (g->have && gy_qsgroups_server_version_check(
                       g->vmaj, g->vmin, evmaj, evmin, nvmaj, nvmin) != GY_OK)
        goto fail;
    /* The stored prior version (if any) is the lineage the check reads admn
     * and the prior vk-lst from; a first write (Create) has none. */
    if (g->have) {
        phdr = g->hdr;
        phlen = g->hlen;
        pml = g->ml;
        pmlen = g->mlen;
        pvk = g->vk;
        pvlen = g->vlen;
    }
    if (gy_qsgroups_server_core_check(suite, op_kind, phdr, phlen, pml, pmlen,
                                      pvk, pvlen, hdr, hlen, ml, mlen, vk, vlen,
                                      sig, slen, vkr, vkrlen) != GY_OK)
        goto fail;

    memcpy(g->gid, gid, QSG_GID_LEN);
    memcpy(g->hdr, hdr, hlen);
    g->hlen = hlen;
    memcpy(g->ml, ml, mlen);
    g->mlen = mlen;
    memcpy(g->vk, vk, vlen);
    g->vlen = vlen;
    memcpy(g->sig, sig, slen);
    g->slen = slen;
    memcpy(g->fet, fet, GY_QSGROUP_FET_LEN);
    g->vmaj = nvmaj;
    g->vmin = nvmin;
    g->have = 1;
    g->apxlen = 0; /* the appendix folds into the new core version. */
    (void)reply(wfd, QSG_MSG_SRV_REPLY, NULL, 0);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/*
 * SUBMIT_APPENDIX: payload gid(16) || newcomer(1) || vkr_len(2)||vkr ||
 * obj_len(4)||single-line-appendix-object.  Run apx_check (against the stored
 * vk-lst for an existing author, or as a newcomer for a JOIN / UserAdd line),
 * then append the line to the group's accumulated appendix.  The single-line
 * object is GID(16) || vMaj(4) || vMin(4) || count(2) || one line; a merge keeps
 * that 26-byte header and concatenates the line bytes, bumping the count.
 */
static void
srv_submit_appendix(struct group_state *groups, uint8_t suite, const uint8_t *p,
                    size_t len, int wfd)
{
    struct group_state *g;
    const uint8_t *vkr, *obj;
    uint8_t merged[QSG_OBJ_MAX];
    size_t off, vkrlen, objlen, merged_len;
    uint8_t newcomer;

    if (len < QSG_GID_LEN + 1 + 2)
        goto fail;
    g = group_find(groups, p);
    if (g == NULL || !g->have)
        goto fail;
    off = QSG_GID_LEN;
    off++; /* skip the submitter's newcomer byte: it is never trusted. */
    vkrlen = rd_be16(p + off);
    off += 2;
    if (vkrlen == 0 || vkrlen > QSG_VKR_MAX || off + vkrlen > len)
        goto fail;
    vkr = p + off;
    off += vkrlen;
    if (take_obj(p, len, &off, &obj, &objlen))
        goto fail;

    /* Derive newcomer from the decoded line type, not the submitter (SEC-v1.5.0
     * LOW-3): only a JOIN is authored under a key not yet in the vk-lst.  The
     * library also rejects a flag that disagrees with the line, but the server
     * must not hand it the submitter's claim in the first place. */
    if (objlen < QSG_APX_HDR_LEN + 1)
        goto fail;
    newcomer = (obj[QSG_APX_HDR_LEN] == QSG_APX_JOIN) ? 1 : 0;

    if (gy_qsgroups_server_apx_check(suite, newcomer ? NULL : g->vk,
                                     newcomer ? 0 : g->vlen, obj, objlen, 0,
                                     vkr, vkrlen, newcomer ? 1 : 0) != GY_OK)
        goto fail;

    /* Append the accepted line to the accumulated appendix through the public
     * assembly helper, so the coordinator never parses the object layout. */
    merged_len = sizeof(merged);
    if (gy_qsgroups_server_appendix_append(suite, g->apxlen ? g->apx : NULL,
                                           g->apxlen, obj, objlen, merged,
                                           &merged_len) != GY_OK ||
        merged_len > sizeof(g->apx))
        goto fail;
    memcpy(g->apx, merged, merged_len);
    g->apxlen = merged_len;
    (void)reply(wfd, QSG_MSG_SRV_REPLY, NULL, 0);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/* FETCH_APPENDIX: payload gid(16) -> the accumulated appendix object (empty
 * when the group has no pending lines). */
static void
srv_fetch_appendix(struct group_state *groups, const uint8_t *p, size_t len,
                   int wfd)
{
    struct group_state *g;

    if (len != QSG_GID_LEN)
        goto fail;
    g = group_find(groups, p);
    if (g == NULL || !g->have)
        goto fail;
    (void)reply(wfd, QSG_MSG_SRV_REPLY, g->apxlen ? g->apx : NULL, g->apxlen);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/*
 * FETCH_CORE: payload gid(16) || token.  Run fetch_check on the presented
 * bearer token, then serve the four core objects (each length-prefixed).
 */
static void
srv_fetch_core(struct group_state *groups, uint8_t suite, const uint8_t *p,
               size_t len, int wfd)
{
    struct group_state *g;
    uint8_t out[DEMO_MAX_PAYLOAD];
    size_t off = 0;

    if (len != QSG_GID_LEN + GY_QSGROUP_FET_LEN)
        goto fail;
    g = group_find(groups, p);
    if (g == NULL || !g->have)
        goto fail;
    if (gy_qsgroups_server_fetch_check(suite, g->fet, p + QSG_GID_LEN) != GY_OK)
        goto fail;
    append_obj(out, &off, g->hdr, g->hlen);
    append_obj(out, &off, g->ml, g->mlen);
    append_obj(out, &off, g->vk, g->vlen);
    append_obj(out, &off, g->sig, g->slen);
    (void)reply(wfd, QSG_MSG_SRV_REPLY, out, off);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/*
 * DEPOSIT_INVITE: payload gid(16) || uid_len(1)||uid || entry.  Store the
 * sealed invite entry under (gid, uid); the coordinator never opens it.
 */
static void
srv_deposit_invite(struct invite_entry *iv, const uint8_t *p, size_t len,
                   int wfd)
{
    struct invite_entry *e;
    const uint8_t *uid, *entry;
    size_t off, uidlen, elen;
    int i;

    if (len < QSG_GID_LEN + 1)
        goto fail;
    off = QSG_GID_LEN;
    uidlen = p[off++];
    if (uidlen == 0 || uidlen > INVITE_UID_MAX || off + uidlen > len)
        goto fail;
    uid = p + off;
    off += uidlen;
    entry = p + off;
    elen = len - off;
    if (elen > QSG_OBJ_MAX)
        goto fail;

    e = invite_find(iv, p, uid, uidlen);
    if (e == NULL) {
        for (i = 0; i < INVITE_MAX; i++)
            if (!iv[i].used) {
                e = &iv[i];
                break;
            }
        if (e == NULL)
            goto fail;
        e->used = 1;
        memcpy(e->gid, p, QSG_GID_LEN);
        memcpy(e->uid, uid, uidlen);
        e->uidlen = uidlen;
    }
    memcpy(e->entry, entry, elen);
    e->len = elen;
    (void)reply(wfd, QSG_MSG_SRV_REPLY, NULL, 0);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

/* FETCH_INVITE: payload gid(16) || uid_len(1)||uid -> the queued entry. */
static void
srv_fetch_invite(struct invite_entry *iv, const uint8_t *p, size_t len, int wfd)
{
    struct invite_entry *e;
    size_t off, uidlen;

    if (len < QSG_GID_LEN + 1)
        goto fail;
    off = QSG_GID_LEN;
    uidlen = p[off++];
    if (uidlen == 0 || uidlen > INVITE_UID_MAX || off + uidlen != len)
        goto fail;
    e = invite_find(iv, p, p + off, uidlen);
    if (e == NULL)
        goto fail;
    (void)reply(wfd, QSG_MSG_SRV_REPLY, e->entry, e->len);
    return;
fail:
    (void)reply(wfd, QSG_MSG_SRV_FAIL, NULL, 0);
}

int
qsgroup_coordinator_run(const int *rfd, const int *wfd, int n, uint8_t suite,
                        const char *base)
{
    struct kv *store;
    struct member_mbox *mbox;
    struct group_state *groups;
    struct invite_entry *invites;
    struct pollfd pfd[QSG_NPROC];
    uint8_t buf[DEMO_MAX_PAYLOAD];
    int i, barrier_count = 0, live = n, rc = 0;

    (void)base;
    store = calloc(STORE_MAX, sizeof(*store));
    mbox = calloc(n, sizeof(*mbox));
    groups = calloc(MAX_GROUPS, sizeof(*groups));
    invites = calloc(INVITE_MAX, sizeof(*invites));
    if (store == NULL || mbox == NULL || groups == NULL || invites == NULL) {
        free(store);
        free(mbox);
        free(groups);
        free(invites);
        return 1;
    }

    while (live > 0) {
        int ready;

        for (i = 0; i < n; i++) {
            pfd[i].fd = mbox[i].done ? -1 : rfd[i];
            pfd[i].events = POLLIN;
            pfd[i].revents = 0;
        }
        ready = poll(pfd, (nfds_t)n, QSG_POLL_TIMEOUT_MS);
        if (ready <= 0) {
            fprintf(stderr, "qsgroup-coord: poll timeout/error\n");
            rc = 1;
            break;
        }

        for (i = 0; i < n; i++) {
            struct demo_frame_header h;
            int r;

            /* POLLHUP/POLLERR (a member exited) can arrive without POLLIN; read
             * anyway so the EOF branch retires the fd, else poll would spin. */
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;
            r = demo_recv_frame(rfd[i], &h, buf, sizeof(buf));
            if (r == DEMO_IPC_EOF) {
                mbox[i].done = 1;
                live--;
                continue;
            }
            if (r != DEMO_IPC_OK) {
                rc = 1;
                live = 0;
                break;
            }

            switch ((enum qsg_msg_type)h.type) {
            case QSG_MSG_BARRIER:
                mbox[i].pending = PEND_BARRIER;
                if (++barrier_count == n) {
                    int k;
                    for (k = 0; k < n; k++) {
                        mbox[k].pending = PEND_NONE;
                        (void)reply(wfd[k], QSG_MSG_SRV_REPLY, NULL, 0);
                    }
                    barrier_count = 0;
                }
                break;

            case QSG_MSG_GOODBYE:
                mbox[i].done = 1;
                live--;
                break;

            case QSG_MSG_SRV_REGISTER:
                srv_kv_put(store, 'a', buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_FETCH_ACCT:
                srv_kv_get(store, 'a', buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_PUBLISH_ID:
                srv_kv_put(store, 'i', buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_FETCH_ID:
                srv_kv_get(store, 'i', buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_SUBMIT_CORE:
                srv_submit_core(groups, suite, buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_FETCH_CORE:
                srv_fetch_core(groups, suite, buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_DEPOSIT_INVITE:
                srv_deposit_invite(invites, buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_FETCH_INVITE:
                srv_fetch_invite(invites, buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_SUBMIT_APPENDIX:
                srv_submit_appendix(groups, suite, buf, h.data_len, wfd[i]);
                break;
            case QSG_MSG_SRV_FETCH_APPENDIX:
                srv_fetch_appendix(groups, buf, h.data_len, wfd[i]);
                break;

            case QSG_MSG_PUBLISH_BUNDLE:
            case QSG_MSG_RELAY: {
                int t = name_index(h.to, n);
                int is_bundle = (h.type == (uint32_t)QSG_MSG_PUBLISH_BUNDLE);

                if (t < 0 || mbox_push(&mbox[t], h.from, buf, h.data_len,
                                       is_bundle) != 0) {
                    (void)reply(wfd[i], QSG_MSG_SRV_FAIL, NULL, 0);
                    break;
                }
                (void)reply(wfd[i], QSG_MSG_SRV_REPLY, NULL, 0);
                /* Serve the recipient's matching pending request, if any. */
                if (is_bundle && mbox[t].pending == PEND_FETCH &&
                    strcmp(mbox[t].fetch_from, h.from) == 0) {
                    struct mbox_item *it =
                        mbox_pop(&mbox[t], 1, mbox[t].fetch_from);
                    if (it != NULL) {
                        (void)deliver_item(wfd[t], it);
                        mbox[t].pending = PEND_NONE;
                    }
                } else if (!is_bundle && mbox[t].pending == PEND_RECV) {
                    struct mbox_item *it = mbox_pop(&mbox[t], 0, NULL);
                    if (it != NULL) {
                        (void)deliver_item(wfd[t], it);
                        mbox[t].pending = PEND_NONE;
                    }
                }
                break;
            }

            case QSG_MSG_FETCH_BUNDLE: {
                struct mbox_item *it = mbox_pop(&mbox[i], 1, h.to);

                if (it != NULL) {
                    (void)deliver_item(wfd[i], it);
                } else {
                    mbox[i].pending = PEND_FETCH;
                    snprintf(mbox[i].fetch_from, sizeof(mbox[i].fetch_from),
                             "%s", h.to);
                }
                break;
            }

            case QSG_MSG_RECV: {
                struct mbox_item *it = mbox_pop(&mbox[i], 0, NULL);

                if (it != NULL)
                    (void)deliver_item(wfd[i], it);
                else
                    mbox[i].pending = PEND_RECV;
                break;
            }

            default:
                (void)reply(wfd[i], QSG_MSG_SRV_FAIL, NULL, 0);
                break;
            }
        }
    }

    free(store);
    free(mbox);
    free(groups);
    free(invites);
    return rc;
}
