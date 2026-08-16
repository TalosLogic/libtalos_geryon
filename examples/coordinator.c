/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <stdio.h>
#include <string.h>

#include "geryon.h"

#include "coordinator.h"
#include "demo_ipc.h"
#include "demo_proto.h"

/* Per-client directory storage bounds (all opaque public bytes). */
#define COORD_REG_MAX 1024
#define COORD_BATCH_MAX 8192
#define COORD_BUNDLE_MAX 1024
#define COORD_MAX_CONSUMED 128

/* Mailbox bounds and the seeded out-of-order delivery schedule. */
#define COORD_MAILBOX_MAX 8
#define COORD_MSG_MAX 2048

/* Published SAK certificate. */
#define COORD_CERT_MAX 512

/* Published self-fingerprint; GY_FINGERPRINT_MAX bounds it. */
#define COORD_FP_MAX 64
/*
 * Reorder seed: bit i set means "at delivery cursor i, hand out message
 * seq i+1 before seq i" (a single adjacent swap that makes a later message
 * arrive first, so the recipient skips then fills from its skip store).  Bit
 * 3 set swaps the fourth/fifth messages; every other cursor is in order.  The
 * schedule is keyed on the per-sender seq, so it is independent of how the two
 * client processes happen to interleave (fully deterministic).
 */
#define COORD_REORDER_SEED 0x08u

/* One queued ciphertext awaiting delivery (opaque to the coordinator). */
struct coord_mail {
    uint8_t buf[COORD_MSG_MAX];
    size_t len;
    uint32_t seq;
    char from[DEMO_NAME_MAX];
};

/*
 * One connected client, from the coordinator's point of view: the two pipe
 * ends it talks over, the opaque public objects it published (its directory
 * entry), and any parked fetch it is waiting on.  No private key material
 * appears here by construction: the coordinator holds no custodian.
 */
struct coord_client {
    int rfd; /* read: client -> coordinator */
    int wfd; /* write: coordinator -> client */
    char name[DEMO_NAME_MAX];
    int gone; /* set once the client departs */

    int has_reg; /* published IK+SPK registration */
    uint8_t reg[COORD_REG_MAX];
    size_t reg_len;
    int has_batch; /* published OPK public batch */
    uint8_t batch[COORD_BATCH_MAX];
    size_t batch_len;
    uint32_t consumed[COORD_MAX_CONSUMED]; /* OPK PKIDs handed out */
    size_t n_consumed;

    int has_pending; /* a fetch parked until the target publishes */
    char pending_target[DEMO_NAME_MAX];

    int has_cert; /* published SAK certificate */
    uint8_t cert[COORD_CERT_MAX];
    size_t cert_len;

    int has_prior_cert; /* retained prior SAK cert after rotation */
    uint8_t prior_cert[COORD_CERT_MAX];
    size_t prior_cert_len;

    int has_fp; /* published self-fingerprint */
    uint8_t fp[COORD_FP_MAX];
    size_t fp_len;

    int has_oneshot; /* published one-shot full bundle */
    uint8_t oneshot[COORD_BUNDLE_MAX];
    size_t oneshot_len;

    int has_noopk_reg; /* registration for the no-OPK fetch */
    uint8_t noopk_reg[COORD_REG_MAX];
    size_t noopk_reg_len;

    uint32_t pending_type; /* the parked fetch's request type (0 if none) */

    struct coord_mail mailbox[COORD_MAILBOX_MAX]; /* messages for THIS client */
    size_t mail_count;
    uint32_t deliver_base; /* lowest seq not yet handed out (reorder cursor) */
    int deliver_phase;     /* 1 while mid-swap at deliver_base */
    int recv_parked;       /* a RECV waiting for its scheduled message */
    int reorder;           /* apply the seeded reorder to THIS mailbox */
};

/* The coordinator is a singleton in the parent; its state persists across a
 * client restart. */
static struct coord_client g_clients[2];

static struct coord_client *
find_client(struct coord_client *cs, const char *name)
{
    int i;

    for (i = 0; i < 2; i++)
        if (strcmp(cs[i].name, name) == 0)
            return &cs[i];
    return NULL;
}

/* Reply to c with an empty-payload frame of the given type. */
static int
reply_empty(struct coord_client *c, enum demo_msg_type type)
{
    struct demo_frame_header out;

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)type;
    out.data_len = 0;
    snprintf(out.from, sizeof(out.from), "coordinator");
    snprintf(out.to, sizeof(out.to), "%s", c->name);
    return demo_send_frame(c->wfd, &out, NULL);
}

static uint32_t
be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int
is_consumed(const struct coord_client *t, uint32_t pkid)
{
    size_t i;

    for (i = 0; i < t->n_consumed; i++)
        if (t->consumed[i] == pkid)
            return 1;
    return 0;
}

/*
 * Pick the next unused OPK from target t's published batch, marking it
 * consumed by PKID.  Sets opk and opk_len to a zero-copy slice (valid while
 * t->batch lives), or to NULL/0 if t has no batch or the pool is exhausted
 * (a bundle with no OPK is still valid).  Returns 0, or -1 on a malformed
 * batch.
 */
static int
pick_opk(struct coord_client *t, const uint8_t **opk, size_t *opk_len)
{
    size_t count, i;

    *opk = NULL;
    *opk_len = 0;
    if (!t->has_batch)
        return 0;
    if (gy_opk_batch_count(t->batch, t->batch_len, &count) != GY_OK)
        return -1;

    for (i = 0; i < count; i++) {
        const uint8_t *slice;
        size_t slen;
        uint32_t pkid;

        if (gy_opk_batch_get(t->batch, t->batch_len, i, &slice, &slen) != GY_OK)
            return -1;
        pkid = be32(slice);
        if (is_consumed(t, pkid))
            continue;
        if (t->n_consumed < COORD_MAX_CONSUMED)
            t->consumed[t->n_consumed++] = pkid;
        *opk = slice;
        *opk_len = slen;
        printf("[coordinator] issuing %s's OPK pkid=%08x\n", t->name, pkid);
        return 0;
    }
    printf("[coordinator] %s OPK pool exhausted; bundle without OPK\n",
           t->name);
    return 0;
}

/*
 * Assemble target's registration plus one unused OPK into a fetch bundle and
 * send it to the requester.  Returns 0 on success, -1 on an assembly or IPC
 * error.
 */
static int
answer_fetch(struct coord_client *req, struct coord_client *target)
{
    struct demo_frame_header out;
    uint8_t bundle[COORD_BUNDLE_MAX];
    const uint8_t *opk;
    size_t opk_len, blen;

    if (pick_opk(target, &opk, &opk_len) != 0)
        return -1;

    blen = sizeof(bundle);
    if (gy_bundle_assemble(target->reg, target->reg_len, opk, opk_len, bundle,
                           &blen) != GY_OK)
        return -1;

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)DEMO_MSG_BUNDLE;
    out.data_len = (uint32_t)blen;
    snprintf(out.from, sizeof(out.from), "%.*s", (int)sizeof(out.from) - 1,
             target->name);
    snprintf(out.to, sizeof(out.to), "%.*s", (int)sizeof(out.to) - 1,
             req->name);
    printf("[coordinator] delivering %s's bundle to %s (%zu bytes)\n",
           target->name, req->name, blen);
    return demo_send_frame(req->wfd, &out, bundle) == DEMO_IPC_OK ? 0 : -1;
}

/* A directory entry is fetchable once both its registration and OPK batch
 * are present (the demo always publishes both). */
static int
target_ready(const struct coord_client *t)
{
    return t->has_reg && t->has_batch;
}

/* An identity entry is fetchable once its registration and self-fingerprint
 * are both published. */
static int
identity_ready(const struct coord_client *t)
{
    return t->has_reg && t->has_fp;
}

/*
 * Answer req's identity fetch for target: reply with fp_len_be16 || fp ||
 * registration, the public material req needs to derive target's fingerprint
 * locally (gy_bundle_fingerprint) and compare it against target's own.  The
 * registration is served as-is (no OPK is consumed, unlike a bundle fetch).
 * Returns 0, or -1 on an IPC error.
 */
static int
answer_identity(struct coord_client *req, struct coord_client *target)
{
    struct demo_frame_header out;
    uint8_t buf[2 + COORD_FP_MAX + COORD_REG_MAX];
    size_t len;

    buf[0] = (uint8_t)(target->fp_len >> 8);
    buf[1] = (uint8_t)(target->fp_len & 0xFFu);
    memcpy(buf + 2, target->fp, target->fp_len);
    memcpy(buf + 2 + target->fp_len, target->reg, target->reg_len);
    len = 2 + target->fp_len + target->reg_len;

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)DEMO_MSG_IDENTITY;
    out.data_len = (uint32_t)len;
    snprintf(out.from, sizeof(out.from), "%.*s", (int)sizeof(out.from) - 1,
             target->name);
    snprintf(out.to, sizeof(out.to), "%.*s", (int)sizeof(out.to) - 1,
             req->name);
    printf("[coordinator] delivering %s's identity to %s (fp %zu + reg %zu "
           "bytes)\n",
           target->name, req->name, target->fp_len, target->reg_len);
    return demo_send_frame(req->wfd, &out, buf) == DEMO_IPC_OK ? 0 : -1;
}

/* A one-shot entry is fetchable once its full bundle has been published. */
static int
oneshot_ready(const struct coord_client *t)
{
    return t->has_oneshot;
}

/*
 * Answer req's one-shot fetch for target: relay target's published full bundle
 * (a complete gy_publish_bundle output) verbatim, with no assembly and no OPK
 * bookkeeping (the OPK was reserved by the publisher, not by the relay).
 * Returns 0, or -1 on an IPC error.
 */
static int
answer_oneshot(struct coord_client *req, struct coord_client *target)
{
    struct demo_frame_header out;

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)DEMO_MSG_ONESHOT;
    out.data_len = (uint32_t)target->oneshot_len;
    snprintf(out.from, sizeof(out.from), "%.*s", (int)sizeof(out.from) - 1,
             target->name);
    snprintf(out.to, sizeof(out.to), "%.*s", (int)sizeof(out.to) - 1,
             req->name);
    printf("[coordinator] relaying %s's one-shot bundle to %s (%zu bytes, "
           "no assembly)\n",
           target->name, req->name, target->oneshot_len);
    return demo_send_frame(req->wfd, &out, target->oneshot) == DEMO_IPC_OK ? 0
                                                                           : -1;
}

/* A no-OPK entry is fetchable once its registration has been published. */
static int
noopk_ready(const struct coord_client *t)
{
    return t->has_noopk_reg;
}

/*
 * Answer req's no-OPK fetch for target: assemble target's registration into a
 * bundle with NO one-time prekey (gy_bundle_assemble with opk_pub == NULL) and
 * send it.  The peer will initiate a valid X3DH session without an OPK (reduced
 * forward secrecy).  Reuses DEMO_MSG_BUNDLE.  Returns 0, or -1 on error.
 */
static int
answer_noopk(struct coord_client *req, struct coord_client *target)
{
    struct demo_frame_header out;
    uint8_t bundle[COORD_BUNDLE_MAX];
    size_t blen = sizeof(bundle);

    if (gy_bundle_assemble(target->noopk_reg, target->noopk_reg_len, NULL, 0,
                           bundle, &blen) != GY_OK)
        return -1;

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)DEMO_MSG_BUNDLE;
    out.data_len = (uint32_t)blen;
    snprintf(out.from, sizeof(out.from), "%.*s", (int)sizeof(out.from) - 1,
             target->name);
    snprintf(out.to, sizeof(out.to), "%.*s", (int)sizeof(out.to) - 1,
             req->name);
    printf("[coordinator] assembling %s's no-OPK bundle for %s (%zu bytes, "
           "opk_pub == NULL)\n",
           target->name, req->name, blen);
    return demo_send_frame(req->wfd, &out, bundle) == DEMO_IPC_OK ? 0 : -1;
}

/*
 * After any publish, answer any parked fetch whose target is now ready.  The
 * parked request's type selects what "ready" means and how it is answered.
 * Returns 0, or -1 on an error while answering.
 */
static int
service_pending(struct coord_client *cs)
{
    int i;

    for (i = 0; i < 2; i++) {
        struct coord_client *req = &cs[i];
        struct coord_client *target;

        if (!req->has_pending)
            continue;
        target = find_client(cs, req->pending_target);
        if (target == NULL)
            continue;
        if (req->pending_type == DEMO_MSG_FETCH_IDENTITY) {
            if (!identity_ready(target))
                continue;
            req->has_pending = 0;
            if (answer_identity(req, target) != 0)
                return -1;
        } else if (req->pending_type == DEMO_MSG_FETCH_ONESHOT) {
            if (!oneshot_ready(target))
                continue;
            req->has_pending = 0;
            if (answer_oneshot(req, target) != 0)
                return -1;
        } else if (req->pending_type == DEMO_MSG_FETCH_NOOPK) {
            if (!noopk_ready(target))
                continue;
            req->has_pending = 0;
            if (answer_noopk(req, target) != 0)
                return -1;
        } else {
            if (!target_ready(target))
                continue;
            req->has_pending = 0;
            if (answer_fetch(req, target) != 0)
                return -1;
        }
    }
    return 0;
}

/*
 * Seeded swap bit for c's delivery cursor base (see COORD_REORDER_SEED).  Only
 * mailboxes flagged for reorder are permuted; every other stream is strict
 * FIFO, so unrelated request/response traffic (e.g. lifecycle acks) is never
 * reordered into a circular wait.
 */
static int
swap_at(const struct coord_client *c, uint32_t base)
{
    if (!c->reorder)
        return 0;
    return (COORD_REORDER_SEED >> (base & 31)) & 1u;
}

/* The seq the next RECV from c should be handed, without advancing state. */
static uint32_t
peek_want(const struct coord_client *c)
{
    if (swap_at(c, c->deliver_base))
        return c->deliver_phase == 0 ? c->deliver_base + 1 : c->deliver_base;
    return c->deliver_base;
}

/* Advance the reorder cursor past the seq just delivered. */
static void
advance_cursor(struct coord_client *c)
{
    if (swap_at(c, c->deliver_base)) {
        if (c->deliver_phase == 0)
            c->deliver_phase = 1; /* delivered base+1; base still owed */
        else {
            c->deliver_base += 2;
            c->deliver_phase = 0;
        }
    } else {
        c->deliver_base += 1;
    }
}

/* Index of the mailbox entry with the given seq, or -1. */
static int
mail_index(const struct coord_client *c, uint32_t seq)
{
    size_t i;

    for (i = 0; i < c->mail_count; i++)
        if (c->mailbox[i].seq == seq)
            return (int)i;
    return -1;
}

/*
 * If c's next message is ready, deliver it and advance.  A reordered mailbox
 * follows the seeded seq schedule (parking until the scheduled seq arrives); a
 * plain mailbox delivers FIFO, ignoring seq, so a peer that resumed in a fresh
 * process (with a reset seq counter) still reaches this client.
 * Returns 1 if delivered, 0 if waiting on an unarrived scheduled seq, -1 on an
 * IPC error.
 */
static int
deliver_next(struct coord_client *c)
{
    struct demo_frame_header out;
    struct coord_mail *m;
    size_t idx;

    if (c->mail_count == 0)
        return 0;
    if (c->reorder) {
        int i = mail_index(c, peek_want(c));

        if (i < 0)
            return 0; /* the scheduled seq has not arrived yet */
        idx = (size_t)i;
    } else {
        idx = 0; /* FIFO: the oldest queued message */
    }
    m = &c->mailbox[idx];

    memset(&out, 0, sizeof(out));
    out.type = (uint32_t)DEMO_MSG_DELIVER;
    out.data_len = (uint32_t)m->len;
    out.seq = m->seq;
    snprintf(out.from, sizeof(out.from), "%s", m->from);
    snprintf(out.to, sizeof(out.to), "%s", c->name);
    printf("[coordinator] delivering seq=%u to %s (%zu bytes)\n", m->seq,
           c->name, m->len);
    if (demo_send_frame(c->wfd, &out, m->buf) != DEMO_IPC_OK)
        return -1;

    /* Remove the delivered entry, shifting the rest down to preserve order. */
    memmove(&c->mailbox[idx], &c->mailbox[idx + 1],
            (c->mail_count - idx - 1) * sizeof(*m));
    c->mail_count--;
    if (c->reorder)
        advance_cursor(c);
    return 1;
}

/*
 * Queue one SEND for its recipient, then deliver if a RECV is parked and the
 * scheduled message is now present.  Returns 0, or -1 on an error.
 */
static int
mailbox_send(struct coord_client *cs, const struct demo_frame_header *hdr,
             const uint8_t *payload)
{
    struct coord_client *to = find_client(cs, hdr->to);
    struct coord_mail *m;

    if (to == NULL || hdr->data_len > COORD_MSG_MAX ||
        to->mail_count >= COORD_MAILBOX_MAX)
        return -1;

    m = &to->mailbox[to->mail_count++];
    memcpy(m->buf, payload, hdr->data_len);
    m->len = hdr->data_len;
    m->seq = hdr->seq;
    snprintf(m->from, sizeof(m->from), "%s", hdr->from);
    printf("[coordinator] queued seq=%u for %s (from %s, %u bytes)\n", hdr->seq,
           to->name, hdr->from, hdr->data_len);

    /* Untrusted-relay illustration: dump the first relayed
     * ciphertext so a reader can SEE the coordinator only ever handles opaque
     * bytes.  This shows the deployment shape; it is not a security proof. */
    {
        static int dumped;
        size_t i, n = hdr->data_len < 32 ? hdr->data_len : 32;

        if (!dumped) {
            dumped = 1;
            printf(
                "[coordinator] relayed ciphertext is opaque (first %zu of %u "
                "bytes):\n    ",
                n, hdr->data_len);
            for (i = 0; i < n; i++)
                printf("%02x", payload[i]);
            printf("\n[coordinator] the relay never holds a key and never "
                   "decrypts these bytes\n");
        }
    }

    if (to->recv_parked) {
        int rv = deliver_next(to);

        if (rv < 0)
            return -1;
        if (rv == 1)
            to->recv_parked = 0;
    }
    return 0;
}

/*
 * Verify a SAK-signed request from c.  The payload is
 * msg_len_be16 || msg || sig.  The coordinator holds no custodian: it pins
 * c's identity key from c's published registration (TOFU) via
 * gy_registration_identity_pub - never from the cert - and supplies its OWN
 * now for the expiry check.  Returns 1 if the signature verifies, 0 if it is
 * rejected.
 */
static int
verify_auth_request(const struct coord_client *c, const uint8_t *payload,
                    size_t len)
{
    const uint8_t *ik, *msg, *sig;
    size_t iklen, msg_len, sig_len;

    if (!c->has_reg || !c->has_cert || len < 2)
        return 0;
    msg_len = ((size_t)payload[0] << 8) | (size_t)payload[1];
    if (2 + msg_len > len)
        return 0;
    msg = payload + 2;
    sig = payload + 2 + msg_len;
    sig_len = len - 2 - msg_len;

    if (gy_registration_identity_pub(c->reg, c->reg_len, &ik, &iklen) != GY_OK)
        return 0;

    /* now = 0: this custodian-less server supplies its own clock value; the
     * demo's SAKs are minted with no expiry, so any value verifies.  A request
     * is accepted if it verifies against the ACTIVE cert or, within the
     * rotation window, the retained PRIOR cert. */
    if (gy_appkey_verify(ik, iklen, c->cert, c->cert_len,
                         (const uint8_t *)DEMO_AUTH_CTX, strlen(DEMO_AUTH_CTX),
                         msg, msg_len, sig, sig_len, 0) == GY_OK)
        return 1;
    if (c->has_prior_cert &&
        gy_appkey_verify(ik, iklen, c->prior_cert, c->prior_cert_len,
                         (const uint8_t *)DEMO_AUTH_CTX, strlen(DEMO_AUTH_CTX),
                         msg, msg_len, sig, sig_len, 0) == GY_OK)
        return 1;
    return 0;
}

/*
 * Dispatch one received frame from client c.  Returns 0 to keep serving, 1
 * once c has departed, and -1 on an error.
 */
static int
handle_frame(struct coord_client *cs, struct coord_client *c,
             const struct demo_frame_header *hdr, const uint8_t *payload)
{
    switch (hdr->type) {
    case DEMO_MSG_PING:
        return reply_empty(c, DEMO_MSG_PONG) == DEMO_IPC_OK ? 0 : -1;

    case DEMO_MSG_PUBLISH_REGISTRATION:
        if (hdr->data_len > COORD_REG_MAX)
            return -1;
        memcpy(c->reg, payload, hdr->data_len);
        c->reg_len = hdr->data_len;
        c->has_reg = 1;
        printf("[coordinator] %s published registration (%u bytes)\n", c->name,
               hdr->data_len);
        return service_pending(cs) == 0 ? 0 : -1;

    case DEMO_MSG_PUBLISH_OPK_BATCH:
        if (hdr->data_len > COORD_BATCH_MAX)
            return -1;
        memcpy(c->batch, payload, hdr->data_len);
        c->batch_len = hdr->data_len;
        c->has_batch = 1;
        /*
         * Do NOT reset n_consumed: a replenished batch ADDS one-time prekeys,
         * it does not resurrect the pkids already handed out.  PKIDs are never
         * reused (gy_opk_generate dedups against existing), so a consumed pkid
         * can never reappear as a fresh OPK and the tracking never yields a
         * false skip.  Resetting here would let a still-unused but already-
         * issued OPK (e.g. one reserved in a peer's pre-rotation bundle for a
         * later handshake) be handed out a SECOND time and consumed early,
         * breaking that reserved handshake.
         */
        printf("[coordinator] %s published OPK batch (%u bytes)\n", c->name,
               hdr->data_len);
        return service_pending(cs) == 0 ? 0 : -1;

    case DEMO_MSG_FETCH_BUNDLE: {
        struct coord_client *target = find_client(cs, hdr->to);

        if (target == NULL)
            return reply_empty(c, DEMO_MSG_ERROR) == DEMO_IPC_OK ? 0 : -1;
        if (target_ready(target))
            return answer_fetch(c, target) == 0 ? 0 : -1;
        /* Park the request until the target publishes (no deadlock: every
         * client publishes before it blocks on a fetch). */
        c->has_pending = 1;
        c->pending_type = DEMO_MSG_FETCH_BUNDLE;
        snprintf(c->pending_target, sizeof(c->pending_target), "%s", hdr->to);
        printf("[coordinator] parking %s's fetch for %s\n", c->name, hdr->to);
        return 0;
    }

    case DEMO_MSG_PUBLISH_FINGERPRINT:
        if (hdr->data_len == 0 || hdr->data_len > COORD_FP_MAX)
            return -1;
        memcpy(c->fp, payload, hdr->data_len);
        c->fp_len = hdr->data_len;
        c->has_fp = 1;
        printf("[coordinator] %s published self-fingerprint (%u bytes)\n",
               c->name, hdr->data_len);
        return service_pending(cs) == 0 ? 0 : -1;

    case DEMO_MSG_FETCH_IDENTITY: {
        struct coord_client *target = find_client(cs, hdr->to);

        if (target == NULL)
            return reply_empty(c, DEMO_MSG_ERROR) == DEMO_IPC_OK ? 0 : -1;
        if (identity_ready(target))
            return answer_identity(c, target) == 0 ? 0 : -1;
        c->has_pending = 1;
        c->pending_type = DEMO_MSG_FETCH_IDENTITY;
        snprintf(c->pending_target, sizeof(c->pending_target), "%s", hdr->to);
        printf("[coordinator] parking %s's identity fetch for %s\n", c->name,
               hdr->to);
        return 0;
    }

    case DEMO_MSG_PUBLISH_ONESHOT:
        if (hdr->data_len == 0 || hdr->data_len > COORD_BUNDLE_MAX)
            return -1;
        memcpy(c->oneshot, payload, hdr->data_len);
        c->oneshot_len = hdr->data_len;
        c->has_oneshot = 1;
        printf("[coordinator] %s published a one-shot full bundle (%u bytes)\n",
               c->name, hdr->data_len);
        return service_pending(cs) == 0 ? 0 : -1;

    case DEMO_MSG_FETCH_ONESHOT: {
        struct coord_client *target = find_client(cs, hdr->to);

        if (target == NULL)
            return reply_empty(c, DEMO_MSG_ERROR) == DEMO_IPC_OK ? 0 : -1;
        if (oneshot_ready(target))
            return answer_oneshot(c, target) == 0 ? 0 : -1;
        c->has_pending = 1;
        c->pending_type = DEMO_MSG_FETCH_ONESHOT;
        snprintf(c->pending_target, sizeof(c->pending_target), "%s", hdr->to);
        printf("[coordinator] parking %s's one-shot fetch for %s\n", c->name,
               hdr->to);
        return 0;
    }

    case DEMO_MSG_PUBLISH_NOOPK_REG:
        if (hdr->data_len == 0 || hdr->data_len > COORD_REG_MAX)
            return -1;
        memcpy(c->noopk_reg, payload, hdr->data_len);
        c->noopk_reg_len = hdr->data_len;
        c->has_noopk_reg = 1;
        printf("[coordinator] %s published a no-OPK-path registration (%u "
               "bytes)\n",
               c->name, hdr->data_len);
        return service_pending(cs) == 0 ? 0 : -1;

    case DEMO_MSG_FETCH_NOOPK: {
        struct coord_client *target = find_client(cs, hdr->to);

        if (target == NULL)
            return reply_empty(c, DEMO_MSG_ERROR) == DEMO_IPC_OK ? 0 : -1;
        if (noopk_ready(target))
            return answer_noopk(c, target) == 0 ? 0 : -1;
        c->has_pending = 1;
        c->pending_type = DEMO_MSG_FETCH_NOOPK;
        snprintf(c->pending_target, sizeof(c->pending_target), "%s", hdr->to);
        printf("[coordinator] parking %s's no-OPK fetch for %s\n", c->name,
               hdr->to);
        return 0;
    }

    case DEMO_MSG_SEND:
        /* Relay opaque ciphertext into the recipient's mailbox. */
        return mailbox_send(cs, hdr, payload) == 0 ? 0 : -1;

    case DEMO_MSG_RECV:
        /* Deliver c's next scheduled message, or park until it arrives. */
        {
            int rv = deliver_next(c);

            if (rv < 0)
                return -1;
            if (rv == 0)
                c->recv_parked = 1;
            return 0;
        }

    case DEMO_MSG_PUBLISH_CERT:
        if (hdr->data_len > COORD_CERT_MAX)
            return -1;
        memcpy(c->cert, payload, hdr->data_len);
        c->cert_len = hdr->data_len;
        c->has_cert = 1;
        printf("[coordinator] %s published SAK cert (%u bytes)\n", c->name,
               hdr->data_len);
        return 0;

    case DEMO_MSG_PUBLISH_PRIOR_CERT:
        if (hdr->data_len > COORD_CERT_MAX)
            return -1;
        memcpy(c->prior_cert, payload, hdr->data_len);
        c->prior_cert_len = hdr->data_len;
        c->has_prior_cert = 1;
        printf("[coordinator] %s published prior SAK cert (%u bytes, rotation "
               "window)\n",
               c->name, hdr->data_len);
        return 0;

    case DEMO_MSG_AUTH_REQ: {
        int ok = verify_auth_request(c, payload, hdr->data_len);

        printf("[coordinator] %s SAK request %s (identity pinned from its "
               "published IK)\n",
               c->name, ok ? "VERIFIED" : "REJECTED");
        return reply_empty(c, ok ? DEMO_MSG_AUTH_OK : DEMO_MSG_AUTH_FAIL) ==
                       DEMO_IPC_OK
                   ? 0
                   : -1;
    }

    case DEMO_MSG_RESTART:
        /* c's process is exiting and will be re-forked with fresh pipes; keep
         * all of its directory/mailbox state.  Signal the caller (return 2). */
        printf("[coordinator] %s requested restart (state preserved)\n",
               c->name);
        return 2;

    case DEMO_MSG_GOODBYE:
        printf("[coordinator] GOODBYE from %s\n", c->name);
        c->gone = 1;
        return 1;

    default:
        printf("[coordinator] unexpected frame type %u from %s\n", hdr->type,
               c->name);
        return reply_empty(c, DEMO_MSG_ERROR) == DEMO_IPC_OK ? 0 : -1;
    }
}

void
coordinator_init(int alice_rfd, int alice_wfd, int bob_rfd, int bob_wfd)
{
    memset(g_clients, 0, sizeof(g_clients));
    g_clients[0].rfd = alice_rfd;
    g_clients[0].wfd = alice_wfd;
    snprintf(g_clients[0].name, sizeof(g_clients[0].name), "alice");
    g_clients[1].rfd = bob_rfd;
    g_clients[1].wfd = bob_wfd;
    snprintf(g_clients[1].name, sizeof(g_clients[1].name), "bob");
    /* Bob is the recipient of the out-of-order d-batch; only his
     * mailbox is reordered.  Alice's stream stays strict FIFO. */
    g_clients[1].reorder = 1;

    printf("[coordinator] serving alice and bob (no custodian, no keys)\n");
    printf("[coordinator] reorder seed=0x%02x (out-of-order delivery)\n",
           COORD_REORDER_SEED);
}

void
coordinator_rewire_bob(int bob_rfd, int bob_wfd)
{
    /* Re-point at the re-forked bob's fresh pipes; every other field (mailbox,
     * directory, delivery cursor, reorder flag) is retained. */
    g_clients[1].rfd = bob_rfd;
    g_clients[1].wfd = bob_wfd;
    g_clients[1].gone = 0;
    g_clients[1].recv_parked = 0;
    printf("[coordinator] bob re-forked; resuming with preserved state\n");
}

int
coordinator_run(void)
{
    struct pollfd fds[2];
    uint8_t buf[DEMO_MAX_PAYLOAD];
    int i, live;

    for (;;) {
        live = 0;
        for (i = 0; i < 2; i++) {
            fds[i].fd = g_clients[i].gone ? -1 : g_clients[i].rfd;
            fds[i].events = POLLIN;
            fds[i].revents = 0;
            if (!g_clients[i].gone)
                live++;
        }
        if (live == 0)
            break;

        if (poll(fds, 2, -1) < 0) {
            perror("[coordinator] poll");
            return COORD_ERROR;
        }

        for (i = 0; i < 2; i++) {
            struct demo_frame_header hdr;
            int rv, hr;

            if (g_clients[i].gone)
                continue;
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
                continue;

            rv = demo_recv_frame(g_clients[i].rfd, &hdr, buf, sizeof(buf));
            if (rv == DEMO_IPC_EOF) {
                g_clients[i].gone = 1;
                continue;
            }
            if (rv != DEMO_IPC_OK) {
                fprintf(stderr, "[coordinator] IPC error from %s\n",
                        g_clients[i].name);
                return COORD_ERROR;
            }
            hr = handle_frame(g_clients, &g_clients[i], &hdr, buf);
            if (hr < 0)
                return COORD_ERROR;
            if (hr == 2)
                return COORD_RESTART_BOB; /* bob is being re-forked */
        }
    }

    printf("[coordinator] both clients departed; shutting down\n");
    return COORD_DONE;
}
