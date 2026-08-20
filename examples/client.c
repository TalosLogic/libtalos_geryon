/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geryon.h"

#include "client.h"
#include "demo_ipc.h"
#include "demo_proto.h"
#include "filestore.h"

/* Demo parameters. */
#define CLIENT_N_OPKS 4     /* one-time prekeys minted at identity creation */
#define CLIENT_REPLENISH 4  /* one-time prekeys added on replenishment */
#define CLIENT_SPK_TS2 2000 /* rotated signed-prekey timestamp */
#define CLIENT_LIFECYCLE_ROUNDS 6 /* prekey-lifecycle exchange rounds */
#define CLIENT_SPK_TS 1000        /* signed-prekey timestamp (app-chosen) */
#define CLIENT_CLOCK_BASE 2000    /* monotone clock start (D-SES-7) */
#define CLIENT_NEW_CRED "bob-secret-rotated" /* example changed credential */
/*
 * example expiration policy (D-SES-7).  A tiny max_send makes a session go
 * stale after a few sends; the section 4.2 inequality
 * max_recv > max_send + 2*max_latency must hold (10 > 3 + 2*1), and it is
 * enforced at gy_custodian_create.
 */
#define EXP_MAX_SEND 3
#define EXP_MAX_RECV 10
#define EXP_MAX_LATENCY 1
/*
 * Serialized-object upper bounds.  These are sized for the LARGER hybrid suite
 * (geryon_h25519_512): an ML-KEM-512 ek is 800 bytes, an ML-DSA-44 public key
 * 1312 and its signature 2420, so a hybrid registration/bundle/message runs to
 * several KB where the classical equivalents are a few hundred bytes.  The demo
 * uses fixed stack buffers for brevity; a real consumer sizes exactly by the
 * OpenSSL-style query convention (call with a NULL buffer to learn the length,
 * then allocate), so it never hardcodes these and is unaffected by the suite.
 */
#define CLIENT_REG_MAX 16384   /* serialized registration upper bound */
#define CLIENT_BATCH_MAX 16384 /* serialized OPK batch upper bound */
#define CLIENT_MSG_MAX 8192    /* enveloped message upper bound */
#define CLIENT_BUNDLE_MAX 8192 /* serialized bundle upper bound */
#define DEMO_FANOUT_MAX 4      /* fan-out descriptors (one peer device here) */
/*
 * Continuous ratchet round-trips for the hybrid ML-KEM-refresh illustration.
 * The library refreshes the Double Ratchet ML-KEM keypair on a fixed interval
 * (HYBRID_SPEC section 6.6; 20 DH-ratchet steps in this build).  Each round-trip
 * here is two direction changes, hence two DH-ratchet steps, so 12 round-trips
 * (24 steps) crosses at least one PERIODIC refresh boundary beyond the refresh
 * the initial handshake already forces.  The refresh is internal (the consumer
 * just keeps sending), so this illustrates the path; it asserts only that every
 * message still round-trips across the boundary. */
#define DEMO_KEM_REFRESH_ROUNDS 12
#define CLIENT_INITIATE_RETRY 2 /* bounded send-retry over the initiate path */
#define CLIENT_POLL_MS 50       /* per-attempt poll timeout (archive pattern) */
#define CLIENT_POLL_ATTEMPTS                                                   \
    200 /* bounded attempts: ~10s, then fail (no hang) */

/*
 * Each client runs a single device, named "<user>-dev".  The two clients must
 * use DISTINCT DeviceIDs: DeviceRecords are keyed per (UserID, DeviceID)
 * (D-SES-12), so a shared DeviceID string would only have worked under the old
 * DeviceID-only keying this release corrects, and it also kept the fan-out from
 * ever reaching the steady-state MESSAGE path (the peer was mistaken for the
 * sender's own device).  self_did() names our own device; peer_did() names the
 * peer's.  Both derive from the logical user names, so the two ends agree.
 */
static const char *
self_did(const struct client_cfg *cfg)
{
    static char buf[64];

    if (buf[0] == '\0')
        snprintf(buf, sizeof(buf), "%s-dev", cfg->name);
    return buf;
}

static const char *
peer_did(const struct client_cfg *cfg)
{
    static char buf[64];

    if (buf[0] == '\0')
        snprintf(buf, sizeof(buf), "%s-dev", cfg->peer);
    return buf;
}

/* Per-process outbound message counter (each client has one peer). */
static uint32_t s_send_seq;

/*
 * Fail-closed self-test hook: when GERYON_DEMO_FAULT is set the
 * initiator corrupts one recovered plaintext, forcing a mismatch so the demo
 * exits nonzero.  It demonstrates the demo fails closed; normal runs never set
 * it.
 */
static int
demo_fault(void)
{
    return getenv("GERYON_DEMO_FAULT") != NULL;
}

/* Monotone clock callback: time enters the library only through this. */
static uint64_t
demo_clock(void *ctx)
{
    uint64_t *tick = ctx;

    return (*tick)++;
}

/*
 * Wait for one frame with a bounded poll loop (the archive pattern): poll with
 * a short timeout up to a fixed number of attempts, so a message that never
 * arrives fails cleanly instead of blocking the process forever.  Returns 0 on
 * success, -1 on error or timeout.
 */
static int
wait_frame(int rfd, struct demo_frame_header *hdr, uint8_t *buf, size_t cap)
{
    struct pollfd p;
    int attempts;

    p.fd = rfd;
    p.events = POLLIN;
    for (attempts = 0; attempts < CLIENT_POLL_ATTEMPTS; attempts++) {
        int rv = poll(&p, 1, CLIENT_POLL_MS);

        if (rv < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rv == 0)
            continue; /* timeout: keep waiting, bounded */
        return demo_recv_frame(rfd, hdr, buf, cap) == DEMO_IPC_OK ? 0 : -1;
    }
    return -1; /* gave up: the expected message never arrived */
}

/*
 * Send one frame carrying an opaque payload of the given type from name to
 * dst, stamped with seq.  Returns 0 on success, -1 on an IPC error.
 */
static int
send_frame(int wfd, const char *name, const char *dst, enum demo_msg_type type,
           uint32_t seq, const uint8_t *data, size_t data_len)
{
    struct demo_frame_header hdr;

    memset(&hdr, 0, sizeof(hdr));
    hdr.type = (uint32_t)type;
    hdr.data_len = (uint32_t)data_len;
    hdr.seq = seq;
    snprintf(hdr.from, sizeof(hdr.from), "%s", name);
    snprintf(hdr.to, sizeof(hdr.to), "%s", dst);
    return demo_send_frame(wfd, &hdr, data) == DEMO_IPC_OK ? 0 : -1;
}

/*
 * Publish the identity+SPK registration (only) to the directory, using the
 * OpenSSL-style size-query convention.  Made at identity creation and on SPK
 * rotation.  Returns 0 on success, -1 on failure.
 */
static int
publish_registration(gy_custodian *c, const struct client_cfg *cfg, int wfd)
{
    uint8_t reg[CLIENT_REG_MAX];
    size_t need = 0, len;

    if (gy_custodian_publish_registration(c, NULL, &need) != GY_OK ||
        need > sizeof(reg))
        return -1;
    len = sizeof(reg);
    if (gy_custodian_publish_registration(c, reg, &len) != GY_OK)
        return -1;
    return send_frame(wfd, cfg->name, "coordinator",
                      DEMO_MSG_PUBLISH_REGISTRATION, 0, reg, len);
}

/*
 * Publish the current unused OPK public batch (only) to the directory.  Made
 * at identity creation and on OPK replenishment.  Returns 0 on success.
 */
static int
publish_opk_batch(gy_custodian *c, const struct client_cfg *cfg, int wfd)
{
    uint8_t batch[CLIENT_BATCH_MAX];
    size_t need = 0, len;

    if (gy_custodian_publish_opk_batch(c, NULL, &need) != GY_OK ||
        need > sizeof(batch))
        return -1;
    len = sizeof(batch);
    if (gy_custodian_publish_opk_batch(c, batch, &len) != GY_OK)
        return -1;
    return send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_PUBLISH_OPK_BATCH,
                      0, batch, len);
}

/* Publish both the registration and the OPK batch (initial publish). */
static int
publish_directory(gy_custodian *c, const struct client_cfg *cfg, int wfd)
{
    if (publish_registration(c, cfg, wfd) != 0 ||
        publish_opk_batch(c, cfg, wfd) != 0)
        return -1;
    printf("[%s] published registration and OPK batch\n", cfg->name);
    return 0;
}

/*
 * Fetch the peer's bundle from the coordinator into out (capacity in
 * *out_len, length out).  Returns 0 on success, -1 on an IPC/protocol error.
 */
static int
fetch_bundle(const struct client_cfg *cfg, int rfd, int wfd, uint8_t *out,
             size_t *out_len)
{
    struct demo_frame_header hdr;

    if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_FETCH_BUNDLE, 0, NULL,
                   0) != 0)
        return -1;
    if (wait_frame(rfd, &hdr, out, *out_len) != 0) {
        fprintf(stderr, "[%s] timed out waiting for bundle\n", cfg->name);
        return -1;
    }
    if (hdr.type != DEMO_MSG_BUNDLE || hdr.data_len == 0)
        return -1;
    *out_len = hdr.data_len;
    return 0;
}

/*
 * Send the FIRST message to the peer: fetch a bundle and gy_initiate inside a
 * send transaction, honoring a bounded retry over a peer key change (accept
 * then retry).  Returns 0 on success, -1 on failure.
 */
static int
msg_initiate(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd,
             const uint8_t *pt, size_t ptlen)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    size_t pul = strlen(cfg->peer);
    int attempt;

    for (attempt = 0; attempt < CLIENT_INITIATE_RETRY; attempt++) {
        uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX];
        size_t blen = sizeof(bundle), mlen = sizeof(msg);
        gy_keychange chg;
        int rc;

        if (fetch_bundle(cfg, rfd, wfd, bundle, &blen) != 0)
            return -1;
        if (gy_send_open(c) != GY_OK)
            return -1;
        memset(&chg, 0, sizeof(chg));
        rc = gy_initiate(c, puid, pul, (const uint8_t *)peer_did(cfg),
                         strlen(peer_did(cfg)), bundle, blen, pt, ptlen, &chg,
                         msg, &mlen);
        if (rc == GY_ERR_KEY_CHANGED) {
            gy_rollback(c);
            if (gy_accept_identity(c, puid, pul, (const uint8_t *)peer_did(cfg),
                                   strlen(peer_did(cfg)), bundle,
                                   blen) != GY_OK)
                return -1;
            continue; /* retry the fetch/initiate */
        }
        if (rc != GY_OK) {
            gy_rollback(c);
            return -1;
        }
        if (gy_commit(c) != GY_OK)
            return -1;
        return send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_SEND,
                          s_send_seq++, msg, mlen);
    }
    return -1;
}

/*
 * A fan-out disposition as a short label, for the demo log.
 */
static const char *
fanout_status(int status)
{
    switch (status) {
    case GY_FANOUT_MESSAGE:
        return "MESSAGE";
    case GY_FANOUT_NEEDS_BUNDLE:
        return "NEEDS_BUNDLE";
    case GY_FANOUT_STALE:
        return "STALE";
    default:
        return "none";
    }
}

/*
 * Send one message the way a real client does: open the transaction, enumerate
 * the fan-out with gy_prepare (one peer with one device here, but coded as a
 * loop so it reads as the real multi-device path), then act on this device's
 * disposition.  GY_FANOUT_MESSAGE encrypts over the live session and commits;
 * every other case falls to msg_initiate's fetch-a-bundle-and-initiate path:
 * an empty fan-out (a still-unknown peer contributes no descriptor, arriving
 * via the reject/bundle path), GY_FANOUT_NEEDS_BUNDLE (a known device whose
 * session was dropped, e.g. after gy_accept_identity), or GY_FANOUT_STALE (an
 * expired session, D-SES-7).  Returns 0 on success, -1 on failure.
 */
static int
msg_send(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd,
         const uint8_t *pt, size_t ptlen)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    const uint8_t *did = (const uint8_t *)peer_did(cfg);
    size_t pul = strlen(cfg->peer);
    size_t dl = strlen(peer_did(cfg));
    gy_fanout_desc descs[DEMO_FANOUT_MAX];
    gy_target tgt;
    size_t cap, n, i;
    int status;

    tgt.user_id = puid;
    tgt.user_id_len = pul;

    if (gy_send_open(c) != GY_OK)
        return -1;

    /* Size query (descs == NULL), then enumerate: the fan-out count uses the
     * same OpenSSL-style sizing convention as the output buffers. */
    n = 0;
    if (gy_prepare(c, &tgt, 1, NULL, &n) != GY_OK || n > DEMO_FANOUT_MAX) {
        gy_rollback(c);
        return -1;
    }
    cap = DEMO_FANOUT_MAX;
    if (n > 0 && gy_prepare(c, &tgt, 1, descs, &cap) != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    n = n > 0 ? cap : 0;

    /* Find this peer device's disposition; an unknown peer yields no descriptor
     * at all, which reads here as status "none". */
    status = 0;
    for (i = 0; i < n; i++)
        if (descs[i].device_id_len == dl &&
            memcmp(descs[i].device_id, did, dl) == 0) {
            status = descs[i].status;
            break;
        }
    printf("[%s] fan-out %s/%s -> %s\n", cfg->name, cfg->peer, peer_did(cfg),
           fanout_status(status));

    if (status == GY_FANOUT_MESSAGE) {
        uint8_t msg[CLIENT_MSG_MAX];
        size_t mlen = sizeof(msg);

        if (gy_encrypt(c, puid, pul, did, dl, pt, ptlen, msg, &mlen) != GY_OK) {
            gy_rollback(c);
            return -1;
        }
        if (gy_commit(c) != GY_OK)
            return -1;
        return send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_SEND,
                          s_send_seq++, msg, mlen);
    }

    /* No live session for this device: the prepare pass was read-only, so
     * discard the transaction and (re)establish through the bundle path, which
     * opens its own transaction and absorbs a peer key change. */
    gy_rollback(c);
    return msg_initiate(c, cfg, rfd, wfd, pt, ptlen);
}

/*
 * Receive one message: request the next from the mailbox (blocking until the
 * coordinator's schedule releases it) and gy_receive it.  On success out
 * holds the plaintext and *out_len its length.  Returns 0, -1 on failure.
 */
static int
msg_receive(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd,
            uint8_t *out, size_t *out_len)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    size_t pul = strlen(cfg->peer);
    struct demo_frame_header hdr;
    uint8_t msg[CLIENT_MSG_MAX];

    if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_RECV, 0, NULL, 0) !=
        0)
        return -1;
    if (wait_frame(rfd, &hdr, msg, sizeof(msg)) != 0) {
        fprintf(stderr, "[%s] timed out waiting for a message\n", cfg->name);
        return -1;
    }
    if (hdr.type != DEMO_MSG_DELIVER)
        return -1;
    if (gy_receive(c, puid, pul, (const uint8_t *)peer_did(cfg),
                   strlen(peer_did(cfg)), msg, hdr.data_len, out,
                   out_len) != GY_OK)
        return -1;
    return 0;
}

/* Scripted conversation for the initiator (Alice). */
static int
run_initiator(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd)
{
    uint8_t out[256];
    size_t ol;
    int i;
    static const char *DMSG[4] = {"d1", "d2", "d3", "d4"};

    if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"a-one", 5) != 0) {
        fprintf(stderr, "[%s] initiate failed\n", cfg->name);
        return -1;
    }
    printf("[%s] sent a-one (initiated session)\n", cfg->name);

    ol = sizeof(out);
    if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
        return -1;
    if (ol != 5 || memcmp(out, "b-one", 5) != 0) {
        fprintf(stderr, "[%s] expected b-one\n", cfg->name);
        return -1;
    }
    printf("[%s] received b-one\n", cfg->name);

    if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"a-two", 5) != 0)
        return -1;
    printf("[%s] sent a-two\n", cfg->name);

    /* Four messages in one chain; the coordinator delivers them out of order
     * (d1, d3, d2, d4) so the peer exercises its skip store, then fills the
     * gap.  All four are delivered (none dropped) so the mailbox is clean for
     * the prekey-lifecycle phase that follows. */
    for (i = 0; i < 4; i++)
        if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)DMSG[i], 2) != 0)
            return -1;
    printf("[%s] sent d1..d4\n", cfg->name);
    return 0;
}

/*
 * Demo: the initiator's PQ-authentication state, as seen by the responder
 * (gy_pq_pending).  This is the ONE consumer-visible surface that differs
 * between suites: in a hybrid suite the responder's first reply encapsulates to
 * the initiator's identity ML-KEM key and mixes that secret into the root KDF,
 * so the initiator is PQ-PENDING (classical-strength only) until the responder
 * receives the initiator's first message AFTER that confirmation, at which
 * point it reads PQ-CONFIRMED (deniable KEM confirmation, no transcript
 * signature).  The classical suites carry no such state and always report
 * GY_PQ_NOT_APPLICABLE, so the expected value is suite-gated; the same call runs
 * in the classical demo and asserts the NOT_APPLICABLE contract.  A consumer
 * that does not surface PQ-auth state never has to make this call.  Returns 0 on
 * the expected state, -1 on any error or an unexpected state.
 */
static int
observe_pq_state(gy_custodian *c, const struct client_cfg *cfg, int want)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    const uint8_t *did = (const uint8_t *)peer_did(cfg);
    int st =
        gy_pq_pending(c, puid, strlen(cfg->peer), did, strlen(peer_did(cfg)));

    if (st < 0) {
        fprintf(stderr, "[%s] gy_pq_pending failed (%d)\n", cfg->name, st);
        return -1;
    }
    if (cfg->suite != GY_SUITE_H25519_512) {
        if (st != GY_PQ_NOT_APPLICABLE) {
            fprintf(stderr, "[%s] classical suite reported PQ state %d\n",
                    cfg->name, st);
            return -1;
        }
        return 0;
    }
    if (st != want) {
        fprintf(stderr, "[%s] PQ state %d for %s, expected %d\n", cfg->name, st,
                cfg->peer, want);
        return -1;
    }
    printf("[%s] PQ auth for %s/%s: %s\n", cfg->name, cfg->peer, peer_did(cfg),
           want == GY_PQ_PENDING
               ? "PENDING (classical-strength until the initiator's first "
                 "post-confirmation message)"
               : "CONFIRMED (initiator identity is PQ-authenticated)");
    return 0;
}

/* Scripted conversation for the responder (Bob). */
static int
run_responder(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd)
{
    uint8_t out[256], seen[4][2];
    size_t ol;
    int i, j;

    ol = sizeof(out);
    if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
        return -1;
    if (ol != 5 || memcmp(out, "a-one", 5) != 0) {
        fprintf(stderr, "[%s] expected a-one\n", cfg->name);
        return -1;
    }
    printf("[%s] received a-one\n", cfg->name);

    if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"b-one", 5) != 0)
        return -1;
    printf("[%s] sent b-one\n", cfg->name);

    /* The confirmation has been sent but the initiator has not yet spoken after
     * it: the initiator is PQ-pending (hybrid) / not-applicable (classical). */
    if (observe_pq_state(c, cfg, GY_PQ_PENDING) != 0)
        return -1;

    ol = sizeof(out);
    if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
        return -1;
    if (ol != 5 || memcmp(out, "a-two", 5) != 0) {
        fprintf(stderr, "[%s] expected a-two\n", cfg->name);
        return -1;
    }
    printf("[%s] received a-two\n", cfg->name);

    /* The initiator's first post-confirmation message has now been received:
     * its identity is PQ-authenticated in a hybrid suite. */
    if (observe_pq_state(c, cfg, GY_PQ_CONFIRMED) != 0)
        return -1;

    /* All four d-messages arrive, reordered (d1, d3, d2, d4).  Assert each is
     * a valid 2-byte "dN" and all four are distinct (out-of-order recovery). */
    for (i = 0; i < 4; i++) {
        ol = sizeof(out);
        if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
            return -1;
        if (ol != 2 || out[0] != 'd' || out[1] < '1' || out[1] > '4') {
            fprintf(stderr, "[%s] bad reordered message\n", cfg->name);
            return -1;
        }
        for (j = 0; j < i; j++)
            if (memcmp(seen[j], out, 2) == 0) {
                fprintf(stderr, "[%s] duplicate reordered message\n",
                        cfg->name);
                return -1;
            }
        memcpy(seen[i], out, 2);
        printf("[%s] received reordered %c%c\n", cfg->name, out[0], out[1]);
    }
    return 0;
}

/*
 * Force a fresh initiating session to the peer and send its initial message.
 * When bundle is NULL a fresh bundle is fetched (drawing a directory OPK);
 * otherwise the caller-held bundle is used (e.g. a reserved pre-rotation
 * bundle).  Returns 0 on success, -1 on failure.
 */
static int
send_reinitiate(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd,
                const uint8_t *bundle, size_t blen)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    size_t pul = strlen(cfg->peer);
    uint8_t fb[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX];
    size_t mlen = sizeof(msg);
    int rc;

    if (bundle == NULL) {
        size_t fblen = sizeof(fb);

        if (fetch_bundle(cfg, rfd, wfd, fb, &fblen) != 0)
            return -1;
        bundle = fb;
        blen = fblen;
    }
    if (gy_send_open(c) != GY_OK)
        return -1;
    rc = gy_reinitiate(c, puid, pul, (const uint8_t *)peer_did(cfg),
                       strlen(peer_did(cfg)), bundle, blen,
                       (const uint8_t *)"lc", 2, NULL, msg, &mlen);
    if (rc != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    if (gy_commit(c) != GY_OK)
        return -1;
    return send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_SEND, s_send_seq++,
                      msg, mlen);
}

/*
 * Initiator side of the prekey-lifecycle phase: drive repeated
 * fresh handshakes so the responder's OPK pool depletes and is replenished,
 * then exercise SPK rotation.  Each round is a reinitiate plus a wait for the
 * responder's ack, so the responder's pool/rotation change lands before the
 * next fetch.  The final round reuses a reserved pre-rotation bundle to show
 * the old SPK still receives (history window).
 */
static int
run_initiator_lifecycle(gy_custodian *c, const struct client_cfg *cfg, int rfd,
                        int wfd)
{
    uint8_t oldb[CLIENT_BUNDLE_MAX], out[256];
    size_t oldblen = sizeof(oldb), ol;
    int round;

    /* Reserve a pre-rotation (SPK v1) bundle for the history-window test. */
    if (fetch_bundle(cfg, rfd, wfd, oldb, &oldblen) != 0) {
        fprintf(stderr, "[%s] reserve fetch failed\n", cfg->name);
        return -1;
    }

    for (round = 0; round < CLIENT_LIFECYCLE_ROUNDS; round++) {
        int last = round == CLIENT_LIFECYCLE_ROUNDS - 1;

        if (send_reinitiate(c, cfg, rfd, wfd, last ? oldb : NULL,
                            last ? oldblen : 0) != 0) {
            fprintf(stderr, "[%s] lifecycle reinit round %d failed\n",
                    cfg->name, round);
            return -1;
        }
        ol = sizeof(out);
        if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0) {
            fprintf(stderr, "[%s] lifecycle ack round %d failed\n", cfg->name,
                    round);
            return -1;
        }
    }
    printf("[%s] prekey lifecycle complete\n", cfg->name);
    return 0;
}

/*
 * Responder side of the prekey-lifecycle phase: receive each fresh handshake
 * (consuming an OPK), report pool stats, replenish once the pool is drawn
 * down, rotate the SPK, and ack every round so the initiator stays in step.
 */
static int
run_responder_lifecycle(gy_custodian *c, const struct client_cfg *cfg, int rfd,
                        int wfd)
{
    uint8_t out[256];
    size_t total, used, unused;
    int round;

    for (round = 0; round < CLIENT_LIFECYCLE_ROUNDS; round++) {
        size_t ol = sizeof(out);

        if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0) {
            fprintf(stderr, "[%s] lifecycle recv round %d failed\n", cfg->name,
                    round);
            return -1;
        }
        if (gy_custodian_opk_stats(c, &total, &used, &unused) != GY_OK)
            return -1;
        printf("[%s] round %d: opk total=%zu used=%zu unused=%zu\n", cfg->name,
               round, total, used, unused);

        if (round == 1) {
            size_t before = unused;

            if (gy_custodian_generate_onetime_prekeys(c, CLIENT_REPLENISH) !=
                    GY_OK ||
                publish_opk_batch(c, cfg, wfd) != 0) {
                fprintf(stderr, "[%s] replenish failed\n", cfg->name);
                return -1;
            }
            if (gy_custodian_opk_stats(c, &total, &used, &unused) != GY_OK)
                return -1;
            if (unused <= before) {
                fprintf(stderr, "[%s] replenish did not grow the pool\n",
                        cfg->name);
                return -1;
            }
            printf("[%s] replenished: unused %zu -> %zu, republished batch\n",
                   cfg->name, before, unused);
        }
        if (round == 3) {
            if (gy_custodian_rotate_signed_prekey(c, CLIENT_SPK_TS2) != GY_OK ||
                publish_registration(c, cfg, wfd) != 0) {
                fprintf(stderr, "[%s] SPK rotation failed\n", cfg->name);
                return -1;
            }
            printf("[%s] rotated SPK, republished registration\n", cfg->name);
        }

        if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"ok", 2) != 0)
            return -1;
    }
    printf("[%s] prekey lifecycle complete\n", cfg->name);
    return 0;
}

/*
 * Build a SAK-authenticated request payload (msg_len_be16 || msg || sig) into
 * buf and send it, then wait for the coordinator's verdict.  Returns 1 if the
 * coordinator ACCEPTED, 0 if it REJECTED, -1 on an IPC error.
 */
static int
auth_request(const struct client_cfg *cfg, int rfd, int wfd, const uint8_t *msg,
             size_t msg_len, const uint8_t *sig, size_t sig_len)
{
    struct demo_frame_header hdr;
    uint8_t payload[CLIENT_MSG_MAX];
    size_t plen = 0;

    if (2 + msg_len + sig_len > sizeof(payload))
        return -1;
    payload[plen++] = (uint8_t)(msg_len >> 8);
    payload[plen++] = (uint8_t)(msg_len & 0xff);
    memcpy(payload + plen, msg, msg_len);
    plen += msg_len;
    memcpy(payload + plen, sig, sig_len);
    plen += sig_len;

    if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_AUTH_REQ, 0, payload,
                   plen) != 0)
        return -1;
    if (wait_frame(rfd, &hdr, payload, sizeof(payload)) != 0)
        return -1;
    return hdr.type == DEMO_MSG_AUTH_OK;
}

/*
 * SAK-authenticated request example: mint an application signing
 * key, publish its certificate, then sign a canonical request and show the
 * coordinator (which holds no custodian) accept it - verifying against the
 * client's directory-pinned identity key - and reject a forged signature.
 * The SAK signs only this request payload, never message content (the
 * deniability boundary, CUSTODY_SPEC section 10).  Returns 0 on success.
 */
static int
run_sak_auth(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd)
{
    gy_key_handle sak;
    uint8_t cert[8192], sig[4096], msg[128];
    size_t certlen = sizeof(cert), siglen = sizeof(sig), msglen;
    int verdict;

    if (gy_custodian_generate_appkey(c, 0, &sak) != GY_OK) {
        fprintf(stderr, "[%s] generate_appkey failed\n", cfg->name);
        return -1;
    }
    if (gy_custodian_export_appkey_cert(c, sak, cert, &certlen) != GY_OK)
        return -1;
    if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_PUBLISH_CERT, 0,
                   cert, certlen) != 0)
        return -1;

    /* Canonical signed request: method | target | body. */
    msglen = (size_t)snprintf((char *)msg, sizeof(msg), "FETCH_BUNDLE|%s|body",
                              cfg->peer);
    if (gy_custodian_sign(c, sak, (const uint8_t *)DEMO_AUTH_CTX,
                          strlen(DEMO_AUTH_CTX), msg, msglen, sig,
                          &siglen) != GY_OK) {
        fprintf(stderr, "[%s] sign failed\n", cfg->name);
        return -1;
    }

    /* A valid signature verifies. */
    verdict = auth_request(cfg, rfd, wfd, msg, msglen, sig, siglen);
    if (verdict != 1) {
        fprintf(stderr, "[%s] valid SAK request was rejected (%d)\n", cfg->name,
                verdict);
        return -1;
    }
    printf("[%s] authenticated request accepted\n", cfg->name);

    /* A forged signature is rejected. */
    sig[0] ^= 0xff;
    verdict = auth_request(cfg, rfd, wfd, msg, msglen, sig, siglen);
    if (verdict != 0) {
        fprintf(stderr, "[%s] forged SAK request was NOT rejected (%d)\n",
                cfg->name, verdict);
        return -1;
    }
    printf("[%s] forged request rejected\n", cfg->name);

    /* Demo: SAK rotation with the retained-history window.  Rotate to a
     * new SAK, publish its cert as the ACTIVE cert and the retained prior SAK's
     * cert separately; the coordinator then accepts a request signed by EITHER
     * the new or the still-retained prior SAK (mirrors SPK rotation), while a
     * forged signature is still rejected.  The prior SAK (handle `sak`) stays
     * usable for signing and cert export until history evicts it. */
    {
        gy_key_handle sak2;
        uint8_t cert2[8192];
        size_t clen;

        if (gy_custodian_rotate_appkey(c, 0, &sak2) != GY_OK) {
            fprintf(stderr, "[%s] rotate_appkey failed\n", cfg->name);
            return -1;
        }
        printf("[%s] rotated SAK (prior key retained for the history window)\n",
               cfg->name);

        /* Publish the new cert as active and the retained prior cert. */
        clen = sizeof(cert2);
        if (gy_custodian_export_appkey_cert(c, sak2, cert2, &clen) != GY_OK ||
            send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_PUBLISH_CERT, 0,
                       cert2, clen) != 0)
            return -1;
        certlen = sizeof(cert);
        if (gy_custodian_export_appkey_cert(c, sak, cert, &certlen) != GY_OK ||
            send_frame(wfd, cfg->name, "coordinator",
                       DEMO_MSG_PUBLISH_PRIOR_CERT, 0, cert, certlen) != 0)
            return -1;

        /* A request signed by the NEW SAK verifies (against the active cert). */
        siglen = sizeof(sig);
        if (gy_custodian_sign(c, sak2, (const uint8_t *)DEMO_AUTH_CTX,
                              strlen(DEMO_AUTH_CTX), msg, msglen, sig,
                              &siglen) != GY_OK)
            return -1;
        if (auth_request(cfg, rfd, wfd, msg, msglen, sig, siglen) != 1) {
            fprintf(stderr, "[%s] new-SAK request was rejected\n", cfg->name);
            return -1;
        }
        printf("[%s] new-SAK request accepted\n", cfg->name);

        /* A request signed by the retained PRIOR SAK still verifies within the
         * history window (against the published prior cert). */
        siglen = sizeof(sig);
        if (gy_custodian_sign(c, sak, (const uint8_t *)DEMO_AUTH_CTX,
                              strlen(DEMO_AUTH_CTX), msg, msglen, sig,
                              &siglen) != GY_OK)
            return -1;
        if (auth_request(cfg, rfd, wfd, msg, msglen, sig, siglen) != 1) {
            fprintf(stderr,
                    "[%s] prior-SAK request was rejected in history "
                    "window\n",
                    cfg->name);
            return -1;
        }
        printf("[%s] prior-SAK request accepted within history window\n",
               cfg->name);

        /* A forged signature is still rejected after rotation. */
        sig[0] ^= 0xff;
        if (auth_request(cfg, rfd, wfd, msg, msglen, sig, siglen) != 0) {
            fprintf(stderr, "[%s] forged post-rotation request NOT rejected\n",
                    cfg->name);
            return -1;
        }
        printf("[%s] forged post-rotation request rejected\n", cfg->name);
    }
    return 0;
}

/*
 * Initiator side of the restart-persistence phase: send a
 * message the peer will only receive after it has closed, exited, and been
 * re-forked from its sealed store, then wait for the peer's reply.  A correct
 * reply proves the ratchet state survived the restart on disk.
 */
static int
run_restart_initiator(gy_custodian *c, const struct client_cfg *cfg, int rfd,
                      int wfd)
{
    uint8_t out[256];
    size_t ol = sizeof(out);

    if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"post-restart", 12) != 0) {
        fprintf(stderr, "[%s] restart-phase send failed\n", cfg->name);
        return -1;
    }
    printf("[%s] sent post-restart message; awaiting the resumed peer\n",
           cfg->name);

    if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
        return -1;
    if (demo_fault())
        out[0] ^= 0xff; /* corrupt the recovered plaintext (fail-closed test) */
    if (ol != 7 || memcmp(out, "resumed", 7) != 0) {
        fprintf(stderr, "[%s] resumed-peer reply mismatch%s\n", cfg->name,
                demo_fault() ? " (fault injected: demo fails closed)" : "");
        return -1;
    }
    printf("[%s] peer resumed from its sealed store; conversation intact\n",
           cfg->name);
    return 0;
}

/*
 * Print a byte string as lowercase hex (a fingerprint display encoding; the
 * real encoding is application scope, D-X3DH-11).
 */
static void
print_hex(const char *name, const char *label, const uint8_t *b, size_t n)
{
    size_t i;

    printf("[%s] %s ", name, label);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\n");
}

/*
 * Demo: identity verification (safety numbers).  Each client prints
 * its own gy_self_fingerprint, publishes it, then fetches the peer's identity
 * (its published registration plus its own self-fingerprint) and derives the
 * peer's fingerprint LOCALLY from that registration with gy_bundle_fingerprint.
 * The derived value must equal the peer's self-fingerprint: the byte-identical
 * guarantee across gy_self_fingerprint and gy_bundle_fingerprint is what makes
 * this a real cross-check, the out-of-band comparison a user performs by hand,
 * and a swapped identity key would not match.  The library makes NO trust
 * decision here; pinning stays the app's job (gy_accept_identity).  Returns 0
 * on a match, -1 on any failure or mismatch (fail-closed).
 */
static int
verify_identity(gy_custodian *c, const struct client_cfg *cfg, int rfd, int wfd)
{
    struct demo_frame_header hdr;
    uint8_t own_fp[GY_FINGERPRINT_MAX];
    uint8_t reply[CLIENT_REG_MAX + 2 + GY_FINGERPRINT_MAX];
    uint8_t derived[GY_FINGERPRINT_MAX];
    const uint8_t *peer_fp, *peer_reg;
    size_t own_len = sizeof(own_fp);
    size_t peer_fp_len, peer_reg_len, dlen;

    if (gy_self_fingerprint(c, NULL, &own_len) != GY_OK ||
        own_len > sizeof(own_fp))
        return -1;
    own_len = sizeof(own_fp);
    if (gy_self_fingerprint(c, own_fp, &own_len) != GY_OK)
        return -1;
    print_hex(cfg->name, "my safety number", own_fp, own_len);

    /* Publish our own fingerprint so the peer can compare, then fetch the
     * peer's identity (registration + its self-fingerprint). */
    if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_PUBLISH_FINGERPRINT,
                   0, own_fp, own_len) != 0)
        return -1;
    if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_FETCH_IDENTITY, 0, NULL,
                   0) != 0)
        return -1;
    if (wait_frame(rfd, &hdr, reply, sizeof(reply)) != 0 ||
        hdr.type != DEMO_MSG_IDENTITY || hdr.data_len < 2)
        return -1;

    /* Parse fp_len_be16 || peer_fp || peer_registration. */
    peer_fp_len = ((size_t)reply[0] << 8) | (size_t)reply[1];
    if (2 + peer_fp_len > hdr.data_len)
        return -1;
    peer_fp = reply + 2;
    peer_reg = reply + 2 + peer_fp_len;
    peer_reg_len = hdr.data_len - 2 - peer_fp_len;

    /* Derive the peer's fingerprint locally from its registration. */
    dlen = sizeof(derived);
    if (gy_bundle_fingerprint(peer_reg, peer_reg_len, derived, &dlen) != GY_OK)
        return -1;
    print_hex(cfg->name, "peer safety number (derived)", derived, dlen);

    /* Fail-closed self-test hook: corrupt the derived value so
     * the comparison below must fail and the demo exits nonzero. */
    if (demo_fault() && dlen > 0)
        derived[0] ^= 0xFF;

    if (dlen != peer_fp_len || memcmp(derived, peer_fp, dlen) != 0) {
        fprintf(stderr, "[%s] safety-number MISMATCH for %s%s\n", cfg->name,
                cfg->peer,
                demo_fault() ? " (fault injected: demo fails closed)" : "");
        return -1;
    }
    printf(
        "[%s] verified %s's identity (derived fingerprint matches its own)\n",
        cfg->name, cfg->peer);
    return 0;
}

/*
 * Demo: one-shot full-bundle publish (gy_publish_bundle), shown beside
 * the granular registration+OPK-batch directory model the rest of the demo
 * uses.  gy_publish_bundle emits a COMPLETE bundle (IK + signed SPK + one OPK)
 * a peer feeds straight to gy_initiate with no server-side assembly; it also
 * RESERVES that OPK from its pool (minting a fresh one if the pool is spent),
 * so a one-shot identity must never also publish through the granular path
 * (both draw from one pool).  To honor that, this scenario uses a DEDICATED
 * throwaway identity per side, distinct from the main alice/bob directory
 * identities, in its own sealed store.  Alice (the publisher) publishes the
 * bundle and receives; Bob (the fetcher) initiates from its bytes and sends.
 * Alice is the receiver on purpose: her mailbox is strict FIFO, so the single
 * one-shot delivery does not perturb the reordered d-batch that follows.
 * Returns 0 on success, -1 on any failure.
 */
static int
run_oneshot(const struct client_cfg *cfg, int rfd, int wfd)
{
    struct filestore fs;
    gy_store_callbacks cb;
    gy_custodian *c = NULL;
    char osdir[FILESTORE_DIR_MAX];
    int rc = -1;

    if (snprintf(osdir, sizeof(osdir), "%s-os", cfg->store_dir) >=
        (int)sizeof(osdir))
        return -1;
    if (filestore_bind(&fs, osdir, &cb) != 0)
        return -1;
    if (gy_custodian_create(&c, cfg->suite, &cb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), (const uint8_t *)cfg->name,
                            strlen(cfg->name), (const uint8_t *)self_did(cfg),
                            strlen(self_did(cfg)), NULL, NULL, NULL) != GY_OK)
        return -1;
    if (gy_custodian_generate_identity(c, CLIENT_SPK_TS, 2) != GY_OK)
        goto out;

    if (cfg->role == CLIENT_INITIATOR) {
        /* Publisher/receiver: publish a complete one-shot bundle (reserving an
         * OPK), then receive the message the peer initiates from it. */
        uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX], out[64];
        struct demo_frame_header hdr;
        size_t need = 0, blen, ol = sizeof(out);

        if (gy_publish_bundle(c, NULL, &need) != GY_OK || need > sizeof(bundle))
            goto out;
        blen = sizeof(bundle);
        if (gy_publish_bundle(c, bundle, &blen) != GY_OK)
            goto out;
        if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_PUBLISH_ONESHOT,
                       0, bundle, blen) != 0)
            goto out;
        printf("[%s] published a one-shot full bundle (%zu bytes, OPK reserved "
               "from its own pool)\n",
               cfg->name, blen);

        if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_RECV, 0, NULL,
                       0) != 0)
            goto out;
        if (wait_frame(rfd, &hdr, msg, sizeof(msg)) != 0 ||
            hdr.type != DEMO_MSG_DELIVER)
            goto out;
        if (gy_receive(c, (const uint8_t *)cfg->peer, strlen(cfg->peer),
                       (const uint8_t *)peer_did(cfg), strlen(peer_did(cfg)),
                       msg, hdr.data_len, out, &ol) != GY_OK)
            goto out;
        if (ol != 8 || memcmp(out, "os-hello", 8) != 0) {
            fprintf(stderr, "[%s] one-shot handshake plaintext mismatch\n",
                    cfg->name);
            goto out;
        }
        printf(
            "[%s] completed a session from the one-shot bundle (delete-on-use "
            "consumed the reserved OPK)\n",
            cfg->name);
        rc = 0;
    } else {
        /* Fetcher/initiator: fetch the peer's one-shot bundle and initiate
         * straight from its bytes, no server-side assembly. */
        uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX];
        struct demo_frame_header hdr;
        size_t blen, mlen = sizeof(msg);
        gy_keychange chg;

        if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_FETCH_ONESHOT, 0,
                       NULL, 0) != 0)
            goto out;
        if (wait_frame(rfd, &hdr, bundle, sizeof(bundle)) != 0 ||
            hdr.type != DEMO_MSG_ONESHOT || hdr.data_len == 0)
            goto out;
        blen = hdr.data_len;
        if (gy_send_open(c) != GY_OK)
            goto out;
        memset(&chg, 0, sizeof(chg));
        if (gy_initiate(c, (const uint8_t *)cfg->peer, strlen(cfg->peer),
                        (const uint8_t *)peer_did(cfg), strlen(peer_did(cfg)),
                        bundle, blen, (const uint8_t *)"os-hello", 8, &chg, msg,
                        &mlen) != GY_OK) {
            gy_rollback(c);
            goto out;
        }
        if (gy_commit(c) != GY_OK)
            goto out;
        if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_SEND, s_send_seq++,
                       msg, mlen) != 0)
            goto out;
        printf(
            "[%s] initiated from the peer's one-shot bundle (fed straight to "
            "gy_initiate)\n",
            cfg->name);
        rc = 0;
    }

out:
    gy_custodian_close(c);
    return rc;
}

/*
 * Demo: the no-OPK handshake path.  An X3DH bundle need not carry a
 * one-time prekey; a session established without one is valid but has reduced
 * forward secrecy (there is no per-session OPK to consume and delete), so it is
 * a deliberate, clearly labeled scenario, not the default.  Alice (the
 * receiver) publishes a registration for an OPK-less fetch; the coordinator
 * assembles the bundle with gy_bundle_assemble(..., opk_pub == NULL); Bob
 * initiates from it and sends.  A dedicated throwaway identity per side keeps
 * this off the directory pool and out of the main conversation, and off the
 * receiver's published SAK registration.  Alice is the receiver so the single
 * delivery lands in her FIFO mailbox and does not perturb the reordered
 * d-batch.  Returns 0 on success, -1 on any failure.
 */
static int
run_noopk(const struct client_cfg *cfg, int rfd, int wfd)
{
    struct filestore fs;
    gy_store_callbacks cb;
    gy_custodian *c = NULL;
    char nodir[FILESTORE_DIR_MAX];
    int rc = -1;

    if (snprintf(nodir, sizeof(nodir), "%s-no", cfg->store_dir) >=
        (int)sizeof(nodir))
        return -1;
    if (filestore_bind(&fs, nodir, &cb) != 0)
        return -1;
    if (gy_custodian_create(&c, cfg->suite, &cb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), (const uint8_t *)cfg->name,
                            strlen(cfg->name), (const uint8_t *)self_did(cfg),
                            strlen(self_did(cfg)), NULL, NULL, NULL) != GY_OK)
        return -1;
    if (gy_custodian_generate_identity(c, CLIENT_SPK_TS, 2) != GY_OK)
        goto out;

    if (cfg->role == CLIENT_INITIATOR) {
        /* Receiver: publish a registration for the OPK-less fetch, then receive
         * the message the peer initiates without an OPK. */
        uint8_t reg[CLIENT_REG_MAX], msg[CLIENT_MSG_MAX], out[64];
        struct demo_frame_header hdr;
        size_t need = 0, rlen, ol = sizeof(out);

        if (gy_custodian_publish_registration(c, NULL, &need) != GY_OK ||
            need > sizeof(reg))
            goto out;
        rlen = sizeof(reg);
        if (gy_custodian_publish_registration(c, reg, &rlen) != GY_OK)
            goto out;
        if (send_frame(wfd, cfg->name, "coordinator",
                       DEMO_MSG_PUBLISH_NOOPK_REG, 0, reg, rlen) != 0)
            goto out;
        printf("[%s] published a no-OPK-path registration\n", cfg->name);

        if (send_frame(wfd, cfg->name, "coordinator", DEMO_MSG_RECV, 0, NULL,
                       0) != 0)
            goto out;
        if (wait_frame(rfd, &hdr, msg, sizeof(msg)) != 0 ||
            hdr.type != DEMO_MSG_DELIVER)
            goto out;
        if (gy_receive(c, (const uint8_t *)cfg->peer, strlen(cfg->peer),
                       (const uint8_t *)peer_did(cfg), strlen(peer_did(cfg)),
                       msg, hdr.data_len, out, &ol) != GY_OK)
            goto out;
        if (ol != 8 || memcmp(out, "noopk-hi", 8) != 0) {
            fprintf(stderr, "[%s] no-OPK handshake plaintext mismatch\n",
                    cfg->name);
            goto out;
        }
        printf("[%s] received over a no-OPK session (valid X3DH, reduced "
               "forward secrecy vs a session that consumed an OPK)\n",
               cfg->name);
        rc = 0;
    } else {
        /* Initiator: fetch the peer's OPK-less bundle and initiate from it. */
        uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX];
        struct demo_frame_header hdr;
        size_t blen, mlen = sizeof(msg);
        gy_keychange chg;

        if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_FETCH_NOOPK, 0, NULL,
                       0) != 0)
            goto out;
        if (wait_frame(rfd, &hdr, bundle, sizeof(bundle)) != 0 ||
            hdr.type != DEMO_MSG_BUNDLE || hdr.data_len == 0)
            goto out;
        blen = hdr.data_len;
        if (gy_send_open(c) != GY_OK)
            goto out;
        memset(&chg, 0, sizeof(chg));
        if (gy_initiate(c, (const uint8_t *)cfg->peer, strlen(cfg->peer),
                        (const uint8_t *)peer_did(cfg), strlen(peer_did(cfg)),
                        bundle, blen, (const uint8_t *)"noopk-hi", 8, &chg, msg,
                        &mlen) != GY_OK) {
            gy_rollback(c);
            goto out;
        }
        if (gy_commit(c) != GY_OK)
            goto out;
        if (send_frame(wfd, cfg->name, cfg->peer, DEMO_MSG_SEND, s_send_seq++,
                       msg, mlen) != 0)
            goto out;
        printf("[%s] initiated a no-OPK X3DH session from an OPK-less bundle\n",
               cfg->name);
        rc = 0;
    }

out:
    gy_custodian_close(c);
    return rc;
}

/*
 * Assert this custodian has NO live session to the peer device: gy_prepare over
 * the peer must return an EMPTY fan-out (a purged device contributes no
 * descriptor, exactly like a never-seen one).  Opens and rolls back a throwaway
 * transaction so it observes state without changing it.  Returns 0 if the peer
 * is absent, -1 if a session still exists or on any error.
 */
static int
assert_no_session(gy_custodian *c, const struct client_cfg *cfg)
{
    gy_fanout_desc descs[DEMO_FANOUT_MAX];
    gy_target tgt;
    size_t n = 0, cap;
    int gone;

    tgt.user_id = (const uint8_t *)cfg->peer;
    tgt.user_id_len = strlen(cfg->peer);
    if (gy_send_open(c) != GY_OK)
        return -1;
    if (gy_prepare(c, &tgt, 1, NULL, &n) != GY_OK || n > DEMO_FANOUT_MAX) {
        gy_rollback(c);
        return -1;
    }
    cap = DEMO_FANOUT_MAX;
    if (n > 0 && gy_prepare(c, &tgt, 1, descs, &cap) != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    gone = (n == 0);
    gy_rollback(c);
    return gone ? 0 : -1;
}

/*
 * Demo: peer removal (gy_purge_device / gy_purge_user, D-SES-2).  On
 * the MAIN conversation: the initiator purges the peer (first one device, then
 * the whole user), asserts the session is gone, and re-adds it with an ordinary
 * fresh handshake; the responder just answers each fresh inbound handshake.
 * This shows that removal is complete (the session and its records are
 * zeroized, so the peer looks never-seen) and that re-adding a contact is
 * nothing special - it is a normal initiation.  Runs on the main custodians:
 * each cycle ends in a healthy fresh session, so the restart phase that follows
 * still resumes cleanly.  Returns 0 on success, -1 on any failure.
 */
static int
run_peer_removal(gy_custodian *c, const struct client_cfg *cfg, int rfd,
                 int wfd)
{
    const uint8_t *puid = (const uint8_t *)cfg->peer;
    size_t pul = strlen(cfg->peer);
    uint8_t out[64];
    size_t ol;

    if (cfg->role == CLIENT_INITIATOR) {
        /* Cycle 1: remove a single device. */
        if (gy_purge_device(c, puid, pul, (const uint8_t *)peer_did(cfg),
                            strlen(peer_did(cfg))) != GY_OK) {
            fprintf(stderr, "[%s] purge_device failed\n", cfg->name);
            return -1;
        }
        if (assert_no_session(c, cfg) != 0) {
            fprintf(stderr, "[%s] session survived purge_device\n", cfg->name);
            return -1;
        }
        printf("[%s] purged %s's device; its session and records are gone\n",
               cfg->name, cfg->peer);
        if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"readd-dev", 9) != 0)
            return -1;
        ol = sizeof(out);
        if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
            return -1;
        if (ol != 7 || memcmp(out, "ack-dev", 7) != 0) {
            fprintf(stderr, "[%s] re-add (device) round-trip mismatch\n",
                    cfg->name);
            return -1;
        }
        printf("[%s] re-added %s's device with a fresh handshake\n", cfg->name,
               cfg->peer);

        /* Cycle 2: remove the entire user. */
        if (gy_purge_user(c, puid, pul) != GY_OK) {
            fprintf(stderr, "[%s] purge_user failed\n", cfg->name);
            return -1;
        }
        if (assert_no_session(c, cfg) != 0) {
            fprintf(stderr, "[%s] session survived purge_user\n", cfg->name);
            return -1;
        }
        printf("[%s] purged the whole user %s; all its devices are gone\n",
               cfg->name, cfg->peer);
        if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)"readd-usr", 9) != 0)
            return -1;
        ol = sizeof(out);
        if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
            return -1;
        if (ol != 7 || memcmp(out, "ack-usr", 7) != 0) {
            fprintf(stderr, "[%s] re-add (user) round-trip mismatch\n",
                    cfg->name);
            return -1;
        }
        printf("[%s] re-added user %s with a fresh handshake\n", cfg->name,
               cfg->peer);
        return 0;
    }

    /* Responder: answer each of the two fresh inbound handshakes. */
    {
        static const char *ACK[2] = {"ack-dev", "ack-usr"};
        int k;

        for (k = 0; k < 2; k++) {
            ol = sizeof(out);
            if (msg_receive(c, cfg, rfd, wfd, out, &ol) != 0)
                return -1;
            if (ol != 9 || memcmp(out, "readd-", 6) != 0) {
                fprintf(stderr, "[%s] unexpected re-add message\n", cfg->name);
                return -1;
            }
            if (msg_send(c, cfg, rfd, wfd, (const uint8_t *)ACK[k], 7) != 0)
                return -1;
            printf("[%s] answered a re-add handshake (%s)\n", cfg->name,
                   ACK[k]);
        }
        return 0;
    }
}

/*
 * Demo: session expiration policy (gy_config, D-SES-7).  Expiration is
 * a CREATE-TIME custodian policy (the section 4.2 inequality is validated in
 * gy_custodian_create), so it cannot be toggled on the main alice/bob
 * custodians, which are created with expiration OFF.  This runs an isolated,
 * in-process pair of throwaway custodians created WITH a tiny expiration policy:
 * after max_send messages on a session, gy_prepare reports GY_FANOUT_STALE and
 * gy_encrypt returns GY_ERR_EXPIRED (a stale session is never sent under,
 * D-SES-7).  The sender hands each ciphertext straight to the peer in-process,
 * so there is NO coordinator traffic and the scenario is fully deterministic
 * and cannot perturb the main conversation.  Returns 0 on success, -1 on any
 * failure.
 */
static int
run_expiration(const struct client_cfg *cfg)
{
    static const gy_config expiry = {1, EXP_MAX_SEND, EXP_MAX_RECV,
                                     EXP_MAX_LATENCY};
    struct filestore sfs, pfs;
    gy_store_callbacks scb, pcb;
    gy_custodian *s = NULL, *p = NULL;
    gy_fanout_desc descs[DEMO_FANOUT_MAX];
    gy_target tgt;
    gy_keychange chg;
    char sdir[FILESTORE_DIR_MAX], pdir[FILESTORE_DIR_MAX];
    uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX], out[64];
    uint64_t stick = CLIENT_CLOCK_BASE, ptick = CLIENT_CLOCK_BASE;
    const uint8_t *su = (const uint8_t *)"exp-sender";
    const uint8_t *pu = (const uint8_t *)"exp-peer";
    const uint8_t *s_did = (const uint8_t *)"exp-dev-s";
    const uint8_t *p_did = (const uint8_t *)"exp-dev-p";
    size_t sul = strlen("exp-sender"), pul = strlen("exp-peer");
    size_t s_dl = strlen("exp-dev-s"), p_dl = strlen("exp-dev-p");
    size_t need = 0, blen, mlen, ol;
    int rc = -1, round, saw_stale = 0;

    if (snprintf(sdir, sizeof(sdir), "%s-exp-s", cfg->store_dir) >=
            (int)sizeof(sdir) ||
        snprintf(pdir, sizeof(pdir), "%s-exp-p", cfg->store_dir) >=
            (int)sizeof(pdir))
        return -1;
    if (filestore_bind(&sfs, sdir, &scb) != 0 ||
        filestore_bind(&pfs, pdir, &pcb) != 0)
        return -1;

    /* Both custodians carry the same create-time expiration policy. */
    if (gy_custodian_create(&s, cfg->suite, &scb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), su, sul, s_did, s_dl, demo_clock,
                            &stick, &expiry) != GY_OK)
        return -1;
    if (gy_custodian_create(&p, cfg->suite, &pcb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), pu, pul, p_did, p_dl, demo_clock,
                            &ptick, &expiry) != GY_OK)
        goto out;
    if (gy_custodian_generate_identity(s, CLIENT_SPK_TS, 2) != GY_OK ||
        gy_custodian_generate_identity(p, CLIENT_SPK_TS, 2) != GY_OK)
        goto out;

    /* Establish a session: the peer publishes a one-shot bundle, the sender
     * initiates from it, the peer receives (all in-process). */
    blen = sizeof(bundle);
    if (gy_publish_bundle(p, NULL, &need) != GY_OK || need > sizeof(bundle) ||
        gy_publish_bundle(p, bundle, &blen) != GY_OK)
        goto out;
    if (gy_send_open(s) != GY_OK)
        goto out;
    memset(&chg, 0, sizeof(chg));
    mlen = sizeof(msg);
    if (gy_initiate(s, pu, pul, p_did, p_dl, bundle, blen,
                    (const uint8_t *)"e0", 2, &chg, msg, &mlen) != GY_OK) {
        gy_rollback(s);
        goto out;
    }
    if (gy_commit(s) != GY_OK)
        goto out;
    ol = sizeof(out);
    if (gy_receive(p, su, sul, s_did, s_dl, msg, mlen, out, &ol) != GY_OK)
        goto out;

    /* The peer replies once so the sender's session becomes ACTIVE: an
     * initiating session is not enumerable by gy_prepare (its device record is
     * created only when the peer's first reply is received). */
    {
        uint8_t rmsg[CLIENT_MSG_MAX];
        size_t rlen = sizeof(rmsg);

        if (gy_send_open(p) != GY_OK)
            goto out;
        if (gy_encrypt(p, su, sul, s_did, s_dl, (const uint8_t *)"p0", 2, rmsg,
                       &rlen) != GY_OK) {
            gy_rollback(p);
            goto out;
        }
        if (gy_commit(p) != GY_OK)
            goto out;
        ol = sizeof(out);
        if (gy_receive(s, pu, pul, p_did, p_dl, rmsg, rlen, out, &ol) != GY_OK)
            goto out;
    }

    /* Steady-state sends until the session goes stale. */
    tgt.user_id = pu;
    tgt.user_id_len = pul;
    for (round = 0; round < EXP_MAX_SEND + 3; round++) {
        size_t n = 0, cap, i;
        int status = 0;

        if (gy_send_open(s) != GY_OK)
            goto out;
        if (gy_prepare(s, &tgt, 1, NULL, &n) != GY_OK || n > DEMO_FANOUT_MAX) {
            gy_rollback(s);
            goto out;
        }
        cap = DEMO_FANOUT_MAX;
        if (n > 0 && gy_prepare(s, &tgt, 1, descs, &cap) != GY_OK) {
            gy_rollback(s);
            goto out;
        }
        n = n > 0 ? cap : 0;
        for (i = 0; i < n; i++)
            if (descs[i].device_id_len == p_dl &&
                memcmp(descs[i].device_id, p_did, p_dl) == 0) {
                status = descs[i].status;
                break;
            }

        if (status == GY_FANOUT_MESSAGE) {
            mlen = sizeof(msg);
            if (gy_encrypt(s, pu, pul, p_did, p_dl, (const uint8_t *)"em", 2,
                           msg, &mlen) != GY_OK) {
                gy_rollback(s);
                goto out;
            }
            if (gy_commit(s) != GY_OK)
                goto out;
            ol = sizeof(out);
            if (gy_receive(p, su, sul, s_did, s_dl, msg, mlen, out, &ol) !=
                GY_OK)
                goto out;
            continue;
        }
        if (status == GY_FANOUT_STALE) {
            /* The send path refuses under a stale device: confirm gy_encrypt
             * also returns GY_ERR_EXPIRED in the same open transaction. */
            size_t el = sizeof(msg);
            int erc = gy_encrypt(s, pu, pul, p_did, p_dl, (const uint8_t *)"x",
                                 1, msg, &el);

            gy_rollback(s);
            if (erc != GY_ERR_EXPIRED) {
                fprintf(stderr,
                        "[%s] stale device did not yield GY_ERR_EXPIRED (%d)\n",
                        cfg->name, erc);
                goto out;
            }
            saw_stale = 1;
            printf("[%s] session expired after %d sends: gy_prepare -> STALE, "
                   "gy_encrypt -> GY_ERR_EXPIRED (do not send; re-establish)\n",
                   cfg->name, round);
            break;
        }

        gy_rollback(s);
        fprintf(stderr, "[%s] unexpected fan-out status %d\n", cfg->name,
                status);
        goto out;
    }

    if (!saw_stale) {
        fprintf(stderr, "[%s] session never went stale\n", cfg->name);
        goto out;
    }
    rc = 0;

out:
    gy_custodian_close(s);
    gy_custodian_close(p);
    return rc;
}

/*
 * Demo (hybrid suites only): a Double Ratchet run that crosses an ML-KEM refresh
 * boundary.  A hybrid session mixes a fresh ML-KEM secret into the root KDF on
 * each ratchet step and refreshes its ML-KEM keypair on a fixed interval
 * (HYBRID_SPEC section 6.6).  This runs a long continuous ping-pong over ONE
 * session so the periodic refresh fires mid-conversation; from the consumer's
 * side nothing changes (it just keeps sending), and every message still decrypts
 * across the boundary.  Isolated in-process throwaway custodians (like
 * run_expiration), so there is no coordinator traffic and it cannot perturb the
 * main conversation.  Returns 0 on success, -1 on any failure.
 */
static int
run_kem_refresh(const struct client_cfg *cfg)
{
    struct filestore sfs, pfs;
    gy_store_callbacks scb, pcb;
    gy_custodian *s = NULL, *p = NULL;
    char sdir[FILESTORE_DIR_MAX], pdir[FILESTORE_DIR_MAX];
    uint8_t bundle[CLIENT_BUNDLE_MAX], msg[CLIENT_MSG_MAX], out[64];
    gy_keychange chg;
    const uint8_t *su = (const uint8_t *)"kem-sender";
    const uint8_t *pu = (const uint8_t *)"kem-peer";
    const uint8_t *s_did = (const uint8_t *)"kem-dev-s";
    const uint8_t *p_did = (const uint8_t *)"kem-dev-p";
    size_t sul = strlen("kem-sender"), pul = strlen("kem-peer");
    size_t s_dl = strlen("kem-dev-s"), p_dl = strlen("kem-dev-p");
    size_t need = 0, blen, mlen, ol;
    int rc = -1, round;

    if (snprintf(sdir, sizeof(sdir), "%s-kem-s", cfg->store_dir) >=
            (int)sizeof(sdir) ||
        snprintf(pdir, sizeof(pdir), "%s-kem-p", cfg->store_dir) >=
            (int)sizeof(pdir))
        return -1;
    if (filestore_bind(&sfs, sdir, &scb) != 0 ||
        filestore_bind(&pfs, pdir, &pcb) != 0)
        return -1;

    if (gy_custodian_create(&s, cfg->suite, &scb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), su, sul, s_did, s_dl, NULL, NULL,
                            NULL) != GY_OK)
        return -1;
    if (gy_custodian_create(&p, cfg->suite, &pcb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), pu, pul, p_did, p_dl, NULL, NULL,
                            NULL) != GY_OK)
        goto out;
    if (gy_custodian_generate_identity(s, CLIENT_SPK_TS, 2) != GY_OK ||
        gy_custodian_generate_identity(p, CLIENT_SPK_TS, 2) != GY_OK)
        goto out;

    /* Establish a session: the peer publishes a one-shot bundle, the sender
     * initiates from it, the peer receives (all in-process). */
    blen = sizeof(bundle);
    if (gy_publish_bundle(p, NULL, &need) != GY_OK || need > sizeof(bundle) ||
        gy_publish_bundle(p, bundle, &blen) != GY_OK)
        goto out;
    if (gy_send_open(s) != GY_OK)
        goto out;
    memset(&chg, 0, sizeof(chg));
    mlen = sizeof(msg);
    if (gy_initiate(s, pu, pul, p_did, p_dl, bundle, blen,
                    (const uint8_t *)"k0", 2, &chg, msg, &mlen) != GY_OK) {
        gy_rollback(s);
        goto out;
    }
    if (gy_commit(s) != GY_OK)
        goto out;
    ol = sizeof(out);
    if (gy_receive(p, su, sul, s_did, s_dl, msg, mlen, out, &ol) != GY_OK)
        goto out;

    /* Alternate single messages each direction.  Each direction change is a DH
     * ratchet step (a fresh ML-KEM mix), so the loop crosses the refresh
     * interval; the peer replying first also makes the sender's session ACTIVE
     * so gy_encrypt applies over the live session on both ends. */
    for (round = 0; round < DEMO_KEM_REFRESH_ROUNDS; round++) {
        /* peer -> sender */
        mlen = sizeof(msg);
        if (gy_send_open(p) != GY_OK)
            goto out;
        if (gy_encrypt(p, su, sul, s_did, s_dl, (const uint8_t *)"pr", 2, msg,
                       &mlen) != GY_OK) {
            gy_rollback(p);
            goto out;
        }
        if (gy_commit(p) != GY_OK)
            goto out;
        ol = sizeof(out);
        if (gy_receive(s, pu, pul, p_did, p_dl, msg, mlen, out, &ol) != GY_OK ||
            ol != 2 || memcmp(out, "pr", 2) != 0)
            goto out;

        /* sender -> peer */
        mlen = sizeof(msg);
        if (gy_send_open(s) != GY_OK)
            goto out;
        if (gy_encrypt(s, pu, pul, p_did, p_dl, (const uint8_t *)"sr", 2, msg,
                       &mlen) != GY_OK) {
            gy_rollback(s);
            goto out;
        }
        if (gy_commit(s) != GY_OK)
            goto out;
        ol = sizeof(out);
        if (gy_receive(p, su, sul, s_did, s_dl, msg, mlen, out, &ol) != GY_OK ||
            ol != 2 || memcmp(out, "sr", 2) != 0)
            goto out;
    }
    printf("[%s] hybrid ratchet crossed an ML-KEM refresh boundary over %d "
           "round-trips; every message decrypted\n",
           cfg->name, DEMO_KEM_REFRESH_ROUNDS);
    rc = 0;

out:
    gy_custodian_close(s);
    gy_custodian_close(p);
    return rc;
}

int
client_run(const struct client_cfg *cfg, int coord_rfd, int coord_wfd)
{
    struct filestore fs;
    gy_store_callbacks cb;
    gy_custodian *c = NULL;
    uint64_t tick = CLIENT_CLOCK_BASE;
    int rc = 1;

    if (filestore_bind(&fs, cfg->store_dir, &cb) != 0) {
        fprintf(stderr, "[%s] cannot open store %s\n", cfg->name,
                cfg->store_dir);
        return 1;
    }
    if (gy_custodian_create(&c, cfg->suite, &cb, (const uint8_t *)cfg->cred,
                            strlen(cfg->cred), (const uint8_t *)cfg->name,
                            strlen(cfg->name), (const uint8_t *)self_did(cfg),
                            strlen(self_did(cfg)), demo_clock, &tick,
                            NULL) != GY_OK) {
        fprintf(stderr, "[%s] custodian create failed\n", cfg->name);
        return 1;
    }
    if (gy_custodian_generate_identity(c, CLIENT_SPK_TS, CLIENT_N_OPKS) !=
        GY_OK) {
        fprintf(stderr, "[%s] generate_identity failed\n", cfg->name);
        goto out;
    }

    /* Sealing-at-rest illustration. */
    filestore_dump_identity(&fs);

    if (publish_directory(c, cfg, coord_wfd) != 0) {
        fprintf(stderr, "[%s] publish failed\n", cfg->name);
        goto out;
    }

    /* Demo: identity verification (safety numbers) before messaging. */
    if (verify_identity(c, cfg, coord_rfd, coord_wfd) != 0) {
        fprintf(stderr, "[%s] identity verification failed\n", cfg->name);
        goto out;
    }

    /* Demo: one-shot full-bundle publish beside the granular split.
     * A dedicated throwaway identity per side (never mixing publish models on
     * one pool); completes before the main conversation opens. */
    if (run_oneshot(cfg, coord_rfd, coord_wfd) != 0) {
        fprintf(stderr, "[%s] one-shot bundle scenario failed\n", cfg->name);
        goto out;
    }

    if (cfg->role == CLIENT_INITIATOR)
        rc = run_initiator(c, cfg, coord_rfd, coord_wfd);
    else
        rc = run_responder(c, cfg, coord_rfd, coord_wfd);

    /* the example: prekey lifecycle (OPK depletion/replenish, SPK rotation). */
    if (rc == 0) {
        if (cfg->role == CLIENT_INITIATOR)
            rc = run_initiator_lifecycle(c, cfg, coord_rfd, coord_wfd);
        else
            rc = run_responder_lifecycle(c, cfg, coord_rfd, coord_wfd);
    }

    /* Demo: no-OPK handshake path (valid X3DH, reduced forward
     * secrecy) on a dedicated identity, right after the lifecycle phase. */
    if (rc == 0)
        rc = run_noopk(cfg, coord_rfd, coord_wfd);

    /* the example: SAK-authenticated client -> coordinator request. */
    if (rc == 0)
        rc = run_sak_auth(c, cfg, coord_rfd, coord_wfd);

    /* Demo: peer removal (gy_purge_device / gy_purge_user) and re-add,
     * on the main conversation, before the restart phase. */
    if (rc == 0)
        rc = run_peer_removal(c, cfg, coord_rfd, coord_wfd);

    /* Demo: session expiration policy (gy_config, D-SES-7).  Isolated,
     * in-process, and initiator-only (it exchanges no coordinator traffic), so
     * it neither needs the peer process nor perturbs the main conversation. */
    if (rc == 0 && cfg->role == CLIENT_INITIATOR)
        rc = run_expiration(cfg);

    /* Demo (hybrid suites only): a Double Ratchet run crossing an ML-KEM refresh
     * boundary.  Isolated and in-process like the expiration phase, and skipped
     * for classical suites, which carry no ML-KEM refresh. */
    if (rc == 0 && cfg->role == CLIENT_INITIATOR &&
        cfg->suite == GY_SUITE_H25519_512)
        rc = run_kem_refresh(cfg);

    /* the example: restart persistence.  The responder hands off to a fresh
     * process: it signals a restart, closes its custodian, and exits WITHOUT a
     * GOODBYE - main re-forks it into client_resume, which reopens the sealed
     * store.  The initiator sends a message the resumed peer will receive. */
    if (rc == 0) {
        if (cfg->role == CLIENT_INITIATOR) {
            rc = run_restart_initiator(c, cfg, coord_rfd, coord_wfd);
        } else {
            if (send_frame(coord_wfd, cfg->name, "coordinator",
                           DEMO_MSG_RESTART, 0, NULL, 0) == 0) {
                /* Demo: change the store credential before handing off.
                 * Only the credential-derived PDK is re-wrapped; the KEK and
                 * everything sealed under it are untouched, so the resumed
                 * process reopens with the NEW credential (and the OLD one is
                 * then rejected) with no re-handshake. */
                if (gy_custodian_change_credential(
                        c, (const uint8_t *)CLIENT_NEW_CRED,
                        strlen(CLIENT_NEW_CRED)) != GY_OK) {
                    fprintf(stderr, "[%s] change_credential failed\n",
                            cfg->name);
                    gy_custodian_close(c);
                    return 1;
                }
                printf("[%s] changed store credential (KEK and sealed material "
                       "unchanged); closing for restart\n",
                       cfg->name);
                gy_custodian_close(c);
                return 0; /* exit; main re-forks us into client_resume */
            }
            rc = 1;
        }
    }
    rc = (rc == 0) ? 0 : 1;

    if (rc == 0)
        printf("[%s] conversation complete\n", cfg->name);
out:
    gy_custodian_close(c);
    if (send_frame(coord_wfd, cfg->name, "coordinator", DEMO_MSG_GOODBYE, 0,
                   NULL, 0) != 0)
        rc = 1;
    return rc;
}

int
client_resume(const struct client_cfg *cfg, int coord_rfd, int coord_wfd)
{
    struct filestore fs;
    gy_store_callbacks cb;
    gy_custodian *c = NULL;
    uint8_t out[256];
    size_t ol = sizeof(out);
    int rc;

    if (filestore_bind(&fs, cfg->store_dir, &cb) != 0) {
        fprintf(stderr, "[%s] resume: cannot open store %s\n", cfg->name,
                cfg->store_dir);
        return 1;
    }

    /* Negative: a clearly-wrong passphrase fails with the uniform error and
     * does not corrupt the store (the reopen below then succeeds). */
    rc = gy_custodian_open(&c, &cb, (const uint8_t *)"wrong-passphrase", 16);
    if (rc != GY_ERR_VERIFY) {
        fprintf(stderr,
                "[%s] resume: wrong passphrase not uniformly rejected "
                "(%d)\n",
                cfg->name, rc);
        return 1;
    }
    printf("[%s] wrong passphrase rejected (uniform error); store intact\n",
           cfg->name);

    /* Demo: the OLD credential (valid before the change) is now
     * rejected with the SAME uniform error - proof the credential change took
     * (and that a change is not a bad-credential-vs-corrupt-store oracle). */
    rc = gy_custodian_open(&c, &cb, (const uint8_t *)cfg->cred,
                           strlen(cfg->cred));
    if (rc != GY_ERR_VERIFY) {
        fprintf(stderr,
                "[%s] resume: old credential not rejected after change (%d)\n",
                cfg->name, rc);
        return 1;
    }
    printf("[%s] old credential rejected after change_credential (uniform "
           "error)\n",
           cfg->name);

    /* Reopen with the NEW credential: the re-wrap left the KEK and all sealed
     * material untouched, so session state comes ONLY from the sealed store -
     * no re-handshake, no in-memory state carried across. */
    if (gy_custodian_open(&c, &cb, (const uint8_t *)CLIENT_NEW_CRED,
                          strlen(CLIENT_NEW_CRED)) != GY_OK) {
        fprintf(stderr, "[%s] resume: reopen with new credential failed\n",
                cfg->name);
        return 1;
    }
    printf("[%s] reopened with the new credential (no re-handshake)\n",
           cfg->name);

    /* Receive the message queued during the restart, then reply. */
    if (msg_receive(c, cfg, coord_rfd, coord_wfd, out, &ol) != 0) {
        fprintf(stderr, "[%s] resume: receive failed\n", cfg->name);
        gy_custodian_close(c);
        return 1;
    }
    if (ol != 12 || memcmp(out, "post-restart", 12) != 0) {
        fprintf(stderr, "[%s] resume: queued message mismatch\n", cfg->name);
        gy_custodian_close(c);
        return 1;
    }
    printf("[%s] received the queued message after restart: ratchet survived\n",
           cfg->name);

    rc = msg_send(c, cfg, coord_rfd, coord_wfd, (const uint8_t *)"resumed", 7);
    gy_custodian_close(c);
    if (rc != 0)
        return 1;
    if (send_frame(coord_wfd, cfg->name, "coordinator", DEMO_MSG_GOODBYE, 0,
                   NULL, 0) != 0)
        return 1;
    printf("[%s] resume complete\n", cfg->name);
    return 0;
}
