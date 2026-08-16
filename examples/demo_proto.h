/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Wire protocol for the geryon end-to-end example.  This is the
 * IPC framing spoken between the untrusted coordinator and the two clients,
 * NOT the geryon protocol: every geryon ciphertext or public bundle travels
 * as an opaque payload inside a demo frame, and the coordinator never parses
 * a payload it is only relaying.
 *
 * A frame is a fixed-size header (which carries the payload length) followed
 * by exactly data_len opaque bytes.  The reader always reads the header in
 * full, then the announced payload in full, so the stream stays framed even
 * across short pipe reads.
 *
 * the example exercises only PING/PONG/GOODBYE; the publish/fetch/mailbox
 * message types are declared here now and handled in later tickets.
 */

#ifndef GERYON_DEMO_PROTO_H
#define GERYON_DEMO_PROTO_H

#include <stddef.h>
#include <stdint.h>

/* Client name field width, including the NUL terminator. */
#define DEMO_NAME_MAX 32

/* Upper bound on a single frame payload (an assembled bundle or a
 * ciphertext record both sit comfortably under this). */
#define DEMO_MAX_PAYLOAD (64u * 1024u)

/*
 * Canonical domain-separation context both sides feed to gy_custodian_sign /
 * gy_appkey_verify for a SAK-authenticated request.  The signed
 * request bytes are method || target || body-hash; freshness/anti-replay is
 * out of scope for the example.
 */
#define DEMO_AUTH_CTX "geryon-demo/req-v1"

enum demo_msg_type {
    /* Liveness round-trip. */
    DEMO_MSG_PING = 1,
    DEMO_MSG_PONG,

    /* Directory publish/fetch. */
    DEMO_MSG_PUBLISH_REGISTRATION,
    DEMO_MSG_PUBLISH_OPK_BATCH,
    DEMO_MSG_FETCH_BUNDLE,
    DEMO_MSG_BUNDLE,

    /* Mailbox relay. */
    DEMO_MSG_SEND,    /* client -> coordinator: relay this ciphertext */
    DEMO_MSG_RECV,    /* client -> coordinator: give me my next message */
    DEMO_MSG_DELIVER, /* coordinator -> client: here is a message */
    DEMO_MSG_NO_MAIL, /* coordinator -> client: nothing queued */

    /* SAK-authenticated requests. */
    DEMO_MSG_PUBLISH_CERT, /* client -> coordinator: my SAK certificate */
    DEMO_MSG_AUTH_REQ,     /* client -> coordinator: a SAK-signed request */
    DEMO_MSG_AUTH_OK,      /* coordinator -> client: signature verified */
    DEMO_MSG_AUTH_FAIL,    /* coordinator -> client: signature rejected */

    /* SAK rotation: after gy_custodian_rotate_appkey the client
     * publishes the NEW cert as active and the retained PRIOR cert separately;
     * the coordinator accepts a request that verifies against EITHER during the
     * rotation window (the retained-history property, mirroring SPK rotation). */
    DEMO_MSG_PUBLISH_PRIOR_CERT, /* client -> coordinator: my retained prior SAK cert */

    /* Identity verification: safety-number exchange.  A client
     * publishes its own gy_self_fingerprint, then fetches a peer's identity
     * (published registration plus that self-fingerprint) so it can derive the
     * peer's fingerprint locally with gy_bundle_fingerprint and compare. */
    DEMO_MSG_PUBLISH_FINGERPRINT, /* client -> coordinator: my self-fingerprint */
    DEMO_MSG_FETCH_IDENTITY, /* client -> coordinator: peer's reg + self-fp */
    DEMO_MSG_IDENTITY, /* coordinator -> client: fp_len_be16 || fp || registration */

    /* One-shot full-bundle publish.  A client publishes a
     * complete gy_publish_bundle output (IK + signed SPK + one reserved OPK)
     * that a peer fetches and feeds straight to gy_initiate, with NO
     * server-side assembly.  gy_publish_bundle RESERVES an OPK from its own
     * pool, so a one-shot identity must never also publish through the granular
     * registration+OPK-batch path (they would draw from one pool); the demo
     * uses a dedicated one-shot identity to honor that. */
    DEMO_MSG_PUBLISH_ONESHOT, /* client -> coordinator: my one-shot full bundle */
    DEMO_MSG_FETCH_ONESHOT, /* client -> coordinator: peer's one-shot bundle */
    DEMO_MSG_ONESHOT,       /* coordinator -> client: the one-shot bundle */

    /* No-OPK handshake path.  A client publishes a registration
     * for a deliberately OPK-less fetch; the coordinator assembles the bundle
     * with gy_bundle_assemble(..., opk_pub == NULL) so the peer initiates an
     * X3DH session with NO one-time prekey (valid, but reduced forward secrecy).
     * Kept on a dedicated identity so it neither draws a directory OPK nor
     * perturbs the main conversation.  The reply reuses DEMO_MSG_BUNDLE. */
    DEMO_MSG_PUBLISH_NOOPK_REG, /* client -> coordinator: my no-OPK-path registration */
    DEMO_MSG_FETCH_NOOPK, /* client -> coordinator: peer's registration, no OPK */

    /* Restart handoff: the sender is exiting and should be
     * re-forked; its sealed store persists, the coordinator's state persists. */
    DEMO_MSG_RESTART,

    /* Orderly teardown, and a uniform failure reply. */
    DEMO_MSG_GOODBYE,
    DEMO_MSG_ERROR
};

/*
 * Fixed-size frame header.  Written and read as a raw struct: the example is
 * a same-host fork demo, so both ends share one ABI and no on-wire byte
 * layout portability is claimed.  data_len bounds the opaque payload that
 * follows; from/to name the logical endpoints (the coordinator routes by
 * "to", never by inspecting the payload).  seq is a per-(sender,recipient)
 * message number the untrusted relay uses to apply its delivery schedule
 *; it is transport metadata, never part
 * of the sealed ciphertext.
 */
struct demo_frame_header {
    uint32_t type;            /* enum demo_msg_type */
    uint32_t data_len;        /* opaque payload byte count */
    uint32_t seq;             /* per-(sender,recipient) message number */
    char from[DEMO_NAME_MAX]; /* sender logical name */
    char to[DEMO_NAME_MAX];   /* recipient logical name */
};

#endif /* GERYON_DEMO_PROTO_H */
