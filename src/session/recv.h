/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_RECV_H
#define GY_RECV_H

#include <stddef.h>
#include <stdint.h>

#include "lifecycle.h"

/*
 * Sesame receive path (the Sesame specification, section 3.4, D-SES-6, D-X3DH-10,
 * D-DR-17).  The milestone's security-critical operation: it decides which
 * session (if any) owns an incoming message, decrypts it, and commits the
 * resulting state transactionally, all under header encryption where the wire
 * carries no routing aid (D-SES-6.6).
 *
 * gy_recv is a single self-committing call: it stages every mutation and
 * commits only when a payload verifies; on ANY failure (no session, bad tag,
 * garbage) it aborts, leaving the store byte-for-byte unchanged and returning
 * one uniform error (D-SES-6.2), so no decryption oracle is exposed.  The
 * caller already holds the sender identifiers it passed in, which is the
 * D-SES-8 undecryptable-with-sender-identifiers signal.  A peer identity-key
 * change on an initiation surfaces distinctly as GY_ERR_KEY_CHANGED (the
 * receive leg of the D-SES-9 matrix).
 *
 * The envelope is the minimal typed framing (proto/ finalizes it):
 * version || suite || msg_type || inner_message, msg_type 0x01 = initiation,
 * 0x02 = Double Ratchet; the inner message's own version/suite must match the
 * outer (D-GEN-1 amendment).
 */

#define GY_MSG_INIT 0x01 /* inner is an X3DH initial message (D-X3DH-15) */
#define GY_MSG_DR 0x02   /* inner is a Double Ratchet frame (D-DR-16) */

/* Optional monotone clock (D-SES-7: time enters only through a callback). */
typedef uint64_t (*gy_recv_clock_fn)(void *ctx);

/*
 * Receive context.  store/desc/aead_id/expiry mirror the send context.
 * local_ik/spks/opks are the RESPONDER material used to answer an initiation
 * (the application unseals them from its store, D-GEN-4).  spks[0..n_spks) is
 * the CURRENT signed prekey plus any retained history (D-X3DH-5
 * rotation): an initiation's spk_id is public wire data (carried in the
 * clear), so recv_init trying each candidate in turn until one matches leaks
 * nothing new via timing.  An unknown SPK/OPK by PKID (matching none of
 * spks[]) fails the handshake uniformly (no prekey oracle, D-X3DH-10).  clock
 * (if set) stamps last_recv_at for D-SES-7 stale tracking.  op is the ~3 MB
 * staging arena, so the whole context must be heap- or statically allocated.
 * last_sessions_tried records how many candidate sessions the DR association
 * walked on the most recent gy_recv (the D-SES-6 session-order metric).
 */
struct gy_recv_ctx {
    const struct gy_store *store;
    const struct gy_suite_desc *desc;
    uint8_t aead_id;
    struct gy_expiry_cfg expiry;

    const struct gy_keypair *local_ik;
    const struct gy_keypair *spks;
    size_t n_spks;
    const struct gy_keypair *opks;
    size_t n_opks;

    gy_recv_clock_fn clock;
    void *clock_ctx;

    unsigned last_sessions_tried;

    struct gy_op op;
};

/*
 * Initialize a receive context.  store/desc/local_ik are required; spks must
 * be non-NULL with n_spks >= 1 (the current SPK, plus any retained
 * history); opks may be NULL with n_opks 0 (no one-time prekeys stocked);
 * expiry/clock may be NULL.  The pointers must outlive the context.  Returns
 * GY_ERR_ARG on a NULL/empty required argument.
 */
int gy_recv_ctx_init(struct gy_recv_ctx *c, const struct gy_store *store,
                     const struct gy_suite_desc *desc,
                     const struct gy_keypair *local_ik,
                     const struct gy_keypair *spks, size_t n_spks,
                     const struct gy_keypair *opks, size_t n_opks,
                     uint8_t aead_id, const struct gy_expiry_cfg *expiry,
                     gy_recv_clock_fn clock, void *clock_ctx);

/*
 * Receive one enveloped message from (user_id, device_id) and recover its
 * plaintext.  out uses the OpenSSL-style sizing convention: out == NULL writes
 * an upper bound to *out_len (and touches nothing); otherwise *out_len is the
 * capacity in and the plaintext length out.  On success the session state and
 * any activation (D-SES-5) / initiation records are committed.  Returns GY_OK,
 * GY_ERR_KEY_CHANGED on a surfaced peer key change, GY_ERR_ARG on a NULL
 * argument or short output buffer, or GY_ERR_VERIFY as the single uniform
 * "message rejected" outcome (D-SES-6.2).
 */
int gy_recv(struct gy_recv_ctx *c, const uint8_t *user_id, size_t user_id_len,
            const uint8_t *device_id, size_t device_id_len, const uint8_t *msg,
            size_t msg_len, uint8_t *out, size_t *out_len);

#endif /* GY_RECV_H */
