/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_SEND_H
#define GY_SEND_H

#include <stddef.h>
#include <stdint.h>

#include "lifecycle.h"

/*
 * Sesame send path (the Sesame specification, section 3.3, D-SES-1/7/8/10,
 * D-X3DH-15, D-DR-16).  A message fans out to one INDEPENDENT ciphertext per
 * recipient device (each device has its own session; nothing is shared across
 * devices), so the API is per-session, not batched:
 *
 *   gy_send_begin        open the staging transaction on the shared context
 *   gy_send_prepare      enumerate the fan-out into a descriptor array (which
 *                        devices get a message, need a bundle, or are stale)
 *   gy_send_encrypt      encrypt one device's message on its active session
 *   gy_send_initiate     start a session from a fetched bundle, then encrypt
 *   gy_session_reinitiate  force a fresh initiating session (orphan escape)
 *   gy_send_commit/abort commit the whole fan-out once the server accepts, or
 *                        discard it (D-SES-10)
 *
 * gy_send_encrypt / gy_send_initiate use the OpenSSL-style output convention:
 * call with out == NULL to learn the required size in *out_len, then call again
 * with a buffer of that size (out != NULL, *out_len = capacity in, bytes
 * written out).  The reported size is an upper bound; the second call writes
 * the exact length.  All record and session state stages into the context and
 * touches the store only at gy_send_commit; a server reject is gy_send_abort
 * plus the caller reconciling the device delta with the lifecycle
 * ops (conditional update / delete-device) before re-running preparation.  The
 * section 6.5 bounded retry counter is the application's (suggested 8).
 */

/* One outgoing recipient UserID for the fan-out. */
struct gy_send_target {
    const uint8_t *user_id;
    size_t user_id_len;
};

/* Per-device fan-out disposition. */
enum gy_send_status {
    GY_SEND_MESSAGE = 1,      /* has a usable active session: gy_send_encrypt */
    GY_SEND_NEEDS_BUNDLE = 2, /* no active session: fetch a bundle, initiate */
    GY_SEND_STALE = 3, /* active session expired (D-SES-7): do not send */
};

/* One fan-out descriptor: which device, and what to do with it. */
struct gy_send_desc {
    uint8_t user_id[GY_USER_ID_MAX];
    size_t user_id_len;
    uint8_t device_id[GY_DEVICE_ID_MAX];
    size_t device_id_len;
    enum gy_send_status status;
};

/*
 * Send context.  store/desc/local_ik/aead_id are the sender's fixed identity
 * (local_ik is the sender's own identity key pair, needed to initiate); expiry
 * is the D-SES-7 policy (may be disabled).  self_device_id is the sending
 * device, excluded from its own user's fan-out (section 3.1: the sender's own
 * UserRecord is otherwise treated like any other, so include the sender's
 * UserID among the targets to sync their other devices).  op is the staging
 * arena and is large (~3 MB); the whole context must be heap- or statically
 * allocated, never placed on the stack.
 */
struct gy_send_ctx {
    const struct gy_store *store;
    const struct gy_suite_desc *desc;
    const struct gy_keypair *local_ik;
    uint8_t aead_id;
    struct gy_expiry_cfg expiry;
    const uint8_t *self_user_id;
    size_t self_user_id_len;
    const uint8_t *self_device_id;
    size_t self_device_id_len;

    struct gy_op op;
    int begun;
};

/*
 * Initialize a send context (does not open a transaction).  Copies the scalar
 * fields and the expiry policy; the pointers (store, desc, local_ik,
 * self_user_id, self_device_id) must outlive the context.  self_user_id +
 * self_device_id together identify the sender's own device, excluded from its
 * own user's fan-out (D-SES-12: exclusion is by the (UserID, DeviceID) pair,
 * not DeviceID alone).  Returns GY_ERR_ARG on a NULL required argument.
 */
int gy_send_ctx_init(struct gy_send_ctx *c, const struct gy_store *store,
                     const struct gy_suite_desc *desc,
                     const struct gy_keypair *local_ik, uint8_t aead_id,
                     const struct gy_expiry_cfg *expiry,
                     const uint8_t *self_user_id, size_t self_user_id_len,
                     const uint8_t *self_device_id, size_t self_device_id_len);

/* Open / discard / commit the staging transaction. */
int gy_send_begin(struct gy_send_ctx *c);
void gy_send_abort(struct gy_send_ctx *c);
int gy_send_commit(struct gy_send_ctx *c);

/*
 * Enumerate the fan-out over targets[0..n) into descs (OpenSSL sizing on the
 * count): descs == NULL or too small writes the needed count to *desc_count and
 * returns GY_OK / GY_ERR_ARG respectively; otherwise fills descs and sets
 * *desc_count.  Unknown target UserRecords contribute nothing (their devices
 * arrive via the server reject / bundle-fetch path).  The sender's own sending
 * device (self_device_id) is skipped.  Read-only: stages nothing.
 */
int gy_send_prepare(struct gy_send_ctx *c, const struct gy_send_target *targets,
                    size_t n, struct gy_send_desc *descs, size_t *desc_count);

/*
 * Encrypt one plaintext for one device's active session and stage the advanced
 * session (D-DR-16 wire frame).  Fails with GY_ERR_STATE if the device has no
 * active session and GY_ERR_EXPIRED if that session is expired (D-SES-7: never
 * encrypt under a stale device).  out == NULL reports the size only.
 */
int gy_send_encrypt(struct gy_send_ctx *c, const uint8_t *user_id,
                    size_t user_id_len, const uint8_t *device_id,
                    size_t device_id_len, const uint8_t *pt, size_t ptlen,
                    uint8_t *out, size_t *out_len);

/*
 * Start a session from a fetched (already validated) bundle and encrypt the
 * first message.  Runs the conditional update first: a peer
 * identity-key change fails closed with GY_ERR_KEY_CHANGED (chg filled if not
 * NULL) and the caller must gy_accept_key_change before retrying.  The initial
 * message embeds the complete first DR frame after the X3DH prefix's
 * ciphertext-length field (D-X3DH-15 / D-DR-16).  out == NULL reports the size.
 */
int gy_send_initiate(struct gy_send_ctx *c, const uint8_t *user_id,
                     size_t user_id_len, const uint8_t *device_id,
                     size_t device_id_len,
                     const struct gy_prekey_bundle *bundle, const uint8_t *pt,
                     size_t ptlen, struct gy_key_change *chg, uint8_t *out,
                     size_t *out_len);

/*
 * Explicit re-initiate (D-SES-8 section 4.1(3d) orphan escape): create and
 * insert a FRESH initiating session for a device even if one already exists,
 * demoting the previous active session (ordinary insert semantics).  Identical
 * mechanics to gy_send_initiate; named separately because it is a deliberate
 * application action, not a fan-out consequence.
 */
int gy_session_reinitiate(struct gy_send_ctx *c, const uint8_t *user_id,
                          size_t user_id_len, const uint8_t *device_id,
                          size_t device_id_len,
                          const struct gy_prekey_bundle *bundle,
                          const uint8_t *pt, size_t ptlen,
                          struct gy_key_change *chg, uint8_t *out,
                          size_t *out_len);

/* ------------------------------------------------------------------------- *
 * Hybrid initiation (HYBRID_SPEC section 6).  No separate context type: a
 * hybrid session reuses the classical gy_send_ctx (initialize it with a NULL
 * local_ik, since the hybrid identity is passed per-call), so the transaction
 * lifecycle, fan-out, and steady-state gy_send_encrypt (which dispatches on the
 * loaded session's suite) are all shared.  Only initiation needs the hybrid
 * identity + ML-KEM refresh policy, supplied as arguments below.
 * ------------------------------------------------------------------------- */

/*
 * Start a hybrid session from a fetched (already dual-signature-validated)
 * hybrid bundle and encrypt the first message (section 6.5 initial message).
 * c is a gy_send_ctx pinned to the hybrid suite; local_hik is the sender's
 * hybrid identity key pair; mlkem_interval is the preferred ML-KEM refresh
 * interval, clamped to the peer SPK's signed advertisement (with the AEAD from
 * c->aead_id, section 6.6).  Runs gy_hybrid_conditional_update first
 * (full-identity key-change, GY_ERR_KEY_CHANGED with chg filled on a change),
 * runs hybrid X3DH, starts the hybrid ratchet, and emits the prefix followed by
 * the first DR frame.  out == NULL reports the size.
 */
int gy_send_initiate_hybrid(
    struct gy_send_ctx *c, const struct gy_hybrid_identity_keypair *local_hik,
    uint32_t mlkem_interval, const uint8_t *user_id, size_t user_id_len,
    const uint8_t *device_id, size_t device_id_len,
    const struct gy_hybrid_prekey_bundle *bundle, const uint8_t *pt,
    size_t ptlen, struct gy_key_change *chg, uint8_t *out, size_t *out_len);

#endif /* GY_SEND_H */
