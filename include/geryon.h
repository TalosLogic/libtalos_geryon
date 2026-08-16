/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * libtalos_geryon: a clean-room C17 implementation of the Signal protocol
 * (X3DH, Double Ratchet, Sesame, XEdDSA).  This is the ONLY installed
 * header and the entire public API surface; everything else is internal.
 *
 * ABI FROZEN as of v1.0.0 (GY_VERSION_MAJOR 1): handle-based key custody
 * (D-CUST-1) is the public surface this freeze covers.  The public struct
 * layouts, the wire format (protocol_version 0x01), and stored-blob formats
 * are frozen from here; breaking changes require a major bump.  The numeric
 * error codes have been stable from day one.  Later suites arrive
 * additively as minor bumps.
 *
 * ---------------------------------------------------------------------------
 * Concurrency (D-GEN-8): a gy_custodian is NOT thread-safe and is NOT
 * re-entrant.  A single custodian must be used from one thread at a time, and
 * no gy_* call on a custodian may be made from within a store callback it
 * invoked (the library asserts this in debug builds).  Use one custodian per
 * thread, or serialize.
 *
 * Post-quantum: the classical suites (geryon_c25519, geryon_c448) provide NO
 * post-quantum confidentiality; they exist for size- and bandwidth-constrained
 * deployments.
 *
 * Custody (D-CUST-1, CUSTODY_SPEC): the library, not the application, is the
 * custodian of every private key it generates.  The application still owns
 * the storage MEDIUM via gy_store_callbacks, but the identity, prekey, and
 * record blobs it is handed are already library-sealed (AEAD-wrapped under a
 * KEK the application never sees); it persists opaque bytes and MUST NOT try
 * to parse or reseal them.  No public entry point returns cleartext private
 * key material: outputs are opaque handles, public key bytes, or sealed
 * blobs.  gy_custodian_open requires the same credential (or the wrapping
 * hardware, in a later Stage-2 backend) that created the custodian; a wrong
 * credential and a corrupt store both fail with the single uniform
 * GY_ERR_VERIFY (no bad-credential-vs-corrupt-store oracle).
 *
 * No plaintext retention (D-SES-8): geryon never stores message plaintext.
 * Retry/resend and any MessageRecord retention are application scope.
 *
 * Send loop (Sesame 6.5, REQUIRED): a send that the server rejects with a
 * stale device list must be retried a BOUNDED number of times (reconcile the
 * delta, re-prepare, resend).  The library exposes exactly one iteration; the
 * bounded retry counter is the application's responsibility (suggested max 8).
 * ---------------------------------------------------------------------------
 */

#ifndef GERYON_H
#define GERYON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(GY_BUILD) && (defined(__GNUC__) || defined(__clang__))
#define GY_EXPORT __attribute__((visibility("default")))
#else
#define GY_EXPORT
#endif

/* ---- versioning -------------------------------------------------------- */

#define GY_VERSION_MAJOR 1
#define GY_VERSION_MINOR 0
#define GY_VERSION_PATCH 0
#define GY_PROTOCOL_VERSION 0x01 /* wire version byte (D-GEN-1). */

/* ---- cipher suites (pinned per identity, never negotiated) ------------- */

#define GY_SUITE_C25519 0x01     /* X25519 + XEdDSA, SHA-256 (classical). */
#define GY_SUITE_H25519_512 0x02 /* reserved for a future suite. */
#define GY_SUITE_C448 0x03       /* X448 + XEd448, SHA-512 (classical). */
#define GY_SUITE_H448_1024 0x04  /* reserved for a future suite. */

/*
 * Error codes (ABI-stable; every code documented).  Defined as macros so they
 * coexist with the identically-valued internal codes; the values are the
 * public contract.
 */
#define GY_OK 0          /* Success. */
#define GY_ERR_ARG -1    /* NULL/short argument or a bad length. */
#define GY_ERR_CRYPTO -2 /* Underlying crypto provider failure. */
#define GY_ERR_VERIFY                                                          \
    -3                     /* Signature/tag/comparison mismatch; also the
                             * single UNIFORM error a rejected received message
                             * returns (D-SES-6.2): no session, bad tag, and
                             * garbage are indistinguishable to callers. */
#define GY_ERR_TOOLONG -4  /* Input exceeds a protocol length bound. */
#define GY_ERR_WEAK_KEY -5 /* Degenerate/all-zero DH output. */
#define GY_ERR_STATE                                                           \
    -6                        /* Operation invalid in the current state, or a
                             * cross-suite message (downgrade signal). */
#define GY_ERR_UNSUPPORTED -7 /* Feature unavailable on this build/CPU. */
#define GY_ERR_KEY_CHANGED                                                     \
    -8 /* Peer identity key changed; fail-closed until
                               * gy_accept_identity (fingerprints in the
                               * gy_keychange out-struct). */
#define GY_ERR_EXPIRED                                                         \
    -9 /* Session past its expiration bound (never encrypt
                             * under a stale session). */
#define GY_ERR_NOT_FOUND                                                       \
    -10 /* Custodian lifecycle: unknown key handle or key id.
                              * Kept off the receive/verify
                              * path (D-SES-6.2 keeps GY_ERR_VERIFY uniform). */
#define GY_ERR_NO_SPACE                                                        \
    -11 /* Custodian lifecycle: key-slot table exhausted;
                              * a fixed HSM-style bound, not
                              * runtime-mutable. */

/* ---- bounds (mirror the internal record model) ------------------------- */

#define GY_USER_ID_MAX 64
#define GY_DEVICE_ID_MAX 64
#define GY_FINGERPRINT_MAX 64
#define GY_SESSION_ID_LEN 4

/* ---- store callbacks (D-SES-10; the application's storage) -------------- */

/* Record kinds passed to the record callbacks (keying is the app's). */
#define GY_RECORD_USER 1
#define GY_RECORD_DEVICE 2
#define GY_RECORD_SESSION 3

/* Prekey kinds passed to the prekey load callback. */
#define GY_PK_SPK 1
#define GY_PK_OPK 2

/*
 * Application storage.  Every callback returns GY_OK or a negative gy_error.  A
 * load of an absent record returns GY_OK with *out_len == 0 ("not found"), not
 * an error.  The record callbacks receive COMPLETE post-operation blobs, never
 * incremental mutations (D-SES-10).  consume_opk marks a one-time prekey used
 * and is invoked ONLY after a first message verifies (D-X3DH-10); one-time
 * prekeys are genuinely one-time - geryon destroys the OPK's private key the
 * moment it is used to establish a session (delete-on-use), so a reused OPK
 * cannot establish a second session even if it is offered again.  ctx is
 * passed back to every callback unchanged.
 */
typedef struct gy_store_callbacks {
    void *ctx;
    int (*load_record)(void *ctx, int kind, const uint8_t *id, size_t id_len,
                       uint8_t *out, size_t cap, size_t *out_len);
    int (*store_record)(void *ctx, int kind, const uint8_t *id, size_t id_len,
                        const uint8_t *blob, size_t blob_len);
    int (*delete_record)(void *ctx, int kind, const uint8_t *id, size_t id_len);
    int (*load_identity)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    int (*store_identity)(void *ctx, const uint8_t *blob, size_t blob_len);
    int (*load_prekey)(void *ctx, int kind, uint32_t pkid, uint8_t *out,
                       size_t cap, size_t *out_len);
    int (*consume_opk)(void *ctx, uint32_t pkid);
} gy_store_callbacks;

/* Optional monotone clock (D-SES-7: time enters only through this callback). */
typedef uint64_t (*gy_clock_fn)(void *ctx);

/*
 * Optional expiration policy (D-SES-7).  When enabled != 0 the section 4.2
 * inequality max_recv > max_send + 2*max_latency is enforced at
 * gy_custodian_create.  Expiration is OFF when cfg is NULL or enabled == 0.
 */
typedef struct gy_config {
    int enabled;
    uint32_t max_send;
    uint32_t max_recv;
    uint64_t max_latency;
} gy_config;

/* Old/new identity fingerprints surfaced on GY_ERR_KEY_CHANGED (D-X3DH-11). */
typedef struct gy_keychange {
    size_t fp_len;
    uint8_t old_fp[GY_FINGERPRINT_MAX];
    uint8_t new_fp[GY_FINGERPRINT_MAX];
} gy_keychange;

/* ---- send fan-out ------------------------------------------------------ */

/* A recipient UserID for gy_prepare. */
typedef struct gy_target {
    const uint8_t *user_id;
    size_t user_id_len;
} gy_target;

/* Per-device fan-out disposition from gy_prepare. */
#define GY_FANOUT_MESSAGE 1      /* has a usable session: gy_encrypt. */
#define GY_FANOUT_NEEDS_BUNDLE 2 /* no session: fetch a bundle, gy_initiate. */
#define GY_FANOUT_STALE 3        /* session expired (D-SES-7): do not send. */

typedef struct gy_fanout_desc {
    uint8_t user_id[GY_USER_ID_MAX];
    size_t user_id_len;
    uint8_t device_id[GY_DEVICE_ID_MAX];
    size_t device_id_len;
    int status; /* GY_FANOUT_* */
} gy_fanout_desc;

/* PQ-authentication states (classical suites are always NOT_APPLICABLE). */
#define GY_PQ_NOT_APPLICABLE 0
#define GY_PQ_PENDING 1
#define GY_PQ_CONFIRMED 2

/*
 * Opaque custody object: one identity, HSM-style (D-CUST-1, CUSTODY_SPEC).
 * Holds the unlocked KEK and identity/prekey material in guarded memory, this
 * device's addresses, and the store/clock callbacks.  One custodian is one
 * identity; it is the object every protocol operation below takes.  There is
 * no gy_ctx: the custodian subsumes that role and, unlike it, never hands
 * private key bytes across the API.
 */
typedef struct gy_custodian gy_custodian;

/* An opaque, process-local, non-forgeable reference to a key object the
 * custodian holds.  0 is the reserved invalid handle
 * (D-GEN-2 zero-sentinel); the key TYPE lives in the custodian's internal
 * slot, never in the handle's bits.  Meaningless across processes or across
 * a close/reopen; the durable cross-process reference is a stable persisted
 * key id. */
typedef uint32_t gy_key_handle;
#define GY_KEY_HANDLE_INVALID ((gy_key_handle)0)

/*
 * Output-buffer convention (OpenSSL-style) used by gy_encrypt, gy_initiate,
 * gy_reinitiate, gy_receive, gy_publish_bundle, gy_self_fingerprint: call with
 * out == NULL to write the required size into *out_len (touching nothing);
 * call again with a buffer of at least that size (out != NULL, *out_len = the
 * capacity in, bytes written out).  gy_prepare uses the same convention on its
 * descriptor COUNT.
 */

/* ---- lifecycle (D-CUST-1; CUSTODY_SPEC sections 3-4, 7) ----------------- */

/*
 * Create a fresh custodian: mint a random KEK, protect it under (cred,
 * cred_len) at the library's fixed Argon2id floor (not caller-lowerable),
 * and persist the sealed bootstrap state through store.  suite_id is pinned
 * here and never negotiated.  self_user_id/self_device_id name this device
 * (excluded from its own fan-out, section 3.1).  clock/cfg may be NULL.  No
 * identity key material exists yet (call gy_custodian_generate_identity
 * next).  On success *out owns a heap allocation freed by
 * gy_custodian_close.  Returns GY_OK, GY_ERR_ARG on a bad argument or
 * unknown suite, GY_ERR_CRYPTO on RNG/allocation failure.
 */
GY_EXPORT int gy_custodian_create(gy_custodian **out, uint8_t suite_id,
                                  const gy_store_callbacks *store,
                                  const uint8_t *cred, size_t cred_len,
                                  const uint8_t *self_user_id,
                                  size_t self_user_id_len,
                                  const uint8_t *self_device_id,
                                  size_t self_device_id_len, gy_clock_fn clock,
                                  void *clock_ctx, const gy_config *cfg);

/*
 * Open an existing custodian: recover the KEK from the sealed bootstrap
 * state and (cred, cred_len), and reload any previously generated identity/
 * prekey material into guarded memory.  A wrong credential and a corrupt or
 * tampered store both fail with the single uniform GY_ERR_VERIFY (CUSTODY_
 * SPEC section 15: no bad-credential-vs-corrupt-store oracle).  Returns
 * GY_ERR_STATE if no custodian was ever created in this store.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_open(gy_custodian **out,
                                const gy_store_callbacks *store,
                                const uint8_t *cred, size_t cred_len);

/* Lock: zeroize the KEK and all unlocked material, and free *c (safe on NULL). */
GY_EXPORT void gy_custodian_close(gy_custodian *c);

/*
 * Wipe this identity: zeroize and delete all custodied material and return
 * the store to absent.  Distinct from gy_purge_device / gy_purge_user, which
 * remove PEER records; reset removes the LOCAL identity.  c must be
 * unlocked; frees *c like gy_custodian_close.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
GY_EXPORT int gy_custodian_reset(gy_custodian *c);

/*
 * Credential change: re-derive the PDK from new_cred and re-wrap the
 * current live KEK; the KEK and everything sealed under it are untouched
 * (D-CUST-1 item 6).  This is NOT recovery from a compromised credential
 * (full KEK rotation is a later increment).  Returns GY_OK or a negative
 * GY_ERR_*.
 */
GY_EXPORT int gy_custodian_change_credential(gy_custodian *c,
                                             const uint8_t *new_cred,
                                             size_t new_cred_len);

/*
 * Generate this identity's key material: the identity key pair, one signed
 * prekey (signed at spk_timestamp), and n_opks one-time prekeys (0 for none,
 * up to the batch cap).  Sealed and persisted immediately; never returned in
 * the clear.  c must be unlocked and must not already have generated an
 * identity (regeneration/rotation is a later increment).  Returns GY_OK or a
 * negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_generate_identity(gy_custodian *c,
                                             uint64_t spk_timestamp,
                                             size_t n_opks);

/*
 * Serialize a complete one-shot prekey bundle (public material: IK + active
 * signed prekey + one one-time prekey), ready to hand a peer directly for
 * gy_initiate without any server-side assembly - the directory-less path.
 * This RESERVES the one-time prekey it emits (minting a fresh one if the pool
 * is spent) so no later publish hands out the same key; it is therefore a
 * MUTATING, persisting call, not a query, on the out != NULL invocation.  Do
 * NOT mix it with the granular publish model (gy_custodian_publish_registration
 * + gy_custodian_publish_opk_batch) for one identity: pick one, since both draw
 * the same one-time-prekey pool.  Same OpenSSL-style sizing convention.
 */
GY_EXPORT int gy_publish_bundle(gy_custodian *c, uint8_t *out, size_t *out_len);

/* Write this identity's fingerprint (D-X3DH-11); display encoding is app scope. */
GY_EXPORT int gy_self_fingerprint(gy_custodian *c, uint8_t *out,
                                  size_t *out_len);

/* ---- send (staged; commit on server accept, D-SES-10) ------------------ */

/* Open the send transaction (stages until gy_commit / gy_rollback). */
GY_EXPORT int gy_send_open(gy_custodian *c);

/*
 * Enumerate the fan-out over targets[0..n) into descs (sizing convention on the
 * count).  Unknown users contribute nothing (they arrive via the reject/bundle
 * path).  Read-only.  Requires an open send transaction.
 */
GY_EXPORT int gy_prepare(gy_custodian *c, const gy_target *targets, size_t n,
                         gy_fanout_desc *descs, size_t *desc_count);

/* Encrypt one plaintext for one device's active session (GY_ERR_EXPIRED if stale). */
GY_EXPORT int gy_encrypt(gy_custodian *c, const uint8_t *user_id,
                         size_t user_id_len, const uint8_t *device_id,
                         size_t device_id_len, const uint8_t *pt, size_t ptlen,
                         uint8_t *out, size_t *out_len);

/*
 * Start a session from a fetched (serialized) bundle and encrypt the first
 * message.  A peer key change fails closed with GY_ERR_KEY_CHANGED (chg filled
 * if non-NULL); call gy_accept_identity, then retry.
 */
GY_EXPORT int gy_initiate(gy_custodian *c, const uint8_t *user_id,
                          size_t user_id_len, const uint8_t *device_id,
                          size_t device_id_len, const uint8_t *bundle,
                          size_t bundle_len, const uint8_t *pt, size_t ptlen,
                          gy_keychange *chg, uint8_t *out, size_t *out_len);

/* Force a fresh initiating session (Sesame 4.1 orphan escape, D-SES-8). */
GY_EXPORT int gy_reinitiate(gy_custodian *c, const uint8_t *user_id,
                            size_t user_id_len, const uint8_t *device_id,
                            size_t device_id_len, const uint8_t *bundle,
                            size_t bundle_len, const uint8_t *pt, size_t ptlen,
                            gy_keychange *chg, uint8_t *out, size_t *out_len);

/* Commit / discard the staged send fan-out. */
GY_EXPORT int gy_commit(gy_custodian *c);
GY_EXPORT void gy_rollback(gy_custodian *c);

/* ---- receive (self-committing; uniform failure, D-SES-6.2) ------------- */

/*
 * Receive one enveloped message from (user_id, device_id) and recover its
 * plaintext.  On success the session state (and any activation / initiation
 * records) is committed; on ANY rejection the store is untouched and the return
 * is the uniform GY_ERR_VERIFY.  A peer key change surfaces as
 * GY_ERR_KEY_CHANGED.
 */
GY_EXPORT int gy_receive(gy_custodian *c, const uint8_t *user_id,
                         size_t user_id_len, const uint8_t *device_id,
                         size_t device_id_len, const uint8_t *msg,
                         size_t msg_len, uint8_t *out, size_t *out_len);

/* ---- lifecycle management (peer records) -------------------------------- */

/*
 * Accept a peer identity-key change from a fetched bundle (Sesame 3.2
 * replacement): install the new key and delete the old key's sessions.  Commits
 * immediately.  Returns GY_ERR_STATE if the device is unknown.
 */
GY_EXPORT int gy_accept_identity(gy_custodian *c, const uint8_t *user_id,
                                 size_t user_id_len, const uint8_t *device_id,
                                 size_t device_id_len, const uint8_t *bundle,
                                 size_t bundle_len);

/* Delete a device / an entire user and zeroize their records (D-SES-2). */
GY_EXPORT int gy_purge_device(gy_custodian *c, const uint8_t *user_id,
                              size_t user_id_len, const uint8_t *device_id,
                              size_t device_id_len);
GY_EXPORT int gy_purge_user(gy_custodian *c, const uint8_t *user_id,
                            size_t user_id_len);

/*
 * Query a peer device's PQ-authentication state.  Returns
 * GY_PQ_NOT_APPLICABLE for the classical suites (reserved so a future suite
 * can report it additively), or a negative gy_error.
 */
GY_EXPORT int gy_pq_pending(gy_custodian *c, const uint8_t *user_id,
                            size_t user_id_len, const uint8_t *device_id,
                            size_t device_id_len);

/* ---- prekey lifecycle (CUSTODY_SPEC section 9) ------------------------- */

/*
 * Rotate the signed prekey: mint a new identity-signed, timestamped SPK
 * (D-X3DH-4/5) and make it active.  The superseded SPK is RETAINED (a fixed
 * history depth) so a session established against it still receives; the
 * oldest is zeroized once history is full.  c must have a generated
 * identity.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_rotate_signed_prekey(gy_custodian *c,
                                                uint64_t spk_timestamp);

/*
 * Generate count additional one-time prekeys into the pool (without
 * touching the identity or SPK).  count is 1..the batch cap: 0 or a count
 * above the cap is GY_ERR_ARG, and an in-range count with no room left in
 * the pool is GY_ERR_NO_SPACE.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_generate_onetime_prekeys(gy_custodian *c,
                                                    size_t count);

/* Pool observability: total held, consumed, and unused OPKs.  Any out
 * pointer may be NULL.  Returns GY_OK or a negative GY_ERR_*. */
GY_EXPORT int gy_custodian_opk_stats(gy_custodian *c, size_t *total,
                                     size_t *used, size_t *unused);

/*
 * Publish the identity+current-SPK registration ONLY (never an OPK - see
 * gy_custodian_publish_opk_batch for that).  The low-churn granular-publish
 * call: made at identity creation and on SPK rotation.  Same OpenSSL-style
 * sizing convention as gy_publish_bundle.  Returns GY_ERR_STATE if
 * no identity has been generated.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_publish_registration(gy_custodian *c, uint8_t *out,
                                                size_t *out_len);

/*
 * Emit every currently unused, unconsumed OPK's public key as one batch:
 * the high-churn granular-publish call, independent of
 * gy_custodian_publish_registration.  Same sizing convention.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_publish_opk_batch(gy_custodian *c, uint8_t *out,
                                             size_t *out_len);

/*
 * Map a server-reported PKID (kind: GY_PK_SPK or GY_PK_OPK) back to the
 * local handle, so the application can query or delete it.  Returns the
 * handle, or GY_KEY_HANDLE_INVALID if kind/pkid names nothing currently
 * held.
 */
GY_EXPORT gy_key_handle gy_custodian_find_prekey(gy_custodian *c, int kind,
                                                 uint32_t pkid);

/*
 * Delete a prekey (a retained SPK history entry, or an OPK) by handle,
 * zeroizing it; the handle is freed.  Deleting the currently active SPK is
 * refused (GY_ERR_STATE - rotate first).  Returns GY_ERR_NOT_FOUND on a
 * stale/unknown handle.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_delete_prekey(gy_custodian *c, gy_key_handle h);

/*
 * Server-side bundle assembly: a FREE function, no custodian (like
 * gy_appkey_verify).  Combines a published registration
 * (IK + signed SPK from gy_custodian_publish_registration) with one OPK
 * public key (sliced from a gy_custodian_publish_opk_batch batch; opk_pub
 * may be NULL/0 to assemble a bundle with no OPK) into the serialized
 * bundle gy_initiate consumes.  Same OpenSSL-style sizing convention.
 * Returns GY_OK, or GY_ERR_ARG if registration already carries an OPK (not
 * a registration) or the shapes are malformed.
 */
GY_EXPORT int gy_bundle_assemble(const uint8_t *registration, size_t reg_len,
                                 const uint8_t *opk_pub, size_t opk_len,
                                 uint8_t *out, size_t *out_len);

/*
 * Enumerate a published OPK batch (gy_custodian_publish_opk_batch) on the
 * server side, so a key directory can hand out one OPK per fetch and feed it
 * to gy_bundle_assemble.  FREE functions, no custodian (like
 * gy_bundle_assemble).  gy_opk_batch_count reports how many OPK public keys
 * the batch holds.  gy_opk_batch_get yields a zero-copy pointer to the
 * index-th key IN PLACE (valid while batch stays alive), in the exact wire
 * form gy_bundle_assemble's opk_pub expects; the leading 4 bytes are that
 * OPK's PKID (big-endian), so the directory can track which it has consumed.
 * An index at or past the count is GY_ERR_NOT_FOUND; a malformed batch is
 * GY_ERR_ARG.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_opk_batch_count(const uint8_t *batch, size_t batch_len,
                                 size_t *count);
GY_EXPORT int gy_opk_batch_get(const uint8_t *batch, size_t batch_len,
                               size_t index, const uint8_t **opk_pub,
                               size_t *opk_len);

/*
 * Extract the raw identity public key from a published registration
 * (gy_custodian_publish_registration), server-side.  A FREE function, no
 * custodian and no private key (like gy_bundle_assemble / gy_appkey_verify):
 * a directory pins a client's IK for gy_appkey_verify's identity_pub argument
 * (TOFU on first publish) without holding any secret.  *ik_pub is a zero-copy
 * pointer into registration (valid while it stays alive); *ik_len is the
 * suite's curve_pk_len.  A malformed registration is GY_ERR_ARG.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_registration_identity_pub(const uint8_t *registration,
                                           size_t reg_len,
                                           const uint8_t **ik_pub,
                                           size_t *ik_len);

/*
 * Fingerprint the identity key inside a fetched bundle or a published
 * registration (public bytes; either wire shape is accepted).  A FREE
 * function, no custodian and no private key (like gy_bundle_assemble /
 * gy_registration_identity_pub): it lets an app render a PEER's safety number
 * for out-of-band identity verification, the counterpart to the custodian's
 * own gy_self_fingerprint.  The output is byte-identical to that peer's own
 * gy_self_fingerprint and to gy_keychange.new_fp for the same identity, so the
 * two sides can compare and match.  The suite is read from the serialized
 * bytes; sizing follows the OpenSSL-style out == NULL convention.  A malformed
 * buffer or unknown suite is GY_ERR_ARG.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_bundle_fingerprint(const uint8_t *bundle, size_t bundle_len,
                                    uint8_t *out, size_t *out_len);

/* ---- application signing key (CUSTODY_SPEC section 10) ----------------- */

/*
 * Mint a fresh application signing key (XEdDSA, classical suite only this
 * milestone), certify it with the identity key, seal, and persist.  c must
 * have a generated identity and must NOT already hold a SAK (GY_ERR_STATE;
 * use gy_custodian_rotate_appkey to replace one).  expiry is a caller-
 * chosen absolute time bound (0 = no expiry); the library never reads a
 * clock.  The identity key is NEVER used for request signing.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_generate_appkey(gy_custodian *c, uint64_t expiry,
                                           gy_key_handle *out);

/*
 * Mint a new SAK and make it active; the superseded SAK is RETAINED (a
 * fixed history depth, the same shape as gy_custodian_rotate_signed_prekey)
 * so in-flight verification against a not-yet-refreshed cert still works,
 * with the oldest zeroized once history is full.  c must already hold a
 * SAK.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_rotate_appkey(gy_custodian *c, uint64_t expiry,
                                         gy_key_handle *out);

/*
 * Export the public certificate for a held SAK (by handle: the active one
 * or a retained superseded one).  Same OpenSSL-style sizing convention as
 * the other publish surfaces.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_export_appkey_cert(gy_custodian *c,
                                              gy_key_handle sak, uint8_t *out,
                                              size_t *out_len);

/*
 * Sign app-supplied bytes with a held SAK (by handle), domain-separated so
 * the result can never be confused with or replayed as a protocol
 * signature (D-GEN-3).  app_ctx_len + msg_len is bounded (GY_ERR_TOOLONG
 * past it; this is a request-authentication primitive, not bulk-data
 * signing).  Freshness (a challenge/nonce/timestamp inside msg or app_ctx)
 * is the APPLICATION's responsibility - the library adds none.  NEVER sign
 * protocol message content or transcripts with this: doing so destroys
 * deniability for that content (CUSTODY_SPEC section 10).  Never returns
 * the SAK private key.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_sign(gy_custodian *c, gy_key_handle sak,
                                const uint8_t *app_ctx, size_t app_ctx_len,
                                const uint8_t *msg, size_t msg_len,
                                uint8_t *sig, size_t *sig_len);

/*
 * Verify a SAK-signed request: a FREE function, no custodian and no private
 * key (server-side), needing no custodian (like gy_bundle_assemble).
 * identity_pub is the raw identity public key bytes (curve_pk_len for the
 * cert's own suite), pinned by the caller out of band or via TOFU - never
 * taken from the cert.  Verifies the identity's signature over cert, the
 * expiry against now (0 in the cert = no expiry), then the SAK signature
 * over the same domain-separated framing gy_custodian_sign used.  Returns
 * GY_OK, GY_ERR_EXPIRED past expiry, or GY_ERR_VERIFY on any signature
 * failure (the identity-over-cert check and the SAK-over-request check
 * share this one uniform failure code - no partial-validity oracle).
 */
GY_EXPORT int gy_appkey_verify(const uint8_t *identity_pub,
                               size_t identity_pub_len, const uint8_t *cert,
                               size_t cert_len, const uint8_t *app_ctx,
                               size_t app_ctx_len, const uint8_t *msg,
                               size_t msg_len, const uint8_t *sig,
                               size_t sig_len, uint64_t now);

#ifdef __cplusplus
}
#endif

#endif /* GERYON_H */
