/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_CUSTODIAN_H
#define GY_CUSTODIAN_H

#include <stddef.h>
#include <stdint.h>

#include "facade.h"
#include "recv.h"
#include "sealed_store.h"
#include "send.h"

/*
 * gy_custodian: the top-level custody object (D-CUST-1,
 * CUSTODY_SPEC sections 3-4, 7-8).  It subsumes what gy_ctx (formerly
 * proto/api.c's own struct) held: the unlocked KEK, the identity/signed-
 * prekey/one-time-prekey material, the send/receive contexts, this
 * device's addresses, and the store/clock callbacks, plus a handle-
 * addressed slot table for the prekey and SAK key objects.  It IS the public
 * surface include/geryon.h exposes; there is no gy_ctx
 * anymore.  Not independently thread-safe (D-GEN-8: one per thread, or
 * caller-serialized); active is the debug-build re-entrancy guard (see
 * custodian.c).
 *
 * Bootstrap persistence (a design decision the custody layer had to make, since
 * gy_custodian_open takes only (store, cred) - no suite id, no device ids,
 * per CUSTODY_SPEC section 12 - so everything needed to recover the KEK
 * must be recoverable from the store before the KEK exists).  The KEK-wrap
 * blob, suite_id, and this device's addresses are carried in a small
 * unsealed HEADER (gy_cust_header) persisted through the application's OWN
 * store_identity/load_identity callback (gy_custodian.app_store), the one
 * existing per-device callback with no key id (D-SES-2).  The header is NOT
 * KEK-sealed (it is what recovers the KEK); it is only as strong as the
 * credential protecting the embedded kekprot wrap blob, matching the
 * envelope hierarchy's own trust boundary.
 *
 * The bootstrap then appends the KEK-sealed identity/prekey material (gy_cust_idmat,
 * sealed as raw struct bytes under a distinct AD tag) immediately after the
 * header in that SAME store_identity blob, written/read via the caller's RAW
 * app_store (never through gy_custodian.sealed_store, which assumes the
 * header has already been stripped).  Because gy_custodian_generate_identity
 * takes no credential (CUSTODY_SPEC section 12), and re-persisting the
 * header requires the wrap blob, create/open/change_credential cache the
 * CURRENT wrap blob in gy_custodian.wrap so any later call that must rewrite
 * the header (generate_identity, prekey/SAK persistence)
 * can do so without re-deriving the PDK.
 *
 * gy_custodian.sealed_store (gy_sealed_store_bind over ks and app_store) is
 * for every OTHER record/prekey/session blob (wired into gy_custodian.store,
 * the internal session/ store, by create/open); only the bootstrap header
 * and the identity/prekey material bypass it, because they must be readable
 * before the KEK is unwrapped or because they share the header's blob.
 */

/* gy_key_handle / GY_KEY_HANDLE_INVALID are public (include/geryon.h),
 * reachable here transitively via sealed_store.h -> geryon.h. */

/*
 * Key-object slot types (D-CUST-1 item 1: "the key type is stored in the
 * slot, never packed into handle bits").  The prekey lifecycle is the first to
 * populate them (SPK/OPK, keyed by pkid); the SAK follows.  The
 * identity key itself is NOT slot-registered: gy_custodian.ik is reached
 * directly (a field, not a handle indirection), matching how the rest of
 * the protocol API already addresses "this identity" implicitly via the
 * custodian.
 */
enum gy_slot_type {
    GY_SLOT_IDENTITY = 1,
    GY_SLOT_SPK = 2,
    GY_SLOT_OPK = 3,
    GY_SLOT_SAK = 4,
};

/* Fixed HSM-style bound (CUSTODY_SPEC section 7 "immutable configuration"):
 * not runtime-mutable. */
#define GY_CUSTODIAN_MAX_SLOTS 48

/*
 * Signed-prekey history depth (D-X3DH-4/5 retention): [0] is
 * always the current/active SPK, [1..n_spks) are superseded ones retained
 * so an in-flight session started against an old SPK still resolves
 * (session/recv.c tries each in turn by PKID - see recv.h).  4 (current +
 * 3 superseded) comfortably covers realistic rotation cadences against
 * plausible message latency; eviction of the oldest on a further rotation
 * is a zeroizing delete, matching D-SES-4-style fixed bounds elsewhere.
 */
#define GY_CUSTODIAN_SPK_HISTORY_MAX 4

/*
 * Application-signing-key history depth; the same rationale
 * as GY_CUSTODIAN_SPK_HISTORY_MAX: [0] is the current/active SAK, retained
 * superseded SAKs let a verifier holding a not-yet-refreshed cert (or a
 * signing request already in flight against it) keep working across a
 * rotation, with the oldest zeroized once history is full.
 */
#define GY_CUSTODIAN_SAK_HISTORY_MAX 4

/*
 * Bound on app_ctx_len + msg_len for gy_custodian_sign: the
 * underlying XEdDSA primitive has its own hard maximum message length; this
 * library-level cap, well under it once the domain-separation prefix is
 * added, keeps the signing buffer a plain stack local (no dynamic
 * allocation in the signing path).  SAK signing is a request-authentication
 * primitive (small challenge/nonce-bearing payloads), not bulk-data
 * signing, so this is not a meaningful restriction for its purpose.
 */
#define GY_CUSTODIAN_SIGN_MAX 8000

struct gy_key_slot {
    int in_use;
    int type;        /* enum gy_slot_type; meaningless when !in_use */
    uint32_t key_id; /* stable persisted id (e.g. a pkid); 0 if none */
};

/* The bootstrap header this ticket persists via app_store.store_identity;
 * see the file docstring above.  Bounds mirror geryon.h/keystore.h. */
struct gy_cust_header {
    uint8_t suite_id;
    uint8_t self_uid[GY_USER_ID_MAX];
    size_t self_uid_len;
    uint8_t self_did[GY_DEVICE_ID_MAX];
    size_t self_did_len;
    uint8_t wrap[GY_KEYSTORE_WRAP_MAX];
    size_t wrap_len;
};

#define GY_CUST_HDR_VERSION 1
/* version(1) + suite_id(1) + uid_len(1) + uid + did_len(1) + did +
 * wrap_len(2) + wrap. */
#define GY_CUST_HDR_MAX                                                        \
    (1 + 1 + 1 + GY_USER_ID_MAX + 1 + GY_DEVICE_ID_MAX + 2 +                   \
     GY_KEYSTORE_WRAP_MAX)

int gy_cust_header_encode(const struct gy_cust_header *h, uint8_t *out,
                          size_t cap, size_t *out_len);
/* consumed (may be NULL) receives the number of header bytes read, so a
 * caller can locate what follows in the same blob (the identity
 * material). */
int gy_cust_header_decode(const uint8_t *in, size_t in_len,
                          struct gy_cust_header *h, size_t *consumed);

/*
 * Raw struct-bytes packing of the private material a custodian owns
 *: gy_seal is an AEAD over arbitrary bytes, so the suite-
 * dependent "how many bytes of pk/sk are real" question (answered by
 * curve_type/desc wherever the key is actually USED) does not need to be
 * re-derived for storage; the whole fixed-size struct round-trips as-is,
 * padding included.  Always heap/guard-allocated (gy_guarded_alloc, the
 * facade.h re-export of core's gy_secure_alloc), never a stack local:
 * sizeof this struct runs into the tens of KB.
 */
/*
 * A held application signing key plus its identity-issued certificate
 * fields (CUSTODY_SPEC section 10).  expiry 0 means no
 * expiry.  identity_sig covers EncodeEC(kp.pub) || issued_at_be64 ||
 * expiry_be64 || identity_pkid_be32 under the "appkey-cert" domain-
 * separation label (see custodian.c); identity_pkid is carried for the
 * verifier's convenience only (identity_pub itself is pinned out of band,
 * CUSTODY_SPEC section 12's cert-shape decision). */
struct gy_cust_sak {
    struct gy_keypair kp;
    uint64_t issued_at;
    uint64_t expiry;
    uint32_t identity_pkid;
    uint8_t identity_sig[GY_SIG_MAX];
};

struct gy_cust_idmat {
    struct gy_keypair ik;
    /* [0] = current/active SPK; [1..n_spks) = retained history, most-recent
     * superseded first. */
    struct gy_signed_prekey spks[GY_CUSTODIAN_SPK_HISTORY_MAX];
    uint64_t n_spks;
    /* OPK pool: opk_used[i] gates whether opks[i] is a real, currently-held
     * key (gaps from deletion are possible); opk_consumed[i] marks a key that
     * has been EXPORTED in a one-shot bundle (reserved so it is never handed
     * out twice) but not yet used.  A one-time prekey used to establish a
     * session is DELETED outright (delete-on-use, tr_consume_opk): its slot is
     * wiped and freed, so opks[]/gy_recv_ctx_init never see a spent key and a
     * reused OPK cannot establish a second session.  Base-key dedupe
     * (D-SES-6.1) still routes legitimate retransmits to the established
     * session without touching an OPK. */
    struct gy_keypair opks[GY_OPK_BATCH_MAX];
    uint8_t opk_used[GY_OPK_BATCH_MAX];
    uint8_t opk_consumed[GY_OPK_BATCH_MAX];
    uint64_t n_opks; /* high-water mark: opks[0..n_opks) is the scanned range */
    /* [0] = current/active SAK; [1..n_saks) = retained history,
     * same shape as spks[] above. */
    struct gy_cust_sak saks[GY_CUSTODIAN_SAK_HISTORY_MAX];
    uint64_t n_saks;
};

#define GY_CUST_IDMAT_MAX sizeof(struct gy_cust_idmat)
#define GY_CUST_IDMAT_SEALED_MAX (GY_CUST_IDMAT_MAX + GY_SEAL_MAX_OVERHEAD)
/* The full store_identity payload: header || sealed identity material. */
#define GY_CUST_BLOB_MAX (GY_CUST_HDR_MAX + GY_CUST_IDMAT_SEALED_MAX)

struct gy_custodian {
    struct gy_keystore ks;
    struct gy_sealed_store ss;
    gy_store_callbacks app_store;    /* the caller's raw callbacks */
    gy_store_callbacks sealed_store; /* app_store wrapped over ks; for
                                       * every record/prekey/session blob,
                                       * not the bootstrap header */
    struct gy_store store; /* internal session/ store, wired to sealed_store */

    const struct gy_suite_desc *desc;
    uint8_t suite_id;

    uint8_t self_uid[GY_USER_ID_MAX];
    size_t self_uid_len;
    uint8_t self_did[GY_DEVICE_ID_MAX];
    size_t self_did_len;

    /* Cached KEK-wrap blob (see the file docstring): lets a later call
     * rewrite the bootstrap header without the credential. */
    uint8_t wrap[GY_KEYSTORE_WRAP_MAX];
    size_t wrap_len;

    gy_clock_fn clock;
    void *clock_ctx;
    struct gy_expiry_cfg expiry; /* immutable once create/open has run */

    /* Identity/prekey material and the protocol contexts built over it
     *; have_identity is 0 until gy_custodian_generate_identity
     * or a reopen that recovers persisted material has run. */
    struct gy_keypair ik;

    /* SPK history; mirrors gy_cust_idmat.spks.  spk_kps is a
     * dense struct-gy_keypair view of spks[0..n_spks), rebuilt on every
     * rotation: what gy_recv_ctx_init (session/, plain gy_keypair array, no
     * per-entry metadata) actually takes - spks[] itself cannot be passed
     * directly, its stride is sizeof(gy_signed_prekey), not gy_keypair. */
    struct gy_signed_prekey spks[GY_CUSTODIAN_SPK_HISTORY_MAX];
    size_t n_spks;
    struct gy_keypair spk_kps[GY_CUSTODIAN_SPK_HISTORY_MAX];

    /* OPK pool; mirrors gy_cust_idmat.opks/opk_used/
     * opk_consumed exactly (same index meaning), so no separate dense view
     * is needed here - opks[] IS already the plain gy_keypair array
     * gy_recv_ctx_init wants. */
    struct gy_keypair opks[GY_OPK_BATCH_MAX];
    int opk_used[GY_OPK_BATCH_MAX];
    int opk_consumed[GY_OPK_BATCH_MAX];
    size_t n_opks;

    /* Application signing key history; mirrors
     * gy_cust_idmat.saks exactly, same [0]-is-active convention as spks[]
     * above. */
    struct gy_cust_sak saks[GY_CUSTODIAN_SAK_HISTORY_MAX];
    size_t n_saks;

    int have_identity;

    struct gy_send_ctx send;
    struct gy_recv_ctx recv;
    int send_open;

    struct gy_key_slot slots[GY_CUSTODIAN_MAX_SLOTS];

    int unlocked;
    int active; /* D-GEN-8 debug re-entrancy guard */
};

/*
 * gy_custodian embeds a gy_sealed_store (a large fixed scratch buffer, see
 * sealed_store.h); every instance MUST be heap-allocated (as create/open
 * do) and never a stack local, matching the gy_op/gy_sealed_store
 * precedent.
 */

int gy_custodian_create(struct gy_custodian **out, uint8_t suite_id,
                        const gy_store_callbacks *store, const uint8_t *cred,
                        size_t cred_len, const uint8_t *self_uid,
                        size_t self_uid_len, const uint8_t *self_did,
                        size_t self_did_len, gy_clock_fn clock, void *clock_ctx,
                        const gy_config *cfg);
int gy_custodian_open(struct gy_custodian **out,
                      const gy_store_callbacks *store, const uint8_t *cred,
                      size_t cred_len);
void gy_custodian_close(struct gy_custodian *c);
int gy_custodian_reset(struct gy_custodian *c);
int gy_custodian_change_credential(struct gy_custodian *c,
                                   const uint8_t *new_cred,
                                   size_t new_cred_len);

/*
 * Generate this custodian's identity key pair, a signed prekey, and an
 * initial one-time-prekey batch (0 <= n_opks <= GY_OPK_BATCH_MAX); seal the
 * whole set and persist it appended after the bootstrap header
 * (CUSTODY_SPEC section 7).  Wires the send/receive protocol contexts over
 * the result.  c must be unlocked and must not already have generated an
 * identity (GY_ERR_STATE otherwise; rotation is the prekey/SAK lifecycle's
 * job, not regeneration).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_generate_identity(struct gy_custodian *c,
                                   uint64_t spk_timestamp, size_t n_opks);

/* Generic slot allocator behind the handle model (D-CUST-1 item 1); shared
 * to register identity/prekey/SAK key objects. */
int gy_custodian_slot_alloc(struct gy_custodian *c, int type, uint32_t key_id,
                            gy_key_handle *out);
int gy_custodian_slot_get(struct gy_custodian *c, gy_key_handle h, int *type,
                          uint32_t *key_id);
void gy_custodian_slot_free(struct gy_custodian *c, gy_key_handle h);

/* ---- prekey lifecycle ------------------------------------- */

/*
 * Mint a new identity-signed, timestamped SPK (D-X3DH-4/5) and make it the
 * active one; the superseded SPK is RETAINED (GY_CUSTODIAN_SPK_HISTORY_MAX
 * deep) so a session referencing its PKID still resolves, with the oldest
 * zeroized on eviction once history is full.  Re-wires the receive context
 * over the new spks[] and re-persists the sealed identity material.  c must
 * be unlocked with an identity already generated.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_custodian_rotate_signed_prekey(struct gy_custodian *c,
                                      uint64_t spk_timestamp);

/*
 * Generate count additional one-time prekeys into the pool's first free
 * slots, without touching the identity or SPK.  count must be
 * 1..GY_OPK_BATCH_MAX (0 or above the cap is GY_ERR_ARG); an
 * in-range count whose slots would exceed the pool's current free capacity
 * is GY_ERR_NO_SPACE.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_generate_onetime_prekeys(struct gy_custodian *c, size_t count);

/* Pool observability: total occupied slots, how many are consumed, and how
 * many remain unused.  Any out pointer may be NULL.  Returns GY_OK or a
 * negative GY_ERR_*. */
int gy_custodian_opk_stats(struct gy_custodian *c, size_t *total, size_t *used,
                           size_t *unused);

/*
 * Publish the identity+current-SPK registration ONLY - no OPK, ever (the
 * granular publish model: this is the low-churn call, made only at identity
 * creation and on SPK rotation; gy_custodian_publish_opk_batch is the
 * separate high-churn OPK-only call).  Same OpenSSL-style sizing convention
 * as gy_publish_bundle (out == NULL queries the size).  Returns
 * GY_ERR_STATE if no identity has been generated yet.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_custodian_publish_registration(struct gy_custodian *c, uint8_t *out,
                                      size_t *out_len);

/*
 * Emit every currently-unused, unconsumed OPK's public key as one batch
 * (D-GEN-1 versioned framing, reusing the per-key wire encoding already
 * used inside a prekey bundle; see gy_opk_batch_put in envelope.h).  Same
 * sizing convention.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_publish_opk_batch(struct gy_custodian *c, uint8_t *out,
                                   size_t *out_len);

/*
 * Serialize a complete one-shot prekey bundle (IK + active SPK + one OPK) for
 * the directory-less / direct-handoff path (public gy_publish_bundle).  Unlike
 * the granular publish model, this RESERVES its OPK: it marks the emitted
 * one-time key as exported (minting a fresh one if the pool is spent) and
 * persists, so no later export hands out the same key.  The private key is
 * retained until the peer uses the bundle, when delete-on-use destroys it.
 * Mutating.  Same OpenSSL-style sizing convention.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_custodian_publish_bundle(struct gy_custodian *c, uint8_t *out,
                                size_t *out_len);

/*
 * Map a server-reported PKID (kind: GY_PK_SPK or GY_PK_OPK, geryon.h) back
 * to the local handle, so the application can query or delete it.  Returns
 * the handle, or GY_KEY_HANDLE_INVALID if kind/pkid names nothing currently
 * held (unknown, already deleted, or c is locked/NULL).
 */
gy_key_handle gy_custodian_find_prekey(struct gy_custodian *c, int kind,
                                       uint32_t pkid);

/*
 * Delete a prekey (SPK history entry or OPK) by handle, zeroizing it and
 * re-persisting the sealed identity material; the handle itself is freed
 * (GY_ERR_NOT_FOUND on a stale/unknown handle).  Deleting the currently
 * ACTIVE SPK (spks[0]) is refused (GY_ERR_STATE): rotate first.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_delete_prekey(struct gy_custodian *c, gy_key_handle h);

/* ---- application signing key ------------------------------ */

/*
 * Mint a fresh SAK (XEdDSA, classical suite only this milestone), certify it
 * with the identity key, seal, and persist.  c must be unlocked with an
 * identity already generated and must NOT already hold a SAK (GY_ERR_STATE;
 * use gy_custodian_rotate_appkey to replace one).  expiry is a caller-chosen
 * absolute time bound (0 = no expiry); the library never reads a clock.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_generate_appkey(struct gy_custodian *c, uint64_t expiry,
                                 gy_key_handle *out);

/*
 * Mint a new SAK and make it active; the superseded SAK is RETAINED
 * (GY_CUSTODIAN_SAK_HISTORY_MAX deep, oldest zeroized on eviction), the same
 * shape as gy_custodian_rotate_signed_prekey.  c must already hold a SAK.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_rotate_appkey(struct gy_custodian *c, uint64_t expiry,
                               gy_key_handle *out);

/* Export the public certificate for a held SAK (by handle: the active one
 * or a retained superseded one).  Same OpenSSL-style sizing convention as
 * the other publish surfaces.  Returns GY_OK or a negative GY_ERR_*. */
int gy_custodian_export_appkey_cert(struct gy_custodian *c, gy_key_handle sak,
                                    uint8_t *out, size_t *out_len);

/*
 * Sign app-supplied bytes with a held SAK (by handle), framed as
 * sign(SAK, appkey_info || be32(app_ctx_len) || app_ctx || msg) (D-GEN-3
 * domain separation, so this can never be confused with or replayed as a
 * protocol signature; the be32 app_ctx length delimits the app_ctx/msg
 * boundary so distinct splits cannot sign identical bytes).
 * app_ctx_len + msg_len must not exceed GY_CUSTODIAN_SIGN_MAX
 * (GY_ERR_TOOLONG).  Freshness (a challenge/nonce/timestamp inside msg or
 * app_ctx) is the APPLICATION's responsibility - the library adds none.
 * NEVER sign protocol message content or transcripts with this: doing so
 * destroys deniability for that content (CUSTODY_SPEC section 10).  Returns
 * GY_OK or a negative GY_ERR_*.
 */
int gy_custodian_sign(struct gy_custodian *c, gy_key_handle sak,
                      const uint8_t *app_ctx, size_t app_ctx_len,
                      const uint8_t *msg, size_t msg_len, uint8_t *sig,
                      size_t *sig_len);

#endif /* GY_CUSTODIAN_H */
