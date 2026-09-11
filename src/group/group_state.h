/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_STATE_H
#define GY_GROUP_STATE_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES, GY_GROUP_PROFILEKEY_BYTES */
#include "group_mac.h"    /* struct gy_group_mac_tag */
#include "group_ops.h"    /* the client operations wrapped by *_stored below */
#include "group_params.h" /* generators, Group{Secret,Public}Params */
#include "group_store.h"
#include "group_tier.h"

/*
 * Group state, storage, and zeroization (GROUP_SPEC section 10, D-GRP-7),
 * GER-M8-09.  Client-side only: the server target is stateless (D-GRP-2).
 *
 * Rederive, never cache.  The only per-group secret at rest is the
 * GroupMasterKey; GroupSecretParams / GroupPublicParams are recomputed from it
 * on demand and zeroized after use.  Credentials (AuthCredential,
 * ProfileKeyCredential) and the user's own ProfileKey persist through the store
 * as secret material (D-GEN-4: the app seals the opaque blobs).  Membership is
 * never stored by the library (D-GRP-7 item 2).
 */

/* Local GroupID width (D-SES-3 style, D-GRP-7 item 1): a suite-hash of
 * suite_id || GroupPublicParams, truncated.  Local-only, never on the wire. */
#define GY_GROUP_ID_LEN 16

/* Record blob version byte (versioned from day one, frozen at first KATs). */
#define GY_GROUP_REC_VERSION 0x01

/*
 * Group FORMAT version (GER-GRPVER): the group's capability epoch, chosen at
 * creation, immutable for the life of the group, bound into the GroupID, and
 * carried in the master-key record and the GROUP_KEY_DISTRIBUTION envelope as a
 * 2-byte big-endian field.  A client refuses a group whose version is outside
 * [MIN, MAX] supported.  New groups are minted at GY_GROUP_FORMAT_VERSION.
 */
#define GY_GROUP_FORMAT_VERSION 1
#define GY_GROUP_MIN_SUPPORTED_FORMAT_VERSION 1
#define GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION 1

/* Largest record blob: AUTH_CRED = ver || tag(scalar+2*point) || date(8). */
#define GY_GROUP_REC_BLOB_MAX (1 + GY_GROUP_MAC_TAG_ENC_MAX + 8)

/*
 * An AuthCredential at rest: the algebraic-MAC tag plus the day-aligned
 * redemption date it was issued for (section 5.9, section 10).
 */
struct gy_group_auth_credential {
    struct gy_group_mac_tag mac;
    uint64_t redemption_date; /* day-aligned unix seconds (multiple of 86400) */
};

/*
 * Compute the local GroupID: the first GY_GROUP_ID_LEN bytes of the tier suite
 * hash over suite_id || format_version(BE16) || A || B (GroupPublicParams).
 * Binding the format version makes the group's capability epoch tamper-evident
 * (GER-GRPVER).  Deterministic and recomputable from the GroupMasterKey and the
 * format version alone (no cached state).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_id(const struct gy_group_tier *tier,
                const struct gy_group_public_params *pp,
                uint16_t format_version, uint8_t out[GY_GROUP_ID_LEN]);

/*
 * Create a fresh group and persist it: generate a random GroupMasterKey, derive
 * GroupSecretParams / GroupPublicParams, store the master-key record under the
 * derived GroupID, and return the GroupID and params.  out_sp is secret
 * (zeroize with gy_group_secret_clear); the transient master key is zeroized
 * internally.  Returns GY_OK or a negative GY_ERR_* (nothing stored on failure).
 */
int gy_group_create_stored(const struct gy_group_store *store,
                           const struct gy_group_tier *tier,
                           const struct gy_group_generators *gens,
                           uint8_t out_group_id[GY_GROUP_ID_LEN],
                           struct gy_group_secret_params *out_sp,
                           struct gy_group_public_params *out_pp);

/*
 * Install a GroupMasterKey received via GROUP_KEY_DISTRIBUTION (invitee side):
 * derive params, store the master-key record (with format_version) under the
 * derived GroupID, and return the GroupID and params.  gmk_len must equal
 * tier->master_key_len.  format_version must be within the supported window,
 * else GY_ERR_UNSUPPORTED (nothing stored).  Same secrecy and zeroization
 * contract as gy_group_create_stored.
 */
int gy_group_install_master_key(const struct gy_group_store *store,
                                const struct gy_group_tier *tier,
                                const struct gy_group_generators *gens,
                                const uint8_t *gmk, size_t gmk_len,
                                uint16_t format_version,
                                uint8_t out_group_id[GY_GROUP_ID_LEN],
                                struct gy_group_secret_params *out_sp,
                                struct gy_group_public_params *out_pp);

/*
 * Reopen a group: load the stored GroupMasterKey by GroupID and rederive its
 * params (D-GRP-7: nothing derived is cached).  The recomputed GroupID is
 * const-compared to the lookup key as an integrity check on the record.  out_sp
 * is secret (zeroize).  Returns GY_OK, GY_ERR_NOT_FOUND if no master-key record
 * exists, GY_ERR_VERIFY on a malformed or GroupID-mismatched record, or a
 * negative GY_ERR_*.
 */
int gy_group_load(const struct gy_group_store *store,
                  const struct gy_group_tier *tier,
                  const struct gy_group_generators *gens,
                  const uint8_t group_id[GY_GROUP_ID_LEN],
                  struct gy_group_secret_params *out_sp,
                  struct gy_group_public_params *out_pp);

/*
 * Load the raw GroupMasterKey for group_id (for GROUP_KEY_DISTRIBUTION export,
 * GER-M8-11): the only path that surfaces the key itself, all others rederive.
 * out holds cap >= tier->master_key_len bytes; *out_len is set to master_key_len.
 * Returns GY_OK, GY_ERR_NOT_FOUND if no record, GY_ERR_VERIFY on a malformed
 * record, or a negative GY_ERR_*.
 */
int gy_group_master_key_load(const struct gy_group_store *store,
                             const struct gy_group_tier *tier,
                             const uint8_t group_id[GY_GROUP_ID_LEN],
                             uint8_t *out, size_t cap, size_t *out_len);

/*
 * Load a group's format version (GER-GRPVER) from its master-key record, without
 * surfacing the key.  Used to frame the GROUP_KEY_DISTRIBUTION envelope and by
 * the public version accessor.  Returns GY_OK, GY_ERR_NOT_FOUND if no record,
 * GY_ERR_VERIFY on a malformed record, or a negative GY_ERR_*.
 */
int gy_group_format_version_load(const struct gy_group_store *store,
                                 const struct gy_group_tier *tier,
                                 const uint8_t group_id[GY_GROUP_ID_LEN],
                                 uint16_t *out_version);

/*
 * Remove the group-keyed records (MASTER_KEY, AUTH_CRED, OWN_PK) on leave /
 * eviction / local delete (section 10 device hygiene, not revocation).
 * Per-target ProfileKeyCredentials (keyed by GroupID || UID) are the
 * application's to remove: the library keeps no contact enumeration (D-SES-1).
 * Idempotent.  Returns GY_OK or the first negative store error.
 */
int gy_group_delete_stored(const struct gy_group_store *store,
                           const struct gy_group_tier *tier,
                           const uint8_t group_id[GY_GROUP_ID_LEN]);

/* ------------------------------------------------------------------------- *
 * Credential and own-ProfileKey persistence.  Blobs are opaque/sealed by the
 * application (D-GEN-4); an absent record on load is GY_ERR_NOT_FOUND.
 * ------------------------------------------------------------------------- */

/* Store (overwrite) the own AuthCredential + its redemption date for a group. */
int gy_group_auth_cred_store(const struct gy_group_store *store,
                             const struct gy_group_tier *tier,
                             const uint8_t group_id[GY_GROUP_ID_LEN],
                             const struct gy_group_auth_credential *cred);
/* Load the own AuthCredential; GY_ERR_NOT_FOUND if none stored. */
int gy_group_auth_cred_load(const struct gy_group_store *store,
                            const struct gy_group_tier *tier,
                            const uint8_t group_id[GY_GROUP_ID_LEN],
                            struct gy_group_auth_credential *out_cred);
/*
 * Whether an AuthCredential is presentable at now_unix (unix seconds): valid iff
 * now falls on the credential's redemption day (floor(now / 86400) * 86400 ==
 * redemption_date), matching the [CPZ] daily-credential model (spec-true, no
 * grace window; the server is the acceptance authority, D-GRP-2).  Returns 1 if
 * valid, 0 otherwise.
 */
int gy_group_auth_cred_valid(const struct gy_group_auth_credential *cred,
                             uint64_t now_unix);

/* Store (overwrite) a target's ProfileKeyCredential, keyed by GroupID || UID.
 * Replacing a newer credential over an older one obsoletes the old (the app's
 * seal replaces the blob; call gy_group_pk_cred_remove on UpdateProfileKey). */
int gy_group_pk_cred_store(const struct gy_group_store *store,
                           const struct gy_group_tier *tier,
                           const uint8_t group_id[GY_GROUP_ID_LEN],
                           const uint8_t target_uid[GY_GROUP_UID_BYTES],
                           const struct gy_group_mac_tag *cred);
/* Load a target's ProfileKeyCredential; GY_ERR_NOT_FOUND if none stored. */
int gy_group_pk_cred_load(const struct gy_group_store *store,
                          const struct gy_group_tier *tier,
                          const uint8_t group_id[GY_GROUP_ID_LEN],
                          const uint8_t target_uid[GY_GROUP_UID_BYTES],
                          struct gy_group_mac_tag *out_cred);
/* Remove a target's ProfileKeyCredential (UpdateProfileKey obsoletion). */
int gy_group_pk_cred_remove(const struct gy_group_store *store,
                            const struct gy_group_tier *tier,
                            const uint8_t group_id[GY_GROUP_ID_LEN],
                            const uint8_t target_uid[GY_GROUP_UID_BYTES]);

/* Store (overwrite) the user's own ProfileKey for a group (section 7.2). */
int gy_group_own_pk_store(const struct gy_group_store *store,
                          const struct gy_group_tier *tier,
                          const uint8_t group_id[GY_GROUP_ID_LEN],
                          const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES]);
/* Load the user's own ProfileKey; GY_ERR_NOT_FOUND if none stored. */
int gy_group_own_pk_load(const struct gy_group_store *store,
                         const struct gy_group_tier *tier,
                         const uint8_t group_id[GY_GROUP_ID_LEN],
                         uint8_t pk[GY_GROUP_PROFILEKEY_BYTES]);

/* Zeroize an AuthCredential (part of the protocol, D-GRP-7). */
void gy_group_auth_credential_clear(struct gy_group_auth_credential *cred);

/* ------------------------------------------------------------------------- *
 * Store-integrated operation wrappers (GER-M8-09 increment 3).  Each runs the
 * corresponding client operation and, ON SUCCESS ONLY, persists its output
 * through the store, matching how the one-on-one messaging operations
 * (gy_send / gy_recv) commit records at their single success point.  The
 * wrapper contract is atomic: a return of GY_OK means the output was produced
 * AND persisted; on any failure (crypto or store) the output is zeroized and
 * (single-record cases) nothing is left in the store.  The pure operations in
 * group_ops.h remain for callers that do not persist (tests, ephemeral use).
 * No staging arena is needed: the group operations write at most one record
 * (UpdateProfileKey writes one and best-effort-removes one, in safe order).
 * ------------------------------------------------------------------------- */

/*
 * 7.1 GetAuthCredential + persist: verify pi_I, then store the AuthCredential
 * with its redemption date under the GroupID.  On store failure out_cred is
 * zeroized.  Returns GY_OK, GY_ERR_VERIFY on a bad proof, or a store error.
 */
int gy_group_get_auth_credential_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_server_public *pp_A,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
    const struct gy_group_auth_response *resp,
    struct gy_group_mac_tag *out_cred);

/*
 * 7.3 GetProfileKeyCredential finish + persist: verify pi_BI, decrypt, then
 * store the ProfileKeyCredential for target uid (keyed GroupID || uid).  On
 * store failure out_cred is zeroized.  Returns GY_OK, GY_ERR_VERIFY, or a store
 * error.
 */
int gy_group_get_pk_credential_finish_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_server_public *pp_P,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const struct gy_group_pk_request *req, const uint8_t y[GY_GROUP_SCALAR_MAX],
    const struct gy_group_pk_blind_response *resp,
    struct gy_group_mac_tag *out_cred);

/*
 * 7.2 CommitToProfileKey + persist: derive the version and commitment, then
 * store the user's own ProfileKey under the GroupID.  On store failure
 * out_version and out_commit are zeroized.  Returns GY_OK or a negative code.
 */
int gy_group_commit_to_profile_key_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
    struct gy_group_pk_commitment *out_commit);

/*
 * 7.10 UpdateProfileKey + persist: build the presentation over new_pk, then
 * store the new own ProfileKey (the fatal step) and best-effort remove the
 * caller's now-stale own ProfileKeyCredential (keyed GroupID || own_uid; a
 * leftover is harmless, it fails verification and is re-acquired).  Safe order:
 * store first, remove second.  On the own-PK store failure out_pres is
 * zeroized.  Returns GY_OK or a negative code.
 */
int gy_group_update_profile_key_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_secret_params *sp,
    const struct gy_group_public_params *pp_pub,
    const struct gy_group_server_public *pp_srv_P,
    const struct gy_group_mac_tag *own_cred,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t own_uid[GY_GROUP_UID_BYTES],
    const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
    struct gy_group_pk_presentation *out_pres);

/*
 * 7.4 AuthAsGroupMember + load + validity gate: load the stored AuthCredential
 * for the group, REFUSE to present it if it is not valid at now_unix (the
 * D-GRP-7 item 3 "no presentation from an expired credential" rule; the stored
 * redemption day must equal now's day), else build the presentation over the
 * credential's own redemption date.  Returns GY_OK, GY_ERR_NOT_FOUND if no
 * AuthCredential is stored, GY_ERR_EXPIRED if it is stale, or a negative code.
 */
int gy_group_auth_as_member_stored(
    const struct gy_group_store *store, const struct gy_group_tier *tier,
    const struct gy_group_generators *gens,
    const struct gy_group_secret_params *sp,
    const struct gy_group_public_params *pp_pub,
    const struct gy_group_server_public *pp_srv_A,
    const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t now_unix,
    struct gy_group_auth_presentation *out_pres);

/*
 * 7.5 AddGroupMember + load: load the new member's stored ProfileKeyCredential
 * (keyed GroupID || new_uid) and present it over (new_uid, new_pk).  Returns
 * GY_OK, GY_ERR_NOT_FOUND if no credential is stored for new_uid, or a negative
 * code.  The Role the caller sends alongside out_pres is opaque (section 10).
 */
int gy_group_add_member_stored(const struct gy_group_store *store,
                               const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               const struct gy_group_secret_params *sp,
                               const struct gy_group_public_params *pp_pub,
                               const struct gy_group_server_public *pp_srv_P,
                               const uint8_t group_id[GY_GROUP_ID_LEN],
                               const uint8_t new_uid[GY_GROUP_UID_BYTES],
                               const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                               struct gy_group_pk_presentation *out_pres);

/*
 * 7.8 DeleteGroupMember + cleanup: compute the target's UidCiphertext and, on
 * success, best-effort remove that target's now-obsolete cached
 * ProfileKeyCredential (a leftover is harmless).  Returns GY_OK or a negative
 * code from the operation itself (the cleanup remove never fails the call).
 */
int gy_group_delete_member_stored(const struct gy_group_store *store,
                                  const struct gy_group_tier *tier,
                                  const struct gy_group_secret_params *sp,
                                  const uint8_t group_id[GY_GROUP_ID_LEN],
                                  const uint8_t target_uid[GY_GROUP_UID_BYTES],
                                  struct gy_group_uid_ct *out_uid_ct);

#endif /* GY_GROUP_STATE_H */
