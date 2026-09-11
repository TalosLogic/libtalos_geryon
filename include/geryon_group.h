/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon_group.h - public client API for the classical private group system
 * (GROUP_SPEC, [CPZ] ePrint 2019/1416), serving the classical suites
 * geryon_c25519 and geryon_c448.  This is a PARALLEL VERTICAL: it is a
 * separate link target (geryon_group) with its own header; geryon.h stays
 * messaging-only, so the frozen messaging ABI is unaffected.  Opt out of
 * groups by not linking geryon_group.
 *
 * SCOPE: this is the CLASSICAL group type.  It adds NO post-quantum claim of
 * any kind.  Post-quantum groups are a separate, distinct construction with
 * its own public API; that surface is out of scope here.  The custodian's
 * pinned suite selects the type: every call in this header requires a
 * CLASSICAL-suite custodian (geryon_c25519 / geryon_c448) and returns
 * GY_ERR_UNSUPPORTED on a hybrid-suite custodian.  There is no runtime
 * negotiation and no cross-type fallback, exactly as a hybrid identity cannot
 * complete a classical messaging handshake.
 *
 * MODEL: the group client extends the custodian.  A gy_custodian already
 * owns the suite (pinned at gy_custodian_create), the sealed store, and the
 * caller's identity; group secret state (the GroupMasterKey, credentials,
 * and the caller's own ProfileKey) is per-identity sealed state and rides
 * the SAME custody.  Group records seal under the custodian's KEK, alongside
 * identity/prekey/session records, in the reserved store-kind range below.
 * Nothing derived from the GroupMasterKey is cached or stored; it is
 * rederived on load and zeroized after use (GROUP_SPEC section 10).
 *
 * The server-side crypto is a separate, stateless target with its own
 * handle; see geryon_group_server.h.  A client never links it.
 *
 * WIRE OBJECTS ARE OPAQUE.  Every protocol object that crosses this boundary
 * to or from the server (issuance responses, credential requests,
 * presentations, the encrypted member list) is a canonical, versioned byte
 * string the caller forwards without inspecting.  Only the DECRYPTED member
 * roster crosses as a typed value (gy_group_member_view), because it is
 * terminal data the caller consumes rather than forwards.
 *
 * BUFFER CONVENTION.  Every call that emits a wire object takes
 * (uint8_t *out, size_t *out_len): pass out == NULL to write the required
 * size into *out_len (touching nothing), then call again with a buffer of at
 * least that size (out != NULL, *out_len = capacity in, bytes written out).
 * This matches gy_encrypt / gy_publish_bundle in geryon.h.  The GY_GROUP_*_MAX
 * bounds below let a caller size a fixed buffer instead; a build-time and
 * test-time check keeps them ahead of the wire formulas.
 */
#ifndef GERYON_GROUP_H
#define GERYON_GROUP_H

#include <stddef.h>
#include <stdint.h>

#include "geryon.h" /* gy_custodian, GY_EXPORT, the GY_ERR_* codes, GY_SUITE_* */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- fixed-width identifiers and payloads ------------------------------- */

/* A GroupID: library-derived, 16 bytes, recomputable from the GroupMasterKey
 * (local-only, never negotiated). */
#define GY_GROUP_ID_LEN 16

/* A member UID: an application-level 16-byte account identifier (the [CPZ]
 * UID, Signal's ACI).  It is bound into and encrypted within credentials for
 * unlinkability, but its VALUE is application-known; it is not secret.  A
 * custodian used for groups names this device with a 16-byte self_user_id at
 * gy_custodian_create, and that value IS the caller's group UID (read it back
 * with gy_custodian_group_self_uid). */
#define GY_GROUP_UID_BYTES 16

/* A ProfileKey: 32 bytes. */
#define GY_GROUP_PROFILEKEY_BYTES 32

/* A ProfileKeyVersion: 32 bytes (the "grp-pkv" identifier). */
#define GY_GROUP_PK_VERSION_BYTES 32

/* The maximum roster the library will build or read in one member list. */
#define GY_GROUP_MAX_ENTRIES 1024

/* ---- member roles ------------------------------------------------------- */

#define GY_GROUP_ROLE_DEFAULT 0       /* An ordinary member. */
#define GY_GROUP_ROLE_ADMINISTRATOR 1 /* A member who may add/remove others. */
/* The number of defined roles.  The member-list wire codec is strict: it
 * rejects any roster entry whose role is >= GY_GROUP_ROLE_COUNT, so a decoded
 * view always carries a known role and an application need not defend against
 * an out-of-range value from a malicious or buggy server. */
#define GY_GROUP_ROLE_COUNT 2

/* ---- group format version ----------------------------------------------- */

/*
 * A group's format version is its capability epoch: it is chosen when the group
 * is created, is immutable for the life of the group, and is bound into the
 * GroupID.  A group created at an older version never gains a newer version's
 * features, so clients that support that older version keep working with it; a
 * group that needs a newer feature is created at the newer version, and a client
 * that does not support it refuses to join (GY_ERR_UNSUPPORTED).  This library
 * creates groups at GY_GROUP_FORMAT_VERSION and reads any version up to
 * GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION.  Query a group's version with
 * gy_custodian_group_format_version.
 */
#define GY_GROUP_FORMAT_VERSION 1
#define GY_GROUP_MAX_SUPPORTED_FORMAT_VERSION 1

/* ---- reserved store-kind range ------------------------------------------ */

/*
 * Group records seal into the custodian's store through its existing
 * gy_store_callbacks (load_record / store_record / delete_record), under
 * record-kind values reserved to the group vertical.  A store implementation
 * persists them like any other opaque, already-sealed record and MUST NOT
 * reuse this range for its own records.  The specific kinds are an internal
 * detail; only the reserved span is part of this contract.
 */
#define GY_GROUP_STORE_KIND_MIN 0x40
#define GY_GROUP_STORE_KIND_MAX 0x4F

/* ---- wire-buffer upper bounds (NULL-to-size query is always available) --- */

/* Split by tier (255 vs 448), like GY_BUNDLE_MAX_* in geryon.h.  A caller
 * serving an unknown suite sizes to the 448 bound.  These are compile-time
 * upper bounds; the exact size is what the size query reports. */
#define GY_GROUP_SERVER_PARAMS_MAX_255 256
#define GY_GROUP_SERVER_PARAMS_MAX_448 512
#define GY_GROUP_CRED_REQUEST_MAX_255 1024
#define GY_GROUP_CRED_REQUEST_MAX_448 2048
#define GY_GROUP_PRESENTATION_MAX_255 2048
#define GY_GROUP_PRESENTATION_MAX_448 4096
#define GY_GROUP_KEY_ENVELOPE_MAX_255 64
#define GY_GROUP_KEY_ENVELOPE_MAX_448 96
/* The group public parameters (A, B): two group elements plus object framing. */
#define GY_GROUP_GROUP_PUBLIC_MAX_255 96
#define GY_GROUP_GROUP_PUBLIC_MAX_448 160
/* The encrypted member list: a 3-byte frame plus one fixed-width entry per
 * member (2 + 4 group elements each). */
#define GY_GROUP_MEMBER_LIST_MAX_255 (3 + GY_GROUP_MAX_ENTRIES * 130)
#define GY_GROUP_MEMBER_LIST_MAX_448 (3 + GY_GROUP_MAX_ENTRIES * 226)

/* ---- the decrypted roster view (terminal, consumed data) ---------------- */

/*
 * One member as decrypted by gy_custodian_group_fetch_members.  profile_key is
 * valid only when has_profile_key != 0 (an invited-but-not-joined member has
 * a UID and no profile key).  role is one of GY_GROUP_ROLE_* (the wire codec
 * rejects any roster carrying a role >= GY_GROUP_ROLE_COUNT, so this is never
 * an unknown value).
 */
typedef struct gy_group_member_view {
    uint8_t uid[GY_GROUP_UID_BYTES];
    uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES];
    uint8_t role;
    uint8_t has_profile_key;
} gy_group_member_view;

/* ---- lifecycle: reopen a group-capable custodian ------------------------ */

/*
 * Reopen an existing custodian for GROUP use: identical to gy_custodian_open
 * (recover the KEK from the sealed store and (cred, cred_len), reload the
 * identity/prekey material), then install the monotone clock the group
 * credential operations need.  gy_custodian_open takes no clock, and a clock is
 * a live callback that cannot be sealed to disk, so a plain reopen leaves a
 * custodian unable to present daily group credentials (auth_present returns
 * GY_ERR_STATE).  Messaging (gy_send/gy_receive) does not consult the clock
 * after open, so ONLY the group vertical needs this variant; a caller doing
 * only messaging keeps using gy_custodian_open.  clock/clock_ctx may be NULL if
 * the reopened custodian will not present credentials.  *out and its ownership
 * match gy_custodian_open (free with gy_custodian_close).  Returns GY_OK or the
 * same negative GY_ERR_* as gy_custodian_open (GY_ERR_VERIFY on a wrong
 * credential or tampered store, GY_ERR_STATE if no custodian was ever created).
 */
GY_EXPORT int gy_custodian_group_open(gy_custodian **out,
                                      const gy_store_callbacks *store,
                                      const uint8_t *cred, size_t cred_len,
                                      gy_clock_fn clock, void *clock_ctx);

/* ---- accessors ---------------------------------------------------------- */

/*
 * Write this custodian's own 16-byte group UID (its self_user_id) into
 * out_uid.  Returns GY_ERR_STATE if the custodian was created with a
 * self_user_id that is not exactly GY_GROUP_UID_BYTES long (a group-capable
 * custodian must name itself with a 16-byte account id).  Returns GY_OK or a
 * negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_self_uid(gy_custodian *c,
                                          uint8_t out_uid[GY_GROUP_UID_BYTES]);

/*
 * Derive the 32-byte ProfileKeyVersion for a profile key (the "grp-pkv"
 * identifier bound to (profile_key, this custodian's UID)).  Returns GY_OK or
 * a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_profile_key_version(
    gy_custodian *c, const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES]);

/*
 * Write the format version (capability epoch) of the group group_id into
 * *out_version.  The version is fixed at creation and immutable.  Returns
 * GY_ERR_NOT_FOUND if group_id is unknown to this custodian.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_format_version(gy_custodian *c,
                                  const uint8_t group_id[GY_GROUP_ID_LEN],
                                  uint16_t *out_version);

/* ---- setup: install the service's public parameters --------------------- */

/*
 * Install and seal the ServerPublicParams fetched from the group service
 * (params, params_len as produced by gy_group_server_export_public).  These
 * are per-service, not per-group; install once per custodian before any
 * credential or presentation call.  The bytes are validated against the
 * custodian's suite; a malformed or wrong-suite blob is GY_ERR_VERIFY.
 * Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_install_server_params(gy_custodian *c,
                                                       const uint8_t *params,
                                                       size_t params_len);

/* ---- group creation and key distribution (section 7.6, 2.5) ------------- */

/*
 * 7.6 CreateGroup: mint a fresh GroupMasterKey, derive the group parameters,
 * seal them under this custodian, and write the derived GroupID into
 * out_group_id.  The caller becomes the founding administrator.  The group is
 * created at GY_GROUP_FORMAT_VERSION (its immutable capability epoch).  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_create(gy_custodian *c,
                                        uint8_t out_group_id[GY_GROUP_ID_LEN]);

/*
 * Export the group's public parameters (A, B) for group_id as an opaque object.
 * The founder hands these to the group service so the server can verify members'
 * presentations against this group (the server holds no group secret; the group
 * public key is deployer state it stores per group).  Size query per the buffer
 * convention; the bytes are bounded by GY_GROUP_GROUP_PUBLIC_MAX_<tier>.  Returns
 * GY_ERR_NOT_FOUND if group_id is unknown to this custodian.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_export_group_public_params(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN], uint8_t *out,
    size_t *out_len);

/*
 * Build the GROUP_KEY_DISTRIBUTION payload (envelope msg_type 0x03) that hands
 * a new member the GroupMasterKey for group_id.  The caller sends the returned
 * bytes to that member INSIDE an ordinary pairwise session (gy_encrypt /
 * gy_send); the group layer never transports it.  Size query per the buffer
 * convention.  Returns GY_ERR_NOT_FOUND if group_id is unknown to this
 * custodian.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_export_key_envelope(gy_custodian *c,
                                       const uint8_t group_id[GY_GROUP_ID_LEN],
                                       uint8_t *out, size_t *out_len);

/*
 * Decode a GROUP_KEY_DISTRIBUTION payload (env, env_len) received over a
 * pairwise session, seal the carried GroupMasterKey under this custodian, and
 * write the derived GroupID into out_group_id.  This is how a member joins a
 * group it was added to.  A payload whose suite does not match this custodian,
 * or that is malformed, is GY_ERR_VERIFY; a payload whose group format version
 * this build does not support is GY_ERR_UNSUPPORTED (join declined, nothing
 * stored).  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_install_key_envelope(gy_custodian *c, const uint8_t *env,
                                        size_t env_len,
                                        uint8_t out_group_id[GY_GROUP_ID_LEN]);

/*
 * Forget a group: remove every sealed record for group_id (the GroupMasterKey,
 * cached credentials, and the caller's own ProfileKey) from this custodian.
 * Idempotent.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_forget(gy_custodian *c,
                          const uint8_t group_id[GY_GROUP_ID_LEN]);

/* ---- credentials (interactive with the server) -------------------------- */

/*
 * 7.1 GetAuthCredential (finish): verify the server's issuance response
 * (resp, resp_len from gy_group_server_issue_auth) against uid and the
 * day-aligned redemption_date, then seal the resulting AuthCredential under
 * this custodian for group_id.  redemption_date must be a multiple of 86400
 * (a UTC day); it is rejected, never rounded.  A failed issuance proof is
 * GY_ERR_VERIFY.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_receive_auth_credential(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t redemption_date,
    const uint8_t *resp, size_t resp_len);

/*
 * 7.2 CommitToProfileKey: produce the ProfileKeyCommitment for profile_key,
 * to send to the server.  Size query per the buffer convention.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_profile_key_commit(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len);

/*
 * 7.3 GetProfileKeyCredential (request): produce the blind credential request
 * for profile_key, to send to the server.  The blinding secret is sealed
 * transiently under this custodian and consumed by _finish; only one request
 * per group may be outstanding at a time (a second request for the same group
 * overwrites the first).  Size query per the buffer convention.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_pk_credential_request(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len);

/*
 * 7.3 GetProfileKeyCredential (finish): unblind and verify the server's blind
 * response (resp, resp_len from gy_group_server_blind_issue_pk) against the
 * outstanding request for group_id, then seal the resulting
 * ProfileKeyCredential.  The transient blinding secret is zeroized.  A failed
 * proof is GY_ERR_VERIFY; no outstanding request is GY_ERR_STATE.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_pk_credential_finish(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t profile_key[GY_GROUP_PROFILEKEY_BYTES], const uint8_t *resp,
    size_t resp_len);

/* ---- presentations (emit an opaque object to POST to the server) -------- */

/*
 * 7.4 AuthAsGroupMember: build an AuthCredentialPresentation from the sealed
 * AuthCredential for group_id.  The credential is usable only on its
 * redemption day; presenting off that day is GY_ERR_EXPIRED, and no sealed
 * credential is GY_ERR_NOT_FOUND.  Size query per the buffer convention.
 * Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_auth_present(gy_custodian *c,
                                const uint8_t group_id[GY_GROUP_ID_LEN],
                                uint8_t *out, size_t *out_len);

/*
 * 7.5 AddGroupMember: build the ProfileKeyCredentialPresentation that adds the
 * member (new_uid, new_pk) to group_id, to POST to the server.  Size query per
 * the buffer convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_add_member(gy_custodian *c,
                              const uint8_t group_id[GY_GROUP_ID_LEN],
                              const uint8_t new_uid[GY_GROUP_UID_BYTES],
                              const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                              uint8_t *out, size_t *out_len);

/*
 * 7.9 AddInvitedGroupMember: build the object that adds new_uid as an invited
 * member (no profile key yet) to group_id, to POST to the server.  Size query
 * per the buffer convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_add_invited_member(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t new_uid[GY_GROUP_UID_BYTES], uint8_t *out, size_t *out_len);

/*
 * 7.10 UpdateProfileKey: rotate the caller's own ProfileKey in group_id to
 * new_pk, reseal it, drop any now-stale cached ProfileKeyCredential, and build
 * the ProfileKeyCredentialPresentation to POST to the server.  Size query per
 * the buffer convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_update_profile_key(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES], uint8_t *out,
    size_t *out_len);

/*
 * 7.8 DeleteGroupMember: build the target's UidCiphertext identifying the
 * member to remove from group_id, to POST to the server, and drop that
 * target's now-obsolete cached ProfileKeyCredential.  Size query per the
 * buffer convention.  Returns GY_OK or a negative GY_ERR_*.
 */
GY_EXPORT int
gy_custodian_group_delete_member(gy_custodian *c,
                                 const uint8_t group_id[GY_GROUP_ID_LEN],
                                 const uint8_t target_uid[GY_GROUP_UID_BYTES],
                                 uint8_t *out, size_t *out_len);

/* ---- roster read (section 7.7) ------------------------------------------ */

/*
 * 7.7 FetchGroupMembers: decode the server's encrypted member list
 * (member_list_wire, wire_len) and decrypt each entry under group_id into out
 * (a caller array of max entries), writing the count to *out_count.  Pass
 * out == NULL to write only the entry count into *out_count.  The decode is
 * transactional: a single undecryptable or inconsistent entry zeroizes out
 * and returns the uniform GY_ERR_VERIFY (no per-entry oracle).  A list longer
 * than max, or than GY_GROUP_MAX_ENTRIES, is GY_ERR_TOOLONG.  Returns GY_OK or
 * a negative GY_ERR_*.
 */
GY_EXPORT int gy_custodian_group_fetch_members(
    gy_custodian *c, const uint8_t group_id[GY_GROUP_ID_LEN],
    const uint8_t *member_list_wire, size_t wire_len, gy_group_member_view *out,
    size_t max, size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* GERYON_GROUP_H */
