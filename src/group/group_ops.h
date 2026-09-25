/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_OPS_H
#define GY_GROUP_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES, GY_GROUP_PROFILEKEY_BYTES */
#include "group_cred.h"   /* AuthCredentialResponse */
#include "group_issue.h"  /* ProfileKeyCommitment / Request / Response */
#include "group_mac.h"    /* mac tag (a stored credential), server params */
#include "group_params.h" /* generators, Group{Secret,Public}Params */
#include "group_pres.h"   /* Auth / ProfileKey presentations */
#include "group_tier.h"
#include "group_venc.h" /* UID / ProfileKey ciphertexts */

/*
 * The ten client-side group operations (GROUP_SPEC section 7, [CPZ] section
 * 5.6-5.7).  This unit is pure COMPOSITION of the lower-layer
 * machinery (algebraic MAC, credentials, presentations, verifiable encryption)
 * into the operations a group member performs; it introduces no new group
 * primitive (D-GRP-1) and no new frozen crypto except the ProfileKeyVersion
 * derivation below.
 *
 * Split of duties (2026-09-01):
 *
 *   - The SERVER-side crypto of each operation (issue, verify a presentation,
 *     blind-issue) already exists in group_cred.c / group_pres.c /
 *     group_issue.c and is exercised directly; the server target repackages
 * it as a
 *     standalone stateless target.  This unit is the CLIENT side.
 *
 *   - MEMBERSHIP STATE is server-authoritative and never stored by the library
 *     (GROUP_SPEC section 10, D-GRP-7).  The only member-list structure the
 *     library owns is the transient DECRYPTED VIEW that FetchGroupMembers
 *     returns (section 7.7).  Its shape here is PROVISIONAL: the state layer
 * owns the
 *     store callbacks, rederive-on-load, the zeroization sweep, and freezing
 *     GY_GROUP_MAX_ENTRIES and the persisted entry layout (Split A).  Do not
 *     treat gy_group_member{,_ct} or GY_GROUP_MAX_ENTRIES as wire- or
 *     storage-stable before the state layer lands.
 *
 *   - The ProfileKeyVersion "grp-pkv" derivation is computed here (a single
 *     HKDF); its CANONICAL WIRE encoding, and the blind-issuance object wire +
 *     GOBJ tags, are deferred to the wire layer (Split B).  These operations pass
 *     the section 3.3 objects (commitment, request, response) in memory only.
 *
 * No operation caches a derived secret; GroupSecretParams is rederived by the
 * caller (D-GRP-7) and passed in.  All object structs are byte-defined (the
 * unused 255-tier tail is zeroed by the sub-calls, as elsewhere in the vertical).
 */

/*
 * FetchGroupMembers input bound (GROUP_SPEC section 10, D-SES-4 pattern):
 * at most this many entries are processed per fetch; applications may lower it,
 * never raise it.  FROZEN (Split A): the value and the member-entry
 * wire layout (fixed-width, gy_group_member_list_{encode,decode}) are stable
 * from here.  Default 1024 per section 10.
 */
#define GY_GROUP_MAX_ENTRIES 1024

/* ProfileKeyVersion width (GROUP_SPEC section 3.3): a 32-byte non-secret id on
 * both tiers (a fixed identifier, not a tier-width scalar). */
#define GY_GROUP_PK_VERSION_BYTES 32

/* Highest defined member role (the public GY_GROUP_ROLE_ADMINISTRATOR): the
 * common wire codec rejects any role byte above this on decode AND encode, so a
 * malformed role from an untrusted roster never reaches the application view.
 * This internal bound mirrors the public GY_GROUP_ROLE_COUNT; group_facade_client.c
 * statically asserts the two stay in step (GY_GROUP_ROLE_MAX == COUNT - 1). */
#define GY_GROUP_ROLE_MAX 1

/*
 * A raw, server-authoritative member entry as returned by FetchGroupMembers
 * (section 7.7): the two verifiable-encryption ciphertexts plus the opaque Role.
 * An INVITED member (section 7.9) has no ProfileKeyCiphertext: has_profile_key
 * is 0 and pk_ct is unused.  PROVISIONAL layout (Split A).
 */
struct gy_group_member_ct {
    struct gy_group_uid_ct uid_ct;
    struct gy_group_pk_ct pk_ct; /* valid iff has_profile_key */
    uint8_t role;            /* a wire-validated GY_GROUP_ROLE_* value, carried
                              * not interpreted here (section 10) */
    uint8_t has_profile_key; /* 0 = invited (no ProfileKeyCiphertext) */
};

/*
 * A decrypted member entry (the FetchGroupMembers client view, section 7.7).
 * profile_key is meaningful iff has_profile_key; an invited member exposes only
 * its UID.  profile_key is plaintext secret material: the caller zeroizes the
 * view when done (device hygiene, section 10).  PROVISIONAL layout (Split A).
 */
struct gy_group_member {
    uint8_t uid[GY_GROUP_UID_BYTES];
    uint8_t
        profile_key[GY_GROUP_PROFILEKEY_BYTES]; /* valid iff has_profile_key */
    uint8_t role;
    uint8_t has_profile_key;
};

/*
 * ProfileKeyVersion derivation (GROUP_SPEC section 3.3, "grp-pkv" label frozen
 * at section 2.2 item 5): a 32-byte non-secret identifier binding (ProfileKey,
 * UID), so equal ProfileKeys across users do not collide.  Mirrors the section
 * 6.2 Derive HKDF shape (group_params.c):
 *   PRK = HKDF-Extract(salt = "geryon.1.<suite>.grp-pkv", IKM = ProfileKey||UID)
 *   version = HKDF-Expand(PRK, info = "geryon.1.<suite>.grp-pkv", L = 32)
 * out receives GY_GROUP_PK_VERSION_BYTES bytes.  Returns GY_OK or a negative
 * GY_ERR_*.  (Its wire encoding is in the wire layer, Split B.)
 */
int gy_group_profile_key_version(const struct gy_group_tier *tier,
                                 const uint8_t uid[GY_GROUP_UID_BYTES],
                                 const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                                 uint8_t out[GY_GROUP_PK_VERSION_BYTES]);

/*
 * ProfileKeyVersion canonical wire encoding (GROUP_SPEC section 9,
 * Split B): the tagged object GY_GOBJ_PK_VERSION carrying the fixed 32-byte
 * identifier.  The version is a tier-independent 32-byte value, but the object
 * header still binds the suite_id tag for a uniform wire surface.  Encode needs
 * cap >= GY_GROUP_OBJ_HDR_LEN + GY_GROUP_PK_VERSION_BYTES; decode is strict
 * (exact length, correct header, trailing bytes rejected).  Returns GY_OK,
 * GY_ERR_TOOLONG / GY_ERR_VERIFY / GY_ERR_ARG as elsewhere in the wire layer.
 */
int gy_group_pk_version_encode(const struct gy_group_tier *tier,
                               const uint8_t version[GY_GROUP_PK_VERSION_BYTES],
                               uint8_t *out, size_t cap, size_t *outlen);
int gy_group_pk_version_decode(const struct gy_group_tier *tier,
                               uint8_t version[GY_GROUP_PK_VERSION_BYTES],
                               const uint8_t *in, size_t len);

/*
 * 7.1 GetAuthCredential (client half): verify the issuer's pi_I against the
 * published ServerPublicParams iparams_A (pp_A) and the user's OWN uid + date,
 * and on success extract the stored AuthCredential (the MAC tag t,U,V) into
 * out_cred.  Nothing is written to out_cred on failure (D-GRP-7: nothing
 * stored).  date must be day-aligned.  Returns GY_OK, GY_ERR_VERIFY if pi_I
 * fails, or GY_ERR_ARG on bad input.
 */
int gy_group_get_auth_credential(const struct gy_group_tier *tier,
                                 const struct gy_group_generators *gens,
                                 const struct gy_group_server_public *pp_A,
                                 const uint8_t uid[GY_GROUP_UID_BYTES],
                                 uint64_t date,
                                 const struct gy_group_auth_response *resp,
                                 struct gy_group_mac_tag *out_cred);

/*
 * 7.2 CommitToProfileKey (client half): derive the ProfileKeyVersion and the
 * deterministic ProfileKeyCommitment (J1,J2,J3) for the user's own (uid, pk).
 * The caller sends (out_version, out_commit) to the server.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int
gy_group_commit_to_profile_key(const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               const uint8_t uid[GY_GROUP_UID_BYTES],
                               const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                               uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
                               struct gy_group_pk_commitment *out_commit);

/*
 * 7.3 GetProfileKeyCredential, step 1 (request): derive the target's
 * ProfileKeyVersion and build the blind ProfileKeyCredentialRequest (the
 * ElGamal ciphertexts + pi_BR) for (uid, pk).  The ephemeral decryption secret
 * y is written to y_out (kept by the caller for the finish step, then zeroized);
 * the caller sends (uid, out_version, out_req).  Returns GY_OK or negative.
 */
int gy_group_get_pk_credential_request(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
    uint8_t out_version[GY_GROUP_PK_VERSION_BYTES],
    struct gy_group_pk_request *out_req, uint8_t y_out[GY_GROUP_SCALAR_MAX]);

/*
 * 7.3 GetProfileKeyCredential, step 2 (finish): verify the server's pi_BI
 * against iparams_P (pp_P), decrypt the blinded MAC, and store the
 * ProfileKeyCredential (t,U,V) for the target uid into out_cred.  req and y are
 * the objects from step 1; uid supplies the revealed M1, M2.  Returns GY_OK,
 * GY_ERR_VERIFY if pi_BI fails, or a negative GY_ERR_*.
 */
int gy_group_get_pk_credential_finish(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const struct gy_group_server_public *pp_P,
    const uint8_t uid[GY_GROUP_UID_BYTES],
    const struct gy_group_pk_request *req, const uint8_t y[GY_GROUP_SCALAR_MAX],
    const struct gy_group_pk_blind_response *resp,
    struct gy_group_mac_tag *out_cred);

/*
 * 7.4 AuthAsGroupMember (client half): produce an AuthCredentialPresentation
 * for the member's stored AuthCredential (cred), uid, and redemption date; its
 * embedded (E_A1,E_A2) IS the member's deterministic UidCiphertext (section 6.3)
 * that the server matches against the group.  The caller sends pp_pub and
 * out_pres.  sp holds GroupSecretParams; pp_srv_A the ServerPublicParams
 * iparams_A.  Used by every operation below (7.5-7.10 step 1).  Returns GY_OK or
 * a negative GY_ERR_*.
 */
int gy_group_auth_as_member(const struct gy_group_tier *tier,
                            const struct gy_group_generators *gens,
                            const struct gy_group_secret_params *sp,
                            const struct gy_group_public_params *pp_pub,
                            const struct gy_group_server_public *pp_srv_A,
                            const struct gy_group_mac_tag *cred,
                            const uint8_t uid[GY_GROUP_UID_BYTES],
                            uint64_t date,
                            struct gy_group_auth_presentation *out_pres);

/*
 * 7.5 AddGroupMember (client half): present the NEW member's
 * ProfileKeyCredential (new_cred, obtained via GetProfileKeyCredential for that
 * member) to produce a ProfileKeyCredentialPresentation over the new member's
 * (uid, pk); its embedded (E_A1,E_A2,E_B1,E_B2) are the member's Uid/ProfileKey
 * ciphertexts the server stores.  The Role is a call-side value the caller sends
 * alongside out_pres (opaque to geryon, section 10).  Follows an
 * AuthAsGroupMember by the caller (the server checks the caller's Role permits
 * adding).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_add_member(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const struct gy_group_secret_params *sp,
                        const struct gy_group_public_params *pp_pub,
                        const struct gy_group_server_public *pp_srv_P,
                        const struct gy_group_mac_tag *new_cred,
                        const uint8_t new_uid[GY_GROUP_UID_BYTES],
                        const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                        struct gy_group_pk_presentation *out_pres);

/*
 * 7.6 CreateGroup (client half): generate a fresh GroupMasterKey and derive
 * GroupSecretParams and GroupPublicParams (section 6.2).  out_gmk receives
 * tier->master_key_len bytes (the ONLY stored group secret, D-GRP-7).  The
 * creator then initializes the group with its own entry via a Role-check-skipped
 * AddGroupMember (server policy).  out_sp is secret; zeroize with
 * gy_group_secret_clear().  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_create(const struct gy_group_tier *tier,
                    const struct gy_group_generators *gens, uint8_t *out_gmk,
                    struct gy_group_secret_params *out_sp,
                    struct gy_group_public_params *out_pp);

/*
 * 7.7 FetchGroupMembers (client half): decrypt the server-returned raw member
 * entries into the plaintext view, distinguishing full from invited members
 * (section 10).  Processes at most GY_GROUP_MAX_ENTRIES entries and at most
 * out_cap; n_in exceeding either is GY_ERR_ARG.  Any malformed or inconsistent
 * ciphertext fails the whole fetch (transactional, section 10): out is zeroized
 * and GY_ERR_VERIFY returned.  On success *out_count == n_in.  Returns GY_OK or
 * a negative GY_ERR_*.
 */
int gy_group_fetch_members(const struct gy_group_tier *tier,
                           const struct gy_group_secret_params *sp,
                           const struct gy_group_member_ct *in, size_t n_in,
                           struct gy_group_member *out, size_t out_cap,
                           size_t *out_count);

/*
 * FetchGroupMembers list wire encoding (GROUP_SPEC section 9 item 2,
 * Split C): the ONE variable-length group wire object, the server-returned raw
 * member entries.  Tagged GY_GOBJ_MEMBER_LIST, then a 2-byte big-endian entry
 * count (<= GY_GROUP_MAX_ENTRIES) followed by that many FIXED-WIDTH entries,
 * each has_profile_key(1) || role(1) || UidCiphertext(2 elements) ||
 * ProfileKeyCiphertext(2 elements).  For an invited member (has_profile_key 0)
 * the ProfileKeyCiphertext slot is present and MUST be all-zero (decode rejects
 * a non-zero slot; the only variability is the count).  Strict decode: a count
 * over GY_GROUP_MAX_ENTRIES or over out_cap, a has_profile_key byte other than
 * 0/1, a non-zero invited pk slot, a wrong total length, or trailing bytes all
 * return GY_ERR_VERIFY.  Membership is never persisted by the library (D-GRP-7);
 * this is the transient transport shape only.
 */
int gy_group_member_list_encode(const struct gy_group_tier *tier,
                                const struct gy_group_member_ct *entries,
                                size_t n, uint8_t *out, size_t cap,
                                size_t *outlen);
int gy_group_member_list_decode(const struct gy_group_tier *tier,
                                struct gy_group_member_ct *out, size_t out_cap,
                                size_t *out_n, const uint8_t *in, size_t len);

/*
 * 7.8 DeleteGroupMember (client half): compute the deterministic UidCiphertext
 * of the target (another member's UID, or the caller's own on departure), which
 * the caller sends after an AuthAsGroupMember; the server Role-checks and
 * removes the matching entry.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_delete_member(const struct gy_group_tier *tier,
                           const struct gy_group_secret_params *sp,
                           const uint8_t target_uid[GY_GROUP_UID_BYTES],
                           struct gy_group_uid_ct *out_uid_ct);

/*
 * 7.9 AddInvitedGroupMember (client half): encrypt only the invited member's
 * UID (no ProfileKey known, so no ProfileKeyCiphertext and no pi_P, section
 * 7.9).  The entry becomes full when a later AddGroupMember / UpdateProfileKey
 * populates its ProfileKeyCiphertext.  The inviter separately hands the invitee
 * the GroupMasterKey over a pairwise session (section 3.4).  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_group_add_invited_member(const struct gy_group_tier *tier,
                                const struct gy_group_secret_params *sp,
                                const uint8_t invited_uid[GY_GROUP_UID_BYTES],
                                struct gy_group_uid_ct *out_uid_ct);

/*
 * 7.10 UpdateProfileKey (client half): present the caller's OWN
 * ProfileKeyCredential (own_cred) over its new ProfileKey to produce a
 * ProfileKeyCredentialPresentation, replacing only the caller's own
 * ProfileKeyCiphertext (the server matches the authenticated UidCiphertext,
 * preventing rollback of other members' data, section 7.10).  Cryptographically
 * identical to AddGroupMember over (own_uid, new_pk); the self-vs-other
 * distinction is server policy.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_update_profile_key(const struct gy_group_tier *tier,
                                const struct gy_group_generators *gens,
                                const struct gy_group_secret_params *sp,
                                const struct gy_group_public_params *pp_pub,
                                const struct gy_group_server_public *pp_srv_P,
                                const struct gy_group_mac_tag *own_cred,
                                const uint8_t own_uid[GY_GROUP_UID_BYTES],
                                const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES],
                                struct gy_group_pk_presentation *out_pres);

#endif /* GY_GROUP_OPS_H */
