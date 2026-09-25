/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon_qspgs.h - public client API for the quantum-safe private group system
 * (QSPGS_SPEC.md, [CFG+] ePrint 2026/453), serving the HYBRID suites
 * geryon_h25519_512 and geryon_h448_1024.  This is a SECOND parallel group
 * vertical, distinct from the classical [CPZ] groups of geryon_group.h: it is
 * its own link target (geryon_qspgs) with its own header; geryon.h stays
 * messaging-only, so the frozen messaging ABI is unaffected.  Opt out of
 * quantum-safe groups by not linking geryon_qspgs.
 *
 * SCOPE: this is the POST-QUANTUM group type, hybrid suites only.  Every call
 * requires a hybrid-suite custodian (geryon_h25519_512 / geryon_h448_1024) and
 * returns GY_ERR_UNSUPPORTED on a classical-suite custodian.  There is no
 * runtime negotiation and no cross-type fallback, exactly as a hybrid identity
 * cannot complete a classical messaging handshake.
 *
 * MODEL: the quantum-safe group client EXTENDS the custodian, exactly as the
 * classical group client does (geryon_group.h).  A gy_custodian already owns
 * the suite (pinned at gy_custodian_create), the sealed store, and the caller's
 * identity; QSPGS secret state (the per-user main key, the KR-ML-DSA base pair,
 * and each group key) is per-identity sealed state that rides the SAME custody,
 * sealed under the custodian's KEK alongside identity/prekey/session records in
 * the reserved store-kind range below.  Nothing derived from those keys is
 * cached or stored; it is rederived on load and zeroized after use (D-GRP-7),
 * and the pseudonym signing key is never stored.  The caller's own account id
 * (the custodian's self_user_id) is this member's QSPGS UID.
 *
 * The two identity-anchored registration objects ([CFG+] footnote 7, D-QGS-6)
 * are signed by the custodian's identity key WITHOUT that key ever leaving the
 * custodian; there is no public identity-signing call, and the library drives
 * it internally.
 *
 * The server-side crypto is a separate, stateless target with its own header;
 * see geryon_qsgroups_server.h.  A client never links it.
 *
 * WIRE OBJECTS ARE OPAQUE.  Every protocol object that crosses this boundary to
 * or from the server (the signed core, appendix lines, registration records,
 * invite-queue entries) is a canonical, versioned byte string the caller
 * forwards without inspecting.  Only the DECRYPTED member roster crosses as a
 * typed value, because it is terminal data the caller consumes.
 *
 * BUFFER CONVENTION.  Every call that emits a wire object or a variable-length
 * value takes (uint8_t *out, size_t *out_len): pass out == NULL to write the
 * required size into *out_len (touching nothing), then call again with a buffer
 * of at least that size (out != NULL, *out_len = capacity in, bytes written
 * out).  This matches gy_encrypt / gy_publish_bundle in geryon.h.
 */
#ifndef GERYON_QSPGS_H
#define GERYON_QSPGS_H

#include <stddef.h>
#include <stdint.h>

#include "geryon.h" /* gy_custodian, GY_EXPORT, the GY_ERR_* codes, GY_SUITE_* */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- fixed-width identifiers -------------------------------------------- */

/* A GroupID: opaque and caller-supplied (unlike the classical derived GroupID),
 * 16 bytes. */
#define GY_QSGROUP_GID_LEN 16

/* The fetch-token (fet) width; a separate server record since SEC-v1.5.0 LOW-1,
 * not a header field.  Defined here so the core-edit bundle and create can
 * reference it. */
#define GY_QSGROUP_FET_LEN 32

/* A member UID: an application-level account identifier, exactly
 * GY_QSGROUP_UID_LEN bytes.  A group-capable custodian names itself with a
 * self_user_id of this width at gy_custodian_create, and that value IS the
 * caller's QSPGS UID (read it back with gy_custodian_qsgroup_self_uid).
 *
 * FIXED width, SEC-v1.5.0 LOW-2: a variable-length UID would leak its length
 * class through the cleartext ciphertext lengths a corrupt server sees (mct_len,
 * invite entry_len, newcomer payload_len are each UID length + a tier constant),
 * which it could intersect with the public per-UID ACCT directory.  Mandating a
 * single width makes every sealed member entry the same length, so the server
 * learns member indices only, never a per-entry length class.  An application
 * whose native account id is not 16 bytes hashes it to this width (the spec 1.3
 * "16-byte identifier" convention, matching the classical group's EncodeToG UID).
 * Any other length is rejected with GY_ERR_ARG. */
#define GY_QSGROUP_UID_LEN 16

/* Deprecated alias retained for buffer sizing; the UID is now a fixed width, so
 * this equals GY_QSGROUP_UID_LEN rather than a range maximum (SEC-v1.5.0 LOW-2). */
#define GY_QSGROUP_UID_MAX GY_QSGROUP_UID_LEN

/* ---- group format version ----------------------------------------------- */

/*
 * A group's format version is its capability epoch (D-QGS-12): chosen when the
 * group is created, immutable for the life of the group, and bound into the
 * admin-signed core.  It is DISTINCT from the mutable (vMaj, vMin) state
 * version.  A group created at an older version never gains a newer version's
 * features, so clients supporting that older version keep working with it; a
 * group needing a newer feature is created at the newer version, and a client
 * that does not support it refuses to join (GY_ERR_UNSUPPORTED).  This library
 * creates groups at GY_QSGROUP_FORMAT_VERSION and reads any version up to
 * GY_QSGROUP_MAX_SUPPORTED_FORMAT_VERSION.  Query a group's version with
 * gy_custodian_qsgroup_format_version.
 */
#define GY_QSGROUP_FORMAT_VERSION 1
#define GY_QSGROUP_MIN_SUPPORTED_FORMAT_VERSION 1
#define GY_QSGROUP_MAX_SUPPORTED_FORMAT_VERSION 1

/*
 * Group field AEAD (SEC-v1.5.0 INFO-6).  The admin selects one at
 * gy_custodian_qsgroup_create; like the format version it is pinned into the
 * admin-signed header and immutable for the life of the group (no runtime
 * renegotiation, so no downgrade path).  Every ek-sealed field (member tuples,
 * the settings/attributes header, refresh / modAttr appendix payloads, the join
 * slot) uses it.  Two are offered, both always available on every build (so the
 * choice never fragments membership): ChaCha20-Poly1305, the mandatory-to-
 * implement default, and AEGIS-256, whose 256-bit nonce removes any random-nonce
 * collision margin under the long-lived group key.  The values are the wire
 * bytes; AES-256-GCM is deliberately not offered here (it is hardware-gated).
 */
#define GY_QSGROUP_AEAD_CHACHA20POLY1305 0x01
#define GY_QSGROUP_AEAD_AEGIS256 0x03

/* ---- reserved store-kind range ------------------------------------------ */

/*
 * QSPGS records seal into the custodian's store through its existing
 * gy_store_callbacks (load_record / store_record / delete_record), under
 * record-kind values reserved to the quantum-safe group vertical - a band
 * distinct from the classical group vertical's (GY_GROUP_STORE_KIND_*).  A
 * store implementation persists them like any other opaque, already-sealed
 * record and MUST NOT reuse this range for its own records.  The specific kinds
 * are an internal detail; only the reserved span is part of this contract.
 */
#define GY_QSGROUP_STORE_KIND_MIN 0x50
#define GY_QSGROUP_STORE_KIND_MAX 0x5F

/* ---- accessors ---------------------------------------------------------- */

/*
 * Write this custodian's own QSPGS UID (its self_user_id) into out (size query
 * per the buffer convention: out == NULL reports the length in *out_len).
 * Returns GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * the custodian was created without a self_user_id in exactly GY_QSGROUP_UID_LEN
 * bytes, GY_ERR_ARG on a NULL argument or a short buffer, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_self_uid(gy_custodian *c, uint8_t *out,
                                            size_t *out_len);

/*
 * Write the format version (capability epoch) the group gid was filed under
 * into *out_version, read from the sealed group record without touching its
 * secret payload.  The version is fixed at creation and immutable.  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_NOT_FOUND if gid is
 * unknown to this custodian, GY_ERR_VERIFY on a malformed record header, else
 * GY_OK.
 */
GY_EXPORT int
gy_custodian_qsgroup_format_version(gy_custodian *c,
                                    const uint8_t gid[GY_QSGROUP_GID_LEN],
                                    uint16_t *out_version);

/* ---- registration and acquaintance -------------------------------------- */

/*
 * The largest registration (ACCT) wire object this library emits or consumes,
 * over both hybrid tiers: object header + base verification key + acquaintance
 * tag + epoch + the two length-prefixed identity signatures.  A caller may size
 * a register buffer to this instead of using the size query.
 */
#define GY_QSGROUP_ACCT_MAX 10752

/*
 * RegisterUser: emit this member's registration record (the [CFG+] Acct) for
 * the caller to deposit at the group server.  The record binds the caller's
 * QSPGS base verification key and its acquaintance tag for epoch ep under the
 * custodian identity's dual (XEdDSA + ML-DSA) signature; the identity secret
 * key never leaves the custodian.  The per-user QSPGS hierarchy (main key and
 * base pair) is minted and sealed into the custodian store on first use, the
 * same way group creation mints its group key (there is no separate provision
 * step).  ep is the caller's acquaintance epoch.  Size query per the buffer
 * convention (out == NULL reports the size in *out_len).  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if the
 * custodian is locked or has no identity / self UID, GY_ERR_ARG on a NULL
 * out_len or short buffer, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_register(gy_custodian *c, uint64_t ep,
                                            uint8_t *out, size_t *out_len);

/*
 * GrantAcquaintance / accept ([CFG+] Fig. 8, D-QGS-13 E4): verify a peer's
 * registration record (acct, acct_len) against that peer's hybrid identity
 * public keys (granter_curve_pk, the XEdDSA curve public key, and
 * granter_mldsa_pk, the ML-DSA public key, both obtained out of band from the
 * messaging layer), check that the peer's conveyed user key uk (uk_len = the
 * tier master-key length, sent by the granter over the pairwise channel with
 * (UID, uk)) opens the attested acquaintance tag (acq == KDF(uk)), and on
 * success seal the attested (base verification key, acquaintance tag, uk, epoch)
 * into the custodian store keyed by the granter's UID (granter_uid,
 * exactly GY_QSGROUP_UID_LEN bytes), so this member can later attribute and add that
 * user with its verified uk.  A bad signature, a malformed record, or a uk that
 * does not open acq is GY_ERR_VERIFY.  Returns GY_ERR_UNSUPPORTED on a
 * classical-suite custodian, GY_ERR_STATE if locked, GY_ERR_ARG on a NULL or
 * out-of-range argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_accept_acquaintance(
    gy_custodian *c, const uint8_t *granter_uid, size_t granter_uid_len,
    const uint8_t *granter_curve_pk, const uint8_t *granter_mldsa_pk,
    const uint8_t *acct, size_t acct_len, const uint8_t *uk, size_t uk_len);

/*
 * Export this member's own group user key uk = KDF(muk, "uk@" || ep) for epoch
 * ep into out (out_len: capacity in, length out; size query when out == NULL).
 * This is the (UID, uk) a member conveys to a peer over a pairwise secure
 * channel when granting acquaintance (Fig. 8): the peer feeds it to
 * gy_custodian_qsgroup_accept_acquaintance.  uk is secret; share it only over an
 * E2EE channel and zero it when done.  The per-user hierarchy is minted on first
 * use as in registration.  Returns GY_ERR_UNSUPPORTED on a classical-suite
 * custodian, GY_ERR_STATE if locked or the caller has no UID, GY_ERR_TOOLONG on
 * a short buffer, GY_ERR_ARG on a NULL argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_export_user_key(gy_custodian *c, uint64_t ep,
                                                   uint8_t *out,
                                                   size_t *out_len);

/* ---- group creation and roster read ------------------------------------- */

/* The longest member user key (uk = 2*kappa) a roster view carries. */
#define GY_QSGROUP_USER_KEY_MAX 56

/*
 * One decrypted roster entry (the Fetch client view).  uk is the member's user
 * key, plaintext secret material an admin needs for key rotation; zero the view
 * when done.  admn is 1 for an admin member, else 0.
 */
struct gy_qsgroup_member_view {
    uint8_t uid[GY_QSGROUP_UID_MAX];
    size_t uidlen;
    uint8_t admn;
    uint8_t uk[GY_QSGROUP_USER_KEY_MAX];
    size_t uk_len;
};

/* Length of an application exporter key expKey = KDF(uk, "EXP-Key"). */
#define GY_QSGROUP_EXPORT_KEY_LEN 32

/*
 * Derive the application exporter key expKey = KDF(uk, "EXP-Key") ([CFG+] §2.2,
 * §6.5) from a roster member's user key uk (uk / uk_len as carried in a
 * gy_qsgroup_member_view, or a member's own key from
 * gy_custodian_qsgroup_export_user_key).  The paper's Fetch output is
 * (expKey_i, UID_i); geryon's roster instead exposes the raw uk, so this call
 * lets an application obtain the exporter key WITHOUT re-deriving from uk
 * itself.  out receives GY_QSGROUP_EXPORT_KEY_LEN bytes (out_len: capacity in,
 * length out; size query when out == NULL).  uk_len must equal the suite's user
 * key length (as reported in the view), else GY_ERR_ARG.  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if locked,
 * GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on a NULL/mis-sized argument,
 * else GY_OK.  The custodian holds no group state for this; only its pinned
 * suite selects the KDF.
 */
GY_EXPORT int gy_custodian_qsgroup_export_key(gy_custodian *c,
                                              const uint8_t *uk, size_t uk_len,
                                              uint8_t *out, size_t *out_len);

/*
 * A server-served registration record (ACCT) for one member, supplied to Fetch
 * so it can resolve that member's base verification key when the custodian is
 * not acquainted with them ([CFG+] Fig. 16 GetPseudoVkBase: an AcqRec, else the
 * ACCT the server holds).  acct is the ACCT wire object (GY_QOBJ_ACCT) the
 * deployer fetched for uid over the server's user-anonymous query.
 *
 * Fetch uses it two ways.  It recovers vkbase for the all-member vk-lst
 * recompute (D-QGS-13 E5).  And, for a member the caller has no AcqRec for, it
 * runs IsCorrectUserKey ([CFG+] Fig. 15, D-QGS-13 E4): it verifies the ACCT's
 * identity signature against curve_pk / mldsa_pk (the member's hybrid identity
 * public keys, learned out of band, e.g. from the server's user-anonymous
 * query) AND requires acq == KDF(uk) on the roster user key it decrypts.  A
 * member without an AcqRec whose ACCT is absent or whose uk does not open the
 * attested acq makes the fetched version invalid (GY_ERR_VERIFY).  curve_pk /
 * mldsa_pk may be NULL only for a member the caller is already acquainted with
 * (that member's uk was checked at accept-acquaintance time).
 */
struct gy_qsgroup_acct_ref {
    const uint8_t *uid;
    size_t uid_len;
    const uint8_t *acct;
    size_t acct_len;
    const uint8_t *curve_pk;
    const uint8_t *mldsa_pk;
};

/*
 * Appendix line kinds ([CFG+] section 3.2), as reported by Fetch in a
 * gy_qsgroup_apx_report.  These mirror the internal wire registry; a caller
 * uses them only to interpret a report entry's line_type.
 */
#define GY_QSGROUP_APX_LEAVE 0x01u
#define GY_QSGROUP_APX_REFRESH 0x02u
#define GY_QSGROUP_APX_ADDUSER 0x03u
#define GY_QSGROUP_APX_MODATTR 0x04u
#define GY_QSGROUP_APX_JOIN 0x05u

/*
 * One appendix line's outcome, as Fetch's CheckAppendixLine ([CFG+] Fig. 16)
 * decided it.  Entries are reported in appendix wire order (not application
 * order), so a caller can attribute every line - valid or not - to its author.
 * line_type is a GY_QSGROUP_APX_* kind; author_index is the signer's roster
 * index the line named (for a JOIN it is the newcomer's proposed slot); valid
 * is 1 if the line verified and was applied to the returned roster, 0 if it was
 * ignored (bad signature, gated-off addUser / modAttr, a JOIN with no open
 * link, or an addUser whose commitment did not open).  pending_approval is 1
 * for a JOIN line that verified but was held out of the roster because the
 * group requires admin approval of link joiners (b_adm set, [CFG+] App. B.8,
 * D-QGS-14 E9): such a line has valid == 0 (not applied) and must be approved
 * at Consolidate before it becomes a member; for every other outcome it is 0.
 */
struct gy_qsgroup_apx_report {
    uint8_t line_type;
    uint32_t author_index;
    uint8_t valid;
    uint8_t pending_approval;
};

/*
 * Create a group with the caller-supplied opaque GID (gid, GY_QSGROUP_GID_LEN
 * bytes): mint a fresh group key, seal it into the custodian store under gid,
 * and emit the founding admin-signed core as its four canonical wire objects
 * (the header, the member-list with the caller as the sole admin member, the
 * vk-lst, and the admin core signature), for the caller to deposit at the
 * group server.  The core is signed through the caller's group pseudonym; the
 * group starts at format version GY_QSGROUP_FORMAT_VERSION and state version
 * (1, 0).  The founding header seals the initial settings and attributes
 * ([CFG+] Create takes both): settings_flags is the b_add / b_attr / b_adm
 * combination (GY_QSGROUP_SETTING_*), and attr[0..attr_len) is the opaque
 * attributes blob (attr may be NULL only when attr_len is 0; attr_len must not
 * exceed GY_QSGROUP_ATTR_MAX).  ep is the caller's user-key epoch (as at
 * register).  The per-user QSPGS hierarchy is minted on first use as in
 * registration.
 *
 * aead_id pins the group's field AEAD for its whole life (SEC-v1.5.0 INFO-6):
 * pass GY_QSGROUP_AEAD_CHACHA20POLY1305 (the default) or GY_QSGROUP_AEAD_AEGIS256;
 * any other value is GY_ERR_ARG.  It is bound into the admin-signed header and
 * cannot be changed by any later edit, so there is no downgrade path.
 *
 * Each object follows the buffer convention independently: pass any of the four
 * out pointers as NULL to have all four required sizes reported into the
 * *_len outputs (nothing is sealed); otherwise every out must be non-NULL and
 * large enough, else GY_ERR_TOOLONG (the needed sizes are written back and
 * nothing is sealed).  All four *_len pointers must be non-NULL.  fet_out, when
 * non-NULL, receives the group's fetch token (GY_QSGROUP_FET_LEN bytes) on a
 * committed emit; since SEC-v1.5.0 LOW-1 it is a separate server record, NOT in
 * the header (see struct gy_qsgroup_core).  It is optional: pass NULL to skip
 * it and derive the token later with gy_custodian_qsgroup_fetch_token.  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if locked or
 * without an identity / self UID, GY_ERR_ARG on a NULL argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_create(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN], uint64_t ep,
    uint8_t settings_flags, uint8_t aead_id, const uint8_t *attr,
    size_t attr_len, uint8_t *hdr_out, size_t *hdr_len,
    uint8_t *member_list_out, size_t *member_list_len, uint8_t *vk_lst_out,
    size_t *vk_lst_len, uint8_t *sig_out, size_t *sig_len,
    uint8_t fet_out[GY_QSGROUP_FET_LEN]);

/*
 * Fetch (read a group): given the four core wire objects the server serves (the
 * header, member-list, vk-lst, and admin core signature), run the [CFG+] Fig. 15
 * UsrVfyUpdate verification and decrypt the roster into out[0..max).  The group
 * key is loaded from the custodian store by the GID carried in the header
 * (GY_ERR_NOT_FOUND if this custodian does not hold that group).
 *
 * Verification (D-QGS-13 E2/E5):
 *   - the admin core signature verifies under the signer's recomputed pseudonym
 *     key;
 *   - EVERY member's pseudonym key is recomputed from that member's base
 *     verification key and required to match the received vk-lst entry for
 *     entry, with one vk-lst entry per member.  A member's base key is resolved
 *     as the caller's own (self), else an accept-acquaintance record, else a
 *     matching entry in accts[0..n_accts) (the server-served ACCT, Fig. 16
 *     GetPseudoVkBase); a member resolvable by none of these is GY_ERR_NOT_FOUND.
 *   - IsCorrectUserKey ([CFG+] Fig. 15, D-QGS-13 E4, D-QGS-14 E12): runs over
 *     the EFFECTIVE roster, AFTER the appendix (refresh / addUser / join) and
 *     the invite-queue settling have produced each member's final uk.  An
 *     accept-acquaintance record exempts a member only on an exact (UID, uk)
 *     match; a refreshed or planted uk that differs from the stored one is not
 *     exempt.  For every non-exempt member the matching accts entry's identity
 *     signature must verify under its curve_pk / mldsa_pk AND the roster uk must
 *     open the attested tag, acq == KDF(uk); a member without a matching AcqRec
 *     whose ACCT is missing or whose uk does not match is GY_ERR_VERIFY.  So the
 *     caller must supply the NEW-epoch ACCT for any member that refreshed its
 *     uk.  A still-pending invite (uk_len 0) is skipped; a settled invitee is
 *     exempt (its uk is bound by the invitee's own acceptance signature);
 *   - the signer must be an admin in the fetched roster;
 *   - anti-rollback lineage ([CFG+] Fig. 15 UsrVfyUpdate, D-QGS-14 E11): if a
 *     prior view is supplied (prior != NULL, prior_count > 0), the fetched
 *     version must follow the paper exactly.  A rollback (vMaj < prior_vmaj, or
 *     vMaj == prior_vmaj with a lower core-sig last-vMin than prior_vmin) is
 *     GY_ERR_STATE, and so is a SKIP past the next major (vMaj > prior_vmaj + 1,
 *     Fig. 15 "version skipped").  On the exact next major (vMaj ==
 *     prior_vmaj + 1) the new core's core-sig version (its folded last-vMin)
 *     must equal prior_apx_line_count, the NUMBER of appendix lines the caller
 *     last saw (Consolidate signs last_vMin = |apx|), else GY_ERR_STATE (Fig. 15
 *     "min version skipped": the admin must have consolidated exactly the
 *     appendix the caller was caught up to).  This is NOT the appendix header's
 *     vMin field: that field is a deployer-set constant, and passing it (when it
 *     is smaller than the true line count) would let a colluding server present
 *     a core folded from a hidden SHORTER appendix and defeat this check, so the
 *     caller MUST pass the true count of lines it saw.  The signer must
 *     additionally have been an admin in the prior view.  On the same major
 *     (vMaj == prior_vmaj) a refetch whose core-sig last-vMin is unchanged is
 *     accepted (the Fig. 10 minor-version path).  prior_apx_line_count is
 *     ignored when no prior is supplied.  A first fetch, or a deployer that
 *     keeps no prior,
 *     passes prior == NULL / prior_count == 0 and forfeits the anti-rollback
 *     property (the library keeps no membership state).
 *
 * Appendix consumption ([CFG+] Fig. 15 UsrVfyUpdate over Fig. 16
 * CheckAppendixLine, D-QGS-13 E7): apx / apx_len is the appendix wire object
 * the server serves alongside the core (NULL / 0 when the group has none).  Its
 * header GID and vMaj must match the fetched core.  Each line is verified under
 * its author's recomputed pseudonym key (the author's stored H(vkpsdn) for an
 * existing member, or, for a JOIN newcomer not yet in the vk-lst, the UID
 * carried inside the sealed line resolved through an AcqRec / accts entry); a
 * line with a bad signature is ignored.  addUser is gated on the group's b_add
 * setting and modAttr on b_attr (both read from the sealed header field); a JOIN
 * requires an open join link; an addUser whose commitment does not open is
 * ignored.  Valid lines are applied to the returned roster in the paper's kind
 * order (join / addUser append, then refresh replaces a member's uk, then
 * modAttr replaces the returned attributes, then leave removes), and out /
 * out_count therefore describe the EFFECTIVE roster.  reports[0..reports_cap)
 * receives one gy_qsgroup_apx_report per appendix line in wire order (pass
 * reports == NULL to query the count into *n_reports; GY_ERR_TOOLONG if
 * reports_cap is smaller than the line count, with *n_reports set); n_reports
 * may be NULL only when apx is NULL.  attr_out[0..attr_cap) receives the group
 * attributes after any valid modAttr is applied (buffer convention: attr_out
 * NULL reports the length into *attr_len; GY_ERR_TOOLONG if attr_cap is too
 * small); pass attr_len NULL to skip the attributes.
 *
 * Invite-queue settling ([CFG+] App. B.7, D-QGS-13 E3):
 * invite_queue / invite_queue_len is the invite-queue wire object (NULL / 0
 * when empty).  For each pending roster member (an Invite entry that carries no
 * uk yet), Fetch opens the queue with the group join key derived from gk and,
 * when it finds an acceptance whose invitee signature verifies under that UID's
 * ACCT identity keys, reports that member as settled with the accepted uk.  An
 * unmatched pending member stays reported with uk_len 0.
 *
 * prior is the caller's retained roster from its last accepted fetch; accts are
 * the ACCTs the deployer fetched for members this custodian is not acquainted
 * with (may be NULL / 0 when the custodian is acquainted with everyone).
 * *out_count receives the number of members written; pass out == NULL to query
 * the roster size, GY_ERR_TOOLONG if max is smaller than the roster.  A bad
 * signature, a vk-lst mismatch, a rollback / skipped version, or a member entry
 * that fails to decrypt is GY_ERR_VERIFY (GY_ERR_STATE for the version lineage);
 * zero each view (uk is secret) when done.  Returns GY_ERR_UNSUPPORTED on a
 * classical-suite custodian, GY_ERR_STATE if locked, GY_ERR_ARG on a NULL
 * argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_fetch(
    gy_custodian *c, const uint8_t *hdr, size_t hdr_len,
    const uint8_t *member_list, size_t member_list_len, const uint8_t *vk_lst,
    size_t vk_lst_len, const uint8_t *sig, size_t sig_len, const uint8_t *apx,
    size_t apx_len, const uint8_t *invite_queue, size_t invite_queue_len,
    uint32_t prior_vmaj, uint32_t prior_vmin, uint32_t prior_apx_line_count,
    const struct gy_qsgroup_member_view *prior, size_t prior_count,
    const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
    struct gy_qsgroup_member_view *out, size_t max, size_t *out_count,
    struct gy_qsgroup_apx_report *reports, size_t reports_cap,
    size_t *n_reports, uint8_t *attr_out, size_t attr_cap, size_t *attr_len);

/* ---- values for talking to a section-7.3 server ------------------------- */

/* The tier's full pseudonym key (vkr) width; a caller sizes the buffers below to
 * this or uses the size query.  (GY_QSGROUP_FET_LEN is defined up top.) */
#define GY_QSGROUP_VKR_MAX 2592

/*
 * Write this member's full pseudonym verification key (vkr) for group gid into
 * out.  A member publishes this to the server WITH its first signed submission
 * for the group (the signed core or an appendix line): the core's vk-lst stores
 * only H(vkr), so the server needs the full key to resolve and verify a
 * signature (geryon_qsgroups_server.h's core_check / apx_check take it as
 * signer_vkr / author_vkr).  It is a PUBLIC key, and it changes when the group
 * key rotates (removal / rotate).  Size query per the buffer convention.
 * Returns GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * locked, GY_ERR_NOT_FOUND if the caller does not hold gid, GY_ERR_ARG on a
 * NULL argument or short buffer, else GY_OK.
 */
GY_EXPORT int
gy_custodian_qsgroup_self_vkr(gy_custodian *c,
                              const uint8_t gid[GY_QSGROUP_GID_LEN],
                              uint8_t *out, size_t *out_len);

/*
 * Write group gid's fetch token (GY_QSGROUP_FET_LEN bytes) into out.  This is
 * the bearer token a member presents to fetch the group's core; the server
 * checks it with geryon_qsgroups_server.h's fetch_check / token_check.  It is
 * derived from the group key, so every member holds it and it rotates with the
 * group key.  Size query per the buffer convention.  Returns GY_ERR_UNSUPPORTED
 * on a classical-suite custodian, GY_ERR_STATE if locked, GY_ERR_NOT_FOUND if
 * the caller does not hold gid, GY_ERR_ARG on a NULL argument or short buffer,
 * else GY_OK.
 */
GY_EXPORT int
gy_custodian_qsgroup_fetch_token(gy_custodian *c,
                                 const uint8_t gid[GY_QSGROUP_GID_LEN],
                                 uint8_t *out, size_t *out_len);

/*
 * Leaver fetch token ([CFG+] Fig. 10, lower half): a departed member can still
 * fetch group gid, to confirm its removal was reconciled, by presenting a
 * signature over (GID, k) under its (former) pseudonym key in place of the
 * gk-derived fet it no longer shares.  k is the caller's index in the vk-lst of
 * the version it belonged to.  The token is the raw signature; the caller
 * conveys k and its pseudonym key (gy_custodian_qsgroup_self_vkr) to the server,
 * which checks the token with gy_qsgroups_server_leave_fetch_check.  Size query
 * per the buffer convention (out == NULL reports the signature length).  The
 * caller must still hold the group's key at rest.  Returns GY_ERR_UNSUPPORTED on
 * a classical-suite custodian, GY_ERR_STATE if locked, GY_ERR_NOT_FOUND if the
 * caller does not hold gid, GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on a
 * NULL argument, else GY_OK.
 *
 * Deployer note (SEC-v1.5.0 LOW-1): the fetch token no longer travels in the
 * served header (it is a separate server record; see struct gy_qsgroup_core),
 * so serving a leaver its removal-proving version discloses no bearer secret.
 * Still treat this path as single-use: serve a leaver exactly the one version
 * that proves its removal.  See QSPGS_SPEC.md section 10.2 item 5.
 */
GY_EXPORT int gy_custodian_qsgroup_leave_fetch_token(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN], uint32_t k,
    uint8_t *out, size_t *out_len);

/* Identity public-key widths (for publishing to peers who accept your ACCT):
 * the XEdDSA curve public key and the ML-DSA public key. */
#define GY_QSGROUP_ID_CURVE_MAX 57
#define GY_QSGROUP_ID_MLDSA_MAX GY_QSGROUP_VKR_MAX

/*
 * Write this custodian's hybrid identity public keys - the XEdDSA curve public
 * key into curve_pk (curve_len: capacity in, length out) and the ML-DSA public
 * key into mldsa_pk (mldsa_len: capacity in, length out).  A member publishes
 * these so a peer can pass them to gy_custodian_qsgroup_accept_acquaintance
 * when accepting this member's registration record (the ACCT is signed by the
 * identity, and its PKI binding IS the identity per [CFG+] footnote 7).  These
 * are public keys, unchanging for the identity.  Pass either out pointer as
 * NULL to report both required sizes (size query).  Returns GY_ERR_UNSUPPORTED
 * on a classical-suite custodian, GY_ERR_STATE if locked or without an
 * identity, GY_ERR_ARG on a NULL length pointer or a short buffer, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_identity_public(gy_custodian *c,
                                                   uint8_t *curve_pk,
                                                   size_t *curve_len,
                                                   uint8_t *mldsa_pk,
                                                   size_t *mldsa_len);

/* The group-key envelope width: a 3-byte typed object header, then the GID plus
 * the 2*kappa group key (SEC-v1.5.0 INFO-4). */
#define GY_QSGROUP_KEY_ENVELOPE_MAX 75

/*
 * Export group gid's key as an opaque envelope for delivery to a member being
 * added.  The envelope is a TYPED distribution frame (SEC-v1.5.0 INFO-4): a
 * 3-byte object header (kind || wire version || suite id, the same header every
 * other top-level QSPGS wire object carries) followed by the GID and the group
 * key, versioned from day one like the classical group's key-distribution
 * frame.  It carries the group secret, so a caller MUST send it only over a
 * confidential channel (a pairwise messaging session); it is opaque to the
 * caller, which just forwards it.  Size query per the buffer convention.
 * Returns GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * locked, GY_ERR_NOT_FOUND if the caller does not hold gid, GY_ERR_ARG on a
 * NULL argument or short buffer, else GY_OK.
 */
GY_EXPORT int
gy_custodian_qsgroup_export_group_key(gy_custodian *c,
                                      const uint8_t gid[GY_QSGROUP_GID_LEN],
                                      uint8_t *out, size_t *out_len);

/*
 * Install a group-key envelope received (over a confidential channel) from an
 * admin who added the caller: seal the group key into the custodian store so
 * the caller can now fetch the group and operate in it.  out_gid (may be NULL)
 * receives the group id carried in the envelope.  The typed object header is
 * validated (kind, wire version, and this custodian's suite): a header that
 * does not match, for example a foreign-suite or unknown-version envelope, is
 * GY_ERR_VERIFY; a wrong-length or NULL envelope is GY_ERR_ARG.  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if locked,
 * else GY_OK.
 *
 * INSTALL OVERWRITES UNCONDITIONALLY (SEC-v1.5.0 INFO-4): a valid envelope for
 * a GID replaces any group key the caller already stored for it (a legitimate
 * re-add must work, and the library holds no membership state to arbitrate,
 * D-QGS-8).  The envelope is not admin-authenticated: any pairwise peer can send
 * one.  The application therefore MUST accept an envelope only from the admin it
 * expects to have added it; accepting one from an arbitrary contact lets that
 * contact clobber the caller's stored group key (an availability loss, no
 * exposure).  Deciding whom to accept from is an application duty (D-SES-1 /
 * GROUP_SPEC section 9), not something the library can enforce.
 */
GY_EXPORT int
gy_custodian_qsgroup_install_group_key(gy_custodian *c, const uint8_t *env,
                                       size_t env_len,
                                       uint8_t out_gid[GY_QSGROUP_GID_LEN]);

/* ---- admin core edits --------------------------------------------------- */

/*
 * A group's signed core carried as its four canonical wire objects, the I/O
 * bundle for the admin core edits below.  An edit takes the CURRENT core (all
 * four buffers are inputs; each *_len is that object's length) and writes the
 * NEW core into a separate bundle whose buffers follow the create-style buffer
 * convention: on entry each *_len is the buffer capacity; pass any of the four
 * `next` buffers as NULL to have all four required sizes reported and nothing
 * committed; a short buffer yields GY_ERR_TOOLONG with the needed sizes written
 * back and nothing committed.  The four objects are the same the server checks
 * (geryon_qsgroups_server.h) and fetch consumes; the deployer ships and stores
 * them.
 *
 * fet is the group version's fetch token (GY_QSGROUP_FET_LEN bytes), always
 * populated on a committed (non-query) emit.  Since SEC-v1.5.0 LOW-1 it is NOT
 * inside the signed header: the deployer stores it as a SEPARATE per-version
 * server record (feeding gy_qsgroups_server_fetch_check) and MUST NOT serve it
 * back inside the header.  It is not part of any buffer-size query and needs no
 * capacity input.  See QSPGS_SPEC.md section 10.2 item 5.
 */
struct gy_qsgroup_core {
    uint8_t *hdr;
    size_t hdr_len;
    uint8_t *member_list;
    size_t member_list_len;
    uint8_t *vk_lst;
    size_t vk_lst_len;
    uint8_t *sig;
    size_t sig_len;
    uint8_t fet[GY_QSGROUP_FET_LEN];
};

/*
 * Every admin core edit has the same shape: verify the current core (the caller
 * must be an admin member of it), apply the change in memory, and re-sign the
 * whole core as the new state version (major-version bump; a fresh group key on
 * removal / rotation).  The caller's group pseudonym signs it; the identity key
 * never leaves the custodian.
 *
 * Group-key staging (SEC-v1.5.0 LOW-4): an edit that rotates the group key
 * (RemoveMember, RotateGroupKey, RevokeInvitation, and a Consolidate that folds
 * a leave) does NOT commit the fresh key locally on return.  It STAGES it and
 * leaves the current key in place, so a server rejection cannot strand the
 * admin on a key the group no longer uses.  After submitting the emitted core,
 * the caller MUST resolve the edit: gy_custodian_qsgroup_commit(gid) on server
 * accept, or gy_custodian_qsgroup_rollback(gid) on reject.  This is the group
 * analogue of the messaging send path's gy_commit / gy_rollback (D-SES-10).  A
 * second rotating edit on a group whose previous edit is unresolved returns
 * GY_ERR_STATE.  Non-rotating edits (AddMember, SetAdminRights) do not stage.
 *
 * All resolve the members they touch from the
 * custodian's own state: the current group key (sealed under the core's GID,
 * GY_ERR_NOT_FOUND if absent) and, for every member's base verification key,
 * the caller's own base record or an accepted acquaintance (GY_ERR_NOT_FOUND if
 * a member's acct was never accepted).  Common returns: GY_ERR_UNSUPPORTED on a
 * classical-suite custodian, GY_ERR_STATE if locked or if the caller is not an
 * admin member, GY_ERR_VERIFY if the current core fails verification,
 * GY_ERR_NOT_FOUND as above, GY_ERR_ARG on a NULL/oversize argument, else GY_OK.
 */

/*
 * AddMember: append new_uid as a non-admin member.  Both the member's base key
 * and its user key uk come from the accepted acquaintance record (D-QGS-13 E4:
 * that uk was checked against the attested acq at accept-acquaintance); no user
 * key is accepted out of band.  GY_ERR_NOT_FOUND if new_uid has no acquaintance
 * record.  The group key is unchanged.
 */
GY_EXPORT int gy_custodian_qsgroup_add_member(gy_custodian *c,
                                              const struct gy_qsgroup_core *cur,
                                              const uint8_t *new_uid,
                                              size_t new_uid_len,
                                              struct gy_qsgroup_core *next);

/*
 * SetAdminRights: set member target_uid's admin flag to admin (0 or 1).  The
 * group key is unchanged.  GY_ERR_NOT_FOUND if target_uid is not a member.
 */
GY_EXPORT int gy_custodian_qsgroup_set_admin(gy_custodian *c,
                                             const struct gy_qsgroup_core *cur,
                                             const uint8_t *target_uid,
                                             size_t target_uid_len, int admin,
                                             struct gy_qsgroup_core *next);

/*
 * RemoveMember: drop member target_uid, mint a fresh group key, and re-encrypt
 * and re-publish every surviving member under it (the removed member's
 * pseudonym no longer resolves).  The caller cannot remove ITSELF this way
 * (GY_ERR_ARG): a geryon core edit is self-signed and the signer must remain in
 * the emitted roster, so a direct self-removal would produce an unverifiable
 * core.  To remove yourself (admin or not, [CFG+] Fig. 17 note), author a LEAVE
 * appendix line with gy_custodian_qsgroup_appendix_leave while still a member
 * and have another admin fold it at gy_custodian_qsgroup_consolidate, which
 * rotates the group key on the folded leave.  GY_ERR_NOT_FOUND if target_uid is
 * not a member.  If the group has an open join link it is re-sealed under the
 * static link secret so it survives the rotation; if this admin does not hold
 * that secret the slot is dropped and the call returns the positive
 * GY_QSGROUP_JOIN_LINK_DROPPED.
 */
GY_EXPORT int gy_custodian_qsgroup_remove_member(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t *target_uid, size_t target_uid_len,
    struct gy_qsgroup_core *next);

/*
 * RotateGroupKey: mint a fresh group key and re-encrypt / re-publish every
 * member under it, with no membership change (RemoveMember without the drop).
 * Join-link handling and the GY_QSGROUP_JOIN_LINK_DROPPED return match
 * RemoveMember.
 */
GY_EXPORT int
gy_custodian_qsgroup_rotate_group_key(gy_custodian *c,
                                      const struct gy_qsgroup_core *cur,
                                      struct gy_qsgroup_core *next);

/*
 * Resolve the group key a rotating edit staged for group gid (SEC-v1.5.0
 * LOW-4).  Call gy_custodian_qsgroup_commit after the server accepts the edit's
 * core: it promotes the staged key to current and supersedes the old one.  Call
 * gy_custodian_qsgroup_rollback if the server rejects: it discards the staged
 * key and keeps the current one.  commit returns GY_ERR_NOT_FOUND if nothing is
 * staged for gid; rollback is idempotent (GY_OK if nothing is staged).  Both
 * return GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * locked, GY_ERR_ARG on a NULL gid.
 */
GY_EXPORT int
gy_custodian_qsgroup_commit(gy_custodian *c,
                            const uint8_t gid[GY_QSGROUP_GID_LEN]);
GY_EXPORT int
gy_custodian_qsgroup_rollback(gy_custodian *c,
                              const uint8_t gid[GY_QSGROUP_GID_LEN]);

/* ---- invitations -------------------------------------------------------- */

/* The largest invite-queue entry this library emits, over both hybrid tiers.
 * A caller sizes an invite-entry buffer to this. */
#define GY_QSGROUP_INVITE_MAX 6656

/*
 * An opened invite (OpenInvitation output): the invited UID and the group user
 * key the invitee derived from its own master user key and signed for.  uk is
 * secret material an admin needs to settle the entry (CompleteInvitation); zero
 * the view when done.
 */
struct gy_qsgroup_invite_view {
    uint8_t uid[GY_QSGROUP_UID_MAX];
    size_t uidlen;
    uint8_t uk[GY_QSGROUP_USER_KEY_MAX];
    size_t uk_len;
};

/*
 * Invite (admin core edit, [CFG+] App. B.7): append a PENDING member entry for
 * invitee_uid, taking that UID's base key from an acquaintance record or, if the
 * caller is not acquainted, from the server-served ACCT passed in acct (NULL if
 * acquainted; the acct fields point at a GY_QOBJ_ACCT wire object).  The caller
 * mints NO user key.  A fresh per-invite join-key basis gk' is written to
 * gkprime_out (gkprime_out_len: capacity in, length out; size to
 * GY_QSGROUP_USER_KEY_MAX) - share it with the invitee over a pairwise secure
 * channel: the invitee and every opening member derive the invite key from it.
 * The re-signed core is emitted into next per the four-object edit convention
 * (any next buffer NULL => size query, in which case gkprime_out may be NULL).
 * Returns GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * locked or the caller is not an admin, GY_ERR_NOT_FOUND if the invitee's base
 * key resolves to neither an acquaintance record nor acct, GY_ERR_TOOLONG on a
 * short buffer, GY_ERR_ARG on a NULL/oversize argument, else GY_OK.
 */
GY_EXPORT int
gy_custodian_qsgroup_invite(gy_custodian *c, const struct gy_qsgroup_core *cur,
                            const uint8_t *invitee_uid, size_t invitee_uid_len,
                            const struct gy_qsgroup_acct_ref *acct,
                            uint8_t *gkprime_out, size_t *gkprime_out_len,
                            struct gy_qsgroup_core *next);

/*
 * AcceptInvitation (invitee, [CFG+] App. B.7 / D-QGS-6 item 2): derive this
 * caller's group user key uk = KDF(muk, "uk@" || ep) from its OWN master user
 * key, sign (UID, uk, GID) with its OWN hybrid identity through the custodian
 * seam, and seal the (UID, uk, signature) acceptance to the invite key derived
 * from gkprime (the gk' the admin shared, gkprime_len = the tier master-key
 * length).  ep is the caller's user-key epoch, as at register.  The invite-queue
 * entry is written to entry_out (entry_out_len: capacity in, length out; size to
 * GY_QSGROUP_INVITE_MAX) for the deployer to append to gid's queue.  Returns
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if locked or
 * the caller has no UID, GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on a
 * NULL/oversize argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_accept_invitation(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN],
    const uint8_t *gkprime, size_t gkprime_len, uint64_t ep, uint8_t *entry_out,
    size_t *entry_out_len);

/*
 * OpenInvitation (any member): open an invite-queue entry with the invite key
 * derived from gkprime (the gk' from the invitee's pending entry) and verify its
 * dual signature against the INVITED UID's hybrid identity public keys
 * (invitee_curve_pk / invitee_mldsa_pk, held from accept-acquaintance or the
 * messaging layer).  On success out receives the invited (uid, uk).  A tampered
 * entry or a bad signature is GY_ERR_VERIFY.  Returns GY_ERR_UNSUPPORTED on a
 * classical-suite custodian, GY_ERR_STATE if locked, GY_ERR_ARG on a
 * NULL/oversize argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_open_invitation(
    gy_custodian *c, const uint8_t gid[GY_QSGROUP_GID_LEN],
    const uint8_t *gkprime, size_t gkprime_len, const uint8_t *entry,
    size_t entry_len, const uint8_t *invitee_curve_pk,
    const uint8_t *invitee_mldsa_pk, struct gy_qsgroup_invite_view *out);

/*
 * CompleteInvitation (admin core edit): settle an accepted invitee (its uid and
 * uk from OpenInvitation) by filling the accepted uk into that UID's PENDING
 * member entry, re-sealing the entry in its settled form (admn and the vk-lst
 * hash unchanged), and re-signing the core into next.  The invitee must already
 * be a pending member (from a prior Invite), else GY_ERR_NOT_FOUND.  After a
 * committed success the deployer drops the drained entry from gid's queue (or
 * calls gy_custodian_qsgroup_revoke_invitation).  Same returns as the edits.
 *
 * This is geryon's completion of an outstanding invite, NOT the [CFG+]
 * ApproveJoin functionality (admin approval of a link joiner when b_adm is set,
 * App. B.8): that gated-join path is reconciled inside Consolidate / Fetch.
 */
GY_EXPORT int gy_custodian_qsgroup_complete_invitation(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t *invitee_uid, size_t invitee_uid_len,
    const uint8_t *invitee_uk, size_t invitee_uk_len,
    struct gy_qsgroup_core *next);

/*
 * Consolidate (admin, [CFG+] Fig. 18, D-QGS-13 E7): fold an appendix into the
 * next major version.  cur is the current core (4 wire objects); apx / apx_len
 * is the appendix object to reconcile (NULL / 0 folds nothing), and its header
 * GID and vMaj must match cur.  Each line is checked exactly as Fetch checks it
 * (CheckAppendixLine: signature under the author's recomputed pseudonym key,
 * b_add gating addUser, b_attr gating modAttr, an open link for join, the C_UID'
 * commitment for a new member); only valid lines fold, applied in the paper's
 * kind order (join / addUser append, refresh replaces a uk, modAttr replaces the
 * attributes, leave removes).  When any leave folds, the group key is rotated
 * (fresh gk, every member re-encrypted and re-keyed, §3.3); otherwise the group
 * key is kept and the new members are appended under it.  invite_queue is the
 * current queue (NULL / 0 when empty): a pending member whose acceptance in the
 * queue verifies under its ACCT identity keys is settled with the accepted uk,
 * and the drained queue (that entry removed) is written to queue_out
 * (queue_out_len: capacity in, length out; never larger than invite_queue_len,
 * and queue_out_len may be NULL only when invite_queue is NULL).  accts resolve
 * the base keys of members / newcomers the caller is not acquainted with, as in
 * Fetch.  next receives the emitted core at (vMaj + 1, last vMin = |apx|),
 * signed by the caller (an admin), following the four-object buffer convention.
 *
 * approved_idx[0..n_approved) gates the paper's ApproveJoin ([CFG+] App. B.8,
 * D-QGS-14 E9): when the group requires admin approval of link joiners (b_adm
 * set in the sealed settings), a valid JOIN line folds into the roster only if
 * its appendix-line index (its position in apx wire order, matching the Fetch
 * report index) appears in approved_idx; an unapproved JOIN line drops with the
 * appendix, and the joiner may re-join.  When b_adm is clear, approved_idx is
 * ignored and every valid JOIN line folds.  Pass NULL / 0 to approve none (the
 * common b_adm-clear call).  All other line kinds ignore approved_idx.
 *
 * Returns GY_QSGROUP_JOIN_LINK_DROPPED (positive) if a rotation dropped an open
 * join link the caller does not hold the secret for (as RotateGroupKey does),
 * GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if locked or
 * the caller is not an admin (or would remove itself), GY_ERR_NOT_FOUND if the
 * caller does not hold the group or a member's base key does not resolve,
 * GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on a NULL argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_consolidate(
    gy_custodian *c, const struct gy_qsgroup_core *cur, const uint8_t *apx,
    size_t apx_len, const uint8_t *invite_queue, size_t invite_queue_len,
    const struct gy_qsgroup_acct_ref *accts, size_t n_accts,
    const uint32_t *approved_idx, size_t n_approved,
    struct gy_qsgroup_core *next, uint8_t *queue_out, size_t *queue_out_len);

/*
 * RevokeInvitation (admin core edit, [CFG+] App. B.7 / Fig. 17, D-QGS-14 E10):
 * revoke a not-yet-accepted invitation for target_uid.  This is a real core
 * edit, not a queue-only scrub: the target's PENDING member entry (the
 * (C_UID, mct, 0) line) is removed from cur and the group key is rotated,
 * exactly as RemoveMember does ("similar as in Figure 17"), so the invitee -
 * who still holds the per-invite gk' - cannot re-accept and be settled back in.
 * next receives the emitted core at (vMaj + 1) signed by the caller (an admin),
 * following the four-object buffer convention (query it with NULL out pointers
 * to size the objects).  The caller must be an admin member of cur.
 *
 * The target's queued acceptance is drained in the same call: queue entries are
 * opaque PKE ciphertexts (no cleartext UID), so the target is identified by
 * opening cur_queue with the isk derived from target_uid's per-invite gk' (read
 * from its PENDING entry before the edit); the drained queue (that entry
 * removed, others copied verbatim) is written to out_queue (out_queue_len:
 * capacity in, length out; never larger than cur_queue_len).  target_uid must
 * be a pending invite in cur, else GY_ERR_NOT_FOUND.
 *
 * Returns GY_QSGROUP_JOIN_LINK_DROPPED (positive) if the rotation dropped an
 * open join link the caller does not hold the secret for (as RemoveMember /
 * RotateGroupKey do), GY_ERR_UNSUPPORTED on a classical-suite custodian,
 * GY_ERR_STATE if locked or the caller is not an admin, GY_ERR_NOT_FOUND if the
 * caller does not hold the group or target_uid is not pending, GY_ERR_TOOLONG on
 * a short buffer, GY_ERR_ARG on a NULL argument, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_revoke_invitation(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t *cur_queue, size_t cur_queue_len, const uint8_t *target_uid,
    size_t target_uid_len, struct gy_qsgroup_core *next, uint8_t *out_queue,
    size_t *out_queue_len);

/*
 * Append one invite-queue entry (from gy_custodian_qsgroup_invite) to gid's
 * stored invite queue, producing the new queue.  This is the deployer-side
 * assembly step: the queue that AcceptInvitation entries are drawn from and that
 * RevokeInvitation rebuilds.  cur_queue may be NULL with cur_queue_len 0 for the
 * first entry; otherwise it is the current queue this call extends.  The result
 * is written to out_queue (out_queue_len: capacity in, length out).  The append
 * is pure wire assembly (the entry ciphertext is copied verbatim, never opened),
 * so it needs no group key.  Returns GY_ERR_UNSUPPORTED on a classical-suite
 * custodian, GY_ERR_STATE if locked, GY_ERR_TOOLONG on a short out_queue or a
 * full queue, GY_ERR_ARG on a NULL/oversize argument, GY_ERR_VERIFY on a
 * malformed cur_queue, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_invite_queue_append(
    gy_custodian *c, const uint8_t *cur_queue, size_t cur_queue_len,
    const uint8_t *entry, size_t entry_len, uint8_t *out_queue,
    size_t *out_queue_len);

/* ---- settings, appendix (non-admin), and the join link ------------------ */

/*
 * Group settings bits ([CFG+] §3.2).  The header's sealed field plaintext is a
 * one-byte settings prefix followed by the application's opaque attributes:
 *   flags(1) = b_add | b_attr << 1 | b_adm << 2 || attr
 * so a fetching client can read the gating bits CheckAppendixLine needs.
 *   b_add  : non-admin members may add users (the UserAdd appendix line).
 *   b_attr : non-admin members may change attributes (the ChangeAttr line).
 *   b_adm  : admin approval gates link joins (ApproveJoin); geryon's own bit.
 */
#define GY_QSGROUP_SETTING_ADD 0x01u
#define GY_QSGROUP_SETTING_ATTR 0x02u
#define GY_QSGROUP_SETTING_ADM 0x04u

/* Largest opaque attributes blob accepted at Create / ChangeSettings. */
#define GY_QSGROUP_ATTR_MAX 1024

/* The out-of-band join-link secret width. */
#define GY_QSGROUP_LINK_SECRET_LEN 32

/*
 * Positive status (not an error) returned by remove_member / rotate_group_key:
 * the group had an open join link but this admin does not hold the link secret
 * (it was generated by another admin), so the rotation dropped the join slot
 * rather than re-seal it ([CFG+] App. B.8).  The rotation itself
 * succeeded; the emitted core has no link.  A deployer surfaces this so the
 * link owner can re-enable the link (the paper: the admin who generated the
 * join link communicates jk to the other admins).  All genuine failures remain
 * negative, so callers test `rc < 0` for error and may treat `rc > 0` as
 * success-with-caveat.
 */
#define GY_QSGROUP_JOIN_LINK_DROPPED 1

/* The largest single-line appendix object this library emits, over both
 * tiers.  A caller sizes an appendix-line buffer to this. */
#define GY_QSGROUP_APPENDIX_MAX 8192

/*
 * ChangeSettings / ChangeAttr: an admin edit that re-seals the group's settings
 * and attributes into the header under the group key and re-signs the core.
 * settings_flags is the b_add / b_attr / b_adm combination (GY_QSGROUP_SETTING_*)
 * and attr[0..attr_len) the opaque attributes blob (attr may be NULL only when
 * attr_len is 0; attr_len must not exceed GY_QSGROUP_ATTR_MAX).  The header
 * plaintext is flags(1) || attr, the single sealed field the [CFG+] data
 * structure carries, so one call covers both the settings and the attributes.
 * cur / next follow the admin-edit bundle convention above.  Same returns as
 * the edits.
 */
GY_EXPORT int gy_custodian_qsgroup_change_settings(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint8_t settings_flags,
    const uint8_t *attr, size_t attr_len, struct gy_qsgroup_core *next);

/*
 * Non-admin appendix operations.  A member who is not the editing admin records
 * an operation as an append-only, individually-signed appendix line, which an
 * admin later reconciles into a new core version.  Each call verifies the
 * current core (cur, the four objects), signs one line with the caller's group
 * pseudonym, and emits a single-line appendix object at the caller-supplied
 * minor version vmin into line_out (line_out_len: capacity in, length out; size
 * to GY_QSGROUP_APPENDIX_MAX).  The deployer appends the line to gid's stored
 * appendix (the server orders lines by vmin).  The caller must be a member of
 * the current core.  Returns GY_ERR_UNSUPPORTED on a classical-suite custodian,
 * GY_ERR_STATE if locked or not a member, GY_ERR_VERIFY if the current core
 * fails verification, GY_ERR_NOT_FOUND / GY_ERR_TOOLONG / GY_ERR_ARG as usual,
 * else GY_OK.
 *
 *   Leave    : announce the caller is leaving (empty payload).
 *   Refresh  : rotate the caller's user key to epoch ep (uk' = derive(muk,ep)),
 *              the [CFG+] blocking mechanism.
 *   ModAttr  : propose an opaque new attributes blob (attr).
 *   AddUser  : propose adding (new_uid, new_uk) (an admin approves it into the
 *              core at reconciliation; new_uk is minted / delivered as in the
 *              invite flow).
 *
 * AddUser additionally outputs the new member's attribution hash H(vkpsdn) into
 * vkhash_out ([CFG+] Fig. 12): the newcomer is not yet in the vk-lst, so the
 * deployer appends this hash to vk-lst when it accepts the line (the server's
 * newcomer apx_check path resolves the author against it).  It is computed from
 * new_uid's base key, taken from the caller's acquaintance record for new_uid
 * (GY_ERR_NOT_FOUND if the caller is not acquainted with new_uid), under the
 * current group rerandomization salt.  vkhash_out follows the buffer convention
 * (vkhash_out == NULL reports the suite hash length into *vkhash_out_len);
 * vkhash_out_len must be non-NULL.  It is a public value, safe to hand out.
 */
GY_EXPORT int gy_custodian_qsgroup_appendix_leave(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint32_t vmin,
    uint8_t *line_out, size_t *line_out_len);

GY_EXPORT int gy_custodian_qsgroup_appendix_refresh(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint32_t vmin,
    uint64_t ep, uint8_t *line_out, size_t *line_out_len);

GY_EXPORT int gy_custodian_qsgroup_appendix_mod_attr(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint32_t vmin,
    const uint8_t *attr, size_t attr_len, uint8_t *line_out,
    size_t *line_out_len);

GY_EXPORT int gy_custodian_qsgroup_appendix_add_user(
    gy_custodian *c, const struct gy_qsgroup_core *cur, uint32_t vmin,
    const uint8_t *new_uid, size_t new_uid_len, const uint8_t *new_uk,
    size_t new_uk_len, uint8_t *line_out, size_t *line_out_len,
    uint8_t *vkhash_out, size_t *vkhash_out_len);

/*
 * ToggleJoinLink: an admin edit that flips the header's join slot and re-signs
 * the core, keyed on the current state.  If the current core has no link, this
 * ENABLES one: it seals the group key and fetch token into the slot under a
 * freshly minted 32-byte secret, persists that secret (so it survives later
 * group-key rotation, App. B.8), and writes it to link_secret_out (required on
 * this transition); share it out of band with a prospective member, who joins
 * with gy_custodian_qsgroup_join_via_link.  If the current core already has a
 * link, this DISABLES it: the slot is dropped, the stored secret retired, and
 * link_secret_out is left untouched (may be NULL).  The caller holds cur, so it
 * knows which transition it requested.  cur / next follow the admin-edit bundle
 * convention.  Same returns as the edits.
 */
GY_EXPORT int gy_custodian_qsgroup_toggle_join_link(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    uint8_t link_secret_out[GY_QSGROUP_LINK_SECRET_LEN],
    struct gy_qsgroup_core *next);

/*
 * JoinViaLink: with the out-of-band link secret, open the current core's join
 * slot to recover the group key, seal it into the custodian store (the caller
 * becomes able to fetch and decrypt immediately), derive the caller's own user
 * key uk = KDF(muk, "uk@" || ep) (written to uk_out; deliver nothing - the
 * caller keeps it), and emit a JOIN appendix line (into line_out, size to
 * GY_QSGROUP_APPENDIX_MAX) for an admin to reconcile the caller into the core.
 * ep is the caller's user-key epoch, as at register.
 *
 * Before the group key is installed the current core's admin signature is
 * verified: the joiner holds no acquaintance records yet,
 * so it is a signature-only check against the signing admin's registration
 * object signer_acct (signer_acct / signer_acct_len), supplied out of band by
 * whoever shared the link.  The caller vouches for that ACCT identity; its full
 * dual-signature is verified when the joiner later accepts acquaintance, and the
 * all-member vk-lst recompute runs at the joiner's first Fetch.  A forged or
 * tampered core is rejected with GY_ERR_VERIFY before any state is stored.
 *
 * Returns GY_ERR_UNSUPPORTED on a classical-suite custodian, GY_ERR_STATE if
 * locked, GY_ERR_VERIFY if the slot does not open (wrong secret / no join link)
 * or the core signature does not verify under signer_acct, GY_ERR_TOOLONG /
 * GY_ERR_ARG as usual, else GY_OK.
 */
GY_EXPORT int gy_custodian_qsgroup_join_via_link(
    gy_custodian *c, const struct gy_qsgroup_core *cur,
    const uint8_t link_secret[GY_QSGROUP_LINK_SECRET_LEN], uint64_t ep,
    const uint8_t *signer_acct, size_t signer_acct_len, uint8_t *uk_out,
    size_t *uk_out_len, uint8_t *line_out, size_t *line_out_len);

#ifdef __cplusplus
}
#endif

#endif /* GERYON_QSPGS_H */
