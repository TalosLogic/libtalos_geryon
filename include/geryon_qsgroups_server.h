/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon_qsgroups_server.h - public server API for the quantum-safe private
 * group system (QSPGS_SPEC.md section 7, [CFG+] ePrint 2026/453), the hybrid
 * analogue of geryon_group_server.h.  A SEPARATE, STATELESS target
 * (geryon_qsgroups_server) shipping the section-7.3 acceptance checks and
 * nothing else.  It carries NO user identity, NO prekeys, NO sessions, NO core
 * secret parameter, and no KR-ML-DSA rerandomization internal (rrs / rho /
 * skpsdn): it never sees a custodian.  A client never links it, and this header
 * deliberately depends on NOTHING in geryon.h or geryon_qspgs.h, so the
 * client/server boundary (QSPGS_SPEC section 7.1, D-QGS-6) is an ABI property,
 * not only a symbol-audit one (tests/audit/nm_scope_qspgs_server.sh).
 *
 * HANDLE-FREE.  Unlike the classical group server, which seals a KVAC
 * ServerSecretParams and therefore needs a handle, a store, and a lifecycle,
 * the QSPGS server holds NO secret at all.  Every check below is a pure
 * function of its inputs.  There is no create / open / close and no server
 * store: a deployer calls these functions directly.  What state a deployment
 * keeps (the current core, the per-GID fetch/send tokens, the version head, the
 * invite queue) is the deployer's, held however it likes; this target verifies
 * and decides, it does not store.
 *
 * HYBRID ONLY.  QSPGS serves the hybrid suites geryon_h25519_512 and
 * geryon_h448_1024.  A classical suite id is GY_ERR_UNSUPPORTED (classical
 * groups have their own server, geryon_group_server.h); there is no runtime
 * negotiation and no cross-type fallback.
 *
 * WIRE OBJECTS ARE OPAQUE, DECODED INTERNALLY.  The protocol objects a member
 * submits arrive as the canonical, versioned byte strings the client produced.
 * These functions DECODE them internally against the frozen section-4 grammar;
 * the caller never assembles or inspects a decoded structure, and no wire
 * struct is part of this ABI.  The core is carried as its THREE constituent
 * objects (the header, the member-list, and the vk-lst), each an independently
 * framed, exact-length object (that is how the client emits and the codec
 * decodes them); a caller passes whichever the check needs, and never a
 * concatenation it would have to length-delimit itself.  A member's full
 * pseudonym key (vkr / vkpsdn), which it supplies with its first signature so
 * the server can resolve it against the stored H(vkpsdn), is the one raw fixed-
 * width value a caller passes; it is the tier's standard ML-DSA public key.
 *
 * DEPLOYER LIMITATION (section 7.4, D-QGS-6 item 5).  The server cannot validate
 * the CONTENTS of encrypted entries (member ciphertexts, appendix payloads,
 * invite / join slots): only members holding the group key or isk can open
 * them, and it does not try.  These checks bound WHO may write (a resolved
 * pseudonym; an admin line for a core edit), not whether an encrypted blob is
 * well-formed inside.  The mitigations are send-token rate limiting (section
 * 6.5) and admin cleanup at reconciliation, both deployer responsibilities.
 */
#ifndef GERYON_QSGROUPS_SERVER_H
#define GERYON_QSGROUPS_SERVER_H

#include <stddef.h>
#include <stdint.h>

/* Self-contained visibility macro and error codes: identical values to
 * geryon.h, guarded so this header may be included beside geryon.h or
 * geryon_qspgs.h in one TU. */
#ifndef GY_EXPORT
#if defined(__GNUC__) || defined(__clang__)
#define GY_EXPORT __attribute__((visibility("default")))
#else
#define GY_EXPORT
#endif
#endif

#ifndef GY_OK
#define GY_OK 0           /* Success. */
#define GY_ERR_ARG -1     /* NULL/short argument or a bad length. */
#define GY_ERR_CRYPTO -2  /* Underlying crypto or allocation failure. */
#define GY_ERR_VERIFY -3  /* Signature, hash, token, or grammar mismatch. */
#define GY_ERR_TOOLONG -4 /* Input exceeds a protocol length bound. */
#define GY_ERR_STATE -6   /* Version conflict / operation invalid in state. */
#define GY_ERR_UNSUPPORTED -7 /* Suite or capability not served here. */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* The hybrid suite ids the QSPGS server serves (guarded; same values as
 * geryon.h).  A classical suite id is GY_ERR_UNSUPPORTED. */
#ifndef GY_SUITE_H25519_512
#define GY_SUITE_H25519_512 0x02
#define GY_SUITE_H448_1024 0x04
#endif

/* The fetch-token width (section 6.5): the bearer token a client presents to
 * FetchGroup, checked against the core's stored fet.  Guarded so this header
 * may coexist with geryon_qspgs.h. */
#ifndef GY_QSGROUP_FET_LEN
#define GY_QSGROUP_FET_LEN 32
#endif

/* The fixed member-UID width (SEC-v1.5.0 LOW-2): a single width so a corrupt
 * server sees identical sealed member-entry lengths and learns member indices
 * only, never a per-entry length class.  The server keys registration and
 * acquaintance records by this UID; it is a shared wire contract.  Guarded so
 * this header may coexist with geryon_qspgs.h. */
#ifndef GY_QSGROUP_UID_LEN
#define GY_QSGROUP_UID_LEN 16
#endif

/*
 * Core-edit operation kind (section 7.3 item 1): a submission names its
 * operation so the stateless server can apply the [CFG+] per-operation vk-lst
 * rule against the stored prior version.  Guarded so this header may coexist
 * with the internal wire header (same values as GY_QSPGS_OP_*).  See
 * gy_qsgroups_server_core_check.
 */
#ifndef GY_QSGROUP_OP_CREATE
#define GY_QSGROUP_OP_CREATE 0     /* no prior; vk-lst = submitted, vMaj 1. */
#define GY_QSGROUP_OP_UNCHANGED 1  /* vk-lst == prior (SetAdminRights etc.). */
#define GY_QSGROUP_OP_APPEND_ONE 2 /* vk-lst == prior + one (AddMember etc.). */
#define GY_QSGROUP_OP_REPLACE 3    /* any vk-lst (RemoveMember/Rotate). */
#endif

/* ---- pure token / version checks ---------------------------------------- */

/*
 * Constant-time bearer-token check (section 7.3 item 5): compare a presented
 * token against the token the deployer stored for a GID (the header fetch token
 * fet, or a derived send token, section 6.5).  Both are opaque fixed-width
 * bearer bytes, so this is a single const-time equality over token_len bytes;
 * the server neither derives nor interprets them.  Returns GY_OK on a match,
 * GY_ERR_VERIFY on a mismatch, GY_ERR_ARG on a NULL argument or a zero length.
 */
GY_EXPORT int gy_qsgroups_server_token_check(const uint8_t *presented,
                                             const uint8_t *stored,
                                             size_t token_len);

/*
 * Version discipline / compare-and-swap (section 7.3 item 4): decide whether a
 * write applies to the deployer's current head.  Versions order
 * lexicographically as (vMaj, vMin).  A write NAMES the version it extends
 * ((ext_vmaj, ext_vmin), the head it read) and carries its new version
 * ((new_vmaj, new_vmin)).  The server, holding the current head ((cur_vmaj,
 * cur_vmin)), accepts iff the write BOTH extends the current head ((ext) ==
 * (cur), the compare-and-swap) AND strictly advances it ((new) > (cur)); it
 * NEVER merges.  Returns GY_OK to apply, or GY_ERR_STATE on a conflict (the
 * loser re-fetches the head and rebuilds).  A pure comparison; no argument can
 * be invalid.
 */
GY_EXPORT int
gy_qsgroups_server_version_check(uint32_t cur_vmaj, uint32_t cur_vmin,
                                 uint32_t ext_vmaj, uint32_t ext_vmin,
                                 uint32_t new_vmaj, uint32_t new_vmin);

/* ---- checks over opaque wire (decoded internally) ----------------------- */

/*
 * Fetch-token check (section 7.3 item 5): const-time compare presented
 * (GY_QSGROUP_FET_LEN bytes) against the group's stored fetch token fet.
 *
 * Since SEC-v1.5.0 LOW-1 fet is NOT carried in the served header (a signed,
 * byte-exact header disclosed the current token to every fetcher, including a
 * leaver's post-removal confirmation fetch).  The admin emits fet as a separate
 * record in the core bundle (struct gy_qsgroup_core .fet); the deployer stores
 * it per group version alongside the four wire objects and passes it here.  It
 * is never served back inside the header.  A convenience over
 * gy_qsgroups_server_token_check for the common case; a deployer-derived send
 * token uses the generic token check.  Returns GY_OK on a match, GY_ERR_VERIFY
 * on a mismatch, GY_ERR_UNSUPPORTED on a classical suite, GY_ERR_ARG on a NULL
 * argument.
 */
GY_EXPORT int gy_qsgroups_server_fetch_check(uint8_t suite_id,
                                             const uint8_t *fet,
                                             const uint8_t *presented);

/*
 * Core-signature acceptance (section 7.3 item 1, D-QGS-13 E2): the check a
 * server runs before applying an admin core edit, against the STORED prior
 * version.  Decodes the submitted core's three objects (header, member-list,
 * vk-lst, each exact-length), the core-signature object (sig_obj: signer index,
 * covered last_vMin, signature), and, unless op_kind is GY_QSGROUP_OP_CREATE,
 * the prior version's three objects, for suite_id.  op_kind (GY_QSGROUP_OP_*)
 * selects the [CFG+] per-operation vk-lst rule and where the signer's own
 * vkpsdn is resolved:
 *   CREATE     prior objects are NULL; the submitted core is the sole-member
 *              (n==1), vMaj==1, admin-signed genesis; signer resolves against
 *              the submitted vk-lst[0].
 *   UNCHANGED  submitted vk-lst MUST equal the prior byte for byte
 *              (SetAdminRights, ChangeSettings, ChangeAttr, ToggleJoinLink).
 *   APPEND_ONE submitted vk-lst MUST equal the prior with exactly one newcomer
 *              hash appended (AddMember, UserAdd, Invite).
 *   REPLACE    any submitted vk-lst accepted; rotation rerandomized every key
 *              and the server holds no gk (RemoveMember, RotateGroupKey).
 * For every non-CREATE op the admn gate reads the PRIOR member-list, so a
 * non-admin cannot self-promote by signing a next core that sets its own admn
 * bit; the signature then verifies over the SUBMITTED objects under the
 * resolved key.  Pass all three prior objects together or none; a partial
 * prior is GY_ERR_ARG.  signer_vkr is the signer's full pseudonym public key
 * (the tier's standard ML-DSA public key); signer_vkr_len must equal that tier
 * length.  Returns GY_OK on acceptance, GY_ERR_VERIFY on a non-admin signer, a
 * disallowed vk-lst transition, a hash mismatch, a bad signature, or a
 * malformed object, GY_ERR_UNSUPPORTED on a classical suite, GY_ERR_TOOLONG if
 * a list exceeds the entry bound, GY_ERR_ARG on bad input (unknown op_kind,
 * partial prior, prior present for a CREATE or absent for a non-CREATE, or a
 * signer_index past the relevant list), or GY_ERR_CRYPTO on an allocation
 * failure.
 */
GY_EXPORT int gy_qsgroups_server_core_check(
    uint8_t suite_id, uint8_t op_kind, const uint8_t *prior_header_obj,
    size_t prior_header_obj_len, const uint8_t *prior_member_list_obj,
    size_t prior_member_list_obj_len, const uint8_t *prior_vk_lst_obj,
    size_t prior_vk_lst_obj_len, const uint8_t *header_obj,
    size_t header_obj_len, const uint8_t *member_list_obj,
    size_t member_list_obj_len, const uint8_t *vk_lst_obj,
    size_t vk_lst_obj_len, const uint8_t *sig_obj, size_t sig_obj_len,
    const uint8_t *signer_vkr, size_t signer_vkr_len);

/*
 * Appendix-line acceptance (section 7.3 item 2): verify one append-only line's
 * signature under its author's full pseudonym key.  Decodes the appendix object
 * (apx_obj) for suite_id and selects the line at line_index.  Newcomer status
 * is derived from the decoded line, not trusted from the caller: ONLY a join
 * line is authored under a key not yet in the vk-lst, so only a join skips the
 * stored-hash resolution (SEC-v1.5.0 LOW-3).  Every other line kind (leave,
 * refresh, addUser, modAttr) is authored by an EXISTING member: its vk-lst
 * object (vk_lst_obj) is decoded and the line's author_index resolves
 * author_vkr against the stored H(vkpsdn) at that index (const-time, item 3);
 * author_index past the vk-lst is GY_ERR_ARG.  The newcomer argument MUST match
 * the decoded line (nonzero iff the line is a join) or the call is GY_ERR_ARG;
 * derive it from the line type, never from the submitter.  For a join pass
 * vk_lst_obj == NULL (no hash resolution; the deployer appends H(author_vkr) to
 * the vk-lst on acceptance); a non-join with vk_lst_obj == NULL is GY_ERR_ARG.
 * The line payload is never opened (it is an opaque ek ciphertext).  author_vkr
 * is the tier's standard ML-DSA public key; author_vkr_len must equal that tier
 * length.  Returns GY_OK, GY_ERR_VERIFY on a hash mismatch, a bad signature, or
 * a malformed object, GY_ERR_UNSUPPORTED on a classical suite, GY_ERR_TOOLONG
 * if a list exceeds the entry bound, GY_ERR_ARG on bad input (line_index past
 * the appendix, or a newcomer flag that disagrees with the line), or
 * GY_ERR_CRYPTO on an internal allocation failure.
 */
GY_EXPORT int gy_qsgroups_server_apx_check(
    uint8_t suite_id, const uint8_t *vk_lst_obj, size_t vk_lst_obj_len,
    const uint8_t *apx_obj, size_t apx_obj_len, size_t line_index,
    const uint8_t *author_vkr, size_t author_vkr_len, int newcomer);

/*
 * Leaver fetch-token check ([CFG+] Fig. 10, lower half): authorize a departed
 * member's fetch by verifying its token (from gy_custodian_qsgroup_leave_fetch_token)
 * over (GID, k) under the pseudonym key it held.  vk_lst_obj is the vk-lst of
 * the version the leaver belonged to; k is the leaver's index in it.  leaver_vkr
 * (the tier's standard ML-DSA public key; leaver_vkr_len must equal that tier
 * length) is resolved against the stored H(vkpsdn) at index k (const-time), then
 * the token signature is verified under it.  gid is the group id the server
 * serves.  The deployer decides what fetch this authorizes (it does not grant a
 * token; it confirms membership at version k).  Returns GY_OK, GY_ERR_VERIFY on
 * a hash mismatch or bad signature, GY_ERR_UNSUPPORTED on a classical suite,
 * GY_ERR_TOOLONG if the vk-lst exceeds the entry bound, GY_ERR_ARG on bad input
 * (k past the vk-lst included), or GY_ERR_CRYPTO on an allocation failure.
 *
 * Deployer note (SEC-v1.5.0 LOW-1): the fetch token no longer travels in the
 * served header (it is a separate server record), so the version served to a
 * leaver discloses no bearer secret.  Still treat this check as single-use:
 * serve a leaver exactly the one version that proves its removal.  See
 * QSPGS_SPEC.md section 10.2 item 5.
 */
GY_EXPORT int gy_qsgroups_server_leave_fetch_check(
    uint8_t suite_id, const uint8_t *vk_lst_obj, size_t vk_lst_obj_len,
    const uint8_t *gid, uint32_t k, const uint8_t *sig, size_t sig_len,
    const uint8_t *leaver_vkr, size_t leaver_vkr_len);

/*
 * Appendix assembly: append the lines of a submitted appendix object (line_obj,
 * as a member's appendix-line calls emit - itself a valid one-line appendix
 * object) to the group's accumulated appendix (cur_apx), producing the new
 * appendix object in out.  This is the deployer-side wire assembly a coordinator
 * runs after apx_check accepts a line, so it never has to parse the object
 * layout itself; the lines are copied verbatim (never opened).  cur_apx may be
 * NULL with cur_apx_len 0 for the first line; otherwise line_obj must carry the
 * same GID and (vMaj, vMin) as cur_apx (GY_ERR_VERIFY on a mismatch).  out /
 * out_len follow the buffer convention (out == NULL reports the needed size;
 * cur_apx_len + line_obj_len is always a safe upper bound).  Returns GY_OK,
 * GY_ERR_UNSUPPORTED on a classical suite, GY_ERR_VERIFY on a malformed object
 * or a header mismatch, GY_ERR_TOOLONG on a short out or too many lines, or
 * GY_ERR_ARG on a NULL argument.
 */
GY_EXPORT int gy_qsgroups_server_appendix_append(uint8_t suite_id,
                                                 const uint8_t *cur_apx,
                                                 size_t cur_apx_len,
                                                 const uint8_t *line_obj,
                                                 size_t line_obj_len,
                                                 uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* GERYON_QSGROUPS_SERVER_H */
