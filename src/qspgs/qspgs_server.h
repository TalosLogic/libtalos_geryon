/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_SERVER_H
#define GY_QSPGS_SERVER_H

#include <stddef.h>
#include <stdint.h>

#include "qspgs_wire.h" /* struct gy_qspgs_core, gy_qspgs_apx_line */

/*
 * QSPGS server side (QSPGS_SPEC.md section 7, D-QGS-6).  A stateless set of
 * pure crypto checks shipped as the SEPARATE geryon_qsgroups_server target
 * (mirroring geryon_groups_server, the D-GRP-2 shape).  The server holds NO
 * core secret parameters and never touches KR-ML-DSA internals or any
 * rerandomization secret (rrs / rho / skpsdn): every signature check is the
 * PUBLIC liboqs verifier reached through the sk-free common layer
 * (qspgs_wire.c, target geryon_qspgs_internal), and every pseudonym key the
 * server verifies under is the full vkpsdn a member supplies with its first
 * signature (checked against the stored H(vkpsdn), section 7.3 item 3).  The
 * client-only recompute-from-rrs path (gy_qspgs_core_resolve_verify in
 * qspgs_ops.c) is NOT part of this target; the nm-scope audit
 * (tests/audit/nm_scope_qspgs_server.sh) enforces the boundary structurally.
 *
 * Storage, policy, channel handling, and the registration-record service
 * (section 7.2) belong to the deploying application; this target ships the
 * section 7.3 crypto checks only.
 *
 * DEPLOYER LIMITATION (section 7.4, D-QGS-6 item 5): the server cannot validate
 * the CONTENTS of encrypted entries (member ciphertexts, appendix payloads,
 * invite / join slots) - only members holding the group key or isk can open
 * them - and it does not try.  A group with no honest admin can therefore
 * accumulate attributable-but-invalid state that only an admin cleans up at
 * reconciliation.  The signature checks below bound WHO may write (a resolved
 * pseudonym, an admin line for a core edit), not whether an encrypted blob is
 * well-formed inside.  The mitigations are send-token rate limiting (section
 * 6.5) and admin cleanup, both deployer responsibilities; a deployment must not
 * assume the server rejects semantically garbage entries.
 */

/*
 * Constant-time bearer-token check (section 7.3 item 5): compare a presented
 * token against the token stored for a GID (the header fetch token fet, or a
 * derived send token, section 6.5).  Both are opaque fixed-width bearer bytes,
 * so this is a single const-time equality test (gy_const_memcmp) over token_len
 * bytes; the server neither derives nor interprets them.  token_len is the
 * agreed token width (GY_QSPGS_FET_LEN for the fetch token).
 *
 * Returns GY_OK when the tokens match, GY_ERR_VERIFY on a mismatch, GY_ERR_ARG
 * on a NULL argument or a zero length.
 */
int gy_qspgs_server_token_check(const uint8_t *presented, const uint8_t *stored,
                                size_t token_len);

/*
 * Core-signature acceptance (section 7.3 item 1, D-QGS-13 E2): the shipped
 * check a server runs before applying an admin core edit at signer_index.  It
 * is a pure function of the STORED prior core, the operation kind, the
 * SUBMITTED next core, the signer index, and the full pseudonym key signer_vkr
 * the member supplies (the server has no rrs and never recomputes vkr from a
 * base key; that is the client path).
 *
 * prior is the server's stored version and is NULL only for op_kind ==
 * GY_QSPGS_OP_CREATE.  op_kind (GY_QSPGS_OP_*) selects the [CFG+]
 * per-operation vk-lst rule and where the signer's own vkpsdn is resolved:
 *   CREATE     prior NULL; next->n_members == 1, next->n_vk == 1, vMaj == 1;
 *              member[0] is admin; signer resolves against next->vkhash[0].
 *   UNCHANGED  next vk-lst MUST equal prior byte for byte; signer resolves
 *              against the (identical) submitted hash.
 *   APPEND_ONE next vk-lst MUST equal prior with exactly one hash appended;
 *              signer (an existing member) resolves against its prior hash.
 *   REPLACE    any next vk-lst accepted (rotation; server holds no gk); signer
 *              resolves against the submitted (rotated) hash.
 * In every non-CREATE case the admn gate reads the PRIOR mem-lst, so a
 * non-admin cannot sign a next core flipping its own admn bit, and the core
 * signature then verifies over the NEXT objects under the resolved key.
 *
 * signer_vkr is GY_QSPGS_VKR_MAX-sized for the tier; scratch is caller-provided
 * working space for the TBS (no allocation).  Returns GY_OK on acceptance,
 * GY_ERR_VERIFY on a non-admin signer, a disallowed vk-lst transition, a hash
 * mismatch, or a bad signature, GY_ERR_TOOLONG if scratch is too small, or
 * GY_ERR_ARG (bad input, unknown op_kind, prior NULL for a non-CREATE, or a
 * signer_index past the relevant list).
 */
int gy_qspgs_server_core_check(const struct gy_qspgs_core *prior,
                               uint8_t op_kind,
                               const struct gy_qspgs_core *next,
                               uint32_t signer_index, const uint8_t *signer_vkr,
                               const uint8_t *sig, size_t sig_len,
                               uint8_t *scratch, size_t scratch_cap);

/*
 * Appendix-line acceptance (section 7.3 item 2): verify one append-only line's
 * signature under the author's full pseudonym key author_vkr, via the public
 * verifier in the common layer.  stored_vkhash, when non-NULL, is the author's
 * vk-lst hash H(vkpsdn) to resolve author_vkr against (const-time, item 3):
 * pass core->vkhash for the author's index for an EXISTING-member line (leave /
 * refresh / addUser / modAttr); pass NULL for a UserAdd / JoinViaLink newcomer,
 * whose vkpsdn is not yet in the vk-lst (the deployer appends H(author_vkr),
 * computed with gy_qspgs_vkpsdn_hash, to the vk-lst on acceptance).  The
 * signature covers the apx-hdr (gid, vmaj, vmin) and the line (D-QGS-13 E1),
 * so the caller passes the appendix header the line was decoded from.  The
 * server never opens the line payload (it is an opaque ek ciphertext).  scratch
 * is caller-provided working space.  Returns GY_OK, GY_ERR_VERIFY on a hash
 * mismatch or bad signature, GY_ERR_TOOLONG if scratch is too small, or
 * GY_ERR_ARG.
 */
int gy_qspgs_server_apx_check(uint8_t suite_id,
                              const uint8_t gid[GY_QSPGS_GID_LEN],
                              uint32_t vmaj, uint32_t vmin,
                              const struct gy_qspgs_apx_line *line,
                              const uint8_t *author_vkr,
                              const uint8_t *stored_vkhash, uint8_t *scratch,
                              size_t scratch_cap);

/*
 * Version discipline / compare-and-swap (section 7.3 item 4): decide whether a
 * write applies to the server's current head.  Versions order lexicographically
 * as (vMaj, vMin).  A write NAMES the version it extends ((ext_vmaj, ext_vmin),
 * the head it read) and carries its new version ((new_vmaj, new_vmin)).  The
 * server, holding its current head ((cur_vmaj, cur_vmin)), accepts the write
 * iff BOTH:
 *   - it extends the current head: (ext_vmaj, ext_vmin) == (cur_vmaj, cur_vmin)
 *     (this is the compare-and-swap; a concurrent write that moved the head is
 *     the conflict, and the server NEVER merges - it rejects); and
 *   - it strictly advances it: (new_vmaj, new_vmin) > (cur_vmaj, cur_vmin).
 * The strict-advance check alone catches a duplicate; the extend check
 * additionally catches a stale writer that skipped ahead over another's change.
 * Returns GY_OK to apply, or GY_ERR_STATE on a conflict (the loser re-fetches
 * the current head, (cur_vmaj, cur_vmin), and rebuilds - this is the structured,
 * distinct-from-VERIFY conflict signal).  It is a pure comparison; no argument
 * can be invalid.
 */
int gy_qspgs_server_version_check(uint32_t cur_vmaj, uint32_t cur_vmin,
                                  uint32_t ext_vmaj, uint32_t ext_vmin,
                                  uint32_t new_vmaj, uint32_t new_vmin);

/*
 * Fetch-token check (section 7.3 item 5): constant-time compare of a presented
 * fetch token against the group's stored fet (GY_QSPGS_FET_LEN bytes).  Since
 * SEC-v1.5.0 LOW-1 fet is NOT in the served header; the deployer stores it as a
 * separate server record (the emit bundle's fet field) and passes it here.  A
 * convenience over gy_qspgs_server_token_check for the common case; the send
 * token (section 6.5), being deployer-derived, uses the generic token check.
 * Returns GY_OK on a match, GY_ERR_VERIFY on a mismatch, GY_ERR_ARG on a NULL
 * argument.
 *
 * Invite-queue and join-slot handling (section 7.3 item 6) ships no crypto
 * check here: the server FRAMES entries with the common-layer codecs
 * (gy_qspgs_invite_queue_* / the header join slot) and appends / serves them
 * opaquely, validating nothing inside (only members holding isk can open them,
 * section 7.4).  Storage of the queue and slot is the deployer's, per section
 * 7.1.
 */
int gy_qspgs_server_fetch_check(const uint8_t *fet, const uint8_t *presented);

#endif /* GY_QSPGS_SERVER_H */
