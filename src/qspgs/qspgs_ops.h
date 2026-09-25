/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_OPS_H
#define GY_QSPGS_OPS_H

#include <stddef.h>
#include <stdint.h>

#include "qspgs_join.h" /* gy_qspgs_join_pk_t, gy_qspgs_join_sk_t */
#include "qspgs_keys.h" /* gy_qspgs_psdn_sk_t, GY_QSPGS_*_BYTES, VKR_MAX */
#include "qspgs_pers.h" /* GY_QSPGS_PERS_*_SIG_MAX */
#include "qspgs_wire.h" /* GY_QSPGS_GID_LEN, GY_QSPGS_HASH_MAX */

/*
 * QSPGS client operations (QSPGS_SPEC.md section 5, transcription of [CFG+] §4 /
 * App. B; section 6 attribution).
 *
 * This is the CLIENT-side composition engine over the frozen wire and
 * the key hierarchy, mirroring the classical group_ops.c: pure
 * functions over caller-provided key material, no persisted or cached derived
 * state (D-QGS-8 / D-GRP-7).  The custody / gy_qspgs_store facade wrappers ride
 * a later ticket, as the classical facade rode gy_group_store.
 *
 * Increment 1 lands the shared crypto engine every operation uses: the
 * per-call member context (the calling member's ek / rrs / rho / skpsdn derived
 * from gk and its base pair) and the attribution helper (recompute a member's
 * H(vkpsdn) so a decoded vk-lst line can be matched to an identity, section
 * 6.2).  The operations themselves land in increments 2-4.
 */

/*
 * The calling member's transient per-group crypto working set (section 6.1),
 * derived from the group key gk and the member's own base pair.  Held in memory
 * only for the duration of an operation; NEVER persisted (skpsdn in particular,
 * D-QGS-11 item 7).  Clear it with gy_qspgs_member_ctx_clear when done.
 *
 * ek / rrs come from gk (SUB-KEY); rho from (rrs, own UID); skpsdn and the
 * member's own published pseudonym key vkr from (base pair, rho).  vkr is the
 * full key a member supplies with its first signature (the vk-lst stores only
 * H(vkr)).
 */
struct gy_qspgs_member_ctx {
    uint8_t suite_id; /* 0 until a successful open. */
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    gy_qspgs_psdn_sk_t sk;         /* skpsdn = RandSK(skbase, vkbase, rho). */
    uint8_t vkr[GY_QSPGS_VKR_MAX]; /* the caller's own vkpsdn = RandVK(...). */
};

/*
 * Open a member context: derive (ek, rrs) from gk, rho from (rrs, uid), then
 * the caller's skpsdn and vkr from its base pair (skb, vkb) and rho.  gk is the
 * tier master-key length (gy_qspgs_master_key_len); uid is exactly GY_QSPGS_UID_LEN.
 * On any failure the context is cleared and left unusable (suite_id 0).
 * Returns GY_OK, GY_ERR_ARG on bad input, or a negative GY_ERR_* from a
 * derivation.
 */
int gy_qspgs_member_ctx_open(struct gy_qspgs_member_ctx *ctx, uint8_t suite_id,
                             const uint8_t *gk, const uint8_t *skb,
                             const uint8_t *vkb, const uint8_t *uid,
                             size_t uidlen);

/* Zeroize a member context (idempotent; NULL-safe). */
void gy_qspgs_member_ctx_clear(struct gy_qspgs_member_ctx *ctx);

/*
 * Attribution (section 6.2): recompute the H(vkpsdn) a vk-lst line would store
 * for the member identified by UID, from the group's rerandomization seed rrs
 * and that member's base verification key vkb (held per acquaintance, section
 * 2.2).  out receives the suite's hash length (size to GY_QSPGS_HASH_MAX); the
 * caller matches it against the decoded vk-lst entry (gy_const_memcmp) to
 * attribute a line to an identity.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_attribute_hash(uint8_t suite_id,
                            const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                            const uint8_t *vkb, const uint8_t *uid,
                            size_t uidlen, uint8_t *out);

/* ------------------------------------------------------------------------- *
 * RegisterUser and GrantAcquaintance (QSPGS_SPEC.md section 5, section 7.2).
 *
 * RegisterUser deposits the paper's Acct = (vkbase, acq, ep, sigma), where
 * sigma is the hybrid identity's dual (XEdDSA + ML-DSA) signature over the
 * frozen registration object  vkbase || acq  (context GY_QSPGS_CTX_REGUSER).
 * The signed-object layout freezes here (the last D-QGS-7 sub-item).  A member
 * accepts an acquaintance by verifying that record: on success it holds the
 * attested (vkbase, acq) it later needs to attribute and add that user
 * (section 6.2).
 * ------------------------------------------------------------------------- */

/*
 * Build the frozen to-be-signed objects the two identity-anchored signatures
 * cover (D-QGS-6, footnote 7), returning the object length.  This is the
 * RAW-KEY path (gy_qspgs_register / the invite builder below, which hold the
 * identity secret keys in hand).  The custody path does NOT use these: the
 * custodian owns the identical layout and builds it itself
 * (gy_custodian_qspgs_sign_reguser / _invaccept), so the identity key never
 * leaves it (SEC-v1.5.0 LOW-6).  Both share the field-width constants
 * (qspgs_const.h) and both produce signatures gy_qspgs_pers_verify /
 * _acct_verify / _invite_verify accept; since those verifiers rebuild the
 * object with these builders, the custody path's layout is pinned to this one
 * by the lifecycle round-trip.  out sizes to GY_QSPGS_PERS_OBJ_MAX.
 *   reguser   : vkbase(tier VKB) || acq(2*kappa).
 *   invaccept : uidlen(1) || UID || uk(2*kappa) || GID.
 */
size_t gy_qspgs_reguser_tbs(uint8_t suite_id, const uint8_t *vkb,
                            const uint8_t *acq, uint8_t *out);
size_t gy_qspgs_invaccept_tbs(uint8_t suite_id, const uint8_t *uid,
                              size_t uidlen, const uint8_t *uk,
                              const uint8_t gid[GY_QSPGS_GID_LEN],
                              uint8_t *out);

/*
 * RegisterUser (client half): sign (vkbase, acq) under the identity's dual
 * capability and emit the GY_QOBJ_ACCT record into out.  acq is the 2*kappa
 * acquaintance tag (gy_qspgs_derive_acq); ep the current epoch; id_curve_sk /
 * id_mldsa_sk the identity's XEdDSA and ML-DSA secret keys.  out / cap / *outlen
 * as the wire encoders.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_register(uint8_t suite_id, const uint8_t *vkb, const uint8_t *acq,
                      uint64_t ep, const uint8_t *id_curve_sk,
                      const uint8_t *id_mldsa_sk, uint8_t *out, size_t cap,
                      size_t *outlen);

/*
 * GrantAcquaintance / accept (client half): decode a registration record and
 * verify its sigma against the granter's hybrid identity public keys.  On GY_OK
 * *vkb and *acq point INTO in (zero-copy; the caller keeps in alive and stores
 * the attested pair keyed by the granter's UID), and *ep holds the epoch.  A bad
 * signature is GY_ERR_VERIFY.  Returns GY_OK, GY_ERR_VERIFY, or GY_ERR_ARG.
 */
int gy_qspgs_acct_verify(uint8_t suite_id, const uint8_t *id_curve_pk,
                         const uint8_t *id_mldsa_pk, const uint8_t *in,
                         size_t inlen, const uint8_t **vkb, const uint8_t **acq,
                         uint64_t *ep);

/* ------------------------------------------------------------------------- *
 * Invite and AcceptInvitation (section 5, section 4 item 6).
 *
 * An invite-queue entry is PKE.Enc_ipk(UID, uk, sigma) where sigma is the
 * INVITED user's own dual identity signature over the frozen object
 * uidlen || UID || uk || GID  (context GY_QSPGS_CTX_INVACCEPT; layout freezes
 * here), with uk = KDF(muk, "uk@" || ep) derived from the invitee's own master
 * user key ([CFG+] App. B.7, D-QGS-6 item 2).  ipk / isk are derived from the
 * per-invite basis gk' the admin placed in the invitee's pending entry and
 * shared over a pairwise channel; the invited UID is not yet a settled member.
 * Any member holding isk opens the entry, recovers (UID, uk, sigma), and
 * verifies sigma against THE INVITED UID's identity public keys before an admin
 * settles the pending entry (ApproveJoin).
 * ------------------------------------------------------------------------- */

/* An opened invite entry.  uk is secret; clear with gy_qspgs_invite_clear. */
struct gy_qspgs_invite {
    uint8_t uid[GY_QSPGS_UID_MAX];
    size_t uidlen;
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t ed_sig[GY_QSPGS_PERS_ED_SIG_MAX];
    size_t ed_sig_len;
    uint8_t mldsa_sig[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    size_t mldsa_sig_len;
};

/*
 * AcceptInvitation (client half): sign (UID, uk, GID) under the INVITEE's own
 * dual identity capability, then seal (UID, uk, sigma) to the invite ipk (an
 * invite-queue entry).  ipk is gy_qspgs_join_derive(gk'); uid is
 * exactly GY_QSPGS_UID_LEN; uk the invitee's own 2*kappa user key.  out / cap /
 * *outlen as the join seal.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_invite_seal(uint8_t suite_id, const gy_qspgs_join_pk_t *ipk,
                         const uint8_t gid[GY_QSPGS_GID_LEN],
                         const uint8_t *uid, size_t uidlen, const uint8_t *uk,
                         const uint8_t *id_curve_sk, const uint8_t *id_mldsa_sk,
                         uint8_t *out, size_t cap, size_t *outlen);

/*
 * Invite seal from a PRECOMPUTED dual signature: assemble the invite plaintext
 * (uidlen || UID || uk || the two length-prefixed signatures) and seal it to
 * ipk, exactly as gy_qspgs_invite_seal's tail.  Exposed so the client facade
 * can sign (UID, uk, GID) THROUGH the custodian identity seam (context
 * GY_QSPGS_CTX_INVACCEPT) and seal the result, so no identity secret key leaves
 * the custodian.  ed_sig_len / mldsa_sig_len must be the tier widths.  Returns
 * GY_OK, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_invite_seal_signed(uint8_t suite_id, const gy_qspgs_join_pk_t *ipk,
                                const uint8_t *uid, size_t uidlen,
                                const uint8_t *uk, const uint8_t *ed_sig,
                                size_t ed_sig_len, const uint8_t *mldsa_sig,
                                size_t mldsa_sig_len, uint8_t *out, size_t cap,
                                size_t *outlen);

/*
 * AcceptInvitation, step 1 (open): decrypt an invite-queue entry with isk
 * (rederived from gk) and parse it into *out (UID, uk, and the two identity
 * signatures).  A malformed plaintext or failed decryption is GY_ERR_VERIFY.
 * The caller then looks up the invited UID's identity and calls
 * gy_qspgs_invite_verify.  Returns GY_OK, GY_ERR_VERIFY, GY_ERR_TOOLONG, or
 * GY_ERR_ARG.
 */
int gy_qspgs_invite_open(uint8_t suite_id, const gy_qspgs_join_sk_t *isk,
                         const uint8_t *in, size_t inlen,
                         struct gy_qspgs_invite *out);

/*
 * OpenInvitation, step 2 (verify): check the opened invite's sigma over
 * (UID, uk, GID) against the INVITED UID's hybrid identity public keys - the
 * id_curve_pk / id_mldsa_pk passed here are the invitee's own, held from
 * accept-acquaintance or the messaging layer.  gid is the group id.  Returns
 * GY_OK, GY_ERR_VERIFY on a bad signature, or GY_ERR_ARG.
 */
int gy_qspgs_invite_verify(uint8_t suite_id,
                           const uint8_t gid[GY_QSPGS_GID_LEN],
                           const uint8_t *id_curve_pk,
                           const uint8_t *id_mldsa_pk,
                           const struct gy_qspgs_invite *inv);

/* Zeroize an opened invite (idempotent; NULL-safe): uk is secret. */
void gy_qspgs_invite_clear(struct gy_qspgs_invite *inv);

/* ------------------------------------------------------------------------- *
 * Fetch (read path, section 5, [CFG+] Fetch; the GROUP_SPEC 7.7 analogue).
 *
 * A fetching member decrypts each member-list entry into a plaintext view and
 * verifies the admin core signature.  Both are pure functions over the decoded
 * gy_qspgs_core plus the member's ek and the acquaintance records
 * (each acquaintance's vkbase, held from GrantAcquaintance); walking a store is
 * the facade's job.  Appendix-line attribution rides increment 4
 * (it must also handle the new-author vkpsdn that UserAdd / JoinViaLink append
 * outside the core vk-lst).
 * ------------------------------------------------------------------------- */

/*
 * A decrypted member entry (the Fetch client view).  uk is plaintext secret
 * material: clear the view with gy_qspgs_member_view_clear when done.  pending
 * is 1 for an invite that has not been accepted (D-QGS-13 E3): its mct carries
 * gk' in place of uk, so uk is left zeroed and callers report uk_len 0.
 */
struct gy_qspgs_member_view {
    uint8_t uid[GY_QSPGS_UID_MAX];
    size_t uidlen;
    uint8_t admn;
    uint8_t pending;
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
};

/*
 * Decrypt one member entry into out: open m->mct under ek (GID as AAD) into
 * (UID, r_c, uk), then recompute C_UID = H(qspgs-cuid || r_c || UID) and check
 * it equals m->cuid (const-time).  admn is copied through.  A failed
 * decryption or a C_UID that does not open the commitment is GY_ERR_VERIFY (the
 * whole entry is rejected, nothing written).  Returns GY_OK, GY_ERR_VERIFY,
 * GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_member_decrypt(uint8_t suite_id, uint8_t aead_id,
                            const uint8_t ek[GY_QSPGS_EK_BYTES],
                            const uint8_t gid[GY_QSPGS_GID_LEN],
                            const struct gy_qspgs_member *m,
                            struct gy_qspgs_member_view *out);

/* Zeroize a member view (idempotent; NULL-safe): uk is secret. */
void gy_qspgs_member_view_clear(struct gy_qspgs_member_view *v);

/*
 * Resolve and verify the admin core signature (section 6.2, 6.3): recompute the
 * signing admin's pseudonym key vkr = RandVK(signer_vkb, RandRho(rrs,
 * signer_uid)), check it against the stored vk-lst hash core->vkhash for
 * signer_index (const-time), then verify sig over the canonical core TBS under
 * that vkr (gy_qspgs_core_verify; caller scratch, no allocation).  signer_uid is
 * the admin's UID (recovered from its member entry via gy_qspgs_member_decrypt),
 * signer_vkb its base verification key (held per acquaintance).  Returns GY_OK,
 * GY_ERR_VERIFY on a hash mismatch or bad signature, GY_ERR_TOOLONG if scratch
 * is too small, or GY_ERR_ARG (signer_index past the vk-lst included).
 */
int gy_qspgs_core_resolve_verify(
    const struct gy_qspgs_core *core, uint32_t signer_index,
    const uint8_t rrs[GY_QSPGS_RRS_BYTES], const uint8_t *signer_vkb,
    const uint8_t *signer_uid, size_t signer_uidlen, const uint8_t *sig,
    size_t sig_len, uint8_t *scratch, size_t scratch_cap);

/* ------------------------------------------------------------------------- *
 * Core admin edits (section 5 core / extended operations, section 6.3).
 *
 * Every operation that mutates the core list (Create, AddMember, RemoveMember,
 * SetAdminRights, ChangeSettings, ChangeAttr, RotateGroupKey, ApproveJoin) is
 * the same shape: the editing admin mutates the in-memory gy_qspgs_core, then
 * re-signs the WHOLE list under its skpsdn (gy_qspgs_core_sign).  Because the
 * core carries caller-owned, zero-copy arrays (no dynamic allocation), the
 * mutation is done by the caller in its own member / vk-lst / header buffers;
 * this engine supplies the three shared primitives those edits compose, rather
 * than one wrapper per operation:
 *
 *   - gy_qspgs_group_key_gen : a fresh gk for Create and for the gk rotation
 *     RemoveMember / RotateGroupKey perform.
 *   - gy_qspgs_member_build  : build one member entry (mct, C_UID, vk-lst hash)
 *     for Create's initial member, AddMember, ApproveJoin, and every SURVIVING
 *     member re-encrypted under a rotated gk.
 *   - gy_qspgs_core_sign     : re-sign the current core under the admin skpsdn.
 *
 * Operation compositions (all end in gy_qspgs_core_sign by the editing admin):
 *   Create        : group_key_gen -> derive_sub_key -> member_build(self,
 *                   admn=1) -> assemble core (format_version =
 *                   GY_QSPGS_FORMAT_VERSION, vMaj 1) -> core_sign.  The format
 *                   epoch (D-QGS-12) is fixed here and never changes for the
 *                   group; vMaj is the state version that advances on edits.
 *   AddMember     : member_build(new) appended to the member / vk-lst arrays
 *                   (the new member's uk arrives via Invite or an out-of-band
 *                   grant) -> core_sign.
 *   RemoveMember  : drop entry i; group_key_gen (new gk) -> derive_sub_key
 *                   (ek', rrs'); member_build for each SURVIVOR under (ek',
 *                   rrs') so every mct is re-encrypted and every vkpsdn
 *                   republished (the removed member's pseudonym no longer
 *                   resolves); bump vMaj -> core_sign.  Members recover each
 *                   survivor's (UID, uk) with gy_qspgs_member_decrypt and its
 *                   vkbase from the acquaintance store.
 *   RotateGroupKey: RemoveMember without the drop.
 *   SetAdminRights: flip a member's admn flag -> core_sign.
 *   ChangeSettings/
 *   ChangeAttr    : re-seal the header field (gy_qspgs_field_seal, FIELD_HEADER
 *                   / FIELD_ATTR) -> core_sign.
 *   ApproveJoin   : for each opened + verified invite (gy_qspgs_invite_open /
 *                   _verify), member_build(new) -> core_sign; drop the drained
 *                   entries from the invite queue.
 *   RevokeInvitation: rebuild the invite-queue array without the entry (no core
 *                   re-sign; the queue is not covered by the core signature).
 *
 * ToggleJoinLink and JoinViaLink ride increment 4 (they need the join-slot
 * (gk, fet) layout).  Appendix (non-admin) operations also ride increment 4.
 * ------------------------------------------------------------------------- */

/*
 * Generate a fresh group key gk (2*kappa random bytes) for Create /
 * RotateGroupKey / RemoveMember.  gk must have room for
 * gy_qspgs_master_key_len(suite_id) bytes.  Returns GY_OK or GY_ERR_ARG.
 */
int gy_qspgs_group_key_gen(uint8_t suite_id, uint8_t *gk);

/*
 * Build one member-list entry for (uid, uk) under the group key material
 * (ek, rrs) and group gid: seal mct = Enc_ek(UID, r_c, uk) with a FRESH random
 * r_c into mct_buf (setting out_member->mct / mct_len and *mct_len), compute the
 * commitment out_member->cuid = C_UID, set out_member->admn (0/1), and write the
 * member's vk-lst hash H(vkpsdn) (from rrs + vkb + uid) into vkhash_out (the
 * suite hash length; size to GY_QSPGS_HASH_MAX).  r_c is not returned: it is
 * recoverable only by decrypting mct.  Returns GY_OK, GY_ERR_TOOLONG if mct_cap
 * is short, or a negative GY_ERR_*.
 */
int gy_qspgs_member_build(uint8_t suite_id, uint8_t aead_id,
                          const uint8_t ek[GY_QSPGS_EK_BYTES],
                          const uint8_t gid[GY_QSPGS_GID_LEN],
                          const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                          const uint8_t *uid, size_t uidlen, const uint8_t *uk,
                          const uint8_t *vkb, uint8_t admn,
                          struct gy_qspgs_member *out_member, uint8_t *mct_buf,
                          size_t mct_cap, size_t *mct_len, uint8_t *vkhash_out);

/*
 * Build a PENDING invite entry (D-QGS-13 E3): as gy_qspgs_member_build
 * but the mct is sealed in the PENDING form with the per-invite join-key basis
 * gk' in place of uk, and admn is always 0.  vkhash_out is H(vkpsdn) from the
 * invitee's base key vkb exactly as for a settled member, so the entry occupies
 * its final vk-lst slot from the moment of invitation; ApproveJoin later re-seals
 * the mct PRESENT with the accepted uk without touching vkhash.  Returns GY_OK,
 * GY_ERR_TOOLONG if mct_cap is short, or a negative GY_ERR_*.
 */
int gy_qspgs_member_build_pending(
    uint8_t suite_id, uint8_t aead_id, const uint8_t ek[GY_QSPGS_EK_BYTES],
    const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t rrs[GY_QSPGS_RRS_BYTES],
    const uint8_t *uid, size_t uidlen, const uint8_t *gk_prime,
    const uint8_t *vkb, struct gy_qspgs_member *out_member, uint8_t *mct_buf,
    size_t mct_cap, size_t *mct_len, uint8_t *vkhash_out);

/*
 * Re-sign the current core under the editing admin's skpsdn (section 4 item 4,
 * section 6.3): build the canonical TBS for signer_index into the caller scratch
 * buffer (no allocation) and sign it with ctx->sk under the frozen qspgs-core
 * context, emitting the CORE_SIG object into out.  ctx is the admin's member
 * context (gy_qspgs_member_ctx_open with the admin's own gk / base pair / UID),
 * and signer_index is the admin's line in the member / vk-lst.  ctx->suite_id
 * must match core->suite_id.  out / cap / *outlen as the wire encoders.  Returns
 * GY_OK, GY_ERR_TOOLONG, GY_ERR_CRYPTO on a sign failure, or GY_ERR_ARG.
 */
int gy_qspgs_core_sign(const struct gy_qspgs_core *core, uint32_t signer_index,
                       const struct gy_qspgs_member_ctx *ctx, uint8_t *out,
                       size_t cap, size_t *outlen, uint8_t *scratch,
                       size_t scratch_cap);

/* ------------------------------------------------------------------------- *
 * Appendix (non-admin) operations and the join link (section 4 item 5,
 * section 5).
 *
 * A member who is not the editing admin records an operation as an append-only,
 * individually-signed appendix line, reconciled into a later core version by an
 * admin (increment 3's ApproveJoin / core edits).  Each line signs
 * (line_type || author_index || payload) under the author's skpsdn (context
 * qspgs-appendix); the payload is the op-specific ek ciphertext, built with the
 * increment-1 field seals:
 *   Leave       (GY_QAPX_LEAVE)   : empty payload.
 *   Refresh     (GY_QAPX_REFRESH) : gy_qspgs_field_seal(FIELD_UK, uk').
 *   modAttr     (GY_QAPX_MODATTR) : gy_qspgs_field_seal(FIELD_ATTR, attr).
 *   addUser     (GY_QAPX_ADDUSER) : C_UID'(hash_len) ||
 *                                   gy_qspgs_member_ct_seal(UID', r', uk').
 *   join        (GY_QAPX_JOIN)    : gy_qspgs_member_ct_seal(own UID, r, uk),
 *                                   appended by a JoinViaLink newcomer.
 *
 * JoinViaLink is: gy_qspgs_joinlink_open the header slot to recover (gk, fet),
 * derive ek / rrs, then a GY_QAPX_JOIN line signed by the newcomer (whose vkpsdn
 * is NOT yet in the core vk-lst - see the resolve-verify note).  ToggleJoinLink
 * is an admin core edit: gy_qspgs_joinlink_seal (a fresh link secret) into the
 * header join slot, then gy_qspgs_core_sign.
 * ------------------------------------------------------------------------- */

/*
 * Sign one appendix line under the author's skpsdn: build the canonical TBS
 * (apx-hdr gid || vmaj || vmin, then line_type || author_index || payload) into
 * the caller scratch and sign it with ctx->sk under the frozen qspgs-appendix
 * context, writing the signature into sig_out (*sig_len set).  The apx-hdr
 * (gid, vmaj, vmin) binds the line to its group and version (D-QGS-13 E1).
 * line_type must be a known GY_QAPX_* value; an empty payload (payload NULL,
 * payload_len 0) is allowed (Leave).  The caller then assembles the
 * gy_qspgs_apx_line (payload + sig_out) and encodes it.  Returns GY_OK,
 * GY_ERR_TOOLONG (short sig_out or scratch), GY_ERR_CRYPTO on a sign failure,
 * or GY_ERR_ARG (unknown line_type / NULL gid / bad context).
 */
int gy_qspgs_apx_line_sign(uint8_t suite_id,
                           const struct gy_qspgs_member_ctx *ctx,
                           const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
                           uint32_t vmin, uint8_t line_type,
                           uint32_t author_index, const uint8_t *payload,
                           size_t payload_len, uint8_t *sig_out, size_t sig_cap,
                           size_t *sig_len, uint8_t *scratch,
                           size_t scratch_cap);

/*
 * Resolve and verify one appendix line's author signature: recompute the
 * author's vkr = RandVK(author_vkb, RandRho(rrs, author_uid)), and verify the
 * line signature under it over the apx-hdr (gid, vmaj, vmin) and the line
 * (gy_qspgs_apx_line_verify; caller scratch, no allocation).  The apx-hdr is
 * the header of the appendix the line was decoded from (D-QGS-13 E1).
 * stored_vkhash, when non-NULL, is the author's vk-lst hash to check the
 * recomputed key against (const-time) - pass core->vkhash for author_index for
 * an EXISTING member (Leave / Refresh / modAttr / addUser); pass NULL for a
 * join newcomer, whose vkpsdn is not yet in the vk-lst.  Returns GY_OK,
 * GY_ERR_VERIFY on a hash mismatch or bad signature, GY_ERR_TOOLONG if scratch
 * is too small, or GY_ERR_ARG.
 */
int gy_qspgs_apx_line_resolve_verify(
    uint8_t suite_id, const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
    uint32_t vmin, const struct gy_qspgs_apx_line *line,
    const uint8_t rrs[GY_QSPGS_RRS_BYTES], const uint8_t *author_vkb,
    const uint8_t *author_uid, size_t author_uidlen,
    const uint8_t *stored_vkhash, uint8_t *scratch, size_t scratch_cap);

/*
 * Leaver fetch token ([CFG+] Fig. 10, lower half): sign the
 * canonical TBS GID(16) || k(BE32) under the caller's skpsdn (ctx->sk) with the
 * frozen qspgs-leavefetch context, writing the signature into sig_out (*sig_len
 * set).  k is the signer's index in the vk-lst of the version it belonged to.
 * No scratch is needed (the TBS is 20 bytes, built internally).  Returns GY_OK,
 * GY_ERR_TOOLONG on a short sig_out, GY_ERR_CRYPTO on a sign failure, or
 * GY_ERR_ARG.
 */
int gy_qspgs_leave_token_sign(uint8_t suite_id,
                              const struct gy_qspgs_member_ctx *ctx,
                              const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                              uint8_t *sig_out, size_t sig_cap,
                              size_t *sig_len);
/* The matching TBS builder and verifier are sk-free and live in the common
 * layer (qspgs_wire.h): gy_qspgs_leave_token_tbs / gy_qspgs_leave_token_verify. */

#endif /* GY_QSPGS_OPS_H */
