/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_FIELD_H
#define GY_QSPGS_FIELD_H

#include <stddef.h>
#include <stdint.h>

#include "qspgs_keys.h" /* GY_QSPGS_EK_BYTES, GY_QSPGS_MASTER_KEY_MAX, UID_MAX */
#include "qspgs_wire.h" /* GY_QSPGS_GID_LEN, GY_QSPGS_RC_LEN */

/*
 * QSPGS ek-encrypted field layer (QSPGS_SPEC.md section 5).
 *
 * The section-4 structure carries several fields as opaque AEAD ciphertexts
 * sealed under the group key ek: each member's mct = Enc_ek(UID, r_c, uk), the
 * header's Enc_ek(settings, attributes), and the appendix payloads
 * (refresh = Enc_ek(uk'), modAttr = Enc_ek(attr), addUser / join member
 * tuples).  The wire layer froze the structure grammar and carried these as
 * length-prefixed opaque blobs; THIS layer owns and freezes what is inside
 * them.
 *
 * Every sealed field is  nonce || AEAD ciphertext || tag, under the group's
 * pinned AEAD (aead_id): the admin selects it at Create and it is immutable for
 * the group's life (carried in the signed header, enforced by core_check).  The
 * frame carries no AEAD id of its own; both sealer and opener learn it from the
 * header, so callers pass the group's aead_id (see gy_qspgs_group_aead_ok).
 * ek is a long-lived group key (constant across a major version, changed only
 * when RemoveMember / RotateGroupKey rotates gk), so a fresh random nonce is
 * drawn per seal, unlike the single-use-key join seal (qspgs_join.c).  The
 * associated data is  gy_info(suite, "qspgs-field") || field_tag || GID:
 * the field-kind tag stops a ciphertext of one kind being reinterpreted as
 * another, and the GID stops cross-group replay.  Version rollback is caught by
 * the core signature (which covers vMaj / vMin), so the AAD binds no version;
 * this keeps re-encryption on gk rotation a plain reseal.
 *
 * All buffers are caller-provided (no dynamic allocation).
 */

/* Field-kind tags (part of the AAD; append, never renumber). */
#define GY_QSPGS_FIELD_MEMBER 0x01   /* (UID, r_c, uk): mct, addUser, join. */
#define GY_QSPGS_FIELD_HEADER 0x02   /* (settings, attributes): header. */
#define GY_QSPGS_FIELD_ATTR 0x03     /* (attributes): modAttr. */
#define GY_QSPGS_FIELD_UK 0x04       /* (uk'): refresh. */
#define GY_QSPGS_FIELD_JOINSLOT 0x05 /* (gk, fet): join link (layout inc 4). */

/*
 * Member-tuple form (the leading byte of a GY_QSPGS_FIELD_MEMBER plaintext,
 * D-QGS-13 E3).  A settled member carries its user key (PRESENT);
 * an admin's invite of a UID that has not yet accepted carries the per-invite
 * join-key basis gk' in the key slot instead (PENDING, uk absent), so members
 * can still derive the isk the acceptance seals to after a later rotation.  The
 * two forms share the (uidlen || UID || r_c || key) tail; only the leading byte
 * and the meaning of the key slot differ.
 */
#define GY_QSPGS_MEMBER_FORM_PRESENT 0x00 /* key slot = uk (settled member). */
#define GY_QSPGS_MEMBER_FORM_PENDING 0x01 /* key slot = gk' (invite pending). */

/*
 * Plaintext of a member tuple: form(1) || uidlen(1) || UID || r_c(32) ||
 * key(tier master-key length).  The key is uk (PRESENT) or gk' (PENDING).  The
 * widest tuple (UID_MAX, 448-tier key).
 */
#define GY_QSPGS_MEMBER_PT_MAX                                                 \
    (1 + 1 + GY_QSPGS_UID_MAX + GY_QSPGS_RC_LEN + GY_QSPGS_MASTER_KEY_MAX)

/*
 * Whether aead_id is a group-approved AEAD (SEC-v1.5.0 INFO-6): the admin pins
 * one at Create, immutable for the group's life.  Only ChaCha20-Poly1305 (MTI
 * default) and AEGIS-256 are allowed; both are always available on every build,
 * so the choice never fragments membership.  AES-256-GCM is excluded (hardware
 * gated).  Returns 1 if allowed, 0 otherwise (including an unknown id).
 */
int gy_qspgs_group_aead_ok(uint8_t aead_id);

/*
 * Bytes a seal adds to the plaintext (nonce || ... || tag) for the group's
 * pinned AEAD aead_id.  A caller sizes an output buffer to plaintext length +
 * this.  Returns 0 for a non-group AEAD id.
 */
size_t gy_qspgs_field_overhead(uint8_t aead_id);

/*
 * Seal pt[0..ptlen) as an ek-encrypted field of kind field_tag for group gid.
 * out receives nonce || ciphertext || tag; on entry cap is its capacity and on
 * success *outlen holds the bytes written (ptlen + the aead's field overhead).
 * ek is GY_QSPGS_EK_BYTES.  Returns GY_OK, GY_ERR_TOOLONG on a short buffer,
 * GY_ERR_ARG on a NULL argument / non-hybrid suite / unknown field_tag, or a
 * negative GY_ERR_* from the AEAD / RNG.
 */
int gy_qspgs_field_seal(uint8_t suite_id, uint8_t aead_id,
                        const uint8_t ek[GY_QSPGS_EK_BYTES], uint8_t field_tag,
                        const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *pt,
                        size_t ptlen, uint8_t *out, size_t cap, size_t *outlen);

/*
 * Open an ek-encrypted field of kind field_tag for group gid: split the nonce,
 * verify and decrypt into pt[0..cap).  On success *ptlen holds the plaintext
 * length.  A tag mismatch (wrong ek, wrong field kind, wrong GID, or tamper)
 * returns GY_ERR_VERIFY and writes no plaintext.  Returns GY_OK, GY_ERR_VERIFY,
 * GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_field_open(uint8_t suite_id, uint8_t aead_id,
                        const uint8_t ek[GY_QSPGS_EK_BYTES], uint8_t field_tag,
                        const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *in,
                        size_t inlen, uint8_t *pt, size_t cap, size_t *ptlen);

/*
 * mct = Enc_ek(PRESENT, UID, r_c, uk) (section 4 item 2): serialize a settled
 * member tuple and seal it as a GY_QSPGS_FIELD_MEMBER field.  uidlen is
 * exactly GY_QSPGS_UID_LEN; uk is the tier master-key length
 * (gy_qspgs_master_key_len).  out / cap / outlen as gy_qspgs_field_seal.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_member_ct_seal(uint8_t suite_id, uint8_t aead_id,
                            const uint8_t ek[GY_QSPGS_EK_BYTES],
                            const uint8_t gid[GY_QSPGS_GID_LEN],
                            const uint8_t *uid, size_t uidlen,
                            const uint8_t rc[GY_QSPGS_RC_LEN],
                            const uint8_t *uk, uint8_t *out, size_t cap,
                            size_t *outlen);

/*
 * mct for a PENDING invite (D-QGS-13 E3): as gy_qspgs_member_ct_seal
 * but the key slot carries the per-invite join-key basis gk' (tier master-key
 * length) in place of uk and the form byte is GY_QSPGS_MEMBER_FORM_PENDING.
 * ApproveJoin / Consolidate later re-seals this entry as PRESENT with the
 * accepted uk.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_member_ct_seal_pending(uint8_t suite_id, uint8_t aead_id,
                                    const uint8_t ek[GY_QSPGS_EK_BYTES],
                                    const uint8_t gid[GY_QSPGS_GID_LEN],
                                    const uint8_t *uid, size_t uidlen,
                                    const uint8_t rc[GY_QSPGS_RC_LEN],
                                    const uint8_t *gk_prime, uint8_t *out,
                                    size_t cap, size_t *outlen);

/*
 * Open an mct back into (form, UID, r_c, key).  form_out receives the member
 * form (GY_QSPGS_MEMBER_FORM_PRESENT or _PENDING); uid receives up to uid_cap
 * bytes with *uidlen set; rc receives GY_QSPGS_RC_LEN bytes; key receives the
 * tier master-key length (uk for PRESENT, gk' for PENDING; size key to
 * GY_QSPGS_MASTER_KEY_MAX).  A malformed plaintext (bad inner length, unknown
 * form, uidlen over uid_cap or GY_QSPGS_UID_MAX, wrong total) is GY_ERR_VERIFY.
 * Returns GY_OK, GY_ERR_VERIFY, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_member_ct_open(uint8_t suite_id, uint8_t aead_id,
                            const uint8_t ek[GY_QSPGS_EK_BYTES],
                            const uint8_t gid[GY_QSPGS_GID_LEN],
                            const uint8_t *in, size_t inlen, uint8_t *form_out,
                            uint8_t *uid, size_t uid_cap, size_t *uidlen,
                            uint8_t rc[GY_QSPGS_RC_LEN], uint8_t *key);

/* ------------------------------------------------------------------------- *
 * Join slot (section 4 item 1): the header's optional join-link encryption of
 * (gk, fet).  Unlike the ek fields, it is keyed by a join-link key derived from
 * a link secret shared out of band, so a link holder can obtain gk (and hence
 * ek) WITHOUT already having it.  The sealed bytes use the same field format as
 * the ek fields (GY_QSPGS_FIELD_JOINSLOT tag, GID in the AAD); only the key is
 * jlk = HKDF(link secret) instead of ek.
 * ------------------------------------------------------------------------- */

/* Join-link secret width (the out-of-band secret carried by the link). */
#define GY_QSPGS_JOINLINK_SECRET 32

/*
 * ToggleJoinLink (seal): derive the join-link key from jls and seal the slot
 * plaintext gk(2*kappa) || fet(GY_QSPGS_FET_LEN) for group gid.  gk is the tier
 * master-key length; fet is the fetch token.  out / cap / *outlen as
 * gy_qspgs_field_seal.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_qspgs_joinlink_seal(uint8_t suite_id, uint8_t aead_id,
                           const uint8_t jls[GY_QSPGS_JOINLINK_SECRET],
                           const uint8_t gid[GY_QSPGS_GID_LEN],
                           const uint8_t *gk,
                           const uint8_t fet[GY_QSPGS_FET_LEN], uint8_t *out,
                           size_t cap, size_t *outlen);

/*
 * JoinViaLink (open): derive the join-link key from jls and open the slot,
 * recovering gk into gk_out (2*kappa bytes; size to GY_QSPGS_MASTER_KEY_MAX) and
 * fet into fet_out (GY_QSPGS_FET_LEN).  A wrong secret / GID / tamper, or a slot
 * whose plaintext is not the expected width, is GY_ERR_VERIFY.  Returns GY_OK,
 * GY_ERR_VERIFY, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_joinlink_open(uint8_t suite_id, uint8_t aead_id,
                           const uint8_t jls[GY_QSPGS_JOINLINK_SECRET],
                           const uint8_t gid[GY_QSPGS_GID_LEN],
                           const uint8_t *in, size_t inlen, uint8_t *gk_out,
                           uint8_t fet_out[GY_QSPGS_FET_LEN]);

#endif /* GY_QSPGS_FIELD_H */
