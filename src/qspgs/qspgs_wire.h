/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_WIRE_H
#define GY_QSPGS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "qspgs_keys.h" /* GY_QSPGS_VKR_MAX, GY_QSPGS_SIG_MAX */

/*
 * QSPGS group data structure wire format (QSPGS_SPEC.md section 4, transcription
 * of [CFG+] section 3.2 / Fig. 5; the section 8 D-QGS-7 freeze).
 *
 * Framing follows the classical group vertical (group_wire.h) exactly, a
 * parallel but SEPARATE wire: one QSPGS msg_type under D-GEN-1, and every
 * top-level object carries the 3-byte object header
 *   obj_type || GY_QSPGS_WIRE_VERSION || suite_id
 * The object-type registry is FROZEN at the first published structure KATs;
 * later versions append, never renumber.  Integers are big-endian
 * (gy_be*_put/get).  Lists are a count (BE16) followed by that many entries,
 * and decode is STRICT: exact length, correct header, trailing bytes rejected.
 *
 * The encrypted/opaque fields (the settings+attributes AEAD ciphertext, each
 * member's mct, the optional join slot, appendix payloads, invite entries) are
 * carried as LENGTH-PREFIXED OPAQUE blobs: the codec frames and bounds them but
 * never interprets ciphertext.  Their AEAD-internal layout is a client-operation
 * matter and is deliberately not frozen by the structure grammar.
 * The fixed-width fields are the ones whose size the crypto already fixes: GID,
 * C_UID (a tier-hash commitment), H(vkpsdn) (a tier-hash), and the BE32
 * versions.  (fet is fixed-width too but no longer a header field; SEC-v1.5.0
 * LOW-1.  It rides the emit bundle as a separate server record.)
 *
 * The wire freeze is cleared by the satisfied D-QGS-7 benchmark;
 * versioned from day one (GY_QSPGS_WIRE_VERSION).
 */

/* D-GEN-1 msg_type for the QSPGS vertical (0x01 INIT, 0x02 DR, 0x03 the
 * classical GROUP_KEY_DISTRIBUTION are taken; session/recv.h).  A single QSPGS
 * type demultiplexed by the object header, mirroring the classical 0x03. */
#define GY_QSPGS_MSG 0x04

#define GY_QSPGS_WIRE_VERSION 0x01
#define GY_QSPGS_OBJ_HDR_LEN 3

/*
 * QSPGS FORMAT / capability epoch (D-QGS-12; the QSPGS analogue of the classical
 * group format_version).  This is DISTINCT from the group STATE version
 * (vMaj, vMin): the state version advances on every membership / key edit, while
 * the format version names which [CFG+] data-structure revision the group
 * follows.  It is chosen at Create, IMMUTABLE for the group's life, carried as a
 * 2-byte big-endian field in the header object (item 1), and therefore covered
 * by the admin core signature (the header is inside the core TBS) - the QSPGS
 * substitute for classical binding it into a derived GroupID, since the QSPGS
 * GID is an opaque caller-supplied value.  The SAME value is stamped into the
 * gy_qspgs_store records (§9).  A decoder refuses a group whose format version is
 * outside [MIN, MAX] (GY_ERR_UNSUPPORTED).  New groups mint at
 * GY_QSPGS_FORMAT_VERSION; a future [CFG+] revision raises MAX (and eventually
 * MIN, to deprecate the old epoch).  QSPGS is new, so the window opens at 1. */
#define GY_QSPGS_FORMAT_VERSION 1
#define GY_QSPGS_MIN_SUPPORTED_FORMAT_VERSION 1
#define GY_QSPGS_MAX_SUPPORTED_FORMAT_VERSION 1

/* Object-type registry (section 4).  Append below, never renumber. */
#define GY_QOBJ_HEADER 0x01       /* section 4 item 1 */
#define GY_QOBJ_MEMBER_LIST 0x02  /* section 4 item 2 */
#define GY_QOBJ_VK_LST 0x03       /* section 4 item 3 */
#define GY_QOBJ_CORE_SIG 0x04     /* section 4 item 4 */
#define GY_QOBJ_APPENDIX 0x05     /* section 4 item 5 */
#define GY_QOBJ_INVITE_QUEUE 0x06 /* section 4 item 6 */
#define GY_QOBJ_ACCT 0x07         /* section 7.2 registration record */
#define GY_QOBJ_GROUP_KEY                                                      \
    0x08 /* group-key distribution envelope (client op,
                                     section 5 gk delivery; SEC-v1.5.0 INFO-4) */

/* Fixed-width structure fields. GY_QSPGS_GID_LEN is defined in qspgs_const.h
 * (via qspgs_keys.h), shared with the custodian's certification layout. */
#define GY_QSPGS_FET_LEN 32 /* fetch token (bearer, per major version). */
#define GY_QSPGS_RC_LEN 32  /* C_UID opening randomness r_c. */

/*
 * Tier-hash-sized fields (C_UID commitment and H(vkpsdn)): 32 on the 25519
 * tier, 64 on the 448 tier.  Callers size to the MAX; the codec carries the
 * active hash length inline (a leading byte) and validates it against the
 * suite's hash_len on decode.
 */
#define GY_QSPGS_HASH_MAX 64

/*
 * Per-fetch entry bound (D-QGS-8 / the GY_GROUP_MAX_ENTRIES pattern): the codec
 * processes at most this many member / vk-lst entries; applications may lower
 * it, never raise it.  FROZEN here with the wire.
 */
#define GY_QSPGS_MAX_ENTRIES 1024

/*
 * Core-edit operation kind (D-QGS-13 E2, section 7.3 item 1).  A submission
 * carries the operation so the stateless server can apply the [CFG+]
 * per-operation vk-lst rule against the STORED prior core (Fig. 11 / 17 / 19 /
 * 20, App. B.5).  The four categories are the reduction of every core-signing
 * operation; they fix both the vk-lst transition the server enforces and where
 * the signer's own vkpsdn is resolved:
 *   CREATE     no prior; vk-lst = submitted, n_vk == 1, vMaj == 1.
 *   UNCHANGED  submitted vk-lst MUST equal prior byte for byte
 *              (SetAdminRights, ChangeSettings, ChangeAttr, ToggleJoinLink).
 *   APPEND_ONE submitted vk-lst MUST equal prior with exactly one newcomer
 *              hash appended (AddMember, UserAdd, Invite).
 *   REPLACE    any submitted vk-lst accepted; rotation rerandomized every key
 *              and the server holds no gk (RemoveMember, RotateGroupKey).
 * The operation is routing metadata, not a trust anchor: the fetch-time client
 * recompute (section 5, E5) is the security guarantee; this is the server-side
 * defense-in-depth gate.  Append, never renumber.
 */
#define GY_QSPGS_OP_CREATE 0
#define GY_QSPGS_OP_UNCHANGED 1
#define GY_QSPGS_OP_APPEND_ONE 2
#define GY_QSPGS_OP_REPLACE 3

/* ------------------------------------------------------------------------- *
 * Frozen tier-hash helpers (D-QGS-7): the C_UID commitment and the H(vkpsdn)
 * list optimization.  Both are the tier hash (SHA-256 / SHA-512) over a
 * D-GEN-3 domain-separated input, so neither collides across suites.
 * ------------------------------------------------------------------------- */

/*
 * C_UID = H(domain || r_c || UID), the member-entry commitment ([CFG+] uses a
 * statistically hiding commitment; geryon's hash-based commitment is
 * computationally hiding, the recorded section 2.3 item 3 deviation).  out
 * receives desc->hash_len bytes (size to GY_QSPGS_HASH_MAX).  r_c is the
 * GY_QSPGS_RC_LEN-byte opening.  Returns GY_OK, GY_ERR_ARG on a NULL argument,
 * a non-hybrid suite, or a UID length outside exactly GY_QSPGS_UID_LEN.
 */
int gy_qspgs_cuid_commit(uint8_t suite_id, const uint8_t *uid, size_t uidlen,
                         const uint8_t rc[GY_QSPGS_RC_LEN], uint8_t *out);

/*
 * H(vkpsdn) = H(domain || vkr): the value the server stores per vk-lst line;
 * the full vkr is supplied with a member's first signature and checked against
 * this hash ([CFG+] section 3.2 optimization, D-QGS-6 item 3).  vkr is the
 * tier's standard ML-DSA public key (GY_QSPGS_VKR_MAX); out receives
 * desc->hash_len bytes.  Returns GY_OK or GY_ERR_ARG.
 */
int gy_qspgs_vkpsdn_hash(uint8_t suite_id, const uint8_t *vkr, uint8_t *out);

/*
 * Constant-time check that vkr resolves to the stored hash (H(vkpsdn) ==
 * stored): recomputes the hash and compares with gy_const_memcmp.  Returns
 * GY_OK on a match, GY_ERR_VERIFY on a mismatch, GY_ERR_ARG on bad input.
 */
int gy_qspgs_vkpsdn_hash_check(uint8_t suite_id, const uint8_t *vkr,
                               const uint8_t *stored_hash);

/* ------------------------------------------------------------------------- *
 * The core list (header + member list + vk-lst) and its admin core signature.
 * These three objects plus the versions are what the editing admin signs under
 * skpsdn (section 4 item 4), so they are grouped here.
 * ------------------------------------------------------------------------- */

/* A server-authoritative member entry (section 4 item 2).  cuid is hash_len
 * bytes; mct is the opaque Enc_ek(UID, r_c, uk) ciphertext (carried, never
 * interpreted).  admn is the server-visible admin flag (0 / 1). */
struct gy_qspgs_member {
    uint8_t cuid[GY_QSPGS_HASH_MAX];
    uint8_t admn;
    const uint8_t *mct;
    size_t mct_len;
};

/*
 * The full section-4 core list, in memory.  All list/blob storage is
 * caller-provided (no dynamic allocation): the codec reads and writes through
 * these pointers.  suite_id selects the tier (hash_len, key sizes).
 */
struct gy_qspgs_core {
    uint8_t suite_id;

    /* Header (item 1). */
    uint8_t gid[GY_QSPGS_GID_LEN];
    uint16_t format_version; /* D-QGS-12 capability epoch; set at Create, then
                                immutable.  Distinct from vmaj (state). */
    uint8_t aead_id; /* SEC-v1.5.0 INFO-6: group field AEAD, admin-pinned
                                at Create, immutable for the group's life
                                (gy_qspgs_group_aead_ok).  Inside the header, so
                                covered by the core signature and enforced by
                                gy_qspgs_server_core_check. */
    uint32_t vmaj;
    uint8_t fet[GY_QSPGS_FET_LEN];
    const uint8_t *sa_ct; /* Enc_ek(settings, attributes). */
    size_t sa_ct_len;
    const uint8_t *join_ct; /* optional join slot; NULL / 0 if absent. */
    size_t join_ct_len;

    /* Member list (item 2). */
    const struct gy_qspgs_member *members;
    size_t n_members;

    /* Pseudonym key list (item 3): n_vk entries of hash_len bytes, packed. */
    const uint8_t *vkhash;
    size_t n_vk;

    /* Last reconciled minor version (covered by the core signature). */
    uint32_t last_vmin;
};

/*
 * Encode the header object (GY_QOBJ_HEADER) into out.  On entry *outlen is the
 * capacity; on success it holds the bytes written.  Returns GY_OK,
 * GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on bad input.
 */
int gy_qspgs_header_encode(const struct gy_qspgs_core *core, uint8_t *out,
                           size_t cap, size_t *outlen);

/*
 * Encode the member-list object (GY_QOBJ_MEMBER_LIST): hash_len(1) ||
 * count(BE16) || count * (cuid(hash_len) || admn(1) || mct_len(BE16) || mct).
 * n_members must be <= GY_QSPGS_MAX_ENTRIES.  Returns as above.
 */
int gy_qspgs_member_list_encode(const struct gy_qspgs_core *core, uint8_t *out,
                                size_t cap, size_t *outlen);

/*
 * Encode the vk-lst object (GY_QOBJ_VK_LST): hash_len(1) || count(BE16) ||
 * count * hash_len bytes (packed H(vkpsdn)).  Returns as above.
 */
int gy_qspgs_vk_lst_encode(const struct gy_qspgs_core *core, uint8_t *out,
                           size_t cap, size_t *outlen);

/*
 * Assemble the canonical to-be-signed byte string for the core signature
 * (section 4 item 4): signer_index(BE32) || header-object || member-list-object
 * || vk-lst-object || vMaj(BE32) || last_vMin(BE32).  This is the exact input
 * to sign under skpsdn and to verify under the signer's vkpsdn.  On entry
 * *outlen is the capacity; on success it holds the bytes written.  Returns
 * GY_OK, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_core_tbs(const struct gy_qspgs_core *core, uint32_t signer_index,
                      uint8_t *out, size_t cap, size_t *outlen);

/*
 * Encode the core-signature object (GY_QOBJ_CORE_SIG): signer_index(BE32) ||
 * last_vMin(BE32) || sig_len(BE16) || sig.  sig is the KR-ML-DSA signature over
 * the gy_qspgs_core_tbs bytes (produced by gy_kr<set>_sign under skpsdn).
 * last_vMin travels here (it is covered by the signature but is not a header
 * field), so a decoder can rebuild the TBS.  Returns as above.
 */
int gy_qspgs_core_sig_encode(uint8_t suite_id, uint32_t signer_index,
                             uint32_t last_vmin, const uint8_t *sig,
                             size_t sig_len, uint8_t *out, size_t cap,
                             size_t *outlen);

/*
 * Verify the admin core signature: rebuild the TBS bytes for signer_index into
 * the caller-provided scratch buffer (no allocation; the client-side signer
 * needs the same working buffer), then verify sig under the signer's full
 * pseudonym public key vkr (the key a member supplies with its first signature;
 * the caller has already resolved it against the vk-lst H(vkpsdn) via
 * gy_qspgs_vkpsdn_hash_check).  Signing/verifying use the frozen
 * GY_QSPGS_CTX_CORE context.  Returns GY_OK, GY_ERR_VERIFY on a bad signature,
 * GY_ERR_TOOLONG if scratch is too small, or GY_ERR_ARG on bad input.
 */
int gy_qspgs_core_verify(const struct gy_qspgs_core *core,
                         uint32_t signer_index, const uint8_t *vkr,
                         const uint8_t *sig, size_t sig_len, uint8_t *scratch,
                         size_t scratch_cap);

/* ------------------------------------------------------------------------- *
 * Decode.  The decoder fills a gy_qspgs_core whose blob/list pointers reference
 * INTO the input buffer (zero-copy); the caller keeps the input alive for the
 * lifetime of the decoded view and provides the member array.
 * ------------------------------------------------------------------------- */

/*
 * Decode a header object from in[0..len).  On success fills the header fields of
 * *core (gid, vmaj, sa_ct/join_ct pointing into in; fet is no longer a header
 * field, SEC-v1.5.0 LOW-1) and sets *consumed to
 * the object length.  core->suite_id must already name the tier.  Returns
 * GY_OK, GY_ERR_VERIFY on a header/length/suite mismatch, GY_ERR_ARG on bad
 * input.
 */
int gy_qspgs_header_decode(struct gy_qspgs_core *core, const uint8_t *in,
                           size_t len, size_t *consumed);

/*
 * Decode a member-list object into out[0..out_cap) (each entry's mct points
 * into in).  Sets core->members = out, core->n_members, and *consumed.  The
 * inline hash_len must equal the suite's; count must be <= min(out_cap,
 * GY_QSPGS_MAX_ENTRIES).  Returns GY_OK, GY_ERR_VERIFY, GY_ERR_TOOLONG if the
 * count exceeds out_cap, or GY_ERR_ARG.
 */
int gy_qspgs_member_list_decode(struct gy_qspgs_core *core,
                                struct gy_qspgs_member *out, size_t out_cap,
                                const uint8_t *in, size_t len,
                                size_t *consumed);

/*
 * Decode a vk-lst object: validates the inline hash_len and count, points
 * core->vkhash into in, sets core->n_vk and *consumed.  Returns GY_OK,
 * GY_ERR_VERIFY, GY_ERR_TOOLONG if the count exceeds GY_QSPGS_MAX_ENTRIES, or
 * GY_ERR_ARG.
 */
int gy_qspgs_vk_lst_decode(struct gy_qspgs_core *core, const uint8_t *in,
                           size_t len, size_t *consumed);

/*
 * Decode a core-signature object: fills *signer_index and *last_vmin and points
 * *sig into in with *sig_len.  Returns GY_OK, GY_ERR_VERIFY, GY_ERR_ARG.
 */
int gy_qspgs_core_sig_decode(uint8_t suite_id, const uint8_t *in, size_t len,
                             uint32_t *signer_index, uint32_t *last_vmin,
                             const uint8_t **sig, size_t *sig_len,
                             size_t *consumed);

/* ------------------------------------------------------------------------- *
 * Appendix (section 4 item 5): the append-only, per-line-signed log an admin
 * later reconciles into a new core version.  Each line is individually signed
 * by its author's skpsdn over the apx-hdr (GID || vMaj || vMin) followed by
 * (line_type || author_index || payload), under the frozen
 * GY_QSPGS_CTX_APPENDIX context; the apx-hdr binds the line to its group and
 * version (D-QGS-13 E1, anti-replay) and the line_type byte inside the signed
 * data separates the five kinds.  Invalid lines are ignored by honest clients
 * and attributable to their signer.
 * ------------------------------------------------------------------------- */

/* Appendix line-type registry ([CFG+] section 3.2).  Append, never renumber. */
#define GY_QAPX_LEAVE 0x01   /* leave(i) */
#define GY_QAPX_REFRESH 0x02 /* refresh(i, Enc_ek(uk')) */
#define GY_QAPX_ADDUSER 0x03 /* addUser(i, C_UID', Enc_ek(UID', r', uk')) */
#define GY_QAPX_MODATTR 0x04 /* modAttr(i, Enc_ek(attr)) */
#define GY_QAPX_JOIN 0x05    /* join(Enc_ek(C_UID, r, uk)) */

/* One appendix line.  payload is the opaque op-specific ciphertext; sig is the
 * author's skpsdn signature over the line TBS (below).  Both point into the
 * input buffer after a decode. */
struct gy_qspgs_apx_line {
    uint8_t line_type;
    uint32_t author_index;
    const uint8_t *payload;
    size_t payload_len;
    const uint8_t *sig;
    size_t sig_len;
};

/* The appendix object header fields plus its lines. */
struct gy_qspgs_appendix {
    uint8_t suite_id;
    uint8_t gid[GY_QSPGS_GID_LEN];
    uint32_t vmaj;
    uint32_t vmin;
    const struct gy_qspgs_apx_line *lines; /* for encode. */
    size_t n_lines;
};

/*
 * Assemble the canonical to-be-signed bytes for one appendix line:
 * GID(16) || vMaj(BE32) || vMin(BE32) || line_type(1) || author_index(BE32) ||
 * payload.  The leading apx-hdr (gid, vmaj, vmin) binds the line to its group
 * and version so a corrupt server cannot replay an old signed line at a later
 * version (D-QGS-13 E1; [CFG+] Fig. 12/16 sign Sgn(apx-hdr, line)).  This is
 * what the author signs under skpsdn (context GY_QSPGS_CTX_APPENDIX) and what a
 * verifier rebuilds.  On entry cap is the buffer capacity; on success *outlen
 * holds the bytes written.  Returns GY_OK, GY_ERR_TOOLONG, or GY_ERR_ARG
 * (unknown line_type or NULL gid included).
 */
int gy_qspgs_apx_line_tbs(const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
                          uint32_t vmin, uint8_t line_type,
                          uint32_t author_index, const uint8_t *payload,
                          size_t payload_len, uint8_t *out, size_t cap,
                          size_t *outlen);

/*
 * Verify one appendix line's signature under the author's full pseudonym key
 * vkr, rebuilding the line TBS (over the apx-hdr gid/vmaj/vmin and the line)
 * into the caller-provided scratch buffer.  The caller supplies the appendix
 * header fields, which the decoded gy_qspgs_appendix already carries.  Returns
 * GY_OK, GY_ERR_VERIFY on a bad signature, GY_ERR_TOOLONG if scratch is too
 * small, or GY_ERR_ARG.
 */
int gy_qspgs_apx_line_verify(uint8_t suite_id,
                             const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
                             uint32_t vmin,
                             const struct gy_qspgs_apx_line *line,
                             const uint8_t *vkr, uint8_t *scratch,
                             size_t scratch_cap);

/*
 * Leaver fetch token ([CFG+] Fig. 10, lower half): build the canonical TBS
 * GID(16) || k(BE32) into out[0..cap) (*outlen set), and verify such a token
 * under the leaver's full pseudonym key vkr.  These are sk-free (verify path
 * only), so they live in the common layer and the stateless server can call
 * them; the signing counterpart is gy_qspgs_leave_token_sign (qspgs_ops.h).
 * verify returns GY_OK, GY_ERR_VERIFY on a bad signature, or GY_ERR_ARG.
 */
int gy_qspgs_leave_token_tbs(const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                             uint8_t *out, size_t cap, size_t *outlen);

int gy_qspgs_leave_token_verify(uint8_t suite_id,
                                const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                                const uint8_t *sig, size_t sig_len,
                                const uint8_t *vkr);

/*
 * Encode the appendix object (GY_QOBJ_APPENDIX): GID(16) || vMaj(BE32) ||
 * vMin(BE32) || count(BE16) || count * (line_type(1) || author_index(BE32) ||
 * payload_len(BE16) || payload || sig_len(BE16) || sig).  n_lines must be <=
 * GY_QSPGS_MAX_ENTRIES.  Returns GY_OK, GY_ERR_TOOLONG, GY_ERR_ARG.
 */
int gy_qspgs_appendix_encode(const struct gy_qspgs_appendix *apx, uint8_t *out,
                             size_t cap, size_t *outlen);

/*
 * Decode an appendix object into out[0..out_cap) (payload / sig point into in).
 * apx->suite_id must already name the tier; fills apx's header fields, sets
 * apx->lines = out and apx->n_lines, and *consumed.  Rejects an unknown
 * line_type, an empty signature, a count over min(out_cap, GY_QSPGS_MAX_ENTRIES)
 * (GY_ERR_TOOLONG if only over out_cap), or trailing bytes.  Returns GY_OK,
 * GY_ERR_VERIFY, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_appendix_decode(struct gy_qspgs_appendix *apx,
                             struct gy_qspgs_apx_line *out, size_t out_cap,
                             const uint8_t *in, size_t len, size_t *consumed);

/* ------------------------------------------------------------------------- *
 * Invite queue (section 4 item 6): a counted list of opaque PKE ciphertexts,
 * each a gy_qspgs_join_seal output over (UID, uk, Sgn(skpers, (UID, uk, GID))).
 * The codec frames the entries; it never opens them (members holding isk do).
 * ------------------------------------------------------------------------- */

/* One invite-queue entry: an opaque join-PKE ciphertext (into in after decode). */
struct gy_qspgs_invite_entry {
    const uint8_t *ct;
    size_t ct_len;
};

/*
 * Encode the invite-queue object (GY_QOBJ_INVITE_QUEUE): count(BE16) ||
 * count * (entry_len(BE32) || entry).  n must be <= GY_QSPGS_MAX_ENTRIES.
 * Returns GY_OK, GY_ERR_TOOLONG, GY_ERR_ARG.
 */
int gy_qspgs_invite_queue_encode(uint8_t suite_id,
                                 const struct gy_qspgs_invite_entry *entries,
                                 size_t n, uint8_t *out, size_t cap,
                                 size_t *outlen);

/*
 * Decode an invite-queue object into out[0..out_cap) (each ct points into in).
 * Sets *n_out and *consumed.  Rejects an empty entry, a count over
 * min(out_cap, GY_QSPGS_MAX_ENTRIES) (GY_ERR_TOOLONG if only over out_cap), or
 * trailing bytes.  Returns GY_OK, GY_ERR_VERIFY, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_invite_queue_decode(uint8_t suite_id,
                                 struct gy_qspgs_invite_entry *out,
                                 size_t out_cap, const uint8_t *in, size_t len,
                                 size_t *n_out, size_t *consumed);

/* ------------------------------------------------------------------------- *
 * Registration record (section 7.2, [CFG+] Acct): the server's per-UID record,
 * deposited at RegisterUser and served to anyone who queries.  A pure carrier
 * object; the crypto (skpers signs (vkbase, acq), verified against the hybrid
 * identity) lives in qspgs_ops.c (gy_qspgs_register / gy_qspgs_acct_verify).
 * The signature sigma is the dual XEdDSA + ML-DSA pair (both-or-abort,
 * qspgs_pers.c), carried length-prefixed.
 * ------------------------------------------------------------------------- */

/*
 * Encode the registration record (GY_QOBJ_ACCT): hdr || vkbase(tier VKB) ||
 * acq(2*kappa) || ep(BE64) || ed_sig_len(BE16) || ed_sig || mldsa_sig_len(BE16)
 * || mldsa_sig.  vkbase and acq are fixed-width for the tier; the two
 * signatures are length-prefixed (XEdDSA width differs by curve).  Returns
 * GY_OK, GY_ERR_TOOLONG, or GY_ERR_ARG.
 */
int gy_qspgs_acct_encode(uint8_t suite_id, const uint8_t *vkb,
                         const uint8_t *acq, uint64_t ep, const uint8_t *ed_sig,
                         size_t ed_sig_len, const uint8_t *mldsa_sig,
                         size_t mldsa_sig_len, uint8_t *out, size_t cap,
                         size_t *outlen);

/*
 * Decode a registration record: points vkb / acq / ed_sig / mldsa_sig into in
 * (zero-copy), fills *ep and the two signature lengths, and sets *consumed.
 * Strict: exact length, correct header, non-empty signatures.  Returns GY_OK,
 * GY_ERR_VERIFY, or GY_ERR_ARG.
 */
int gy_qspgs_acct_decode(uint8_t suite_id, const uint8_t *in, size_t len,
                         const uint8_t **vkb, const uint8_t **acq, uint64_t *ep,
                         const uint8_t **ed_sig, size_t *ed_sig_len,
                         const uint8_t **mldsa_sig, size_t *mldsa_sig_len,
                         size_t *consumed);

#endif /* GY_QSPGS_WIRE_H */
