/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_KEYS_H
#define GY_QSPGS_KEYS_H

#include <stddef.h>
#include <stdint.h>

#include "krmldsa44.h"
#include "krmldsa87.h"
#include "qspgs_const.h" /* GY_QSPGS_MASTER_KEY_*, GY_QSPGS_UID_LEN (shared with
                          * the custodian's IK-certification layout). */

/*
 * QSPGS key hierarchy (QSPGS_SPEC.md section 2.2, transcription of [CFG+]
 * Figure 6).  The user and group key derivations plus the
 * pseudonym-key wiring over the KR-ML-DSA base pair.
 *
 * QSPGS serves the HYBRID suites only (section 2.1); every entry point takes a
 * suite id and rejects a non-hybrid suite (GY_ERR_ARG).  It is a PARALLEL
 * vertical beside the classical [CPZ] group (geryon_group), reusing geryon_core
 * for HKDF / the suite descriptor exactly as the classical vertical does.
 *
 * Derivation convention (D-QGS-11, D-GEN-3; frozen with the task-6 KATs).
 * Every [CFG+] KDF(key, label[|| var]) is the tier-hash HKDF (RFC 5869) with
 * the section-2.3 extract-then-expand shape:
 *   domain = gy_info(suite_id, purpose)          (qspgs_labels.h)
 *   PRK    = HKDF-Extract(salt = domain, ikm = key)
 *   out    = HKDF-Expand(PRK, info = domain [|| var], L)
 * The variable field, when present, is appended to the expand info: ep as an
 * 8-byte big-endian counter (uk), UID length-prefixed by one byte (rho).  This
 * mirrors group_ops.c / group_hash.c byte-for-byte in idiom.
 */

/*
 * Symmetric key widths.  The main / per-epoch / acquaintance / group keys are
 * 2*kappa per tier (kappa = 16 on the 25519 tier, 28 on the 448 tier), the
 * same GroupMasterKey width the classical vertical uses (QSPGS_SPEC.md section
 * 1.2: muk replaces GroupMasterKey).  Callers stack-allocate to the MAX and
 * operate on gy_qspgs_master_key_len(suite_id) bytes.  GY_QSPGS_MASTER_KEY_*
 * are defined once in qspgs_const.h (shared with the custodian's certification
 * layout).
 */

#define GY_QSPGS_EXPKEY_BYTES 32 /* application exporter root ([CFG+] 6.5). */
#define GY_QSPGS_EK_BYTES 32     /* group-structure AEAD key. */
#define GY_QSPGS_RRS_BYTES 32    /* rerandomization seed. */
#define GY_QSPGS_SEND_BYTES 32   /* section 6.5 send bearer token. */
#define GY_QSPGS_FET_BYTES                                                     \
    32                        /* section 6.5 fetch token (== GY_QSPGS_FET_LEN,
                                    the wire field width in qspgs_wire.h). */
#define GY_QSPGS_RHO_BYTES 64 /* pseudonym randomizer (ExpandS seed width). */
/* GY_QSPGS_UID_LEN is the fixed member-UID width (SEC-v1.5.0 LOW-2), defined in
 * qspgs_const.h.  GY_QSPGS_UID_MAX is the deprecated alias kept for buffer
 * sizing and equals the fixed width. */
#define GY_QSPGS_UID_MAX GY_QSPGS_UID_LEN

/* Pseudonym-key buffer maxima (set by the 87 tier); see krmldsa{44,87}.h. */
#define GY_QSPGS_VKB_MAX GY_KR87_VKB
#define GY_QSPGS_SKB_MAX GY_KR87_SKB
#define GY_QSPGS_VKR_MAX GY_KR87_VKR
#define GY_QSPGS_SIG_MAX GY_KR87_SIG

/* rho is the KR-ML-DSA rerandomizer; the widths must agree across the seam. */
_Static_assert(GY_QSPGS_RHO_BYTES == GY_KR44_RAND &&
                   GY_QSPGS_RHO_BYTES == GY_KR87_RAND,
               "QSPGS rho width must equal the KR-ML-DSA rerandomizer width");

/*
 * Suite-generic pseudonym signing key: the in-memory, backend-affine RandSK
 * result (never serialized; see krmldsa_backend.h).  Tagged with its suite so
 * the sign path dispatches without a second suite argument.  Clear it with
 * gy_qspgs_psdn_sk_clear when done; skpsdn is derived on demand and never
 * stored (QSPGS_SPEC.md sections 2.2, 9).
 */
typedef struct gy_qspgs_psdn_sk {
    uint8_t suite_id;
    union {
        gy_kr44_rsk_t k44;
        gy_kr87_rsk_t k87;
    } rsk;
} gy_qspgs_psdn_sk_t;

/*
 * 2*kappa for suite_id (32 / 56), or 0 if suite_id is not an enabled hybrid
 * suite.  This is the width of muk, uk, acq, and gk.
 */
size_t gy_qspgs_master_key_len(uint8_t suite_id);

/*
 * Base verification-key (vkbase) length for suite_id (GY_KR44_VKB / GY_KR87_VKB),
 * or 0 if suite_id is not an enabled hybrid suite.  Callers size to
 * GY_QSPGS_VKB_MAX.
 */
size_t gy_qspgs_base_vkb_len(uint8_t suite_id);

/*
 * Base signing-key (skbase) length for suite_id (GY_KR44_SKB / GY_KR87_SKB), or
 * 0 if suite_id is not an enabled hybrid suite.  Callers size to
 * GY_QSPGS_SKB_MAX.  Used by the gy_qspgs_store BASE_KEY record (skbase ||
 * vkbase, D-QGS-8) to size the secret half.
 */
size_t gy_qspgs_base_skb_len(uint8_t suite_id);

/* ---- base pair (section 2.2, generated at hybrid-identity creation) ------
 *
 * (skbase, vkbase) = the KR-ML-DSA base pair, one per hybrid identity, from
 * FRESH randomness via gy_kr<set>_keygen_base.  It is NEVER derived from any
 * other key (the section 2.1 base-key independence invariant: not from muk, not
 * from classical key material), so no muk/uk argument appears here.  vkb is
 * shared with acquaintances only; skb is the custody secret at rest (its
 * persistence is the gy_qspgs_store's job, D-QGS-8 / section 9).  vkb / skb are
 * the tier's base sizes (GY_KR<set>_VKB / _SKB); callers size to
 * GY_QSPGS_VKB_MAX / GY_QSPGS_SKB_MAX.
 */
int gy_qspgs_base_keygen(uint8_t suite_id, uint8_t *vkb, uint8_t *skb);

/* Deterministic variant: base pair from a 32-byte seed, for KATs and the
 * independence invariant (a fixed seed => fixed vkbase, regardless of muk). */
int gy_qspgs_base_keygen_seed(uint8_t suite_id, uint8_t *vkb, uint8_t *skb,
                              const uint8_t *seed);

/* ---- user keys (section 2.2) --------------------------------------------
 *
 * muk and gk are fresh randomness (drawn by the caller from core/ rng.c), NOT
 * derived here.  uk and acq are master_key_len bytes; the caller stack-sizes
 * them to GY_QSPGS_MASTER_KEY_MAX.  Each returns GY_OK or a negative GY_ERR_*
 * and zeroizes its intermediates.
 */

/* uk = KDF(muk, "uk@" || ep): the per-epoch user key.  Bumping ep is Refresh
 * (acquaintance reset / blocking). */
int gy_qspgs_derive_uk(uint8_t suite_id, const uint8_t *muk, uint64_t ep,
                       uint8_t *uk);

/* acq = KDF(uk, "ACQ-Tag"): the acquaintance tag deposited at registration. */
int gy_qspgs_derive_acq(uint8_t suite_id, const uint8_t *uk, uint8_t *acq);

/* expKey = KDF(uk, "EXP-Key"): exporter root for application material. */
int gy_qspgs_derive_exp_key(uint8_t suite_id, const uint8_t *uk,
                            uint8_t out[GY_QSPGS_EXPKEY_BYTES]);

/* ---- group keys (section 2.2) -------------------------------------------- */

/* (ek, rrs) = KDF(gk, "SUB-KEY"): the group-structure AEAD key and the
 * rerandomization seed, in one expand (ek || rrs). */
int gy_qspgs_derive_sub_key(uint8_t suite_id, const uint8_t *gk,
                            uint8_t ek[GY_QSPGS_EK_BYTES],
                            uint8_t rrs[GY_QSPGS_RRS_BYTES]);

/* rho = KDF(rrs, "rerand@" || UID): the per-member pseudonym randomizer.  UID
 * is length-prefixed into the expand info; uidlen must be exactly GY_QSPGS_UID_LEN. */
int gy_qspgs_derive_rho(uint8_t suite_id, const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                        const uint8_t *uid, size_t uidlen,
                        uint8_t rho[GY_QSPGS_RHO_BYTES]);

/* ---- symmetric fetch / send tokens (section 6.5) --------
 *
 * fet = KDF(gk, "qspgs-fet") and the send token = KDF(gk, "qspgs-send"): two
 * independent bearer tokens off the group key, per-major-version by gk rotation.
 * Each is a single expand; rederived on demand, never stored (section 9).  The
 * derived fet is what a fetching member presents and gy_qspgs_server_fetch_check
 * compares against the server's separately stored fet record (SEC-v1.5.0 LOW-1;
 * no longer a header field).  Each returns GY_OK or a negative
 * GY_ERR_* and zeroizes its intermediates.
 */
int gy_qspgs_derive_fet(uint8_t suite_id, const uint8_t *gk,
                        uint8_t fet[GY_QSPGS_FET_BYTES]);
int gy_qspgs_derive_send(uint8_t suite_id, const uint8_t *gk,
                         uint8_t send[GY_QSPGS_SEND_BYTES]);

/* ---- pseudonym keys (section 2.2, over the KR-ML-DSA base pair) ----------
 *
 * Suite-dispatched thin wrappers over gy_kr<set>_randvk / randsk with rho as
 * derived by gy_qspgs_derive_rho.  vkpsdn is a byte-standard ML-DSA key every
 * member recomputes from rrs; skpsdn is derived on demand and cleared after
 * use.  Both reject a base key whose fixed-A field is wrong (GY_ERR_ARG, via
 * the primitive).
 */

/* vkpsdn = RandVK(vkbase, rho).  vkr is the tier's standard ML-DSA pk
 * (GY_KR44_VKR / GY_KR87_VKR); caller sizes to GY_QSPGS_VKR_MAX. */
int gy_qspgs_derive_vk_psdn(uint8_t suite_id, uint8_t *vkr, const uint8_t *vkb,
                            const uint8_t rho[GY_QSPGS_RHO_BYTES]);

/* skpsdn = RandSK(skbase, vkbase, rho), into the suite-generic *out. */
int gy_qspgs_derive_sk_psdn(uint8_t suite_id, gy_qspgs_psdn_sk_t *out,
                            const uint8_t *skb, const uint8_t *vkb,
                            const uint8_t rho[GY_QSPGS_RHO_BYTES]);

/* Zeroize a pseudonym signing key (idempotent; NULL-safe). */
void gy_qspgs_psdn_sk_clear(gy_qspgs_psdn_sk_t *sk);

#endif /* GY_QSPGS_KEYS_H */
