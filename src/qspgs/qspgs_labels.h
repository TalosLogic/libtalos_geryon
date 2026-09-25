/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_LABELS_H
#define GY_QSPGS_LABELS_H

#include "qspgs_const.h" /* GY_QSPGS_CTX_REGUSER / _INVACCEPT (the two identity-
                          * signed labels, shared with the custodian). */

/*
 * QSPGS key-hierarchy label registry (QSPGS_SPEC.md section 2.3 item 2).
 * These are the D-GEN-3 domain-separation purposes for the
 * section 2.2 KDF steps; each is fed to gy_info(suite_id, purpose) to build
 * "geryon" "." "1" "." <suite_name> "." <purpose>, so the suite string
 * (app_id || protocol_version || suite_id) rides every derivation.  The
 * [CFG+] Figure 6 label each one instantiates is named alongside it.
 *
 * FROZEN with the first published derivation KATs: once a
 * KAT pins the bytes, a purpose string is part of the wire and must not change.
 * New entries append; existing ones never mutate.
 *
 * One other frozen string lives outside this file and is NOT redefined here:
 * the fixed-A seed label "geryon-QSPGS-KR-ML-DSA-<44|87>-v1" (QSPGS_SPEC.md
 * section 3.3; src/core/krmldsa/krmldsa_impl.c), a bare SHAKE256 input with no
 * gy_info framing.  The skpers per-operation context strings (D-QGS-6 item 2)
 * ARE registered here, at the end of this file.
 */

/* KDF(muk, "uk@" || ep)  -> uk (per-epoch user key). ep is appended be64. */
#define GY_QSPGS_LBL_UK "qspgs-uk"

/* KDF(uk, "ACQ-Tag")  -> acq (acquaintance tag). */
#define GY_QSPGS_LBL_ACQ "qspgs-acq"

/* KDF(uk, "EXP-Key")  -> expKey (application exporter root). */
#define GY_QSPGS_LBL_EXP "qspgs-exp"

/* KDF(gk, "SUB-KEY")  -> ek || rrs (group AEAD key, rerandomization seed). */
#define GY_QSPGS_LBL_SUB "qspgs-sub"

/* KDF(rrs, "rerand@" || UID)  -> rho (pseudonym randomizer). UID is appended
 * length-prefixed (one byte) after the domain. */
#define GY_QSPGS_LBL_RERAND "qspgs-rerand"

/*
 * Symmetric fetch / send bearer tokens (QSPGS_SPEC.md section 6.5).  Two
 * INDEPENDENT branches off gk (like the join keypair's two
 * halves): KDF(gk, "qspgs-fet") -> fet, KDF(gk, "qspgs-send") -> the send token.
 * gk rotates on a major version, so both tokens are per-major-version by
 * construction (no version is mixed in by hand).  fet is the 32-byte server-record /
 * join-slot bearer field a fetching member presents; the server compares it with
 * gy_qspgs_server_fetch_check.  Rederived on load, never persisted (section 9).
 * These ship the symmetric derivation only; rate limiting stays with the
 * deployer (section 6.5). */
#define GY_QSPGS_LBL_FET "qspgs-fet"
#define GY_QSPGS_LBL_SEND "qspgs-send"

/*
 * skpers per-operation context strings (QSPGS_SPEC.md section 2.2, D-QGS-6
 * item 2).  The hybrid identity's XEdDSA + ML-DSA signing capability signs
 * exactly two QSPGS objects, each under its own context; both schemes must
 * verify.  As gy_info purposes these become the XEdDSA prepended-info string
 * AND the FIPS 204 ML-DSA context (D-PQ-1), so the suite string is bound into
 * both halves.  GY_QSPGS_CTX_REGUSER (signs (vkbase, acq) at RegisterUser,
 * [CFG+] Figure 7) and GY_QSPGS_CTX_INVACCEPT (signs (UID, uk, GID) in the
 * invite acceptance) are defined in qspgs_const.h: the custodian owns the two
 * objects the identity key certifies, so their labels and byte layouts live
 * once, shared with the vertical's raw-key path.
 */

/*
 * Join-keypair derivation and seal (QSPGS_SPEC.md section 2.2 (ipk, isk),
 * section 8, D-QGS-7 / D-QGS-2 item).  (ipk, isk) is the group-wide
 * join-request keypair, rederived from gk by every member (nothing derived is
 * stored, section 9); the invite queue is sealed to ipk and drained by members
 * holding isk.  In geryon the PKE is the suite KEM hybrid (ECDH + ML-KEM,
 * section 10.1), so isk has two secret halves and MUST be derived so that
 * breaking one primitive on a quantum computer does not reveal the other: the
 * curve scalar and the ML-KEM keygen seed come from two INDEPENDENT,
 * domain-separated HKDF branches off gk.  HKDF-Expand is one-way, so recovering
 * one derived secret (via a broken primitive) yields neither the PRK nor the
 * other branch; this preserves the hybrid guarantee at the key level, not only
 * at the per-ciphertext fusion.  The two branch labels are therefore distinct
 * gy_info purposes, never one seed split by hand.
 */

/* HKDF-Extract(gk)+Expand -> the curve (X25519/X448) scalar for isk. */
#define GY_QSPGS_LBL_JOIN_EC "qspgs-join-ec"

/* HKDF-Extract(gk)+Expand -> the 64-byte ML-KEM KeyGen seed for isk. */
#define GY_QSPGS_LBL_JOIN_MLKEM "qspgs-join-mlkem"

/*
 * Per-seal KEM-DEM key fusion.  key = KDF over (kem_ss || dh), PQ-first per the
 * HYBRID_SPEC hybrid combiner: a fresh ephemeral ECDH plus one ML-KEM
 * encapsulation to ipk, fused, then the payload is AEAD-sealed.  Confidentiality
 * survives if EITHER primitive holds (project hybrid invariant).
 */
#define GY_QSPGS_LBL_JOIN_KEM "qspgs-join-kem"

/*
 * Group data structure (QSPGS_SPEC.md section 4, section 8).  Two
 * frozen tier-hash domains and the admin core-signature context.  The hash
 * labels are gy_info domains PREPENDED to the hashed input (D-GEN-3
 * domain separation across suites); the context label is the FIPS 204 /
 * rerandomized-key context the admin core signature is made under.
 */

/* C_UID = H(gy_info("qspgs-cuid") || r_c || UID): member-entry commitment. */
#define GY_QSPGS_LBL_CUID "qspgs-cuid"

/* H(vkpsdn) = H(gy_info("qspgs-vkhash") || vkr): the vk-lst stored hash. */
#define GY_QSPGS_LBL_VKHASH "qspgs-vkhash"

/* Context for the editing admin's core signature under skpsdn (section 4
 * item 4), passed to gy_kr<set>_sign / _verify. */
#define GY_QSPGS_CTX_CORE "qspgs-core"

/* Context for an appendix line's author signature under skpsdn (section 4
 * item 5).  The line_type byte inside the signed bytes separates the five
 * line kinds, so one context suffices. */
#define GY_QSPGS_CTX_APPENDIX "qspgs-appendix"

/* Context for a departed member's fetch token ([CFG+] Fig. 10, lower half): a
 * signature under the leaver's (former) skpsdn over (GID || k), where k is its
 * index in the vk-lst it belonged to.  It lets a leaver fetch to confirm its
 * removal was reconciled, in place of the gk-derived fet it no longer shares. */
#define GY_QSPGS_CTX_LEAVEFETCH "qspgs-leavefetch"

/*
 * Client operations, ek-encrypted field layer (QSPGS_SPEC.md section 5).  The
 * group structure's encrypted fields (mct, the header
 * (settings, attributes), the appendix payloads, the join slot) are AEAD-sealed
 * under the group key ek with this gy_info domain plus a one-byte field-kind tag
 * and the GID in the associated data.  Binding the field kind stops a ciphertext
 * of one kind being replayed as another; binding the GID stops cross-group
 * replay.  Rollback across versions is caught by the core signature (which
 * covers vMaj / vMin), so the field AAD does not bind a version.  ek is a
 * long-lived group key, so every seal draws a fresh random nonce (prepended to
 * the ciphertext), unlike the single-use-key join seal (qspgs-join-kem). */
#define GY_QSPGS_LBL_FIELD "qspgs-field"

/*
 * Join-link key (QSPGS_SPEC.md section 4 item 1, section 5 ToggleJoinLink /
 * JoinViaLink).  The header's optional join slot encrypts (gk, fet)
 * so a link holder can join WITHOUT already knowing gk; it is therefore keyed
 * NOT by ek (which needs gk) but by a join-link key jlk = HKDF(join-link
 * secret), the secret being shared out of band via the link.  The sealed slot
 * still uses the ek-field format (nonce || ct || tag, GY_QSPGS_FIELD_JOINSLOT
 * tag, GID in the AAD); only the key differs.  Rotating the link (or
 * RemoveMember's gk rotation) invalidates an old slot. */
#define GY_QSPGS_LBL_JOINLINK "qspgs-joinlink"

#endif /* GY_QSPGS_LABELS_H */
