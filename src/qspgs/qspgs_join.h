/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_JOIN_H
#define GY_QSPGS_JOIN_H

#include <stddef.h>
#include <stdint.h>

#include "mlkem1024.h" /* the 87-tier sizes set the buffer maxima. */

/*
 * QSPGS join-request keypair and its public-key encryption (QSPGS_SPEC.md
 * section 2.2 (ipk, isk) and section 8, D-QGS-7 / the deferred
 * D-QGS-2 item).  The invite queue holds PKE.Enc_ipk(UID, uk, Sgn(skpers, ...))
 * entries and the JoinViaLink path seals to the same key; per [CFG+] every
 * member holds isk and drains the queue.
 *
 * (ipk, isk) is a single GROUP-WIDE keypair rederived from gk (section 9
 * rederive-only; nothing derived is stored), which is exactly what preserves
 * anonymity: the queue is sealed to one group key and any member can open it,
 * so an inviter never targets a specific approver.  The PKE is the suite KEM
 * hybrid (ECDH + ML-KEM, section 10.1): NO classical-only primitive appears.
 *
 * Quantum cross-leak resistance (qspgs_labels.h): the curve scalar and the
 * ML-KEM keygen seed are two INDEPENDENT domain-separated HKDF branches off gk
 * (labels qspgs-join-ec / qspgs-join-mlkem).  HKDF-Expand is one-way, so a
 * quantum break of one primitive (recovering that secret) reveals neither the
 * PRK nor the other branch: the hybrid guarantee holds at the key level, not
 * just at the per-seal fusion.
 *
 * Serves the HYBRID suites only; every entry rejects a non-hybrid suite
 * (GY_ERR_ARG).  Parallel vertical over geryon_core, like qspgs_keys.
 */

/* Buffer maxima (the 87 tier sets them). */
#define GY_QSPGS_JOIN_CURVE_MAX 56               /* X448 public/secret width. */
#define GY_QSPGS_JOIN_KEM_PK_MAX GY_MLKEM1024_PK /* ML-KEM ek (1568). */
#define GY_QSPGS_JOIN_KEM_SK_MAX GY_MLKEM1024_SK /* ML-KEM dk (3168). */
#define GY_QSPGS_JOIN_KEM_CT_MAX GY_MLKEM1024_CT /* ML-KEM ct (1568). */

/*
 * ipk: the group-wide join public key.  curve_pk / mlkem_ek are the suite's
 * curve and ML-KEM public lengths; suite_id selects them.  Public, but only
 * ever handled by members (never published to non-members): it is derived from
 * gk, which the server never holds.
 */
typedef struct gy_qspgs_join_pk {
    uint8_t suite_id;
    uint8_t curve_pk[GY_QSPGS_JOIN_CURVE_MAX];
    uint8_t mlkem_ek[GY_QSPGS_JOIN_KEM_PK_MAX];
} gy_qspgs_join_pk_t;

/*
 * isk: the group-wide join secret key.  In-memory only, rederived on demand,
 * NEVER serialized (section 9); clear it with gy_qspgs_join_sk_clear.
 */
typedef struct gy_qspgs_join_sk {
    uint8_t suite_id;
    uint8_t curve_sk[GY_QSPGS_JOIN_CURVE_MAX];
    uint8_t mlkem_dk[GY_QSPGS_JOIN_KEM_SK_MAX];
} gy_qspgs_join_sk_t;

/*
 * Derive (ipk, isk) from gk (gy_qspgs_master_key_len(suite_id) bytes).  Both
 * outputs are tagged with suite_id.  Deterministic: the same gk always yields
 * the same pair, so every member reconstructs it.  Returns GY_OK, GY_ERR_ARG on
 * a NULL argument or a non-hybrid suite, or a negative GY_ERR_* from the
 * primitives.  On any failure isk is zeroized.
 */
int gy_qspgs_join_derive(uint8_t suite_id, const uint8_t *gk,
                         gy_qspgs_join_pk_t *ipk, gy_qspgs_join_sk_t *isk);

/* Zeroize a join secret key (idempotent; NULL-safe). */
void gy_qspgs_join_sk_clear(gy_qspgs_join_sk_t *isk);

/*
 * Sealed-ciphertext overhead added to the plaintext length: the ephemeral curve
 * public key, the ML-KEM ciphertext, and the AEAD tag.  Returns 0 for a
 * non-hybrid suite.
 */
size_t gy_qspgs_join_overhead(uint8_t suite_id);

/*
 * Seal pt[0..ptlen) to ipk (KEM-DEM: fresh ephemeral ECDH + one ML-KEM
 * encapsulation to ipk, fused PQ-first into an AEAD key, then AEAD-encrypt).
 * The wire ciphertext is eph_curve_pk || mlkem_ct || (aead ciphertext||tag);
 * the KEM transcript is the AEAD associated data.  Each call draws fresh
 * randomness, so ciphertexts are sender-unlinkable.  On entry *outlen is out's
 * capacity; on success it is set to gy_qspgs_join_overhead(suite) + ptlen.
 * Returns GY_OK, GY_ERR_TOOLONG on a short buffer, GY_ERR_ARG on bad input, or
 * a negative GY_ERR_* from the primitives.
 */
int gy_qspgs_join_seal(const gy_qspgs_join_pk_t *ipk, const uint8_t *pt,
                       size_t ptlen, uint8_t *out, size_t cap, size_t *outlen);

/*
 * Open a ciphertext produced by gy_qspgs_join_seal under isk.  On entry *ptlen
 * is pt's capacity; on success it is set to the recovered plaintext length.
 * A forged or tampered ciphertext returns GY_ERR_VERIFY and writes no plaintext
 * (ML-KEM implicit rejection folds into the AEAD tag check, so there is no
 * decapsulation oracle).  Returns GY_OK, GY_ERR_VERIFY, GY_ERR_TOOLONG on a
 * short input or output buffer, or GY_ERR_ARG on bad input.
 */
int gy_qspgs_join_open(const gy_qspgs_join_sk_t *isk, const uint8_t *in,
                       size_t inlen, uint8_t *pt, size_t cap, size_t *ptlen);

#endif /* GY_QSPGS_JOIN_H */
