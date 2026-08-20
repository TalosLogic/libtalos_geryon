/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_MLKEM_H
#define GY_MLKEM_H

#include <stddef.h>
#include <stdint.h>

/*
 * ML-KEM-512 (FIPS 203) thin wrapper over liboqs' direct, allocation-free
 * per-algorithm entry points (OQS_KEM_ml_kem_512_*, D-PQ-2/3).  This is a
 * library-first wrapper in the sense of x25519.c: geryon implements no KEM
 * arithmetic, only the GY_OK/GY_ERR_* contract, output zeroization on failure,
 * and the FIPS 203 implicit-rejection guarantee at the boundary.  Callers must
 * have completed gy_core_init() (which registers the RNG liboqs draws through,
 * D-PQ-2).
 *
 * The h25519_512 suite uses ML-KEM-512; the 448 tier uses ML-KEM-1024 and gets
 * its own wrapper.  Sizes are exposed as macros for stack buffers here; the
 * kex/ratchet layers size against the suite-descriptor kem_* fields (D-GEN-7),
 * never these macros directly.
 */

#define GY_MLKEM512_PK 800  /* encapsulation key (public) */
#define GY_MLKEM512_SK 1632 /* decapsulation key (secret) */
#define GY_MLKEM512_CT 768  /* ciphertext */
#define GY_MLKEM512_SS 32   /* shared secret */

/*
 * Generate an ML-KEM-512 keypair.  pk is public, sk is secret; sk is zeroized
 * if the underlying provider fails.  Signature matches the suite descriptor's
 * kem_keypair slot.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_mlkem_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Encapsulate to pk, writing the ciphertext ct and the shared secret ss.  ss is
 * zeroized on failure.  Matches the kem_encap slot.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_mlkem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/*
 * Decapsulate ct under sk, writing the shared secret ss.  Preserves FIPS 203
 * implicit rejection EXACTLY: a corrupt or forged ct does NOT produce an error;
 * it yields GY_OK with a deterministic pseudorandom ss, so no decapsulation
 * oracle exists.  The ONLY failure paths are provider/argument errors, never a
 * decrypt-failure signal.  ss is zeroized on the error paths.  Matches the
 * kem_decap slot.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#ifdef GY_TEST_HOOKS
/*
 * Derandomized seams for FIPS 203 ACVP known-answer tests ONLY (D-PQ-3),
 * compiled solely under GY_TEST_HOOKS so no test-only symbol has unconditional
 * external linkage (the M0-L3 lesson).  Production code must use the randomized
 * entry points above.  keypair takes a 64-byte d||z seed; encaps takes a
 * 32-byte m.  Decaps needs no seam (it is deterministic; ACVP decaps VAL cases,
 * including implicit rejection, run the production path unchanged).
 */
#define GY_MLKEM512_KEYPAIR_SEED 64
#define GY_MLKEM512_ENCAPS_SEED 32

int gy_mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
int gy_mlkem_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *seed);
#endif /* GY_TEST_HOOKS */

#endif /* GY_MLKEM_H */
