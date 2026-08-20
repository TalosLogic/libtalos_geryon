/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_MLDSA_H
#define GY_MLDSA_H

#include <stddef.h>
#include <stdint.h>

/*
 * ML-DSA-44 (FIPS 204) thin wrapper over liboqs' direct, allocation-free
 * per-algorithm entry points (OQS_SIG_ml_dsa_44_*, D-PQ-1/2).  Like ed25519.c,
 * this is a library-first wrapper: geryon implements no signature arithmetic,
 * only the GY_OK/GY_ERR_* contract and secret zeroization.  Callers must have
 * completed gy_core_init() (which registers the RNG hedged signing draws
 * through, D-PQ-2).
 *
 * Signing is HEDGED (FIPS 204 default: fresh randomness per signature, D-PQ-1);
 * there is deliberately no deterministic mode.  The context string is a
 * PARAMETER (D-PQ-1): the wrapper knows no protocol strings; kex/prekeys.c
 * passes INFO("prekey").  Signing and verification always go through the
 * with_ctx_str entry points, never the bare ones.
 *
 * The h25519_512 suite uses ML-DSA-44; the 448 tier uses ML-DSA-87 and gets its
 * own wrapper.  Sizes are exposed for stack buffers; the kex/ratchet layers
 * size against the suite-descriptor dsa_* fields (D-GEN-7), never these macros.
 */

#define GY_MLDSA44_PK 1312  /* public (verifying) key */
#define GY_MLDSA44_SK 2560  /* secret (signing) key */
#define GY_MLDSA44_SIG 2420 /* signature (fixed length) */

/* FIPS 204 caps the context string at 255 bytes. */
#define GY_MLDSA_CTX_MAX 255

/*
 * Generate an ML-DSA-44 keypair.  pk is public, sk is secret; sk is zeroized if
 * the provider fails.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_mldsa_keypair(uint8_t *pk, uint8_t *sk);

/*
 * Sign msg[0..mlen) under sk with context ctx[0..ctxlen), writing the 2420-byte
 * signature to sig.  ctx may be NULL only when ctxlen is 0; ctxlen > 255 is
 * GY_ERR_TOOLONG.  Hedged: fresh randomness is drawn internally.  sig is
 * zeroized on failure.  Returns GY_OK or a negative GY_ERR_*.  Argument order
 * follows the library sign convention (sig, key, msg, msg_len, ...), matching
 * gy_xeddsa_sign and the descriptor sign/dsa_sign slots.
 */
int gy_mldsa_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg,
                  size_t mlen, const uint8_t *ctx, size_t ctxlen);

/*
 * Verify the 2420-byte signature sig over msg[0..mlen) under pk with context
 * ctx[0..ctxlen).  Returns GY_OK if valid, GY_ERR_VERIFY if not, GY_ERR_TOOLONG
 * if ctxlen > 255, GY_ERR_ARG on a NULL argument.  A ctx mismatch (including
 * empty vs nonempty) is a verification failure, which is how D-PQ-1 makes the
 * context load-bearing.
 */
int gy_mldsa_verify(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg,
                    size_t mlen, const uint8_t *ctx, size_t ctxlen);

#endif /* GY_MLDSA_H */
