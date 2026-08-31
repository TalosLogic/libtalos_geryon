/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_X448_H
#define GY_X448_H

#include <stdint.h>

/*
 * X448 key generation and Diffie-Hellman over libdecaf (RFC 7748), the 448-tier
 * analog of x25519.c (D-XED-9/12).  Keys and shared secrets are 56 bytes.
 * Callers must have completed gy_core_init().
 */

/*
 * Generate an X448 key pair.  Per D-XED-10/12 the 56-byte private scalar is
 * drawn from the RNG and the RFC 7748 X448 clamp is applied at generation time
 * (k[0] &= 252; k[55] |= 128), so sk is stored ALREADY CLAMPED; every later use
 * can assume that invariant.  pk is the corresponding public key.  Returns
 * GY_OK, or a negative GY_ERR_* (sk is zeroized on failure).
 */
int gy_x448_keypair(uint8_t pk[56], uint8_t sk[56]);

/*
 * Compute the X448 shared secret out = sk * peer_pk.  An all-zero result
 * (a small-order or otherwise degenerate peer key) is rejected with
 * GY_ERR_WEAK_KEY and out is zeroized (D-X3DH-8).  The all-zero check is done
 * here unconditionally, so the invariant does not rely on the provider also
 * checking.  Returns GY_OK on success.
 */
int gy_x448(uint8_t out[56], const uint8_t sk[56], const uint8_t peer_pk[56]);

#endif /* GY_X448_H */
