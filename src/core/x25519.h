/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_X25519_H
#define GY_X25519_H

#include <stdint.h>

/*
 * X25519 key generation and Diffie-Hellman over libsodium (RFC 7748).
 * Callers must have completed gy_core_init().
 */

/*
 * Generate an X25519 key pair.  Per D-XED-10 the 32-byte private scalar is
 * drawn from the RNG and the RFC 7748 clamp is applied at generation time, so
 * sk is stored ALREADY CLAMPED; every later use can assume that invariant.
 * pk is the corresponding public key.  Returns GY_OK, or a negative GY_ERR_*
 * (sk is zeroized on failure).
 */
int gy_x25519_keypair(uint8_t pk[32], uint8_t sk[32]);

/*
 * Compute the X25519 shared secret out = sk * peer_pk.  An all-zero result
 * (a small-order or otherwise degenerate peer key) is rejected with
 * GY_ERR_WEAK_KEY and out is zeroized (D-X3DH-8).  The all-zero check is done
 * here unconditionally, so the invariant does not rely on the provider also
 * checking.  Returns GY_OK on success.
 */
int gy_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer_pk[32]);

#endif /* GY_X25519_H */
