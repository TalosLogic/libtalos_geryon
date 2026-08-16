/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_ED25519_H
#define GY_ED25519_H

#include <stddef.h>
#include <stdint.h>

/*
 * XEdDSA over Curve25519, clean-room from the XEdDSA specification
 * (Revision 1) sections 2.3 and 3, and decisions D-XED-4/5/6/7.  Signatures
 * are a composition over libsodium's Ed25519 scalar/point primitives; per
 * D-XED-5 the sign path derives the key pair directly in Edwards form, so it
 * performs NO Montgomery-to-Edwards conversion (that map is used only on the
 * verify path).  Callers must have completed gy_core_init().
 */

/*
 * Maximum signable message length (D-XED-7): XEdDSA does not pre-hash, so the
 * message is bounded.  Longer messages are rejected with GY_ERR_TOOLONG.
 */
#define GY_XEDDSA_MAX_MSG 8192

/*
 * Derive the Ed25519 public key (with sign bit forced to 0) and the matching
 * signing scalar a from a clamped Montgomery private key mont_sk, per
 * D-XED-5/6.  The sign bit of kB is handled with a constant-time conditional
 * move (no branch on secret data).  scalar_a is secret; ed_pk is public.
 * Exposed for tests and internal use.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_xeddsa_calculate_key_pair(uint8_t ed_pk[32], uint8_t scalar_a[32],
                                 const uint8_t mont_sk[32]);

/*
 * Sign msg[0..msg_len) under the clamped Montgomery private key mont_sk,
 * writing a 64-byte signature (R || s).  Fresh 64-byte randomness Z is drawn
 * internally.  msg_len > GY_XEDDSA_MAX_MSG returns GY_ERR_TOOLONG.  All secret
 * intermediates are zeroized on every path.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
int gy_xeddsa_sign(uint8_t sig[64], const uint8_t mont_sk[32],
                   const uint8_t *msg, size_t msg_len);

/*
 * Deterministic core of gy_xeddsa_sign taking the nonce Z explicitly.  Exposed
 * for known-answer tests ONLY; production code must use gy_xeddsa_sign so Z is
 * unpredictable.
 */
int gy_xeddsa_sign_z(uint8_t sig[64], const uint8_t mont_sk[32],
                     const uint8_t *msg, size_t msg_len, const uint8_t z[64]);

/*
 * Verify a 64-byte XEdDSA signature (R || s) over msg under the Montgomery
 * public key mont_pk.  Per D-XED-5 the u-coordinate is checked to be canonical
 * (u < p = 2^255 - 19), converted to an Edwards key via the birational map,
 * then handed to libsodium's Ed25519 verify, inheriting its stricter-than-spec
 * checks (canonical s < L, small-order/identity A rejection).  Returns GY_OK
 * if valid, GY_ERR_VERIFY if not, GY_ERR_TOOLONG if msg_len exceeds the bound.
 */
int gy_xeddsa_verify(const uint8_t sig[64], const uint8_t mont_pk[32],
                     const uint8_t *msg, size_t msg_len);

#endif /* GY_ED25519_H */
