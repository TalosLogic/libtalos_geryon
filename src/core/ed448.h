/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_ED448_H
#define GY_ED448_H

#include <stddef.h>
#include <stdint.h>

/*
 * XEd448, clean-room from the XEdDSA specification (Revision 1) section 6 and
 * decisions D-XED-8/9/12/13.  Route = birational-direct (D-XED-13 R1): sign and
 * verify are a spec composition over an in-house constant-time twisted-Edwards
 * (a = 1) point layer on the curve birationally equivalent to Curve448
 * (d = 39082/39081 mod p), built over libdecaf's INTERNAL gf field arithmetic,
 * libdecaf's public decaf_448 scalar ring (same group order q as XEd448), and
 * the RFC 7748 X448 ladder.  Nothing is delegated to libdecaf's RFC 8032 Ed448
 * (decaf_ed448_sign/verify), which is a different scheme on the 4-isogenous
 * Goldilocks curve (the D-XED-9 no-library-calls-Ed448 rule).  Hashing is
 * SHA-512 via core/hash.c, never libdecaf's SHAKE.  Keys are 56-byte Montgomery
 * (X448) values; encoded points and integers are 57 bytes and signatures are
 * 114 bytes (D-XED-8).  Callers must have completed gy_core_init().
 */

/*
 * Maximum signable message length (D-XED-7): XEdDSA does not pre-hash, so the
 * message is bounded.  Longer messages are rejected with GY_ERR_TOOLONG.
 */
#define GY_XED448_MAX_MSG 8192

/* Encoded-signature length (R || s), 2b = 114 bytes (D-XED-8). */
#define GY_XED448_SIG_BYTES 114

/* Encoded Edwards point / public-key length, b = 57 bytes (D-XED-8). */
#define GY_XED448_POINT_BYTES 57

/*
 * Derive the XEd448 public key A (57-byte Edwards encoding with sign bit forced
 * to 0) and the matching signing scalar a (57-byte little-endian encoding; the
 * 56 scalar bytes followed by a zero byte) from a clamped Montgomery private
 * key mont_sk, per D-XED-13 R4.  scalar_a is SECRET; ed_pk is public.  Exposed
 * for tests (the sign-path-A vs verify-path-A cross-check) and internal use.
 * Returns GY_OK or a negative GY_ERR_*; scalar_a is zeroized on failure.
 */
int gy_xed448_calculate_key_pair(uint8_t ed_pk[57], uint8_t scalar_a[57],
                                 const uint8_t mont_sk[56]);

/*
 * Map a Montgomery public key mont_pk (X448 u-coordinate, 56 bytes) to the
 * XEd448 Edwards public key A (57-byte encoding, sign bit 0) via
 * u_to_y(u) = (u + 1) * inv(u - 1) on the birational curve (the X448-compatible
 * orientation; D-XED-8 CORRECTION 2026-08-20, D-XED-13 R5).
 * Rejects a non-canonical u (u >= p) with GY_ERR_VERIFY.  This is the verify
 * path's A derivation; exposed for the cross-check test.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_xed448_mont_to_ed(uint8_t ed_pk[57], const uint8_t mont_pk[56]);

/*
 * Sign msg[0..msg_len) under the clamped Montgomery private key mont_sk,
 * writing a 114-byte signature (R || s).  Fresh 64-byte randomness Z is drawn
 * internally.  msg_len > GY_XED448_MAX_MSG returns GY_ERR_TOOLONG.  All secret
 * intermediates are zeroized on every path.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
int gy_xed448_sign(uint8_t sig[114], const uint8_t mont_sk[56],
                   const uint8_t *msg, size_t msg_len);

#ifdef GY_TEST_HOOKS
/*
 * Deterministic core of gy_xed448_sign taking the nonce Z explicitly.  Exposed
 * for known-answer tests ONLY and compiled solely under GY_TEST_HOOKS (the
 * M0-L3 lesson: the 25519 tier's unconditional gy_xeddsa_sign_z is NOT repeated
 * here).  Production code must use gy_xed448_sign so Z is unpredictable.
 */
int gy_xed448_sign_z(uint8_t sig[114], const uint8_t mont_sk[56],
                     const uint8_t *msg, size_t msg_len, const uint8_t z[64]);
#endif /* GY_TEST_HOOKS */

/*
 * Verify a 114-byte XEd448 signature (R || s) over msg under the Montgomery
 * public key mont_pk.  Per D-XED-13 R5 the u-coordinate is checked canonical
 * (u < p), mapped to the Edwards key A (sign 0), s is checked canonical
 * (s < q, top byte 0) BEFORE any scalar multiplication (D-XED-5 malleability
 * strictness), and acceptance is the constant-time byte-compare of the encoded
 * R_check = sB - hA against R (the cofactor-less strict compare of XEdDSA
 * section 3).  Returns GY_OK if valid, GY_ERR_VERIFY if not, GY_ERR_TOOLONG if
 * msg_len exceeds the bound.
 */
int gy_xed448_verify(const uint8_t sig[114], const uint8_t mont_pk[56],
                     const uint8_t *msg, size_t msg_len);

#endif /* GY_ED448_H */
