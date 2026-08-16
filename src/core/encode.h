/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_ENCODE_H
#define GY_ENCODE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Wire encoding helpers: big-endian integers, suite/curve constants, the
 * EncodeEC public-key encoding, PKID derivation, top-level framing, and KDF
 * info strings.  Per decision register D-GEN-1 (framing), D-GEN-2 (PKID),
 * D-GEN-3 (info strings), and D-X3DH-1 (EncodeEC).
 *
 * Everything here is public wire structure, not secret material: the byte
 * layouts and the PKID are grindable lookup handles, never security values.
 * Comparisons over PKID against the zero sentinel still use the constant-time
 * helper, because the OPK-presence check that reads it must not branch on it
 * (D-GEN-2).
 */

/*
 * Suite identifiers (D-GEN-1 table).  These
 * are wire values and are ABI-stable.  0x00 is reserved and never a valid
 * suite.  Classical suites take the odd bytes so the tier ordering reads from
 * the identifier.
 */
#define GY_SUITE_C25519 0x01
#define GY_SUITE_H25519_512 0x02
#define GY_SUITE_C448 0x03
#define GY_SUITE_H448_1024 0x04

/*
 * Curve-type bytes (D-X3DH-1).  The value is the encoded curve public-key
 * length in bytes, so the same byte both names the curve and bounds the key.
 */
#define GY_CURVE_TYPE_25519 0x20 /* 32-byte X25519 public key. */
#define GY_CURVE_TYPE_448 0x38   /* 56-byte X448 public key. */

/* The wire protocol version byte that prefixes every top-level frame. */
#define GY_WIRE_VERSION 0x01

/*
 * The suite descriptor (struct gy_suite_desc) and its lookup, gy_suite_desc,
 * live in suite.h: it is the one suite table for the library (D-GEN-7).  The
 * wire-structure helpers below take a bare suite_id and resolve it internally.
 */

/*
 * Big-endian fixed-width integer store/load.  The pointers need not be
 * aligned; every access is byte-by-byte.  The store helpers write exactly
 * 2/4/8 bytes; the load helpers read the same.
 */
void gy_be16_put(uint8_t *out, uint16_t v);
void gy_be32_put(uint8_t *out, uint32_t v);
void gy_be64_put(uint8_t *out, uint64_t v);
uint16_t gy_be16_get(const uint8_t *in);
uint32_t gy_be32_get(const uint8_t *in);
uint64_t gy_be64_get(const uint8_t *in);

/*
 * EncodeEC (D-X3DH-1): write curve_type || pk into out, where the pk length
 * is curve_type (0x20 = 32 bytes, 0x38 = 56 bytes).  The encoded length is
 * 1 + curve_type.  Returns the number of bytes written, or GY_ERR_ARG on an
 * unknown curve_type or if cap is too small.
 */
int gy_encode_ec(uint8_t *out, size_t cap, uint8_t curve_type,
                 const uint8_t *pk);

/*
 * PKID (D-GEN-2): the first 4 bytes of the suite
 * hash over the already-encoded public key, loaded big-endian into *pkid.
 * The suite selects the hash (SHA-256 for 25519, SHA-512 for 448).  Returns
 * GY_ERR_ARG on an unknown suite or NULL argument.  This only computes the
 * value; the regenerate-on-zero rule lives with key generation.
 */
int gy_pkid(uint32_t *pkid, uint8_t suite_id, const uint8_t *encoded_key,
            size_t len);

/*
 * Constant-time "PKID present" test: returns 1 if pkid is nonzero, 0 if it is
 * the reserved zero sentinel (D-GEN-2).  The comparison is against zero bytes
 * with gy_const_memcmp rather than pkid != 0, so OPK-presence detection does
 * not branch on the value.
 */
int gy_pkid_is_present(uint32_t pkid);

/*
 * Framing (D-GEN-1): write the two-byte top-level prefix version || suite_id
 * into out.  Always writes exactly 2 bytes.
 */
void gy_frame_put(uint8_t out[2], uint8_t suite_id);

/*
 * Validate a received top-level frame prefix before any cryptographic
 * processing (D-GEN-1).  Returns GY_OK when buf is at least 2 bytes, the
 * version byte is GY_WIRE_VERSION, and the suite byte equals expected_suite.
 * Distinguishes the failures: GY_ERR_ARG for a short buffer or a version
 * mismatch, GY_ERR_STATE for a suite mismatch (a cross-suite message, which
 * is a downgrade attempt rather than a malformed one).
 */
int gy_frame_check(const uint8_t *buf, size_t len, uint8_t expected_suite);

/*
 * Info string (D-GEN-3): write
 * "geryon" "." "1" "." suite_name "." purpose into out as ASCII with no
 * trailing NUL, storing the byte length in *outlen.  purpose is a
 * NUL-terminated ASCII string from the closed set in section 3.2.  Returns
 * GY_ERR_ARG on an unknown suite or NULL argument, GY_ERR_TOOLONG if the
 * result does not fit in cap.
 */
int gy_info(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
            const char *purpose);

#endif /* GY_ENCODE_H */
