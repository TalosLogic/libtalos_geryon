/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_HASH_H
#define GY_HASH_H

#include <stddef.h>
#include <stdint.h>

#include <sodium.h>

/*
 * SHA-2, HMAC, and HKDF, all thin wrappers over libsodium (D-X3DH-7).  The
 * incremental state types alias the libsodium states directly; callers treat
 * them as opaque.  sodium.h is pulled in here only for those state types.
 * Every function returns GY_OK or a negative GY_ERR_*; the crypto itself does
 * not fail, so errors are argument or length-bound violations.
 */

/* One-shot digests. */
int gy_sha256(uint8_t out[32], const uint8_t *in, size_t len);
int gy_sha512(uint8_t out[64], const uint8_t *in, size_t len);

/*
 * Incremental digests, so XEdDSA can hash prefix || a || M || Z without a
 * concatenation buffer.  gy_*_final zeroizes the state before returning.
 */
typedef crypto_hash_sha256_state gy_sha256_state;
typedef crypto_hash_sha512_state gy_sha512_state;

int gy_sha256_init(gy_sha256_state *st);
int gy_sha256_update(gy_sha256_state *st, const uint8_t *in, size_t len);
int gy_sha256_final(gy_sha256_state *st, uint8_t out[32]);

int gy_sha512_init(gy_sha512_state *st);
int gy_sha512_update(gy_sha512_state *st, const uint8_t *in, size_t len);
int gy_sha512_final(gy_sha512_state *st, uint8_t out[64]);

/*
 * HMAC over an arbitrary-length key (the init/update/final wrappers below
 * handle keys longer than the block size per RFC 2104).
 */
int gy_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t klen,
                   const uint8_t *in, size_t inlen);
int gy_hmac_sha512(uint8_t out[64], const uint8_t *key, size_t klen,
                   const uint8_t *in, size_t inlen);

/*
 * Scatter/gather HMAC and HKDF-Extract (D-X3DH-7): the message / IKM is
 * supplied as an array of gy_iov elements fed to the underlying incremental
 * API one at a time, so no concatenation buffer is ever built.  The result is
 * byte-identical to the flat wrappers run over the concatenation of the
 * elements; the flat wrappers remain as the single-input case.  gy_iov is
 * forward-declared here (defined in suite.h); these take only a pointer to it.
 */
struct gy_iov;
int gy_hmac_sha256_iov(uint8_t out[32], const uint8_t *key, size_t klen,
                       const struct gy_iov *iov, size_t niov);
int gy_hmac_sha512_iov(uint8_t out[64], const uint8_t *key, size_t klen,
                       const struct gy_iov *iov, size_t niov);
int gy_hkdf_sha256_extract_iov(uint8_t prk[32], const uint8_t *salt,
                               size_t slen, const struct gy_iov *iov,
                               size_t niov);
int gy_hkdf_sha512_extract_iov(uint8_t prk[64], const uint8_t *salt,
                               size_t slen, const struct gy_iov *iov,
                               size_t niov);

/*
 * HKDF (RFC 5869).  The PRK is 32 bytes for SHA-256 and 64 for SHA-512.
 * Expand enforces the RFC 5869 output bound of 255 * HashLen and rejects a
 * longer request with GY_ERR_ARG.  A NULL salt/info with length 0 is allowed.
 */
int gy_hkdf_sha256_extract(uint8_t prk[32], const uint8_t *salt, size_t slen,
                           const uint8_t *ikm, size_t ilen);
int gy_hkdf_sha256_expand(uint8_t *out, size_t outlen, const uint8_t prk[32],
                          const uint8_t *info, size_t infolen);
int gy_hkdf_sha512_extract(uint8_t prk[64], const uint8_t *salt, size_t slen,
                           const uint8_t *ikm, size_t ilen);
int gy_hkdf_sha512_expand(uint8_t *out, size_t outlen, const uint8_t prk[64],
                          const uint8_t *info, size_t infolen);

#endif /* GY_HASH_H */
