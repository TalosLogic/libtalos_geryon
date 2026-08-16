/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KDF_H
#define GY_KDF_H

#include <stddef.h>
#include <stdint.h>

#include "suite.h"

/*
 * SP 800-108 KDF in Counter Mode (D-DR-2), generic over the suite descriptor:
 * the PRF is the row's iov HMAC, so the same construction serves SHA-256 and
 * SHA-512 tiers.  Used by KDF_CK (dr.msg / dr.chain) and the per-message AEAD
 * key/nonce derivation (dr.aead) in the ratchet.
 */

/*
 * Raw counter-mode core, EXPOSED FOR TESTS ONLY: computes
 *   K(i) = PRF(key, [i]_32BE || fixed),  i = 1, 2, ...
 * and writes the concatenation of the single-block outputs, truncated to
 * outlen.  `fixed` is an opaque scatter/gather blob prepended with the 32-bit
 * big-endian counter; the NIST CAVP KBKDF vectors supply FixedInputData as
 * exactly such a blob, so this is the form the official vectors validate.
 * Production code calls gy_kdf_ctr instead, which pins the D-DR-2 layout.
 *
 * Returns GY_OK, or GY_ERR_ARG on a NULL argument, outlen 0, or more than
 * GY_KDF_CTR_MAX_FIXED fixed elements.  The output is zeroized on failure.
 */
#define GY_KDF_CTR_MAX_FIXED 7
int gy_kdf_ctr_raw(const struct gy_suite_desc *desc, uint8_t *out,
                   size_t outlen, const uint8_t *key, size_t klen,
                   const struct gy_iov *fixed, size_t nfixed);

/*
 * Counter-mode KDF with the pinned D-DR-2 fixed-input layout
 *   [i]_32BE || Label || 0x00 || Context || [L]_32BE
 * where the counter starts at 1 and L is the output length in BITS.  Label is
 * a gy_info string (D-GEN-3); this function does not build it.  Rejects
 * outlen 0 or outlen > 255 * hash_len with GY_ERR_ARG.  Returns GY_OK on
 * success; the output is zeroized on failure.
 */
int gy_kdf_ctr(const struct gy_suite_desc *desc, uint8_t *out, size_t outlen,
               const uint8_t *key, size_t klen, const uint8_t *label,
               size_t llen, const uint8_t *context, size_t clen);

#endif /* GY_KDF_H */
