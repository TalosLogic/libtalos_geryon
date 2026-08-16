/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_HE_H
#define GY_HE_H

#include <stddef.h>
#include <stdint.h>

#include "kex.h"

/*
 * Header AEAD primitive pair (D-DR-15),
 * self-contained over a caller-owned header key hk.  No ratchet state lives
 * here; wiring hk/nhk into the DR state machine and the D-DR-16 wire frame is
 * the job of double_ratchet.c.
 *
 * Per header a fresh 16-byte hdr_salt is drawn and transmitted in the clear;
 * the header AEAD key and nonce are derived, never hk itself:
 *
 *   key || nonce = KDF-CTR(K_in = hk, Label = INFO("he.aead"),
 *                          Context = aead_id || hdr_salt,
 *                          L = 32 + nonce_len(aead_id))
 *
 * The AEAD associated data is the message's outer version || suite_id pair, so
 * cross-version and cross-suite header confusion is a cryptographic failure,
 * not merely a parse rejection.  Derived key/nonce material is zeroized on
 * every path; hk is caller-owned and never keys the AEAD directly.
 */

/* Transmitted header salt length (D-DR-15). */
#define GY_HE_SALT_LEN 16

/*
 * HENCRYPT: draw hdr_salt, derive key||nonce from hk, and seal header[0..hlen)
 * into out_enc (capacity cap; needs hlen + tag_len(aead_id) bytes), writing
 * the salt into out_salt[16] and the enc_header length into *out_len.  ad2 is
 * the outer version || suite_id bytes.  On any failure the derived material is
 * zeroized and neither out_salt nor *out_len is written (wipe-on-fail).
 * Returns GY_OK, GY_ERR_ARG on a NULL argument or short buffer, or
 * GY_ERR_UNSUPPORTED for an unknown/unavailable aead_id.
 */
int gy_he_encrypt(const struct gy_suite_desc *desc, uint8_t aead_id,
                  const uint8_t hk[32], const uint8_t *header, size_t hlen,
                  const uint8_t ad2[2], uint8_t out_salt[16], uint8_t *out_enc,
                  size_t cap, size_t *out_len);

/*
 * HDECRYPT: derive key||nonce from (hk, salt) and open enc[0..elen) into
 * out_header (capacity cap), writing the header length into *out_len.  ad2 is
 * the outer version || suite_id bytes.  A tag mismatch (or a ciphertext too
 * short to hold a tag) returns GY_ERR_VERIFY and releases no plaintext (the
 * underlying AEAD zeroes out_header rather than leaving it untouched); the
 * derived material is zeroized on every path.  Returns GY_OK, GY_ERR_ARG,
 * GY_ERR_UNSUPPORTED, or GY_ERR_VERIFY.
 */
int gy_he_decrypt(const struct gy_suite_desc *desc, uint8_t aead_id,
                  const uint8_t hk[32], const uint8_t salt[16],
                  const uint8_t *enc, size_t elen, const uint8_t ad2[2],
                  uint8_t *out_header, size_t cap, size_t *out_len);

#ifdef GY_TEST_HOOKS
/*
 * Test seam: when set, hdr_salt generation calls this instead of
 * gy_random_bytes, so the round-trip and pinned-ciphertext KATs can inject a
 * fixed salt (same pattern as the ratchet-keypair seam).  Set to NULL
 * to restore production behavior.
 */
extern int (*gy_he_test_salt)(uint8_t *out, size_t n);

/*
 * Expose the key||nonce derivation for the D-DR-15 layout KAT and the Context
 * separation KAT (differing key||nonce across aead_ids for one (hk, salt)).
 * out_nonce holds up to GY_AEAD_MAX_NONCE bytes; *nonce_len is the actual.
 */
int gy_he_derive(const struct gy_suite_desc *desc, uint8_t aead_id,
                 const uint8_t hk[32], const uint8_t salt[16], uint8_t *key,
                 uint8_t *nonce, size_t *nonce_len);
#endif

#endif /* GY_HE_H */
