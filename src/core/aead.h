/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_AEAD_H
#define GY_AEAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * Authenticated encryption, combined mode (ciphertext || tag), per
 * D-DR-10 (no tag truncation).  All AEADs use a
 * 32-byte key; suite security is set by the key exchange, not the AEAD.
 * ChaCha20-Poly1305 is mandatory-to-implement and the default.  Callers must
 * have completed gy_core_init().
 *
 * The IDs are wire values; keep them exact.
 */
#define GY_AEAD_CHACHA20POLY1305 0x01 /* MTI, default */
#define GY_AEAD_AES256GCM 0x02        /* hardware-gated */
#define GY_AEAD_AEGIS256 0x03

/* Upper bounds across all suites, for caller buffer sizing. */
#define GY_AEAD_KEY_LEN 32
#define GY_AEAD_MAX_NONCE 32
#define GY_AEAD_MAX_TAG 32

/*
 * Whether an AEAD can be used on this build/CPU.  0x02 requires hardware
 * AES-GCM support (libsodium gates it); 0x01 and 0x03 are always available
 * (libsodium's AEGIS-256 has a constant-time software fallback and is not
 * gated).  Returns 1 if available, 0 otherwise (including an unknown ID).
 */
int gy_aead_available(uint8_t aead_id);

/* Nonce length for an AEAD (12/12/32), or 0 for an unknown ID. */
size_t gy_aead_nonce_len(uint8_t aead_id);

/* Authentication tag length for an AEAD (16/16/32), or 0 for unknown. */
size_t gy_aead_tag_len(uint8_t aead_id);

/*
 * Encrypt pt[0..ptlen) under key/nonce with associated data ad, writing
 * ciphertext || tag into ct.  On entry *ctlen is ct's capacity; on success it
 * is set to the bytes written (ptlen + tag_len).  nlen must equal
 * gy_aead_nonce_len(id) exactly.  Requesting AES-256-GCM where unavailable
 * returns GY_ERR_UNSUPPORTED (the library never software-fallbacks GCM; that
 * choice is the caller's, at the algorithm level).  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_aead_encrypt(uint8_t id, uint8_t *ct, size_t *ctlen,
                    const uint8_t key[32], const uint8_t *nonce, size_t nlen,
                    const uint8_t *ad, size_t adlen, const uint8_t *pt,
                    size_t ptlen);

/*
 * Decrypt ct[0..ctlen) (ciphertext || tag) under key/nonce/ad, writing the
 * plaintext into pt.  On entry *ptlen is pt's capacity; on success it is set
 * to the plaintext length (ctlen - tag_len).  A tag mismatch returns
 * GY_ERR_VERIFY and writes no plaintext bytes.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
int gy_aead_decrypt(uint8_t id, uint8_t *pt, size_t *ptlen,
                    const uint8_t key[32], const uint8_t *nonce, size_t nlen,
                    const uint8_t *ad, size_t adlen, const uint8_t *ct,
                    size_t ctlen);

#endif /* GY_AEAD_H */
