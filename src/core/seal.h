/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_SEAL_H
#define GY_SEAL_H

#include <stddef.h>
#include <stdint.h>

/*
 * Self-describing wrap AEAD for at-rest key custody (D-CUST-1 items 4-5).
 * This is a distinct numbering space from the message-layer AEAD IDs in
 * aead.h (D-DR-3 wire values): custody blobs never leave the local store, so
 * nothing here is a wire value.  Blob layout:
 *
 *   version(1) || alg_id(1) || nonce(alg) || ciphertext || tag
 *
 * gy_seal always authenticates version and alg_id as part of the associated
 * data (prepended ahead of the caller's own ad, which typically carries a
 * key id / key type / tier per D-CUST-1 item 5), so a caller cannot forget
 * to bind them and an attacker cannot flip either byte without failing the
 * tag check.  gy_unseal reads alg_id from the blob to select the cipher and
 * never re-detects.  Callers must have completed gy_core_init().
 */

/* alg_id values.  AEGIS-256 is the default; XChaCha20-Poly1305 is available
 * as an explicit caller choice, not an automatic hardware fallback: this
 * project's libsodium has no crypto_aead_aegis256_is_available(), and
 * AEGIS-256 always has a working constant-time software implementation, so
 * there is no hardware-absent condition to detect (D-CUST-1 item 4,
 * corrected 2026-08-11; matches the existing D-DR-3 treatment).
 *
 * Deliberately numbered outside the GY_AEAD_* range (aead.h, 0x01-0x03): a
 * mistaken cross-use of a message-AEAD ID here (or vice versa) must land on
 * GY_ERR_ARG/GY_ERR_VERIFY, never silently select a different-but-valid
 * cipher. */
#define GY_SEAL_ALG_AEGIS256 0x11
#define GY_SEAL_ALG_XCHACHA20POLY1305 0x12

#define GY_SEAL_VERSION 1

#define GY_SEAL_KEY_LEN 32

/* Largest caller-supplied associated data this primitive accepts (beyond the
 * version/alg_id bytes it binds itself): a tag byte, a kind byte, and an
 * application identifier up to GY_USER_ID_MAX/GY_DEVICE_ID_MAX (64 bytes,
 * include/geryon.h), with headroom to spare. */
#define GY_SEAL_MAX_AD 96

/* Upper bound on a blob's fixed overhead, for caller buffer sizing:
 * version(1) + alg_id(1) + the larger nonce(32) + the larger tag(32). */
#define GY_SEAL_MAX_OVERHEAD 66

/*
 * Seal pt[0..ptlen) under key with associated data ad (see GY_SEAL_MAX_AD),
 * using the cipher named by alg_id (GY_SEAL_ALG_*).  Writes
 * version || alg_id || nonce || ciphertext || tag into out; on entry
 * *outlen is out's capacity, on success it is set to the bytes written.
 * The nonce is freshly random per call: both ciphers' nonces (256-bit /
 * 192-bit) are wide enough that random reuse is negligible at keystore
 * volumes.  Returns GY_OK or a negative GY_ERR_*: GY_ERR_ARG for an
 * unrecognized alg_id, a NULL argument, or an undersized output buffer;
 * GY_ERR_TOOLONG if ad exceeds GY_SEAL_MAX_AD.
 */
int gy_seal(uint8_t *out, size_t *outlen, const uint8_t key[GY_SEAL_KEY_LEN],
            uint8_t alg_id, const uint8_t *ad, size_t adlen, const uint8_t *pt,
            size_t ptlen);

/*
 * Open a blob produced by gy_seal.  ad must be the same bytes passed to
 * gy_seal.  On entry *ptlen is pt's capacity; on success it is set to the
 * plaintext length.  A malformed blob (unrecognized version or alg_id, or
 * too short to hold a header and tag) and an authentication failure both
 * return the single GY_ERR_VERIFY: there is no oracle distinguishing a
 * corrupt or tampered blob from a wrong key (CUSTODY_SPEC section 15).
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_unseal(uint8_t *pt, size_t *ptlen, const uint8_t key[GY_SEAL_KEY_LEN],
              const uint8_t *ad, size_t adlen, const uint8_t *blob,
              size_t bloblen);

#endif /* GY_SEAL_H */
