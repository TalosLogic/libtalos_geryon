/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_PWHASH_H
#define GY_PWHASH_H

#include <stddef.h>
#include <stdint.h>

/*
 * Argon2id password hashing, a thin wrapper over libsodium crypto_pwhash
 * (D-CUST-1 item 2: the credential -> PDK tier of the custody envelope).
 * Callers must have completed gy_core_init().
 */

#define GY_PWHASH_SALT_LEN 16 /* crypto_pwhash_argon2id_SALTBYTES. */

/*
 * Compiled-in cost bounds (D-CUST-1 item 2, CUSTODY_SPEC section 7): a
 * running custodian cannot be created or opened outside this range, even if
 * the caller (or a stored parameter loaded from a blob) asks for less or
 * more.  The floor is libsodium's "moderate" Argon2id tier, a deliberate
 * step above "interactive" for at-rest credential material; the ceiling is
 * the "sensitive" tier, a defensive bound against a corrupted or tampered
 * stored memlimit driving unbounded allocation on unwrap.
 */
#define GY_PWHASH_OPSLIMIT_MIN 3U /* crypto_pwhash_OPSLIMIT_MODERATE. */
#define GY_PWHASH_OPSLIMIT_MAX 4U /* crypto_pwhash_OPSLIMIT_SENSITIVE. */
#define GY_PWHASH_MEMLIMIT_MIN 268435456U  /* MEMLIMIT_MODERATE, 256 MiB. */
#define GY_PWHASH_MEMLIMIT_MAX 1073741824U /* MEMLIMIT_SENSITIVE, 1 GiB. */

/*
 * Derive outlen bytes of key material from a credential under Argon2id.
 * salt must be GY_PWHASH_SALT_LEN bytes, generated once (gy_random_bytes) at
 * create time and stored beside opslimit/memlimit so the same output can be
 * re-derived on open.  opslimit must be within
 * [GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_OPSLIMIT_MAX] and memlimit within
 * [GY_PWHASH_MEMLIMIT_MIN, GY_PWHASH_MEMLIMIT_MAX]; a value outside its range
 * is rejected with GY_ERR_ARG rather than clamped, so a caller's stored
 * parameters always match what was actually used.  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_pwhash_derive(uint8_t *out, size_t outlen, const uint8_t *cred,
                     size_t credlen, const uint8_t salt[GY_PWHASH_SALT_LEN],
                     uint32_t opslimit, size_t memlimit);

#endif /* GY_PWHASH_H */
