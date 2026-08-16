/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_RNG_H
#define GY_RNG_H

#include <stddef.h>
#include <stdint.h>

/*
 * Random byte generation, backed unconditionally by libsodium's
 * randombytes_buf (getrandom(2)-backed on Linux; D-XED-1).  geryon's RNG is
 * NOT pluggable: there is deliberately no application-supplied RNG hook,
 * since such a hook is an injection surface for a broken or malicious
 * generator.  All key and nonce material comes through this one path.
 */

/*
 * Fill out[0..n) with cryptographically secure random bytes.  Returns GY_OK
 * on success, GY_ERR_ARG if out is NULL or n is 0.  The caller must have
 * already completed gy_core_init(); this is a documented precondition and is
 * not re-checked at runtime.
 */
int gy_random_bytes(uint8_t *out, size_t n);

#endif /* GY_RNG_H */
