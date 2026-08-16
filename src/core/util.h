/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_UTIL_H
#define GY_UTIL_H

#include <stddef.h>

/*
 * Small constant-time and lifecycle helpers over libsodium.  Callers must
 * have completed gy_core_init() before using any other geryon function.
 */

/*
 * Initialize the crypto backend (wraps sodium_init()).  Idempotent and
 * thread-safe per libsodium: safe to call repeatedly and from multiple
 * threads.  Returns GY_OK on success or if already initialized, GY_ERR_CRYPTO
 * on failure.  Every other module assumes this has succeeded.
 */
int gy_core_init(void);

/*
 * Overwrite n bytes at p with zero (wraps sodium_memzero).  Constant-time
 * and not elided by the optimizer even when p is dead afterward, which is
 * why plain memset must not be used to erase key material.
 */
void gy_secure_zero(void *p, size_t n);

/*
 * Compare n bytes of a and b in constant time (wraps sodium_memcmp).
 * Returns 0 when the buffers are equal, nonzero otherwise.  This is an
 * equality test only: the sign and magnitude carry no ordering information.
 * Use this, never memcmp, for any comparison over secret bytes.
 */
int gy_const_memcmp(const void *a, const void *b, size_t n);

/*
 * Test whether all n bytes at p are zero, in constant time (wraps
 * sodium_is_zero).  Returns 1 if every byte is zero, 0 otherwise.  Timing
 * does not depend on where a nonzero byte occurs.
 */
int gy_is_zero(const void *p, size_t n);

/*
 * Allocate n bytes of guarded memory (wraps sodium_malloc: guard pages plus
 * an implicit mlock), for key material that must live outside the ordinary
 * heap (CUSTODY_SPEC section 15).  Returns NULL on failure (out of memory or
 * n == 0); the caller must release it with gy_secure_free, never plain
 * free().
 */
void *gy_secure_alloc(size_t n);

/*
 * Release memory allocated by gy_secure_alloc (wraps sodium_free, which
 * zeroizes the region before releasing its guard pages).  Safe on NULL
 * (no-op).
 */
void gy_secure_free(void *p);

#endif /* GY_UTIL_H */
