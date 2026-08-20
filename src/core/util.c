/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <sodium.h>

#include "error.h"
#include "pqinit.h"
#include "util.h"

int
gy_core_init(void)
{
    int rc;

    /*
     * sodium_init() returns 0 on first success, 1 if already initialized
     * (both fine), and -1 on failure.
     */
    if (sodium_init() < 0)
        return GY_ERR_CRYPTO;

    /*
     * Point liboqs at geryon's RNG before any PQ primitive can run (D-PQ-2).
     * Ordering matters: this must precede the first keypair/encaps/sign call,
     * so it lives in the one mandatory init entry point.
     */
    if ((rc = gy_pq_init()) != GY_OK)
        return rc;

    return GY_OK;
}

void
gy_secure_zero(void *p, size_t n)
{
    sodium_memzero(p, n);
}

int
gy_const_memcmp(const void *a, const void *b, size_t n)
{
    return sodium_memcmp(a, b, n);
}

int
gy_is_zero(const void *p, size_t n)
{
    return sodium_is_zero(p, n);
}

void *
gy_secure_alloc(size_t n)
{
    return sodium_malloc(n);
}

void
gy_secure_free(void *p)
{
    sodium_free(p);
}
