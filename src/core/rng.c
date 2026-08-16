/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <sodium.h>

#include "error.h"
#include "rng.h"

int
gy_random_bytes(uint8_t *out, size_t n)
{
    if (out == NULL || n == 0)
        return GY_ERR_ARG;

    /*
     * randombytes_buf cannot fail: on a getrandom-backed system it either
     * returns entropy or the process aborts.  The gy_core_init precondition
     * is documented in rng.h and not re-checked here.
     */
    randombytes_buf(out, n);
    return GY_OK;
}
