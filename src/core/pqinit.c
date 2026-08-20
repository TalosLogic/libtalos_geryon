/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdlib.h>

#include <oqs/oqs.h>

#include "error.h"
#include "pqinit.h"
#include "rng.h"

/*
 * liboqs pin assert (D-PQ-2 / D-GEN-5): geryon's ML-KEM / ML-DSA wrappers are
 * verified against the API and behaviour of exactly one liboqs release.  A
 * submodule bump must be a deliberate event (re-run the ACVP suites), so drift
 * FAILS THE BUILD here rather than surfacing as a test failure later.  The
 * check is compile-time against the version macros liboqs installs in
 * oqs/oqsconfig.h; OQS_version() is the runtime counterpart but cannot fail a
 * build, which is the property this ticket requires.
 */
_Static_assert(
    OQS_VERSION_MAJOR == 0 && OQS_VERSION_MINOR == 16 && OQS_VERSION_PATCH == 0,
    "liboqs pin drift: geryon requires liboqs 0.16.0 (D-GEN-5 / D-PQ-2)");

/*
 * liboqs random-byte source.  The callback returns void, so a failing RNG
 * cannot be signalled through it: rather than let liboqs proceed over an
 * unfilled buffer (predictable keys / signatures), the shim ABORTS.  gy_random_
 * bytes is backed by libsodium's randombytes_buf, which itself aborts the
 * process on a getrandom failure, so this path is belt-and-suspenders; the
 * death test (D-PQ-2) drives it via the same hook the D-PQ-3 KAT shim uses.
 *
 * A zero-length request is a no-op success: liboqs may legitimately ask for 0
 * bytes, and gy_random_bytes rejects n == 0 as an argument error.
 */
#ifdef GY_TEST_HOOKS
static size_t gy_pq_rng_draws;
static int gy_pq_rng_force_fail;

size_t
gy_pq_rng_draw_count(void)
{
    return gy_pq_rng_draws;
}

void
gy_pq_rng_reset_draw_count(void)
{
    gy_pq_rng_draws = 0;
}

void
gy_pq_rng_set_force_fail(int on)
{
    gy_pq_rng_force_fail = on;
}
#endif /* GY_TEST_HOOKS */

static void
gy_pq_rng_shim(uint8_t *out, size_t n)
{
    if (n == 0)
        return;
#ifdef GY_TEST_HOOKS
    gy_pq_rng_draws += n;
    if (gy_pq_rng_force_fail)
        abort();
#endif
    if (out == NULL || gy_random_bytes(out, n) != GY_OK)
        abort();
}

int
gy_pq_init(void)
{
    /*
     * Sets a process-global pointer; idempotent, so a second gy_core_init()
     * call simply re-points it at the same shim (init test asserts this).
     */
    OQS_randombytes_custom_algorithm(gy_pq_rng_shim);
    return GY_OK;
}
