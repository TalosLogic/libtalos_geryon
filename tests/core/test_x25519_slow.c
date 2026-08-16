/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Slow RFC 7748 iterated X25519 test: 1,000,000 iterations.  Registered with
 * the CTest `slow` label and excluded from the default run (ctest -LE slow).
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "x25519.h"
#include "util.h"

#include "gy_test.h"

TEST(rfc7748_iterated_1000000)
{
    uint8_t k[32] = {9};
    uint8_t u[32] = {9};
    uint8_t r[32];
    uint8_t want[32];
    unsigned int i;

    (void)gy_hex_decode(
        want, 32,
        "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424");

    for (i = 0; i < 1000000; i++) {
        ASSERT_EQ(gy_x25519(r, k, u), GY_OK);
        memcpy(u, k, 32);
        memcpy(k, r, 32);
    }
    ASSERT_MEMEQ(k, want, 32);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(rfc7748_iterated_1000000),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
