/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * X448 validation gate, iterated X448 vectors (RFC 7748 section 5.2,
 * "After 1,000 iterations"). Carries the `slow` CTest label. Vectors from
 * RFC 7748. The 1,000,000-iteration vector is
 * deliberately not run (cost); 1,000 exercises the same code path.
 *
 * Procedure (RFC 7748): set k = u = the base u-coordinate (5); then repeatedly
 * set (k, u) = (X448(k, u), k). X448(k, u) is decaf_x448(out, u, k): base is
 * the u-coordinate, scalar is k. decaf_error_t: DECAF_SUCCESS == -1.
 */

#include <stdint.h>
#include <string.h>

#include <decaf.h>

#include "gy_test.h"

static void
x448_iterate(uint8_t k[56], unsigned iterations)
{
    uint8_t u[56], r[56], oldk[56];
    unsigned i;

    memset(u, 0, 56);
    u[0] = 5;
    memset(k, 0, 56);
    k[0] = 5;

    for (i = 0; i < iterations; i++) {
        ASSERT_EQ(decaf_x448(r, u, k), DECAF_SUCCESS);
        memcpy(oldk, k, 56);
        memcpy(k, r, 56);
        memcpy(u, oldk, 56);
    }
}

TEST(rfc7748_x448_iterated_1)
{
    uint8_t k[56], want[56];

    (void)gy_hex_decode(
        want, 56,
        "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a"
        "4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
    x448_iterate(k, 1);
    ASSERT_MEMEQ(k, want, 56);
}

TEST(rfc7748_x448_iterated_1000)
{
    uint8_t k[56], want[56];

    (void)gy_hex_decode(
        want, 56,
        "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4"
        "af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");
    x448_iterate(k, 1000);
    ASSERT_MEMEQ(k, want, 56);
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(rfc7748_x448_iterated_1),
        GY_TEST(rfc7748_x448_iterated_1000),
    };
    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
