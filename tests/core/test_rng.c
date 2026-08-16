/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/rng.c.  These are sanity checks only: the real
 * assurance for the generator is libsodium's, not ours.
 */

#include <stdint.h>

#include "error.h"
#include "rng.h"
#include "util.h"

#include "gy_test.h"

TEST(random_bytes_differ_and_nonzero)
{
    uint8_t a[64];
    uint8_t b[64];

    ASSERT_EQ(gy_core_init(), GY_OK);

    ASSERT_EQ(gy_random_bytes(a, sizeof(a)), GY_OK);
    ASSERT_EQ(gy_random_bytes(b, sizeof(b)), GY_OK);

    /* Two independent draws must not collide, and neither is all-zero. */
    ASSERT_TRUE(gy_const_memcmp(a, b, sizeof(a)) != 0, "two draws differ");
    ASSERT_EQ(gy_is_zero(a, sizeof(a)), 0);
    ASSERT_EQ(gy_is_zero(b, sizeof(b)), 0);
}

TEST(random_bytes_rejects_null)
{
    ASSERT_EQ(gy_random_bytes(NULL, 32), GY_ERR_ARG);
}

TEST(random_bytes_rejects_zero_length)
{
    uint8_t buf[1];

    ASSERT_EQ(gy_random_bytes(buf, 0), GY_ERR_ARG);
}

GY_TEST_MAIN(GY_TEST(random_bytes_differ_and_nonzero),
             GY_TEST(random_bytes_rejects_null),
             GY_TEST(random_bytes_rejects_zero_length))
