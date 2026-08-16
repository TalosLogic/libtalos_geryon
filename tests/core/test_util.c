/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/util.c and error.c: crypto-backend init, constant-time
 * comparison, all-zero test, and secure zeroization.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "util.h"

#include "gy_test.h"

TEST(core_init_idempotent)
{
    /* Must run first: later tests assume the backend is initialized. */
    ASSERT_EQ(gy_core_init(), GY_OK);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(const_memcmp_equal)
{
    uint8_t a[4] = {1, 2, 3, 4};
    uint8_t b[4] = {1, 2, 3, 4};

    ASSERT_EQ(gy_const_memcmp(a, b, sizeof(a)), 0);
}

TEST(const_memcmp_unequal)
{
    uint8_t a[4] = {1, 2, 3, 4};
    uint8_t b[4] = {1, 2, 3, 5};

    /* Equality test only: any nonzero result signals "differ". */
    ASSERT_TRUE(gy_const_memcmp(a, b, sizeof(a)) != 0,
                "differing buffers compare nonzero");
    /* A difference in the first byte differs too. */
    b[0] = 9;
    ASSERT_TRUE(gy_const_memcmp(a, b, sizeof(a)) != 0,
                "first-byte difference compares nonzero");
}

TEST(const_memcmp_zero_length)
{
    uint8_t a[1] = {0xa5};
    uint8_t b[1] = {0x5a};

    /* A zero-length comparison is defined and always equal. */
    ASSERT_EQ(gy_const_memcmp(a, b, 0), 0);
}

TEST(is_zero_all_zero)
{
    uint8_t z[8] = {0};

    ASSERT_EQ(gy_is_zero(z, sizeof(z)), 1);
}

TEST(is_zero_nonzero)
{
    uint8_t z[8] = {0};

    /* A nonzero byte at the end is detected. */
    z[7] = 1;
    ASSERT_EQ(gy_is_zero(z, sizeof(z)), 0);
    /* And at the start (timing must not depend on position). */
    z[7] = 0;
    z[0] = 1;
    ASSERT_EQ(gy_is_zero(z, sizeof(z)), 0);
}

TEST(is_zero_zero_length)
{
    uint8_t z[1] = {0xff};

    /* Zero bytes are vacuously all-zero. */
    ASSERT_EQ(gy_is_zero(z, 0), 1);
}

TEST(secure_zero_erases)
{
    uint8_t buf[32];
    uint8_t zero[32] = {0};

    /*
     * Write a pattern, confirm it took, then erase.  gy_secure_zero wraps
     * sodium_memzero, which the compiler may not elide even though buf is
     * dead after this function returns; a plain memset here could be
     * optimized away and must never be used to clear key material.
     */
    memset(buf, 0xa5, sizeof(buf));
    ASSERT_TRUE(memcmp(buf, zero, sizeof(buf)) != 0, "pattern was written");
    gy_secure_zero(buf, sizeof(buf));
    ASSERT_MEMEQ(buf, zero, sizeof(buf));
}

TEST(strerror_nonnull)
{
    /* Known and unknown codes both yield a usable static string. */
    ASSERT_TRUE(gy_strerror(GY_OK) != NULL, "known code non-null");
    ASSERT_TRUE(gy_strerror(GY_ERR_WEAK_KEY) != NULL, "known code non-null");
    ASSERT_TRUE(gy_strerror(-999) != NULL, "unknown code non-null");
}

GY_TEST_MAIN(GY_TEST(core_init_idempotent), GY_TEST(const_memcmp_equal),
             GY_TEST(const_memcmp_unequal), GY_TEST(const_memcmp_zero_length),
             GY_TEST(is_zero_all_zero), GY_TEST(is_zero_nonzero),
             GY_TEST(is_zero_zero_length), GY_TEST(secure_zero_erases),
             GY_TEST(strerror_nonnull))
