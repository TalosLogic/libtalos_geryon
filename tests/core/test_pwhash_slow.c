/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/pwhash.c.  Argon2id correctness itself is libsodium's
 * responsibility (library-first, MIT-licensed dependency): these tests
 * confirm the wrapper is wired correctly (matches a direct crypto_pwhash
 * call byte-for-byte, is deterministic given the same salt, and enforces
 * the compiled cost floor/ceiling) at the project's real MODERATE-tier
 * floor cost, which is why this file is tagged _slow.
 */

#include <stdint.h>
#include <string.h>

#include <sodium.h>

#include "error.h"
#include "pwhash.h"
#include "rng.h"
#include "util.h"

#include "gy_test.h"

TEST(matches_direct_libsodium_call)
{
    uint8_t salt[GY_PWHASH_SALT_LEN];
    uint8_t out[32], want[32];
    const char *cred = "correct horse battery staple";

    ASSERT_EQ(gy_random_bytes(salt, sizeof(salt)), GY_OK);

    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_OK);

    ASSERT_EQ(crypto_pwhash(want, sizeof(want), cred, strlen(cred), salt,
                            GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                            crypto_pwhash_ALG_ARGON2ID13),
              0);
    ASSERT_MEMEQ(out, want, sizeof(out));
}

TEST(deterministic_and_salt_sensitive)
{
    uint8_t salt_a[GY_PWHASH_SALT_LEN], salt_b[GY_PWHASH_SALT_LEN];
    uint8_t out1[32], out2[32], out3[32];
    const char *cred = "another test credential";

    ASSERT_EQ(gy_random_bytes(salt_a, sizeof(salt_a)), GY_OK);
    ASSERT_EQ(gy_random_bytes(salt_b, sizeof(salt_b)), GY_OK);

    ASSERT_EQ(gy_pwhash_derive(out1, sizeof(out1), (const uint8_t *)cred,
                               strlen(cred), salt_a, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_OK);
    ASSERT_EQ(gy_pwhash_derive(out2, sizeof(out2), (const uint8_t *)cred,
                               strlen(cred), salt_a, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_OK);
    ASSERT_MEMEQ(out1, out2, sizeof(out1));

    ASSERT_EQ(gy_pwhash_derive(out3, sizeof(out3), (const uint8_t *)cred,
                               strlen(cred), salt_b, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_OK);
    ASSERT_TRUE(memcmp(out1, out3, sizeof(out1)) != 0,
                "different salt yields different output");
}

TEST(floor_and_ceiling_rejected)
{
    uint8_t salt[GY_PWHASH_SALT_LEN];
    uint8_t out[32];
    const char *cred = "cred";

    ASSERT_EQ(gy_random_bytes(salt, sizeof(salt)), GY_OK);

    /* All four rejections trip the argument check before any Argon2id work
     * runs, so this test case itself stays fast. */
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MIN - 1,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_ERR_ARG);
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN - 1),
              GY_ERR_ARG);
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MAX + 1,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_ERR_ARG);
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MAX + 1),
              GY_ERR_ARG);
}

TEST(rejects_null_arguments)
{
    uint8_t salt[GY_PWHASH_SALT_LEN] = {0};
    uint8_t out[32];
    const char *cred = "cred";

    ASSERT_EQ(gy_pwhash_derive(NULL, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), salt, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_ERR_ARG);
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), NULL, strlen(cred), salt,
                               GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN),
              GY_ERR_ARG);
    ASSERT_EQ(gy_pwhash_derive(out, sizeof(out), (const uint8_t *)cred,
                               strlen(cred), NULL, GY_PWHASH_OPSLIMIT_MIN,
                               GY_PWHASH_MEMLIMIT_MIN),
              GY_ERR_ARG);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(matches_direct_libsodium_call),
            GY_TEST(deterministic_and_salt_sensitive),
            GY_TEST(floor_and_ceiling_rejected),
            GY_TEST(rejects_null_arguments),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
