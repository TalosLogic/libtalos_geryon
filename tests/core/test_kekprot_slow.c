/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/kekprot.c: the Stage-1 (passphrase) KEK-protector seam
 * (D-CUST-1 item 3, CUSTODY_SPEC section 6).  Every wrap/unwrap round trip
 * runs a real Argon2id derivation at the compiled MODERATE-tier floor, so
 * this file is tagged _slow.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "kekprot.h"
#include "pwhash.h"
#include "rng.h"
#include "seal.h"
#include "util.h"

#include "gy_test.h"

TEST(roundtrip_default_and_explicit_cipher)
{
    uint8_t kek[GY_KEKPROT_KEK_LEN], recovered[GY_KEKPROT_KEK_LEN];
    uint8_t blob[GY_KEKPROT_MAX_BLOB], ad[6];
    const char *cred = "correct horse battery staple";
    size_t bloblen;

    gy_random_bytes(kek, sizeof(kek));
    gy_random_bytes(ad, sizeof(ad));

    bloblen = sizeof(blob);
    ASSERT_EQ(gy_kekprot_wrap(blob, &bloblen, GY_SEAL_ALG_AEGIS256,
                              GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                              (const uint8_t *)cred, strlen(cred), ad,
                              sizeof(ad), kek),
              GY_OK);
    memset(recovered, 0, sizeof(recovered));
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)cred, strlen(cred),
                                ad, sizeof(ad), blob, bloblen),
              GY_OK);
    ASSERT_MEMEQ(recovered, kek, sizeof(kek));

    bloblen = sizeof(blob);
    ASSERT_EQ(gy_kekprot_wrap(blob, &bloblen, GY_SEAL_ALG_XCHACHA20POLY1305,
                              GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                              (const uint8_t *)cred, strlen(cred), ad,
                              sizeof(ad), kek),
              GY_OK);
    memset(recovered, 0, sizeof(recovered));
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)cred, strlen(cred),
                                ad, sizeof(ad), blob, bloblen),
              GY_OK);
    ASSERT_MEMEQ(recovered, kek, sizeof(kek));
}

TEST(wrong_credential_and_corrupt_blob_are_uniform)
{
    uint8_t kek[GY_KEKPROT_KEK_LEN], recovered[GY_KEKPROT_KEK_LEN];
    uint8_t blob[GY_KEKPROT_MAX_BLOB];
    const char *cred = "the right credential";
    const char *wrong = "the wrong credential";
    size_t bloblen;

    gy_random_bytes(kek, sizeof(kek));

    bloblen = sizeof(blob);
    ASSERT_EQ(gy_kekprot_wrap(blob, &bloblen, GY_SEAL_ALG_AEGIS256,
                              GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                              (const uint8_t *)cred, strlen(cred), NULL, 0,
                              kek),
              GY_OK);

    /* Wrong credential: the same error code as a corrupted blob, below - no
     * bad-credential-vs-corrupt-blob oracle (CUSTODY_SPEC section 15). */
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)wrong,
                                strlen(wrong), NULL, 0, blob, bloblen),
              GY_ERR_VERIFY);

    /* Corrupted sealed portion (past the parameter header), right
     * credential. */
    blob[GY_KEKPROT_HDR_LEN] ^= 0x01;
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)cred, strlen(cred),
                                NULL, 0, blob, bloblen),
              GY_ERR_VERIFY);
    blob[GY_KEKPROT_HDR_LEN] ^= 0x01;

    /* Mismatched ad, right credential and blob otherwise. */
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)cred, strlen(cred),
                                (const uint8_t *)"x", 1, blob, bloblen),
              GY_ERR_VERIFY);

    /* A good unwrap still works, confirming the fixture is valid throughout. */
    ASSERT_EQ(gy_kekprot_unwrap(recovered, (const uint8_t *)cred, strlen(cred),
                                NULL, 0, blob, bloblen),
              GY_OK);
    ASSERT_MEMEQ(recovered, kek, sizeof(kek));
}

TEST(rejects_null_and_short_blob)
{
    uint8_t kek[GY_KEKPROT_KEK_LEN], out[GY_KEKPROT_KEK_LEN];
    uint8_t blob[8];
    const char *cred = "cred";
    size_t bloblen;

    gy_random_bytes(kek, sizeof(kek));

    bloblen = sizeof(blob);
    ASSERT_EQ(gy_kekprot_wrap(NULL, &bloblen, GY_SEAL_ALG_AEGIS256,
                              GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                              (const uint8_t *)cred, strlen(cred), NULL, 0,
                              kek),
              GY_ERR_ARG);
    /* Undersized output buffer: fails before any Argon2id work runs. */
    ASSERT_EQ(gy_kekprot_wrap(blob, &bloblen, GY_SEAL_ALG_AEGIS256,
                              GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                              (const uint8_t *)cred, strlen(cred), NULL, 0,
                              kek),
              GY_ERR_ARG);

    /* Too short to hold the parameter header: fails before any Argon2id
     * work runs. */
    ASSERT_EQ(gy_kekprot_unwrap(out, (const uint8_t *)cred, strlen(cred), NULL,
                                0, blob, sizeof(blob)),
              GY_ERR_VERIFY);
    ASSERT_EQ(gy_kekprot_unwrap(NULL, (const uint8_t *)cred, strlen(cred), NULL,
                                0, blob, sizeof(blob)),
              GY_ERR_ARG);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(roundtrip_default_and_explicit_cipher),
            GY_TEST(wrong_credential_and_corrupt_blob_are_uniform),
            GY_TEST(rejects_null_and_short_blob),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
