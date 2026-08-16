/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/session/keystore.c: the in-memory keystore
 * (D-CUST-1 items 1-2 and 6).  create/open/change_credential each run a real
 * Argon2id derivation at the compiled MODERATE-tier floor, so this file is
 * tagged _slow.
 */

#include <stdint.h>
#include <string.h>

#include "keystore.h"

#include "gy_test.h"

TEST(create_close_open_roundtrip)
{
    struct gy_keystore ks1, ks2;
    uint8_t wrap[GY_KEYSTORE_WRAP_MAX];
    uint8_t sealed[128], ad[4], recovered[64];
    const char *cred = "correct horse battery staple";
    size_t wraplen, sealedlen, ptlen;

    memset(&ks1, 0, sizeof(ks1));
    wraplen = sizeof(wrap);
    ASSERT_EQ(gy_keystore_create(&ks1, GY_SEAL_ALG_AEGIS256,
                                 GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                                 (const uint8_t *)cred, strlen(cred), wrap,
                                 &wraplen),
              GY_OK);
    ASSERT_TRUE(ks1.unlocked, "created keystore is unlocked");

    /* Seal something under ks1's KEK before closing, to prove open recovers
     * the SAME KEK (not just any KEK). */
    memset(ad, 0x11, sizeof(ad));
    sealedlen = sizeof(sealed);
    ASSERT_EQ(gy_keystore_seal(&ks1, GY_SEAL_ALG_AEGIS256, ad, sizeof(ad),
                               (const uint8_t *)"hello keystore", 14, sealed,
                               &sealedlen),
              GY_OK);

    gy_keystore_close(&ks1);
    ASSERT_TRUE(!ks1.unlocked, "closed keystore is locked");

    memset(&ks2, 0, sizeof(ks2));
    ASSERT_EQ(gy_keystore_open(&ks2, (const uint8_t *)cred, strlen(cred), wrap,
                               wraplen),
              GY_OK);
    ASSERT_TRUE(ks2.unlocked, "reopened keystore is unlocked");

    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_keystore_unseal(&ks2, ad, sizeof(ad), sealed, sealedlen,
                                 recovered, &ptlen),
              GY_OK);
    ASSERT_EQ(ptlen, 14);
    ASSERT_MEMEQ(recovered, "hello keystore", 14);

    /* A mismatched ad fails: proves gy_keystore_unseal actually forwards ad
     * to gy_unseal rather than silently ignoring it. */
    ad[0] ^= 0x01;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_keystore_unseal(&ks2, ad, sizeof(ad), sealed, sealedlen,
                                 recovered, &ptlen),
              GY_ERR_VERIFY);

    gy_keystore_close(&ks2);
}

TEST(wrong_credential_and_double_open_rejected)
{
    struct gy_keystore ks;
    uint8_t wrap[GY_KEYSTORE_WRAP_MAX];
    const char *cred = "the right credential";
    const char *wrong = "the wrong credential";
    size_t wraplen;

    memset(&ks, 0, sizeof(ks));
    wraplen = sizeof(wrap);
    ASSERT_EQ(gy_keystore_create(&ks, GY_SEAL_ALG_AEGIS256,
                                 GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                                 (const uint8_t *)cred, strlen(cred), wrap,
                                 &wraplen),
              GY_OK);

    /* Already open: create/open again is rejected, not a silent leak. */
    ASSERT_EQ(gy_keystore_create(&ks, GY_SEAL_ALG_AEGIS256,
                                 GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                                 (const uint8_t *)cred, strlen(cred), wrap,
                                 &wraplen),
              GY_ERR_STATE);

    gy_keystore_close(&ks);

    memset(&ks, 0, sizeof(ks));
    ASSERT_EQ(gy_keystore_open(&ks, (const uint8_t *)wrong, strlen(wrong), wrap,
                               wraplen),
              GY_ERR_VERIFY);
    ASSERT_TRUE(!ks.unlocked, "failed open leaves the keystore locked");
}

TEST(credential_change_preserves_kek)
{
    struct gy_keystore ks;
    uint8_t wrap1[GY_KEYSTORE_WRAP_MAX], wrap2[GY_KEYSTORE_WRAP_MAX];
    uint8_t sealed[128], recovered[64];
    const char *cred1 = "original credential";
    const char *cred2 = "replacement credential";
    size_t wrap1len, wrap2len, sealedlen, ptlen;

    memset(&ks, 0, sizeof(ks));
    wrap1len = sizeof(wrap1);
    ASSERT_EQ(gy_keystore_create(&ks, GY_SEAL_ALG_AEGIS256,
                                 GY_PWHASH_OPSLIMIT_MIN, GY_PWHASH_MEMLIMIT_MIN,
                                 (const uint8_t *)cred1, strlen(cred1), wrap1,
                                 &wrap1len),
              GY_OK);

    sealedlen = sizeof(sealed);
    ASSERT_EQ(gy_keystore_seal(&ks, GY_SEAL_ALG_AEGIS256, NULL, 0,
                               (const uint8_t *)"still here", 10, sealed,
                               &sealedlen),
              GY_OK);

    wrap2len = sizeof(wrap2);
    ASSERT_EQ(gy_keystore_change_credential(
                  &ks, GY_SEAL_ALG_AEGIS256, GY_PWHASH_OPSLIMIT_MIN,
                  GY_PWHASH_MEMLIMIT_MIN, (const uint8_t *)cred2, strlen(cred2),
                  wrap2, &wrap2len),
              GY_OK);

    /* Material sealed BEFORE the credential change still opens under the
     * SAME live KEK, without having been re-touched. */
    ptlen = sizeof(recovered);
    ASSERT_EQ(
        gy_keystore_unseal(&ks, NULL, 0, sealed, sealedlen, recovered, &ptlen),
        GY_OK);
    ASSERT_EQ(ptlen, 10);
    ASSERT_MEMEQ(recovered, "still here", 10);
    gy_keystore_close(&ks);

    /* The new wrap blob opens the same KEK under cred2. */
    memset(&ks, 0, sizeof(ks));
    ASSERT_EQ(gy_keystore_open(&ks, (const uint8_t *)cred2, strlen(cred2),
                               wrap2, wrap2len),
              GY_OK);
    ptlen = sizeof(recovered);
    ASSERT_EQ(
        gy_keystore_unseal(&ks, NULL, 0, sealed, sealedlen, recovered, &ptlen),
        GY_OK);
    ASSERT_MEMEQ(recovered, "still here", 10);
    gy_keystore_close(&ks);

    /* change_credential re-wraps; it does not invalidate the prior wrap
     * blob, which still opens the same KEK under the ORIGINAL credential. */
    memset(&ks, 0, sizeof(ks));
    ASSERT_EQ(gy_keystore_open(&ks, (const uint8_t *)cred1, strlen(cred1),
                               wrap1, wrap1len),
              GY_OK);
    ptlen = sizeof(recovered);
    ASSERT_EQ(
        gy_keystore_unseal(&ks, NULL, 0, sealed, sealedlen, recovered, &ptlen),
        GY_OK);
    ASSERT_MEMEQ(recovered, "still here", 10);
    gy_keystore_close(&ks);
}

TEST(operations_on_a_locked_keystore_are_rejected)
{
    struct gy_keystore ks;
    uint8_t out[64];
    size_t outlen;

    memset(&ks, 0, sizeof(ks));
    outlen = sizeof(out);
    ASSERT_EQ(gy_keystore_seal(&ks, GY_SEAL_ALG_AEGIS256, NULL, 0,
                               (const uint8_t *)"x", 1, out, &outlen),
              GY_ERR_STATE);
    ASSERT_EQ(gy_keystore_unseal(&ks, NULL, 0, out, sizeof(out), out, &outlen),
              GY_ERR_STATE);

    /* Idempotent close on a never-opened keystore. */
    gy_keystore_close(&ks);
    gy_keystore_close(&ks);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(create_close_open_roundtrip),
            GY_TEST(wrong_credential_and_double_open_rejected),
            GY_TEST(credential_change_preserves_kek),
            GY_TEST(operations_on_a_locked_keystore_are_rejected),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
