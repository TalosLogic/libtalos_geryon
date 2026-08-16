/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/seal.c: the self-describing wrap AEAD used by key
 * custody (D-CUST-1 items 4-5).
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "rng.h"
#include "seal.h"
#include "util.h"

#include "gy_test.h"

#define MAXPT 512
#define MAXBLOB (MAXPT + GY_SEAL_MAX_OVERHEAD)

static void
roundtrip_one(uint8_t alg_id)
{
    uint8_t key[GY_SEAL_KEY_LEN], ad[8], pt[200];
    uint8_t blob[MAXBLOB], recovered[MAXPT];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));
    gy_random_bytes(ad, sizeof(ad));
    gy_random_bytes(pt, sizeof(pt));

    outlen = sizeof(blob);
    ASSERT_EQ(
        gy_seal(blob, &outlen, key, alg_id, ad, sizeof(ad), pt, sizeof(pt)),
        GY_OK);
    ASSERT_EQ(blob[1], alg_id);

    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_OK);
    ASSERT_EQ(ptlen, sizeof(pt));
    ASSERT_MEMEQ(recovered, pt, sizeof(pt));
}

TEST(roundtrip_aegis256_default)
{
    roundtrip_one(GY_SEAL_ALG_AEGIS256);
}

TEST(roundtrip_xchacha20poly1305_explicit)
{
    roundtrip_one(GY_SEAL_ALG_XCHACHA20POLY1305);
}

TEST(roundtrip_empty_plaintext_and_ad)
{
    uint8_t key[GY_SEAL_KEY_LEN], blob[GY_SEAL_MAX_OVERHEAD];
    uint8_t recovered[1];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));

    outlen = sizeof(blob);
    ASSERT_EQ(
        gy_seal(blob, &outlen, key, GY_SEAL_ALG_AEGIS256, NULL, 0, NULL, 0),
        GY_OK);
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, NULL, 0, blob, outlen), GY_OK);
    ASSERT_EQ(ptlen, 0);
}

TEST(ad_tamper_and_wrong_key)
{
    uint8_t key[GY_SEAL_KEY_LEN], ad[4], pt[32];
    uint8_t blob[MAXBLOB], recovered[MAXPT];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));
    memset(ad, 0x11, sizeof(ad));
    memset(pt, 0x22, sizeof(pt));

    outlen = sizeof(blob);
    ASSERT_EQ(gy_seal(blob, &outlen, key, GY_SEAL_ALG_AEGIS256, ad, sizeof(ad),
                      pt, sizeof(pt)),
              GY_OK);

    /* Wrong caller-supplied ad. */
    ad[0] ^= 0x01;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_ERR_VERIFY);
    ad[0] ^= 0x01;

    /*
     * Flipped alg_id byte in the blob header: still a recognized cipher
     * (XChaCha20-Poly1305), but not the one the AD was bound under at seal
     * time, so the tag check fails.  This is exactly the downgrade the AD
     * binding (D-CUST-1 item 5) exists to catch.
     */
    blob[1] = GY_SEAL_ALG_XCHACHA20POLY1305;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_ERR_VERIFY);
    blob[1] = GY_SEAL_ALG_AEGIS256;

    /* Flipped version byte. */
    blob[0] ^= 0x01;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_ERR_VERIFY);
    blob[0] ^= 0x01;

    /* Wrong key. */
    key[0] ^= 0x01;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_ERR_VERIFY);
    key[0] ^= 0x01;

    /* A good unseal still works after all the above tamper/restore pairs,
     * confirming the fixture itself is valid throughout. */
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_OK);
    ASSERT_MEMEQ(recovered, pt, sizeof(pt));
}

static void
poison_check_one(uint8_t alg_id)
{
    uint8_t key[GY_SEAL_KEY_LEN], pt[32];
    uint8_t blob[MAXBLOB], recovered[MAXPT];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));
    memset(pt, 0x55, sizeof(pt));

    outlen = sizeof(blob);
    ASSERT_EQ(gy_seal(blob, &outlen, key, alg_id, NULL, 0, pt, sizeof(pt)),
              GY_OK);

    /* Poison the destination first so a no-write on failure would also be
     * caught, then flip a ciphertext byte and confirm the true plaintext is
     * never released (gy_aead_decrypt and libsodium's own combined-mode
     * decrypt both zero the output buffer on tag failure). */
    memset(recovered, 0xa5, sizeof(recovered));
    blob[outlen - 1] ^= 0x01;
    ptlen = sizeof(recovered);
    ASSERT_EQ(gy_unseal(recovered, &ptlen, key, NULL, 0, blob, outlen),
              GY_ERR_VERIFY);
    ASSERT_TRUE(memcmp(recovered, pt, sizeof(pt)) != 0,
                "no plaintext released on verify failure");
}

TEST(no_plaintext_released_on_failure_aegis256)
{
    poison_check_one(GY_SEAL_ALG_AEGIS256);
}

TEST(no_plaintext_released_on_failure_xchacha20poly1305)
{
    poison_check_one(GY_SEAL_ALG_XCHACHA20POLY1305);
}

TEST(unrecognized_alg_id)
{
    uint8_t key[GY_SEAL_KEY_LEN], pt[8], out[128], blob[128];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));
    memset(pt, 0x33, sizeof(pt));

    /* gy_seal: a caller-supplied bad alg_id is a plain argument error. */
    outlen = sizeof(out);
    ASSERT_EQ(gy_seal(out, &outlen, key, 0x7f, NULL, 0, pt, sizeof(pt)),
              GY_ERR_ARG);

    /* gy_unseal: a bad alg_id read from the blob is attacker-influenceable
     * and must not be distinguishable from a tag failure. */
    outlen = sizeof(blob);
    ASSERT_EQ(gy_seal(blob, &outlen, key, GY_SEAL_ALG_AEGIS256, NULL, 0, pt,
                      sizeof(pt)),
              GY_OK);
    blob[1] = 0x7f;
    ptlen = sizeof(out);
    ASSERT_EQ(gy_unseal(out, &ptlen, key, NULL, 0, blob, outlen),
              GY_ERR_VERIFY);
}

TEST(argument_and_length_errors)
{
    uint8_t key[GY_SEAL_KEY_LEN], ad[GY_SEAL_MAX_AD + 1], pt[8];
    uint8_t out[128], blob[128], small[4];
    size_t outlen, ptlen;

    gy_random_bytes(key, sizeof(key));
    memset(ad, 0, sizeof(ad));
    memset(pt, 0x44, sizeof(pt));

    outlen = sizeof(out);
    ASSERT_EQ(gy_seal(NULL, &outlen, key, GY_SEAL_ALG_AEGIS256, NULL, 0, pt,
                      sizeof(pt)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_seal(out, &outlen, NULL, GY_SEAL_ALG_AEGIS256, NULL, 0, pt,
                      sizeof(pt)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_seal(out, &outlen, key, GY_SEAL_ALG_AEGIS256, ad, sizeof(ad),
                      pt, sizeof(pt)),
              GY_ERR_TOOLONG);

    outlen = sizeof(small);
    ASSERT_EQ(gy_seal(small, &outlen, key, GY_SEAL_ALG_AEGIS256, NULL, 0, pt,
                      sizeof(pt)),
              GY_ERR_ARG);

    outlen = sizeof(blob);
    ASSERT_EQ(gy_seal(blob, &outlen, key, GY_SEAL_ALG_AEGIS256, NULL, 0, pt,
                      sizeof(pt)),
              GY_OK);

    ptlen = sizeof(out);
    ASSERT_EQ(gy_unseal(NULL, &ptlen, key, NULL, 0, blob, outlen), GY_ERR_ARG);
    ASSERT_EQ(gy_unseal(out, &ptlen, key, ad, sizeof(ad), blob, outlen),
              GY_ERR_TOOLONG);
    ASSERT_EQ(gy_unseal(out, &ptlen, key, NULL, 0, blob, 1), GY_ERR_VERIFY);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(roundtrip_aegis256_default),
            GY_TEST(roundtrip_xchacha20poly1305_explicit),
            GY_TEST(roundtrip_empty_plaintext_and_ad),
            GY_TEST(ad_tamper_and_wrong_key),
            GY_TEST(no_plaintext_released_on_failure_aegis256),
            GY_TEST(no_plaintext_released_on_failure_xchacha20poly1305),
            GY_TEST(unrecognized_alg_id),
            GY_TEST(argument_and_length_errors),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
