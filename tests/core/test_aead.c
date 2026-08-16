/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/aead.c.  Vectors:
 *   - ChaCha20-Poly1305 IETF: RFC 8439 section 2.8.2 worked example.
 *   - AES-256-GCM: GCM spec (McGrew/Viega) test case 16; run only when the
 *     CPU exposes hardware AES-GCM, skipped with a note otherwise.
 *   - AEGIS-256: known-answer test from libsodium's own vector table
 *     (test/default/aead_aegis256.c, case 1), plus round-trip and tamper.
 * Plus a round-trip property sweep and negative/tamper cases on ChaCha.
 */

#include <stdint.h>
#include <string.h>

#include "aead.h"
#include "error.h"
#include "rng.h"
#include "util.h"

#include "gy_test.h"

#define MAXPT 4096
#define MAXCT (MAXPT + GY_AEAD_MAX_TAG)

static size_t
hx(uint8_t *buf, size_t cap, const char *hex)
{
    int n = gy_hex_decode(buf, cap, hex);
    return n < 0 ? 0 : (size_t)n;
}

TEST(chacha20poly1305_rfc8439)
{
    uint8_t key[32], nonce[12], ad[12], pt[114];
    uint8_t want[114 + 16];
    uint8_t ct[MAXCT], out[MAXPT];
    size_t klen, nlen, adlen, ptlen, wlen, ctlen, outlen;

    klen =
        hx(key, sizeof(key),
           "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    nlen = hx(nonce, sizeof(nonce), "070000004041424344454647");
    adlen = hx(ad, sizeof(ad), "50515253c0c1c2c3c4c5c6c7");
    ptlen =
        hx(pt, sizeof(pt),
           "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
           "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
           "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
           "637265656e20776f756c642062652069742e");
    wlen = hx(want, sizeof(want),
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
              "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
              "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116"
              "1ae10b594f09e26a7e902ecbd0600691");
    (void)klen;

    ctlen = sizeof(ct);
    ASSERT_EQ(gy_aead_encrypt(GY_AEAD_CHACHA20POLY1305, ct, &ctlen, key, nonce,
                              nlen, ad, adlen, pt, ptlen),
              GY_OK);
    ASSERT_EQ(ctlen, wlen);
    ASSERT_MEMEQ(ct, want, wlen);

    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(GY_AEAD_CHACHA20POLY1305, out, &outlen, key,
                              nonce, nlen, ad, adlen, want, wlen),
              GY_OK);
    ASSERT_EQ(outlen, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

TEST(aes256gcm_nist_case16)
{
    uint8_t key[32], nonce[12], ad[20], pt[60];
    uint8_t want[60 + 16];
    uint8_t ct[MAXCT], out[MAXPT];
    size_t nlen, adlen, ptlen, wlen, ctlen, outlen;

    if (!gy_aead_available(GY_AEAD_AES256GCM)) {
        printf("  (AES-256-GCM unavailable on this CPU, skipping KAT)\n");
        return;
    }

    hx(key, sizeof(key),
       "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    nlen = hx(nonce, sizeof(nonce), "cafebabefacedbaddecaf888");
    adlen = hx(ad, sizeof(ad), "feedfacedeadbeeffeedfacedeadbeefabaddad2");
    ptlen =
        hx(pt, sizeof(pt),
           "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
           "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
    wlen = hx(want, sizeof(want),
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
              "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
              "76fc6ece0f4e1768cddf8853bb2d551b");

    ctlen = sizeof(ct);
    ASSERT_EQ(gy_aead_encrypt(GY_AEAD_AES256GCM, ct, &ctlen, key, nonce, nlen,
                              ad, adlen, pt, ptlen),
              GY_OK);
    ASSERT_EQ(ctlen, wlen);
    ASSERT_MEMEQ(ct, want, wlen);

    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(GY_AEAD_AES256GCM, out, &outlen, key, nonce, nlen,
                              ad, adlen, want, wlen),
              GY_OK);
    ASSERT_EQ(outlen, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

TEST(aegis256_libsodium_kat)
{
    uint8_t key[32], nonce[32], ad[30], pt[105];
    uint8_t want[105 + 32];
    uint8_t ct[MAXCT], out[MAXPT];
    size_t nlen, adlen, ptlen, wlen, ctlen, outlen;

    hx(key, sizeof(key),
       "7083505997f52fdf86548d86ee87c1429ed91f108cd56384dc840269ef7fdd73");
    nlen =
        hx(nonce, sizeof(nonce),
           "18cd778e6f5b1d35d4ca975fd719a17aaf22c3eba01928b6a78bac5810c92c75");
    adlen = hx(ad, sizeof(ad),
               "af5b16a480e6a1400be15c8e6b194c2aca175e3b5c3f3fbbeca865f9390a");
    ptlen =
        hx(pt, sizeof(pt),
           "5d6691271eb1b2261d1b34fa7560e274b83373343c2e49b2b6a82bc0f20cee85"
           "cd608d195c1a16679d720441c95fae86631f3f2cd27f38f71cedc79aaca7fddd"
           "bd4da4eeb97632366db65ca21acd85b41fd1a9de688bddff433a4757eb084e68"
           "16dbc8ff93f5995804");
    wlen =
        hx(want, sizeof(want),
           "0943a3e659b86e267ffea969ddd6d6d63aa35d1a1f31fb6f47205104b132da65"
           "799cc64cc9f66ffa5ec479550c2c5dfa006f827ef02e3ab4dae3446bf93ccb5c"
           "17e1ec0393f161fca94f2944d041f162e9c964558b6b57d3bb393b9743b1f833"
           "8ff878a154800fd16c"
           "480091eb823480e8b29c7aa96ffd55a026ac3d7fa16787c36c25865131a639a4");

    ctlen = sizeof(ct);
    ASSERT_EQ(gy_aead_encrypt(GY_AEAD_AEGIS256, ct, &ctlen, key, nonce, nlen,
                              ad, adlen, pt, ptlen),
              GY_OK);
    ASSERT_EQ(ctlen, wlen);
    ASSERT_MEMEQ(ct, want, wlen);

    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(GY_AEAD_AEGIS256, out, &outlen, key, nonce, nlen,
                              ad, adlen, want, wlen),
              GY_OK);
    ASSERT_EQ(outlen, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

/* Encrypt then decrypt across several plaintext lengths for one AEAD. */
static void
roundtrip_lengths(uint8_t id)
{
    static const size_t lens[] = {0, 1, 63, 64, 65, 4096};
    uint8_t key[GY_AEAD_KEY_LEN], nonce[GY_AEAD_MAX_NONCE], ad[16];
    uint8_t pt[MAXPT], ct[MAXCT], out[MAXPT];
    size_t i, nlen, taglen, ptlen, ctlen, outlen;

    nlen = gy_aead_nonce_len(id);
    taglen = gy_aead_tag_len(id);

    for (i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
        ptlen = lens[i];
        gy_random_bytes(key, sizeof(key));
        gy_random_bytes(nonce, nlen);
        gy_random_bytes(ad, sizeof(ad));
        if (ptlen > 0)
            gy_random_bytes(pt, ptlen);

        ctlen = sizeof(ct);
        ASSERT_EQ(gy_aead_encrypt(id, ct, &ctlen, key, nonce, nlen, ad,
                                  sizeof(ad), pt, ptlen),
                  GY_OK);
        ASSERT_EQ(ctlen, ptlen + taglen);

        outlen = sizeof(out);
        ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                                  sizeof(ad), ct, ctlen),
                  GY_OK);
        ASSERT_EQ(outlen, ptlen);
        if (ptlen > 0)
            ASSERT_MEMEQ(out, pt, ptlen);
    }
}

TEST(roundtrip_all_available)
{
    roundtrip_lengths(GY_AEAD_CHACHA20POLY1305);
    roundtrip_lengths(GY_AEAD_AEGIS256);
    if (gy_aead_available(GY_AEAD_AES256GCM))
        roundtrip_lengths(GY_AEAD_AES256GCM);
}

TEST(tamper_and_argument_errors)
{
    uint8_t key[32], nonce[12], ad[8], pt[32];
    uint8_t ct[MAXCT], out[MAXPT];
    size_t nlen, ctlen, outlen;
    uint8_t id = GY_AEAD_CHACHA20POLY1305;

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(ad, 0x33, sizeof(ad));
    memset(pt, 0x44, sizeof(pt));
    nlen = gy_aead_nonce_len(id);

    ctlen = sizeof(ct);
    ASSERT_EQ(gy_aead_encrypt(id, ct, &ctlen, key, nonce, nlen, ad, sizeof(ad),
                              pt, sizeof(pt)),
              GY_OK);

    /* A good decrypt first, to confirm the fixture is valid. */
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                              sizeof(ad), ct, ctlen),
              GY_OK);

    /*
     * Flipped ciphertext byte: verify fails and no unverified plaintext is
     * released.  libsodium zeroes the output buffer on failure rather than
     * leaving it untouched, so assert the true plaintext is not revealed
     * (poison the buffer first so a no-write would also be caught).
     */
    ct[0] ^= 0x01;
    memset(out, 0x5a, sizeof(out));
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                              sizeof(ad), ct, ctlen),
              GY_ERR_VERIFY);
    ASSERT_TRUE(memcmp(out, pt, sizeof(pt)) != 0,
                "no plaintext released on verify failure");
    ct[0] ^= 0x01;

    /* Flipped tag byte (last byte of ct || tag). */
    ct[ctlen - 1] ^= 0x80;
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                              sizeof(ad), ct, ctlen),
              GY_ERR_VERIFY);
    ct[ctlen - 1] ^= 0x80;

    /* Flipped associated-data byte at decrypt time. */
    ad[0] ^= 0x01;
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                              sizeof(ad), ct, ctlen),
              GY_ERR_VERIFY);
    ad[0] ^= 0x01;

    /* Wrong key. */
    key[0] ^= 0x01;
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen, ad,
                              sizeof(ad), ct, ctlen),
              GY_ERR_VERIFY);
    key[0] ^= 0x01;

    /* Wrong nonce length is an argument error, not a verify failure. */
    outlen = sizeof(out);
    ASSERT_EQ(gy_aead_decrypt(id, out, &outlen, key, nonce, nlen - 1, ad,
                              sizeof(ad), ct, ctlen),
              GY_ERR_ARG);
    ctlen = sizeof(ct);
    ASSERT_EQ(gy_aead_encrypt(id, ct, &ctlen, key, nonce, nlen + 1, ad,
                              sizeof(ad), pt, sizeof(pt)),
              GY_ERR_ARG);
}

TEST(metadata_and_unsupported)
{
    ASSERT_EQ(gy_aead_nonce_len(GY_AEAD_CHACHA20POLY1305), 12);
    ASSERT_EQ(gy_aead_nonce_len(GY_AEAD_AES256GCM), 12);
    ASSERT_EQ(gy_aead_nonce_len(GY_AEAD_AEGIS256), 32);
    ASSERT_EQ(gy_aead_tag_len(GY_AEAD_CHACHA20POLY1305), 16);
    ASSERT_EQ(gy_aead_tag_len(GY_AEAD_AEGIS256), 32);

    /* Unknown ID: no metadata, not available. */
    ASSERT_EQ(gy_aead_nonce_len(0x00), 0);
    ASSERT_EQ(gy_aead_tag_len(0xff), 0);
    ASSERT_EQ(gy_aead_available(0x7f), 0);
    ASSERT_EQ(gy_aead_available(GY_AEAD_CHACHA20POLY1305), 1);
}

int
main(void)
{
    ASSERT_EQ(gy_core_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(chacha20poly1305_rfc8439),
            GY_TEST(aes256gcm_nist_case16),
            GY_TEST(aegis256_libsodium_kat),
            GY_TEST(roundtrip_all_available),
            GY_TEST(tamper_and_argument_errors),
            GY_TEST(metadata_and_unsupported),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
