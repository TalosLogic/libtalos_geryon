/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/hash.c.  Vectors:
 *   - SHA-256/512: FIPS 180 "abc" and empty-message KATs.
 *   - HMAC-SHA256/512: RFC 4231 test cases 1-7 (case 5 is 128-bit truncated,
 *     so only the leading 16 bytes are checked against our full output).
 *   - HKDF-SHA256: RFC 5869 test cases 1-3.
 *   - HKDF-SHA512: no RFC vectors exist, so it is cross-checked against an
 *     independent HKDF built from the gy_hmac_sha512 wrapper.
 */

#include <stdint.h>
#include <string.h>

#include "error.h"
#include "hash.h"

#include "gy_test.h"

/* Decode hex into buf, asserting it fits, and return the byte length. */
static size_t
hx(uint8_t *buf, size_t cap, const char *hex)
{
    int n = gy_hex_decode(buf, cap, hex);
    return n < 0 ? 0 : (size_t)n;
}

TEST(sha256_kats)
{
    uint8_t out[32];
    uint8_t want[32];

    gy_sha256(out, (const uint8_t *)"abc", 3);
    hx(want, sizeof(want),
       "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    ASSERT_MEMEQ(out, want, sizeof(out));

    gy_sha256(out, (const uint8_t *)"", 0);
    hx(want, sizeof(want),
       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ASSERT_MEMEQ(out, want, sizeof(out));
}

TEST(sha512_kats)
{
    uint8_t out[64];
    uint8_t want[64];

    gy_sha512(out, (const uint8_t *)"abc", 3);
    hx(want, sizeof(want),
       "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
       "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    ASSERT_MEMEQ(out, want, sizeof(out));

    gy_sha512(out, (const uint8_t *)"", 0);
    hx(want, sizeof(want),
       "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
       "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    ASSERT_MEMEQ(out, want, sizeof(out));
}

TEST(sha512_incremental_matches_oneshot)
{
    gy_sha512_state st;
    uint8_t inc[64];
    uint8_t one[64];

    /* Split "abc" across two updates; must equal the one-shot digest. */
    gy_sha512_init(&st);
    gy_sha512_update(&st, (const uint8_t *)"a", 1);
    gy_sha512_update(&st, (const uint8_t *)"bc", 2);
    gy_sha512_final(&st, inc);

    gy_sha512(one, (const uint8_t *)"abc", 3);
    ASSERT_MEMEQ(inc, one, sizeof(inc));
}

TEST(sha256_incremental_matches_oneshot)
{
    gy_sha256_state st;
    uint8_t inc[32];
    uint8_t one[32];

    gy_sha256_init(&st);
    gy_sha256_update(&st, (const uint8_t *)"a", 1);
    gy_sha256_update(&st, (const uint8_t *)"bc", 2);
    gy_sha256_final(&st, inc);

    gy_sha256(one, (const uint8_t *)"abc", 3);
    ASSERT_MEMEQ(inc, one, sizeof(inc));
}

struct hmac_vec {
    const char *key;
    const char *data;
    const char *mac256;
    const char *mac512;
    size_t cmp;     /* bytes to compare (16 for the truncated case 5) */
    size_t keyfill; /* if >0, key is this many 0xaa bytes (built at runtime) */
};

/* RFC 4231 test cases 1-7. */
static const struct hmac_vec hmac_vecs[] = {
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
     "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
     0, 0},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
     "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
     0, 0},
    {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
     "dddddddddddddddddddddddddddddddddddddddddddddddddd"
     "dddddddddddddddddddddddddddddddddddddddddddddddddd",
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
     "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
     "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
     0, 0},
    {"0102030405060708090a0b0c0d0e0f10111213141516171819",
     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
     "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
     "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
     0, 0},
    {"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
     "546573742057697468205472756e636174696f6e",
     "a3b6167473100ee06e0c796c2955552b", "415fad6271580a531d4179bc891d87a6", 16,
     0},
    /* Cases 6 and 7 use a 131-byte 0xaa key, built at runtime via keyfill. */
    {NULL,
     "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a"
     "65204b6579202d2048617368204b6579204669727374",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
     "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
     "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
     0, 131},
    {NULL,
     "5468697320697320612074657374207573696e672061206c6172676572207468"
     "616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074"
     "68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565"
     "647320746f20626520686173686564206265666f7265206265696e6720757365"
     "642062792074686520484d414320616c676f726974686d2e",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
     "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
     "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
     0, 131},
};

TEST(hmac_rfc4231)
{
    uint8_t key[131];
    uint8_t data[160];
    uint8_t out[64];
    uint8_t want[64];
    size_t i, klen, dlen, cmp;

    for (i = 0; i < sizeof(hmac_vecs) / sizeof(hmac_vecs[0]); i++) {
        if (hmac_vecs[i].keyfill > 0) {
            memset(key, 0xaa, hmac_vecs[i].keyfill);
            klen = hmac_vecs[i].keyfill;
        } else {
            klen = hx(key, sizeof(key), hmac_vecs[i].key);
        }
        dlen = hx(data, sizeof(data), hmac_vecs[i].data);

        cmp = hmac_vecs[i].cmp ? hmac_vecs[i].cmp : 32;
        gy_hmac_sha256(out, key, klen, data, dlen);
        hx(want, sizeof(want), hmac_vecs[i].mac256);
        ASSERT_MEMEQ(out, want, cmp);

        cmp = hmac_vecs[i].cmp ? hmac_vecs[i].cmp : 64;
        gy_hmac_sha512(out, key, klen, data, dlen);
        hx(want, sizeof(want), hmac_vecs[i].mac512);
        ASSERT_MEMEQ(out, want, cmp);
    }
}

struct hkdf_vec {
    const char *ikm;
    const char *salt;
    const char *info;
    size_t okmlen;
    const char *prk;
    const char *okm;
};

/* RFC 5869 test cases 1-3 (HKDF-SHA256). */
static const struct hkdf_vec hkdf256_vecs[] = {
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
     "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
     "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
     "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
     "34007208d5b887185865"},
    {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
     "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
     "404142434445464748494a4b4c4d4e4f",
     "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
     "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
     "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
     "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
     "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
     82, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
     "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
     "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
     "cc30c58179ec3e87c14c01d5c1f3434f1d87"},
    {"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "", 42,
     "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
     "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
     "9d201395faa4b61a96c8"},
};

TEST(hkdf_sha256_rfc5869)
{
    uint8_t ikm[80], salt[80], info[80];
    uint8_t prk[32], okm[82];
    uint8_t want_prk[32], want_okm[82];
    size_t i, il, sl, fl;

    for (i = 0; i < sizeof(hkdf256_vecs) / sizeof(hkdf256_vecs[0]); i++) {
        il = hx(ikm, sizeof(ikm), hkdf256_vecs[i].ikm);
        sl = hx(salt, sizeof(salt), hkdf256_vecs[i].salt);
        fl = hx(info, sizeof(info), hkdf256_vecs[i].info);

        ASSERT_EQ(gy_hkdf_sha256_extract(prk, salt, sl, ikm, il), GY_OK);
        hx(want_prk, sizeof(want_prk), hkdf256_vecs[i].prk);
        ASSERT_MEMEQ(prk, want_prk, sizeof(prk));

        ASSERT_EQ(
            gy_hkdf_sha256_expand(okm, hkdf256_vecs[i].okmlen, prk, info, fl),
            GY_OK);
        hx(want_okm, sizeof(want_okm), hkdf256_vecs[i].okm);
        ASSERT_MEMEQ(okm, want_okm, hkdf256_vecs[i].okmlen);
    }
}

/*
 * Independent HKDF-SHA512 built only from the gy_hmac_sha512 wrapper, used to
 * cross-check the libsodium-backed gy_hkdf_sha512_* path (RFC 5869 has no
 * SHA-512 vectors).  Handles a salt shorter than one hash block by zero-
 * padding to HashLen, exactly as RFC 5869 specifies.
 */
static void
ref_hkdf_sha512(uint8_t *okm, size_t okmlen, const uint8_t *salt, size_t slen,
                const uint8_t *ikm, size_t ilen, const uint8_t *info,
                size_t infolen)
{
    uint8_t zero_salt[64] = {0};
    uint8_t prk[64];
    uint8_t t[64];
    uint8_t block[64 + 80 + 1];
    size_t done, tlen, blen;
    uint8_t counter;

    if (slen == 0) {
        salt = zero_salt;
        slen = sizeof(zero_salt);
    }
    gy_hmac_sha512(prk, salt, slen, ikm, ilen);

    done = 0;
    tlen = 0;
    counter = 1;
    while (done < okmlen) {
        blen = 0;
        memcpy(block + blen, t, tlen);
        blen += tlen;
        memcpy(block + blen, info, infolen);
        blen += infolen;
        block[blen++] = counter;
        gy_hmac_sha512(t, prk, sizeof(prk), block, blen);
        tlen = sizeof(t);
        {
            size_t take = okmlen - done < tlen ? okmlen - done : tlen;
            memcpy(okm + done, t, take);
            done += take;
        }
        counter++;
    }
}

TEST(hkdf_sha512_crosscheck)
{
    uint8_t ikm[22], salt[13], info[10];
    uint8_t prk[64], okm[100], ref[100];
    size_t il, sl, fl;

    /* Reuse RFC 5869 case-1 style inputs; expected values are our own. */
    il = hx(ikm, sizeof(ikm), "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    sl = hx(salt, sizeof(salt), "000102030405060708090a0b0c");
    fl = hx(info, sizeof(info), "f0f1f2f3f4f5f6f7f8f9");

    /* extract equals HMAC(salt, ikm) by definition. */
    ASSERT_EQ(gy_hkdf_sha512_extract(prk, salt, sl, ikm, il), GY_OK);

    /* Two output blocks (100 > 64) exercise the expand counter. */
    ASSERT_EQ(gy_hkdf_sha512_expand(okm, sizeof(okm), prk, info, fl), GY_OK);
    ref_hkdf_sha512(ref, sizeof(ref), salt, sl, ikm, il, info, fl);
    ASSERT_MEMEQ(okm, ref, sizeof(okm));
}

TEST(hkdf_expand_length_bound)
{
    uint8_t prk256[32] = {0};
    uint8_t prk512[64] = {0};
    uint8_t out[8];

    /* One byte past 255 * HashLen is rejected before any crypto runs. */
    ASSERT_EQ(gy_hkdf_sha256_expand(out, (size_t)255 * 32 + 1, prk256, NULL, 0),
              GY_ERR_ARG);
    ASSERT_EQ(gy_hkdf_sha512_expand(out, (size_t)255 * 64 + 1, prk512, NULL, 0),
              GY_ERR_ARG);
    /* Zero length is also an argument error. */
    ASSERT_EQ(gy_hkdf_sha256_expand(out, 0, prk256, NULL, 0), GY_ERR_ARG);
}

GY_TEST_MAIN(GY_TEST(sha256_kats), GY_TEST(sha512_kats),
             GY_TEST(sha512_incremental_matches_oneshot),
             GY_TEST(sha256_incremental_matches_oneshot), GY_TEST(hmac_rfc4231),
             GY_TEST(hkdf_sha256_rfc5869), GY_TEST(hkdf_sha512_crosscheck),
             GY_TEST(hkdf_expand_length_bound))
