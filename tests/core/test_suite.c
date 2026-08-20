/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/suite.c and the iov hash variants in src/core/hash.c
 * (D-GEN-7, D-X3DH-7).  The suite table is validated for
 * self-consistency against the libsodium provider constants; the iov HMAC /
 * HKDF-Extract paths are re-run over the RFC 4231 / RFC 5869 inputs split at
 * every boundary of a 3-part split and checked byte-identical to the flat
 * wrappers.
 */

#include <stdint.h>
#include <string.h>

#include <sodium.h>

#include "encode.h"
#include "error.h"
#include "hash.h"
#include "suite.h"

#include "gy_test.h"

/* Decode hex into buf, asserting it fits, and return the byte length. */
static size_t
hx(uint8_t *buf, size_t cap, const char *hex)
{
    int n = gy_hex_decode(buf, cap, hex);
    return n < 0 ? 0 : (size_t)n;
}

TEST(c25519_self_consistency)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);

    ASSERT_TRUE(d != NULL, "c25519 present");

    /* Identity matches the D-GEN-1 table. */
    ASSERT_EQ(d->suite_id, GY_SUITE_C25519);
    ASSERT_EQ(d->curve_type, GY_CURVE_TYPE_25519);
    ASSERT_EQ(d->is_hybrid, 0);
    ASSERT_TRUE(strcmp(d->name, "c25519") == 0, "name c25519");

    /* Sizes equal the provider constants (self-consistency, D-GEN-7). */
    ASSERT_EQ(d->curve_pk_len, crypto_scalarmult_curve25519_BYTES);
    ASSERT_EQ(d->curve_sk_len, crypto_scalarmult_curve25519_SCALARBYTES);
    ASSERT_EQ(d->dh_len, crypto_scalarmult_curve25519_BYTES);
    ASSERT_EQ(d->sig_len, crypto_sign_BYTES);
    ASSERT_EQ(d->hash_len, crypto_hash_sha256_BYTES);
    ASSERT_EQ(d->f_len, 32);

    /* Every size fits its compile-time maximum. */
    ASSERT_TRUE(d->curve_pk_len <= GY_CURVE_PK_MAX, "pk <= max");
    ASSERT_TRUE(d->curve_sk_len <= GY_CURVE_SK_MAX, "sk <= max");
    ASSERT_TRUE(d->dh_len <= GY_DH_MAX, "dh <= max");
    ASSERT_TRUE(d->sig_len <= GY_SIG_MAX, "sig <= max");
    ASSERT_TRUE(d->hash_len <= GY_HASH_MAX, "hash <= max");
    ASSERT_TRUE(d->f_len <= GY_F_MAX, "f <= max");

    /* Classical ops present. */
    ASSERT_TRUE(d->keypair != NULL, "keypair set");
    ASSERT_TRUE(d->dh != NULL, "dh set");
    ASSERT_TRUE(d->sign != NULL, "sign set");
    ASSERT_TRUE(d->verify != NULL, "verify set");
    ASSERT_TRUE(d->hash != NULL, "hash set");
    ASSERT_TRUE(d->hmac != NULL, "hmac set");
    ASSERT_TRUE(d->hkdf_extract != NULL, "hkdf_extract set");
    ASSERT_TRUE(d->hkdf_expand != NULL, "hkdf_expand set");

    /* Hybrid sizes zero and ops NULL in a classical row. */
    ASSERT_EQ(d->kem_pk_len, 0);
    ASSERT_EQ(d->kem_sk_len, 0);
    ASSERT_EQ(d->kem_ct_len, 0);
    ASSERT_EQ(d->kem_ss_len, 0);
    ASSERT_EQ(d->dsa_pk_len, 0);
    ASSERT_EQ(d->dsa_sk_len, 0);
    ASSERT_EQ(d->dsa_sig_len, 0);
    ASSERT_TRUE(d->kem_keypair == NULL, "kem_keypair NULL");
    ASSERT_TRUE(d->kem_encap == NULL, "kem_encap NULL");
    ASSERT_TRUE(d->kem_decap == NULL, "kem_decap NULL");
    ASSERT_TRUE(d->dsa_sign == NULL, "dsa_sign NULL");
    ASSERT_TRUE(d->dsa_verify == NULL, "dsa_verify NULL");
}

TEST(enabled_suites)
{
    unsigned i;

    /* c25519 (0x01) and h25519_512 (0x02) resolve; every other byte is NULL. */
    for (i = 0; i <= 0xff; i++) {
        const struct gy_suite_desc *d = gy_suite_desc((uint8_t)i);
        if (i == GY_SUITE_C25519 || i == GY_SUITE_H25519_512)
            ASSERT_TRUE(d != NULL, "25519-tier suite enabled");
        else
            ASSERT_TRUE(d == NULL, "other suite NULL");
    }
}

TEST(suite_f_prefix)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    uint8_t out[GY_F_MAX];
    uint8_t want[GY_F_MAX];
    size_t i;

    memset(out, 0x00, sizeof(out));
    ASSERT_EQ(gy_suite_f(d, out), GY_OK);

    memset(want, 0xff, d->f_len);
    ASSERT_MEMEQ(out, want, d->f_len);
    /* f_len bytes exactly are 0xFF. */
    for (i = 0; i < d->f_len; i++)
        ASSERT_EQ(out[i], 0xff);

    /* NULL arguments reject. */
    ASSERT_EQ(gy_suite_f(NULL, out), GY_ERR_ARG);
    ASSERT_EQ(gy_suite_f(d, NULL), GY_ERR_ARG);
}

/*
 * Run gy_hmac_sha256_iov over data split into every prefix/middle/suffix
 * 3-part arrangement and assert each equals the flat gy_hmac_sha256 output.
 */
static void
hmac256_all_splits(const uint8_t *key, size_t klen, const uint8_t *data,
                   size_t dlen)
{
    uint8_t flat[32], got[32];
    size_t a, b;

    gy_hmac_sha256(flat, key, klen, data, dlen);
    for (a = 0; a <= dlen; a++) {
        for (b = a; b <= dlen; b++) {
            struct gy_iov iov[3] = {
                {data, a},
                {data + a, b - a},
                {data + b, dlen - b},
            };
            ASSERT_EQ(gy_hmac_sha256_iov(got, key, klen, iov, 3), GY_OK);
            ASSERT_MEMEQ(got, flat, sizeof(flat));
        }
    }
}

static void
hmac512_all_splits(const uint8_t *key, size_t klen, const uint8_t *data,
                   size_t dlen)
{
    uint8_t flat[64], got[64];
    size_t a, b;

    gy_hmac_sha512(flat, key, klen, data, dlen);
    for (a = 0; a <= dlen; a++) {
        for (b = a; b <= dlen; b++) {
            struct gy_iov iov[3] = {
                {data, a},
                {data + a, b - a},
                {data + b, dlen - b},
            };
            ASSERT_EQ(gy_hmac_sha512_iov(got, key, klen, iov, 3), GY_OK);
            ASSERT_MEMEQ(got, flat, sizeof(flat));
        }
    }
}

TEST(hmac_iov_matches_flat)
{
    uint8_t key[32], data[64];
    size_t klen, dlen;

    /* RFC 4231 case 2. */
    klen = hx(key, sizeof(key), "4a656665");
    dlen = hx(data, sizeof(data),
              "7768617420646f2079612077616e7420666f72206e6f7468696e673f");
    hmac256_all_splits(key, klen, data, dlen);
    hmac512_all_splits(key, klen, data, dlen);

    /* Empty message: niov 0 and a single empty element both match flat. */
    {
        uint8_t flat[32], got[32];
        struct gy_iov empty = {NULL, 0};
        gy_hmac_sha256(flat, key, klen, NULL, 0);
        ASSERT_EQ(gy_hmac_sha256_iov(got, key, klen, NULL, 0), GY_OK);
        ASSERT_MEMEQ(got, flat, sizeof(flat));
        ASSERT_EQ(gy_hmac_sha256_iov(got, key, klen, &empty, 1), GY_OK);
        ASSERT_MEMEQ(got, flat, sizeof(flat));
    }
}

TEST(hkdf_extract_iov_matches_flat)
{
    uint8_t salt[16], ikm[32];
    uint8_t flat256[32], got256[32];
    uint8_t flat512[64], got512[64];
    size_t slen, ilen, a, b;

    /* RFC 5869 case 1 inputs. */
    slen = hx(salt, sizeof(salt), "000102030405060708090a0b0c");
    ilen = hx(ikm, sizeof(ikm), "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");

    gy_hkdf_sha256_extract(flat256, salt, slen, ikm, ilen);
    gy_hkdf_sha512_extract(flat512, salt, slen, ikm, ilen);

    for (a = 0; a <= ilen; a++) {
        for (b = a; b <= ilen; b++) {
            struct gy_iov iov[3] = {
                {ikm, a},
                {ikm + a, b - a},
                {ikm + b, ilen - b},
            };
            ASSERT_EQ(gy_hkdf_sha256_extract_iov(got256, salt, slen, iov, 3),
                      GY_OK);
            ASSERT_MEMEQ(got256, flat256, sizeof(flat256));
            ASSERT_EQ(gy_hkdf_sha512_extract_iov(got512, salt, slen, iov, 3),
                      GY_OK);
            ASSERT_MEMEQ(got512, flat512, sizeof(flat512));
        }
    }

    /* Empty salt (RFC 5869 zero-salt rule) still matches the flat path. */
    {
        struct gy_iov iov = {ikm, ilen};
        gy_hkdf_sha256_extract(flat256, NULL, 0, ikm, ilen);
        ASSERT_EQ(gy_hkdf_sha256_extract_iov(got256, NULL, 0, &iov, 1), GY_OK);
        ASSERT_MEMEQ(got256, flat256, sizeof(flat256));
    }
}

GY_TEST_MAIN(GY_TEST(c25519_self_consistency), GY_TEST(enabled_suites),
             GY_TEST(suite_f_prefix), GY_TEST(hmac_iov_matches_flat),
             GY_TEST(hkdf_extract_iov_matches_flat))
