/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/ratchet/he.c (D-DR-15):
 * HENCRYPT/HDECRYPT over a caller-owned header key.  Byte-level wire vectors
 * are pinned by the checked-in self-KATs (dr_he_self.vec,
 * D-GEN-6); here we pin the KDF-CTR layout and the enc_header size and assert
 * that gy_he_encrypt/decrypt compose derive-and-seal exactly, plus the
 * negative matrix and the salt-uniqueness smoke test.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "header.h"
#include "he.h"

#include "gy_test.h"

/*
 * Pinned self-KATs, print-if-unpinned pattern (D-GEN-6): with
 * a vector's *_PINNED flag at 0 the test prints the computed hex to paste in
 * below and skips the compare; flip the flag to 1 once the bytes are filled
 * and the value is asserted on every run.  These pin the real HMAC-chain
 * output, complementing the composition recompute checks.  Fixed inputs: the
 * HK below, aead_id 0x01 (ChaCha20-Poly1305), suite c25519, and the named
 * salts / header fill.
 */
#define KAT_KEYNONCE_PINNED 1
#define KAT_ENCHEADER_PINNED 1

#if KAT_KEYNONCE_PINNED
/* he.aead key||nonce: HK, salt = 0x5a x16, aead_id 0x01. */
static const uint8_t KAT_keynonce[44] = {
    0xb1, 0x48, 0xeb, 0xe5, 0xa7, 0x65, 0x88, 0xc0, 0x17, 0x3c, 0x76,
    0xdc, 0x1c, 0xce, 0x16, 0x81, 0x99, 0xc4, 0x47, 0xd2, 0x5d, 0x7e,
    0xaf, 0x1a, 0xf8, 0x3b, 0xcc, 0xbd, 0x39, 0x74, 0x1b, 0xd7, 0xad,
    0xf4, 0x98, 0x42, 0x6d, 0x79, 0xd8, 0xc7, 0x5e, 0x83, 0x51, 0x90,
};
#endif
#if KAT_ENCHEADER_PINNED
/* 60-byte classical enc_header: HK, salt = 0x77 x16, header 0x40.., aead 0x01. */
static const uint8_t KAT_encheader[60] = {
    0xaf, 0x1d, 0x21, 0xb8, 0x35, 0x06, 0x24, 0x07, 0xc2, 0x6f, 0xc8, 0x02,
    0xf4, 0xb4, 0xe4, 0x7a, 0x07, 0xa6, 0x65, 0x1c, 0x5a, 0x1c, 0x7b, 0x49,
    0x7b, 0x05, 0x1d, 0x17, 0x81, 0xbf, 0xb4, 0xc8, 0xa5, 0x37, 0x7a, 0xdd,
    0xbc, 0x8d, 0x42, 0x7a, 0x88, 0xec, 0x05, 0x8a, 0xba, 0x2c, 0x08, 0xdf,
    0x3f, 0x2e, 0xff, 0x57, 0x89, 0xbd, 0x95, 0x3a, 0x85, 0x16, 0x76, 0x79,
};
#endif

#if !defined(KAT_KEYNONCE_PINNED) || !defined(KAT_ENCHEADER_PINNED)
static void
dump_hex(const char *label, const uint8_t *b, size_t n)
{
    size_t i;

    fprintf(stderr, "PIN %s (%zu bytes):\n    ", label, n);
    for (i = 0; i < n; i++)
        fprintf(stderr, "0x%02x,%s", b[i], (i % 12 == 11) ? "\n    " : " ");
    fprintf(stderr, "\n");
}
#endif

/* Fixed hdr_salt seam so the deterministic KATs are reproducible. */
static uint8_t g_fixed_salt[GY_HE_SALT_LEN];

static int
fixed_salt(uint8_t *out, size_t n)
{
    if (n != GY_HE_SALT_LEN)
        return GY_ERR_ARG;
    memcpy(out, g_fixed_salt, n);
    return GY_OK;
}

static const struct gy_suite_desc *D; /* geryon_c25519 */

/* A representative classical header plaintext (opaque to HE) and its key. */
static const uint8_t HK[32] = {
    0x9e, 0x3f, 0x14, 0xc7, 0x52, 0x0a, 0xdb, 0x88, 0x61, 0x4d, 0x2f,
    0xb0, 0x0c, 0x93, 0x77, 0xa1, 0x5c, 0xe8, 0x36, 0x49, 0xba, 0x1e,
    0xd5, 0x70, 0x2b, 0x84, 0xf6, 0x19, 0xcd, 0x40, 0x63, 0x8a,
};

static size_t
header_len(void)
{
    return 4 + D->curve_pk_len + 8; /* flags || curve_pk || pn || n */
}

static void
fill_header(uint8_t *h, size_t hlen)
{
    for (size_t i = 0; i < hlen; i++)
        h[i] = (uint8_t)(0x40 + i);
}

/*
 * D-DR-15 derivation layout: key||nonce = KDF-CTR(hk, INFO("he.aead"),
 * aead_id || hdr_salt).  Recompute independently through the primitives and
 * assert gy_he_derive matches, pinning the Label and Context byte order.
 */
TEST(derive_layout)
{
    uint8_t info[48], ctx[1 + GY_HE_SALT_LEN];
    uint8_t exp[32 + GY_AEAD_MAX_NONCE];
    uint8_t key[32], nonce[GY_AEAD_MAX_NONCE];
    size_t infolen, nl, got_nl;

    memset(g_fixed_salt, 0x5a, sizeof(g_fixed_salt));

    nl = gy_aead_nonce_len(GY_AEAD_CHACHA20POLY1305);
    ASSERT_EQ(nl, 12);

    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "he.aead"),
              GY_OK);
    ctx[0] = GY_AEAD_CHACHA20POLY1305;
    memcpy(ctx + 1, g_fixed_salt, GY_HE_SALT_LEN);
    ASSERT_EQ(
        gy_kdf_ctr(D, exp, 32 + nl, HK, 32, info, infolen, ctx, sizeof(ctx)),
        GY_OK);

    ASSERT_EQ(gy_he_derive(D, GY_AEAD_CHACHA20POLY1305, HK, g_fixed_salt, key,
                           nonce, &got_nl),
              GY_OK);
    ASSERT_EQ(got_nl, nl);
    ASSERT_MEMEQ(key, exp, 32);
    ASSERT_MEMEQ(nonce, exp + 32, nl);
}

/*
 * Context separation (D-DR-3): the same (hk, salt) yields a distinct AEAD key
 * per aead_id, because aead_id is the first Context byte.  nonce_len does not
 * gate on hardware, so all three ids derive even where GCM is unavailable.
 */
TEST(context_separation)
{
    uint8_t k1[32], k2[32], k3[32], n[GY_AEAD_MAX_NONCE];
    size_t nl;

    memset(g_fixed_salt, 0x11, sizeof(g_fixed_salt));

    ASSERT_EQ(
        gy_he_derive(D, GY_AEAD_CHACHA20POLY1305, HK, g_fixed_salt, k1, n, &nl),
        GY_OK);
    ASSERT_EQ(gy_he_derive(D, GY_AEAD_AES256GCM, HK, g_fixed_salt, k2, n, &nl),
              GY_OK);
    ASSERT_EQ(gy_he_derive(D, GY_AEAD_AEGIS256, HK, g_fixed_salt, k3, n, &nl),
              GY_OK);

    ASSERT_TRUE(memcmp(k1, k2, 32) != 0, "0x01 vs 0x02 keys differ");
    ASSERT_TRUE(memcmp(k1, k3, 32) != 0, "0x01 vs 0x03 keys differ");
    ASSERT_TRUE(memcmp(k2, k3, 32) != 0, "0x02 vs 0x03 keys differ");
}

/*
 * gy_he_encrypt composes gen_salt + derive + seal: with the salt fixed, the
 * output must equal an independently derived-and-sealed enc_header, and the
 * classical enc_header size is pinned (44-byte header + 16-byte tag = 60).
 */
TEST(encrypt_composition_and_size)
{
    uint8_t header[GY_DR_HEADER_MAX];
    uint8_t key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t enc_exp[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    uint8_t out_salt[GY_HE_SALT_LEN];
    uint8_t out_enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    const uint8_t ad2[2] = {GY_WIRE_VERSION, 0};
    size_t hlen, nl, exp_len, out_len;
    uint8_t *ad = (uint8_t *)ad2;

    ad[1] = D->suite_id;
    hlen = header_len();
    fill_header(header, hlen);
    memset(g_fixed_salt, 0x77, sizeof(g_fixed_salt));
    gy_he_test_salt = fixed_salt;

    /* Independent derive-and-seal. */
    ASSERT_EQ(gy_he_derive(D, GY_AEAD_CHACHA20POLY1305, HK, g_fixed_salt, key,
                           nonce, &nl),
              GY_OK);
    exp_len = sizeof(enc_exp);
    ASSERT_EQ(gy_aead_encrypt(GY_AEAD_CHACHA20POLY1305, enc_exp, &exp_len, key,
                              nonce, nl, ad2, 2, header, hlen),
              GY_OK);

    ASSERT_EQ(gy_he_encrypt(D, GY_AEAD_CHACHA20POLY1305, HK, header, hlen, ad2,
                            out_salt, out_enc, sizeof(out_enc), &out_len),
              GY_OK);
    ASSERT_MEMEQ(out_salt, g_fixed_salt, GY_HE_SALT_LEN);
    ASSERT_EQ(out_len, hlen + 16); /* classical c25519: 44 + 16 = 60 */
    ASSERT_EQ(out_len, exp_len);
    ASSERT_MEMEQ(out_enc, enc_exp, out_len);

    gy_he_test_salt = NULL;
}

/*
 * Pinned HMAC-chain KATs (print-if-unpinned): the true he.aead key||nonce and
 * the 60-byte classical enc_header for the fixed inputs above.  Unlike the
 * recompute checks these catch drift in the shared KDF-CTR/AEAD primitives.
 */
TEST(pinned_vectors)
{
    uint8_t salt[GY_HE_SALT_LEN], kn[32 + 12];
    uint8_t key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t header[GY_DR_HEADER_MAX], out_salt[GY_HE_SALT_LEN];
    uint8_t enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    const uint8_t ad2[2] = {GY_WIRE_VERSION, GY_SUITE_C25519};
    size_t nl, hlen, out_len;

    /* key||nonce vector. */
    memset(salt, 0x5a, sizeof(salt));
    ASSERT_EQ(
        gy_he_derive(D, GY_AEAD_CHACHA20POLY1305, HK, salt, key, nonce, &nl),
        GY_OK);
    ASSERT_EQ(nl, 12);
    memcpy(kn, key, 32);
    memcpy(kn + 32, nonce, 12);
#if KAT_KEYNONCE_PINNED
    ASSERT_MEMEQ(kn, KAT_keynonce, sizeof(kn));
#else
    dump_hex("he.aead key||nonce c25519 HK salt=0x5a*16 aead=0x01", kn,
             sizeof(kn));
#endif

    /* enc_header vector. */
    hlen = header_len();
    fill_header(header, hlen);
    memset(g_fixed_salt, 0x77, sizeof(g_fixed_salt));
    gy_he_test_salt = fixed_salt;
    ASSERT_EQ(gy_he_encrypt(D, GY_AEAD_CHACHA20POLY1305, HK, header, hlen, ad2,
                            out_salt, enc, sizeof(enc), &out_len),
              GY_OK);
    gy_he_test_salt = NULL;
    ASSERT_EQ(out_len, 60);
#if KAT_ENCHEADER_PINNED
    ASSERT_MEMEQ(enc, KAT_encheader, 60);
#else
    dump_hex("enc_header c25519 HK salt=0x77*16 header=0x40.. aead=0x01", enc,
             60);
#endif
}

/* Round-trip over both classical suites with a real (unseamed) RNG salt. */
TEST(round_trip_both_suites)
{
    const uint8_t ids[2] = {GY_SUITE_C25519, GY_SUITE_C448};

    gy_he_test_salt = NULL;
    for (size_t s = 0; s < 2; s++) {
        const struct gy_suite_desc *d = gy_suite_desc(ids[s]);
        uint8_t header[GY_DR_HEADER_MAX], got[GY_DR_HEADER_MAX];
        uint8_t enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
        uint8_t salt[GY_HE_SALT_LEN];
        const uint8_t ad2[2] = {GY_WIRE_VERSION, ids[s]};
        size_t hlen, enclen, gotlen;

        /* c448 primitives (X448/Ed448); skip until its descriptor
         * exists.  HE is suite-generic, so this auto-covers c448 then. */
        if (d == NULL)
            continue;
        hlen = 4 + d->curve_pk_len + 8;
        for (size_t i = 0; i < hlen; i++)
            header[i] = (uint8_t)(0x30 + i);

        ASSERT_EQ(gy_he_encrypt(d, GY_AEAD_CHACHA20POLY1305, HK, header, hlen,
                                ad2, salt, enc, sizeof(enc), &enclen),
                  GY_OK);
        ASSERT_EQ(enclen, hlen + 16);
        ASSERT_EQ(gy_he_decrypt(d, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                                enclen, ad2, got, sizeof(got), &gotlen),
                  GY_OK);
        ASSERT_EQ(gotlen, hlen);
        ASSERT_MEMEQ(got, header, hlen);
    }
}

/* Encrypt a baseline (fixed salt) for the negative matrix to tamper with. */
static void
seal_baseline(uint8_t aead_id, const uint8_t ad2[2], uint8_t *header,
              size_t hlen, uint8_t *salt, uint8_t *enc, size_t *enclen)
{
    memset(g_fixed_salt, 0x33, GY_HE_SALT_LEN);
    gy_he_test_salt = fixed_salt;
    fill_header(header, hlen);
    (void)gy_he_encrypt(D, aead_id, HK, header, hlen, ad2, salt, enc,
                        GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG, enclen);
    gy_he_test_salt = NULL;
}

/*
 * Negative matrix: wrong hk, flipped salt byte, flipped enc byte, flipped tag
 * byte, wrong ad2 (version and suite each), and wrong aead_id all fail, and no
 * plaintext header is released on any failing path.
 */
TEST(negative_matrix)
{
    uint8_t header[GY_DR_HEADER_MAX], salt[GY_HE_SALT_LEN];
    uint8_t enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    uint8_t out[GY_DR_HEADER_MAX];
    uint8_t bad_hk[32];
    uint8_t ad2[2] = {GY_WIRE_VERSION, 0};
    size_t hlen = header_len(), enclen, outlen;
    int rc;

    ad2[1] = D->suite_id;
    seal_baseline(GY_AEAD_CHACHA20POLY1305, ad2, header, hlen, salt, enc,
                  &enclen);
    ASSERT_EQ(enclen, hlen + 16);

/*
 * Every failing decrypt must release no plaintext: gy_aead_decrypt zeroes the
 * output on verification failure (it does not leave it untouched, aead.c), and
 * the early-return paths leave the 0x5a poison, so in both cases `out` must
 * differ from the true header.
 */
#define EXPECT_FAIL(call, want)                                                \
    do {                                                                       \
        memset(out, 0x5a, sizeof(out));                                        \
        outlen = 0;                                                            \
        rc = (call);                                                           \
        ASSERT_EQ(rc, (want));                                                 \
        ASSERT_TRUE(memcmp(out, header, hlen) != 0, "no plaintext on fail");   \
    } while (0)

    /* Baseline succeeds. */
    ASSERT_EQ(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc, enclen,
                            ad2, out, sizeof(out), &outlen),
              GY_OK);
    ASSERT_EQ(outlen, hlen);

    /* Wrong hk. */
    memcpy(bad_hk, HK, 32);
    bad_hk[0] ^= 0x01;
    EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, bad_hk, salt, enc,
                              enclen, ad2, out, sizeof(out), &outlen),
                GY_ERR_VERIFY);

    /* Flipped salt byte. */
    salt[3] ^= 0x01;
    EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                              enclen, ad2, out, sizeof(out), &outlen),
                GY_ERR_VERIFY);
    salt[3] ^= 0x01;

    /* Flipped enc (header ciphertext) byte. */
    enc[0] ^= 0x01;
    EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                              enclen, ad2, out, sizeof(out), &outlen),
                GY_ERR_VERIFY);
    enc[0] ^= 0x01;

    /* Flipped tag byte (last byte of enc). */
    enc[enclen - 1] ^= 0x01;
    EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                              enclen, ad2, out, sizeof(out), &outlen),
                GY_ERR_VERIFY);
    enc[enclen - 1] ^= 0x01;

    /* Wrong ad2 version. */
    {
        uint8_t bad_ad[2] = {GY_WIRE_VERSION + 1, D->suite_id};
        EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                                  enclen, bad_ad, out, sizeof(out), &outlen),
                    GY_ERR_VERIFY);
    }

    /* Wrong ad2 suite. */
    {
        uint8_t bad_ad[2] = {GY_WIRE_VERSION, GY_SUITE_C448};
        EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, salt, enc,
                                  enclen, bad_ad, out, sizeof(out), &outlen),
                    GY_ERR_VERIFY);
    }

    /* Wrong aead_id (0x03 always available; wrong key/nonce/tag-len -> fail). */
    EXPECT_FAIL(gy_he_decrypt(D, GY_AEAD_AEGIS256, HK, salt, enc, enclen, ad2,
                              out, sizeof(out), &outlen),
                GY_ERR_VERIFY);

    /* Unknown aead_id is rejected outright. */
    EXPECT_FAIL(gy_he_decrypt(D, 0x7f, HK, salt, enc, enclen, ad2, out,
                              sizeof(out), &outlen),
                GY_ERR_UNSUPPORTED);

#undef EXPECT_FAIL
}

/* Truncated enc (shorter than the tag) is rejected, out untouched. */
TEST(short_ciphertext)
{
    uint8_t out[GY_DR_HEADER_MAX];
    uint8_t enc[8] = {0};
    const uint8_t ad2[2] = {GY_WIRE_VERSION, GY_SUITE_C25519};
    size_t outlen = 0;

    memset(out, 0x5a, sizeof(out));
    ASSERT_EQ(gy_he_decrypt(D, GY_AEAD_CHACHA20POLY1305, HK, g_fixed_salt, enc,
                            sizeof(enc), ad2, out, sizeof(out), &outlen),
              GY_ERR_VERIFY);
    for (size_t i = 0; i < sizeof(out); i++)
        ASSERT_TRUE(out[i] == 0x5a, "no header on short ct");
}

/* Short output buffer on encrypt is rejected before any RNG/derivation. */
TEST(encrypt_short_buffer)
{
    uint8_t header[GY_DR_HEADER_MAX], salt[GY_HE_SALT_LEN];
    uint8_t enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    const uint8_t ad2[2] = {GY_WIRE_VERSION, GY_SUITE_C25519};
    size_t hlen = header_len(), outlen;

    gy_he_test_salt = NULL;
    fill_header(header, hlen);
    ASSERT_EQ(gy_he_encrypt(D, GY_AEAD_CHACHA20POLY1305, HK, header, hlen, ad2,
                            salt, enc, hlen + 15, &outlen),
              GY_ERR_ARG);
}

/*
 * Salt-uniqueness smoke test (D-DR-15): a batch of gy_he_encrypt calls under
 * the real RNG produce pairwise-distinct salts.  This is a birthday smoke
 * test at 2^-30 scale, not the 2^64 proof (that is D-DR-15's argument).
 */
#define SALT_N 100000
static uint8_t g_salts[SALT_N][GY_HE_SALT_LEN];

static int
salt_cmp(const void *a, const void *b)
{
    return memcmp(a, b, GY_HE_SALT_LEN);
}

TEST(salt_uniqueness)
{
    uint8_t header[GY_DR_HEADER_MAX];
    uint8_t enc[GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG];
    const uint8_t ad2[2] = {GY_WIRE_VERSION, GY_SUITE_C25519};
    size_t hlen = header_len(), enclen, k;

    gy_he_test_salt = NULL;
    fill_header(header, hlen);
    for (k = 0; k < SALT_N; k++)
        ASSERT_EQ(gy_he_encrypt(D, GY_AEAD_CHACHA20POLY1305, HK, header, hlen,
                                ad2, g_salts[k], enc, sizeof(enc), &enclen),
                  GY_OK);

    qsort(g_salts, SALT_N, GY_HE_SALT_LEN, salt_cmp);
    for (k = 1; k < SALT_N; k++)
        ASSERT_TRUE(memcmp(g_salts[k - 1], g_salts[k], GY_HE_SALT_LEN) != 0,
                    "salts distinct");
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_C25519);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(derive_layout),
            GY_TEST(context_separation),
            GY_TEST(encrypt_composition_and_size),
            GY_TEST(pinned_vectors),
            GY_TEST(round_trip_both_suites),
            GY_TEST(negative_matrix),
            GY_TEST(short_ciphertext),
            GY_TEST(encrypt_short_buffer),
            GY_TEST(salt_uniqueness),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
