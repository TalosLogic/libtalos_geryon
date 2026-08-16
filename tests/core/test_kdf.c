/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/kdf.c (SP 800-108 KDF in Counter Mode, D-DR-2).
 *
 * CAVP vectors: docs/KDFCTR_gen.txt (NIST CAVS 14.4 "SP800-108 - KDF",
 * generated 2013-04-23), section [PRF=HMAC_SHA256][CTRLOCATION=BEFORE_FIXED]
 * [RLEN=32_BITS].  Those vectors give FixedInputData as an opaque blob and the
 * counter as a 32-bit big-endian prefix, exactly the shape gy_kdf_ctr_raw
 * consumes.  COUNT=0 (L=128) exercises a single truncated block; the two
 * L=320 cases exercise the two-block counter increment; L=256 the exact
 * single-block boundary.
 *
 * The layout of the public gy_kdf_ctr (which prepends the D-DR-2 fixed input
 * [i]_32BE || Label || 0x00 || Context || [L]_32BE) is validated against an
 * independent in-test recomputation (kdf_ref), including the multi-block path
 * and the boundary outlen = 255 * hash_len.  With an empty Context this layout
 * is byte-identical to the archive's sp800_108_counter_mode
 * ([i]_32 || Label || 0x00 || [L]_32); archive_crosscheck reproduces one such
 * value, recomputed here rather than copied.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h"
#include "error.h"
#include "hash.h"
#include "kdf.h"
#include "suite.h"

#include "gy_test.h"

static size_t
hx(uint8_t *buf, size_t cap, const char *hex)
{
    int n = gy_hex_decode(buf, cap, hex);
    return n < 0 ? 0 : (size_t)n;
}

/*
 * Independent recomputation of the D-DR-2 counter-mode layout using only the
 * flat gy_hmac_sha256 wrapper, for validating gy_kdf_ctr's byte assembly.
 */
static void
kdf_ref(uint8_t *out, size_t outlen, const uint8_t *key, size_t klen,
        const uint8_t *label, size_t llen, const uint8_t *ctx, size_t clen)
{
    uint8_t buf[512];
    uint8_t block[32];
    size_t done, take, o;
    uint32_t i, lbits;

    lbits = (uint32_t)(outlen * 8);
    done = 0;
    i = 1;
    while (done < outlen) {
        o = 0;
        buf[o++] = (uint8_t)(i >> 24);
        buf[o++] = (uint8_t)(i >> 16);
        buf[o++] = (uint8_t)(i >> 8);
        buf[o++] = (uint8_t)i;
        if (llen > 0)
            memcpy(buf + o, label, llen);
        o += llen;
        buf[o++] = 0x00;
        if (clen > 0)
            memcpy(buf + o, ctx, clen);
        o += clen;
        buf[o++] = (uint8_t)(lbits >> 24);
        buf[o++] = (uint8_t)(lbits >> 16);
        buf[o++] = (uint8_t)(lbits >> 8);
        buf[o++] = (uint8_t)lbits;

        gy_hmac_sha256(block, key, klen, buf, o);
        take = outlen - done < sizeof(block) ? outlen - done : sizeof(block);
        memcpy(out + done, block, take);
        done += take;
        i++;
    }
}

struct ctr_vec {
    const char *ki;
    const char *fid;
    const char *ko;
    size_t outlen;
};

/* NIST CAVP, BEFORE_FIXED, RLEN=32_BITS, HMAC-SHA256 (docs/KDFCTR_gen.txt). */
static const struct ctr_vec ctr_vecs[] = {
    /* COUNT=0, L=128. */
    {"dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0",
     "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b8"
     "64a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac",
     "10621342bfb0fd40046c0e29f2cfdbf0", 16},
    /* L=256 (single block, exact). */
    {"e204d6d466aad507ffaf6d6dab0a5b26152c9e21e764370464e360c8fbc765c6",
     "7b03b98d9f94b899e591f3ef264b71b193fba7043c7e953cde23bc5384bc1a62"
     "93580115fae3495fd845dadbd02bd6455cf48d0f62b33e62364a3a80",
     "770dfab6a6a4a4bee0257ff335213f78d8287b4fd537d5c1fffa956910e7c779", 32},
    /* L=320 (two blocks, counter increments 1 -> 2). */
    {"c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac",
     "1c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacac"
     "e6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b",
     "1da47638d6c9c4d04d74d4640bbd42ab814d9e8cc22f4326695239f96b0693f1"
     "2d0dd1152cf44430",
     40},
    {"22256ca571d5c896db80a8758ff81cf8631d2bc38c7e76f3bafb0c2af540a356",
     "9dd2dcd97b926251b50c6111d988e2951b02accc143702c88920cf36848f7c73"
     "1756ab0537cb26e22725f11de069e5335802b0cb56c158dd75014791",
     "a11aa3b1a93d2ce117550866c28d6974cf626719385b8868101a71a5d2aa793b"
     "c23c3cfdebe52ec9",
     40},
};

TEST(cavp_raw_vectors)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    uint8_t ki[32], fid[60], ko[64], out[64];
    size_t i, kilen, fidlen, kolen;

    for (i = 0; i < sizeof(ctr_vecs) / sizeof(ctr_vecs[0]); i++) {
        struct gy_iov fixed;

        kilen = hx(ki, sizeof(ki), ctr_vecs[i].ki);
        fidlen = hx(fid, sizeof(fid), ctr_vecs[i].fid);
        kolen = hx(ko, sizeof(ko), ctr_vecs[i].ko);
        ASSERT_EQ(kolen, ctr_vecs[i].outlen);

        fixed.p = fid;
        fixed.len = fidlen;
        ASSERT_EQ(
            gy_kdf_ctr_raw(d, out, ctr_vecs[i].outlen, ki, kilen, &fixed, 1),
            GY_OK);
        ASSERT_MEMEQ(out, ko, ctr_vecs[i].outlen);
    }
}

TEST(layout_kat)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    uint8_t key[32];
    uint8_t got[48], want[48];
    const uint8_t *label = (const uint8_t *)"geryon.1.c25519.dr.msg";
    const uint8_t *ctx = (const uint8_t *)"\x01\x00\x00\x00\x07";
    size_t llen = strlen((const char *)label);
    size_t clen = 5;

    memset(key, 0x2b, sizeof(key));

    /* Single block: exact byte layout, incl. 0x00 separator and L-in-bits. */
    ASSERT_EQ(gy_kdf_ctr(d, got, 32, key, sizeof(key), label, llen, ctx, clen),
              GY_OK);
    kdf_ref(want, 32, key, sizeof(key), label, llen, ctx, clen);
    ASSERT_MEMEQ(got, want, 32);

    /* Two blocks: counter advances 1 -> 2 under the same fixed input. */
    ASSERT_EQ(gy_kdf_ctr(d, got, 48, key, sizeof(key), label, llen, ctx, clen),
              GY_OK);
    kdf_ref(want, 48, key, sizeof(key), label, llen, ctx, clen);
    ASSERT_MEMEQ(got, want, 48);
}

TEST(archive_crosscheck)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    uint8_t key[32];
    uint8_t got[32], want[32];
    const uint8_t *label = (const uint8_t *)"DR-MessageKey";
    size_t llen = 13;

    /*
     * Empty Context makes gy_kdf_ctr's layout identical to the archive's
     * sp800_108_counter_mode; kdf_ref with clen 0 is the independent recompute.
     */
    memset(key, 0xaa, sizeof(key));
    ASSERT_EQ(gy_kdf_ctr(d, got, 32, key, sizeof(key), label, llen, NULL, 0),
              GY_OK);
    kdf_ref(want, 32, key, sizeof(key), label, llen, NULL, 0);
    ASSERT_MEMEQ(got, want, 32);
}

TEST(boundary_and_args)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    static uint8_t got[255 * 32];
    static uint8_t want[255 * 32];
    uint8_t key[32];
    uint8_t small[16];
    struct gy_iov fixed = {key, sizeof(key)};

    memset(key, 0x11, sizeof(key));

    /* Maximum output: outlen = 255 * hash_len succeeds and matches the ref. */
    ASSERT_EQ(gy_kdf_ctr(d, got, sizeof(got), key, sizeof(key),
                         (const uint8_t *)"L", 1, NULL, 0),
              GY_OK);
    kdf_ref(want, sizeof(want), key, sizeof(key), (const uint8_t *)"L", 1, NULL,
            0);
    ASSERT_MEMEQ(got, want, sizeof(want));

    /* One byte past the maximum, and zero length, are argument errors. */
    ASSERT_EQ(
        gy_kdf_ctr(d, got, 255 * 32 + 1, key, sizeof(key), NULL, 0, NULL, 0),
        GY_ERR_ARG);
    ASSERT_EQ(gy_kdf_ctr(d, got, 0, key, sizeof(key), NULL, 0, NULL, 0),
              GY_ERR_ARG);

    /* NULL descriptor/out/key reject in both forms. */
    ASSERT_EQ(gy_kdf_ctr(NULL, small, 16, key, sizeof(key), NULL, 0, NULL, 0),
              GY_ERR_ARG);
    ASSERT_EQ(gy_kdf_ctr(d, NULL, 16, key, sizeof(key), NULL, 0, NULL, 0),
              GY_ERR_ARG);
    ASSERT_EQ(gy_kdf_ctr_raw(d, small, 16, NULL, 0, &fixed, 1), GY_ERR_ARG);

    /* Too many fixed elements reject. */
    ASSERT_EQ(gy_kdf_ctr_raw(d, small, 16, key, sizeof(key), &fixed,
                             GY_KDF_CTR_MAX_FIXED + 1),
              GY_ERR_ARG);
}

GY_TEST_MAIN(GY_TEST(cavp_raw_vectors), GY_TEST(layout_kat),
             GY_TEST(archive_crosscheck), GY_TEST(boundary_and_args))
