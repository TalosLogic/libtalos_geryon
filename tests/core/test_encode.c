/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/core/encode.c (D-GEN-1/2/3, D-X3DH-1).
 * The PKID KATs use hand-computed hash prefixes:
 *   - SHA-256(0x20 || 0x01*32)[0..3]  = 2491ab32
 *   - SHA-512(0x38 || 0x02*56)[0..3]  = d56c4023
 * The gy_info KATs check the exact ASCII byte strings
 */

#include <stdint.h>
#include <string.h>

#include "encode.h"
#include "error.h"
#include "suite.h"

#include "gy_test.h"

TEST(be_roundtrips)
{
    uint8_t b[8];
    static const uint16_t v16[] = {0, 1, 0x8000, 0xffff};
    static const uint32_t v32[] = {0, 1, 0x80000000u, 0xffffffffu};
    static const uint64_t v64[] = {0, 1, 0x8000000000000000ull,
                                   0xffffffffffffffffull};
    size_t i;

    for (i = 0; i < sizeof(v16) / sizeof(v16[0]); i++) {
        gy_be16_put(b, v16[i]);
        ASSERT_EQ(gy_be16_get(b), v16[i]);
    }
    for (i = 0; i < sizeof(v32) / sizeof(v32[0]); i++) {
        gy_be32_put(b, v32[i]);
        ASSERT_EQ(gy_be32_get(b), v32[i]);
    }
    for (i = 0; i < sizeof(v64) / sizeof(v64[0]); i++) {
        gy_be64_put(b, v64[i]);
        ASSERT_TRUE(gy_be64_get(b) == v64[i], "be64 roundtrip");
    }

    /* Byte order is big-endian: most significant byte first. */
    gy_be32_put(b, 0x01020304u);
    ASSERT_EQ(b[0], 0x01);
    ASSERT_EQ(b[1], 0x02);
    ASSERT_EQ(b[2], 0x03);
    ASSERT_EQ(b[3], 0x04);
}

TEST(suite_lookup)
{
    const struct gy_suite_desc *d;

    d = gy_suite_desc(GY_SUITE_C25519);
    ASSERT_TRUE(d != NULL && d->hash_len == 32 &&
                    d->curve_type == GY_CURVE_TYPE_25519 &&
                    strcmp(d->name, "c25519") == 0,
                "c25519 descriptor");
    /* Only geryon_c25519 is enabled; every other byte is NULL. */
    ASSERT_TRUE(gy_suite_desc(0x00) == NULL, "reserved 0x00 unknown");
    ASSERT_TRUE(gy_suite_desc(GY_SUITE_H25519_512) == NULL, "0x02 not enabled");
    ASSERT_TRUE(gy_suite_desc(GY_SUITE_C448) == NULL, "0x03 not enabled");
    ASSERT_TRUE(gy_suite_desc(GY_SUITE_H448_1024) == NULL, "0x04 not enabled");
    ASSERT_TRUE(gy_suite_desc(0x05) == NULL, "0x05 unknown");
}

TEST(encode_ec)
{
    uint8_t pk[56];
    uint8_t out[64];
    int n;

    memset(pk, 0x01, sizeof(pk));

    n = gy_encode_ec(out, sizeof(out), GY_CURVE_TYPE_25519, pk);
    ASSERT_EQ(n, 33);
    ASSERT_EQ(out[0], GY_CURVE_TYPE_25519);
    ASSERT_MEMEQ(out + 1, pk, 32);

    n = gy_encode_ec(out, sizeof(out), GY_CURVE_TYPE_448, pk);
    ASSERT_EQ(n, 57);
    ASSERT_EQ(out[0], GY_CURVE_TYPE_448);
    ASSERT_MEMEQ(out + 1, pk, 56);

    /* Unknown curve type and too-small capacity both reject. */
    ASSERT_EQ(gy_encode_ec(out, sizeof(out), 0x21, pk), GY_ERR_ARG);
    ASSERT_EQ(gy_encode_ec(out, 32, GY_CURVE_TYPE_25519, pk), GY_ERR_ARG);
    ASSERT_EQ(gy_encode_ec(NULL, sizeof(out), GY_CURVE_TYPE_25519, pk),
              GY_ERR_ARG);
}

TEST(pkid_kats)
{
    uint8_t enc[57];
    uint32_t pkid;

    /* SHA-256(0x20 || 0x01*32)[0..3] = 0x2491ab32 (25519 suite). */
    enc[0] = 0x20;
    memset(enc + 1, 0x01, 32);
    ASSERT_EQ(gy_pkid(&pkid, GY_SUITE_C25519, enc, 33), GY_OK);
    ASSERT_EQ(pkid, 0x2491ab32u);

    /* Suites not yet enabled (0x02..0x04) and NULL arguments reject. */
    ASSERT_EQ(gy_pkid(&pkid, GY_SUITE_C448, enc, 57), GY_ERR_ARG);
    ASSERT_EQ(gy_pkid(&pkid, 0x00, enc, 57), GY_ERR_ARG);
    ASSERT_EQ(gy_pkid(NULL, GY_SUITE_C25519, enc, 33), GY_ERR_ARG);
    ASSERT_EQ(gy_pkid(&pkid, GY_SUITE_C25519, NULL, 0), GY_ERR_ARG);
}

TEST(pkid_presence)
{
    ASSERT_EQ(gy_pkid_is_present(0x00000000u), 0);
    ASSERT_EQ(gy_pkid_is_present(0x00000001u), 1);
    ASSERT_EQ(gy_pkid_is_present(0x80000000u), 1);
    ASSERT_EQ(gy_pkid_is_present(0xffffffffu), 1);
}

TEST(framing)
{
    uint8_t frame[2];

    gy_frame_put(frame, GY_SUITE_H25519_512);
    ASSERT_EQ(frame[0], GY_WIRE_VERSION);
    ASSERT_EQ(frame[1], GY_SUITE_H25519_512);
    ASSERT_EQ(gy_frame_check(frame, 2, GY_SUITE_H25519_512), GY_OK);

    /* Short buffers reject as malformed. */
    ASSERT_EQ(gy_frame_check(frame, 0, GY_SUITE_H25519_512), GY_ERR_ARG);
    ASSERT_EQ(gy_frame_check(frame, 1, GY_SUITE_H25519_512), GY_ERR_ARG);

    /* Wrong version rejects as malformed. */
    frame[0] = 0x00;
    ASSERT_EQ(gy_frame_check(frame, 2, GY_SUITE_H25519_512), GY_ERR_ARG);
    frame[0] = 0x02;
    ASSERT_EQ(gy_frame_check(frame, 2, GY_SUITE_H25519_512), GY_ERR_ARG);

    /* Correct version but wrong suite is a downgrade attempt: GY_ERR_STATE. */
    gy_frame_put(frame, GY_SUITE_C25519);
    ASSERT_EQ(gy_frame_check(frame, 2, GY_SUITE_H25519_512), GY_ERR_STATE);
}

TEST(info_kats)
{
    uint8_t out[64];
    size_t outlen;

    ASSERT_EQ(gy_info(out, sizeof(out), &outlen, GY_SUITE_C25519, "x3dh"),
              GY_OK);
    ASSERT_EQ(outlen, strlen("geryon.1.c25519.x3dh"));
    ASSERT_MEMEQ(out, "geryon.1.c25519.x3dh", outlen);

    ASSERT_EQ(gy_info(out, sizeof(out), &outlen, GY_SUITE_C25519, "dr.aead"),
              GY_OK);
    ASSERT_EQ(outlen, strlen("geryon.1.c25519.dr.aead"));
    ASSERT_MEMEQ(out, "geryon.1.c25519.dr.aead", outlen);

    /* Unknown / not-yet-enabled suites, NULL args, and short cap reject. */
    ASSERT_EQ(gy_info(out, sizeof(out), &outlen, 0x00, "x3dh"), GY_ERR_ARG);
    ASSERT_EQ(gy_info(out, sizeof(out), &outlen, GY_SUITE_H25519_512, "x3dh"),
              GY_ERR_ARG);
    ASSERT_EQ(gy_info(out, sizeof(out), &outlen, GY_SUITE_C25519, NULL),
              GY_ERR_ARG);
    ASSERT_EQ(gy_info(out, 4, &outlen, GY_SUITE_C25519, "x3dh"),
              GY_ERR_TOOLONG);
}

GY_TEST_MAIN(GY_TEST(be_roundtrips), GY_TEST(suite_lookup), GY_TEST(encode_ec),
             GY_TEST(pkid_kats), GY_TEST(pkid_presence), GY_TEST(framing),
             GY_TEST(info_kats))
