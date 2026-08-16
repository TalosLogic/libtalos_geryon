/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "encode.h"
#include "error.h"
#include "hash.h"
#include "suite.h"
#include "util.h"

void
gy_be16_put(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v >> 8);
    out[1] = (uint8_t)v;
}

void
gy_be32_put(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

void
gy_be64_put(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)(v >> 56);
    out[1] = (uint8_t)(v >> 48);
    out[2] = (uint8_t)(v >> 40);
    out[3] = (uint8_t)(v >> 32);
    out[4] = (uint8_t)(v >> 24);
    out[5] = (uint8_t)(v >> 16);
    out[6] = (uint8_t)(v >> 8);
    out[7] = (uint8_t)v;
}

uint16_t
gy_be16_get(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

uint32_t
gy_be32_get(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

uint64_t
gy_be64_get(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

int
gy_encode_ec(uint8_t *out, size_t cap, uint8_t curve_type, const uint8_t *pk)
{
    size_t pk_len;

    if (out == NULL || pk == NULL)
        return GY_ERR_ARG;
    if (curve_type != GY_CURVE_TYPE_25519 && curve_type != GY_CURVE_TYPE_448)
        return GY_ERR_ARG;

    /* The curve_type byte is the encoded curve public-key length. */
    pk_len = curve_type;
    if (cap < 1 + pk_len)
        return GY_ERR_ARG;

    out[0] = curve_type;
    memcpy(out + 1, pk, pk_len);
    return (int)(1 + pk_len);
}

int
gy_pkid(uint32_t *pkid, uint8_t suite_id, const uint8_t *encoded_key,
        size_t len)
{
    const struct gy_suite_desc *desc;
    uint8_t digest[64];

    if (pkid == NULL || encoded_key == NULL)
        return GY_ERR_ARG;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    if (desc->hash_len == 32)
        gy_sha256(digest, encoded_key, len);
    else
        gy_sha512(digest, encoded_key, len);

    *pkid = gy_be32_get(digest);
    gy_secure_zero(digest, sizeof(digest));
    return GY_OK;
}

int
gy_pkid_is_present(uint32_t pkid)
{
    uint8_t bytes[4];
    static const uint8_t zero[4] = {0, 0, 0, 0};

    gy_be32_put(bytes, pkid);
    /* Nonzero (present) means the constant-time equality test fails. */
    return gy_const_memcmp(bytes, zero, sizeof(bytes)) != 0 ? 1 : 0;
}

void
gy_frame_put(uint8_t out[2], uint8_t suite_id)
{
    out[0] = GY_WIRE_VERSION;
    out[1] = suite_id;
}

int
gy_frame_check(const uint8_t *buf, size_t len, uint8_t expected_suite)
{
    if (buf == NULL || len < 2)
        return GY_ERR_ARG;
    if (buf[0] != GY_WIRE_VERSION)
        return GY_ERR_ARG;
    if (buf[1] != expected_suite)
        return GY_ERR_STATE;
    return GY_OK;
}

int
gy_info(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
        const char *purpose)
{
    const struct gy_suite_desc *desc;
    size_t need, off, plen, nlen;

    if (out == NULL || outlen == NULL || purpose == NULL)
        return GY_ERR_ARG;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    /* "geryon" "." "1" "." suite_name "." purpose (D-GEN-3, section 3.2). */
    nlen = strlen(desc->name);
    plen = strlen(purpose);
    need = 6 + 1 + 1 + 1 + nlen + 1 + plen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    off = 0;
    memcpy(out + off, "geryon", 6);
    off += 6;
    out[off++] = '.';
    out[off++] = '1';
    out[off++] = '.';
    memcpy(out + off, desc->name, nlen);
    off += nlen;
    out[off++] = '.';
    memcpy(out + off, purpose, plen);
    off += plen;

    *outlen = off;
    return GY_OK;
}
