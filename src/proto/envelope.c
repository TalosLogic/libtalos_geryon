/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Layer 5 wire serialization: the typed envelope and the prekey
 * bundle format.  proto/ touches only session/ symbols and opaque bytes; it
 * does its own endian and byte work here so its objects reference no ratchet/
 * or core/ symbol (the nm audit).  No cryptography lives in this file.
 */

#include <string.h>

#include "envelope.h"

/* ---- local endian helpers (no core/ dependency) ------------------------ */

static void
put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint32_t
get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
put_be64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

static uint64_t
get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    int i;

    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

/* ---- typed envelope (D-GEN-1) ------------------------------------------ */

int
gy_envelope_put(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
                uint8_t msg_type, const uint8_t *inner, size_t ilen)
{
    if (out == NULL || outlen == NULL || (inner == NULL && ilen))
        return GY_ERR_ARG;
    if (msg_type != GY_MSG_INIT && msg_type != GY_MSG_DR)
        return GY_ERR_ARG;
    if (cap < GY_ENVELOPE_HDR_LEN + ilen)
        return GY_ERR_ARG;

    out[0] = GY_WIRE_VERSION;
    out[1] = suite_id;
    out[2] = msg_type;
    memcpy(out + GY_ENVELOPE_HDR_LEN, inner, ilen);
    *outlen = GY_ENVELOPE_HDR_LEN + ilen;
    return GY_OK;
}

int
gy_envelope_parse(const uint8_t *buf, size_t len, uint8_t expected_suite,
                  uint8_t *out_type, const uint8_t **out_inner,
                  size_t *out_inner_len)
{
    const uint8_t *inner;
    size_t inner_len;

    if (buf == NULL || out_type == NULL || out_inner == NULL ||
        out_inner_len == NULL)
        return GY_ERR_ARG;
    if (len < GY_ENVELOPE_HDR_LEN)
        return GY_ERR_ARG;
    if (buf[0] != GY_WIRE_VERSION)
        return GY_ERR_ARG;
    if (buf[1] != expected_suite)
        return GY_ERR_STATE; /* cross-suite envelope (downgrade signal) */
    if (buf[2] != GY_MSG_INIT && buf[2] != GY_MSG_DR)
        return GY_ERR_ARG; /* reserved msg_type */

    inner = buf + GY_ENVELOPE_HDR_LEN;
    inner_len = len - GY_ENVELOPE_HDR_LEN;
    /* The inner message repeats version || suite; it must match the outer. */
    if (inner_len < 2 || inner[0] != buf[0] || inner[1] != buf[1])
        return GY_ERR_ARG;

    *out_type = buf[2];
    *out_inner = inner;
    *out_inner_len = inner_len;
    return GY_OK;
}

/* ---- prekey bundle wire format (D-X3DH-15 key structure) --------------- */

static void
put_key(uint8_t **p, const struct gy_public_key *k, size_t cpl)
{
    put_be32(*p, k->pkid);
    *p += 4;
    *(*p)++ = k->curve_type;
    memcpy(*p, k->pk, cpl);
    *p += cpl;
}

static void
get_key(const uint8_t **p, struct gy_public_key *k, size_t cpl)
{
    memset(k, 0, sizeof(*k));
    k->pkid = get_be32(*p);
    *p += 4;
    k->curve_type = *(*p)++;
    memcpy(k->pk, *p, cpl);
    *p += cpl;
}

size_t
gy_bundle_wire_len(const struct gy_suite_desc *desc, int with_opk)
{
    size_t kw = 4 + 1 + desc->curve_pk_len;

    return 2 + 2 * kw + 8 + desc->sig_len + 1 + (with_opk ? kw : 0);
}

int
gy_bundle_put(uint8_t *out, size_t cap, size_t *outlen,
              const struct gy_suite_desc *desc,
              const struct gy_prekey_bundle *b)
{
    size_t cpl, siglen, need;
    int present;
    uint8_t *p;

    if (out == NULL || outlen == NULL || desc == NULL || b == NULL)
        return GY_ERR_ARG;
    cpl = desc->curve_pk_len;
    siglen = desc->sig_len;
    present = b->opk.pkid != 0;
    need = gy_bundle_wire_len(desc, present);
    if (cap < need)
        return GY_ERR_ARG;

    p = out;
    *p++ = GY_WIRE_VERSION;
    *p++ = desc->suite_id;
    put_key(&p, &b->ik, cpl);
    put_key(&p, &b->spk, cpl);
    put_be64(p, b->spk_timestamp);
    p += 8;
    memcpy(p, b->spk_sig, siglen);
    p += siglen;
    *p++ = present ? 1 : 0;
    if (present)
        put_key(&p, &b->opk, cpl);

    *outlen = (size_t)(p - out);
    return GY_OK;
}

int
gy_bundle_parse(struct gy_prekey_bundle *out, const struct gy_suite_desc *desc,
                const uint8_t *buf, size_t len)
{
    size_t cpl, siglen, kw, need;
    int present;
    const uint8_t *p;

    if (out == NULL || desc == NULL || buf == NULL)
        return GY_ERR_ARG;
    cpl = desc->curve_pk_len;
    siglen = desc->sig_len;
    kw = 4 + 1 + cpl;
    need = 2 + 2 * kw + 8 + siglen + 1;
    if (len < need)
        return GY_ERR_ARG;
    if (buf[0] != GY_WIRE_VERSION)
        return GY_ERR_ARG;
    if (buf[1] != desc->suite_id)
        return GY_ERR_STATE;

    memset(out, 0, sizeof(*out));
    p = buf + 2;
    get_key(&p, &out->ik, cpl);
    get_key(&p, &out->spk, cpl);
    out->spk_timestamp = get_be64(p);
    p += 8;
    memcpy(out->spk_sig, p, siglen);
    p += siglen;
    present = *p++;
    if (present) {
        if (len < need + kw)
            return GY_ERR_ARG;
        get_key(&p, &out->opk, cpl);
    } else {
        out->opk.pkid = 0; /* absent sentinel */
    }
    if ((size_t)(p - buf) != len)
        return GY_ERR_ARG; /* trailing bytes */
    return GY_OK;
}

/* ---- fingerprint surface (delegates to session/) ----------------------- */

int
gy_proto_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                     const struct gy_public_key *ik)
{
    return gy_identity_fingerprint(desc, out, ik);
}

/* ---- one-time-prekey batch wire format -------------------- */

size_t
gy_opk_batch_wire_len(const struct gy_suite_desc *desc, size_t n)
{
    size_t kw = 4 + 1 + desc->curve_pk_len;

    return 2 + 2 + n * kw;
}

int
gy_opk_batch_put(uint8_t *out, size_t cap, size_t *outlen,
                 const struct gy_suite_desc *desc,
                 const struct gy_public_key *keys, size_t n)
{
    size_t cpl, need, i;
    uint8_t *p;

    if (out == NULL || outlen == NULL || desc == NULL || (keys == NULL && n))
        return GY_ERR_ARG;
    cpl = desc->curve_pk_len;
    need = gy_opk_batch_wire_len(desc, n);
    if (cap < need)
        return GY_ERR_ARG;

    p = out;
    *p++ = GY_WIRE_VERSION;
    *p++ = desc->suite_id;
    if (n > 0xFFFF)
        return GY_ERR_TOOLONG;
    p[0] = (uint8_t)(n >> 8);
    p[1] = (uint8_t)n;
    p += 2;
    for (i = 0; i < n; i++)
        put_key(&p, &keys[i], cpl);

    *outlen = (size_t)(p - out);
    return GY_OK;
}

int
gy_opk_batch_parse(struct gy_public_key *out, size_t out_cap, size_t *n,
                   const struct gy_suite_desc *desc, const uint8_t *buf,
                   size_t len)
{
    size_t cpl, kw, count, i;
    const uint8_t *p;

    if (out == NULL || n == NULL || desc == NULL || buf == NULL)
        return GY_ERR_ARG;
    if (len < 4)
        return GY_ERR_ARG;
    if (buf[0] != GY_WIRE_VERSION)
        return GY_ERR_ARG;
    if (buf[1] != desc->suite_id)
        return GY_ERR_STATE;

    cpl = desc->curve_pk_len;
    kw = 4 + 1 + cpl;
    count = ((size_t)buf[2] << 8) | (size_t)buf[3];
    if (count > out_cap)
        return GY_ERR_TOOLONG;
    if (len != 4 + count * kw)
        return GY_ERR_ARG;

    p = buf + 4;
    for (i = 0; i < count; i++)
        get_key(&p, &out[i], cpl);
    *n = count;
    return GY_OK;
}

/* ---- application signing key certificate wire format ----- */

size_t
gy_appkey_cert_wire_len(const struct gy_suite_desc *desc)
{
    size_t kw = 4 + 1 + desc->curve_pk_len;

    return 1 + 1 + kw + 8 + 8 + 4 + desc->sig_len;
}

int
gy_appkey_cert_put(uint8_t *out, size_t cap, size_t *outlen,
                   const struct gy_suite_desc *desc,
                   const struct gy_public_key *sak_pub, uint64_t issued_at,
                   uint64_t expiry, uint32_t identity_pkid,
                   const uint8_t *identity_sig)
{
    size_t cpl, siglen, need;
    uint8_t *p;

    if (out == NULL || outlen == NULL || desc == NULL || sak_pub == NULL ||
        identity_sig == NULL)
        return GY_ERR_ARG;
    cpl = desc->curve_pk_len;
    siglen = desc->sig_len;
    need = gy_appkey_cert_wire_len(desc);
    if (cap < need)
        return GY_ERR_ARG;

    p = out;
    *p++ = GY_WIRE_VERSION;
    *p++ = desc->suite_id;
    put_key(&p, sak_pub, cpl);
    put_be64(p, issued_at);
    p += 8;
    put_be64(p, expiry);
    p += 8;
    put_be32(p, identity_pkid);
    p += 4;
    memcpy(p, identity_sig, siglen);
    p += siglen;

    *outlen = (size_t)(p - out);
    return GY_OK;
}

int
gy_appkey_cert_parse(const struct gy_suite_desc *desc, const uint8_t *buf,
                     size_t len, struct gy_public_key *sak_pub,
                     uint64_t *issued_at, uint64_t *expiry,
                     uint32_t *identity_pkid, uint8_t *identity_sig)
{
    size_t cpl, siglen, kw, need;
    const uint8_t *p;

    if (desc == NULL || buf == NULL || sak_pub == NULL || issued_at == NULL ||
        expiry == NULL || identity_pkid == NULL || identity_sig == NULL)
        return GY_ERR_ARG;
    cpl = desc->curve_pk_len;
    siglen = desc->sig_len;
    kw = 4 + 1 + cpl;
    need = 1 + 1 + kw + 8 + 8 + 4 + siglen;
    if (len != need)
        return GY_ERR_ARG;
    if (buf[0] != GY_WIRE_VERSION)
        return GY_ERR_ARG;
    if (buf[1] != desc->suite_id)
        return GY_ERR_STATE;

    p = buf + 2;
    get_key(&p, sak_pub, cpl);
    *issued_at = get_be64(p);
    p += 8;
    *expiry = get_be64(p);
    p += 8;
    *identity_pkid = get_be32(p);
    p += 4;
    memcpy(identity_sig, p, siglen);

    return GY_OK;
}
