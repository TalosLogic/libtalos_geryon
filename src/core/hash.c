/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <sodium.h>

#include "error.h"
#include "hash.h"
#include "suite.h"
#include "util.h"

int
gy_sha256(uint8_t out[32], const uint8_t *in, size_t len)
{
    crypto_hash_sha256(out, in, len);
    return GY_OK;
}

int
gy_sha512(uint8_t out[64], const uint8_t *in, size_t len)
{
    crypto_hash_sha512(out, in, len);
    return GY_OK;
}

int
gy_sha256_init(gy_sha256_state *st)
{
    crypto_hash_sha256_init(st);
    return GY_OK;
}

int
gy_sha256_update(gy_sha256_state *st, const uint8_t *in, size_t len)
{
    crypto_hash_sha256_update(st, in, len);
    return GY_OK;
}

int
gy_sha256_final(gy_sha256_state *st, uint8_t out[32])
{
    crypto_hash_sha256_final(st, out);
    gy_secure_zero(st, sizeof(*st));
    return GY_OK;
}

int
gy_sha512_init(gy_sha512_state *st)
{
    crypto_hash_sha512_init(st);
    return GY_OK;
}

int
gy_sha512_update(gy_sha512_state *st, const uint8_t *in, size_t len)
{
    crypto_hash_sha512_update(st, in, len);
    return GY_OK;
}

int
gy_sha512_final(gy_sha512_state *st, uint8_t out[64])
{
    crypto_hash_sha512_final(st, out);
    gy_secure_zero(st, sizeof(*st));
    return GY_OK;
}

int
gy_hmac_sha256(uint8_t out[32], const uint8_t *key, size_t klen,
               const uint8_t *in, size_t inlen)
{
    crypto_auth_hmacsha256_state st;

    crypto_auth_hmacsha256_init(&st, key, klen);
    crypto_auth_hmacsha256_update(&st, in, inlen);
    crypto_auth_hmacsha256_final(&st, out);
    gy_secure_zero(&st, sizeof(st));
    return GY_OK;
}

int
gy_hmac_sha512(uint8_t out[64], const uint8_t *key, size_t klen,
               const uint8_t *in, size_t inlen)
{
    crypto_auth_hmacsha512_state st;

    crypto_auth_hmacsha512_init(&st, key, klen);
    crypto_auth_hmacsha512_update(&st, in, inlen);
    crypto_auth_hmacsha512_final(&st, out);
    gy_secure_zero(&st, sizeof(st));
    return GY_OK;
}

int
gy_hmac_sha256_iov(uint8_t out[32], const uint8_t *key, size_t klen,
                   const struct gy_iov *iov, size_t niov)
{
    crypto_auth_hmacsha256_state st;
    size_t i;

    if (iov == NULL && niov != 0)
        return GY_ERR_ARG;

    crypto_auth_hmacsha256_init(&st, key, klen);
    for (i = 0; i < niov; i++)
        crypto_auth_hmacsha256_update(&st, iov[i].p, iov[i].len);
    crypto_auth_hmacsha256_final(&st, out);
    gy_secure_zero(&st, sizeof(st));
    return GY_OK;
}

int
gy_hmac_sha512_iov(uint8_t out[64], const uint8_t *key, size_t klen,
                   const struct gy_iov *iov, size_t niov)
{
    crypto_auth_hmacsha512_state st;
    size_t i;

    if (iov == NULL && niov != 0)
        return GY_ERR_ARG;

    crypto_auth_hmacsha512_init(&st, key, klen);
    for (i = 0; i < niov; i++)
        crypto_auth_hmacsha512_update(&st, iov[i].p, iov[i].len);
    crypto_auth_hmacsha512_final(&st, out);
    gy_secure_zero(&st, sizeof(st));
    return GY_OK;
}

/*
 * HKDF-Extract (RFC 5869) is HMAC(salt-as-key, IKM); an empty salt is HMAC
 * with a zero-length key, which HMAC pads to a zero block, exactly the
 * HashLen-of-zeros salt the RFC prescribes.  So these route through the iov
 * HMAC and match the flat gy_hkdf_*_extract path byte for byte.
 */
int
gy_hkdf_sha256_extract_iov(uint8_t prk[32], const uint8_t *salt, size_t slen,
                           const struct gy_iov *iov, size_t niov)
{
    return gy_hmac_sha256_iov(prk, salt, slen, iov, niov);
}

int
gy_hkdf_sha512_extract_iov(uint8_t prk[64], const uint8_t *salt, size_t slen,
                           const struct gy_iov *iov, size_t niov)
{
    return gy_hmac_sha512_iov(prk, salt, slen, iov, niov);
}

int
gy_hkdf_sha256_extract(uint8_t prk[32], const uint8_t *salt, size_t slen,
                       const uint8_t *ikm, size_t ilen)
{
    if (crypto_kdf_hkdf_sha256_extract(prk, salt, slen, ikm, ilen) != 0)
        return GY_ERR_CRYPTO;
    return GY_OK;
}

int
gy_hkdf_sha256_expand(uint8_t *out, size_t outlen, const uint8_t prk[32],
                      const uint8_t *info, size_t infolen)
{
    if (out == NULL || outlen == 0 || outlen > crypto_kdf_hkdf_sha256_BYTES_MAX)
        return GY_ERR_ARG;
    if (crypto_kdf_hkdf_sha256_expand(out, outlen, (const char *)info, infolen,
                                      prk) != 0)
        return GY_ERR_CRYPTO;
    return GY_OK;
}

int
gy_hkdf_sha512_extract(uint8_t prk[64], const uint8_t *salt, size_t slen,
                       const uint8_t *ikm, size_t ilen)
{
    if (crypto_kdf_hkdf_sha512_extract(prk, salt, slen, ikm, ilen) != 0)
        return GY_ERR_CRYPTO;
    return GY_OK;
}

int
gy_hkdf_sha512_expand(uint8_t *out, size_t outlen, const uint8_t prk[64],
                      const uint8_t *info, size_t infolen)
{
    if (out == NULL || outlen == 0 || outlen > crypto_kdf_hkdf_sha512_BYTES_MAX)
        return GY_ERR_ARG;
    if (crypto_kdf_hkdf_sha512_expand(out, outlen, (const char *)info, infolen,
                                      prk) != 0)
        return GY_ERR_CRYPTO;
    return GY_OK;
}
