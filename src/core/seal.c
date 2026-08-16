/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include <sodium.h>

#include "aead.h"
#include "error.h"
#include "rng.h"
#include "seal.h"

#define SEAL_HDR_LEN 2 /* version(1) || alg_id(1). */

/*
 * Nonce and tag lengths for a wrap alg_id.  Returns GY_OK, or GY_ERR_ARG for
 * an unrecognized alg_id: callers that read alg_id from an untrusted blob
 * (gy_unseal) must translate that into the uniform GY_ERR_VERIFY themselves,
 * since an unrecognized byte there is attacker-influenceable and must not be
 * distinguishable from an authentication failure.
 */
static int
seal_alg_lengths(uint8_t alg_id, size_t *nlen, size_t *taglen)
{
    switch (alg_id) {
    case GY_SEAL_ALG_AEGIS256:
        *nlen = gy_aead_nonce_len(GY_AEAD_AEGIS256);
        *taglen = gy_aead_tag_len(GY_AEAD_AEGIS256);
        return GY_OK;
    case GY_SEAL_ALG_XCHACHA20POLY1305:
        *nlen = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        *taglen = crypto_aead_xchacha20poly1305_ietf_ABYTES;
        return GY_OK;
    default:
        return GY_ERR_ARG;
    }
}

int
gy_seal(uint8_t *out, size_t *outlen, const uint8_t key[GY_SEAL_KEY_LEN],
        uint8_t alg_id, const uint8_t *ad, size_t adlen, const uint8_t *pt,
        size_t ptlen)
{
    uint8_t full_ad[SEAL_HDR_LEN + GY_SEAL_MAX_AD];
    uint8_t nonce[GY_AEAD_MAX_NONCE];
    unsigned long long clen;
    size_t ctcap, need, nlen, taglen;
    int rc;

    if (out == NULL || outlen == NULL || key == NULL)
        return GY_ERR_ARG;
    if (ad == NULL && adlen != 0)
        return GY_ERR_ARG;
    if (adlen > GY_SEAL_MAX_AD)
        return GY_ERR_TOOLONG;
    rc = seal_alg_lengths(alg_id, &nlen, &taglen);
    if (rc != GY_OK)
        return rc;

    need = SEAL_HDR_LEN + nlen + ptlen + taglen;
    if (*outlen < need)
        return GY_ERR_ARG;

    full_ad[0] = GY_SEAL_VERSION;
    full_ad[1] = alg_id;
    if (adlen > 0)
        memcpy(full_ad + SEAL_HDR_LEN, ad, adlen);

    rc = gy_random_bytes(nonce, nlen);
    if (rc != GY_OK)
        return rc;

    out[0] = GY_SEAL_VERSION;
    out[1] = alg_id;
    memcpy(out + SEAL_HDR_LEN, nonce, nlen);

    if (alg_id == GY_SEAL_ALG_AEGIS256) {
        ctcap = *outlen - SEAL_HDR_LEN - nlen;
        rc = gy_aead_encrypt(GY_AEAD_AEGIS256, out + SEAL_HDR_LEN + nlen,
                             &ctcap, key, nonce, nlen, full_ad,
                             SEAL_HDR_LEN + adlen, pt, ptlen);
        if (rc != GY_OK)
            return rc;
        *outlen = SEAL_HDR_LEN + nlen + ctcap;
        return GY_OK;
    }

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            out + SEAL_HDR_LEN + nlen, &clen, pt, ptlen, full_ad,
            SEAL_HDR_LEN + adlen, NULL, nonce, key) != 0)
        return GY_ERR_CRYPTO;
    *outlen = SEAL_HDR_LEN + nlen + (size_t)clen;
    return GY_OK;
}

int
gy_unseal(uint8_t *pt, size_t *ptlen, const uint8_t key[GY_SEAL_KEY_LEN],
          const uint8_t *ad, size_t adlen, const uint8_t *blob, size_t bloblen)
{
    uint8_t full_ad[SEAL_HDR_LEN + GY_SEAL_MAX_AD];
    const uint8_t *ct, *nonce;
    unsigned long long mlen;
    size_t ctlen, nlen, taglen;
    uint8_t alg_id, version;
    int rc;

    if (pt == NULL || ptlen == NULL || key == NULL || blob == NULL)
        return GY_ERR_ARG;
    if (ad == NULL && adlen != 0)
        return GY_ERR_ARG;
    if (adlen > GY_SEAL_MAX_AD)
        return GY_ERR_TOOLONG;
    if (bloblen < SEAL_HDR_LEN)
        return GY_ERR_VERIFY;

    version = blob[0];
    alg_id = blob[1];
    if (version != GY_SEAL_VERSION)
        return GY_ERR_VERIFY;
    if (seal_alg_lengths(alg_id, &nlen, &taglen) != GY_OK)
        return GY_ERR_VERIFY;
    if (bloblen < SEAL_HDR_LEN + nlen + taglen)
        return GY_ERR_VERIFY;

    nonce = blob + SEAL_HDR_LEN;
    ct = blob + SEAL_HDR_LEN + nlen;
    ctlen = bloblen - SEAL_HDR_LEN - nlen;

    full_ad[0] = version;
    full_ad[1] = alg_id;
    if (adlen > 0)
        memcpy(full_ad + SEAL_HDR_LEN, ad, adlen);

    if (alg_id == GY_SEAL_ALG_AEGIS256)
        return gy_aead_decrypt(GY_AEAD_AEGIS256, pt, ptlen, key, nonce, nlen,
                               full_ad, SEAL_HDR_LEN + adlen, ct, ctlen);

    if (*ptlen < ctlen - taglen)
        return GY_ERR_ARG;
    rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        pt, &mlen, NULL, ct, ctlen, full_ad, SEAL_HDR_LEN + adlen, nonce, key);
    if (rc != 0)
        return GY_ERR_VERIFY;
    *ptlen = (size_t)mlen;
    return GY_OK;
}
