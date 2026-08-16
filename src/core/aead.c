/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdint.h>

#include <sodium.h>

#include "aead.h"
#include "error.h"

int
gy_aead_available(uint8_t aead_id)
{
    switch (aead_id) {
    case GY_AEAD_CHACHA20POLY1305:
        return 1;
    case GY_AEAD_AES256GCM:
        return crypto_aead_aes256gcm_is_available();
    case GY_AEAD_AEGIS256:
        return 1;
    default:
        return 0;
    }
}

size_t
gy_aead_nonce_len(uint8_t aead_id)
{
    switch (aead_id) {
    case GY_AEAD_CHACHA20POLY1305:
        return crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    case GY_AEAD_AES256GCM:
        return crypto_aead_aes256gcm_NPUBBYTES;
    case GY_AEAD_AEGIS256:
        return crypto_aead_aegis256_NPUBBYTES;
    default:
        return 0;
    }
}

size_t
gy_aead_tag_len(uint8_t aead_id)
{
    switch (aead_id) {
    case GY_AEAD_CHACHA20POLY1305:
        return crypto_aead_chacha20poly1305_ietf_ABYTES;
    case GY_AEAD_AES256GCM:
        return crypto_aead_aes256gcm_ABYTES;
    case GY_AEAD_AEGIS256:
        return crypto_aead_aegis256_ABYTES;
    default:
        return 0;
    }
}

int
gy_aead_encrypt(uint8_t id, uint8_t *ct, size_t *ctlen, const uint8_t key[32],
                const uint8_t *nonce, size_t nlen, const uint8_t *ad,
                size_t adlen, const uint8_t *pt, size_t ptlen)
{
    unsigned long long clen;
    size_t taglen;
    int rc;

    if (ct == NULL || ctlen == NULL || key == NULL || nonce == NULL)
        return GY_ERR_ARG;
    taglen = gy_aead_tag_len(id);
    if (taglen == 0)
        return GY_ERR_ARG;
    if (nlen != gy_aead_nonce_len(id))
        return GY_ERR_ARG;
    if (id == GY_AEAD_AES256GCM && !gy_aead_available(id))
        return GY_ERR_UNSUPPORTED;
    /* Overflow-safe capacity check: ptlen + taglen must not wrap
     * before it is compared against the output buffer's capacity. */
    if (ptlen > SIZE_MAX - taglen || *ctlen < ptlen + taglen)
        return GY_ERR_ARG;

    switch (id) {
    case GY_AEAD_CHACHA20POLY1305:
        rc = crypto_aead_chacha20poly1305_ietf_encrypt(ct, &clen, pt, ptlen, ad,
                                                       adlen, NULL, nonce, key);
        break;
    case GY_AEAD_AES256GCM:
        rc = crypto_aead_aes256gcm_encrypt(ct, &clen, pt, ptlen, ad, adlen,
                                           NULL, nonce, key);
        break;
    case GY_AEAD_AEGIS256:
        rc = crypto_aead_aegis256_encrypt(ct, &clen, pt, ptlen, ad, adlen, NULL,
                                          nonce, key);
        break;
    default:
        return GY_ERR_ARG;
    }
    if (rc != 0)
        return GY_ERR_CRYPTO;
    *ctlen = (size_t)clen;
    return GY_OK;
}

int
gy_aead_decrypt(uint8_t id, uint8_t *pt, size_t *ptlen, const uint8_t key[32],
                const uint8_t *nonce, size_t nlen, const uint8_t *ad,
                size_t adlen, const uint8_t *ct, size_t ctlen)
{
    unsigned long long mlen;
    size_t taglen;
    int rc;

    if (pt == NULL || ptlen == NULL || key == NULL || nonce == NULL ||
        ct == NULL)
        return GY_ERR_ARG;
    taglen = gy_aead_tag_len(id);
    if (taglen == 0)
        return GY_ERR_ARG;
    if (nlen != gy_aead_nonce_len(id))
        return GY_ERR_ARG;
    if (id == GY_AEAD_AES256GCM && !gy_aead_available(id))
        return GY_ERR_UNSUPPORTED;
    /* Too short to hold a tag: authentication cannot succeed. */
    if (ctlen < taglen)
        return GY_ERR_VERIFY;
    if (*ptlen < ctlen - taglen)
        return GY_ERR_ARG;

    switch (id) {
    case GY_AEAD_CHACHA20POLY1305:
        rc = crypto_aead_chacha20poly1305_ietf_decrypt(
            pt, &mlen, NULL, ct, ctlen, ad, adlen, nonce, key);
        break;
    case GY_AEAD_AES256GCM:
        rc = crypto_aead_aes256gcm_decrypt(pt, &mlen, NULL, ct, ctlen, ad,
                                           adlen, nonce, key);
        break;
    case GY_AEAD_AEGIS256:
        rc = crypto_aead_aegis256_decrypt(pt, &mlen, NULL, ct, ctlen, ad, adlen,
                                          nonce, key);
        break;
    default:
        return GY_ERR_ARG;
    }
    /*
     * On verification failure libsodium releases no unverified plaintext: it
     * zeroes the output buffer (it does not leave it untouched).  Do not
     * distinguish tag failure from other decrypt errors: both are
     * GY_ERR_VERIFY, no oracle.
     */
    if (rc != 0)
        return GY_ERR_VERIFY;
    *ptlen = (size_t)mlen;
    return GY_OK;
}
