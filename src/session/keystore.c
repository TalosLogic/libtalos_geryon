/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "keystore.h"

int
gy_keystore_create(struct gy_keystore *ks, uint8_t alg_id, uint32_t opslimit,
                   size_t memlimit, const uint8_t *cred, size_t credlen,
                   uint8_t *out, size_t *outlen)
{
    int rc;

    if (ks == NULL || cred == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (ks->unlocked)
        return GY_ERR_STATE;

    ks->kek = gy_secure_alloc(GY_KEKPROT_KEK_LEN);
    if (ks->kek == NULL)
        return GY_ERR_CRYPTO;

    rc = gy_random_bytes(ks->kek, GY_KEKPROT_KEK_LEN);
    if (rc != GY_OK) {
        gy_secure_free(ks->kek);
        ks->kek = NULL;
        return rc;
    }

    rc = gy_kekprot_wrap(out, outlen, alg_id, opslimit, memlimit, cred, credlen,
                         NULL, 0, ks->kek);
    if (rc != GY_OK) {
        gy_secure_free(ks->kek); /* gy_secure_free zeroizes before releasing */
        ks->kek = NULL;
        return rc;
    }
    ks->unlocked = 1;
    return GY_OK;
}

int
gy_keystore_open(struct gy_keystore *ks, const uint8_t *cred, size_t credlen,
                 const uint8_t *wrap, size_t wraplen)
{
    int rc;

    if (ks == NULL || cred == NULL || wrap == NULL)
        return GY_ERR_ARG;
    if (ks->unlocked)
        return GY_ERR_STATE;

    ks->kek = gy_secure_alloc(GY_KEKPROT_KEK_LEN);
    if (ks->kek == NULL)
        return GY_ERR_CRYPTO;

    rc = gy_kekprot_unwrap(ks->kek, cred, credlen, NULL, 0, wrap, wraplen);
    if (rc != GY_OK) {
        gy_secure_free(ks->kek);
        ks->kek = NULL;
        return rc;
    }
    ks->unlocked = 1;
    return GY_OK;
}

void
gy_keystore_close(struct gy_keystore *ks)
{
    if (ks == NULL)
        return;
    if (ks->kek != NULL) {
        gy_secure_free(ks->kek); /* zeroizes before releasing its pages */
        ks->kek = NULL;
    }
    ks->unlocked = 0;
}

int
gy_keystore_change_credential(struct gy_keystore *ks, uint8_t alg_id,
                              uint32_t opslimit, size_t memlimit,
                              const uint8_t *new_cred, size_t new_credlen,
                              uint8_t *out, size_t *outlen)
{
    if (ks == NULL || new_cred == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (!ks->unlocked)
        return GY_ERR_STATE;

    return gy_kekprot_wrap(out, outlen, alg_id, opslimit, memlimit, new_cred,
                           new_credlen, NULL, 0, ks->kek);
}

int
gy_keystore_seal(struct gy_keystore *ks, uint8_t alg_id, const uint8_t *ad,
                 size_t adlen, const uint8_t *pt, size_t ptlen, uint8_t *out,
                 size_t *outlen)
{
    if (ks == NULL)
        return GY_ERR_ARG;
    if (!ks->unlocked)
        return GY_ERR_STATE;
    return gy_seal(out, outlen, ks->kek, alg_id, ad, adlen, pt, ptlen);
}

int
gy_keystore_unseal(struct gy_keystore *ks, const uint8_t *ad, size_t adlen,
                   const uint8_t *blob, size_t bloblen, uint8_t *pt,
                   size_t *ptlen)
{
    if (ks == NULL)
        return GY_ERR_ARG;
    if (!ks->unlocked)
        return GY_ERR_STATE;
    return gy_unseal(pt, ptlen, ks->kek, ad, adlen, blob, bloblen);
}
