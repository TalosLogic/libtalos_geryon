/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <sodium.h>

#include "error.h"
#include "pwhash.h"
#include "util.h"

int
gy_pwhash_derive(uint8_t *out, size_t outlen, const uint8_t *cred,
                 size_t credlen, const uint8_t salt[GY_PWHASH_SALT_LEN],
                 uint32_t opslimit, size_t memlimit)
{
    if (out == NULL || cred == NULL || salt == NULL)
        return GY_ERR_ARG;
    if (outlen < crypto_pwhash_BYTES_MIN || outlen > crypto_pwhash_BYTES_MAX)
        return GY_ERR_ARG;
    if (opslimit < GY_PWHASH_OPSLIMIT_MIN || opslimit > GY_PWHASH_OPSLIMIT_MAX)
        return GY_ERR_ARG;
    if (memlimit < GY_PWHASH_MEMLIMIT_MIN || memlimit > GY_PWHASH_MEMLIMIT_MAX)
        return GY_ERR_ARG;

    /*
     * crypto_pwhash's only failure mode past argument validation is
     * allocation failure inside Argon2id (a provider-level failure, not an
     * argument problem), so any nonzero return past this point maps to
     * GY_ERR_CRYPTO.
     */
    if (crypto_pwhash(out, (unsigned long long)outlen, (const char *)cred,
                      (unsigned long long)credlen, salt,
                      (unsigned long long)opslimit, memlimit,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        gy_secure_zero(out, outlen);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}
