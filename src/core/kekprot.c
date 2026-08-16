/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "encode.h"
#include "error.h"
#include "kekprot.h"
#include "pwhash.h"
#include "rng.h"
#include "seal.h"
#include "util.h"

int
gy_kekprot_wrap(uint8_t *out, size_t *outlen, uint8_t alg_id, uint32_t opslimit,
                size_t memlimit, const uint8_t *cred, size_t credlen,
                const uint8_t *ad, size_t adlen,
                const uint8_t kek[GY_KEKPROT_KEK_LEN])
{
    uint8_t *pdk;
    uint8_t *salt;
    size_t bloblen, need;
    int rc;

    if (out == NULL || outlen == NULL || cred == NULL || kek == NULL)
        return GY_ERR_ARG;

    need = GY_KEKPROT_HDR_LEN + GY_SEAL_MAX_OVERHEAD + GY_KEKPROT_KEK_LEN;
    if (*outlen < need)
        return GY_ERR_ARG;

    /*
     * The password-derived key is credential-equivalent (it is what unseals
     * the KEK), so it lives in guarded (sodium_malloc / mlock'd) memory for
     * its whole lifetime rather than on the stack: no swap-out during the
     * memory-hard Argon2id window, and exclusion from core dumps
     * (CUSTODY_SPEC section 15).  gy_secure_free zeroizes before releasing.
     */
    pdk = gy_secure_alloc(GY_SEAL_KEY_LEN);
    if (pdk == NULL)
        return GY_ERR_CRYPTO;

    salt = out;
    rc = gy_random_bytes(salt, GY_PWHASH_SALT_LEN);
    if (rc != GY_OK) {
        gy_secure_free(pdk);
        return rc;
    }
    gy_be32_put(out + GY_PWHASH_SALT_LEN, opslimit);
    gy_be64_put(out + GY_PWHASH_SALT_LEN + 4, (uint64_t)memlimit);

    rc = gy_pwhash_derive(pdk, GY_SEAL_KEY_LEN, cred, credlen, salt, opslimit,
                          memlimit);
    if (rc != GY_OK) {
        gy_secure_free(pdk);
        return rc;
    }

    bloblen = *outlen - GY_KEKPROT_HDR_LEN;
    rc = gy_seal(out + GY_KEKPROT_HDR_LEN, &bloblen, pdk, alg_id, ad, adlen,
                 kek, GY_KEKPROT_KEK_LEN);
    gy_secure_free(pdk);
    if (rc != GY_OK)
        return rc;

    *outlen = GY_KEKPROT_HDR_LEN + bloblen;
    return GY_OK;
}

int
gy_kekprot_unwrap(uint8_t kek[GY_KEKPROT_KEK_LEN], const uint8_t *cred,
                  size_t credlen, const uint8_t *ad, size_t adlen,
                  const uint8_t *blob, size_t bloblen)
{
    uint8_t *pdk;
    const uint8_t *salt, *sealed;
    uint64_t memlimit64;
    size_t ptlen, sealedlen;
    int rc;
    uint32_t opslimit;

    if (kek == NULL || cred == NULL || blob == NULL)
        return GY_ERR_ARG;
    if (bloblen < GY_KEKPROT_HDR_LEN)
        return GY_ERR_VERIFY;

    salt = blob;
    opslimit = gy_be32_get(blob + GY_PWHASH_SALT_LEN);
    memlimit64 = gy_be64_get(blob + GY_PWHASH_SALT_LEN + 4);

    /*
     * The parameter header sits outside gy_seal's authenticated region, so a
     * write-access adversary could tamper it.  That cannot weaken this check
     * (gy_pwhash_derive enforces the same floor/ceiling regardless) and
     * cannot help an offline attacker, who would derive their own guesses at
     * whatever cost they choose against the salt directly: this is a
     * fail-fast/DoS guard against an oversized memlimit driving unbounded
     * allocation, not a security boundary (the AEAD tag is).  Checked before
     * the size_t cast below so a 32-bit size_t cannot silently truncate an
     * out-of-range value back into range.
     */
    if (memlimit64 > (uint64_t)GY_PWHASH_MEMLIMIT_MAX)
        return GY_ERR_VERIFY;

    /* Guarded, credential-equivalent PDK: see gy_kekprot_wrap. */
    pdk = gy_secure_alloc(GY_SEAL_KEY_LEN);
    if (pdk == NULL)
        return GY_ERR_CRYPTO;

    rc = gy_pwhash_derive(pdk, GY_SEAL_KEY_LEN, cred, credlen, salt, opslimit,
                          (size_t)memlimit64);
    if (rc != GY_OK) {
        gy_secure_free(pdk);
        /* An out-of-range stored parameter is attacker-influenceable and
         * must not be distinguishable from a wrong credential. */
        return rc == GY_ERR_ARG ? GY_ERR_VERIFY : rc;
    }

    sealed = blob + GY_KEKPROT_HDR_LEN;
    sealedlen = bloblen - GY_KEKPROT_HDR_LEN;
    ptlen = GY_KEKPROT_KEK_LEN;
    rc = gy_unseal(kek, &ptlen, pdk, ad, adlen, sealed, sealedlen);
    gy_secure_free(pdk);
    if (rc != GY_OK)
        return rc;
    if (ptlen != GY_KEKPROT_KEK_LEN) {
        gy_secure_zero(kek, GY_KEKPROT_KEK_LEN);
        return GY_ERR_VERIFY;
    }
    return GY_OK;
}
