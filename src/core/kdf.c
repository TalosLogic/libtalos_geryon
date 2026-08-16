/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "encode.h"
#include "error.h"
#include "kdf.h"
#include "suite.h"
#include "util.h"

int
gy_kdf_ctr_raw(const struct gy_suite_desc *desc, uint8_t *out, size_t outlen,
               const uint8_t *key, size_t klen, const struct gy_iov *fixed,
               size_t nfixed)
{
    struct gy_iov iov[GY_KDF_CTR_MAX_FIXED + 1];
    uint8_t block[GY_HASH_MAX];
    uint8_t ctr[4];
    size_t hlen, done, take, i;
    uint32_t counter;
    int rc;

    if (desc == NULL || out == NULL || key == NULL)
        return GY_ERR_ARG;
    if (fixed == NULL && nfixed != 0)
        return GY_ERR_ARG;
    if (nfixed > GY_KDF_CTR_MAX_FIXED)
        return GY_ERR_ARG;
    if (outlen == 0)
        return GY_ERR_ARG;

    hlen = desc->hash_len;

    /* The 32-bit counter is the first PRF input; the fixed blob follows. */
    iov[0].p = ctr;
    iov[0].len = sizeof(ctr);
    for (i = 0; i < nfixed; i++)
        iov[i + 1] = fixed[i];

    done = 0;
    counter = 1;
    rc = GY_OK;
    while (done < outlen) {
        gy_be32_put(ctr, counter);
        rc = desc->hmac(block, key, klen, iov, nfixed + 1);
        if (rc != GY_OK)
            break;
        take = outlen - done < hlen ? outlen - done : hlen;
        memcpy(out + done, block, take);
        done += take;
        counter++;
    }

    gy_secure_zero(block, sizeof(block));
    if (rc != GY_OK)
        gy_secure_zero(out, outlen);
    return rc;
}

int
gy_kdf_ctr(const struct gy_suite_desc *desc, uint8_t *out, size_t outlen,
           const uint8_t *key, size_t klen, const uint8_t *label, size_t llen,
           const uint8_t *context, size_t clen)
{
    struct gy_iov fixed[4];
    uint8_t sep = 0x00;
    uint8_t lbits[4];

    if (desc == NULL || out == NULL || key == NULL)
        return GY_ERR_ARG;
    if (label == NULL && llen != 0)
        return GY_ERR_ARG;
    if (context == NULL && clen != 0)
        return GY_ERR_ARG;
    if (outlen == 0 || outlen > 255 * desc->hash_len)
        return GY_ERR_ARG;

    /* L is the requested output length in BITS, 32-bit big-endian (D-DR-2). */
    gy_be32_put(lbits, (uint32_t)(outlen * 8));

    fixed[0].p = label;
    fixed[0].len = llen;
    fixed[1].p = &sep;
    fixed[1].len = 1;
    fixed[2].p = context;
    fixed[2].len = clen;
    fixed[3].p = lbits;
    fixed[3].len = sizeof(lbits);

    return gy_kdf_ctr_raw(desc, out, outlen, key, klen, fixed, 4);
}
