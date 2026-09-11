/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_hash.h"

#include "encode.h" /* gy_info */
#include "error.h"
#include "util.h"

/*
 * Longest hashed input this module concatenates after the domain: the M3 / j3
 * inputs are ProfileKey (32) || UID (16) = 48 bytes.  The seed buffer holds the
 * domain plus that; over-long inputs are rejected rather than truncated.
 */
#define GY_GROUP_HASH_INPUT_MAX 48
#define GY_GROUP_SEED_MAX (GY_GROUP_DOMAIN_MAX + GY_GROUP_HASH_INPUT_MAX)

int
gy_group_domain(uint8_t suite_id, const char *purpose, uint8_t *out, size_t cap,
                size_t *outlen)
{
    return gy_info(out, cap, outlen, suite_id, purpose);
}

/*
 * Build domain(purpose) || input into seed and return its length in *seed_len,
 * or a negative code.  input may be NULL only when input_len is 0.
 */
static int
group_seed(const struct gy_group_tier *tier, const char *purpose,
           const uint8_t *input, size_t input_len,
           uint8_t seed[GY_GROUP_SEED_MAX], size_t *seed_len)
{
    size_t dlen;
    int rc;

    if (tier == NULL || purpose == NULL || (input == NULL && input_len != 0))
        return GY_ERR_ARG;
    if (input_len > GY_GROUP_HASH_INPUT_MAX)
        return GY_ERR_TOOLONG;

    rc = gy_group_domain(tier->suite_id, purpose, seed, GY_GROUP_DOMAIN_MAX,
                         &dlen);
    if (rc != GY_OK)
        return rc;

    if (input_len != 0)
        memcpy(seed + dlen, input, input_len);
    *seed_len = dlen + input_len;
    return GY_OK;
}

int
gy_group_hash_to_g(const struct gy_group_tier *tier, const char *purpose,
                   const uint8_t *input, size_t input_len, uint8_t *out)
{
    uint8_t seed[GY_GROUP_SEED_MAX];
    size_t seed_len;
    int rc;

    if (out == NULL)
        return GY_ERR_ARG;
    rc = group_seed(tier, purpose, input, input_len, seed, &seed_len);
    if (rc != GY_OK)
        return rc;

    rc = tier->hash_to_group(out, seed, seed_len, 0);
    gy_secure_zero(seed, sizeof(seed));
    return rc == 0 ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_hash_to_g1(const struct gy_group_tier *tier, const char *purpose,
                    const uint8_t *input, size_t input_len, uint8_t *out)
{
    uint8_t seed[GY_GROUP_SEED_MAX];
    size_t seed_len;
    int rc;

    if (out == NULL)
        return GY_ERR_ARG;
    rc = group_seed(tier, purpose, input, input_len, seed, &seed_len);
    if (rc != GY_OK)
        return rc;

    rc = tier->hash_to_g1(out, seed, seed_len);
    gy_secure_zero(seed, sizeof(seed));
    return rc == 0 ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_hash_to_zq(const struct gy_group_tier *tier, const char *purpose,
                    const uint8_t *input, size_t input_len, uint8_t *out)
{
    uint8_t domain[GY_GROUP_DOMAIN_MAX];
    size_t dlen;
    int rc;

    if (tier == NULL || purpose == NULL || out == NULL ||
        (input == NULL && input_len != 0))
        return GY_ERR_ARG;

    rc =
        gy_group_domain(tier->suite_id, purpose, domain, sizeof(domain), &dlen);
    if (rc != GY_OK)
        return rc;

    rc = tier->hash_to_scalar(out, input, input_len, domain, dlen);
    gy_secure_zero(domain, sizeof(domain));
    return rc == 0 ? GY_OK : GY_ERR_CRYPTO;
}
