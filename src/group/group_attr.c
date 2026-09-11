/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_attr.h"

#include "group_hash.h"

#include "error.h"

/*
 * Frozen attribute-map domains (GROUP_SPEC section 2.2 label registry): M1 uses
 * the two-map HashToG under "grp-m1"; M3_prof uses the single-map HashToG1 under
 * "grp-m3".  M2/M4 are the provider EncodeToG and carry no group-side domain.
 */
#define GY_GROUP_M1_PURPOSE "grp-m1"
#define GY_GROUP_M3_PURPOSE "grp-m3"

int
gy_group_redemption_scalar(const struct gy_group_tier *tier, uint64_t date,
                           uint8_t *out)
{
    size_t i;

    if (tier == NULL || out == NULL)
        return GY_ERR_ARG;
    if (date % GY_GROUP_DAY_SECS != 0)
        return GY_ERR_ARG; /* day-aligned only; reject, never round. */

    /* Canonical little-endian scalar of the value: low 8 bytes carry the date,
     * the rest are zero.  date < l, so this is already reduced. */
    memset(out, 0, tier->scalar_len);
    for (i = 0; i < 8; i++)
        out[i] = (uint8_t)(date >> (8 * i));
    return GY_OK;
}

int
gy_group_auth_m3(const struct gy_group_tier *tier,
                 const struct gy_group_generators *gens, uint64_t date,
                 uint8_t *out)
{
    uint8_t m3[GY_GROUP_SCALAR_MAX];
    int rc;

    if (tier == NULL || gens == NULL || out == NULL)
        return GY_ERR_ARG;

    rc = gy_group_redemption_scalar(tier, date, m3);
    if (rc != GY_OK)
        return rc;
    rc = tier->point_scalarmul(out, m3, gens->g[GY_GEN_M3]);
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_attr_auth(const struct gy_group_tier *tier,
                   const struct gy_group_generators *gens,
                   const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                   uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX])
{
    int rc;

    if (tier == NULL || gens == NULL || uid == NULL || M == NULL)
        return GY_ERR_ARG;

    /* M1 = HashToG("grp-m1", UID). */
    rc = gy_group_hash_to_g(tier, GY_GROUP_M1_PURPOSE, uid, GY_GROUP_UID_BYTES,
                            M[0]);
    if (rc != GY_OK)
        return rc;
    /* M2 = EncodeToG(UID). */
    rc = tier->encode_uid(M[1], uid);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    /* M3 = G_m3^m3 (redemption date). */
    return gy_group_auth_m3(tier, gens, date, M[2]);
}

int
gy_group_attr_profile(const struct gy_group_tier *tier,
                      const uint8_t uid[GY_GROUP_UID_BYTES],
                      const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                      uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX])
{
    uint8_t input[GY_GROUP_PROFILEKEY_BYTES + GY_GROUP_UID_BYTES];
    int rc;

    if (tier == NULL || uid == NULL || pk == NULL || M == NULL)
        return GY_ERR_ARG;

    /* M1 = HashToG("grp-m1", UID). */
    rc = gy_group_hash_to_g(tier, GY_GROUP_M1_PURPOSE, uid, GY_GROUP_UID_BYTES,
                            M[0]);
    if (rc != GY_OK)
        return rc;
    /* M2 = EncodeToG(UID). */
    rc = tier->encode_uid(M[1], uid);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    /* M3 = HashToG1("grp-m3", ProfileKey || UID). */
    memcpy(input, pk, GY_GROUP_PROFILEKEY_BYTES);
    memcpy(input + GY_GROUP_PROFILEKEY_BYTES, uid, GY_GROUP_UID_BYTES);
    rc = gy_group_hash_to_g1(tier, GY_GROUP_M3_PURPOSE, input, sizeof(input),
                             M[2]);
    if (rc != GY_OK)
        return rc;
    /* M4 = EncodeToG(ProfileKey). */
    rc = tier->encode_pk(M[3], pk);
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}
