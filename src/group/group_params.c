/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_params.h"

#include "group_hash.h"

#include "error.h"
#include "rng.h"
#include "suite.h" /* gy_suite_desc, struct gy_iov, GY_HASH_MAX */
#include "util.h"

/*
 * Frozen NUMS seed purposes (GROUP_SPEC section 2.2 item 2), in the enum order
 * of group_params.h.  Each becomes the D-GEN-3 domain
 * "geryon.1.<suite_name>.sysparams.<name>" fed to hash_to_group.  Frozen at the
 * first published KAT vectors; changing a string reshapes every generator.
 */
static const char *const gy_group_gen_purpose[GY_GROUP_GEN_COUNT] = {
    "sysparams.w",  "sysparams.wprime", "sysparams.x0", "sysparams.x1",
    "sysparams.y1", "sysparams.y2",     "sysparams.y3", "sysparams.y4",
    "sysparams.m1", "sysparams.m2",     "sysparams.m3", "sysparams.m4",
    "sysparams.V",  "sysparams.a1",     "sysparams.a2", "sysparams.b1",
    "sysparams.b2", "sysparams.j1",     "sysparams.j2", "sysparams.j3",
};

/*
 * Derive-purpose domains, one per encryption scheme (section 2.2 item 3,
 * section 2.2 item 5 registry).  Frozen at first published KATs.
 */
#define GY_GROUP_DERIVE_SALT "grp-derive"
#define GY_GROUP_DERIVE_UID "grp-derive-uid"
#define GY_GROUP_DERIVE_PK "grp-derive-pk"

/*
 * Wide segment per derived scalar (section 2.2 item 3): the HKDF okm is
 * partitioned into GY_GROUP_DERIVE_SEG-byte segments, each reduced to a
 * canonical scalar by the provider hash_to_scalar (geryon's sole scalar
 * reduction into schnorr).  64 bytes exceeds both group orders with margin;
 * frozen at first published KATs.
 */
#define GY_GROUP_DERIVE_SEG 64

int
gy_group_generators_derive(const struct gy_group_tier *tier,
                           struct gy_group_generators *gens)
{
    size_t i;
    int rc;

    if (tier == NULL || gens == NULL)
        return GY_ERR_ARG;

    /* Zero the whole struct so the unused per-row tail on the 255 tier (points
     * are point_len < GY_GROUP_POINT_MAX) is defined, not stack garbage: the
     * objects must be byte-deterministic for the KATs and safe to compare or
     * serialize wholesale. */
    memset(gens, 0, sizeof(*gens));

    for (i = 0; i < GY_GROUP_GEN_COUNT; i++) {
        rc = gy_group_hash_to_g(tier, gy_group_gen_purpose[i], NULL, 0,
                                gens->g[i]);
        if (rc != GY_OK)
            return rc;
    }
    return GY_OK;
}

int
gy_group_master_key(const struct gy_group_tier *tier, uint8_t *out)
{
    if (tier == NULL || out == NULL)
        return GY_ERR_ARG;
    return gy_random_bytes(out, tier->master_key_len);
}

/*
 * Derive the two scalars of one encryption scheme: HKDF-expand the PRK under
 * the scheme domain into a 2*SEG okm, then reduce each SEG-byte segment to a
 * canonical scalar via the provider hash_to_scalar (dst = the same scheme
 * domain).  s0, s1 each receive tier->scalar_len bytes.
 */
static int
group_derive_scheme(const struct gy_group_tier *tier,
                    const struct gy_suite_desc *desc, const uint8_t *prk,
                    const char *purpose, uint8_t *s0, uint8_t *s1)
{
    uint8_t info[GY_GROUP_DOMAIN_MAX];
    uint8_t okm[2 * GY_GROUP_DERIVE_SEG];
    size_t ilen;
    int rc;

    rc = gy_group_domain(tier->suite_id, purpose, info, sizeof(info), &ilen);
    if (rc != GY_OK)
        return rc;

    rc = desc->hkdf_expand(okm, sizeof(okm), prk, info, ilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->hash_to_scalar(s0, okm, GY_GROUP_DERIVE_SEG, info, ilen);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = tier->hash_to_scalar(s1, okm + GY_GROUP_DERIVE_SEG,
                              GY_GROUP_DERIVE_SEG, info, ilen);
    rc = (rc == 0) ? GY_OK : GY_ERR_CRYPTO;

out:
    gy_secure_zero(okm, sizeof(okm));
    gy_secure_zero(info, sizeof(info));
    return rc;
}

int
gy_group_secret_derive(const struct gy_group_tier *tier, const uint8_t *gmk,
                       size_t gmk_len, struct gy_group_secret_params *sp)
{
    const struct gy_suite_desc *desc;
    struct gy_iov ikm;
    uint8_t salt[GY_GROUP_DOMAIN_MAX];
    uint8_t prk[GY_HASH_MAX];
    size_t slen;
    int rc;

    if (tier == NULL || gmk == NULL || sp == NULL)
        return GY_ERR_ARG;
    if (gmk_len != tier->master_key_len)
        return GY_ERR_ARG;
    desc = gy_suite_desc(tier->suite_id);
    if (desc == NULL)
        return GY_ERR_ARG;

    /* Define the unused per-scalar tail on the 255 tier (see generators). */
    memset(sp, 0, sizeof(*sp));

    rc = gy_group_domain(tier->suite_id, GY_GROUP_DERIVE_SALT, salt,
                         sizeof(salt), &slen);
    if (rc != GY_OK)
        return rc;

    ikm.p = gmk;
    ikm.len = gmk_len;
    rc = desc->hkdf_extract(prk, salt, slen, &ikm, 1);
    if (rc != GY_OK)
        goto out;

    rc = group_derive_scheme(tier, desc, prk, GY_GROUP_DERIVE_UID, sp->a1,
                             sp->a2);
    if (rc != GY_OK)
        goto out;
    rc = group_derive_scheme(tier, desc, prk, GY_GROUP_DERIVE_PK, sp->b1,
                             sp->b2);

out:
    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(salt, sizeof(salt));
    if (rc != GY_OK)
        gy_group_secret_clear(sp);
    return rc;
}

/*
 * Two-generator multiexp: out = g0^e0 * g1^e1 (section 3.4's A and B).  All
 * operands are tier->point_len / scalar_len bytes.
 */
static int
group_two_muladd(const struct gy_group_tier *tier, const uint8_t *g0,
                 const uint8_t *e0, const uint8_t *g1, const uint8_t *e1,
                 uint8_t *out)
{
    uint8_t t0[GY_GROUP_POINT_MAX];
    uint8_t t1[GY_GROUP_POINT_MAX];
    int rc;

    rc = tier->point_scalarmul(t0, e0, g0);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_scalarmul(t1, e1, g1);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_add(out, t0, t1);
    return (rc == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_public_derive(const struct gy_group_tier *tier,
                       const struct gy_group_generators *gens,
                       const struct gy_group_secret_params *sp,
                       struct gy_group_public_params *pp)
{
    int rc;

    if (tier == NULL || gens == NULL || sp == NULL || pp == NULL)
        return GY_ERR_ARG;

    /* Define the unused per-point tail on the 255 tier (see generators). */
    memset(pp, 0, sizeof(*pp));

    rc = group_two_muladd(tier, gens->g[GY_GEN_A1], sp->a1, gens->g[GY_GEN_A2],
                          sp->a2, pp->A);
    if (rc != GY_OK)
        goto err;
    rc = group_two_muladd(tier, gens->g[GY_GEN_B1], sp->b1, gens->g[GY_GEN_B2],
                          sp->b2, pp->B);
    if (rc != GY_OK)
        goto err;
    return GY_OK;

err:
    gy_secure_zero(pp, sizeof(*pp));
    return rc;
}

void
gy_group_secret_clear(struct gy_group_secret_params *sp)
{
    if (sp != NULL)
        gy_secure_zero(sp, sizeof(*sp));
}
