/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_cred.h"

#include "group_hash.h" /* gy_group_domain */
#include "group_stmt.h" /* gy_group_build_pi_i */

#include "error.h"
#include "util.h"

/*
 * AuthCredential client role (GER-M8-07): the user-side verification of the
 * issuance proof pi_I.  No ServerSecretParams; sk-free.  The issuance half lives
 * in group_cred_server.c and the two never share a translation unit (the
 * client/server structural split, GROUP_SPEC section 8.3).
 */

/* FS binding for pi_I (GROUP_SPEC section 5.0, frozen). */
static const char GY_GROUP_ROLE_ISSUER[] = "geryon-group-server";
#define GY_GROUP_PI_I_PURPOSE "pi_I"

int
gy_group_auth_verify(const struct gy_group_tier *tier,
                     const struct gy_group_generators *gens,
                     const struct gy_group_server_public *pp_A,
                     const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                     const struct gy_group_auth_response *resp)
{
    uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t Pt[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t oilen;
    int rc;

    if (tier == NULL || gens == NULL || pp_A == NULL || uid == NULL ||
        resp == NULL)
        return GY_ERR_ARG;

    /* Recompute the attributes from the user's own uid and the requested date. */
    rc = gy_group_attr_auth(tier, gens, uid, date, M);
    if (rc != GY_OK)
        return rc;

    rc = gy_group_build_pi_i(tier, gens, pp_A->C_W, pp_A->I, &resp->mac,
                             (const uint8_t(*)[GY_GROUP_POINT_MAX])M, gm, mask,
                             Pt);
    if (rc != GY_OK)
        return rc;

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_I_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        return rc;

    rc = tier->gen_verify_conj(
        (const uint8_t(*)[GY_GROUP_POINT_MAX])resp->proof_V,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])resp->proof_r,
        (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])Pt, GY_GROUP_PI_I_K,
        GY_GROUP_PI_I_M, (const uint8_t *)GY_GROUP_ROLE_ISSUER,
        sizeof(GY_GROUP_ROLE_ISSUER) - 1, oi, oilen);
    return (rc == 0) ? GY_OK : GY_ERR_VERIFY;
}
