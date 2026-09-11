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
 * AuthCredential server role (GER-M8-07): non-blind issuance under
 * ServerSecretParams sk_A.  This TU consumes a gy_group_server_secret and is
 * therefore SERVER-ONLY; it is linked into geryon_groups_server and MUST NOT
 * appear in the client archive (enforced by nm_scope_server.sh, GROUP_SPEC
 * section 8.3).
 */

/* FS binding for pi_I (GROUP_SPEC section 5.0, frozen). */
static const char GY_GROUP_ROLE_ISSUER[] = "geryon-group-server";
#define GY_GROUP_PI_I_PURPOSE "pi_I"

int
gy_group_auth_issue(const struct gy_group_tier *tier,
                    const struct gy_group_generators *gens,
                    const struct gy_group_server_secret *sk_A,
                    const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                    struct gy_group_auth_response *out)
{
    struct gy_group_server_public pp;
    uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t Pt[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t w[GY_GROUP_PI_I_K][GY_GROUP_SCALAR_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t slen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sk_A == NULL || uid == NULL ||
        out == NULL)
        return GY_ERR_ARG;
    if (sk_A->n_bound != GY_GROUP_ATTR_AUTH)
        return GY_ERR_ARG;
    slen = tier->scalar_len;

    memset(out, 0, sizeof(*out));

    /* Attributes and the MAC (t, U, V). */
    rc = gy_group_attr_auth(tier, gens, uid, date, M);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_mac(tier, sk_A, (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                      GY_GROUP_ATTR_AUTH, &out->mac);
    if (rc != GY_OK)
        return rc;

    /* iparams_A = (C_W_A, I_A) from the secret key. */
    rc = gy_group_server_public_from_secret(tier, gens, sk_A, &pp);
    if (rc != GY_OK)
        goto out;

    /* pi_I statement + secret witnesses. */
    rc = gy_group_build_pi_i(tier, gens, pp.C_W, pp.I, &out->mac,
                             (const uint8_t(*)[GY_GROUP_POINT_MAX])M, gm, mask,
                             Pt);
    if (rc != GY_OK)
        goto out;

    memset(w, 0, sizeof(w));
    memcpy(w[0], sk_A->w, slen);
    memcpy(w[1], sk_A->wprime, slen);
    memcpy(w[2], sk_A->x0, slen);
    memcpy(w[3], sk_A->x1, slen);
    memcpy(w[4], sk_A->y[0], slen);
    memcpy(w[5], sk_A->y[1], slen);
    memcpy(w[6], sk_A->y[2], slen);

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_I_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->gen_prove_conj(
        out->proof_V, out->proof_r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])Pt,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, GY_GROUP_PI_I_K,
        GY_GROUP_PI_I_M, (const uint8_t *)GY_GROUP_ROLE_ISSUER,
        sizeof(GY_GROUP_ROLE_ISSUER) - 1, oi, oilen);
    rc = (rc == 0) ? GY_OK : GY_ERR_CRYPTO;

out:
    gy_secure_zero(w, sizeof(w));
    if (rc != GY_OK)
        gy_secure_zero(out, sizeof(*out));
    return rc;
}
