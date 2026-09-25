/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_pres.h"

#include "group_attr.h" /* gy_group_auth_m3 */
#include "group_hash.h" /* gy_group_domain */
#include "group_stmt.h" /* gy_group_build_pi_a/p */

#include "error.h"
#include "util.h"

/*
 * Credential presentation server role: the verifier-side pi_A / pi_P
 * checks, which recompute Z from ServerSecretParams and run gen_verify_conj.
 * These consume a gy_group_server_secret, so this TU is SERVER-ONLY and must not
 * appear in the client archive (nm_scope_server.sh, GROUP_SPEC section 8.3).
 */

/* FS binding (GROUP_SPEC section 5.0, frozen). */
static const char GY_GROUP_ROLE_MEMBER[] = "geryon-group-member";
#define GY_GROUP_PI_A_PURPOSE "pi_A"
#define GY_GROUP_PI_P_PURPOSE "pi_P"

/* acc = acc + G^s (variable-base multiply-accumulate). */
static int
muladd(const struct gy_group_tier *tier, uint8_t *acc, const uint8_t *G,
       const uint8_t *s)
{
    uint8_t term[GY_GROUP_POINT_MAX];
    uint8_t sum[GY_GROUP_POINT_MAX];
    int rc;

    rc = tier->point_scalarmul(term, s, G);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_add(sum, acc, term);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    memcpy(acc, sum, GY_GROUP_POINT_MAX);
    return GY_OK;
}

int
gy_group_auth_present_verify(const struct gy_group_tier *tier,
                             const struct gy_group_generators *gens,
                             const struct gy_group_server_secret *sk_A,
                             const struct gy_group_public_params *pp_pub,
                             const struct gy_group_auth_presentation *pres)
{
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t M3[GY_GROUP_POINT_MAX], cy3m3[GY_GROUP_POINT_MAX];
    uint8_t D[GY_GROUP_POINT_MAX], Z[GY_GROUP_POINT_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    struct gy_group_server_public pp;
    size_t plen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sk_A == NULL || pp_pub == NULL ||
        pres == NULL)
        return GY_ERR_ARG;
    if (sk_A->n_bound != GY_GROUP_ATTR_AUTH)
        return GY_ERR_ARG;
    plen = tier->point_len;

    /* iparams_A from sk (eq0 generator I_A; the server holds sk, not iparams). */
    rc = gy_group_server_public_from_secret(tier, gens, sk_A, &pp);
    if (rc != GY_OK)
        return rc;

    /* Everything downstream processes the UNTRUSTED presentation (its date and
     * commitments), so any failure - a non-day-aligned date, a malformed point,
     * the Z-recomputation, the statement build, or the proof check - collapses
     * to the SAME GY_ERR_VERIFY (a tampered presentation must not be
     * distinguishable from a valid-but-wrong one by return code). */

    /* m3 revealed: M3 = G_m3^m3 from the presented (day-aligned) date. */
    rc = gy_group_auth_m3(tier, gens, pres->date, M3);
    if (rc != GY_OK)
        return (rc == GY_ERR_ARG) ? GY_ERR_VERIFY : rc;

    /* Recompute Z = C_V / (W_A C_x0^x0 C_x1^x1 C_y1^y1 C_y2^y2
     * (C_y3 G_m3^m3)^y3). */
    memcpy(D, sk_A->W, plen);                    /* W_A = G_w^w */
    rc = tier->point_add(cy3m3, pres->C_y3, M3); /* C_y3 * G_m3^m3 */
    if (rc != 0)
        return GY_ERR_VERIFY;
    if (muladd(tier, D, pres->C_x0, sk_A->x0) != GY_OK ||
        muladd(tier, D, pres->C_x1, sk_A->x1) != GY_OK ||
        muladd(tier, D, pres->C_y1, sk_A->y[0]) != GY_OK ||
        muladd(tier, D, pres->C_y2, sk_A->y[1]) != GY_OK ||
        muladd(tier, D, cy3m3, sk_A->y[2]) != GY_OK)
        return GY_ERR_VERIFY;
    rc = tier->point_sub(Z, pres->C_V, D);
    if (rc != 0)
        return GY_ERR_VERIFY;

    rc = gy_group_build_pi_a(tier, gens, pp.I, pp_pub->A, pres, gm, mask, P);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    memcpy(P[0], Z, plen);

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_A_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        return rc;

    rc = tier->gen_verify_conj(
        (const uint8_t(*)[GY_GROUP_POINT_MAX])pres->proof_V,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])pres->proof_r,
        (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P, GY_GROUP_PI_A_K,
        GY_GROUP_PI_A_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    return (rc == 0) ? GY_OK : GY_ERR_VERIFY;
}

int
gy_group_pk_present_verify(const struct gy_group_tier *tier,
                           const struct gy_group_generators *gens,
                           const struct gy_group_server_secret *sk_P,
                           const struct gy_group_public_params *pp_pub,
                           const struct gy_group_pk_presentation *pres)
{
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t D[GY_GROUP_POINT_MAX], Z[GY_GROUP_POINT_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    struct gy_group_server_public pp;
    size_t plen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sk_P == NULL || pp_pub == NULL ||
        pres == NULL)
        return GY_ERR_ARG;
    if (sk_P->n_bound != GY_GROUP_ATTR_PROFILE)
        return GY_ERR_ARG;
    plen = tier->point_len;

    rc = gy_group_server_public_from_secret(tier, gens, sk_P, &pp);
    if (rc != GY_OK)
        return rc;

    /* Recompute Z = C_V / (W_P C_x0^x0 C_x1^x1 C_y1^y1 C_y2^y2 C_y3^y3 C_y4^y4).
     * Untrusted presentation data: any failure is a uniform GY_ERR_VERIFY. */
    memcpy(D, sk_P->W, plen);
    if (muladd(tier, D, pres->C_x0, sk_P->x0) != GY_OK ||
        muladd(tier, D, pres->C_x1, sk_P->x1) != GY_OK ||
        muladd(tier, D, pres->C_y1, sk_P->y[0]) != GY_OK ||
        muladd(tier, D, pres->C_y2, sk_P->y[1]) != GY_OK ||
        muladd(tier, D, pres->C_y3, sk_P->y[2]) != GY_OK ||
        muladd(tier, D, pres->C_y4, sk_P->y[3]) != GY_OK)
        return GY_ERR_VERIFY;
    if (tier->point_sub(Z, pres->C_V, D) != 0)
        return GY_ERR_VERIFY;

    rc = gy_group_build_pi_p(tier, gens, pp.I, pp_pub->A, pp_pub->B, pres, gm,
                             mask, P);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    memcpy(P[0], Z, plen);

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_P_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        return rc;

    rc = tier->gen_verify_conj(
        (const uint8_t(*)[GY_GROUP_POINT_MAX])pres->proof_V,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])pres->proof_r,
        (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P, GY_GROUP_PI_P_K,
        GY_GROUP_PI_P_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    return (rc == 0) ? GY_OK : GY_ERR_VERIFY;
}
