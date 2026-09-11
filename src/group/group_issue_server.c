/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_issue.h"

#include "group_hash.h" /* gy_group_domain */
#include "group_stmt.h" /* shared arithmetic + pi_BR/pi_BI builders, BI_* */

#include "error.h"
#include "util.h"

/*
 * Blind-issuance server role (GER-M8-07): verify pi_BR against the stored
 * commitment, homomorphically form the blinded MAC under ServerSecretParams
 * sk_P, and prove pi_BI.  Consumes a gy_group_server_secret, so this TU is
 * SERVER-ONLY (nm_scope_server.sh, GROUP_SPEC section 8.3).
 */

static const char GY_GROUP_ROLE_MEMBER[] = "geryon-group-member";
static const char GY_GROUP_ROLE_ISSUER[] = "geryon-group-server";
#define GY_GROUP_PI_BR_PURPOSE "pi_BR"
#define GY_GROUP_PI_BI_PURPOSE "pi_BI"

/* acc = acc + G^s. */
static int
acc_gmul(const struct gy_group_tier *tier, uint8_t *acc, const uint8_t *G,
         const uint8_t *s)
{
    uint8_t t[GY_GROUP_POINT_MAX], sum[GY_GROUP_POINT_MAX];
    if (tier->point_scalarmul(t, s, G) != 0)
        return GY_ERR_CRYPTO;
    if (tier->point_add(sum, acc, t) != 0)
        return GY_ERR_CRYPTO;
    memcpy(acc, sum, GY_GROUP_POINT_MAX);
    return GY_OK;
}

int
gy_group_pk_blind_issue(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const struct gy_group_server_secret *sk_P,
                        const uint8_t uid[GY_GROUP_UID_BYTES],
                        const struct gy_group_pk_commitment *commit,
                        const struct gy_group_pk_request *req,
                        struct gy_group_pk_blind_response *out)
{
    struct gy_group_server_public pp;
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t w[GY_GROUP_PI_BI_K][GY_GROUP_SCALAR_MAX];
    uint8_t M1[GY_GROUP_POINT_MAX], M2[GY_GROUP_POINT_MAX];
    uint8_t G[GY_GROUP_POINT_MAX], Ut[GY_GROUP_POINT_MAX];
    uint8_t Vp[GY_GROUP_POINT_MAX], e[GY_GROUP_SCALAR_MAX];
    uint8_t u[GY_GROUP_SCALAR_MAX], rp[GY_GROUP_SCALAR_MAX];
    uint8_t tmp[GY_GROUP_SCALAR_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t slen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sk_P == NULL || uid == NULL ||
        commit == NULL || req == NULL || out == NULL)
        return GY_ERR_ARG;
    if (sk_P->n_bound != GY_GROUP_ATTR_PROFILE)
        return GY_ERR_ARG;
    slen = tier->scalar_len;
    memset(out, 0, sizeof(*out));

    if ((rc = gy_group_basepoint(tier, G)) != GY_OK)
        return rc;

    /* Verify pi_BR against the STORED commitment (untrusted request). */
    rc = gy_group_build_pi_br(tier, gens, G, req, commit, gm, mask, P);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_BR_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        return rc;
    rc = tier->gen_verify_conj(
        (const uint8_t(*)[GY_GROUP_POINT_MAX])req->proof_V,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])req->proof_r,
        (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P, GY_GROUP_PI_BR_K,
        GY_GROUP_PI_BR_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    if (rc != 0)
        return GY_ERR_VERIFY;

    /* iparams_P and revealed attributes. */
    if ((rc = gy_group_server_public_from_secret(tier, gens, sk_P, &pp)) !=
        GY_OK)
        return rc;
    if ((rc = gy_group_attrs_uid(tier, uid, M1, M2)) != GY_OK)
        return rc;

    /* Random t, u (U = G^u), r'. */
    memset(out->t, 0, sizeof(out->t));
    memset(u, 0, sizeof(u));
    memset(rp, 0, sizeof(rp));
    tier->scalar_random(out->t);
    tier->scalar_random(u);
    tier->scalar_random(rp);
    if ((rc = gy_group_gmul(tier, out->U, G, u)) != GY_OK)
        goto out;
    if ((rc = tier->point_scalarmul(Ut, out->t, out->U)) != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* Partial MAC V' = W_P + (x0 + x1 t) U + y1 M1 + y2 M2. */
    memset(e, 0, sizeof(e));
    tier->scalar_mul(tmp, sk_P->x1, out->t);
    tier->scalar_add(e, sk_P->x0, tmp);
    memcpy(Vp, sk_P->W, tier->point_len);
    if ((rc = acc_gmul(tier, Vp, out->U, e)) != GY_OK ||
        (rc = acc_gmul(tier, Vp, M1, sk_P->y[0])) != GY_OK ||
        (rc = acc_gmul(tier, Vp, M2, sk_P->y[1])) != GY_OK)
        goto out;

    /* S1 = D1^y3 E1^y4 G^r'. */
    if ((rc = gy_group_gmul(tier, out->S1, req->D1, sk_P->y[2])) != GY_OK ||
        (rc = acc_gmul(tier, out->S1, req->E1, sk_P->y[3])) != GY_OK ||
        (rc = acc_gmul(tier, out->S1, G, rp)) != GY_OK)
        goto out;

    /* S2 = D2^y3 E2^y4 Y^r' * V'. */
    if ((rc = gy_group_gmul(tier, out->S2, req->D2, sk_P->y[2])) != GY_OK ||
        (rc = acc_gmul(tier, out->S2, req->E2, sk_P->y[3])) != GY_OK ||
        (rc = acc_gmul(tier, out->S2, req->Y, rp)) != GY_OK)
        goto out;
    if (tier->point_add(out->S2, out->S2, Vp) != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* pi_BI witnesses and statement. */
    memset(w, 0, sizeof(w));
    memcpy(w[BI_W], sk_P->w, slen);
    memcpy(w[BI_WP], sk_P->wprime, slen);
    memcpy(w[BI_Y1], sk_P->y[0], slen);
    memcpy(w[BI_Y2], sk_P->y[1], slen);
    memcpy(w[BI_Y3], sk_P->y[2], slen);
    memcpy(w[BI_Y4], sk_P->y[3], slen);
    memcpy(w[BI_X0], sk_P->x0, slen);
    memcpy(w[BI_X1], sk_P->x1, slen);
    memcpy(w[BI_RP], rp, slen);

    rc = gy_group_build_pi_bi(tier, gens, G, pp.C_W, pp.I, req, out->U, Ut, M1,
                              M2, out->S1, out->S2, gm, mask, P);
    if (rc != GY_OK)
        goto out;
    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_BI_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->gen_prove_conj(
        out->proof_V, out->proof_r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, GY_GROUP_PI_BI_K,
        GY_GROUP_PI_BI_M, (const uint8_t *)GY_GROUP_ROLE_ISSUER,
        sizeof(GY_GROUP_ROLE_ISSUER) - 1, oi, oilen);
    rc = (rc == 0) ? GY_OK : GY_ERR_CRYPTO;

out:
    gy_secure_zero(w, sizeof(w));
    gy_secure_zero(u, sizeof(u));
    gy_secure_zero(rp, sizeof(rp));
    gy_secure_zero(e, sizeof(e));
    gy_secure_zero(tmp, sizeof(tmp));
    gy_secure_zero(Vp, sizeof(Vp));
    if (rc != GY_OK)
        gy_secure_zero(out, sizeof(*out));
    return rc;
}
