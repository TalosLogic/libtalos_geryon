/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_stmt.h"

#include "group_attr.h"   /* GY_GROUP_ATTR_AUTH, GY_GROUP_UID_BYTES */
#include "group_hash.h"   /* gy_group_hash_to_g */
#include "group_issue.h"  /* gy_group_pk_request / _commitment */
#include "group_mac.h"    /* gy_group_mac_tag */
#include "group_params.h" /* generators, GY_GEN_* */
#include "group_pres.h"   /* auth / pk presentations */

#include "error.h"
#include "util.h"

/*
 * GER-M8-07: the sk-free proof-statement layer shared by the client-role and
 * server-role facades.  Bodies are the [CPZ]-transcribed builders moved verbatim
 * from group_cred.c / group_pres.c / group_issue.c; only their linkage changed
 * (file-local statics -> shared gy_group_ symbols) so both facades can call them
 * from separate translation units.
 */

int
gy_group_gmul(const struct gy_group_tier *tier, uint8_t *out, const uint8_t *G,
              const uint8_t *s)
{
    return (tier->point_scalarmul(out, s, G) == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_basepoint(const struct gy_group_tier *tier, uint8_t *G)
{
    uint8_t one[GY_GROUP_SCALAR_MAX];
    memset(one, 0, sizeof(one));
    one[0] = 1;
    return (tier->scalarmul_base(G, one) == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_attrs_uid(const struct gy_group_tier *tier, const uint8_t *uid,
                   uint8_t *M1, uint8_t *M2)
{
    int rc = gy_group_hash_to_g(tier, "grp-m1", uid, GY_GROUP_UID_BYTES, M1);
    if (rc != GY_OK)
        return rc;
    return (tier->encode_uid(M2, uid) == 0) ? GY_OK : GY_ERR_CRYPTO;
}

/* neg = -P = identity - P.  Used only by the pi_BR statement below. */
static int
gneg(const struct gy_group_tier *tier, uint8_t *neg, const uint8_t *P)
{
    uint8_t zero[GY_GROUP_POINT_MAX];
    memset(zero, 0, sizeof(zero));
    return (tier->point_sub(neg, zero, P) == 0) ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_group_build_pi_i(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *cw, const uint8_t *iparam_I,
    const struct gy_group_mac_tag *tag,
    const uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX],
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX])
{
    uint8_t ut[GY_GROUP_POINT_MAX];
    size_t plen = tier->point_len;
    int rc;

    memset(gm, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K * GY_GROUP_POINT_MAX);
    memset(mask, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K);
    memset(P, 0, GY_GROUP_MAX_EQ * GY_GROUP_POINT_MAX);

    /* eq0: C_W_A = G_w^w G_wprime^wprime. */
    memcpy(gm[0][0], gens->g[GY_GEN_W], plen);
    memcpy(gm[0][1], gens->g[GY_GEN_WPRIME], plen);
    mask[0][0] = mask[0][1] = 1;
    memcpy(P[0], cw, plen);

    /* eq1: G_V / I_A = G_x0^x0 G_x1^x1 G_y1^y1 G_y2^y2 G_y3^y3. */
    memcpy(gm[1][2], gens->g[GY_GEN_X0], plen);
    memcpy(gm[1][3], gens->g[GY_GEN_X1], plen);
    memcpy(gm[1][4], gens->g[GY_GEN_Y1], plen);
    memcpy(gm[1][5], gens->g[GY_GEN_Y2], plen);
    memcpy(gm[1][6], gens->g[GY_GEN_Y3], plen);
    mask[1][2] = mask[1][3] = mask[1][4] = mask[1][5] = mask[1][6] = 1;
    rc = tier->point_sub(P[1], gens->g[GY_GEN_V], iparam_I);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* eq2: V = G_w^w U^x0 (U^t)^x1 M1^y1 M2^y2 M3^y3. */
    rc = tier->point_scalarmul(ut, tag->t, tag->U); /* U^t */
    if (rc != 0)
        return GY_ERR_CRYPTO;
    memcpy(gm[2][0], gens->g[GY_GEN_W], plen);
    memcpy(gm[2][2], tag->U, plen);
    memcpy(gm[2][3], ut, plen);
    memcpy(gm[2][4], M[0], plen);
    memcpy(gm[2][5], M[1], plen);
    memcpy(gm[2][6], M[2], plen);
    mask[2][0] = mask[2][2] = mask[2][3] = mask[2][4] = mask[2][5] =
        mask[2][6] = 1;
    memcpy(P[2], tag->V, plen);

    gy_secure_zero(ut, sizeof(ut));
    return GY_OK;
}

int
gy_group_build_pi_a(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *I_A, const uint8_t *A,
    const struct gy_group_auth_presentation *p,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX])
{
    uint8_t zero[GY_GROUP_POINT_MAX];
    uint8_t neg_ea1[GY_GROUP_POINT_MAX];
    size_t plen = tier->point_len;
    int rc;

    memset(gm, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K * GY_GROUP_POINT_MAX);
    memset(mask, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K);
    memset(P, 0, GY_GROUP_MAX_EQ * GY_GROUP_POINT_MAX);

    /* neg_ea1 = -E_A1 = identity - E_A1 (for the E_A1^{-a2} term of eq3). */
    memset(zero, 0, sizeof(zero));
    rc = tier->point_sub(neg_ea1, zero, p->E_A1);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* eq0: Z = I_A^z. */
    memcpy(gm[0][PA_Z], I_A, plen);
    mask[0][PA_Z] = 1;

    /* eq1: C_x1 = C_x0^t G_x0^z0 G_x1^z. */
    memcpy(gm[1][PA_T], p->C_x0, plen);
    memcpy(gm[1][PA_Z0], gens->g[GY_GEN_X0], plen);
    memcpy(gm[1][PA_Z], gens->g[GY_GEN_X1], plen);
    mask[1][PA_T] = mask[1][PA_Z0] = mask[1][PA_Z] = 1;
    memcpy(P[1], p->C_x1, plen);

    /* eq2: A = G_a1^a1 G_a2^a2. */
    memcpy(gm[2][PA_A1], gens->g[GY_GEN_A1], plen);
    memcpy(gm[2][PA_A2], gens->g[GY_GEN_A2], plen);
    mask[2][PA_A1] = mask[2][PA_A2] = 1;
    memcpy(P[2], A, plen);

    /* eq3: C_y2 / E_A2 = G_y2^z * E_A1^{-a2}. */
    memcpy(gm[3][PA_Z], gens->g[GY_GEN_Y2], plen);
    memcpy(gm[3][PA_A2], neg_ea1, plen);
    mask[3][PA_Z] = mask[3][PA_A2] = 1;
    rc = tier->point_sub(P[3], p->C_y2, p->E_A2);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* eq4: E_A1 = C_y1^a1 G_y1^z1. */
    memcpy(gm[4][PA_A1], p->C_y1, plen);
    memcpy(gm[4][PA_Z1], gens->g[GY_GEN_Y1], plen);
    mask[4][PA_A1] = mask[4][PA_Z1] = 1;
    memcpy(P[4], p->E_A1, plen);

    /* eq5: C_y3 = G_y3^z. */
    memcpy(gm[5][PA_Z], gens->g[GY_GEN_Y3], plen);
    mask[5][PA_Z] = 1;
    memcpy(P[5], p->C_y3, plen);

    return GY_OK;
}

int
gy_group_build_pi_p(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *I_P, const uint8_t *A, const uint8_t *B,
    const struct gy_group_pk_presentation *p,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX])
{
    uint8_t zero[GY_GROUP_POINT_MAX];
    uint8_t neg_ea1[GY_GROUP_POINT_MAX], neg_eb1[GY_GROUP_POINT_MAX];
    size_t plen = tier->point_len;

    memset(gm, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K * GY_GROUP_POINT_MAX);
    memset(mask, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K);
    memset(P, 0, GY_GROUP_MAX_EQ * GY_GROUP_POINT_MAX);

    memset(zero, 0, sizeof(zero));
    if (tier->point_sub(neg_ea1, zero, p->E_A1) != 0 ||
        tier->point_sub(neg_eb1, zero, p->E_B1) != 0)
        return GY_ERR_CRYPTO;

    /* eq0: Z = I_P^z. */
    memcpy(gm[0][PP_Z], I_P, plen);
    mask[0][PP_Z] = 1;

    /* eq1: C_x1 = C_x0^t G_x0^z0 G_x1^z. */
    memcpy(gm[1][PP_T], p->C_x0, plen);
    memcpy(gm[1][PP_Z0], gens->g[GY_GEN_X0], plen);
    memcpy(gm[1][PP_Z], gens->g[GY_GEN_X1], plen);
    mask[1][PP_T] = mask[1][PP_Z0] = mask[1][PP_Z] = 1;
    memcpy(P[1], p->C_x1, plen);

    /* eq2: A = G_a1^a1 G_a2^a2. */
    memcpy(gm[2][PP_A1], gens->g[GY_GEN_A1], plen);
    memcpy(gm[2][PP_A2], gens->g[GY_GEN_A2], plen);
    mask[2][PP_A1] = mask[2][PP_A2] = 1;
    memcpy(P[2], A, plen);

    /* eq3: B = G_b1^b1 G_b2^b2. */
    memcpy(gm[3][PP_B1], gens->g[GY_GEN_B1], plen);
    memcpy(gm[3][PP_B2], gens->g[GY_GEN_B2], plen);
    mask[3][PP_B1] = mask[3][PP_B2] = 1;
    memcpy(P[3], B, plen);

    /* eq4: C_y2 / E_A2 = G_y2^z * E_A1^{-a2}. */
    memcpy(gm[4][PP_Z], gens->g[GY_GEN_Y2], plen);
    memcpy(gm[4][PP_A2], neg_ea1, plen);
    mask[4][PP_Z] = mask[4][PP_A2] = 1;
    if (tier->point_sub(P[4], p->C_y2, p->E_A2) != 0)
        return GY_ERR_CRYPTO;

    /* eq5: E_A1 = C_y1^a1 G_y1^z1. */
    memcpy(gm[5][PP_A1], p->C_y1, plen);
    memcpy(gm[5][PP_Z1], gens->g[GY_GEN_Y1], plen);
    mask[5][PP_A1] = mask[5][PP_Z1] = 1;
    memcpy(P[5], p->E_A1, plen);

    /* eq6: C_y4 / E_B2 = G_y4^z * E_B1^{-b2}. */
    memcpy(gm[6][PP_Z], gens->g[GY_GEN_Y4], plen);
    memcpy(gm[6][PP_B2], neg_eb1, plen);
    mask[6][PP_Z] = mask[6][PP_B2] = 1;
    if (tier->point_sub(P[6], p->C_y4, p->E_B2) != 0)
        return GY_ERR_CRYPTO;

    /* eq7: E_B1 = C_y3^b1 G_y3^z2. */
    memcpy(gm[7][PP_B1], p->C_y3, plen);
    memcpy(gm[7][PP_Z2], gens->g[GY_GEN_Y3], plen);
    mask[7][PP_B1] = mask[7][PP_Z2] = 1;
    memcpy(P[7], p->E_B1, plen);

    return GY_OK;
}

int
gy_group_build_pi_br(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *G, const struct gy_group_pk_request *req,
    const struct gy_group_pk_commitment *cm,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX])
{
    uint8_t neg_j1[GY_GROUP_POINT_MAX], neg_j2[GY_GROUP_POINT_MAX];
    size_t plen = tier->point_len;

    memset(gm, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K * GY_GROUP_POINT_MAX);
    memset(mask, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K);
    memset(P, 0, GY_GROUP_MAX_EQ * GY_GROUP_POINT_MAX);

    if (gneg(tier, neg_j1, gens->g[GY_GEN_J1]) != GY_OK ||
        gneg(tier, neg_j2, gens->g[GY_GEN_J2]) != GY_OK)
        return GY_ERR_CRYPTO;

    /* eq0 Y=G^y; eq1 D1=G^r1; eq2 E1=G^r2. */
    memcpy(gm[0][BR_Y], G, plen);
    mask[0][BR_Y] = 1;
    memcpy(P[0], req->Y, plen);
    memcpy(gm[1][BR_R1], G, plen);
    mask[1][BR_R1] = 1;
    memcpy(P[1], req->D1, plen);
    memcpy(gm[2][BR_R2], G, plen);
    mask[2][BR_R2] = 1;
    memcpy(P[2], req->E1, plen);

    /* eq3 J3 = G_j3^j3. */
    memcpy(gm[3][BR_J3], gens->g[GY_GEN_J3], plen);
    mask[3][BR_J3] = 1;
    memcpy(P[3], cm->J3, plen);

    /* eq4 D2/J1 = Y^r1 * G_j1^{-j3}. */
    memcpy(gm[4][BR_R1], req->Y, plen);
    memcpy(gm[4][BR_J3], neg_j1, plen);
    mask[4][BR_R1] = mask[4][BR_J3] = 1;
    if (tier->point_sub(P[4], req->D2, cm->J1) != 0)
        return GY_ERR_CRYPTO;

    /* eq5 E2/J2 = Y^r2 * G_j2^{-j3}. */
    memcpy(gm[5][BR_R2], req->Y, plen);
    memcpy(gm[5][BR_J3], neg_j2, plen);
    mask[5][BR_R2] = mask[5][BR_J3] = 1;
    if (tier->point_sub(P[5], req->E2, cm->J2) != 0)
        return GY_ERR_CRYPTO;

    return GY_OK;
}

int
gy_group_build_pi_bi(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *G, const uint8_t *C_W_P, const uint8_t *I_P,
    const struct gy_group_pk_request *req, const uint8_t *U, const uint8_t *Ut,
    const uint8_t *M1, const uint8_t *M2, const uint8_t *S1, const uint8_t *S2,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX])
{
    size_t plen = tier->point_len;

    memset(gm, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K * GY_GROUP_POINT_MAX);
    memset(mask, 0, GY_GROUP_MAX_EQ * GY_GROUP_MAX_K);
    memset(P, 0, GY_GROUP_MAX_EQ * GY_GROUP_POINT_MAX);

    /* eq0 C_W_P = G_w^w G_wprime^wprime. */
    memcpy(gm[0][BI_W], gens->g[GY_GEN_W], plen);
    memcpy(gm[0][BI_WP], gens->g[GY_GEN_WPRIME], plen);
    mask[0][BI_W] = mask[0][BI_WP] = 1;
    memcpy(P[0], C_W_P, plen);

    /* eq1 G_V / I_P = G_x0^x0 G_x1^x1 G_y1^y1 G_y2^y2 G_y3^y3 G_y4^y4. */
    memcpy(gm[1][BI_X0], gens->g[GY_GEN_X0], plen);
    memcpy(gm[1][BI_X1], gens->g[GY_GEN_X1], plen);
    memcpy(gm[1][BI_Y1], gens->g[GY_GEN_Y1], plen);
    memcpy(gm[1][BI_Y2], gens->g[GY_GEN_Y2], plen);
    memcpy(gm[1][BI_Y3], gens->g[GY_GEN_Y3], plen);
    memcpy(gm[1][BI_Y4], gens->g[GY_GEN_Y4], plen);
    mask[1][BI_X0] = mask[1][BI_X1] = mask[1][BI_Y1] = mask[1][BI_Y2] =
        mask[1][BI_Y3] = mask[1][BI_Y4] = 1;
    if (tier->point_sub(P[1], gens->g[GY_GEN_V], I_P) != 0)
        return GY_ERR_CRYPTO;

    /* eq2 S1 = D1^y3 E1^y4 G^r'. */
    memcpy(gm[2][BI_Y3], req->D1, plen);
    memcpy(gm[2][BI_Y4], req->E1, plen);
    memcpy(gm[2][BI_RP], G, plen);
    mask[2][BI_Y3] = mask[2][BI_Y4] = mask[2][BI_RP] = 1;
    memcpy(P[2], S1, plen);

    /* eq3 S2 = D2^y3 E2^y4 Y^r' G_w^w U^x0 (U^t)^x1 M1^y1 M2^y2. */
    memcpy(gm[3][BI_Y3], req->D2, plen);
    memcpy(gm[3][BI_Y4], req->E2, plen);
    memcpy(gm[3][BI_RP], req->Y, plen);
    memcpy(gm[3][BI_W], gens->g[GY_GEN_W], plen);
    memcpy(gm[3][BI_X0], U, plen);
    memcpy(gm[3][BI_X1], Ut, plen);
    memcpy(gm[3][BI_Y1], M1, plen);
    memcpy(gm[3][BI_Y2], M2, plen);
    mask[3][BI_Y3] = mask[3][BI_Y4] = mask[3][BI_RP] = mask[3][BI_W] =
        mask[3][BI_X0] = mask[3][BI_X1] = mask[3][BI_Y1] = mask[3][BI_Y2] = 1;
    memcpy(P[3], S2, plen);

    return GY_OK;
}
