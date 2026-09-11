/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_STMT_H
#define GY_GROUP_STMT_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h" /* GY_GROUP_ATTR_AUTH */
#include "group_tier.h" /* GY_GROUP_MAX_EQ/MAX_K/POINT_MAX/SCALAR_MAX */

/*
 * Shared proof-statement assembly for the credential NIZKs (GER-M8-07, the
 * client/server split, GROUP_SPEC section 8.3).  The five build_pi_* helpers and
 * the handful of arithmetic helpers below are the ONLY code the client-role and
 * server-role translation units share; they are sk-free (they take public
 * params, points, and presentations/requests, never a ServerSecretParams), so
 * neither the shared layer nor its presence in the client facade can leak
 * issuance capability.  Isolating them here is what lets the two facades be
 * separate targets with a link-time symbol check (nm_scope_server.sh).
 *
 * The witness-index enums are shared BY CONSTRUCTION: build_pi_* place a
 * generator at gm[eq][idx] and the prover places the matching witness at w[idx],
 * so the prover TU (client or server) and the statement builder MUST agree on
 * the index.  Defining them once here is a correctness requirement, not a
 * convenience.  pi_I uses literal indices 0..6 consistently and needs no enum.
 *
 * The struct types appear only as pointer parameters, so forward declarations
 * suffice in the header; group_stmt.c pulls the full definitions.
 */

struct gy_group_tier;
struct gy_group_generators;
struct gy_group_mac_tag;
struct gy_group_auth_presentation;
struct gy_group_pk_presentation;
struct gy_group_pk_request;
struct gy_group_pk_commitment;

/* pi_A witnesses (k = 6): (z, a1, a2, z0, z1, t). */
enum { PA_Z = 0, PA_A1, PA_A2, PA_Z0, PA_Z1, PA_T };
/* pi_P witnesses (k = 9): (z, a1, a2, b1, b2, z0, z1, z2, t). */
enum { PP_Z = 0, PP_A1, PP_A2, PP_B1, PP_B2, PP_Z0, PP_Z1, PP_Z2, PP_T };
/* pi_BR witnesses (k = 4): (y, r1, r2, j3). */
enum { BR_Y = 0, BR_R1, BR_R2, BR_J3 };
/* pi_BI witnesses (k = 9): (w, wprime, y1, y2, y3, y4, x0, x1, r'). */
enum { BI_W = 0, BI_WP, BI_Y1, BI_Y2, BI_Y3, BI_Y4, BI_X0, BI_X1, BI_RP };

/* ------------------------------------------------------------------------- *
 * Shared group arithmetic (sk-free).
 * ------------------------------------------------------------------------- */

/* out = G^s (single scalar mult).  Returns GY_OK / GY_ERR_CRYPTO. */
int gy_group_gmul(const struct gy_group_tier *tier, uint8_t *out,
                  const uint8_t *G, const uint8_t *s);

/* G = the standard basepoint (G^1). */
int gy_group_basepoint(const struct gy_group_tier *tier, uint8_t *G);

/* M1 = HashToG("grp-m1", uid), M2 = EncodeToG(uid). */
int gy_group_attrs_uid(const struct gy_group_tier *tier, const uint8_t *uid,
                       uint8_t *M1, uint8_t *M2);

/* ------------------------------------------------------------------------- *
 * Shared proof-statement builders (generators matrix gm, witness mask, and
 * public targets P).  The witness VALUES are filled by the prover TU; these
 * only assemble the statement (identical on prover and verifier).
 * ------------------------------------------------------------------------- */

int gy_group_build_pi_i(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *cw, const uint8_t *iparam_I,
    const struct gy_group_mac_tag *tag,
    const uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX],
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX]);

int gy_group_build_pi_a(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *I_A, const uint8_t *A,
    const struct gy_group_auth_presentation *p,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX]);

int gy_group_build_pi_p(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *I_P, const uint8_t *A, const uint8_t *B,
    const struct gy_group_pk_presentation *p,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX]);

int gy_group_build_pi_br(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *G, const struct gy_group_pk_request *req,
    const struct gy_group_pk_commitment *cm,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX]);

int gy_group_build_pi_bi(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    const uint8_t *G, const uint8_t *C_W_P, const uint8_t *I_P,
    const struct gy_group_pk_request *req, const uint8_t *U, const uint8_t *Ut,
    const uint8_t *M1, const uint8_t *M2, const uint8_t *S1, const uint8_t *S2,
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K],
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX]);

#endif /* GY_GROUP_STMT_H */
