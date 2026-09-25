/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_mac.h"

#include "error.h"
#include "util.h"

/*
 * The [CPZ] section 3.1 algebraic MAC (server role): KeyGen, MAC,
 * Verify, and iparams derivation, all under ServerSecretParams.  Every function
 * here consumes a gy_group_server_secret, so this TU is SERVER-ONLY and must not
 * appear in the client archive (nm_scope_server.sh, GROUP_SPEC section 8.3).
 * The MAC wire encode/decode (sk-free) live in the common group_wire.c.
 *
 * The paper is multiplicative; the provider group ops are additive, so each
 * section 4 product term becomes an add and each exponentiation a scalar mult:
 *   W U^e prod Mi^yi   ->   W + e.U + sum yi.Mi.
 */

/* acc <- acc + gen^scalar (variable-base).  acc must already hold a point. */
static int
point_add_muladd(const struct gy_group_tier *tier, uint8_t *acc,
                 const uint8_t *gen, const uint8_t *scalar)
{
    uint8_t term[GY_GROUP_POINT_MAX];
    uint8_t sum[GY_GROUP_POINT_MAX];
    int rc;

    rc = tier->point_scalarmul(term, scalar, gen);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    rc = tier->point_add(sum, acc, term);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    memcpy(acc, sum, tier->point_len);
    return GY_OK;
}

int
gy_group_server_keygen_scalars(const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               unsigned n_bound,
                               const uint8_t scalars[8][GY_GROUP_SCALAR_MAX],
                               struct gy_group_server_secret *sk)
{
    size_t i;
    int rc;

    if (tier == NULL || gens == NULL || scalars == NULL || sk == NULL)
        return GY_ERR_ARG;
    if (n_bound < 3 || n_bound > GY_GROUP_MAC_ATTRS)
        return GY_ERR_ARG;

    /* Zero the whole struct so the unused per-scalar/point tail on the 255 tier
     * is defined (byte-determinism for KATs and safe wholesale zeroize), as in
     * group_params.c. */
    memset(sk, 0, sizeof(*sk));

    memcpy(sk->w, scalars[0], tier->scalar_len);
    memcpy(sk->wprime, scalars[1], tier->scalar_len);
    memcpy(sk->x0, scalars[2], tier->scalar_len);
    memcpy(sk->x1, scalars[3], tier->scalar_len);
    for (i = 0; i < GY_GROUP_MAC_ATTRS; i++)
        memcpy(sk->y[i], scalars[4 + i], tier->scalar_len);

    /* W = G_w^w, "part of sk" (section 4.2). */
    rc = tier->point_scalarmul(sk->W, sk->w, gens->g[GY_GEN_W]);
    if (rc != 0) {
        gy_group_server_secret_clear(sk);
        return GY_ERR_CRYPTO;
    }
    sk->n_bound = (uint8_t)n_bound;
    return GY_OK;
}

int
gy_group_server_keygen(const struct gy_group_tier *tier,
                       const struct gy_group_generators *gens, unsigned n_bound,
                       struct gy_group_server_secret *sk)
{
    uint8_t scalars[8][GY_GROUP_SCALAR_MAX];
    size_t i;
    int rc;

    if (tier == NULL || gens == NULL || sk == NULL)
        return GY_ERR_ARG;

    /* Zero the scratch so the unused tail on the 255 tier is defined before
     * scalar_random overwrites the leading scalar_len bytes. */
    memset(scalars, 0, sizeof(scalars));
    for (i = 0; i < 8; i++)
        tier->scalar_random(scalars[i]);

    rc = gy_group_server_keygen_scalars(tier, gens, n_bound, scalars, sk);
    gy_secure_zero(scalars, sizeof(scalars));
    return rc;
}

int
gy_group_server_public_from_secret(const struct gy_group_tier *tier,
                                   const struct gy_group_generators *gens,
                                   const struct gy_group_server_secret *sk,
                                   struct gy_group_server_public *pp)
{
    uint8_t acc[GY_GROUP_POINT_MAX];
    uint8_t term[GY_GROUP_POINT_MAX];
    size_t i;
    int rc;

    if (tier == NULL || gens == NULL || sk == NULL || pp == NULL)
        return GY_ERR_ARG;
    if (sk->n_bound < 3 || sk->n_bound > GY_GROUP_MAC_ATTRS)
        return GY_ERR_ARG;

    memset(pp, 0, sizeof(*pp));

    /* C_W = G_w^w G_wprime^wprime = W + G_wprime^wprime. */
    rc = tier->point_scalarmul(term, sk->wprime, gens->g[GY_GEN_WPRIME]);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto err;
    }
    rc = tier->point_add(pp->C_W, sk->W, term);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto err;
    }

    /* I = G_V / (G_x0^x0 G_x1^x1 G_y1^y1 ... G_yn'^yn') = G_V - acc. */
    rc = tier->point_scalarmul(acc, sk->x0, gens->g[GY_GEN_X0]);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto err;
    }
    rc = point_add_muladd(tier, acc, gens->g[GY_GEN_X1], sk->x1);
    if (rc != GY_OK)
        goto err;
    for (i = 0; i < sk->n_bound; i++) {
        rc = point_add_muladd(tier, acc, gens->g[GY_GEN_Y1 + i], sk->y[i]);
        if (rc != GY_OK)
            goto err;
    }
    rc = tier->point_sub(pp->I, gens->g[GY_GEN_V], acc);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto err;
    }
    return GY_OK;

err:
    gy_secure_zero(pp, sizeof(*pp));
    return rc;
}

/*
 * Recompute V = W + (x0 + x1 t).U + sum_{i<n'} yi.Mi from a point U and tag
 * scalar t (section 4.3), shared by the MAC core and Verify.  Writes point_len
 * bytes to v_out.
 */
static int
group_mac_recompute_v(const struct gy_group_tier *tier,
                      const struct gy_group_server_secret *sk,
                      const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                      const uint8_t *t, const uint8_t *U, uint8_t *v_out)
{
    uint8_t e[GY_GROUP_SCALAR_MAX];
    uint8_t v[GY_GROUP_POINT_MAX];
    uint8_t ue[GY_GROUP_POINT_MAX];
    size_t i;
    int rc;

    if (n_attr != sk->n_bound)
        return GY_ERR_ARG;

    /* e = x0 + x1 t. */
    memset(e, 0, sizeof(e));
    tier->scalar_mul(e, sk->x1, t);
    tier->scalar_add(e, sk->x0, e);

    /* V = W + U^e. */
    rc = tier->point_scalarmul(ue, e, U);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    rc = tier->point_add(v, sk->W, ue);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    /* V += sum yi.Mi over the bound positions. */
    for (i = 0; i < n_attr; i++) {
        rc = point_add_muladd(tier, v, M[i], sk->y[i]);
        if (rc != GY_OK)
            goto out;
    }
    memcpy(v_out, v, tier->point_len);
    rc = GY_OK;

out:
    gy_secure_zero(e, sizeof(e));
    gy_secure_zero(ue, sizeof(ue));
    gy_secure_zero(v, sizeof(v));
    return rc;
}

int
gy_group_mac_tu(const struct gy_group_tier *tier,
                const struct gy_group_server_secret *sk,
                const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                const uint8_t *t, const uint8_t *u,
                struct gy_group_mac_tag *tag)
{
    int rc;

    if (tier == NULL || sk == NULL || M == NULL || t == NULL || u == NULL ||
        tag == NULL)
        return GY_ERR_ARG;
    if (n_attr != sk->n_bound)
        return GY_ERR_ARG;

    memset(tag, 0, sizeof(*tag));
    memcpy(tag->t, t, tier->scalar_len);

    /* U = G^u, a uniform group element (section 4.3). */
    rc = tier->scalarmul_base(tag->U, u);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto err;
    }
    rc = group_mac_recompute_v(tier, sk, M, n_attr, tag->t, tag->U, tag->V);
    if (rc != GY_OK)
        goto err;
    return GY_OK;

err:
    gy_secure_zero(tag, sizeof(*tag));
    return rc;
}

int
gy_group_mac(const struct gy_group_tier *tier,
             const struct gy_group_server_secret *sk,
             const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
             struct gy_group_mac_tag *tag)
{
    uint8_t t[GY_GROUP_SCALAR_MAX];
    uint8_t u[GY_GROUP_SCALAR_MAX];
    int rc;

    if (tier == NULL || sk == NULL)
        return GY_ERR_ARG;

    /* Zero tails before scalar_random overwrites the leading scalar_len. */
    memset(t, 0, sizeof(t));
    memset(u, 0, sizeof(u));
    tier->scalar_random(t);
    tier->scalar_random(u);

    rc = gy_group_mac_tu(tier, sk, M, n_attr, t, u, tag);
    gy_secure_zero(t, sizeof(t));
    gy_secure_zero(u, sizeof(u));
    return rc;
}

int
gy_group_verify(const struct gy_group_tier *tier,
                const struct gy_group_server_secret *sk,
                const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                const struct gy_group_mac_tag *tag)
{
    uint8_t vp[GY_GROUP_POINT_MAX];
    int rc;

    if (tier == NULL || sk == NULL || M == NULL || tag == NULL)
        return GY_ERR_ARG;

    rc = group_mac_recompute_v(tier, sk, M, n_attr, tag->t, tag->U, vp);
    if (rc != GY_OK)
        return rc;

    /* Constant-time canonical-encoding comparison (section 4.3). */
    rc = tier->point_eq(vp, tag->V);
    gy_secure_zero(vp, sizeof(vp));
    return (rc == 0) ? GY_OK : GY_ERR_VERIFY;
}

void
gy_group_server_secret_clear(struct gy_group_server_secret *sk)
{
    if (sk != NULL)
        gy_secure_zero(sk, sizeof(*sk));
}
