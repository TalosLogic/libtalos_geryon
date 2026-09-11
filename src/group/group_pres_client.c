/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_pres.h"

#include "group_attr.h" /* gy_group_redemption_scalar, gy_group_attr_profile */
#include "group_hash.h" /* gy_group_hash_to_g, gy_group_domain */
#include "group_stmt.h" /* gy_group_build_pi_a and _p, PA and PP enums */
#include "group_venc.h" /* gy_group_uid_encrypt, gy_group_pk_encrypt */

#include "error.h"
#include "util.h"

/*
 * Credential presentation client role (GER-M8-07): the member-side proving of
 * pi_A / pi_P.  Uses GroupSecretParams (a1,a2,b1,b2), never ServerSecretParams,
 * so it is sk-free.  The verification halves live in group_pres_server.c.
 */

/* FS binding (GROUP_SPEC section 5.0, frozen). */
static const char GY_GROUP_ROLE_MEMBER[] = "geryon-group-member";
#define GY_GROUP_PI_A_PURPOSE "pi_A"
#define GY_GROUP_PI_P_PURPOSE "pi_P"

/* out = G^s * M  (a section 5.2 commitment); if M is NULL, out = G^s. */
static int
commit(const struct gy_group_tier *tier, uint8_t *out, const uint8_t *G,
       const uint8_t *s, const uint8_t *M)
{
    uint8_t t[GY_GROUP_POINT_MAX];
    int rc;

    rc = tier->point_scalarmul(out, s, G);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    if (M != NULL) {
        memcpy(t, out, GY_GROUP_POINT_MAX);
        rc = tier->point_add(out, t, M);
        if (rc != 0)
            return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_group_auth_present(const struct gy_group_tier *tier,
                      const struct gy_group_generators *gens,
                      const struct gy_group_secret_params *sp,
                      const struct gy_group_public_params *pp_pub,
                      const struct gy_group_server_public *pp_srv,
                      const struct gy_group_mac_tag *cred,
                      const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                      struct gy_group_auth_presentation *out)
{
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t w[GY_GROUP_PI_A_K][GY_GROUP_SCALAR_MAX];
    uint8_t M1[GY_GROUP_POINT_MAX], M2[GY_GROUP_POINT_MAX];
    uint8_t Ut[GY_GROUP_POINT_MAX], Z[GY_GROUP_POINT_MAX];
    uint8_t z[GY_GROUP_SCALAR_MAX], zt[GY_GROUP_SCALAR_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t slen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sp == NULL || pp_pub == NULL ||
        pp_srv == NULL || cred == NULL || uid == NULL || out == NULL)
        return GY_ERR_ARG;
    /* Reject a non-day-aligned date up front (it becomes revealed m3). */
    {
        uint8_t m3tmp[GY_GROUP_SCALAR_MAX];
        rc = gy_group_redemption_scalar(tier, date, m3tmp);
        gy_secure_zero(m3tmp, sizeof(m3tmp));
        if (rc != GY_OK)
            return rc;
    }
    slen = tier->scalar_len;

    memset(out, 0, sizeof(*out));
    out->date = date;

    /* Attributes M1 = HashToG(UID), M2 = EncodeToG(UID). */
    rc = gy_group_hash_to_g(tier, "grp-m1", uid, GY_GROUP_UID_BYTES, M1);
    if (rc != GY_OK)
        return rc;
    rc = tier->encode_uid(M2, uid);
    if (rc != 0)
        return GY_ERR_CRYPTO;

    /* z random; z0 = -z t, z1 = -z a1. */
    memset(z, 0, sizeof(z));
    tier->scalar_random(z);
    memset(w, 0, sizeof(w));
    memcpy(w[PA_Z], z, slen);
    memcpy(w[PA_A1], sp->a1, slen);
    memcpy(w[PA_A2], sp->a2, slen);
    memcpy(w[PA_T], cred->t, slen);
    tier->scalar_mul(zt, z, cred->t);
    tier->scalar_negate(w[PA_Z0], zt); /* z0 = -(z t) */
    tier->scalar_mul(zt, z, sp->a1);
    tier->scalar_negate(w[PA_Z1], zt); /* z1 = -(z a1) */

    /* Commitments (section 5.2 / 5.2.1). */
    rc = tier->point_scalarmul(Ut, cred->t, cred->U); /* U^t */
    if (rc != 0)
        return GY_ERR_CRYPTO;
    if ((rc = commit(tier, out->C_x0, gens->g[GY_GEN_X0], z, cred->U)) !=
            GY_OK ||
        (rc = commit(tier, out->C_x1, gens->g[GY_GEN_X1], z, Ut)) != GY_OK ||
        (rc = commit(tier, out->C_y1, gens->g[GY_GEN_Y1], z, M1)) != GY_OK ||
        (rc = commit(tier, out->C_y2, gens->g[GY_GEN_Y2], z, M2)) != GY_OK ||
        (rc = commit(tier, out->C_y3, gens->g[GY_GEN_Y3], z, NULL)) != GY_OK ||
        (rc = commit(tier, out->C_V, gens->g[GY_GEN_V], z, cred->V)) != GY_OK)
        goto out;

    /* UidCiphertext: E_A1 = M1^a1, E_A2 = E_A1^a2 M2. */
    rc = tier->point_scalarmul(out->E_A1, sp->a1, M1);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }
    if ((rc = commit(tier, out->E_A2, out->E_A1, sp->a2, M2)) != GY_OK)
        goto out;

    /* Z = I_A^z (the prover's target for eq0; never transmitted). */
    rc = tier->point_scalarmul(Z, z, pp_srv->I);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    rc =
        gy_group_build_pi_a(tier, gens, pp_srv->I, pp_pub->A, out, gm, mask, P);
    if (rc != GY_OK)
        goto out;
    memcpy(P[0], Z, tier->point_len);

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_A_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->gen_prove_conj(
        out->proof_V, out->proof_r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, GY_GROUP_PI_A_K,
        GY_GROUP_PI_A_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    rc = (rc == 0) ? GY_OK : GY_ERR_CRYPTO;

out:
    gy_secure_zero(w, sizeof(w));
    gy_secure_zero(z, sizeof(z));
    gy_secure_zero(zt, sizeof(zt));
    if (rc != GY_OK)
        gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_group_pk_present(const struct gy_group_tier *tier,
                    const struct gy_group_generators *gens,
                    const struct gy_group_secret_params *sp,
                    const struct gy_group_public_params *pp_pub,
                    const struct gy_group_server_public *pp_srv,
                    const struct gy_group_mac_tag *cred,
                    const uint8_t uid[GY_GROUP_UID_BYTES],
                    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                    struct gy_group_pk_presentation *out)
{
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t w[GY_GROUP_PI_P_K][GY_GROUP_SCALAR_MAX];
    uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];
    uint8_t Ut[GY_GROUP_POINT_MAX], Z[GY_GROUP_POINT_MAX];
    uint8_t z[GY_GROUP_SCALAR_MAX], zt[GY_GROUP_SCALAR_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    struct gy_group_uid_ct uct;
    struct gy_group_pk_ct pct;
    size_t slen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || sp == NULL || pp_pub == NULL ||
        pp_srv == NULL || cred == NULL || uid == NULL || pk == NULL ||
        out == NULL)
        return GY_ERR_ARG;
    slen = tier->scalar_len;

    memset(out, 0, sizeof(*out));

    /* Attributes M1..M4 (M1 HashToG, M2 EncodeToG(uid), M3 HashToG1(pk||uid),
     * M4 EncodeToG(pk)). */
    rc = gy_group_attr_profile(tier, uid, pk, M);
    if (rc != GY_OK)
        return rc;

    /* z random; z0 = -z t, z1 = -z a1, z2 = -z b1. */
    memset(z, 0, sizeof(z));
    tier->scalar_random(z);
    memset(w, 0, sizeof(w));
    memcpy(w[PP_Z], z, slen);
    memcpy(w[PP_A1], sp->a1, slen);
    memcpy(w[PP_A2], sp->a2, slen);
    memcpy(w[PP_B1], sp->b1, slen);
    memcpy(w[PP_B2], sp->b2, slen);
    memcpy(w[PP_T], cred->t, slen);
    tier->scalar_mul(zt, z, cred->t);
    tier->scalar_negate(w[PP_Z0], zt);
    tier->scalar_mul(zt, z, sp->a1);
    tier->scalar_negate(w[PP_Z1], zt);
    tier->scalar_mul(zt, z, sp->b1);
    tier->scalar_negate(w[PP_Z2], zt);

    /* Commitments. */
    rc = tier->point_scalarmul(Ut, cred->t, cred->U);
    if (rc != 0)
        return GY_ERR_CRYPTO;
    if ((rc = commit(tier, out->C_y1, gens->g[GY_GEN_Y1], z, M[0])) != GY_OK ||
        (rc = commit(tier, out->C_y2, gens->g[GY_GEN_Y2], z, M[1])) != GY_OK ||
        (rc = commit(tier, out->C_y3, gens->g[GY_GEN_Y3], z, M[2])) != GY_OK ||
        (rc = commit(tier, out->C_y4, gens->g[GY_GEN_Y4], z, M[3])) != GY_OK ||
        (rc = commit(tier, out->C_x0, gens->g[GY_GEN_X0], z, cred->U)) !=
            GY_OK ||
        (rc = commit(tier, out->C_x1, gens->g[GY_GEN_X1], z, Ut)) != GY_OK ||
        (rc = commit(tier, out->C_V, gens->g[GY_GEN_V], z, cred->V)) != GY_OK)
        goto out;

    /* Ciphertexts (section 6.3 / 6.4). */
    if ((rc = gy_group_uid_encrypt(tier, sp, uid, &uct)) != GY_OK)
        goto out;
    if ((rc = gy_group_pk_encrypt(tier, sp, pk, uid, &pct)) != GY_OK)
        goto out;
    memcpy(out->E_A1, uct.E_A1, GY_GROUP_POINT_MAX);
    memcpy(out->E_A2, uct.E_A2, GY_GROUP_POINT_MAX);
    memcpy(out->E_B1, pct.E_B1, GY_GROUP_POINT_MAX);
    memcpy(out->E_B2, pct.E_B2, GY_GROUP_POINT_MAX);

    /* Z = I_P^z. */
    rc = tier->point_scalarmul(Z, z, pp_srv->I);
    if (rc != 0) {
        rc = GY_ERR_CRYPTO;
        goto out;
    }

    rc = gy_group_build_pi_p(tier, gens, pp_srv->I, pp_pub->A, pp_pub->B, out,
                             gm, mask, P);
    if (rc != GY_OK)
        goto out;
    memcpy(P[0], Z, tier->point_len);

    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_P_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->gen_prove_conj(
        out->proof_V, out->proof_r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, GY_GROUP_PI_P_K,
        GY_GROUP_PI_P_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    rc = (rc == 0) ? GY_OK : GY_ERR_CRYPTO;

out:
    gy_secure_zero(w, sizeof(w));
    gy_secure_zero(z, sizeof(z));
    gy_secure_zero(zt, sizeof(zt));
    if (rc != GY_OK)
        gy_secure_zero(out, sizeof(*out));
    return rc;
}
