/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_issue.h"

#include "group_hash.h" /* gy_group_hash_to_g1/zq, gy_group_domain */
#include "group_stmt.h" /* shared arithmetic + pi_BR/pi_BI builders, BR_* */

#include "error.h"
#include "util.h"

/*
 * Blind-issuance client role (GER-M8-07): the requester side (build the blind
 * ProfileKeyCredentialRequest and prove pi_BR; verify pi_BI and decrypt the
 * credential) plus the deterministic ProfileKeyCommitment.  No
 * ServerSecretParams; sk-free.  The server's blind-issue half is in
 * group_issue_server.c.
 */

static const char GY_GROUP_ROLE_MEMBER[] = "geryon-group-member";
static const char GY_GROUP_ROLE_ISSUER[] = "geryon-group-server";
#define GY_GROUP_PI_BR_PURPOSE "pi_BR"
#define GY_GROUP_PI_BI_PURPOSE "pi_BI"

/* out = G^s * M. */
static int
gmuladd(const struct gy_group_tier *tier, uint8_t *out, const uint8_t *G,
        const uint8_t *s, const uint8_t *M)
{
    uint8_t t[GY_GROUP_POINT_MAX];
    if (tier->point_scalarmul(t, s, G) != 0)
        return GY_ERR_CRYPTO;
    return (tier->point_add(out, t, M) == 0) ? GY_OK : GY_ERR_CRYPTO;
}

/* M3 = HashToG1("grp-m3", pk||uid), M4 = EncodeToG(pk), j3 = HashToZq. */
static int
attrs_pk(const struct gy_group_tier *tier, const uint8_t *uid,
         const uint8_t *pk, uint8_t *M3, uint8_t *M4, uint8_t *j3)
{
    uint8_t input[GY_GROUP_PROFILEKEY_BYTES + GY_GROUP_UID_BYTES];
    int rc;

    memcpy(input, pk, GY_GROUP_PROFILEKEY_BYTES);
    memcpy(input + GY_GROUP_PROFILEKEY_BYTES, uid, GY_GROUP_UID_BYTES);
    rc = gy_group_hash_to_g1(tier, "grp-m3", input, sizeof(input), M3);
    if (rc != GY_OK)
        return rc;
    if (M4 != NULL && tier->encode_pk(M4, pk) != 0)
        return GY_ERR_CRYPTO;
    if (j3 != NULL)
        rc = gy_group_hash_to_zq(tier, "grp-j3", input, sizeof(input), j3);
    return rc;
}

int
gy_group_pk_commit(const struct gy_group_tier *tier,
                   const struct gy_group_generators *gens,
                   const uint8_t uid[GY_GROUP_UID_BYTES],
                   const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                   struct gy_group_pk_commitment *out)
{
    uint8_t M3[GY_GROUP_POINT_MAX], M4[GY_GROUP_POINT_MAX];
    uint8_t j3[GY_GROUP_SCALAR_MAX];
    int rc;

    if (tier == NULL || gens == NULL || uid == NULL || pk == NULL ||
        out == NULL)
        return GY_ERR_ARG;
    memset(out, 0, sizeof(*out));

    rc = attrs_pk(tier, uid, pk, M3, M4, j3);
    if (rc != GY_OK)
        return rc;
    if ((rc = gmuladd(tier, out->J1, gens->g[GY_GEN_J1], j3, M3)) != GY_OK ||
        (rc = gmuladd(tier, out->J2, gens->g[GY_GEN_J2], j3, M4)) != GY_OK ||
        (rc = gy_group_gmul(tier, out->J3, gens->g[GY_GEN_J3], j3)) != GY_OK)
        goto out;
out:
    gy_secure_zero(j3, sizeof(j3));
    return rc;
}

int
gy_group_pk_request(const struct gy_group_tier *tier,
                    const struct gy_group_generators *gens,
                    const uint8_t uid[GY_GROUP_UID_BYTES],
                    const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                    struct gy_group_pk_request *out,
                    uint8_t y_out[GY_GROUP_SCALAR_MAX])
{
    struct gy_group_pk_commitment cm;
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t w[GY_GROUP_PI_BR_K][GY_GROUP_SCALAR_MAX];
    uint8_t M3[GY_GROUP_POINT_MAX], M4[GY_GROUP_POINT_MAX];
    uint8_t j3[GY_GROUP_SCALAR_MAX], G[GY_GROUP_POINT_MAX];
    uint8_t y[GY_GROUP_SCALAR_MAX], r1[GY_GROUP_SCALAR_MAX];
    uint8_t r2[GY_GROUP_SCALAR_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t slen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || uid == NULL || pk == NULL ||
        out == NULL || y_out == NULL)
        return GY_ERR_ARG;
    slen = tier->scalar_len;
    memset(out, 0, sizeof(*out));

    rc = attrs_pk(tier, uid, pk, M3, M4, j3);
    if (rc != GY_OK)
        return rc;
    rc = gy_group_pk_commit(tier, gens, uid, pk, &cm);
    if (rc != GY_OK)
        return rc;
    if ((rc = gy_group_basepoint(tier, G)) != GY_OK)
        return rc;

    memset(y, 0, sizeof(y));
    memset(r1, 0, sizeof(r1));
    memset(r2, 0, sizeof(r2));
    tier->scalar_random(y);
    tier->scalar_random(r1);
    tier->scalar_random(r2);

    /* Y = G^y; (D1,D2) = (G^r1, Y^r1 M3); (E1,E2) = (G^r2, Y^r2 M4). */
    if ((rc = gy_group_gmul(tier, out->Y, G, y)) != GY_OK ||
        (rc = gy_group_gmul(tier, out->D1, G, r1)) != GY_OK ||
        (rc = gmuladd(tier, out->D2, out->Y, r1, M3)) != GY_OK ||
        (rc = gy_group_gmul(tier, out->E1, G, r2)) != GY_OK ||
        (rc = gmuladd(tier, out->E2, out->Y, r2, M4)) != GY_OK)
        goto out;

    memset(w, 0, sizeof(w));
    memcpy(w[BR_Y], y, slen);
    memcpy(w[BR_R1], r1, slen);
    memcpy(w[BR_R2], r2, slen);
    memcpy(w[BR_J3], j3, slen);

    rc = gy_group_build_pi_br(tier, gens, G, out, &cm, gm, mask, P);
    if (rc != GY_OK)
        goto out;
    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_BR_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        goto out;

    rc = tier->gen_prove_conj(
        out->proof_V, out->proof_r, (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])w, GY_GROUP_PI_BR_K,
        GY_GROUP_PI_BR_M, (const uint8_t *)GY_GROUP_ROLE_MEMBER,
        sizeof(GY_GROUP_ROLE_MEMBER) - 1, oi, oilen);
    if (rc == 0) {
        memcpy(y_out, y, slen);
        rc = GY_OK;
    } else {
        rc = GY_ERR_CRYPTO;
    }

out:
    gy_secure_zero(w, sizeof(w));
    gy_secure_zero(j3, sizeof(j3));
    gy_secure_zero(y, sizeof(y));
    gy_secure_zero(r1, sizeof(r1));
    gy_secure_zero(r2, sizeof(r2));
    if (rc != GY_OK)
        gy_secure_zero(out, sizeof(*out));
    return rc;
}

int
gy_group_pk_blind_receive(const struct gy_group_tier *tier,
                          const struct gy_group_generators *gens,
                          const struct gy_group_server_public *pp_srv,
                          const uint8_t uid[GY_GROUP_UID_BYTES],
                          const struct gy_group_pk_request *req,
                          const uint8_t y[GY_GROUP_SCALAR_MAX],
                          const struct gy_group_pk_blind_response *resp,
                          struct gy_group_mac_tag *out_cred)
{
    uint8_t gm[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX];
    uint8_t mask[GY_GROUP_MAX_EQ][GY_GROUP_MAX_K];
    uint8_t P[GY_GROUP_MAX_EQ][GY_GROUP_POINT_MAX];
    uint8_t M1[GY_GROUP_POINT_MAX], M2[GY_GROUP_POINT_MAX];
    uint8_t G[GY_GROUP_POINT_MAX], Ut[GY_GROUP_POINT_MAX];
    uint8_t S1y[GY_GROUP_POINT_MAX];
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t plen, oilen;
    int rc;

    if (tier == NULL || gens == NULL || pp_srv == NULL || uid == NULL ||
        req == NULL || y == NULL || resp == NULL || out_cred == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    memset(out_cred, 0, sizeof(*out_cred));

    if ((rc = gy_group_basepoint(tier, G)) != GY_OK)
        return rc;
    if ((rc = gy_group_attrs_uid(tier, uid, M1, M2)) != GY_OK)
        return rc;
    if (tier->point_scalarmul(Ut, resp->t, resp->U) != 0)
        return GY_ERR_VERIFY;

    /* Verify pi_BI (untrusted response). */
    rc = gy_group_build_pi_bi(tier, gens, G, pp_srv->C_W, pp_srv->I, req,
                              resp->U, Ut, M1, M2, resp->S1, resp->S2, gm, mask,
                              P);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_group_domain(tier->suite_id, GY_GROUP_PI_BI_PURPOSE, oi, sizeof(oi),
                         &oilen);
    if (rc != GY_OK)
        return rc;
    rc = tier->gen_verify_conj(
        (const uint8_t(*)[GY_GROUP_POINT_MAX])resp->proof_V,
        (const uint8_t(*)[GY_GROUP_SCALAR_MAX])resp->proof_r,
        (const uint8_t(*)[GY_GROUP_MAX_K])mask,
        (const uint8_t(*)[GY_GROUP_MAX_K][GY_GROUP_POINT_MAX])gm,
        (const uint8_t(*)[GY_GROUP_POINT_MAX])P, GY_GROUP_PI_BI_K,
        GY_GROUP_PI_BI_M, (const uint8_t *)GY_GROUP_ROLE_ISSUER,
        sizeof(GY_GROUP_ROLE_ISSUER) - 1, oi, oilen);
    if (rc != 0)
        return GY_ERR_VERIFY;

    /* Decrypt V = S2 / S1^y. */
    if (tier->point_scalarmul(S1y, y, resp->S1) != 0)
        return GY_ERR_VERIFY;
    memcpy(out_cred->t, resp->t, tier->scalar_len);
    memcpy(out_cred->U, resp->U, plen);
    if (tier->point_sub(out_cred->V, resp->S2, S1y) != 0) {
        gy_secure_zero(out_cred, sizeof(*out_cred));
        return GY_ERR_VERIFY;
    }
    return GY_OK;
}
