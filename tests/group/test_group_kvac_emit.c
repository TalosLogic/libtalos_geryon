/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Emitter for the independent [CPZ] verify-equation oracle (GER-M8-04/05 task
 * 5, D-GEN-6), BOTH tiers.  geryon's group KVAC/NIZK layer is clean-room and
 * deliberately NOT zkgroup-byte-compatible (D-GRP-4), so there is no external
 * byte-compat oracle; instead an INDEPENDENT reimplementation of the [CPZ]
 * section 3.1/5 verify equations + the Fiat-Shamir transcript
 * (tools/oracles/group_kvac/verify.py) checks the proofs geryon produces.  This
 * program runs the five proofs (pi_I, pi_A, pi_P, pi_BR, pi_BI) on each tier on
 * fixed inputs and writes, per proof, the tier tag, the NAMED atomic points/
 * scalars each conjunction equation is built from, the proof (commitments V_j,
 * shared responses r_i), and the FS binding (k, m, UserID, OtherInfo).  The
 * oracle reconstructs the equation layout itself from GROUP_SPEC and verifies
 * (255 over libsodium ristretto255, 448 over geryon's vendored decaf448 via a
 * shim); it never sees geryon's assembled generator matrix.
 *
 * The emitted test server-secret scalars (sk W, x0, x1, y_i) are FIXED test
 * keys, present only so the oracle can reconstruct the secret-derived Z target
 * of the presentation proofs the same way the [CPZ] section 5.2 verifier does.
 *
 * Not a normal assertion test: with no argument it SKIPs (exit 77); with --dump
 * it writes the vector file.  Capture:
 *   ./tests/test_group_kvac_emit --dump > tests/vectors/group_kvac.vec
 * then verify independently (--decaf448 enables the 448 records):
 *   python3 tools/oracles/group_kvac/verify.py \
 *       --decaf448 build/libdecaf448_shim.so tests/vectors/group_kvac.vec
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_cred.h"
#include "group_hash.h" /* gy_group_domain, GY_GROUP_DOMAIN_MAX */
#include "group_issue.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_pres.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

/* Fixed inputs (shared with the property/statement tests). */
static const uint8_t UID[GY_GROUP_UID_BYTES] = {1, 2,  3,  4,  5,  6,  7,  8,
                                                9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

/* 2024-01-01T00:00:00Z = 19723 * 86400: a day-aligned redemption date. */
#define KVAC_DATE 1704067200ull

/* Tier point/scalar width (equal on both classical tiers); set per tier in
 * emit_all before any emission. */
static size_t COLS = 32;

static void
fixed_scalars(uint8_t s[8][GY_GROUP_SCALAR_MAX], uint8_t base)
{
    size_t j, k;

    memset(s, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++)
        for (k = 0; k < 12; k++)
            s[j][k] = (uint8_t)(base + j * 13 + k + 1);
}

/* Emit "name=hex\n" over n bytes. */
static void
eh(const char *name, const uint8_t *p, size_t n)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < n; i++)
        printf("%02x", p[i]);
    printf("\n");
}

/* Emit the raw bytes of a string (UserID / OtherInfo) as hex. */
static void
eh_str(const char *name, const uint8_t *p, size_t n)
{
    eh(name, p, n);
}

/* Emit the 20 NUMS generators as g0..g19. */
static void
emit_gens(const struct gy_group_generators *gens)
{
    char nm[8];
    size_t i;

    for (i = 0; i < GY_GROUP_GEN_COUNT; i++) {
        snprintf(nm, sizeof(nm), "g%zu", i);
        eh(nm, gens->g[i], COLS);
    }
}

/* Emit the proof block: k, m, then Vc0..Vc{m-1} and r0..r{k-1}. */
static void
emit_proof(const uint8_t V[][GY_GROUP_POINT_MAX],
           const uint8_t r[][GY_GROUP_SCALAR_MAX], size_t m, size_t k)
{
    char nm[8];
    size_t i;

    for (i = 0; i < m; i++) {
        snprintf(nm, sizeof(nm), "Vc%zu", i);
        eh(nm, V[i], COLS);
    }
    for (i = 0; i < k; i++) {
        snprintf(nm, sizeof(nm), "r%zu", i);
        eh(nm, r[i], COLS);
    }
}

static void
emit_header(const struct gy_group_tier *tier, const char *proof,
            const char *role, const char *purpose, size_t k, size_t m)
{
    uint8_t oi[GY_GROUP_DOMAIN_MAX];
    size_t oilen;

    printf("proof=%s\n", proof);
    printf("tier=%u\n", tier->suite_id == GY_SUITE_C25519 ? 255u : 448u);
    printf("k=%zu\n", k);
    printf("m=%zu\n", m);
    printf("max_k=%d\n", GY_GROUP_MAX_K);
    eh_str("user_id", (const uint8_t *)role, strlen(role));
    if (gy_group_domain(tier->suite_id, purpose, oi, sizeof(oi), &oilen) ==
        GY_OK)
        eh_str("other_info", oi, oilen);
}

/* Produce a valid credential MAC over (M1..Mn) under sk. */
static int
make_cred(const struct gy_group_tier *tier,
          const struct gy_group_server_secret *sk,
          const uint8_t M[][GY_GROUP_POINT_MAX], size_t n,
          struct gy_group_mac_tag *cred)
{
    return gy_group_mac(tier, sk, M, n, cred);
}

static int
emit_all(const struct gy_group_tier *tier)
{
    struct gy_group_generators gens;
    struct gy_group_server_secret sk_A, sk_P;
    struct gy_group_server_public pp_A, pp_P;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp_pub;
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    uint8_t sc[8][GY_GROUP_SCALAR_MAX];
    size_t i;

    COLS = tier->point_len;

    if (gy_group_generators_derive(tier, &gens) != GY_OK)
        return -1;
    for (i = 0; i < tier->master_key_len; i++)
        gmk[i] = (uint8_t)(i + 1);
    if (gy_group_secret_derive(tier, gmk, tier->master_key_len, &sp) != GY_OK)
        return -1;
    if (gy_group_public_derive(tier, &gens, &sp, &pp_pub) != GY_OK)
        return -1;

    fixed_scalars(sc, 0xa0);
    if (gy_group_server_keygen_scalars(tier, &gens, GY_GROUP_ATTR_AUTH, sc,
                                       &sk_A) != GY_OK)
        return -1;
    fixed_scalars(sc, 0xb0);
    if (gy_group_server_keygen_scalars(tier, &gens, GY_GROUP_ATTR_PROFILE, sc,
                                       &sk_P) != GY_OK)
        return -1;
    if (gy_group_server_public_from_secret(tier, &gens, &sk_A, &pp_A) !=
            GY_OK ||
        gy_group_server_public_from_secret(tier, &gens, &sk_P, &pp_P) != GY_OK)
        return -1;

    /* ---- pi_I: AuthCredential issuance (section 5.1). ---- */
    {
        struct gy_group_auth_response resp;
        uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];

        if (gy_group_attr_auth(tier, &gens, UID, KVAC_DATE, M) != GY_OK)
            return -1;
        if (gy_group_auth_issue(tier, &gens, &sk_A, UID, KVAC_DATE, &resp) !=
            GY_OK)
            return -1;

        emit_header(tier, "pi_I", "geryon-group-server", "pi_I",
                    GY_GROUP_PI_I_K, GY_GROUP_PI_I_M);
        emit_gens(&gens);
        eh("U", resp.mac.U, COLS);
        eh("t", resp.mac.t, COLS);
        eh("Vtag", resp.mac.V, COLS);
        eh("M1", M[0], COLS);
        eh("M2", M[1], COLS);
        eh("M3", M[2], COLS);
        eh("C_W", pp_A.C_W, COLS);
        eh("I", pp_A.I, COLS);
        emit_proof(resp.proof_V, resp.proof_r, GY_GROUP_PI_I_M,
                   GY_GROUP_PI_I_K);
        printf("\n");
    }

    /* ---- pi_A: AuthCredentialPresentation (section 5.2.1). ---- */
    {
        struct gy_group_mac_tag cred;
        struct gy_group_auth_presentation pres;
        uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
        uint8_t M3[GY_GROUP_POINT_MAX];

        if (gy_group_attr_auth(tier, &gens, UID, KVAC_DATE, M) != GY_OK)
            return -1;
        if (make_cred(tier, &sk_A, (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                      GY_GROUP_ATTR_AUTH, &cred) != GY_OK)
            return -1;
        if (gy_group_auth_present(tier, &gens, &sp, &pp_pub, &pp_A, &cred, UID,
                                  KVAC_DATE, &pres) != GY_OK)
            return -1;
        if (gy_group_auth_m3(tier, &gens, KVAC_DATE, M3) != GY_OK)
            return -1;

        emit_header(tier, "pi_A", "geryon-group-member", "pi_A",
                    GY_GROUP_PI_A_K, GY_GROUP_PI_A_M);
        emit_gens(&gens);
        eh("I", pp_A.I, COLS);
        eh("A", pp_pub.A, COLS);
        eh("C_x0", pres.C_x0, COLS);
        eh("C_x1", pres.C_x1, COLS);
        eh("C_y1", pres.C_y1, COLS);
        eh("C_y2", pres.C_y2, COLS);
        eh("C_y3", pres.C_y3, COLS);
        eh("C_V", pres.C_V, COLS);
        eh("E_A1", pres.E_A1, COLS);
        eh("E_A2", pres.E_A2, COLS);
        eh("M3", M3, COLS);
        /* Test server-secret scalars for the Z reconstruction (eq0 target). */
        eh("sk_W", sk_A.W, COLS);
        eh("sk_x0", sk_A.x0, COLS);
        eh("sk_x1", sk_A.x1, COLS);
        eh("sk_y1", sk_A.y[0], COLS);
        eh("sk_y2", sk_A.y[1], COLS);
        eh("sk_y3", sk_A.y[2], COLS);
        emit_proof(pres.proof_V, pres.proof_r, GY_GROUP_PI_A_M,
                   GY_GROUP_PI_A_K);
        printf("\n");
    }

    /* ---- pi_P: ProfileKeyCredentialPresentation (section 5.2.2). ---- */
    {
        struct gy_group_mac_tag cred;
        struct gy_group_pk_presentation pres;
        uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];

        if (gy_group_attr_profile(tier, UID, PK, M) != GY_OK)
            return -1;
        if (make_cred(tier, &sk_P, (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                      GY_GROUP_ATTR_PROFILE, &cred) != GY_OK)
            return -1;
        if (gy_group_pk_present(tier, &gens, &sp, &pp_pub, &pp_P, &cred, UID,
                                PK, &pres) != GY_OK)
            return -1;

        emit_header(tier, "pi_P", "geryon-group-member", "pi_P",
                    GY_GROUP_PI_P_K, GY_GROUP_PI_P_M);
        emit_gens(&gens);
        eh("I", pp_P.I, COLS);
        eh("A", pp_pub.A, COLS);
        eh("B", pp_pub.B, COLS);
        eh("C_x0", pres.C_x0, COLS);
        eh("C_x1", pres.C_x1, COLS);
        eh("C_y1", pres.C_y1, COLS);
        eh("C_y2", pres.C_y2, COLS);
        eh("C_y3", pres.C_y3, COLS);
        eh("C_y4", pres.C_y4, COLS);
        eh("C_V", pres.C_V, COLS);
        eh("E_A1", pres.E_A1, COLS);
        eh("E_A2", pres.E_A2, COLS);
        eh("E_B1", pres.E_B1, COLS);
        eh("E_B2", pres.E_B2, COLS);
        eh("sk_W", sk_P.W, COLS);
        eh("sk_x0", sk_P.x0, COLS);
        eh("sk_x1", sk_P.x1, COLS);
        eh("sk_y1", sk_P.y[0], COLS);
        eh("sk_y2", sk_P.y[1], COLS);
        eh("sk_y3", sk_P.y[2], COLS);
        eh("sk_y4", sk_P.y[3], COLS);
        emit_proof(pres.proof_V, pres.proof_r, GY_GROUP_PI_P_M,
                   GY_GROUP_PI_P_K);
        printf("\n");
    }

    /* ---- pi_BR / pi_BI: blind issuance (section 5.3). ---- */
    {
        struct gy_group_pk_commitment cm;
        struct gy_group_pk_request req;
        struct gy_group_pk_blind_response resp;
        uint8_t y[GY_GROUP_SCALAR_MAX];
        uint8_t G[GY_GROUP_POINT_MAX], one[GY_GROUP_SCALAR_MAX];
        uint8_t Mp[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];

        memset(one, 0, sizeof(one));
        one[0] = 1;
        if (tier->scalarmul_base(G, one) != 0)
            return -1;

        if (gy_group_pk_commit(tier, &gens, UID, PK, &cm) != GY_OK)
            return -1;
        if (gy_group_pk_request(tier, &gens, UID, PK, &req, y) != GY_OK)
            return -1;
        if (gy_group_pk_blind_issue(tier, &gens, &sk_P, UID, &cm, &req,
                                    &resp) != GY_OK)
            return -1;
        if (gy_group_attr_profile(tier, UID, PK, Mp) != GY_OK)
            return -1;

        /* pi_BR (requester proof over the ciphertexts + commitment). */
        emit_header(tier, "pi_BR", "geryon-group-member", "pi_BR",
                    GY_GROUP_PI_BR_K, GY_GROUP_PI_BR_M);
        emit_gens(&gens);
        eh("Gbase", G, COLS);
        eh("Y", req.Y, COLS);
        eh("D1", req.D1, COLS);
        eh("D2", req.D2, COLS);
        eh("E1", req.E1, COLS);
        eh("E2", req.E2, COLS);
        eh("J1", cm.J1, COLS);
        eh("J2", cm.J2, COLS);
        eh("J3", cm.J3, COLS);
        emit_proof(req.proof_V, req.proof_r, GY_GROUP_PI_BR_M,
                   GY_GROUP_PI_BR_K);
        printf("\n");

        /* pi_BI (issuer proof over the homomorphic response). */
        emit_header(tier, "pi_BI", "geryon-group-server", "pi_BI",
                    GY_GROUP_PI_BI_K, GY_GROUP_PI_BI_M);
        emit_gens(&gens);
        eh("Gbase", G, COLS);
        eh("C_W", pp_P.C_W, COLS);
        eh("I", pp_P.I, COLS);
        eh("Y", req.Y, COLS);
        eh("D1", req.D1, COLS);
        eh("D2", req.D2, COLS);
        eh("E1", req.E1, COLS);
        eh("E2", req.E2, COLS);
        eh("U", resp.U, COLS);
        eh("t", resp.t, COLS);
        eh("M1", Mp[0], COLS);
        eh("M2", Mp[1], COLS);
        eh("S1", resp.S1, COLS);
        eh("S2", resp.S2, COLS);
        emit_proof(resp.proof_V, resp.proof_r, GY_GROUP_PI_BI_M,
                   GY_GROUP_PI_BI_K);
        printf("\n");

        gy_secure_zero(y, sizeof(y));
    }

    gy_group_server_secret_clear(&sk_A);
    gy_group_server_secret_clear(&sk_P);
    gy_group_secret_clear(&sp);
    return 0;
}

int
main(int argc, char **argv)
{
    (void)gy_test_run;

    if (talos_schnorr_init() != 0 || gy_core_init() != GY_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};
        size_t s;

        printf("# geryon group KVAC oracle vectors (both tiers, "
               "GER-M8-04/05).\n");
        printf("# Independent verifier: "
               "tools/oracles/group_kvac/verify.py\n");
        printf("# Records separated by blank lines; key=hexvalue; # comments.\n"
               "\n");
        for (s = 0; s < sizeof(suites); s++) {
            const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
            if (tier == NULL) {
                fprintf(stderr, "no tier for suite %u\n", suites[s]);
                return 1;
            }
            if (emit_all(tier) != 0) {
                fprintf(stderr, "emit failed\n");
                return 1;
            }
        }
        return 0;
    }

    fprintf(stderr, "group KVAC oracle emitter; SKIP.\n"
                    "  Capture: ./tests/test_group_kvac_emit --dump > \\\n"
                    "    tests/vectors/group_kvac.vec\n"
                    "  Verify:  python3 tools/oracles/group_kvac/verify.py \\\n"
                    "    tests/vectors/group_kvac.vec\n");
    return 77;
}
