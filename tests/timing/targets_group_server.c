/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time timing targets for the secret-keyed SERVER operations
 * (GROUP_SPEC section 8.4, GER-M8-07), both classical tiers.  ServerSecretParams
 * are long-lived secret keys, so issuance, blind issuance, and the presentation
 * Z-recomputation must not leak the key through timing.  Each target is a
 * fixed-vs-random test in the SECRET KEY: the two classes derive a
 * ServerSecretParams from the same setup path and differ only in the scalar
 * values that enter the measured operation (D-GEN-10):
 *
 *   class A (cls=0): a FIXED key (deterministic low-order scalars).
 *   class B (cls=1): a RANDOM key each trial (xorshift low-order scalars).
 *
 * Only geryon's own composition is under test (the MAC recompute, the iparams
 * derivation, the Z-recompute muladd, the conjunction statement build); the
 * schnorr/decaf primitives it calls are constant-time by the provider contract
 * and common-mode across the two classes ([[timing-schnorr-code-only]]).  Keys
 * use low-order scalars (top bytes zero) so every class-B draw is a canonical
 * scalar below both group orders without touching geryon's RNG on the hot path.
 *
 * HEAVY targets (each runs a full proof / verify); a 1e6-sample certification is
 * slow and is run individually on a quiet, frequency-pinned core.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_cred.h"
#include "group_issue.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_pres.h"
#include "group_tier.h"
#include "util.h" /* gy_core_init */

#include "talos_schnorr.h"

static volatile uint8_t g_srv_sink_u8;

/* Fixed public UID / ProfileKey used to build the invariant request context. */
static const uint8_t srv_uid[GY_GROUP_UID_BYTES] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t srv_pk[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

#define SRV_DATE 1704067200ull /* day-aligned */

/* Per-tier invariant context, derived once (outside the timer). */
struct srv_ctx {
    const struct gy_group_tier *tier;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp_pub;
    struct gy_group_pk_commitment commit; /* for blind issuance */
    struct gy_group_pk_request request;   /* a fixed valid pi_BR request */
    int ready;
};

static struct srv_ctx srv_ctx_255;
static struct srv_ctx srv_ctx_448;

/* xorshift state, shared by all class-B setups (public-path randomness only). */
static uint64_t srv_st = 0x9e3779b97f4a7c15ull;

/*
 * Fill the eight KeyGen scalars: fixed pattern (class A) or xorshift (class B),
 * both confined to the low 16 bytes so the result is a canonical scalar below
 * both group orders, with the rest zeroed for byte-determinism.
 */
static void
srv_fill_scalars(uint8_t sc[8][GY_GROUP_SCALAR_MAX], int cls)
{
    size_t j, k;

    memset(sc, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++) {
        for (k = 0; k < 16; k++) {
            if (cls == 0) {
                sc[j][k] = (uint8_t)(0xa0 + j * 13 + k + 1);
            } else {
                srv_st ^= srv_st << 13;
                srv_st ^= srv_st >> 7;
                srv_st ^= srv_st << 17;
                sc[j][k] = (uint8_t)(srv_st >> 24);
            }
        }
    }
}

static void
srv_global_init(void)
{
    static int done = 0;
    if (done)
        return;
    (void)talos_schnorr_init();
    (void)gy_core_init();
    done = 1;
}

static void
srv_ctx_init(struct srv_ctx *c, uint8_t suite)
{
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    uint8_t y[GY_GROUP_SCALAR_MAX];
    size_t i;

    if (c->ready)
        return;
    srv_global_init();
    c->tier = gy_group_tier_for(suite);
    (void)gy_group_generators_derive(c->tier, &c->gens);
    for (i = 0; i < c->tier->master_key_len; i++)
        gmk[i] = (uint8_t)(i + 1);
    (void)gy_group_secret_derive(c->tier, gmk, c->tier->master_key_len, &c->sp);
    (void)gy_group_public_derive(c->tier, &c->gens, &c->sp, &c->pp_pub);
    /* A fixed valid blind request + its commitment (independent of the server
     * key, so any class-A/B sk_P verifies it and the full issue path runs). */
    (void)gy_group_pk_commit(c->tier, &c->gens, srv_uid, srv_pk, &c->commit);
    (void)gy_group_pk_request(c->tier, &c->gens, srv_uid, srv_pk, &c->request,
                              y);
    gy_secure_zero(y, sizeof(y));
    c->ready = 1;
}

/* ---- Issuance (auth_issue): always completes; secret = sk_A. ---- */
struct srv_issue_state {
    struct gy_group_server_secret sk_A;
};

static void
srv_issue_setup(struct srv_ctx *c, int cls, void *state)
{
    struct srv_issue_state *s = state;
    uint8_t sc[8][GY_GROUP_SCALAR_MAX];

    srv_fill_scalars(sc, cls);
    (void)gy_group_server_keygen_scalars(c->tier, &c->gens, GY_GROUP_ATTR_AUTH,
                                         sc, &s->sk_A);
    gy_secure_zero(sc, sizeof(sc));
}

static void
srv_issue_run(struct srv_ctx *c, const void *state)
{
    const struct srv_issue_state *s = state;
    struct gy_group_auth_response resp;
    int rc = gy_group_auth_issue(c->tier, &c->gens, &s->sk_A, srv_uid, SRV_DATE,
                                 &resp);
    g_srv_sink_u8 ^= resp.mac.V[0] ^ (uint8_t)rc;
}

/* ---- Blind issuance (pk_blind_issue): secret = sk_P. ---- */
struct srv_blind_state {
    struct gy_group_server_secret sk_P;
};

static void
srv_blind_setup(struct srv_ctx *c, int cls, void *state)
{
    struct srv_blind_state *s = state;
    uint8_t sc[8][GY_GROUP_SCALAR_MAX];

    srv_fill_scalars(sc, cls);
    (void)gy_group_server_keygen_scalars(c->tier, &c->gens,
                                         GY_GROUP_ATTR_PROFILE, sc, &s->sk_P);
    gy_secure_zero(sc, sizeof(sc));
}

static void
srv_blind_run(struct srv_ctx *c, const void *state)
{
    const struct srv_blind_state *s = state;
    struct gy_group_pk_blind_response resp;
    int rc = gy_group_pk_blind_issue(c->tier, &c->gens, &s->sk_P, srv_uid,
                                     &c->commit, &c->request, &resp);
    g_srv_sink_u8 ^= resp.S2[0] ^ (uint8_t)rc;
}

/* ---- Presentation verify (Z recompute): secret = sk_A. ----
 * A valid presentation must exist for the current key, so setup rebuilds one
 * for each trial's sk_A (keygen -> issue -> present); only the verify is timed. */
struct srv_verify_state {
    struct gy_group_server_secret sk_A;
    struct gy_group_auth_presentation pres;
};

static void
srv_verify_setup(struct srv_ctx *c, int cls, void *state)
{
    struct srv_verify_state *s = state;
    struct gy_group_server_public pp_A;
    struct gy_group_auth_response resp;
    uint8_t sc[8][GY_GROUP_SCALAR_MAX];

    srv_fill_scalars(sc, cls);
    (void)gy_group_server_keygen_scalars(c->tier, &c->gens, GY_GROUP_ATTR_AUTH,
                                         sc, &s->sk_A);
    (void)gy_group_server_public_from_secret(c->tier, &c->gens, &s->sk_A,
                                             &pp_A);
    (void)gy_group_auth_issue(c->tier, &c->gens, &s->sk_A, srv_uid, SRV_DATE,
                              &resp);
    (void)gy_group_auth_present(c->tier, &c->gens, &c->sp, &c->pp_pub, &pp_A,
                                &resp.mac, srv_uid, SRV_DATE, &s->pres);
    gy_secure_zero(sc, sizeof(sc));
}

static void
srv_verify_run(struct srv_ctx *c, const void *state)
{
    const struct srv_verify_state *s = state;
    int rc = gy_group_auth_present_verify(c->tier, &c->gens, &s->sk_A,
                                          &c->pp_pub, &s->pres);
    g_srv_sink_u8 ^= s->pres.C_x0[0] ^ (uint8_t)rc;
}

/* ---- Per-tier setup/run trampolines. ---- */
#define SRV_TARGET(name, op, suite, ctx)                                       \
    static void name##_setup(int cls, void *state)                             \
    {                                                                          \
        srv_ctx_init(&ctx, suite);                                             \
        srv_##op##_setup(&ctx, cls, state);                                    \
    }                                                                          \
    static void name##_run(const void *state)                                  \
    {                                                                          \
        srv_##op##_run(&ctx, state);                                           \
    }

SRV_TARGET(srv_issue_255, issue, GY_SUITE_C25519, srv_ctx_255)
SRV_TARGET(srv_issue_448, issue, GY_SUITE_C448, srv_ctx_448)
SRV_TARGET(srv_blind_255, blind, GY_SUITE_C25519, srv_ctx_255)
SRV_TARGET(srv_blind_448, blind, GY_SUITE_C448, srv_ctx_448)
SRV_TARGET(srv_verify_255, verify, GY_SUITE_C25519, srv_ctx_255)
SRV_TARGET(srv_verify_448, verify, GY_SUITE_C448, srv_ctx_448)

const struct gy_dudect_target target_group_issue_255 = {
    "group_issue_255", srv_issue_255_setup, srv_issue_255_run,
    sizeof(struct srv_issue_state), 1};
const struct gy_dudect_target target_group_issue_448 = {
    "group_issue_448", srv_issue_448_setup, srv_issue_448_run,
    sizeof(struct srv_issue_state), 1};
const struct gy_dudect_target target_group_blind_issue_255 = {
    "group_blind_issue_255", srv_blind_255_setup, srv_blind_255_run,
    sizeof(struct srv_blind_state), 1};
const struct gy_dudect_target target_group_blind_issue_448 = {
    "group_blind_issue_448", srv_blind_448_setup, srv_blind_448_run,
    sizeof(struct srv_blind_state), 1};
const struct gy_dudect_target target_group_present_verify_255 = {
    "group_present_verify_255", srv_verify_255_setup, srv_verify_255_run,
    sizeof(struct srv_verify_state), 1};
const struct gy_dudect_target target_group_present_verify_448 = {
    "group_present_verify_448", srv_verify_448_setup, srv_verify_448_run,
    sizeof(struct srv_verify_state), 1};
