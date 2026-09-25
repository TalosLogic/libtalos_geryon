/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time timing target for the GROUP_SPEC section 6.4 ProfileKey
 * decryption candidate loop (D-GRP-8), both classical tiers.  This
 * is geryon's ONLY constant-time-critical group composition: gy_group_pk_decrypt
 * candidate-decodes M4', then over the FULL fixed candidate count (64 on the 255
 * tier, 8 on 448; no early exit) tests EB1 = HashToG1(ProfileKey_c, UID)^b1 with
 * const_memcmp and a constant-time select of the winning plaintext.  The timing
 * must not depend on WHICH candidate matches (i.e. on the secret ProfileKey), so
 * the two classes differ only in the ProfileKey value that was encrypted:
 *
 *   class A (cls=0): a FIXED ProfileKey -> a fixed ciphertext.
 *   class B (cls=1): a RANDOM ProfileKey each trial -> the match lands at a
 *                    varying candidate index.
 *
 * Both classes run identical setup (fill the ProfileKey every trial, class A
 * then overwrites with the fixed value; encrypt) so only the value differs into
 * decrypt (D-GEN-10).  GroupSecretParams (the b1/b2 decryption key), the
 * generators, and the UID are the same public/secret context for both classes
 * and are derived once, outside the measured path.  Per [[timing-schnorr-code-
 * only]] the measured code is geryon's own composition; the schnorr/decaf
 * primitives it calls are common-mode across the two classes and cancel.
 *
 * These are HEAVY targets (each decrypt runs the full candidate loop), so a full
 * 1e6-sample run is slow; run them individually with a reduced --samples on a
 * quiet, frequency-pinned core.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_params.h"
#include "group_tier.h"
#include "group_venc.h"
#include "util.h" /* gy_core_init */

#include "talos_schnorr.h"

static volatile uint8_t g_group_sink_u8;

/* Fixed public UID and the class-A ProfileKey. */
static const uint8_t grp_uid[GY_GROUP_UID_BYTES] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t grp_fixed_pk[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

/* Per-tier invariant context, derived once (outside the timer). */
struct grp_ctx {
    const struct gy_group_tier *tier;
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    int ready;
};

static struct grp_ctx grp_ctx_255;
static struct grp_ctx grp_ctx_448;

/* Per-trial state: the ciphertext handed to decrypt. */
struct grp_state {
    struct gy_group_pk_ct ct;
};

static void
grp_global_init(void)
{
    static int done = 0;
    if (done)
        return;
    (void)talos_schnorr_init();
    (void)gy_core_init();
    done = 1;
}

static void
grp_ctx_init(struct grp_ctx *c, uint8_t suite)
{
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    size_t i;

    if (c->ready)
        return;
    grp_global_init();
    c->tier = gy_group_tier_for(suite);
    (void)gy_group_generators_derive(c->tier, &c->gens);
    for (i = 0; i < c->tier->master_key_len; i++)
        gmk[i] = (uint8_t)(i + 1);
    (void)gy_group_secret_derive(c->tier, gmk, c->tier->master_key_len, &c->sp);
    c->ready = 1;
}

static void
grp_setup(struct grp_ctx *c, int cls, void *state)
{
    struct grp_state *s = state;
    static uint64_t st = 0x243f6a8885a308d3ull; /* nonzero xorshift seed */
    uint8_t pk[GY_GROUP_PROFILEKEY_BYTES];
    size_t i;

    /* Both classes fill the ProfileKey every trial (identical setup path);
     * class A then overwrites with the fixed value, so only the value entering
     * decrypt differs (D-GEN-10).  A local xorshift avoids touching geryon's RNG
     * on the class-B path. */
    for (i = 0; i < sizeof(pk); i++) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        pk[i] = (uint8_t)(st >> 24);
    }
    if (cls == 0)
        memcpy(pk, grp_fixed_pk, sizeof(pk));

    (void)gy_group_pk_encrypt(c->tier, &c->sp, pk, grp_uid, &s->ct);
    gy_secure_zero(pk, sizeof(pk));
}

static void
grp_run(struct grp_ctx *c, const void *state)
{
    const struct grp_state *s = state;
    uint8_t out[GY_GROUP_PROFILEKEY_BYTES];
    int rc;

    rc = gy_group_pk_decrypt(c->tier, &c->sp, &s->ct, grp_uid, out);
    /* Consume both the recovered plaintext and the return code so neither the
     * call nor the loop can be dead-code-eliminated. */
    g_group_sink_u8 ^= out[0] ^ (uint8_t)rc;
}

/* 255 tier (64-candidate loop). */
static void
grp255_setup(int cls, void *state)
{
    grp_ctx_init(&grp_ctx_255, GY_SUITE_C25519);
    grp_setup(&grp_ctx_255, cls, state);
}

static void
grp255_run(const void *state)
{
    grp_run(&grp_ctx_255, state);
}

/* 448 tier (8-candidate loop). */
static void
grp448_setup(int cls, void *state)
{
    grp_ctx_init(&grp_ctx_448, GY_SUITE_C448);
    grp_setup(&grp_ctx_448, cls, state);
}

static void
grp448_run(const void *state)
{
    grp_run(&grp_ctx_448, state);
}

/* reps_per_trial = 1: one decrypt already runs the full candidate loop (64 or 8
 * HashToG1 + scalarmul + compare iterations), tens to hundreds of microseconds,
 * far above the timer granularity; repeating only multiplies wall-clock cost. */
const struct gy_dudect_target target_group_pk_decrypt_255 = {
    "group_pk_decrypt_255",
    grp255_setup,
    grp255_run,
    sizeof(struct grp_state),
    1,
};
const struct gy_dudect_target target_group_pk_decrypt_448 = {
    "group_pk_decrypt_448",
    grp448_setup,
    grp448_run,
    sizeof(struct grp_state),
    1,
};
