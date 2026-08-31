/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Timing-validation targets for the classical 448 tier (geryon_c448: X448 +
 * XEd448).  Only geryon-OWNED code that operates on SECRET
 * data is timed; a linked library validates its own primitives' constant-
 * timeness, and timing code that touches only public data is wasteful (it can
 * carry no secret leak).  That principle reduces the tier to two targets:
 *
 *   - gy_x448:      the wrapper over the vendored ladder.  The SECRET is the
 *                   scalar; class A fixes it, class B randomizes it, with a
 *                   fixed peer point.  This covers geryon's added handling (the
 *                   clamp and the constant-time weak-key check on the DH output)
 *                   over the raw-primitive gate target in targets_gate448.c.
 *   - gy_xed448_sign: geryon's in-house XEd448 sign layer (nonce derivation from
 *                   the secret key and the live Z, the Montgomery-to-Edwards
 *                   map, the scalar arithmetic).  The SECRET is the signing key;
 *                   class A fixes it, class B randomizes it, live Z each trial.
 *
 * Deliberately omitted, per the same principle: XEd448 VERIFY operates entirely
 * on public data (public key, message, signature), so it can leak no secret; and
 * the classical c448 X3DH responder adds no geryon-owned secret-dependent branch
 * beyond the X448 DH already covered here (unlike the hybrid responder, whose
 * ML-KEM implicit-rejection compare is a genuine secret-dependent constant-time
 * property timed by target_hybrid_x3dh).
 *
 * Both targets follow the D-GEN-10 rule: both classes do identical per-trial RNG
 * setup work, so only the secret VALUE differs between classes.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "ed448.h"
#include "rng.h"
#include "x448.h"

static volatile uint8_t g_sink_u8;

/* ---- gy_x448: fixed vs random secret scalar, fixed peer point --------- */

struct x448_state {
    uint8_t sk[56];
    uint8_t pk[56];
};

/* A fixed valid peer public key: the X448 base point (u = 5), which is not
 * low-order, so the wrapper's weak-key check takes its accepting path. */
static const uint8_t x448_fixed_pk[56] = {
    5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* A single random-looking fixed scalar (not a repeated constant byte, per the
 * D-GEN-10 Hamming-weight rule); X448 clamps it internally. */
static const uint8_t x448_fixed_sk[56] = {
    0x83, 0x1c, 0x4e, 0xb7, 0x2a, 0xd5, 0x60, 0x19, 0xfe, 0x47, 0xa2, 0x38,
    0x0d, 0xc9, 0x75, 0x6b, 0x14, 0xef, 0x92, 0x5a, 0xbd, 0x03, 0x71, 0xe8,
    0x4f, 0x26, 0xca, 0x99, 0x37, 0x80, 0xd1, 0x6e, 0x1b, 0xf3, 0x58, 0xa4,
    0x0c, 0x67, 0xe2, 0x35, 0x9b, 0x40, 0xd8, 0x7c, 0x21, 0xae, 0x53, 0x08,
    0xc4, 0x6f, 0x1a, 0x95, 0x3d, 0xb0, 0x62, 0xe9,
};

static void
x448_setup(int cls, void *state)
{
    struct x448_state *s = state;

    memcpy(s->pk, x448_fixed_pk, sizeof(s->pk));
    /* Both classes draw from the RNG (identical setup work); class A overwrites
     * with the fixed scalar, so only the scalar VALUE differs into the ladder.
     * Class B still varies every trial, so leak detection is unchanged
     * (D-GEN-10). */
    gy_random_bytes(s->sk, sizeof(s->sk));
    if (cls == 0)
        memcpy(s->sk, x448_fixed_sk, sizeof(s->sk));
}

static void
x448_run(const void *state)
{
    const struct x448_state *s = state;
    uint8_t out[56];

    /* Ignore the weak-key return: the timing, not the value, is the point. */
    (void)gy_x448(out, s->sk, s->pk);
    g_sink_u8 ^= out[0];
}

/* Named "x448_wrap": the raw-ladder gate target in targets_gate448.c already
 * owns "x448"; this one exercises geryon's gy_x448 wrapper (clamp + weak-key
 * check) rather than the vendored primitive directly. */
/* reps_per_trial = 1: X448 is a heavy primitive (hundreds of X25519-equivalents),
 * so a single call per trial already dwarfs the timer granularity; repeating it
 * (as the fast x25519/kdf targets do) would only multiply a 1e6-sample run into
 * hours.  Matches target_hybrid_x3dh, the other heavy target. */
const struct gy_dudect_target target_x448_wrap = {
    "x448_wrap", x448_setup, x448_run, sizeof(struct x448_state), 1,
};

/* ---- gy_xed448_sign: fixed vs random secret key, live Z, fixed msg ---- */

struct xed448_state {
    uint8_t sk[56];
    uint8_t msg[32];
};

/* A single fixed draw of random-looking bytes for the class-A key (same Hamming-
 * weight rationale as the X448 scalar and the 25519 XEdDSA target). */
static const uint8_t xed448_fixed_sk[56] = {
    0x2d, 0x74, 0xc1, 0xe6, 0x93, 0x0b, 0xd8, 0x57, 0xbf, 0x1a, 0x3c, 0xc9,
    0x7e, 0x25, 0x60, 0xf1, 0x8d, 0x36, 0xab, 0x50, 0xe2, 0x09, 0x47, 0xcd,
    0x1b, 0x68, 0x9f, 0x42, 0xd3, 0x7a, 0xb7, 0x5e, 0x04, 0x99, 0x31, 0xac,
    0x6d, 0xf0, 0x22, 0x85, 0x5b, 0xe8, 0x14, 0xc7, 0x3f, 0xa1, 0x59, 0x0e,
    0xd6, 0x63, 0x1c, 0x98, 0x40, 0xbd, 0x72, 0xe5,
};

static void
xed448_setup(int cls, void *state)
{
    struct xed448_state *s = state;

    memset(s->msg, 0x11, sizeof(s->msg));
    /* Both classes draw from the RNG (identical setup work); class A overwrites
     * with the fixed key, so only the key VALUE differs into the sign.  Z is
     * drawn live inside gy_xed448_sign, so both classes carry that variation
     * equally (D-GEN-10). */
    gy_random_bytes(s->sk, sizeof(s->sk));
    if (cls == 0)
        memcpy(s->sk, xed448_fixed_sk, sizeof(s->sk));
}

static void
xed448_run(const void *state)
{
    const struct xed448_state *s = state;
    uint8_t sig[114];

    (void)gy_xed448_sign(sig, s->sk, s->msg, sizeof(s->msg));
    g_sink_u8 ^= sig[0];
}

/* reps_per_trial = 1: XEd448 sign (SHA-512 + a scalar mult) is likewise heavy;
 * one call per trial is well above timer granularity.  See the x448_wrap note. */
const struct gy_dudect_target target_xed448_sign = {
    "xed448_sign", xed448_setup, xed448_run, sizeof(struct xed448_state), 1,
};
