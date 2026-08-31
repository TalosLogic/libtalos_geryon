/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * 448 validation-gate timing target (D-XED-12): the raw libdecaf X448
 * scalar-multiplication primitive, measured fixed-secret (class A) vs
 * random-secret (class B) with a fixed peer point. This validates the vendored
 * build's ladder is constant-time in the SECRET scalar BEFORE any geryon 448
 * code relies on it - the 448 analog of the libsodium-backed
 * target_x25519. The peer point is public; the scalar is the secret, so the
 * scalar is what varies between classes (D-GEN-10: both classes do identical
 * RNG setup work, only the value differs into the ladder). geryon's own
 * gy_x448 wrapper gets its protocol-level target in targets_c448.c.
 *
 * decaf_x448(shared, base, scalar): shared = scalar * base.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include <decaf.h>

static volatile uint8_t g_gate_sink_u8;

/* Peer point (public): the X448 base u-coordinate, 5. */
static const uint8_t x448_fixed_peer[56] = {5};

/* Fixed secret scalar for class A (arbitrary, clamped like any X448 key). */
static const uint8_t x448_fixed_sk[56] = {
    0xa8, 0x1b, 0x2e, 0x8a, 0x70, 0xa5, 0xac, 0x94, 0xff, 0xdb, 0xcc, 0x7d,
    0x0b, 0x9f, 0x3b, 0x2e, 0x2e, 0x39, 0x8f, 0x0e, 0x2c, 0x5f, 0x2a, 0x9c,
    0x1e, 0x0b, 0x77, 0x4a, 0x2b, 0x63, 0x0d, 0x8f, 0x4c, 0x2c, 0x1e, 0x83,
    0x9f, 0x2b, 0x8a, 0x0e, 0x5f, 0x2c, 0x1e, 0x0b, 0x77, 0x4a, 0x2b, 0x63,
    0x0d, 0x8f, 0x4c, 0x2c, 0x1e, 0x83, 0x9f, 0x2b,
};

struct x448_state {
    uint8_t sk[56];
    uint8_t peer[56];
};

static void
x448_setup(int cls, void *state)
{
    struct x448_state *s = state;
    static uint64_t st = 0x243f6a8885a308d3ull; /* nonzero xorshift seed */
    size_t i;

    memcpy(s->peer, x448_fixed_peer, sizeof(s->peer));
    /*
     * Both classes do IDENTICAL setup work (fill the scalar every trial), then
     * class A overwrites with the fixed scalar - so only the scalar VALUE
     * differs into the ladder, never the setup path (D-GEN-10, mirroring
     * target_x25519). This TU links only decaf448, not geryon's RNG, so class B
     * uses a local xorshift64 fill; it need only vary between trials for the
     * class contrast, not be cryptographic.
     *
     * The fill is FULL-RANGE per byte across all 56 bytes: an earlier 4-byte
     * counter pattern tiled 14x gave class B a Hamming-weight profile that
     * differed systematically from the full-entropy fixed class-A scalar, which
     * on some cores (pre-BMI2/ADX Sandy Bridge) shows up as a DVFS/power |t|
     * climb with no control-flow leak. Matching the byte distributions removes
     * that fixed-vs-random confounder.
     */
    for (i = 0; i < sizeof(s->sk); i++) {
        st ^= st << 13;
        st ^= st >> 7;
        st ^= st << 17;
        s->sk[i] = (uint8_t)(st >> 24);
    }
    if (cls == 0)
        memcpy(s->sk, x448_fixed_sk, sizeof(s->sk));
}

static void
x448_run(const void *state)
{
    const struct x448_state *s = state;
    uint8_t out[56];
    decaf_error_t e;

    /* decaf_x448 is warn_unused_result; the error is irrelevant here (the
     * timing, not the value, is the point), so fold it into the sink alongside
     * the output to consume it and defeat dead-code elimination. */
    e = decaf_x448(out, s->peer, s->sk);
    g_gate_sink_u8 ^= out[0] ^ (uint8_t)e;
}

/* reps_per_trial = 1: the X448 scalar mult is tens of microseconds, thousands of
 * times the RDTSCP granularity, so one call per trial already dominates the timer
 * noise; repeating it only multiplies the wall-clock cost of a 1e6-sample run
 * (which is heavy on pre-BMI2/ADX hosts) for no statistical gain.  Matches the
 * gy_x448-wrapper target and target_hybrid_x3dh. */
const struct gy_dudect_target target_x448 = {
    "x448", x448_setup, x448_run, sizeof(struct x448_state), 1,
};
