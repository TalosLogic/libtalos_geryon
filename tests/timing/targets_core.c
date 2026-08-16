/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Timing-validation targets for geryon Layer 1.  geryon requires the
 * timing tests to cover linked-library primitives, not just in-house code, so
 * the X25519, XEdDSA, and AEAD targets exercise the libsodium-backed wrappers
 * directly.  Each target measures a fixed-secret class A against a
 * random-secret class B; a leak shows up as a class-dependent run time and a
 * large |t|.
 *
 * The two sentinel targets validate the harness itself: sentinel_leak is a
 * deliberately data-dependent early-exit loop that MUST be flagged, and
 * sentinel_clean is a fixed-iteration fold that must NOT be.  If either
 * sentinel returns the wrong verdict the harness is untrustworthy.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "aead.h"
#include "ed25519.h"
#include "rng.h"
#include "util.h"
#include "x25519.h"

/* Volatile sinks keep the measured work from being optimized away. */
static volatile uint8_t g_sink_u8;
static volatile int g_sink_int;

/* ---- sentinel_leak: variable-time, MUST fail -------------------------- */

#define SENTINEL_BYTES 32

struct sentinel_state {
    uint8_t secret[SENTINEL_BYTES];
};

static void
sentinel_leak_setup(int cls, void *state)
{
    struct sentinel_state *s = state;
    int i;

    /*
     * Class A: a nonzero-leading secret drives the early-exit loop to the end
     * (slow path).  Class B: all zeros exits on byte 0 (fast path).  The body
     * branches on the secret, which is the leak the harness must catch.
     */
    if (cls == 0) {
        for (i = 0; i < SENTINEL_BYTES; i++)
            s->secret[i] = (uint8_t)(i + 1);
    } else {
        memset(s->secret, 0, sizeof(s->secret));
    }
}

static void
sentinel_leak_run(const void *state)
{
    const struct sentinel_state *s = state;
    uint8_t acc = 0;
    int i;

    for (i = 0; i < SENTINEL_BYTES; i++) {
        if (s->secret[i] == 0)
            break;
        acc ^= s->secret[i];
    }
    g_sink_u8 ^= acc;
}

const struct gy_dudect_target target_sentinel_leak = {
    "sentinel_leak",
    sentinel_leak_setup,
    sentinel_leak_run,
    sizeof(struct sentinel_state),
    2000,
};

/* ---- sentinel_clean: constant-time, must pass ------------------------- */

static void
sentinel_clean_setup(int cls, void *state)
{
    struct sentinel_state *s = state;

    memset(s->secret, cls == 0 ? 0x00 : 0xff, sizeof(s->secret));
}

static void
sentinel_clean_run(const void *state)
{
    const struct sentinel_state *s = state;
    uint8_t acc = 0;
    int i;

    for (i = 0; i < SENTINEL_BYTES; i++)
        acc ^= s->secret[i];
    g_sink_u8 ^= acc;
}

const struct gy_dudect_target target_sentinel_clean = {
    "sentinel_clean",
    sentinel_clean_setup,
    sentinel_clean_run,
    sizeof(struct sentinel_state),
    2000,
};

/* ---- gy_const_memcmp: equal vs first-byte-differs --------------------- */

struct memcmp_state {
    uint8_t a[32];
    uint8_t b[32];
};

static void
const_memcmp_setup(int cls, void *state)
{
    struct memcmp_state *s = state;

    memset(s->a, 0x5a, sizeof(s->a));
    memset(s->b, 0x5a, sizeof(s->b));
    /*
     * Class A: buffers equal.  Class B: they differ in the very first byte.
     * A byte-by-byte compare with an early exit would run far shorter for
     * class B; gy_const_memcmp must not.
     */
    if (cls == 1)
        s->b[0] ^= 0xff;
}

static void
const_memcmp_run(const void *state)
{
    const struct memcmp_state *s = state;

    g_sink_int ^= gy_const_memcmp(s->a, s->b, sizeof(s->a));
}

const struct gy_dudect_target target_const_memcmp = {
    "const_memcmp",
    const_memcmp_setup,
    const_memcmp_run,
    sizeof(struct memcmp_state),
    4000,
};

/* ---- gy_x25519: fixed vs random scalar, fixed peer key ---------------- */

struct x25519_state {
    uint8_t sk[32];
    uint8_t pk[32];
    uint8_t out[32];
};

/* A fixed valid peer public key: the X25519 base-point scalar times 9. */
static const uint8_t x25519_fixed_pk[32] = {
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

/* A single random-looking fixed scalar (not a repeated constant byte, per the
 * D-GEN-10 Hamming-weight rule); X25519 clamps it internally. */
static const uint8_t x25519_fixed_sk[32] = {
    0x71, 0x2e, 0xb4, 0x0d, 0xc6, 0x59, 0xa8, 0x37, 0x1f, 0x93, 0x4a,
    0xe1, 0x08, 0xbd, 0x52, 0x6f, 0x24, 0xcf, 0x85, 0x3a, 0x9c, 0x60,
    0xd7, 0x1b, 0xef, 0x46, 0xa3, 0x58, 0x02, 0xba, 0x7d, 0xe9,
};

static void
x25519_setup(int cls, void *state)
{
    struct x25519_state *s = state;

    memcpy(s->pk, x25519_fixed_pk, sizeof(s->pk));
    /* Both classes draw from the RNG (identical setup work); class A overwrites
     * with the fixed scalar, so only the scalar VALUE differs into the ladder.
     * Class B still varies every trial, so leak detection is unchanged
     * (D-GEN-10). */
    gy_random_bytes(s->sk, sizeof(s->sk));
    if (cls == 0)
        memcpy(s->sk, x25519_fixed_sk, sizeof(s->sk));
}

static void
x25519_run(const void *state)
{
    const struct x25519_state *s = state;
    uint8_t out[32];

    /* Ignore the weak-key return: the timing, not the value, is the point. */
    (void)gy_x25519(out, s->sk, s->pk);
    g_sink_u8 ^= out[0];
}

const struct gy_dudect_target target_x25519 = {
    "x25519", x25519_setup, x25519_run, sizeof(struct x25519_state), 200,
};

/* ---- gy_xeddsa_sign_z: fixed vs random key, fixed msg and Z ----------- */

struct xeddsa_state {
    uint8_t sk[32];
    uint8_t z[64];
    uint8_t msg[32];
    uint8_t sig[64];
};

/*
 * A single fixed draw of random-looking bytes for the class-A key.  A
 * repeated-byte key (all 0x33) gives class A zero input variance and a
 * degenerate Hamming weight; measured against the full-entropy class B that can
 * inflate |t| through DVFS/power effects alone, with no control-flow leak.  A
 * typical random draw keeps fixed-vs-random semantics without that confounder.
 */
static const uint8_t xeddsa_fixed_sk[32] = {
    0x4a, 0x77, 0x1c, 0xe5, 0x93, 0x2b, 0xd8, 0x60, 0xbf, 0x14, 0x3a,
    0xc9, 0x7e, 0x05, 0x62, 0xf1, 0x8d, 0x36, 0xab, 0x50, 0xe2, 0x79,
    0x04, 0xcd, 0x1b, 0x68, 0x9f, 0x42, 0xd3, 0x0a, 0xb7, 0x5e,
};

static void
xeddsa_setup(int cls, void *state)
{
    struct xeddsa_state *s = state;

    memset(s->msg, 0x11, sizeof(s->msg));
    memset(s->z, 0x22, sizeof(s->z));
    /* Both classes draw from the RNG (identical setup work); class A overwrites
     * with the fixed key, so only the key VALUE differs into the sign.  Class B
     * still varies every trial, so leak detection is unchanged (D-GEN-10). */
    gy_random_bytes(s->sk, sizeof(s->sk));
    if (cls == 0)
        memcpy(s->sk, xeddsa_fixed_sk, sizeof(s->sk));
}

static void
xeddsa_run(const void *state)
{
    const struct xeddsa_state *s = state;
    uint8_t sig[64];

    (void)gy_xeddsa_sign_z(sig, s->sk, s->msg, sizeof(s->msg), s->z);
    g_sink_u8 ^= sig[0];
}

const struct gy_dudect_target target_xeddsa_sign = {
    "xeddsa_sign", xeddsa_setup, xeddsa_run, sizeof(struct xeddsa_state), 100,
};

/* ---- AEAD decrypt tag rejection: corrupt-vs-corrupt ------------------
 *
 * The obvious valid-vs-corrupt framing measures the wrong thing.  ChaCha20-
 * Poly1305 is encrypt-then-MAC: gy_aead_decrypt recomputes the Poly1305 tag
 * over the ciphertext, compares it in constant time, and only on success runs
 * the ChaCha20 stream to produce plaintext.  So the accepting class does
 * strictly more work (a full 64-byte stream pass) than the rejecting one, and
 * |t| blows up on EVERY platform -- that is an accept-vs-reject difference on a
 * PUBLIC distinction (a forgery is known to be a forgery), not a secret leak,
 * and a valid message's decrypt time reveals nothing about the key.
 *
 * The security-relevant property is that among FORGERIES the reject time does
 * not depend on WHERE the tag mismatches -- a padding-oracle-style leak from a
 * non-constant-time (early-exit) tag compare.  So both classes here are forged:
 * class A flips the first tag byte, class B the last.  Both take the identical
 * verify-fails-then-return path, and any |t| is a genuine leak in the tag
 * comparison.  Same drift rationale as the Double Ratchet tag target, D-DR-18.
 */

#define AEAD_PT_LEN 64

struct aead_state {
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t ct[AEAD_PT_LEN + 16]; /* ChaCha20-Poly1305 tag is 16 bytes. */
    size_t ctlen;
};

static void
aead_setup(int cls, void *state)
{
    struct aead_state *s = state;
    uint8_t pt[AEAD_PT_LEN];
    size_t ctlen = sizeof(s->ct);
    size_t tagpos;

    memset(s->key, 0x77, sizeof(s->key));
    memset(s->nonce, 0x00, sizeof(s->nonce));
    memset(pt, 0x88, sizeof(pt));

    (void)gy_aead_encrypt(GY_AEAD_CHACHA20POLY1305, s->ct, &ctlen, s->key,
                          s->nonce, sizeof(s->nonce), NULL, 0, pt, sizeof(pt));
    s->ctlen = ctlen;

    /*
     * Both classes forge: class A flips the first tag byte, class B the last.
     * The 16-byte Poly1305 tag occupies the final 16 bytes of the ciphertext.
     */
    tagpos = (cls == 0) ? s->ctlen - 16 : s->ctlen - 1;
    s->ct[tagpos] ^= 0x01;
}

static void
aead_run(const void *state)
{
    const struct aead_state *s = state;
    uint8_t pt[AEAD_PT_LEN];
    size_t ptlen = sizeof(pt);
    int rc;

    rc = gy_aead_decrypt(GY_AEAD_CHACHA20POLY1305, pt, &ptlen, s->key, s->nonce,
                         sizeof(s->nonce), NULL, 0, s->ct, s->ctlen);
    g_sink_int ^= rc;
}

const struct gy_dudect_target target_aead_tag = {
    "aead_tag_reject", aead_setup, aead_run, sizeof(struct aead_state), 200,
};
