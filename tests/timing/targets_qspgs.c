/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time timing targets for the QSPGS / KR-ML-DSA secret-handling
 * composition (SEC-v1.5.0 LOW-5).  Every target is a fixed-vs-random test in
 * the SECRET input (D-GEN-10): the two classes run the identical code path and
 * differ only in the secret bytes that enter the measured call.
 *
 *   class A (cls=0): a FIXED secret (deterministic bytes / seed).
 *   class B (cls=1): a RANDOM secret each trial (xorshift bytes / seed).
 *
 * Only geryon's OWN composition is under test; the liboqs and libsodium
 * primitives it calls are constant-time by the provider contract (D-PQ-4) and
 * are common-mode across the two classes, so they cancel in the Welch t-test
 * ([[timing-schnorr-code-only]], [[timing-over-schnorr-code-only]]):
 *
 *   krmldsa_randsk_{44,87}
 *       KR-ML-DSA RandSK ([CFG+] Fig. 4): geryon adds the rerandomizer's small
 *       (s1', s2') to the base secret and packs the in-memory signing key.  The
 *       secret is the BASE KEY (a fixed vs random keygen seed); the rerandomizer
 *       rho is held FIXED, so liboqs ExpandS (which rejection-samples from rho)
 *       does identical work in both classes and the only class-varying work is
 *       geryon's constant-time poly add and packing over the secret base key.
 *
 *   qspgs_member_open_{44,87}
 *       The Fetch member-entry read path (gy_qspgs_member_ct_open): AEAD-open a
 *       sealed member tuple under the group key ek and parse it.  The secret is
 *       ek; the libsodium AEAD is common-mode.  A wrong-ek open is a uniform
 *       GY_ERR_VERIFY with no plaintext, so the two classes execute the same
 *       glue regardless of the key.
 *
 *   qspgs_token_check
 *       The server bearer-token / C_UID equality (gy_qspgs_server_token_check,
 *       a single gy_const_memcmp over the token width).  The secret is the
 *       stored token; a fixed presented value probes whether the compare time
 *       leaks how many leading bytes of a guess are correct.
 *
 * NOT a target: the KR-ML-DSA SIGN hot loop.  Its secret-dependent arithmetic
 * is entirely inside liboqs (D-PQ-4, not re-timed here), and its rejection-loop
 * iteration count is a FIPS 204 section 5.5 public quantity that standard
 * ML-DSA varies identically; a fixed-vs-random-key sign target would measure
 * that liboqs loop, not geryon glue.  geryon's sign orchestration is fixed-time
 * given the loop count.  Recorded in QSPGS_SPEC.md section 12.
 *
 * HEAVY targets (randsk runs a full key derivation); a 1e6-sample certification
 * is slow and is run individually on a quiet, frequency-pinned core.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "aead.h"   /* GY_AEAD_CHACHA20POLY1305 */
#include "encode.h" /* GY_SUITE_H25519_512 / GY_SUITE_H448_1024 */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "qspgs_const.h" /* GID/UID/master-key sizes */
#include "qspgs_field.h"
#include "qspgs_keys.h" /* GY_QSPGS_EK_BYTES */
#include "qspgs_server.h"
#include "util.h" /* gy_core_init, gy_secure_zero */

static volatile uint8_t g_qs_sink_u8;

/* xorshift state, shared by all class-B setups (public-path randomness only). */
static uint64_t qs_st = 0x243f6a8885a308d3ull;

static uint8_t
qs_next_byte(void)
{
    qs_st ^= qs_st << 13;
    qs_st ^= qs_st >> 7;
    qs_st ^= qs_st << 17;
    return (uint8_t)(qs_st >> 24);
}

/* Fill buf: fixed pattern (class A) or xorshift (class B). */
static void
qs_fill(uint8_t *buf, size_t len, int cls, uint8_t base)
{
    size_t i;

    for (i = 0; i < len; i++)
        buf[i] = (cls == 0) ? (uint8_t)(base + i) : qs_next_byte();
}

static void
qs_global_init(void)
{
    static int done = 0;
    if (done)
        return;
    (void)gy_core_init();
    done = 1;
}

/* ---- KR-ML-DSA RandSK: secret = base keygen seed. ----------------------- */

/* One rerandomizer, fixed across both classes (public per-pseudonym input). */
static const uint8_t qs_rho[GY_KR44_RAND] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
    0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0, 0x13,
    0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xe0, 0x31, 0x75, 0xb9, 0xfd,
    0x42, 0x86, 0xca, 0x0e, 0x53, 0x97, 0xdb, 0x1f, 0x64, 0xa8, 0xec,
    0x20, 0x75, 0xba, 0xff, 0x35, 0x7a, 0xbf, 0x04, 0x49};

struct qs_randsk44_state {
    uint8_t vkb[GY_KR44_VKB];
    uint8_t skb[GY_KR44_SKB];
};

static void
qs_randsk44_setup(int cls, void *state)
{
    struct qs_randsk44_state *s = state;
    uint8_t seed[GY_KR44_SEED];

    qs_global_init();
    qs_fill(seed, sizeof(seed), cls, 0x40);
    (void)gy_kr44_keygen_base_seed(s->vkb, s->skb, seed);
    gy_secure_zero(seed, sizeof(seed));
}

static void
qs_randsk44_run(const void *state)
{
    const struct qs_randsk44_state *s = state;
    gy_kr44_rsk_t rsk;

    (void)gy_kr44_randsk(&rsk, s->skb, s->vkb, qs_rho);
    g_qs_sink_u8 ^= rsk.opaque[0];
    gy_kr44_rsk_clear(&rsk);
}

struct qs_randsk87_state {
    uint8_t vkb[GY_KR87_VKB];
    uint8_t skb[GY_KR87_SKB];
};

static void
qs_randsk87_setup(int cls, void *state)
{
    struct qs_randsk87_state *s = state;
    uint8_t seed[GY_KR87_SEED];

    qs_global_init();
    qs_fill(seed, sizeof(seed), cls, 0x40);
    (void)gy_kr87_keygen_base_seed(s->vkb, s->skb, seed);
    gy_secure_zero(seed, sizeof(seed));
}

static void
qs_randsk87_run(const void *state)
{
    const struct qs_randsk87_state *s = state;
    gy_kr87_rsk_t rsk;

    (void)gy_kr87_randsk(&rsk, s->skb, s->vkb, qs_rho);
    g_qs_sink_u8 ^= rsk.opaque[0];
    gy_kr87_rsk_clear(&rsk);
}

/* ---- QSPGS member-entry open: secret = group key ek. -------------------- */

#define QS_MEMBER_CT_CAP 256

/* Fixed public GID / UID used to build the sealed fixture (outside the timer). */
static const uint8_t qs_gid[GY_QSPGS_GID_LEN] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
static const uint8_t qs_uid[GY_QSPGS_UID_LEN] = {
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf};

struct qs_member_state {
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t ct[QS_MEMBER_CT_CAP];
    size_t ctlen;
    uint8_t suite;
};

/*
 * Seal a fixed member tuple (UID, r_c, uk) under the per-class ek so the timed
 * open runs the full field decrypt + parse.  Both r_c and uk are fixed; only
 * ek differs between classes, so the ciphertext bytes differ but the code path
 * is identical.  The seal (and its RNG nonce draw) is outside the timer.
 */
static void
qs_member_setup(int cls, void *state, uint8_t suite)
{
    struct qs_member_state *s = state;
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];

    qs_global_init();
    s->suite = suite;
    qs_fill(s->ek, sizeof(s->ek), cls, 0x50);
    memset(rc_open, 0x5c, sizeof(rc_open));
    memset(uk, 0x6d, sizeof(uk));
    s->ctlen = 0;
    (void)gy_qspgs_member_ct_seal(suite, GY_AEAD_CHACHA20POLY1305, s->ek,
                                  qs_gid, qs_uid, GY_QSPGS_UID_LEN, rc_open, uk,
                                  s->ct, sizeof(s->ct), &s->ctlen);
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(uk, sizeof(uk));
}

static void
qs_member_run(const void *state)
{
    const struct qs_member_state *s = state;
    uint8_t form, uid[GY_QSPGS_UID_LEN], rc_open[GY_QSPGS_RC_LEN];
    uint8_t key[GY_QSPGS_MASTER_KEY_MAX];
    size_t uidlen;
    int rc;

    rc = gy_qspgs_member_ct_open(s->suite, GY_AEAD_CHACHA20POLY1305, s->ek,
                                 qs_gid, s->ct, s->ctlen, &form, uid,
                                 sizeof(uid), &uidlen, rc_open, key);
    g_qs_sink_u8 ^= (uint8_t)rc ^ form ^ uid[0] ^ key[0];
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(key, sizeof(key));
}

static void
qs_member_44_setup(int cls, void *state)
{
    qs_member_setup(cls, state, GY_SUITE_H25519_512);
}

static void
qs_member_87_setup(int cls, void *state)
{
    qs_member_setup(cls, state, GY_SUITE_H448_1024);
}

/* ---- Bearer-token / C_UID equality: secret = stored token. -------------- */

struct qs_token_state {
    uint8_t stored[GY_QSPGS_FET_LEN];
    uint8_t presented[GY_QSPGS_FET_LEN];
};

static void
qs_token_setup(int cls, void *state)
{
    struct qs_token_state *s = state;

    /* Presented value is a fixed "guess"; the stored secret is fixed (class A)
     * or random (class B).  A leak would show as compare time tracking the
     * matching-prefix length. */
    memset(s->presented, 0x7a, sizeof(s->presented));
    qs_fill(s->stored, sizeof(s->stored), cls, 0x7a);
}

static void
qs_token_run(const void *state)
{
    const struct qs_token_state *s = state;
    int rc =
        gy_qspgs_server_token_check(s->presented, s->stored, GY_QSPGS_FET_LEN);
    g_qs_sink_u8 ^= (uint8_t)rc;
}

/* ---- Registered targets. ------------------------------------------------ */

const struct gy_dudect_target target_krmldsa_randsk_44 = {
    "krmldsa_randsk_44", qs_randsk44_setup, qs_randsk44_run,
    sizeof(struct qs_randsk44_state), 1};
const struct gy_dudect_target target_krmldsa_randsk_87 = {
    "krmldsa_randsk_87", qs_randsk87_setup, qs_randsk87_run,
    sizeof(struct qs_randsk87_state), 1};
const struct gy_dudect_target target_qspgs_member_open_44 = {
    "qspgs_member_open_44", qs_member_44_setup, qs_member_run,
    sizeof(struct qs_member_state), 16};
const struct gy_dudect_target target_qspgs_member_open_87 = {
    "qspgs_member_open_87", qs_member_87_setup, qs_member_run,
    sizeof(struct qs_member_state), 16};
const struct gy_dudect_target target_qspgs_token_check = {
    "qspgs_token_check", qs_token_setup, qs_token_run,
    sizeof(struct qs_token_state), 256};
