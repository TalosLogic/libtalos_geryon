/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Timing-validation targets for the ratchet layer.  gy_kdf_ctr is the SP 800-108
 * counter-mode KDF (D-DR-2) that drives KDF_CK and the per-message AEAD
 * key/nonce derivation; its running time must not depend on the key (the
 * secret), only on the requested length.  Class A fixes the key, class B
 * randomizes it; a leak shows up as a large |t|.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "double_ratchet.h"
#include "encode.h"
#include "kdf.h"
#include "rng.h"
#include "suite.h"

static volatile uint8_t g_sink_u8;

/* ---- gy_kdf_ctr: fixed vs random key, fixed label/length -------------- */

struct kdf_ctr_state {
    const struct gy_suite_desc *desc;
    uint8_t key[32];
};

/*
 * The fixed class-A key is a single fixed draw of random-looking bytes, NOT a
 * repeated constant.  A repeated-byte key (e.g. all 0x33) gives class A zero
 * input variance and a degenerate Hamming weight; on a DVFS-sensitive core that
 * asymmetry against the full-entropy class B can raise |t| through
 * data-dependent frequency/power alone, with no control-flow leak behind it.  A
 * typical random draw removes that confounder while preserving fixed-vs-random.
 */
static const uint8_t kdf_ctr_fixed_key[32] = {
    0x9e, 0x3f, 0xa1, 0x7c, 0x08, 0xd2, 0x4b, 0xe6, 0x51, 0xbd, 0x2a,
    0x94, 0xf0, 0x37, 0xc5, 0x68, 0x1d, 0xe9, 0x83, 0x46, 0xab, 0x70,
    0x5c, 0xf2, 0x09, 0xd7, 0x64, 0x8b, 0x3e, 0xa5, 0x12, 0xcf,
};

static void
kdf_ctr_setup(int cls, void *state)
{
    struct kdf_ctr_state *s = state;

    s->desc = gy_suite_desc(GY_SUITE_C25519);
    /*
     * Both classes draw from the RNG so the per-trial setup work is identical;
     * class A then overwrites with the fixed key.  This leaves the key VALUE as
     * the only thing that differs going into the KDF, so a class-dependent run
     * time can only mean the KDF's timing depends on the key -- the leak we are
     * testing for.  Class B still uses a fresh random key every trial, so the
     * test's power to detect that leak is unchanged (D-GEN-10).
     */
    gy_random_bytes(s->key, sizeof(s->key));
    if (cls == 0)
        memcpy(s->key, kdf_ctr_fixed_key, sizeof(s->key));
}

static void
kdf_ctr_run(const void *state)
{
    const struct kdf_ctr_state *s = state;
    uint8_t out[32];

    /* A single-block derivation, as KDF_CK uses (label length is public). */
    (void)gy_kdf_ctr(s->desc, out, sizeof(out), s->key, sizeof(s->key),
                     (const uint8_t *)"geryon.1.c25519.dr.msg", 22, NULL, 0);
    g_sink_u8 ^= out[0];
}

const struct gy_dudect_target target_kdf_ctr = {
    "kdf_ctr", kdf_ctr_setup, kdf_ctr_run, sizeof(struct kdf_ctr_state), 500,
};

/* ---- DR decrypt tag rejection through the full staged path ------------
 *
 * The plan asked for a valid-vs-corrupt comparison, but commit-after-verify
 * makes the accepting path do strictly more work (the stage commit), which is
 * a class-dependent difference on a PUBLIC input (accept vs reject) rather than
 * a secret-dependent leak.  The security-relevant property is that tag
 * rejection does not leak WHICH tag byte mismatched (a padding-oracle style
 * leak), so both classes here are forged messages that differ only in the
 * flipped tag-byte position: both take the identical staged-and-rejected path,
 * and any |t| would be a genuine leak.  Registered drift: see
 * docs/decisions/double_ratchet.md D-DR-18.
 */

static const uint64_t DR_TS = 0x0000000155667788ull;

/* A DR session built once; the forged decrypts never mutate it (D-DR-4). */
static struct dr_fixture {
    int ready;
    struct gy_dr_state bob;
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;
    uint8_t base[256]; /* a valid message Bob has NOT consumed */
    size_t baselen;
} g_drf;

static void
ensure_dr_fixture(void)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_C25519);
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local local;
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice;
    uint8_t prefix[GY_X3DH_PREFIX_MAX], adb[GY_X3DH_AD_MAX];
    uint8_t m0[256], out[64];
    size_t prefl, adbl, m0len, outlen;

    if (g_drf.ready)
        return;

    gy_keypair_generate(d, &alice_ik);
    gy_keypair_generate(d, &bob_ik);
    gy_spk_create(d, &bob_spk, bob_ik.sk, DR_TS);
    gy_opk_batch(d, bob_opk, 1, NULL, 0);

    memset(&bundle, 0, sizeof(bundle));
    bundle.ik = bob_ik.pub;
    bundle.spk = bob_spk.kp.pub;
    bundle.spk_timestamp = DR_TS;
    memcpy(bundle.spk_sig, bob_spk.sig, GY_SIG_MAX);
    bundle.opk = bob_opk[0].pub;

    gy_keypair_generate(d, &ek);
    gy_x3dh_initiate(d, &sa, g_drf.ad, &g_drf.adl, prefix, &prefl, &alice_ik,
                     &bundle, &ek);
    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    gy_x3dh_respond(d, &sb, adb, &adbl, &ref, &local, prefix, prefl);

    gy_dr_init_alice(&alice, d, GY_AEAD_CHACHA20POLY1305, &sa, bundle.spk.pk);
    gy_dr_init_bob(&g_drf.bob, d, GY_AEAD_CHACHA20POLY1305, &sb, &bob_spk.kp);

    /* m0 establishes Bob's receiving chain (nr becomes 1). */
    gy_dr_encrypt(&alice, m0, sizeof(m0), &m0len, (const uint8_t *)"establish",
                  9, g_drf.ad, g_drf.adl);
    gy_dr_decrypt(&g_drf.bob, out, sizeof(out), &outlen, m0, m0len, g_drf.ad,
                  g_drf.adl);

    /* base is Alice's next message (n=1), valid but never delivered to Bob. */
    gy_dr_encrypt(&alice, g_drf.base, sizeof(g_drf.base), &g_drf.baselen,
                  (const uint8_t *)"timing fixture 32-byte plaintext.", 32,
                  g_drf.ad, g_drf.adl);

    gy_secure_zero(&alice, sizeof(alice));
    g_drf.ready = 1;
}

struct dr_tag_state {
    uint8_t msg[256];
    size_t msglen;
};

static void
dr_tag_setup(int cls, void *state)
{
    struct dr_tag_state *s = state;
    size_t tagpos;

    ensure_dr_fixture();
    memcpy(s->msg, g_drf.base, g_drf.baselen);
    s->msglen = g_drf.baselen;

    /* Flip a class-dependent byte of the 16-byte AEAD tag: class A the first
     * tag byte, class B the last.  Both forge; only the compare distinguishes. */
    tagpos = (cls == 0) ? s->msglen - 16 : s->msglen - 1;
    s->msg[tagpos] ^= 0x01;
}

static void
dr_tag_run(const void *state)
{
    const struct dr_tag_state *s = state;
    uint8_t out[64];
    size_t outlen;
    int rc;

    /* Always fails on the corrupt tag, so the staged state is discarded and
     * Bob is never mutated (D-DR-4); the shared fixture stays constant. */
    rc = gy_dr_decrypt(&g_drf.bob, out, sizeof(out), &outlen, s->msg, s->msglen,
                       g_drf.ad, g_drf.adl);
    g_sink_u8 ^= (uint8_t)rc;
}

const struct gy_dudect_target target_dr_tag = {
    "dr_tag_reject", dr_tag_setup, dr_tag_run, sizeof(struct dr_tag_state), 50,
};
