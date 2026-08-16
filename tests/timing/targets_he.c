/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Timing-validation targets for header encryption (D-DR-19).
 * Both targets are forgery-vs-forgery per D-GEN-10: the two classes are corrupt
 * inputs that differ only in WHICH tag byte was flipped, so they take the
 * identical rejected path and any |t| is a genuine key-independent-leak signal
 * (a padding-oracle-style "which byte mismatched"), never an accept-vs-reject
 * work asymmetry.
 *
 *  - he_tag_reject: HDECRYPT (gy_he_decrypt) of a forged enc_header.
 *  - he_recv_trials: the full receive path (gy_dr_decrypt) with a fixed number
 *    of stored epoch header keys, so the section 7.8.5 trial loop runs a
 *    constant count of HDECRYPT trials before the forged payload tag rejects.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#include "double_ratchet.h"
#include "he.h"
#include "suite.h"
#include "util.h"

static volatile uint8_t g_sink_u8;

static const uint64_t HE_TS = 0x0000000155667788ull;

/* A fixed, random-looking header key (not a repeated constant; D-GEN-10). */
static const uint8_t he_fixed_hk[32] = {
    0x74, 0x1b, 0xc3, 0x2e, 0x90, 0x5d, 0xa8, 0x16, 0xef, 0x42, 0x8c,
    0x37, 0xd1, 0x6a, 0xb5, 0x09, 0x2f, 0xe4, 0x78, 0x53, 0xca, 0x11,
    0x9d, 0x60, 0x3b, 0xf7, 0x84, 0x25, 0xac, 0x58, 0x1e, 0xd6,
};

/* ---- he_tag_reject: HDECRYPT tag rejection, forged-vs-forged ----------- */

struct he_tag_state {
    const struct gy_suite_desc *desc;
    uint8_t enc[GY_DR_ENC_HEADER_MAX];
    size_t elen;
    uint8_t salt[GY_HE_SALT_LEN];
};

static void
he_tag_setup(int cls, void *state)
{
    struct he_tag_state *s = state;
    uint8_t header[GY_DR_HEADER_MAX];
    uint8_t ad2[2] = {0x01, 0x01}; /* version || suite_id */
    size_t hlen, tagpos;

    s->desc = gy_suite_desc(GY_SUITE_C25519);

    /* A well-formed classical header plaintext (contents are immaterial). */
    memset(header, 0x40, sizeof(header));
    header[0] = 0x00;
    header[1] = 0x00;
    header[2] = 0x00;
    header[3] = s->desc->curve_type;
    hlen = 4 + s->desc->curve_pk_len + 8;

    /* Seal it, then forge: both classes flip one tag byte, at a class-
     * dependent position, of the 16-byte trailing tag. */
    gy_he_encrypt(s->desc, GY_AEAD_CHACHA20POLY1305, he_fixed_hk, header, hlen,
                  ad2, s->salt, s->enc, sizeof(s->enc), &s->elen);
    tagpos = (cls == 0) ? s->elen - 16 : s->elen - 1;
    s->enc[tagpos] ^= 0x01;
}

static void
he_tag_run(const void *state)
{
    const struct he_tag_state *s = state;
    uint8_t ad2[2] = {0x01, 0x01};
    uint8_t out[GY_DR_HEADER_MAX];
    size_t olen;
    int rc;

    rc = gy_he_decrypt(s->desc, GY_AEAD_CHACHA20POLY1305, he_fixed_hk, s->salt,
                       s->enc, s->elen, ad2, out, sizeof(out), &olen);
    g_sink_u8 ^= (uint8_t)rc;
}

const struct gy_dudect_target target_he_tag = {
    "he_tag_reject", he_tag_setup, he_tag_run, sizeof(struct he_tag_state), 100,
};

/* ---- he_recv_trials: receive path with a populated epoch table --------- */

#define HE_STORED_EPOCHS 4

/* A Bob session with HE_STORED_EPOCHS live epoch slots and a valid,
 * undelivered message; the forged decrypts never mutate it (D-DR-4). */
static struct he_fixture {
    int ready;
    struct gy_dr_state bob;
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;
    uint8_t base[256];
    size_t baselen;
} g_hef;

static void
ensure_he_fixture(void)
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
    size_t prefl, adbl, m0len, outlen, i;

    if (g_hef.ready)
        return;

    gy_keypair_generate(d, &alice_ik);
    gy_keypair_generate(d, &bob_ik);
    gy_spk_create(d, &bob_spk, bob_ik.sk, HE_TS);
    gy_opk_batch(d, bob_opk, 1, NULL, 0);

    memset(&bundle, 0, sizeof(bundle));
    bundle.ik = bob_ik.pub;
    bundle.spk = bob_spk.kp.pub;
    bundle.spk_timestamp = HE_TS;
    memcpy(bundle.spk_sig, bob_spk.sig, GY_SIG_MAX);
    bundle.opk = bob_opk[0].pub;

    gy_keypair_generate(d, &ek);
    gy_x3dh_initiate(d, &sa, g_hef.ad, &g_hef.adl, prefix, &prefl, &alice_ik,
                     &bundle, &ek);
    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    gy_x3dh_respond(d, &sb, adb, &adbl, &ref, &local, prefix, prefl);

    gy_dr_init_alice(&alice, d, GY_AEAD_CHACHA20POLY1305, &sa, bundle.spk.pk);
    gy_dr_init_bob(&g_hef.bob, d, GY_AEAD_CHACHA20POLY1305, &sb, &bob_spk.kp);

    gy_dr_encrypt(&alice, m0, sizeof(m0), &m0len, (const uint8_t *)"establish",
                  9, g_hef.ad, g_hef.adl);
    gy_dr_decrypt(&g_hef.bob, out, sizeof(out), &outlen, m0, m0len, g_hef.ad,
                  g_hef.adl);

    /*
     * Populate a fixed number of live epoch slots with distinct random header
     * keys so the section 7.8.5 skipped-trial loop runs a constant count of
     * HDECRYPT trials.  None will decrypt the forged header, so the loop always
     * falls through to HKr; count stays 0 (no ent references needed for the
     * loop, which iterates by refs).
     */
    for (i = 0; i < HE_STORED_EPOCHS; i++) {
        memset(g_hef.bob.skipped.epochs[i].hk, (int)(0x11 * (i + 1)), 32);
        g_hef.bob.skipped.epochs[i].refs = 1;
    }

    /* base is Alice's n=1 message: valid header, its payload will be forged. */
    gy_dr_encrypt(&alice, g_hef.base, sizeof(g_hef.base), &g_hef.baselen,
                  (const uint8_t *)"timing fixture 32-byte plaintext.", 32,
                  g_hef.ad, g_hef.adl);

    gy_secure_zero(&alice, sizeof(alice));
    g_hef.ready = 1;
}

struct he_recv_state {
    uint8_t msg[256];
    size_t msglen;
};

static void
he_recv_setup(int cls, void *state)
{
    struct he_recv_state *s = state;
    size_t tagpos;

    ensure_he_fixture();
    memcpy(s->msg, g_hef.base, g_hef.baselen);
    s->msglen = g_hef.baselen;

    /* Forge the payload tag; class A the first byte, class B the last.  The
     * header stays valid, so HKr decrypts it and the constant trial loop runs
     * before the payload tag rejects and the stage is discarded. */
    tagpos = (cls == 0) ? s->msglen - 16 : s->msglen - 1;
    s->msg[tagpos] ^= 0x01;
}

static void
he_recv_run(const void *state)
{
    const struct he_recv_state *s = state;
    uint8_t out[64];
    size_t outlen;
    int rc;

    rc = gy_dr_decrypt(&g_hef.bob, out, sizeof(out), &outlen, s->msg, s->msglen,
                       g_hef.ad, g_hef.adl);
    g_sink_u8 ^= (uint8_t)rc;
}

const struct gy_dudect_target target_he_recv = {
    "he_recv_trials",
    he_recv_setup,
    he_recv_run,
    sizeof(struct he_recv_state),
    40,
};
