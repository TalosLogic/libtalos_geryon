/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Header-encryption self-vectors (D-GEN-6): a seeded reference
 * conversation with both RNG seams fixed (ratchet keypairs derived from fixed
 * scalars, hdr_salt from a fixed counter) emits a deterministic sequence of
 * D-DR-16 frames.  The frames are pinned in tests/vectors/dr_he_self.vec and
 * replayed here; a KDF or wire-layout regression changes the bytes.  This is a
 * SELF-KAT, not an oracle: geryon's hybrid/HE wire has no external generator.
 *
 * When the vector file is absent the test prints the generated records (paste
 * them into the file, then record its sha256 in tests/vectors/README.md) and
 * passes, matching the print-if-unpinned pattern used elsewhere.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "double_ratchet.h"

#include "gy_test.h"

#define VEC_PATH_25519 GERYON_TEST_SOURCE_DIR "/tests/vectors/dr_he_self.vec"
#define VEC_PATH_448 GERYON_TEST_SOURCE_DIR "/tests/vectors/dr_he_c448_self.vec"
#define AEAD GY_AEAD_CHACHA20POLY1305
#define NFRAMES 5

static const struct gy_suite_desc *D;

/* Fixed ratchet-keypair pool: sk is a constant scalar, pk = DH(sk, base). */
static struct gy_keypair g_fixed[6];
static size_t g_fixed_idx;
static uint8_t g_salt_ctr;

/* The suite's vector file (a distinct seeded conversation per classical tier). */
static const char *
vec_path(void)
{
    return (D->suite_id == GY_SUITE_C448) ? VEC_PATH_448 : VEC_PATH_25519;
}

static void
build_kp(struct gy_keypair *kp, uint8_t seed)
{
    uint8_t base[GY_CURVE_PK_MAX];

    /* Montgomery base point: u = 9 for X25519, u = 5 for X448 (RFC 7748). */
    memset(base, 0, sizeof(base));
    base[0] = (D->curve_type == GY_CURVE_TYPE_448) ? 5 : 9;
    memset(kp->sk, 0, sizeof(kp->sk));
    memset(kp->sk, seed, D->curve_sk_len);
    kp->pub.curve_type = D->curve_type;
    kp->pub.pkid = 0;
    ASSERT_EQ(D->dh(kp->pub.pk, kp->sk, base), GY_OK);
}

static int
fixed_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
    (void)desc;
    *out = g_fixed[g_fixed_idx % 6];
    g_fixed_idx++;
    return GY_OK;
}

static int
fixed_salt(uint8_t *out, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(0xC0 + g_salt_ctr + i);
    g_salt_ctr++;
    return GY_OK;
}

/* Encrypt pt on `from`, capture the frame, and confirm it decrypts on `to`. */
static void
send_capture(struct gy_dr_state *from, struct gy_dr_state *to,
             const uint8_t *ad, size_t adl, const char *pt, uint8_t *frame,
             size_t *flen)
{
    uint8_t out[256];
    size_t ol;

    ASSERT_EQ(gy_dr_encrypt(from, frame, 256, flen, (const uint8_t *)pt,
                            strlen(pt), ad, adl),
              GY_OK);
    ASSERT_EQ(gy_dr_decrypt(to, out, sizeof(out), &ol, frame, *flen, ad, adl),
              GY_OK);
    ASSERT_MEMEQ(out, pt, strlen(pt));
}

/* Run the deterministic conversation, capturing the emitted frames. */
static void
generate(uint8_t frames[NFRAMES][256], size_t flen[NFRAMES])
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    uint8_t ad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t i;

    for (i = 0; i < 6; i++)
        build_kp(&g_fixed[i], (uint8_t)(0x11 * (i + 1)));

    memset(&sa, 0, sizeof(sa));
    for (i = 0; i < 32; i++) {
        sa.sk_dr[i] = (uint8_t)(0x40 + i);
        sa.shared_hka[i] = (uint8_t)(0x60 + i);
        sa.shared_nhkb[i] = (uint8_t)(0x80 + i);
    }
    sb = sa; /* both sides share the X3DH-derived triple */

    g_fixed_idx = 0;
    g_salt_ctr = 0;
    gy_dr_test_keypair = fixed_keypair;
    gy_he_test_salt = fixed_salt;

    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &g_fixed[0]), GY_OK);
    g_fixed_idx = 1; /* Alice's initial ratchet key is g_fixed[1] */
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, g_fixed[0].pub.pk), GY_OK);

    send_capture(&alice, &bob, ad, sizeof(ad), "a1", frames[0], &flen[0]);
    send_capture(&alice, &bob, ad, sizeof(ad), "a2", frames[1], &flen[1]);
    send_capture(&bob, &alice, ad, sizeof(ad), "b1", frames[2], &flen[2]);
    send_capture(&alice, &bob, ad, sizeof(ad), "a3", frames[3], &flen[3]);
    send_capture(&bob, &alice, ad, sizeof(ad), "b2", frames[4], &flen[4]);

    gy_dr_test_keypair = NULL;
    gy_he_test_salt = NULL;
    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

static void
dump_frame(size_t idx, const uint8_t *b, size_t n)
{
    size_t i;

    fprintf(stderr, "frame%zu=", idx);
    for (i = 0; i < n; i++)
        fprintf(stderr, "%02x", b[i]);
    fprintf(stderr, "\n");
}

TEST(dr_he_self_vectors)
{
    uint8_t frames[NFRAMES][256], exp[256];
    size_t flen[NFRAMES];
    static char line[1024];
    FILE *f;
    size_t seen = 0, i;

    generate(frames, flen);

    f = fopen(vec_path(), "r");
    if (f == NULL) {
        fprintf(stderr, "  (no %s; pin these records)\n", vec_path());
        for (i = 0; i < NFRAMES; i++)
            dump_frame(i, frames[i], flen[i]);
        return;
    }

    while (gy_read_line(f, line, sizeof(line))) {
        int n;

        if (line[0] == '#' || line[0] == '\0')
            continue;
        if (sscanf(line, "frame%d=", &n) == 1 && n >= 0 && n < NFRAMES) {
            const char *eq = strchr(line, '=');
            int elen = gy_hex_decode(exp, sizeof(exp), eq + 1);
            ASSERT_TRUE(elen >= 0, "valid hex in vector");
            ASSERT_EQ((size_t)elen, flen[n]);
            ASSERT_MEMEQ(exp, frames[n], (size_t)elen);
            seen++;
        }
    }
    fclose(f);
    ASSERT_EQ(seen, (size_t)NFRAMES);
}

int
main(void)
{
    /* A seeded HE self-vector conversation per classical tier
     * (dr_he_self.vec for c25519, dr_he_c448_self.vec for c448). */
    static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};
    static const struct gy_test_case cases[] = {
        GY_TEST(dr_he_self_vectors),
    };
    size_t s;
    int rc = 0;

    if (gy_core_init() != GY_OK)
        return 1;
    for (s = 0; s < sizeof(suites) / sizeof(suites[0]); s++) {
        D = gy_suite_desc(suites[s]);
        if (D == NULL)
            return 1;
        printf("== suite %s ==\n", D->name);
        rc |= gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
    return rc;
}
