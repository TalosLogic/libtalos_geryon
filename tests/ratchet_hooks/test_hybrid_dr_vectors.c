/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Spec-derived hybrid Double Ratchet self-KATs (D-GEN-6, HYBRID_SPEC §11.2):
 * a seeded reference conversation whose every randomness seam is fixed, emitting
 * a deterministic sequence of hybrid frames that are pinned in
 * tests/vectors/dr_hybrid_self.vec.  Covers three ratchet steps each direction
 * including an ML-KEM refresh boundary and the KEM confirmation chain (Bob's
 * first reply), plus skipped-message recovery (a later frame decrypts first, the
 * skipped one recovers from the stored message key).
 *
 * This is the hybrid analogue of the classical dr_he_self.vec KAT
 * (tests/ratchet/test_he_vectors.c).  Determinism comes the same way: the curve
 * ratchet keypair and header salt are fixed via the existing ratchet seams, and
 * the two ML-KEM randomness sources (keygen, encaps) are fixed via the FIPS 203
 * _derand entry points (gy_mlkem_*_derand) with fixed seeds - the standard,
 * seed-driven, portable analogue of X25519(fixed_scalar).  Because decapsulation
 * is unseamed (the receiver runs the real path), the derand material is not just
 * deterministic but VALID, so every frame round-trips through the confirmation.
 * No liboqs-internal behavior is frozen: derand outputs are standard-fixed.
 *
 * This test needs core GY_TEST_HOOKS seams (the _derand entry points), so it is
 * built by the ratchet_hooks harness, which recompiles core+kex+ratchet with
 * -DGY_TEST_HOOKS and WITHOUT GY_PRODUCTION_BUILD; the shipped library carries
 * none of it (src/core/error.h enforces the two macros never coexist).
 *
 * When the vector file is absent the test writes it directly (frames run to a
 * couple KB; a terminal copy-paste hard-wraps them) and passes; review the file
 * and record its sha256 in the vectors README.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hybrid_double_ratchet.h"
#include "mlkem.h"

#include "gy_test.h"

#define VEC_PATH GERYON_TEST_SOURCE_DIR "/tests/vectors/dr_hybrid_self.vec"
#define AEAD GY_AEAD_CHACHA20POLY1305
#define INTERVAL                                                               \
    2 /* small ML-KEM refresh interval so a boundary is exercised */

#define MAXREC 16
#define RECBUF 4096

static const struct gy_suite_desc *D;
static const uint8_t BASE[32] = {9}; /* X25519 base point */

static char g_name[MAXREC][8];
static uint8_t g_buf[MAXREC][RECBUF];
static size_t g_len[MAXREC];
static size_t g_nrec;

/* ---- fixed randomness seams ------------------------------------------- */

static struct gy_keypair g_curve[8];
static size_t g_curve_idx;
static uint8_t g_salt_ctr;
static uint32_t g_kkp, g_kenc;

static void
fill(uint8_t *b, size_t n, uint8_t base)
{
    size_t i;

    for (i = 0; i < n; i++)
        b[i] = (uint8_t)(base + i);
}

static int
fixed_curve_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
    (void)desc;
    *out = g_curve[g_curve_idx % 8];
    g_curve_idx++;
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

static int
derand_kem_keypair(const struct gy_suite_desc *desc, uint8_t *ek, uint8_t *dk)
{
    uint8_t seed[GY_MLKEM512_KEYPAIR_SEED];

    (void)desc;
    fill(seed, sizeof(seed), (uint8_t)(0x40 + g_kkp));
    g_kkp++;
    return gy_mlkem_keypair_derand(ek, dk, seed);
}

static int
derand_kem_encaps(const struct gy_suite_desc *desc, uint8_t *ct, uint8_t *ss,
                  const uint8_t *ek)
{
    uint8_t seed[GY_MLKEM512_ENCAPS_SEED];

    (void)desc;
    fill(seed, sizeof(seed), (uint8_t)(0x80 + g_kenc));
    g_kenc++;
    return gy_mlkem_encaps_derand(ct, ss, ek, seed);
}

/* ---- record table ----------------------------------------------------- */

static void
add_rec(const char *name, const uint8_t *b, size_t n)
{
    ASSERT_TRUE(g_nrec < MAXREC, "record table not full");
    ASSERT_TRUE(n <= RECBUF, "record fits buffer");
    snprintf(g_name[g_nrec], sizeof(g_name[0]), "%s", name);
    memcpy(g_buf[g_nrec], b, n);
    g_len[g_nrec] = n;
    g_nrec++;
}

static int
find_rec(const char *name)
{
    size_t i;

    for (i = 0; i < g_nrec; i++) {
        if (strcmp(g_name[i], name) == 0)
            return (int)i;
    }
    return -1;
}

/* ---- deterministic setup ---------------------------------------------- */

/* Fabricate the shared seed triple both parties get from the handshake. */
static void
make_secrets(struct gy_dr_secrets *s)
{
    size_t i;

    memset(s, 0, sizeof(*s));
    for (i = 0; i < 32; i++) {
        s->sk_dr[i] = (uint8_t)(0x40 + i);
        s->shared_hka[i] = (uint8_t)(0x60 + i);
        s->shared_nhkb[i] = (uint8_t)(0x80 + i);
    }
}

/* Build Bob's SPK hybrid keypair deterministically (fixed scalar + derand KEM). */
static void
build_bob_spk(struct gy_hybrid_keypair *spk)
{
    uint8_t seed[GY_MLKEM512_KEYPAIR_SEED];

    memset(spk, 0, sizeof(*spk));
    spk->pub.curve.curve_type = D->curve_type;
    spk->pub.curve.pkid = 0;
    memset(spk->curve_sk, 0x33, D->curve_pk_len);
    ASSERT_EQ(D->dh(spk->pub.curve.pk, spk->curve_sk, BASE), GY_OK);
    fill(seed, sizeof(seed), 0x01);
    ASSERT_EQ(gy_mlkem_keypair_derand(spk->pub.mlkem_ek, spk->mlkem_dk, seed),
              GY_OK);
}

/* Encrypt pt on `from`, capture the frame, decrypt on `to`, assert round-trip. */
static void
relay(struct gy_hybrid_dr_state *from, struct gy_hybrid_dr_state *to,
      const uint8_t *ad, size_t adl, const char *pt, const char *rec)
{
    uint8_t wire[RECBUF], out[256];
    size_t wl, ol, ptlen = strlen(pt);

    ASSERT_EQ(gy_hybrid_dr_encrypt(from, wire, sizeof(wire), &wl,
                                   (const uint8_t *)pt, ptlen, ad, adl),
              GY_OK);
    add_rec(rec, wire, wl);
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(to, out, sizeof(out), &ol, wire, wl, ad, adl),
        GY_OK);
    ASSERT_EQ(ol, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

/* Run the deterministic reference conversation, capturing every frame. */
static void
run_conversation(void)
{
    struct gy_hybrid_keypair bob_spk;
    struct gy_hybrid_dr_state alice, bob;
    struct gy_dr_secrets sa, sb;
    uint8_t aik_ek[GY_KEM_EK_MAX], aik_dk[GY_KEM_DK_MAX];
    uint8_t seed[GY_MLKEM512_KEYPAIR_SEED];
    uint8_t ad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t f4[RECBUF], f5[RECBUF], out[256];
    size_t l4, l5, ol, i;

    for (i = 0; i < 8; i++) {
        memset(g_curve[i].sk, (uint8_t)(0x11 * (i + 1)), D->curve_pk_len);
        g_curve[i].pub.curve_type = D->curve_type;
        g_curve[i].pub.pkid = 0;
        ASSERT_EQ(D->dh(g_curve[i].pub.pk, g_curve[i].sk, BASE), GY_OK);
    }

    build_bob_spk(&bob_spk);
    fill(seed, sizeof(seed), 0x02); /* Alice identity KEM keypair */
    ASSERT_EQ(gy_mlkem_keypair_derand(aik_ek, aik_dk, seed), GY_OK);
    make_secrets(&sa);
    sb = sa;

    g_curve_idx = 0;
    g_salt_ctr = 0;
    g_kkp = 0;
    g_kenc = 0;
    gy_dr_test_keypair = fixed_curve_keypair;
    gy_he_test_salt = fixed_salt;
    gy_hybrid_dr_test_kem_keypair = derand_kem_keypair;
    gy_hybrid_dr_test_kem_encaps = derand_kem_encaps;

    ASSERT_EQ(
        gy_hybrid_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk, INTERVAL, aik_ek),
        GY_OK);
    ASSERT_EQ(gy_hybrid_dr_init_alice(&alice, D, AEAD, &sa, &bob_spk.pub,
                                      INTERVAL, aik_dk),
              GY_OK);

    /* Three steps each direction; b1 carries the refresh + KEM confirmation. */
    relay(&alice, &bob, ad, sizeof(ad), "a1", "a1");
    relay(&alice, &bob, ad, sizeof(ad), "a2", "a2");
    relay(&bob, &alice, ad, sizeof(ad), "b1", "b1");
    relay(&bob, &alice, ad, sizeof(ad), "b2", "b2");
    relay(&alice, &bob, ad, sizeof(ad), "a3", "a3");
    relay(&bob, &alice, ad, sizeof(ad), "b3", "b3");

    /* Skipped-message recovery: encrypt a4,a5; deliver a5 then a4 to Bob. */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, f4, sizeof(f4), &l4,
                                   (const uint8_t *)"a4", 2, ad, sizeof(ad)),
              GY_OK);
    add_rec("a4", f4, l4);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, f5, sizeof(f5), &l5,
                                   (const uint8_t *)"a5", 2, ad, sizeof(ad)),
              GY_OK);
    add_rec("a5", f5, l5);

    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, f5, l5, ad,
                                   sizeof(ad)),
              GY_OK);
    ASSERT_MEMEQ(out, "a5", 2);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, f4, l4, ad,
                                   sizeof(ad)),
              GY_OK);
    ASSERT_MEMEQ(out, "a4", 2);

    gy_dr_test_keypair = NULL;
    gy_he_test_salt = NULL;
    gy_hybrid_dr_test_kem_keypair = NULL;
    gy_hybrid_dr_test_kem_encaps = NULL;
    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* ---- vector file ------------------------------------------------------ */

static int
write_records(void)
{
    FILE *f;
    size_t i, j;

    f = fopen(VEC_PATH, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "# hybrid Double Ratchet frame self-KATs (HYBRID_SPEC 11.2); see"
               " tests/vectors/README.md\n");
    for (i = 0; i < g_nrec; i++) {
        fprintf(f, "%s=", g_name[i]);
        for (j = 0; j < g_len[i]; j++)
            fprintf(f, "%02x", g_buf[i][j]);
        fprintf(f, "\n");
    }
    fclose(f);
    return 0;
}

TEST(hybrid_dr_self_vectors)
{
    uint8_t exp[RECBUF];
    static char line[RECBUF * 2 + 64];
    FILE *f;
    size_t seen = 0;

    g_nrec = 0;
    run_conversation();

    f = fopen(VEC_PATH, "r");
    if (f == NULL) {
        ASSERT_EQ(write_records(), 0);
        fprintf(stderr, "  (wrote %s; review and record its sha256)\n",
                VEC_PATH);
        return;
    }

    while (gy_read_line(f, line, sizeof(line))) {
        char name[8];
        const char *eq;
        size_t namelen;
        int idx, elen;

        if (line[0] == '#' || line[0] == '\0')
            continue;
        eq = strchr(line, '=');
        if (eq == NULL) {
            ASSERT_TRUE(0, "record line has '=' (a wrapped long line?)");
            continue;
        }
        namelen = (size_t)(eq - line);
        if (namelen >= sizeof(name)) {
            ASSERT_TRUE(0, "record name fits");
            continue;
        }
        memcpy(name, line, namelen);
        name[namelen] = '\0';

        idx = find_rec(name);
        if (idx < 0) {
            ASSERT_TRUE(0, "vector names a generated record");
            continue;
        }
        elen = gy_hex_decode(exp, sizeof(exp), eq + 1);
        ASSERT_TRUE(elen >= 0, "valid hex in vector");
        ASSERT_EQ((size_t)elen, g_len[idx]);
        if (elen >= 0 && (size_t)elen == g_len[idx])
            ASSERT_MEMEQ(exp, g_buf[idx], (size_t)elen);
        seen++;
    }
    fclose(f);
    ASSERT_EQ(seen, g_nrec);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_H25519_512);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(hybrid_dr_self_vectors),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
