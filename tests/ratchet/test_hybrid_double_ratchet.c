/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/ratchet/hybrid_double_ratchet.c (HYBRID_SPEC section 7,
 * GER-M5-07): the hybrid Double Ratchet under header encryption.  Built with
 * -DGY_TEST_HOOKS for the ML-KEM ratchet determinism seams (D-PQ-3), the curve
 * keypair seam (D-DR-11), the hdr_salt seam (D-DR-15), and the op-counters.
 *
 * The engine is exercised directly on a fabricated seed triple plus a real Bob
 * signed-prekey hybrid keypair; full hybrid X3DH and the session layer are
 * separate tickets.  plain memcmp is fine (tests carry no constant-time bar).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "hybrid_double_ratchet.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

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

/*
 * Stand up a two-party hybrid session at the given ML-KEM refresh interval:
 * a real Bob SPK hybrid keypair (curve + ML-KEM) plus a shared fabricated seed
 * triple, then init both engines.
 */
static void
hybrid_setup(struct gy_hybrid_dr_state *alice, struct gy_hybrid_dr_state *bob,
             uint32_t interval)
{
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_keypair bob_spk;
    uint8_t aik_ek[GY_KEM_EK_MAX], aik_dk[GY_KEM_DK_MAX];

    ASSERT_EQ(gy_hybrid_keypair_generate(D, &bob_spk), GY_OK);
    ASSERT_EQ(D->kem_keypair(aik_ek, aik_dk), GY_OK); /* Alice identity KEM */
    make_secrets(&sa);
    sb = sa;

    ASSERT_EQ(
        gy_hybrid_dr_init_bob(bob, D, AEAD, &sb, &bob_spk, interval, aik_ek),
        GY_OK);
    ASSERT_EQ(gy_hybrid_dr_init_alice(alice, D, AEAD, &sa, &bob_spk.pub,
                                      interval, aik_dk),
              GY_OK);
}

/* Encrypt pt on `from`, decrypt on `to`, assert the plaintext round-trips. */
static void
hrelay(struct gy_hybrid_dr_state *from, struct gy_hybrid_dr_state *to,
       const uint8_t *ad, size_t adl, const char *pt)
{
    uint8_t wire[4096], out[512];
    size_t wl, ol, ptlen = strlen(pt);

    ASSERT_EQ(gy_hybrid_dr_encrypt(from, wire, sizeof(wire), &wl,
                                   (const uint8_t *)pt, ptlen, ad, adl),
              GY_OK);
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(to, out, sizeof(out), &ol, wire, wl, ad, adl),
        GY_OK);
    ASSERT_EQ(ol, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

/* enc_header_len_be16 sits at wire[2 + GY_HE_SALT_LEN]. */
static size_t
frame_ehl(const uint8_t *wire)
{
    return gy_be16_get(wire + 2 + GY_HE_SALT_LEN);
}

TEST(init_mapping)
{
    struct gy_hybrid_dr_state alice, bob;
    struct gy_hybrid_keypair bob_spk;
    struct gy_dr_secrets sa, sb;
    uint8_t aik_ek[GY_KEM_EK_MAX], aik_dk[GY_KEM_DK_MAX];
    uint8_t skdr[32];

    ASSERT_EQ(gy_hybrid_keypair_generate(D, &bob_spk), GY_OK);
    ASSERT_EQ(D->kem_keypair(aik_ek, aik_dk), GY_OK);
    make_secrets(&sa);
    sb = sa;
    memcpy(skdr, sa.sk_dr, 32);

    /* Bob: root key = SKdr, no chains yet, counter forced to interval. */
    ASSERT_EQ(gy_hybrid_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk, 5, aik_ek),
              GY_OK);
    ASSERT_MEMEQ(bob.base.rk, skdr, 32);
    ASSERT_EQ(bob.base.have_cks, 0);
    ASSERT_EQ(bob.base.have_ckr, 0);
    ASSERT_EQ(bob.mlkem_counter, 5);
    ASSERT_EQ(bob.have_remote_ek, 0);
    ASSERT_EQ(bob.pq_state, GY_HYBRID_PQ_CLASSICAL_ONLY);
    ASSERT_EQ(bob.confirm_pending, 1);
    ASSERT_EQ(gy_is_zero(sb.sk_dr, 32), 1);

    /* Alice: ratchets on init -> sending chain, cached remote ek, ek pending. */
    ASSERT_EQ(
        gy_hybrid_dr_init_alice(&alice, D, AEAD, &sa, &bob_spk.pub, 5, aik_dk),
        GY_OK);
    ASSERT_EQ(alice.base.have_cks, 1);
    ASSERT_EQ(alice.have_kem_ct, 1);
    ASSERT_EQ(alice.have_remote_ek, 1);
    ASSERT_EQ(alice.send_ek_pending, 1);
    ASSERT_EQ(gy_is_zero(sa.sk_dr, 32), 1);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Alternate directions for `flips` single messages, crossing refresh
 * boundaries per the interval; every message must round-trip. */
static void
drive(uint32_t interval, int flips)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    char pt[24];
    int i;

    hybrid_setup(&alice, &bob, interval);
    for (i = 0; i < flips; i++) {
        snprintf(pt, sizeof(pt), "msg-%d", i);
        if (i % 2 == 0)
            hrelay(&alice, &bob, ad, sizeof(ad), pt);
        else
            hrelay(&bob, &alice, ad, sizeof(ad), pt);
    }
    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* interval 1: every ratchet refreshes the ML-KEM keypair. */
TEST(ping_pong_interval1)
{
    drive(1, 10);
}
/* interval 2: refresh every other ratchet; crosses several boundaries. */
TEST(ping_pong_interval2)
{
    drive(2, 16);
}
/* interval 20: >= 2 refresh boundaries per party (each party ~42 ratchets). */
TEST(ping_pong_interval20)
{
    drive(20, 84);
}
/* interval 100: the protocol ceiling (section 6.6 boundary); stays in sync. */
TEST(ping_pong_interval100)
{
    drive(100, 30);
}

/*
 * Interop property sweep (HYBRID_SPEC section 11.4): a sampled set of legal
 * intervals across the full 1..100 range, each driving a full duplex
 * conversation that must round-trip end to end.  Together with the interval1
 * and interval100 boundary cases this covers "interval boundary values
 * {1, min, max, 100} plus a sampled sweep of legal intervals".
 */
TEST(interval_sweep)
{
    static const uint32_t iv[] = {1, 3, 5, 8, 13, 21, 34, 55, 89, 100};
    size_t i;

    for (i = 0; i < sizeof(iv) / sizeof(iv[0]); i++)
        drive(iv[i], 12);
}

/* Two same-chain messages then an epoch flip both ways (mixed chains). */
TEST(ping_pong_mixed)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[4] = {9, 8, 7, 6};

    hybrid_setup(&alice, &bob, 3);
    hrelay(&alice, &bob, ad, sizeof(ad), "a1");
    hrelay(&alice, &bob, ad, sizeof(ad), "a2");
    hrelay(&bob, &alice, ad, sizeof(ad), "b1");
    hrelay(&bob, &alice, ad, sizeof(ad), "b2");
    hrelay(&alice, &bob, ad, sizeof(ad), "a3");
    hrelay(&bob, &alice, ad, sizeof(ad), "b3");
    hrelay(&alice, &bob, ad, sizeof(ad), "a4");
    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Out-of-order delivery within one sending chain (skipped keys). */
TEST(out_of_order)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0x11, 0x22};
    uint8_t w0[4096], w1[4096], w2[4096], out[64];
    size_t l0, l1, l2, ol;

    hybrid_setup(&alice, &bob, 1);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, w0, sizeof(w0), &l0,
                                   (const uint8_t *)"x0", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, w1, sizeof(w1), &l1,
                                   (const uint8_t *)"x1", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, w2, sizeof(w2), &l2,
                                   (const uint8_t *)"x2", 2, ad, sizeof(ad)),
              GY_OK);

    /* Deliver 2, 0, 1: the first receive skips 0,1 into the store. */
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w2, l2, ad, 2),
              GY_OK);
    ASSERT_MEMEQ(out, "x2", 2);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w0, l0, ad, 2),
              GY_OK);
    ASSERT_MEMEQ(out, "x0", 2);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w1, l1, ad, 2),
              GY_OK);
    ASSERT_MEMEQ(out, "x1", 2);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* A dropped message whose skip spans a refresh boundary (new epoch). */
TEST(dropped_across_refresh)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0x33, 0x44};
    uint8_t w1[4096], w2[4096], out[64];
    size_t l1, l2, ol;

    hybrid_setup(&alice, &bob, 1); /* interval 1: each ratchet refreshes */
    hrelay(&alice, &bob, ad, sizeof(ad), "a0");
    hrelay(&bob, &alice, ad, sizeof(ad), "b0");

    /* Alice's new epoch: a1 is dropped, a2 delivered (bob ratchets, skips a1). */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, w1, sizeof(w1), &l1,
                                   (const uint8_t *)"a1", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, w2, sizeof(w2), &l2,
                                   (const uint8_t *)"a2", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w2, l2, ad, 2),
              GY_OK);
    ASSERT_MEMEQ(out, "a2", 2);
    /* The dropped a1 then arrives from the skip store (crossed the refresh). */
    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w1, l1, ad, 2),
              GY_OK);
    ASSERT_MEMEQ(out, "a1", 2);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* The four section 7.6 header lengths, and encode/decode round-trip of each. */
TEST(header_len_combos)
{
    struct gy_dr_hybrid_header h, g;
    uint8_t buf[GY_DR_HYBRID_HEADER_MAX];
    size_t outlen, consumed, i;

    ASSERT_EQ(gy_dr_hybrid_header_len(D, 0, 0), 812);
    ASSERT_EQ(gy_dr_hybrid_header_len(D, 1, 0), 1612);
    ASSERT_EQ(gy_dr_hybrid_header_len(D, 0, 1), 1580);
    ASSERT_EQ(gy_dr_hybrid_header_len(D, 1, 1), 2380);

    for (i = 0; i < 4; i++) {
        int ek = (int)(i & 1), cf = (int)((i >> 1) & 1);

        memset(&h, 0, sizeof(h));
        h.flags = D->curve_type;
        if (ek)
            h.flags |= GY_DR_FLAG_MLKEM_EK_PRESENT;
        if (cf)
            h.flags |= GY_DR_FLAG_CONFIRM_CT_PRESENT;
        memset(h.ratchet_pk, 0xC1, D->curve_pk_len);
        memset(h.kem_ct, 0xC2, D->kem_ct_len);
        memset(h.mlkem_ek, 0xC3, D->kem_pk_len);
        memset(h.confirm_ct, 0xC4, D->kem_ct_len);
        h.pn = 0x01020304u;
        h.n = 0x05060708u;

        ASSERT_EQ(gy_dr_hybrid_header_encode(D, &h, buf, sizeof(buf), &outlen),
                  GY_OK);
        ASSERT_EQ(outlen, gy_dr_hybrid_header_len(D, ek, cf));

        ASSERT_EQ(gy_dr_hybrid_header_decode(D, &g, buf, outlen, &consumed),
                  GY_OK);
        ASSERT_EQ(consumed, outlen);
        ASSERT_EQ(g.flags, h.flags);
        ASSERT_EQ(g.pn, h.pn);
        ASSERT_EQ(g.n, h.n);
        ASSERT_MEMEQ(g.ratchet_pk, h.ratchet_pk, D->curve_pk_len);
        ASSERT_MEMEQ(g.kem_ct, h.kem_ct, D->kem_ct_len);
        if (ek)
            ASSERT_MEMEQ(g.mlkem_ek, h.mlkem_ek, D->kem_pk_len);
        if (cf)
            ASSERT_MEMEQ(g.confirm_ct, h.confirm_ct, D->kem_ct_len);
    }
}

/* On the wire: Alice's first chain carries the ek; a non-refresh chain does not. */
TEST(header_ek_scheduling)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0x55, 0x66};
    uint8_t wire[4096], out[64];
    size_t wl, ol, tag;

    tag = gy_aead_tag_len(AEAD);
    hybrid_setup(&alice, &bob, 2); /* interval 2 */

    /* Alice's initial chain used a fresh keypair -> ek present. */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"a1", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(frame_ehl(wire), gy_dr_hybrid_header_len(D, 1, 0) + tag);
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_OK);

    /*
     * Bob's first reply refreshes (counter seeded to interval -> ek present)
     * AND carries the KEM confirmation (section 8) -> both optional fields.
     */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&bob, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"b1", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(frame_ehl(wire), gy_dr_hybrid_header_len(D, 1, 1) + tag);
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&alice, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_OK);

    /* Alice's second chain (her 1st ratchet, counter 0->1 < 2): no refresh. */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"a2", 2, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(frame_ehl(wire), gy_dr_hybrid_header_len(D, 0, 0) + tag);
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_OK);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/*
 * A first header lacking mlkem_ek when the receiver holds no cached remote key
 * is rejected before any ML-KEM operation or root KDF (section 7.3).
 */
TEST(missing_ek_rejected)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0x77, 0x88};
    uint8_t wire[4096], out[64];
    size_t wl, ol;

    hybrid_setup(&alice, &bob, 1);
    /* Force Alice's first header compact (no ek) to strip Bob of a cached key. */
    alice.send_ek_pending = 0;
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"nope", 4, ad, sizeof(ad)),
              GY_OK);
    ASSERT_EQ(frame_ehl(wire),
              gy_dr_hybrid_header_len(D, 0, 0) + gy_aead_tag_len(AEAD));

    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_ERR_STATE);
    /* No ML-KEM decaps and no root KDF ran before the rejection. */
    ASSERT_EQ(gy_hybrid_dr_ctr.kem_decaps, 0);
    ASSERT_EQ(gy_hybrid_dr_ctr.kdf_rk, 0);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* A bad enc_header_len (not one of the four combos) is rejected pre-derivation. */
TEST(bad_enc_header_len_rejected)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0x12, 0x34};
    uint8_t wire[4096], out[64];
    size_t wl, ol;

    hybrid_setup(&alice, &bob, 1);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"z", 1, ad, sizeof(ad)),
              GY_OK);
    /* Perturb enc_header_len so it is no longer a valid combo. */
    wire[2 + GY_HE_SALT_LEN] ^= 0x40;

    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_ERR_ARG);
    ASSERT_EQ(gy_hybrid_dr_ctr.kem_decaps, 0);
    ASSERT_EQ(gy_hybrid_dr_ctr.kdf_rk, 0);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Reserved flag bits (10..31) set in a decoded header are rejected. */
TEST(reserved_flag_rejected)
{
    struct gy_dr_hybrid_header h, g;
    uint8_t buf[GY_DR_HYBRID_HEADER_MAX];
    size_t outlen, consumed;

    memset(&h, 0, sizeof(h));
    h.flags = D->curve_type;
    ASSERT_EQ(gy_dr_hybrid_header_encode(D, &h, buf, sizeof(buf), &outlen),
              GY_OK);

    /* Valid as-is. */
    ASSERT_EQ(gy_dr_hybrid_header_decode(D, &g, buf, outlen, &consumed), GY_OK);

    /* Set reserved bit 10 (0x00000400) in the be32 flags -> byte index 2. */
    buf[2] |= 0x04;
    ASSERT_EQ(gy_dr_hybrid_header_decode(D, &g, buf, outlen, &consumed),
              GY_ERR_ARG);

    /* A wrong curve_type (low byte) is a cross-suite rejection. */
    buf[2] &= (uint8_t)~0x04;
    buf[3] ^= 0x01;
    ASSERT_EQ(gy_dr_hybrid_header_decode(D, &g, buf, outlen, &consumed),
              GY_ERR_STATE);
}

/*
 * Tamper matrix: flipping a byte in any frame field is rejected and leaves the
 * receiver byte-identical, so the pristine message still decrypts afterward.
 */
TEST(tamper_matrix)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0xAB, 0xCD};
    uint8_t wire[4096], bad[4096], out[64];
    size_t wl, ol, offs[6], i;

    hybrid_setup(&alice, &bob, 1);
    /* Establish Bob's receiving chain with a first good message. */
    hrelay(&alice, &bob, ad, sizeof(ad), "hello");

    ASSERT_EQ(gy_hybrid_dr_encrypt(&alice, wire, sizeof(wire), &wl,
                                   (const uint8_t *)"world", 5, ad, sizeof(ad)),
              GY_OK);

    offs[0] = 0;                      /* version */
    offs[1] = 1;                      /* suite_id */
    offs[2] = 2;                      /* hdr_salt */
    offs[3] = 2 + GY_HE_SALT_LEN;     /* enc_header_len */
    offs[4] = 2 + GY_HE_SALT_LEN + 2; /* enc_header */
    offs[5] = wl - 1;                 /* payload tag */

    for (i = 0; i < 6; i++) {
        memcpy(bad, wire, wl);
        bad[offs[i]] ^= 0x01;
        ASSERT_TRUE(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, bad, wl,
                                         ad, 2) != GY_OK,
                    "tampered frame must be rejected");
    }

    /* Every rejection was a no-op: the pristine message still decrypts. */
    ASSERT_EQ(
        gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, wire, wl, ad, 2),
        GY_OK);
    ASSERT_MEMEQ(out, "world", 5);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* ---- Determinism: all four RNG seams fixed -> identical wire bytes. ---- */

static struct gy_keypair g_curve[4];
static size_t g_curve_idx;

/*
 * Fixed ML-KEM ratchet material, precomputed once with the production
 * (randomized) descriptor ops and replayed by the seams, so two runs match
 * without needing a derandomized entry point.  The determinism test performs a
 * single init+encrypt, so exactly one keypair and one encapsulation are drawn.
 */
static uint8_t g_ek[GY_KEM_EK_MAX], g_dk[GY_KEM_DK_MAX];
static uint8_t g_ct[GY_KEM_CT_MAX], g_ss[GY_KEM_SS_MAX];

static int
fixed_curve_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
    (void)desc;
    *out = g_curve[g_curve_idx % 4];
    g_curve_idx++;
    return GY_OK;
}

static int
fixed_salt(uint8_t *out, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(0xA0 + i);
    return GY_OK;
}

static int
fixed_kem_keypair(const struct gy_suite_desc *desc, uint8_t *ek, uint8_t *dk)
{
    memcpy(ek, g_ek, desc->kem_pk_len);
    memcpy(dk, g_dk, desc->kem_sk_len);
    return GY_OK;
}

static int
fixed_kem_encaps(const struct gy_suite_desc *desc, uint8_t *ct, uint8_t *ss,
                 const uint8_t *ek)
{
    (void)ek;
    memcpy(ct, g_ct, desc->kem_ct_len);
    memcpy(ss, g_ss, desc->kem_ss_len);
    return GY_OK;
}

TEST(determinism)
{
    struct gy_hybrid_keypair bob_spk;
    struct gy_dr_secrets s1, s2;
    struct gy_hybrid_dr_state st1, st2;
    uint8_t ad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t aik_ek[GY_KEM_EK_MAX], aik_dk[GY_KEM_DK_MAX];
    uint8_t w1[4096], w2[4096];
    size_t l1, l2, i;

    /* Bob's SPK and the fixed ML-KEM material generated once, reused by both. */
    ASSERT_EQ(gy_hybrid_keypair_generate(D, &bob_spk), GY_OK);
    ASSERT_EQ(D->kem_keypair(aik_ek, aik_dk), GY_OK);
    for (i = 0; i < 4; i++)
        ASSERT_EQ(gy_keypair_generate(D, &g_curve[i]), GY_OK);
    ASSERT_EQ(D->kem_keypair(g_ek, g_dk), GY_OK);
    ASSERT_EQ(D->kem_encap(g_ct, g_ss, bob_spk.pub.mlkem_ek), GY_OK);
    make_secrets(&s1);
    s2 = s1;

    gy_dr_test_keypair = fixed_curve_keypair;
    gy_he_test_salt = fixed_salt;
    gy_hybrid_dr_test_kem_keypair = fixed_kem_keypair;
    gy_hybrid_dr_test_kem_encaps = fixed_kem_encaps;

    g_curve_idx = 0;
    ASSERT_EQ(
        gy_hybrid_dr_init_alice(&st1, D, AEAD, &s1, &bob_spk.pub, 3, aik_dk),
        GY_OK);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&st1, w1, sizeof(w1), &l1,
                                   (const uint8_t *)"det", 3, ad, sizeof(ad)),
              GY_OK);

    g_curve_idx = 0;
    ASSERT_EQ(
        gy_hybrid_dr_init_alice(&st2, D, AEAD, &s2, &bob_spk.pub, 3, aik_dk),
        GY_OK);
    ASSERT_EQ(gy_hybrid_dr_encrypt(&st2, w2, sizeof(w2), &l2,
                                   (const uint8_t *)"det", 3, ad, sizeof(ad)),
              GY_OK);

    gy_dr_test_keypair = NULL;
    gy_he_test_salt = NULL;
    gy_hybrid_dr_test_kem_keypair = NULL;
    gy_hybrid_dr_test_kem_encaps = NULL;

    ASSERT_EQ(l1, l2);
    ASSERT_MEMEQ(w1, w2, l1);

    gy_hybrid_dr_free(&st1);
    gy_hybrid_dr_free(&st2);
}

/* Teardown zeroizes all key material. */
TEST(zeroize)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t ad[2] = {0xEE, 0xFF};

    hybrid_setup(&alice, &bob, 1);
    hrelay(&alice, &bob, ad, sizeof(ad), "k1");
    hrelay(&bob, &alice, ad, sizeof(ad), "k2");

    gy_hybrid_dr_free(&alice);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&alice, sizeof(alice)), 1);
    gy_hybrid_dr_free(&bob);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&bob, sizeof(bob)), 1);
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
            GY_TEST(init_mapping),
            GY_TEST(ping_pong_interval1),
            GY_TEST(ping_pong_interval2),
            GY_TEST(ping_pong_interval20),
            GY_TEST(ping_pong_interval100),
            GY_TEST(interval_sweep),
            GY_TEST(ping_pong_mixed),
            GY_TEST(out_of_order),
            GY_TEST(dropped_across_refresh),
            GY_TEST(header_len_combos),
            GY_TEST(header_ek_scheduling),
            GY_TEST(missing_ek_rejected),
            GY_TEST(bad_enc_header_len_rejected),
            GY_TEST(reserved_flag_rejected),
            GY_TEST(tamper_matrix),
            GY_TEST(determinism),
            GY_TEST(zeroize),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
