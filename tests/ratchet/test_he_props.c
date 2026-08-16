/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Header-encryption end-to-end properties over the two-party harness
 * (D-DR-16/17): the frame-granularity
 * tamper matrix (every field is a no-op reject), no-stable-identifier (nothing
 * beyond version || suite || enc_header_len repeats on the wire), delayed-epoch
 * delivery (a message recovered via a stored epoch header key after the
 * receiver advanced two epochs), and both-directions traffic across ratchet
 * steps (header-key rotation under concurrent sends).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gy_sim.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Run the handshake and deliver Alice's first message; leaves both DRs up. */
static void
bringup(struct gy_sim *sim, struct gy_sim_initiator *a)
{
    uint8_t msg[GY_SIM_MSG_MAX], out[64];
    size_t mlen, ol;

    ASSERT_EQ(gy_sim_setup(sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(
        gy_sim_start(a, sim, msg, sizeof(msg), &mlen, (const uint8_t *)"m0", 2),
        GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);
}

/* Encrypt pt on `from` and decrypt on `to`, asserting the round-trip. */
static void
relay(struct gy_dr_state *from, const uint8_t *fad, size_t fadl,
      struct gy_dr_state *to, const uint8_t *tad, size_t tadl, const char *pt)
{
    uint8_t w[256], out[256];
    size_t wl, ol;

    ASSERT_EQ(gy_dr_encrypt(from, w, sizeof(w), &wl, (const uint8_t *)pt,
                            strlen(pt), fad, fadl),
              GY_OK);
    ASSERT_EQ(gy_dr_decrypt(to, out, sizeof(out), &ol, w, wl, tad, tadl),
              GY_OK);
    ASSERT_EQ(ol, strlen(pt));
    ASSERT_MEMEQ(out, pt, ol);
}

TEST(dr_frame_tamper_matrix)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    struct gy_dr_state snap;
    uint8_t tmpl[256], w[256], out[256];
    size_t tl, ol, i;
    static const struct {
        enum gy_sim_field field;
        int rc;
    } cases[] = {
        {GY_SIM_F_VERSION, GY_ERR_ARG},       /* frame version byte */
        {GY_SIM_F_SUITE, GY_ERR_STATE},       /* cross-suite downgrade */
        {GY_SIM_F_SALT, GY_ERR_VERIFY},       /* wrong header key derived */
        {GY_SIM_F_LEN, GY_ERR_ARG},           /* enc_header_len != fixed */
        {GY_SIM_F_ENC_HEADER, GY_ERR_VERIFY}, /* header tag */
        {GY_SIM_F_PAYLOAD, GY_ERR_VERIFY},    /* payload tag */
    };

    bringup(&sim, &a);
    ASSERT_EQ(gy_dr_encrypt(&a.dr, tmpl, sizeof(tmpl), &tl,
                            (const uint8_t *)"hello", 5, a.ad, a.adl),
              GY_OK);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        memcpy(w, tmpl, tl);
        ASSERT_EQ(gy_sim_corrupt(w, tl, cases[i].field), GY_OK);
        snap = sim.bob_dr;
        ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, w, tl,
                                sim.ad, sim.adl),
                  cases[i].rc);
        /* Every rejection is a complete no-op: state byte-identical. */
        ASSERT_EQ(memcmp(&snap, &sim.bob_dr, sizeof(snap)), 0);
    }

    /* The untampered message still decrypts after the whole matrix. */
    ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, tmpl, tl,
                            sim.ad, sim.adl),
              GY_OK);
    ASSERT_EQ(ol, 5);
    ASSERT_MEMEQ(out, "hello", 5);

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(no_stable_identifier)
{
    enum { NA = 6, NB = 4, N = NA + NB };
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t fr[N][256], out[256];
    size_t fl[N], ol, i, j;
    size_t salt = 2, lenoff = 2 + GY_HE_SALT_LEN, ehoff = lenoff + 2;

    bringup(&sim, &a);

    /* NA frames in one epoch, a ratchet, then NB frames in the next epoch. */
    for (i = 0; i < NA; i++)
        ASSERT_EQ(gy_dr_encrypt(&a.dr, fr[i], sizeof(fr[i]), &fl[i],
                                (const uint8_t *)"payload", 7, a.ad, a.adl),
                  GY_OK);
    relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b0"); /* ratchet */
    for (i = NA; i < N; i++)
        ASSERT_EQ(gy_dr_encrypt(&a.dr, fr[i], sizeof(fr[i]), &fl[i],
                                (const uint8_t *)"payload", 7, a.ad, a.adl),
                  GY_OK);

    for (i = 0; i < N; i++) {
        ASSERT_EQ(fl[i], fl[0]); /* classical: identical frame length */
        for (j = i + 1; j < N; j++) {
            /* The only repeating cleartext is version || suite || len. */
            ASSERT_EQ(fr[i][0], fr[j][0]);
            ASSERT_EQ(fr[i][1], fr[j][1]);
            ASSERT_EQ(memcmp(fr[i] + lenoff, fr[j] + lenoff, 2), 0);
            /* Salt and enc_header are unique per message and per epoch. */
            ASSERT_TRUE(memcmp(fr[i] + salt, fr[j] + salt, GY_HE_SALT_LEN) != 0,
                        "hdr_salt repeats on the wire");
            ASSERT_TRUE(memcmp(fr[i] + ehoff, fr[j] + ehoff, 60) != 0,
                        "enc_header repeats on the wire");
        }
    }

    /* Every collected frame still decrypts in delivery order (sanity). */
    for (i = 0; i < NA; i++) {
        ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, fr[i],
                                fl[i], sim.ad, sim.adl),
                  GY_OK);
        ASSERT_MEMEQ(out, "payload", 7);
    }

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(delayed_epoch_delivery)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t held[256], out[256];
    size_t hl, ol;

    bringup(&sim, &a);

    /* Alice's second message in her first chain, held back (epoch e). */
    ASSERT_EQ(gy_dr_encrypt(&a.dr, held, sizeof(held), &hl,
                            (const uint8_t *)"delayed", 7, a.ad, a.adl),
              GY_OK);

    /* Advance two full epochs past it (b->a ratchet, a->b, b->a, a->b). */
    relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b1");
    relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a_e1");
    ASSERT_TRUE(sim.bob_dr.skipped.count >= 1, "epoch-e key was stored");
    relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b2");
    relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a_e2");

    /* The long-delayed epoch-e message still recovers via the stored hk. */
    ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, held, hl,
                            sim.ad, sim.adl),
              GY_OK);
    ASSERT_EQ(ol, 7);
    ASSERT_MEMEQ(out, "delayed", 7);

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(both_directions_ratchet_race)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t wa[256], wb[256], out[256];
    size_t la, lb, ol, r;

    bringup(&sim, &a);

    /* Each round both parties encrypt before either delivers: the header keys
     * rotate under concurrent sends, yet every message decrypts. */
    for (r = 0; r < 4; r++) {
        char pa[16], pb[16];

        snprintf(pa, sizeof(pa), "a%zu", r);
        snprintf(pb, sizeof(pb), "b%zu", r);
        ASSERT_EQ(gy_dr_encrypt(&a.dr, wa, sizeof(wa), &la, (const uint8_t *)pa,
                                strlen(pa), a.ad, a.adl),
                  GY_OK);
        ASSERT_EQ(gy_dr_encrypt(&sim.bob_dr, wb, sizeof(wb), &lb,
                                (const uint8_t *)pb, strlen(pb), sim.ad,
                                sim.adl),
                  GY_OK);

        ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, wa, la,
                                sim.ad, sim.adl),
                  GY_OK);
        ASSERT_MEMEQ(out, pa, strlen(pa));
        ASSERT_EQ(
            gy_dr_decrypt(&a.dr, out, sizeof(out), &ol, wb, lb, a.ad, a.adl),
            GY_OK);
        ASSERT_MEMEQ(out, pb, strlen(pb));
    }

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_C25519);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(dr_frame_tamper_matrix),
            GY_TEST(no_stable_identifier),
            GY_TEST(delayed_epoch_delivery),
            GY_TEST(both_directions_ratchet_race),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
