/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Randomized hybrid soak (`slow`, HYBRID_SPEC §11, GER-M5-09 task 5): >= 10^4
 * messages delivered over a bidirectional hybrid session, reordered within a
 * bounded window, with random drops and duplicate replays, crossing ML-KEM
 * refresh boundaries (small interval) and the KEM confirmation chain (Bob's
 * first reply).  Each round reserves one frame that is delivered a full
 * ping-pong later, so it recovers from the PREVIOUS epoch's skipped-key store
 * (often across a refresh).  The PRNG seed is fixed and printed so any failure
 * is reproducible.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gy_sim.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

#define SOAK_N 10000
#define WINDOW 64  /* per-burst reorder window; < GY_MAX_SKIP */
#define FRAME 3072 /* holds an h25519_512 frame with ek + kem_ct + confirm_ct */

static uint64_t xs;

static uint64_t
xrand(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

TEST(hybrid_reorder_soak)
{
    struct gy_sim_hybrid bob;
    struct gy_sim_hybrid_initiator alice;
    uint8_t msg[GY_SIM_HYBRID_MSG_MAX], out[64];
    static uint8_t wires[WINDOW][FRAME];
    static size_t wl[WINDOW];
    static int widx[WINDOW];
    static uint8_t held[2][FRAME];
    static size_t heldl[2];
    static int heldidx[2], heldhave[2];
    size_t ml, ol;
    long total = 0;
    int round, mid = 0;
    char pt[16], want[16];

    xs = 0xa5a5f00d5eed1234ull;
    printf("hybrid_reorder_soak seed = 0x%016llx\n", (unsigned long long)xs);

    ASSERT_EQ(gy_sim_hybrid_setup(&bob, D, AEAD, 3, 1), GY_OK);
    ASSERT_EQ(gy_sim_hybrid_start(&alice, &bob, msg, sizeof(msg), &ml,
                                  (const uint8_t *)"m0", 2),
              GY_OK);
    ASSERT_EQ(
        gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, out, sizeof(out), &ol),
        GY_OK);

    heldhave[0] = heldhave[1] = 0;

    for (round = 0; total < SOAK_N; round++) {
        /* dir 0: Bob -> Alice (round 0 is Bob's first reply, the confirmation
         * chain).  dir 1: Alice -> Bob. */
        int dir = (round & 1) == 0 ? 0 : 1;
        struct gy_hybrid_dr_state *snd = dir == 0 ? &bob.bob_dr : &alice.dr;
        struct gy_hybrid_dr_state *rcv = dir == 0 ? &alice.dr : &bob.bob_dr;
        const uint8_t *sad = dir == 0 ? bob.ad : alice.ad;
        size_t sadl = dir == 0 ? bob.adl : alice.adl;
        const uint8_t *rad = dir == 0 ? alice.ad : bob.ad;
        size_t radl = dir == 0 ? alice.adl : bob.adl;
        int order[WINDOW];
        int B = 1 + (int)(xrand() % WINDOW);
        int reserve = (int)(xrand() % (uint64_t)B);
        int i, j;

        for (i = 0; i < B; i++) {
            mid++;
            snprintf(pt, sizeof(pt), "m%d", mid);
            ASSERT_EQ(gy_hybrid_dr_encrypt(snd, wires[i], FRAME, &wl[i],
                                           (const uint8_t *)pt, strlen(pt), sad,
                                           sadl),
                      GY_OK);
            widx[i] = mid;
        }

        for (i = 0; i < B; i++)
            order[i] = i;
        for (i = B - 1; i > 0; i--) {
            int t;

            j = (int)(xrand() % (uint64_t)(i + 1));
            t = order[i];
            order[i] = order[j];
            order[j] = t;
        }

        /* Deliver the burst reordered, except the reserved frame; ~5% dropped
         * (its key lands in the skip store), ~1/8 of deliveries replayed. */
        for (i = 0; i < B; i++) {
            int k = order[i];

            if (k == reserve)
                continue;
            if ((xrand() % 100) < 5)
                continue; /* dropped */
            snprintf(want, sizeof(want), "m%d", widx[k]);
            ASSERT_EQ(gy_hybrid_dr_decrypt(rcv, out, sizeof(out), &ol, wires[k],
                                           wl[k], rad, radl),
                      GY_OK);
            ASSERT_EQ(ol, strlen(want));
            ASSERT_MEMEQ(out, want, ol);
            total++;
            if ((xrand() & 7) == 0) {
                uint8_t dup[64];
                size_t dl;

                ASSERT_TRUE(gy_hybrid_dr_decrypt(rcv, dup, sizeof(dup), &dl,
                                                 wires[k], wl[k], rad,
                                                 radl) != GY_OK,
                            "replay of a consumed frame rejected");
            }
        }

        /* Cross-epoch recovery: the frame reserved a full ping-pong ago (an
         * older epoch, often across a refresh) recovers from the skip store. */
        if (heldhave[dir]) {
            snprintf(want, sizeof(want), "m%d", heldidx[dir]);
            ASSERT_EQ(gy_hybrid_dr_decrypt(rcv, out, sizeof(out), &ol,
                                           held[dir], heldl[dir], rad, radl),
                      GY_OK);
            ASSERT_EQ(ol, strlen(want));
            ASSERT_MEMEQ(out, want, ol);
            total++;
        }

        memcpy(held[dir], wires[reserve], wl[reserve]);
        heldl[dir] = wl[reserve];
        heldidx[dir] = widx[reserve];
        heldhave[dir] = 1;
    }

    /* Drain the two outstanding reserved frames (dir 0 -> Alice, dir 1 -> Bob). */
    if (heldhave[0])
        ASSERT_EQ(gy_hybrid_dr_decrypt(&alice.dr, out, sizeof(out), &ol,
                                       held[0], heldl[0], alice.ad, alice.adl),
                  GY_OK);
    if (heldhave[1])
        ASSERT_EQ(gy_hybrid_dr_decrypt(&bob.bob_dr, out, sizeof(out), &ol,
                                       held[1], heldl[1], bob.ad, bob.adl),
                  GY_OK);

    gy_sim_hybrid_initiator_free(&alice);
    gy_sim_hybrid_free(&bob);
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
            GY_TEST(hybrid_reorder_soak),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
