/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Randomized reorder soak (`slow`): >= 10^4 messages
 * delivered under header encryption within a bounded reorder window, every one
 * recovered, with random replay of just-consumed frames (always rejected as a
 * no-op).  The PRNG seed is fixed and printed so a failure is reproducible.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "gy_sim.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

#define SOAK_N 10000
#define SOAK_WINDOW 256

static uint64_t xs;

static uint64_t
xrand(void)
{
    xs ^= xs << 13;
    xs ^= xs >> 7;
    xs ^= xs << 17;
    return xs;
}

TEST(reorder_soak)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t msg[GY_SIM_MSG_MAX], out[64];
    static uint8_t wires[SOAK_WINDOW][128];
    static size_t wl[SOAK_WINDOW];
    static int idx[SOAK_WINDOW];
    size_t mlen, ol, wcount;
    int next;
    char pt[16], want[16];

    xs = 0x0badc0de12345678ull;
    printf("reorder_soak seed = 0x%016llx\n", (unsigned long long)xs);

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                           (const uint8_t *)"m0", 2),
              GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);

    /* Alice sends m1..mN in one chain; deliver them reordered within a window
     * (<= SOAK_WINDOW < MAX_SKIP), verifying each recovered plaintext. */
    wcount = 0;
    next = 1;
    while (next <= SOAK_N || wcount > 0) {
        if (next <= SOAK_N &&
            (wcount == 0 || (wcount < SOAK_WINDOW && (xrand() & 1)))) {
            snprintf(pt, sizeof(pt), "m%d", next);
            ASSERT_EQ(gy_dr_encrypt(&a.dr, wires[wcount], sizeof(wires[0]),
                                    &wl[wcount], (const uint8_t *)pt,
                                    strlen(pt), a.ad, a.adl),
                      GY_OK);
            idx[wcount] = next;
            wcount++;
            next++;
        } else {
            size_t j = (size_t)(xrand() % wcount);
            snprintf(want, sizeof(want), "m%d", idx[j]);
            ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol,
                                    wires[j], wl[j], sim.ad, sim.adl),
                      GY_OK);
            ASSERT_EQ(ol, strlen(want));
            ASSERT_MEMEQ(out, want, ol);
            /* Replay the just-consumed frame ~1/8 of the time: always a
             * no-op reject, never a second delivery. */
            if ((xrand() & 7) == 0) {
                uint8_t dup[64];
                size_t dupl;
                ASSERT_TRUE(gy_dr_decrypt(&sim.bob_dr, dup, sizeof(dup), &dupl,
                                          wires[j], wl[j], sim.ad,
                                          sim.adl) != GY_OK,
                            "replay of a consumed frame rejected");
            }
            wcount--;
            idx[j] = idx[wcount];
            wl[j] = wl[wcount];
            memcpy(wires[j], wires[wcount], sizeof(wires[0]));
        }
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
            GY_TEST(reorder_soak),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
