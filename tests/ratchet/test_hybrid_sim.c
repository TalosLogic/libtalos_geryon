/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The hybrid two-party simulator (tests/harness/gy_sim), driving a full hybrid
 * handshake + KEM confirmation + ratchet through the harness, and the hybrid
 * frame tamper matrix (HYBRID_SPEC §11.3, GER-M5-09 task 4): per-field
 * corruption of the initial message (mlkem_ek, kem_ct, hybrid_flag) and of the
 * confirmation reply (confirm_ct), each rejected, plus base-key dedupe of a
 * replayed initial message.
 */

#include <stdint.h>
#include <string.h>

#include "gy_sim.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Happy path: initial message decrypts, and Bob's confirming reply advances the
 * initiator's PQ state to CONFIRMED. */
TEST(handshake_confirm_reply)
{
    struct gy_sim_hybrid bob;
    struct gy_sim_hybrid_initiator alice;
    uint8_t msg[GY_SIM_HYBRID_MSG_MAX], reply[4096], o1[64], o2[64];
    size_t ml, rl, l1, l2;

    ASSERT_EQ(gy_sim_hybrid_setup(&bob, D, AEAD, 3, 1), GY_OK);
    ASSERT_EQ(gy_sim_hybrid_start(&alice, &bob, msg, sizeof(msg), &ml,
                                  (const uint8_t *)"hi", 2),
              GY_OK);
    ASSERT_EQ(
        gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, o1, sizeof(o1), &l1),
        GY_OK);
    ASSERT_EQ(l1, 2);
    ASSERT_MEMEQ(o1, "hi", 2);

    /* Bob replies on his first sending chain, carrying the KEM confirmation. */
    ASSERT_EQ(gy_hybrid_dr_encrypt(&bob.bob_dr, reply, sizeof(reply), &rl,
                                   (const uint8_t *)"yo", 2, bob.ad, bob.adl),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&alice.dr, o2, sizeof(o2), &l2, reply, rl,
                                   alice.ad, alice.adl),
              GY_OK);
    ASSERT_MEMEQ(o2, "yo", 2);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice.dr), GY_HYBRID_PQ_CONFIRMED);

    gy_sim_hybrid_free(&bob);
    gy_sim_hybrid_initiator_free(&alice);
}

/* Per-field corruption of the initial message: each variant is rejected. */
TEST(initial_tamper_matrix)
{
    static const enum gy_sim_hybrid_field fields[] = {
        GY_SIM_HF_MLKEM_EK, GY_SIM_HF_KEM_CT, GY_SIM_HF_FLAGS};
    size_t i;

    for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        struct gy_sim_hybrid bob;
        struct gy_sim_hybrid_initiator alice;
        uint8_t msg[GY_SIM_HYBRID_MSG_MAX], out[64];
        size_t ml, ol;

        ASSERT_EQ(gy_sim_hybrid_setup(&bob, D, AEAD, 3, 1), GY_OK);
        ASSERT_EQ(gy_sim_hybrid_start(&alice, &bob, msg, sizeof(msg), &ml,
                                      (const uint8_t *)"x", 1),
                  GY_OK);
        ASSERT_EQ(gy_sim_hybrid_corrupt(D, msg, ml, fields[i]), GY_OK);
        ASSERT_TRUE(gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, out,
                                                   sizeof(out), &ol) != GY_OK,
                    "tampered initial message rejected");
        /* Rejection before commit leaves the OPK unconsumed (D-X3DH-10). */
        ASSERT_EQ(bob.opk_count, (size_t)1);

        gy_sim_hybrid_free(&bob);
        gy_sim_hybrid_initiator_free(&alice);
    }
}

/* Corrupting confirm_ct (in Bob's reply enc_header): the reply is undecryptable
 * and the initiator does not advance to CONFIRMED. */
TEST(confirm_ct_tamper)
{
    struct gy_sim_hybrid bob;
    struct gy_sim_hybrid_initiator alice;
    uint8_t msg[GY_SIM_HYBRID_MSG_MAX], reply[4096], o1[64], o2[64];
    size_t ml, rl, l1, l2;

    ASSERT_EQ(gy_sim_hybrid_setup(&bob, D, AEAD, 1, 1), GY_OK);
    ASSERT_EQ(gy_sim_hybrid_start(&alice, &bob, msg, sizeof(msg), &ml,
                                  (const uint8_t *)"hi", 2),
              GY_OK);
    ASSERT_EQ(
        gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, o1, sizeof(o1), &l1),
        GY_OK);

    ASSERT_EQ(gy_hybrid_dr_encrypt(&bob.bob_dr, reply, sizeof(reply), &rl,
                                   (const uint8_t *)"yo", 2, bob.ad, bob.adl),
              GY_OK);
    ASSERT_EQ(gy_sim_hybrid_corrupt(D, reply, rl, GY_SIM_HF_CONFIRM_CT), GY_OK);
    ASSERT_EQ(gy_hybrid_dr_decrypt(&alice.dr, o2, sizeof(o2), &l2, reply, rl,
                                   alice.ad, alice.adl),
              GY_ERR_VERIFY);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice.dr), GY_HYBRID_PQ_CLASSICAL_ONLY);

    gy_sim_hybrid_free(&bob);
    gy_sim_hybrid_initiator_free(&alice);
}

/* A replayed initial message routes to the live session by base-key dedupe;
 * the already-consumed first frame no longer decrypts. */
TEST(replayed_initial_deduped)
{
    struct gy_sim_hybrid bob;
    struct gy_sim_hybrid_initiator alice;
    uint8_t msg[GY_SIM_HYBRID_MSG_MAX], o1[64], o2[64];
    size_t ml, l1, l2;

    ASSERT_EQ(gy_sim_hybrid_setup(&bob, D, AEAD, 2, 1), GY_OK);
    ASSERT_EQ(gy_sim_hybrid_start(&alice, &bob, msg, sizeof(msg), &ml,
                                  (const uint8_t *)"once", 4),
              GY_OK);
    ASSERT_EQ(
        gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, o1, sizeof(o1), &l1),
        GY_OK);
    ASSERT_MEMEQ(o1, "once", 4);

    ASSERT_TRUE(gy_sim_hybrid_bob_recv_initial(&bob, msg, ml, o2, sizeof(o2),
                                               &l2) != GY_OK,
                "replayed first frame is undecryptable on the live session");

    gy_sim_hybrid_free(&bob);
    gy_sim_hybrid_initiator_free(&alice);
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
            GY_TEST(handshake_confirm_reply),
            GY_TEST(initial_tamper_matrix),
            GY_TEST(confirm_ct_tamper),
            GY_TEST(replayed_initial_deduped),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
