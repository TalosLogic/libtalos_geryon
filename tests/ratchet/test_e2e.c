/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * End-to-end properties over the test harness: full conversation,
 * re-send convergence, consumed-OPK replay, junk-message OPK retention,
 * initial- and DR-message tamper matrices, cross-version/suite rejection, and
 * teardown zeroization.
 */

#include <stdint.h>
#include <string.h>

#include "gy_sim.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Classical c25519 initial-message field offsets (kw = 37). */
#define OFF_VERSION 0
#define OFF_SUITE 1
#define OFF_IK_PKID 2
#define OFF_IK_PK 7
#define OFF_IK_ID 76
#define OFF_SPK_ID 80

/* One application message from `from` to `to`, asserting round-trip. */
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

TEST(full_conversation)
{
    int with_opk;

    for (with_opk = 0; with_opk <= 1; with_opk++) {
        struct gy_sim sim;
        struct gy_sim_initiator a;
        uint8_t msg[GY_SIM_MSG_MAX], out[256];
        size_t mlen, ol;

        ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, with_opk), GY_OK);
        ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                               (const uint8_t *)"hello", 5),
                  GY_OK);
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            GY_OK);
        ASSERT_EQ(ol, 5);
        ASSERT_MEMEQ(out, "hello", 5);
        /* The consumed OPK, if any, is deleted on success. */
        ASSERT_EQ(sim.opk_count, 0);

        relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b1");
        relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a2");
        relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b2");
        relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a3");

        gy_sim_initiator_free(&a);
        gy_sim_free(&sim);
    }
}

TEST(resend_convergence)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t msg[GY_SIM_MSG_MAX], out[256];
    size_t mlen, ol;
    int i;

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                           (const uint8_t *)"hello", 5),
              GY_OK);

    /* First copy establishes one session and yields one plaintext. */
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);
    ASSERT_MEMEQ(out, "hello", 5);

    /* Re-sends dedupe to the same session; the consumed first message fails. */
    for (i = 0; i < 4; i++)
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            GY_ERR_VERIFY);

    /* The session is intact: ongoing traffic still flows. */
    relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a1");

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(consumed_opk_replay)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t msg[GY_SIM_MSG_MAX], out[256];
    size_t mlen, ol;

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                           (const uint8_t *)"hi", 2),
              GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);
    ASSERT_EQ(sim.opk_count, 0); /* OPK burned */

    /* Replaying the whole initial message fails cleanly. */
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_ERR_VERIFY);
    ASSERT_EQ(sim.opk_count, 0);

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(junk_message_opk_retention)
{
    struct gy_sim sim;
    struct gy_sim_initiator junk, good;
    uint8_t jmsg[GY_SIM_MSG_MAX], gmsg[GY_SIM_MSG_MAX], out[256];
    size_t jlen, glen, ol;

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);

    /* A well-formed handshake against the same OPK but with a corrupted first
     * message: the handshake responds, the message fails, the OPK is kept. */
    ASSERT_EQ(gy_sim_start(&junk, &sim, jmsg, sizeof(jmsg), &jlen,
                           (const uint8_t *)"x", 1),
              GY_OK);
    jmsg[jlen - 1] ^= 0x01;
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, jmsg, jlen, out, sizeof(out), &ol),
              GY_ERR_VERIFY);
    ASSERT_EQ(sim.opk_count, 1); /* retained (D-X3DH-10) */
    ASSERT_EQ(sim.bob_up, 0);

    /* A later genuine handshake still consumes that OPK. */
    ASSERT_EQ(gy_sim_start(&good, &sim, gmsg, sizeof(gmsg), &glen,
                           (const uint8_t *)"ok", 2),
              GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, gmsg, glen, out, sizeof(out), &ol),
              GY_OK);
    ASSERT_MEMEQ(out, "ok", 2);
    ASSERT_EQ(sim.opk_count, 0);

    gy_sim_initiator_free(&junk);
    gy_sim_initiator_free(&good);
    gy_sim_free(&sim);
}

struct tamper_case {
    size_t off;
    int expect;
};

TEST(initial_message_tamper_matrix)
{
    static const struct tamper_case cases[] = {
        {OFF_VERSION, GY_ERR_ARG},    {OFF_SUITE, GY_ERR_STATE},
        {OFF_IK_PKID, GY_ERR_VERIFY}, {OFF_IK_PK, GY_ERR_VERIFY},
        {OFF_IK_ID, GY_ERR_STATE},    {OFF_SPK_ID, GY_ERR_VERIFY},
    };
    size_t i;

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct gy_sim sim;
        struct gy_sim_initiator a;
        uint8_t msg[GY_SIM_MSG_MAX], out[256];
        size_t mlen, ol;

        ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
        ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                               (const uint8_t *)"hello", 5),
                  GY_OK);
        msg[cases[i].off] ^= 0x01;
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            cases[i].expect);
        /* Nothing committed on any rejection. */
        ASSERT_EQ(sim.bob_up, 0);
        ASSERT_EQ(sim.opk_count, 1);

        gy_sim_initiator_free(&a);
        gy_sim_free(&sim);
    }

    /* Corrupting the carried first-message tag: handshake ok, message fails. */
    {
        struct gy_sim sim;
        struct gy_sim_initiator a;
        uint8_t msg[GY_SIM_MSG_MAX], out[256];
        size_t mlen, ol;

        ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
        ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                               (const uint8_t *)"hello", 5),
                  GY_OK);
        msg[mlen - 1] ^= 0x01;
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            GY_ERR_VERIFY);
        ASSERT_EQ(sim.opk_count, 1);
        gy_sim_initiator_free(&a);
        gy_sim_free(&sim);
    }
}

TEST(dr_message_tamper_noop)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t msg[GY_SIM_MSG_MAX], out[256], w[256];
    size_t mlen, ol, wl;

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                           (const uint8_t *)"hello", 5),
              GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);

    /* Corrupt a ciphertext byte: rejected, Bob's state unharmed, next ok. */
    ASSERT_EQ(gy_dr_encrypt(&a.dr, w, sizeof(w), &wl, (const uint8_t *)"a1", 2,
                            a.ad, a.adl),
              GY_OK);
    w[wl - 1] ^= 0x01;
    ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, w, wl, sim.ad,
                            sim.adl),
              GY_ERR_VERIFY);
    relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a2");

    /* Corrupt the frame suite byte: cross-suite downgrade reject (D-GEN-1).
     * The curve_type now lives inside the encrypted header, so cross-suite is
     * caught at the frame prefix instead of at header decode. */
    ASSERT_EQ(gy_dr_encrypt(&a.dr, w, sizeof(w), &wl, (const uint8_t *)"a3", 2,
                            a.ad, a.adl),
              GY_OK);
    w[1] = GY_SUITE_C448;
    ASSERT_EQ(gy_dr_decrypt(&sim.bob_dr, out, sizeof(out), &ol, w, wl, sim.ad,
                            sim.adl),
              GY_ERR_STATE);
    relay(&a.dr, a.ad, a.adl, &sim.bob_dr, sim.ad, sim.adl, "a4");

    gy_sim_initiator_free(&a);
    gy_sim_free(&sim);
}

TEST(cross_version_suite)
{
    static const uint8_t bad_version[] = {0x00, 0x02};
    static const uint8_t bad_suite[] = {GY_SUITE_H25519_512, GY_SUITE_C448,
                                        GY_SUITE_H448_1024};
    size_t i;

    for (i = 0; i < sizeof(bad_version); i++) {
        struct gy_sim sim;
        struct gy_sim_initiator a;
        uint8_t msg[GY_SIM_MSG_MAX], out[256];
        size_t mlen, ol;

        ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
        ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                               (const uint8_t *)"x", 1),
                  GY_OK);
        msg[OFF_VERSION] = bad_version[i];
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            GY_ERR_ARG);
        gy_sim_initiator_free(&a);
        gy_sim_free(&sim);
    }

    for (i = 0; i < sizeof(bad_suite); i++) {
        struct gy_sim sim;
        struct gy_sim_initiator a;
        uint8_t msg[GY_SIM_MSG_MAX], out[256];
        size_t mlen, ol;

        ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
        ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                               (const uint8_t *)"x", 1),
                  GY_OK);
        msg[OFF_SUITE] = bad_suite[i];
        ASSERT_EQ(
            gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
            GY_ERR_STATE);
        gy_sim_initiator_free(&a);
        gy_sim_free(&sim);
    }
}

TEST(teardown_zeroization)
{
    struct gy_sim sim;
    struct gy_sim_initiator a;
    uint8_t msg[GY_SIM_MSG_MAX], out[256];
    size_t mlen, ol;

    ASSERT_EQ(gy_sim_setup(&sim, D, AEAD, 1), GY_OK);
    ASSERT_EQ(gy_sim_start(&a, &sim, msg, sizeof(msg), &mlen,
                           (const uint8_t *)"hello", 5),
              GY_OK);
    ASSERT_EQ(gy_sim_bob_recv_initial(&sim, msg, mlen, out, sizeof(out), &ol),
              GY_OK);
    relay(&sim.bob_dr, sim.ad, sim.adl, &a.dr, a.ad, a.adl, "b1");

    gy_sim_free(&sim);
    gy_sim_initiator_free(&a);
    ASSERT_EQ(gy_is_zero(&sim, sizeof(sim)), 1);
    ASSERT_EQ(gy_is_zero(&a, sizeof(a)), 1);
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
            GY_TEST(full_conversation),
            GY_TEST(resend_convergence),
            GY_TEST(consumed_opk_replay),
            GY_TEST(junk_message_opk_retention),
            GY_TEST(initial_message_tamper_matrix),
            GY_TEST(dr_message_tamper_noop),
            GY_TEST(cross_version_suite),
            GY_TEST(teardown_zeroization),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
