/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the KEM confirmation and PQ-pending state machine (HYBRID_SPEC
 * section 8, GER-M5-08a: engine mechanics).  The session/API wiring (persistence
 * and gy_pq_pending) is GER-M5-08b.  Built with -DGY_TEST_HOOKS.
 */

#include <stdint.h>
#include <string.h>

#include "hybrid_double_ratchet.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
#define AEAD GY_AEAD_CHACHA20POLY1305
static const uint8_t AD[2] = {0x5A, 0xA5};

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
 * Stand up a session.  Bob always encapsulates the confirmation to the real
 * Alice identity ek; Alice opens it with alice_id_dk (pass NULL to use the
 * matching real dk, or a mismatched dk to model a replayer who lacks it).
 */
static void
gen_session(struct gy_hybrid_dr_state *alice, struct gy_hybrid_dr_state *bob,
            uint32_t interval, const uint8_t *alice_id_dk)
{
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_keypair bob_spk;
    uint8_t ek[GY_KEM_EK_MAX], dk[GY_KEM_DK_MAX];

    ASSERT_EQ(gy_hybrid_keypair_generate(D, &bob_spk), GY_OK);
    ASSERT_EQ(D->kem_keypair(ek, dk), GY_OK);
    make_secrets(&sa);
    sb = sa;

    ASSERT_EQ(gy_hybrid_dr_init_bob(bob, D, AEAD, &sb, &bob_spk, interval, ek),
              GY_OK);
    ASSERT_EQ(gy_hybrid_dr_init_alice(alice, D, AEAD, &sa, &bob_spk.pub,
                                      interval,
                                      alice_id_dk != NULL ? alice_id_dk : dk),
              GY_OK);
}

/* Encrypt on `from` into wire; return length. */
static size_t
enc(struct gy_hybrid_dr_state *from, uint8_t *wire, size_t cap, const char *pt)
{
    size_t wl;

    ASSERT_EQ(gy_hybrid_dr_encrypt(from, wire, cap, &wl, (const uint8_t *)pt,
                                   strlen(pt), AD, sizeof(AD)),
              GY_OK);
    return wl;
}

/* Decrypt on `to`; assert round-trip. */
static void
dec_ok(struct gy_hybrid_dr_state *to, const uint8_t *wire, size_t wl,
       const char *pt)
{
    uint8_t out[256];
    size_t ol;

    ASSERT_EQ(gy_hybrid_dr_decrypt(to, out, sizeof(out), &ol, wire, wl, AD,
                                   sizeof(AD)),
              GY_OK);
    ASSERT_EQ(ol, strlen(pt));
    ASSERT_MEMEQ(out, pt, strlen(pt));
}

/* CLASSICAL_ONLY -> CONFIRM_SENT -> PQ_CONFIRMED (Bob) / -> CONFIRMED (Alice). */
TEST(state_machine)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w[4096];
    size_t wl;

    gen_session(&alice, &bob, 1, NULL);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CLASSICAL_ONLY);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CLASSICAL_ONLY);

    /* Alice's first message: Bob ratchets and sends confirmation -> CONFIRM_SENT. */
    wl = enc(&alice, w, sizeof(w), "a0");
    dec_ok(&bob, w, wl, "a0");
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CONFIRM_SENT);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CLASSICAL_ONLY);

    /* Bob's confirmation reply: Alice binds her PQ identity -> CONFIRMED. */
    wl = enc(&bob, w, sizeof(w), "b0");
    dec_ok(&alice, w, wl, "b0");
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CONFIRMED);
    /* Alice's identity dk is wiped once confirmation completes. */
    ASSERT_EQ(alice.have_id_dk, 0);
    ASSERT_EQ(gy_is_zero(alice.id_mlkem_dk, GY_KEM_DK_MAX), 1);

    /* Alice's reply on a descended chain: Bob reaches PQ_CONFIRMED. */
    wl = enc(&alice, w, sizeof(w), "a1");
    dec_ok(&bob, w, wl, "a1");
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CONFIRMED);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Confirmation completes from any later header of Bob's first chain. */
TEST(loss_tolerance)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w0[4096], w1[4096], w2[4096];
    size_t l0, l1, l2;

    gen_session(&alice, &bob, 5, NULL);
    dec_ok(&bob, w0, enc(&alice, w0, sizeof(w0), "a0"), "a0");

    /* Bob sends three messages in his (single) confirmation chain. */
    l0 = enc(&bob, w0, sizeof(w0), "b0");
    l1 = enc(&bob, w1, sizeof(w1), "b1");
    l2 = enc(&bob, w2, sizeof(w2), "b2");

    /* Drop b0, b1; Alice completes confirmation from b2 and recovers the rest. */
    dec_ok(&alice, w2, l2, "b2");
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CONFIRMED);
    dec_ok(&alice, w0, l0, "b0");
    dec_ok(&alice, w1, l1, "b1");

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Bit 9 set by the initiator is rejected by the responder (state no-op). */
TEST(bit9_from_initiator_rejected)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w[4096], out[256];
    size_t wl, ol;

    gen_session(&alice, &bob, 1, NULL);

    /* Force Alice to emit a confirmation flag she has no business sending. */
    alice.send_confirm_pending = 1;
    memset(alice.confirm_ct, 0x77, D->kem_ct_len);
    wl = enc(&alice, w, sizeof(w), "forge");

    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, w, wl, AD,
                                   sizeof(AD)),
              GY_ERR_STATE);
    /* No-op: Bob is untouched and still owes his confirmation. */
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CLASSICAL_ONLY);
    ASSERT_EQ(bob.confirm_pending, 1);
    ASSERT_EQ(bob.base.have_ckr, 0);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Bit 9 on a later responder chain (not the first) is rejected by the initiator. */
TEST(bit9_on_later_chain_rejected)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w[4096], out[256];
    size_t wl, ol;

    gen_session(&alice, &bob, 1, NULL);
    dec_ok(&bob, w, enc(&alice, w, sizeof(w), "a0"),
           "a0"); /* Bob CONFIRM_SENT */
    dec_ok(&alice, w, enc(&bob, w, sizeof(w), "b0"),
           "b0"); /* Alice CONFIRMED */
    dec_ok(&bob, w, enc(&alice, w, sizeof(w), "a1"), "a1"); /* Bob CONFIRMED */

    /* Bob's next chain must NOT carry confirmation; force it and expect reject. */
    bob.send_confirm_pending = 1;
    memset(bob.confirm_ct, 0x33, D->kem_ct_len);
    wl = enc(&bob, w, sizeof(w), "b1");

    ASSERT_EQ(gy_hybrid_dr_decrypt(&alice, out, sizeof(out), &ol, w, wl, AD,
                                   sizeof(AD)),
              GY_ERR_STATE);
    /* Alice unchanged: still CONFIRMED, no new receiving epoch adopted. */
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CONFIRMED);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* A header claiming bit 9 but truncating confirm_ct is rejected at decode. */
TEST(truncated_confirm_rejected)
{
    struct gy_dr_hybrid_header h, g;
    uint8_t buf[GY_DR_HYBRID_HEADER_MAX];
    size_t outlen, consumed;

    memset(&h, 0, sizeof(h));
    h.flags = D->curve_type | GY_DR_FLAG_CONFIRM_CT_PRESENT;
    ASSERT_EQ(gy_dr_hybrid_header_encode(D, &h, buf, sizeof(buf), &outlen),
              GY_OK);
    ASSERT_EQ(outlen, gy_dr_hybrid_header_len(D, 0, 1));

    /* One byte short of the confirm-carrying length: rejected. */
    ASSERT_EQ(gy_dr_hybrid_header_decode(D, &g, buf, outlen - 1, &consumed),
              GY_ERR_ARG);
}

/*
 * Replay hardening (section 8.5): without the matching identity dk, Bob's
 * confirmation reply is undecryptable and confirmation never completes.
 */
TEST(replay_undecryptable)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t wrong_ek[GY_KEM_EK_MAX], wrong_dk[GY_KEM_DK_MAX];
    uint8_t w[4096], out[256];
    size_t wl, ol;

    /* Alice holds a dk that does NOT match the ek Bob confirms to. */
    ASSERT_EQ(D->kem_keypair(wrong_ek, wrong_dk), GY_OK);
    gen_session(&alice, &bob, 1, wrong_dk);

    dec_ok(&bob, w, enc(&alice, w, sizeof(w), "a0"), "a0");

    /* Bob's confirmation reply cannot be opened with the wrong identity dk. */
    wl = enc(&bob, w, sizeof(w), "b0");
    ASSERT_EQ(gy_hybrid_dr_decrypt(&alice, out, sizeof(out), &ol, w, wl, AD,
                                   sizeof(AD)),
              GY_ERR_VERIFY);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&alice), GY_HYBRID_PQ_CLASSICAL_ONLY);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* PQ_CONFIRMED requires a VERIFIED post-confirmation message (no advance on tamper). */
TEST(confirmed_requires_verified)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w[4096], bad[4096], out[256];
    size_t wl, ol;

    gen_session(&alice, &bob, 1, NULL);
    dec_ok(&bob, w, enc(&alice, w, sizeof(w), "a0"), "a0"); /* CONFIRM_SENT */
    dec_ok(&alice, w, enc(&bob, w, sizeof(w), "b0"),
           "b0"); /* Alice CONFIRMED */

    wl = enc(&alice, w, sizeof(w), "a1");
    memcpy(bad, w, wl);
    bad[wl - 1] ^= 0x01; /* corrupt the payload tag */

    ASSERT_EQ(gy_hybrid_dr_decrypt(&bob, out, sizeof(out), &ol, bad, wl, AD,
                                   sizeof(AD)),
              GY_ERR_VERIFY);
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CONFIRM_SENT);

    /* The pristine message advances the state. */
    dec_ok(&bob, w, wl, "a1");
    ASSERT_EQ(gy_hybrid_dr_pq_state(&bob), GY_HYBRID_PQ_CONFIRMED);

    gy_hybrid_dr_free(&alice);
    gy_hybrid_dr_free(&bob);
}

/* Teardown zeroizes the confirmation material. */
TEST(confirm_material_zeroized)
{
    struct gy_hybrid_dr_state alice, bob;
    uint8_t w[4096];

    gen_session(&alice, &bob, 1, NULL);
    dec_ok(&bob, w, enc(&alice, w, sizeof(w), "a0"), "a0");
    /* Bob now holds a live confirm_ct for his chain. */
    ASSERT_EQ(bob.have_confirm_ct, 1);

    gy_hybrid_dr_free(&bob);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&bob, sizeof(bob)), 1);
    gy_hybrid_dr_free(&alice);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&alice, sizeof(alice)), 1);
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
            GY_TEST(state_machine),
            GY_TEST(loss_tolerance),
            GY_TEST(bit9_from_initiator_rejected),
            GY_TEST(bit9_on_later_chain_rejected),
            GY_TEST(truncated_confirm_rejected),
            GY_TEST(replay_undecryptable),
            GY_TEST(confirmed_requires_verified),
            GY_TEST(confirm_material_zeroized),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
