/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/ratchet/double_ratchet.c skipped-key handling under header
 * encryption (D-DR-4/8/17):
 * out-of-order delivery (same-chain and cross-epoch), MAX_SKIP enforcement,
 * commit-after-verify (a forged message is a complete no-op), oldest-first and
 * aging eviction, the (hk, n) epoch index (distinct hk per epoch, per-receive
 * trial counts, epoch-hk zeroization), and teardown zeroization.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "double_ratchet.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
static const uint64_t TS = 0x0000000155667788ull;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Wire buffer sized for the classical HE frame: 80-byte overhead + payload. */
#define WIRE 128

struct pair {
    struct gy_dr_state alice;
    struct gy_dr_state bob;
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;
};

static void
setup_pair(struct pair *p)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local local;
    struct gy_dr_secrets sa, sb;
    uint8_t prefix[GY_X3DH_PREFIX_MAX], adb[GY_X3DH_AD_MAX];
    size_t prefl, adbl;

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &bob_ik), GY_OK);
    ASSERT_EQ(gy_spk_create(D, &bob_spk, bob_ik.sk, TS), GY_OK);
    ASSERT_EQ(gy_opk_batch(D, bob_opk, 1, NULL, 0), GY_OK);

    memset(&bundle, 0, sizeof(bundle));
    bundle.ik = bob_ik.pub;
    bundle.spk = bob_spk.kp.pub;
    bundle.spk_timestamp = TS;
    memcpy(bundle.spk_sig, bob_spk.sig, GY_SIG_MAX);
    bundle.opk = bob_opk[0].pub;

    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, p->ad, &p->adl, prefix, &prefl,
                               &alice_ik, &bundle, &ek),
              GY_OK);
    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    ASSERT_EQ(gy_x3dh_respond(D, &sb, adb, &adbl, &ref, &local, prefix, prefl),
              GY_OK);

    ASSERT_EQ(gy_dr_init_bob(&p->bob, D, AEAD, &sb, &bob_spk.kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&p->alice, D, AEAD, &sa, bundle.spk.pk), GY_OK);
}

static void
enc(struct pair *p, struct gy_dr_state *from, uint8_t *w, size_t *wl,
    const char *pt)
{
    ASSERT_EQ(gy_dr_encrypt(from, w, WIRE, wl, (const uint8_t *)pt, strlen(pt),
                            p->ad, p->adl),
              GY_OK);
}

static void
dec_ok(struct pair *p, struct gy_dr_state *to, const uint8_t *w, size_t wl,
       const char *want)
{
    uint8_t out[WIRE];
    size_t outlen;

    ASSERT_EQ(
        gy_dr_decrypt(to, out, sizeof(out), &outlen, w, wl, p->ad, p->adl),
        GY_OK);
    ASSERT_EQ(outlen, strlen(want));
    ASSERT_MEMEQ(out, want, outlen);
}

/* Count the live (refs > 0) epoch slots in a skipped-key store. */
static size_t
live_epochs(const struct gy_skip_store *s)
{
    size_t i, n = 0;

    for (i = 0; i < GY_MAX_SKIP; i++)
        if (s->epochs[i].refs > 0)
            n++;
    return n;
}

/* Alice sends `count` messages "m<i>" into the shared wire buffers. */
static uint8_t g_wires[1100][WIRE];
static size_t g_lens[1100];

static void
alice_send_n(struct pair *p, size_t count)
{
    char buf[16];
    size_t i;

    for (i = 0; i < count; i++) {
        snprintf(buf, sizeof(buf), "m%zu", i);
        enc(p, &p->alice, g_wires[i], &g_lens[i], buf);
    }
}

TEST(out_of_order_same_chain)
{
    struct pair p;
    uint8_t w[4][WIRE];
    size_t wl[4];

    setup_pair(&p);
    enc(&p, &p.alice, w[0], &wl[0], "a0");
    enc(&p, &p.alice, w[1], &wl[1], "a1");
    enc(&p, &p.alice, w[2], &wl[2], "a2");
    enc(&p, &p.alice, w[3], &wl[3], "a3");

    /* Deliver 0, 2, 1, 3: n=1 is stored then consumed out of order. */
    dec_ok(&p, &p.bob, w[0], wl[0], "a0");
    dec_ok(&p, &p.bob, w[2], wl[2], "a2");
    ASSERT_EQ(p.bob.skipped.count, 1);
    dec_ok(&p, &p.bob, w[1], wl[1], "a1");
    ASSERT_EQ(p.bob.skipped.count, 0);
    dec_ok(&p, &p.bob, w[3], wl[3], "a3");

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(out_of_order_cross_epoch)
{
    struct pair p;
    uint8_t wa0[WIRE], wa1[WIRE], wa2[WIRE], wb0[WIRE];
    size_t la0, la1, la2, lb0;

    setup_pair(&p);
    enc(&p, &p.alice, wa0, &la0, "a0");
    dec_ok(&p, &p.bob, wa0, la0, "a0");

    enc(&p, &p.alice, wa1, &la1, "a1"); /* held back */

    enc(&p, &p.bob, wb0, &lb0, "b0");
    dec_ok(&p, &p.alice, wb0, lb0, "b0"); /* Alice ratchets */

    enc(&p, &p.alice, wa2, &la2, "a2"); /* new Alice chain */
    dec_ok(&p, &p.bob, wa2, la2, "a2"); /* Bob skips a1 (old chain) */
    ASSERT_EQ(p.bob.skipped.count, 1);

    dec_ok(&p, &p.bob, wa1, la1, "a1"); /* consume the cross-epoch skip */
    ASSERT_EQ(p.bob.skipped.count, 0);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(max_skip_overflow_is_noop)
{
    struct pair p;
    struct gy_dr_state before;
    uint8_t out[WIRE];
    size_t outlen;

    setup_pair(&p);
    alice_send_n(&p, GY_MAX_SKIP + 3);               /* n = 0 .. 1002 */
    dec_ok(&p, &p.bob, g_wires[0], g_lens[0], "m0"); /* bob.nr = 1 */

    /* n=1002 is 1001 past nr: the header decrypts, but the gap > MAX_SKIP is
     * rejected before any message-key derivation, state byte-identical. */
    before = p.bob;
    ASSERT_EQ(gy_dr_decrypt(&p.bob, out, sizeof(out), &outlen,
                            g_wires[GY_MAX_SKIP + 2], g_lens[GY_MAX_SKIP + 2],
                            p.ad, p.adl),
              GY_ERR_STATE);
    ASSERT_EQ(memcmp(&before, &p.bob, sizeof(before)), 0);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(forged_message_is_noop)
{
    struct pair p;
    struct gy_dr_state before;
    uint8_t w0[WIRE], forged[WIRE], out[WIRE];
    size_t l0, outlen, flen;
    size_t ehl = 4 + 32 + 8 + 16; /* c25519 enc_header: 44-byte header + tag */

    setup_pair(&p);
    enc(&p, &p.alice, w0, &l0, "a0");
    dec_ok(&p, &p.bob, w0, l0, "a0"); /* Bob now has HKr */

    /* A well-framed message with a novel salt and a garbage enc_header/payload:
     * neither HKr nor NHKr decrypt the header, so it is a complete no-op. */
    gy_frame_put(forged, D->suite_id);
    memset(forged + 2, 0xab, GY_HE_SALT_LEN);
    gy_be16_put(forged + 2 + GY_HE_SALT_LEN, (uint16_t)ehl);
    memset(forged + 2 + GY_HE_SALT_LEN + 2, 0xcd, ehl);      /* enc_header */
    memset(forged + 2 + GY_HE_SALT_LEN + 2 + ehl, 0xef, 20); /* payload */
    flen = 2 + GY_HE_SALT_LEN + 2 + ehl + 20;

    before = p.bob;
    ASSERT_EQ(gy_dr_decrypt(&p.bob, out, sizeof(out), &outlen, forged, flen,
                            p.ad, p.adl),
              GY_ERR_VERIFY);
    ASSERT_EQ(memcmp(&before, &p.bob, sizeof(before)), 0);

    /* A subsequent genuine message still decrypts. */
    enc(&p, &p.alice, w0, &l0, "a1");
    dec_ok(&p, &p.bob, w0, l0, "a1");

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(capacity_eviction_oldest_first)
{
    struct pair p;

    setup_pair(&p);
    alice_send_n(&p, GY_MAX_SKIP + 4); /* n = 0 .. 1003 */

    /* First delivered message is n=1000: stores 0..999, filling the store. */
    dec_ok(&p, &p.bob, g_wires[GY_MAX_SKIP], g_lens[GY_MAX_SKIP], "m1000");
    ASSERT_EQ(p.bob.skipped.count, GY_MAX_SKIP);
    ASSERT_EQ(p.bob.skipped.ent[0].n, 0);
    ASSERT_EQ(p.bob.skipped.ent[GY_MAX_SKIP - 1].n, GY_MAX_SKIP - 1);
    /* All skips are from one receiving chain: a single epoch key. */
    ASSERT_EQ(live_epochs(&p.bob.skipped), 1);

    /* n=1003 skips 1001,1002: two inserts at capacity evict the two oldest. */
    dec_ok(&p, &p.bob, g_wires[GY_MAX_SKIP + 3], g_lens[GY_MAX_SKIP + 3],
           "m1003");
    ASSERT_EQ(p.bob.skipped.count, GY_MAX_SKIP);
    ASSERT_EQ(p.bob.skipped.ent[0].n, 2); /* 0 and 1 evicted oldest-first */
    ASSERT_EQ(p.bob.skipped.ent[GY_MAX_SKIP - 1].n, GY_MAX_SKIP + 2);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(aging_eviction)
{
    struct pair p;
    size_t k;

    setup_pair(&p);
    alice_send_n(&p, GY_SKIP_AGE_LIMIT + 2); /* n = 0 .. 1001 */

    dec_ok(&p, &p.bob, g_wires[0], g_lens[0], "m0"); /* nr=1, recv_count=1 */
    dec_ok(&p, &p.bob, g_wires[2], g_lens[2], "m2"); /* stores n=1, age=1 */
    ASSERT_EQ(p.bob.skipped.count, 1);

    /* Deliver n=3..1001 in order: at recv_count 1001 the age-1 entry evicts. */
    for (k = 3; k <= GY_SKIP_AGE_LIMIT + 1; k++) {
        char buf[16];
        snprintf(buf, sizeof(buf), "m%zu", k);
        dec_ok(&p, &p.bob, g_wires[k], g_lens[k], buf);
    }
    ASSERT_EQ(p.bob.skipped.count, 0);
    ASSERT_EQ(live_epochs(&p.bob.skipped), 0);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

/*
 * Build a Bob store holding skipped keys from two distinct epochs: a0/a1 in
 * Alice's first chain, then a2/a3 in a second chain, with a1 and a2 held back.
 * Delivering a3 skips a1 (old epoch) and a2 (new epoch).
 */
static void
two_epoch_skips(struct pair *p, uint8_t held1[WIRE], size_t *lh1,
                uint8_t held2[WIRE], size_t *lh2)
{
    uint8_t wa0[WIRE], wa3[WIRE], wb0[WIRE];
    size_t la0, la3, lb0;

    setup_pair(p);
    enc(p, &p->alice, wa0, &la0, "a0");
    dec_ok(p, &p->bob, wa0, la0, "a0");
    enc(p, &p->alice, held1, lh1, "a1"); /* held: old epoch, n=1 */

    enc(p, &p->bob, wb0, &lb0, "b0");
    dec_ok(p, &p->alice, wb0, lb0, "b0"); /* Alice ratchets */

    enc(p, &p->alice, held2, lh2, "a2"); /* held: new epoch, n=0 */
    enc(p, &p->alice, wa3, &la3, "a3");  /* new epoch, n=1 */
    dec_ok(p, &p->bob, wa3, la3, "a3");  /* skips a1 (old) and a2 (new) */
}

TEST(epoch_hk_distinct)
{
    struct pair p;
    uint8_t h1[WIRE], h2[WIRE];
    size_t l1, l2, i, j;

    two_epoch_skips(&p, h1, &l1, h2, &l2);

    /* Two entries from two distinct epochs: two live slots, differing hks. */
    ASSERT_EQ(p.bob.skipped.count, 2);
    ASSERT_EQ(live_epochs(&p.bob.skipped), 2);
    ASSERT_TRUE(p.bob.skipped.ent[0].epoch != p.bob.skipped.ent[1].epoch,
                "entries in distinct epoch slots");
    for (i = 0; i < GY_MAX_SKIP; i++) {
        if (p.bob.skipped.epochs[i].refs == 0)
            continue;
        for (j = i + 1; j < GY_MAX_SKIP; j++)
            if (p.bob.skipped.epochs[j].refs > 0)
                ASSERT_TRUE(memcmp(p.bob.skipped.epochs[i].hk,
                                   p.bob.skipped.epochs[j].hk, 32) != 0,
                            "two epochs never share an hk");
    }

    /* Both cross-epoch skips still recover; header.n and the tag arbitrate. */
    dec_ok(&p, &p.bob, h1, l1, "a1");
    dec_ok(&p, &p.bob, h2, l2, "a2");
    ASSERT_EQ(p.bob.skipped.count, 0);
    ASSERT_EQ(live_epochs(&p.bob.skipped), 0);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(receive_trial_counts)
{
    struct pair p;
    uint8_t wa0[WIRE], wa1[WIRE], wa2[WIRE], wb0[WIRE], out[WIRE];
    size_t la0, la1, la2, lb0, ol;

    setup_pair(&p);

    /* Bob's first receive: empty store, HKr unset, NHKr succeeds (k=2 slot). */
    enc(&p, &p.alice, wa0, &la0, "a0");
    dec_ok(&p, &p.bob, wa0, la0, "a0");
    ASSERT_EQ(gy_dr_he_ctr.skipped, 0u);
    ASSERT_EQ(gy_dr_he_ctr.hkr, 0u); /* have_hkr was 0 */
    ASSERT_EQ(gy_dr_he_ctr.nhkr, 1u);

    /* In-order on the same chain: HKr succeeds after 0 skipped trials (k=1). */
    enc(&p, &p.alice, wa1, &la1, "a1");
    dec_ok(&p, &p.bob, wa1, la1, "a1");
    ASSERT_EQ(gy_dr_he_ctr.skipped, 0u);
    ASSERT_EQ(gy_dr_he_ctr.hkr, 1u);
    ASSERT_EQ(gy_dr_he_ctr.nhkr, 0u);

    /* A ratchet message: HKr fails, NHKr succeeds (distinct 0 + k=2). */
    enc(&p, &p.bob, wb0, &lb0, "b0");
    ASSERT_EQ(
        gy_dr_decrypt(&p.alice, out, sizeof(out), &ol, wb0, lb0, p.ad, p.adl),
        GY_OK);
    enc(&p, &p.alice, wa2, &la2, "a2");
    dec_ok(&p, &p.bob, wa2, la2, "a2");
    ASSERT_EQ(gy_dr_he_ctr.skipped, 0u);
    ASSERT_EQ(gy_dr_he_ctr.hkr, 1u);
    ASSERT_EQ(gy_dr_he_ctr.nhkr, 1u);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(stored_epoch_trials_and_zeroization)
{
    struct pair p;
    uint8_t h1[WIRE], h2[WIRE];
    size_t l1, l2, ep;
    uint8_t saved_hk[32];

    two_epoch_skips(&p, h1, &l1, h2, &l2);
    ASSERT_EQ(live_epochs(&p.bob.skipped), 2);

    /* a1 is in a stored epoch: phase 1 finds it and stops before HKr/NHKr. */
    ep = p.bob.skipped.ent[0].epoch; /* a1's epoch slot (oldest entry) */
    memcpy(saved_hk, p.bob.skipped.epochs[ep].hk, 32);
    ASSERT_EQ(gy_is_zero(saved_hk, 32), 0);
    ASSERT_EQ(p.bob.skipped.epochs[ep].refs, 1u); /* one entry references it */

    dec_ok(&p, &p.bob, h1, l1, "a1");
    ASSERT_TRUE(gy_dr_he_ctr.skipped >= 1u, "at least one skipped trial");
    ASSERT_EQ(gy_dr_he_ctr.hkr, 0u); /* stopped at phase 1 */
    ASSERT_EQ(gy_dr_he_ctr.nhkr, 0u);

    /* Consuming a1's last entry zeroizes and frees that epoch's hk. */
    ASSERT_EQ(p.bob.skipped.epochs[ep].refs, 0u);
    ASSERT_EQ(gy_is_zero(p.bob.skipped.epochs[ep].hk, 32), 1);
    ASSERT_TRUE(memcmp(p.bob.skipped.epochs[ep].hk, saved_hk, 32) != 0,
                "epoch hk zeroized on last consumption");
    ASSERT_EQ(live_epochs(&p.bob.skipped), 1);

    dec_ok(&p, &p.bob, h2, l2, "a2");
    ASSERT_EQ(live_epochs(&p.bob.skipped), 0);

    gy_dr_free(&p.alice);
    gy_dr_free(&p.bob);
}

TEST(teardown_zeroization)
{
    struct pair p;
    uint8_t w[WIRE];
    size_t wl;

    setup_pair(&p);
    enc(&p, &p.alice, w, &wl, "hi");
    dec_ok(&p, &p.bob, w, wl, "hi");

    gy_dr_free(&p.bob);
    ASSERT_EQ(gy_is_zero(&p.bob, sizeof(p.bob)), 1);
    gy_dr_free(&p.alice);
    ASSERT_EQ(gy_is_zero(&p.alice, sizeof(p.alice)), 1);
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
            GY_TEST(out_of_order_same_chain),
            GY_TEST(out_of_order_cross_epoch),
            GY_TEST(max_skip_overflow_is_noop),
            GY_TEST(forged_message_is_noop),
            GY_TEST(capacity_eviction_oldest_first),
            GY_TEST(aging_eviction),
            GY_TEST(epoch_hk_distinct),
            GY_TEST(receive_trial_counts),
            GY_TEST(stored_epoch_trials_and_zeroization),
            GY_TEST(teardown_zeroization),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
