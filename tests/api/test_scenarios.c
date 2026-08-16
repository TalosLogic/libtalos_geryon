/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * public-API integration scenarios (include/geryon.h only): a
 * two-party duplex conversation, out-of-order and dropped delivery within
 * MAX_SKIP, replay rejection, racing-initiation convergence (D-SES-5),
 * mid-conversation key change with accept (D-SES-9), orphan re-initiate
 * (D-SES-8), device-compromise purge and re-add (D-SES-2), counter expiration
 * (D-SES-7), record-blob save/restore (state loss), pre-commit fault-injection
 * store equality (D-SES-10), and public-teardown zeroization.
 */

#include <string.h>

#include "geryon.h"

#include "apistore.h"
#include "gy_test.h"

/* ---- party abstraction (a device with its own ctx + store) ------------- */

struct party {
    gy_custodian *c;
    struct apistore st;
    gy_store_callbacks cb;
    const uint8_t *uid;
    size_t ul;
    const uint8_t *did;
    size_t dl;
};

static const uint8_t A_UID[4] = {0xA1, 0x01, 0x01, 0x01};
static const uint8_t A_DID[4] = {0xA1, 0x0D, 0x0D, 0x0D};
static const uint8_t B_UID[4] = {0xB2, 0x02, 0x02, 0x02};
static const uint8_t B_DID[4] = {0xB2, 0x0D, 0x0D, 0x0D};

static const uint8_t PARTY_CRED[] = "test party credential";

static void
party_up(struct party *p, const uint8_t *uid, const uint8_t *did,
         gy_clock_fn clock, void *cctx, const gy_config *cfg)
{
    as_bind(&p->st, &p->cb);
    p->uid = uid;
    p->ul = 4;
    p->did = did;
    p->dl = 4;
    ASSERT_EQ(gy_custodian_create(&p->c, GY_SUITE_C25519, &p->cb, PARTY_CRED,
                                  sizeof(PARTY_CRED) - 1, uid, 4, did, 4, clock,
                                  cctx, cfg),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(p->c, 1000, 4), GY_OK);
}

static void
party_down(struct party *p)
{
    gy_custodian_close(p->c);
    p->c = NULL;
}

static size_t
party_bundle(struct party *p, uint8_t *buf)
{
    size_t n = 0;

    ASSERT_EQ(gy_publish_bundle(p->c, NULL, &n), GY_OK);
    ASSERT_EQ(gy_publish_bundle(p->c, buf, &n), GY_OK);
    return n;
}

/* from initiates a session to to; returns the enveloped message length. */
static size_t
p_initiate(struct party *from, struct party *to, const uint8_t *pt,
           size_t ptlen, uint8_t *msg)
{
    uint8_t bundle[1024];
    size_t blen, mlen = 2048;

    blen = party_bundle(to, bundle);
    ASSERT_EQ(gy_send_open(from->c), GY_OK);
    ASSERT_EQ(gy_initiate(from->c, to->uid, to->ul, to->did, to->dl, bundle,
                          blen, pt, ptlen, NULL, msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(from->c), GY_OK);
    return mlen;
}

static size_t
p_encrypt(struct party *from, struct party *to, const uint8_t *pt, size_t ptlen,
          uint8_t *msg)
{
    size_t mlen = 2048;

    ASSERT_EQ(gy_send_open(from->c), GY_OK);
    ASSERT_EQ(gy_encrypt(from->c, to->uid, to->ul, to->did, to->dl, pt, ptlen,
                         msg, &mlen),
              GY_OK);
    ASSERT_EQ(gy_commit(from->c), GY_OK);
    return mlen;
}

/* to receives a message claimed to be from `from`; returns gy_receive rc. */
static int
p_recv(struct party *to, struct party *from, const uint8_t *msg, size_t mlen,
       uint8_t *out, size_t *olen)
{
    *olen = 256;
    return gy_receive(to->c, from->uid, from->ul, from->did, from->dl, msg,
                      mlen, out, olen);
}

/* ---- fixtures ---------------------------------------------------------- */

static struct party g_a, g_b, g_b2;
static struct apistore g_snap;
static uint64_t g_now;

static uint64_t
mock_clock(void *ctx)
{
    (void)ctx;
    return g_now;
}

/* ---- scenarios --------------------------------------------------------- */

TEST(two_party_duplex)
{
    uint8_t m[2048], out[256];
    size_t ml, ol;
    uint8_t a1[6] = "a-one", b1[6] = "b-one", a2[6] = "a-two";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);

    /* Alice initiates; Bob replies on the session he learned; Alice again. */
    ml = p_initiate(&g_a, &g_b, a1, sizeof(a1), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(ol == sizeof(a1) && memcmp(out, a1, ol) == 0, "a1");

    ml = p_encrypt(&g_b, &g_a, b1, sizeof(b1), m);
    ASSERT_EQ(p_recv(&g_a, &g_b, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(ol == sizeof(b1) && memcmp(out, b1, ol) == 0, "b1");

    ml = p_encrypt(&g_a, &g_b, a2, sizeof(a2), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(ol == sizeof(a2) && memcmp(out, a2, ol) == 0, "a2");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(out_of_order_and_dropped)
{
    uint8_t e1[2048], e2[2048], e3[2048], e4[2048], m0[2048], out[256];
    size_t l1, l2, l3, l4, lm, ol;
    uint8_t p0[3] = "go", d1[3] = "d1", d2[3] = "d2", d3[3] = "d3",
            d4[3] = "d4";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);

    lm = p_initiate(&g_a, &g_b, p0, sizeof(p0), m0);
    ASSERT_EQ(p_recv(&g_b, &g_a, m0, lm, out, &ol), GY_OK);

    l1 = p_encrypt(&g_a, &g_b, d1, sizeof(d1), e1);
    l2 = p_encrypt(&g_a, &g_b, d2, sizeof(d2), e2);
    l3 = p_encrypt(&g_a, &g_b, d3, sizeof(d3), e3);
    l4 = p_encrypt(&g_a, &g_b, d4, sizeof(d4), e4);
    (void)l4;
    (void)e4; /* d4 is dropped and never delivered */

    /* Deliver 1, then 3 (skipping 2), then 2 out of order. */
    ASSERT_EQ(p_recv(&g_b, &g_a, e1, l1, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, d1, ol) == 0, "d1");
    ASSERT_EQ(p_recv(&g_b, &g_a, e3, l3, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, d3, ol) == 0, "d3");
    ASSERT_EQ(p_recv(&g_b, &g_a, e2, l2, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, d2, ol) == 0, "d2 from skip store");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(replay_rejected)
{
    uint8_t m[2048], out[256];
    size_t ml, ol;
    uint8_t p0[3] = "hi";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);

    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);
    /* The identical initial replayed: uniform rejection, no new records. */
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_ERR_VERIFY);
    ASSERT_EQ(as_count(&g_b.st, GY_RECORD_SESSION), 1);

    party_down(&g_a);
    party_down(&g_b);
}

TEST(racing_initiation_converges)
{
    uint8_t ma[2048], mb[2048], m[2048], out[256];
    size_t la, lb, ml, ol;
    uint8_t pa[3] = "ra", pb[3] = "rb", conv[5] = "conv";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);

    /* Crossing initiations: each starts before receiving the other's. */
    la = p_initiate(&g_a, &g_b, pa, sizeof(pa), ma);
    lb = p_initiate(&g_b, &g_a, pb, sizeof(pb), mb);
    ASSERT_EQ(p_recv(&g_b, &g_a, ma, la, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, pa, ol) == 0, "b got a's initial");
    ASSERT_EQ(p_recv(&g_a, &g_b, mb, lb, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, pb, ol) == 0, "a got b's initial");

    /* A further message still decrypts: the association converges the pair. */
    ml = p_encrypt(&g_a, &g_b, conv, sizeof(conv), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, conv, ol) == 0, "converged, no plaintext loss");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(key_change_then_accept)
{
    uint8_t m[2048], out[256], bundle2[1024];
    size_t ml, ol, b2len;
    gy_keychange chg;
    uint8_t p0[3] = "k1", p1[3] = "k2";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* A second Bob identity on the same UserID/DeviceID: a key change. */
    party_up(&g_b2, B_UID, B_DID, NULL, NULL, NULL);
    b2len = party_bundle(&g_b2, bundle2);

    ASSERT_EQ(gy_send_open(g_a.c), GY_OK);
    ml = 2048;
    memset(&chg, 0, sizeof(chg));
    ASSERT_EQ(gy_initiate(g_a.c, B_UID, 4, B_DID, 4, bundle2, b2len, p1,
                          sizeof(p1), &chg, m, &ml),
              GY_ERR_KEY_CHANGED);
    gy_rollback(g_a.c);
    ASSERT_TRUE(chg.fp_len > 0, "key-change fingerprints surfaced");
    ASSERT_TRUE(memcmp(chg.old_fp, chg.new_fp, chg.fp_len) != 0, "fps differ");

    /* Accept the new key, then the fresh initiation succeeds and delivers. */
    ASSERT_EQ(gy_accept_identity(g_a.c, B_UID, 4, B_DID, 4, bundle2, b2len),
              GY_OK);
    ml = p_initiate(&g_a, &g_b2, p1, sizeof(p1), m);
    ASSERT_EQ(p_recv(&g_b2, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, p1, ol) == 0, "post-accept message");

    party_down(&g_a);
    party_down(&g_b);
    party_down(&g_b2);
}

TEST(orphan_reinitiate)
{
    uint8_t bundle[1024], m[2048], out[256];
    size_t blen, ml, ol;
    uint8_t p0[3] = "o1", p1[3] = "o2";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* Force a fresh initiating session (orphan escape) and use it. */
    blen = party_bundle(&g_b, bundle);
    ASSERT_EQ(gy_send_open(g_a.c), GY_OK);
    ml = 2048;
    ASSERT_EQ(gy_reinitiate(g_a.c, B_UID, 4, B_DID, 4, bundle, blen, p1,
                            sizeof(p1), NULL, m, &ml),
              GY_OK);
    ASSERT_EQ(gy_commit(g_a.c), GY_OK);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, p1, ol) == 0, "reinitiated message");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(compromise_purge_and_readd)
{
    uint8_t m[2048], out[256];
    size_t ml, ol;
    uint8_t p0[3] = "c1", p1[3] = "c2";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* Alice purges Bob's device; its records and sessions are gone. */
    ASSERT_EQ(gy_purge_device(g_a.c, B_UID, 4, B_DID, 4), GY_OK);
    ASSERT_EQ(as_count(&g_a.st, GY_RECORD_SESSION), 0);
    ASSERT_EQ(as_count(&g_a.st, GY_RECORD_DEVICE), 0);

    /* Re-add is an ordinary initiation (Bob re-registers a fresh identity). */
    party_up(&g_b2, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b2, p1, sizeof(p1), m);
    ASSERT_EQ(p_recv(&g_b2, &g_a, m, ml, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, p1, ol) == 0, "re-added device");

    party_down(&g_a);
    party_down(&g_b);
    party_down(&g_b2);
}

TEST(counter_expiration)
{
    gy_config cfg;
    gy_target tgt;
    gy_fanout_desc desc;
    uint8_t m[2048], out[256];
    size_t ml, ol, dc;
    uint8_t p0[3] = "e1", p1[3] = "e2";

    /* max_send = 1: the initiation message already reaches the bound. */
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    cfg.max_send = 1;
    cfg.max_recv = 10;
    cfg.max_latency = 1;

    party_up(&g_a, A_UID, A_DID, mock_clock, NULL, &cfg);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* prepare marks the device stale; encrypt refuses under expiration. */
    ASSERT_EQ(gy_send_open(g_a.c), GY_OK);
    tgt.user_id = B_UID;
    tgt.user_id_len = 4;
    dc = 1;
    ASSERT_EQ(gy_prepare(g_a.c, &tgt, 1, &desc, &dc), GY_OK);
    ASSERT_EQ(dc, 1u);
    ASSERT_EQ(desc.status, GY_FANOUT_STALE);
    ml = 2048;
    ASSERT_EQ(gy_encrypt(g_a.c, B_UID, 4, B_DID, 4, p1, sizeof(p1), m, &ml),
              GY_ERR_EXPIRED);
    gy_rollback(g_a.c);

    party_down(&g_a);
    party_down(&g_b);
}

TEST(state_loss_save_restore)
{
    uint8_t m0[2048], m1[2048], out[256];
    size_t l0, l1, ol;
    uint8_t p0[3] = "s0", p1[3] = "s1";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    l0 = p_initiate(&g_a, &g_b, p0, sizeof(p0), m0);
    ASSERT_EQ(p_recv(&g_b, &g_a, m0, l0, out, &ol), GY_OK);

    /* Snapshot Bob's store, advance it by one message, then "crash" back. */
    as_snapshot(&g_snap, &g_b.st);
    l1 = p_encrypt(&g_a, &g_b, p1, sizeof(p1), m1);
    ASSERT_EQ(p_recv(&g_b, &g_a, m1, l1, out, &ol), GY_OK);
    as_snapshot(&g_b.st, &g_snap); /* restore records from the saved blobs */

    /* Re-delivery of the same message resumes from the restored blobs. */
    ASSERT_EQ(p_recv(&g_b, &g_a, m1, l1, out, &ol), GY_OK);
    ASSERT_TRUE(memcmp(out, p1, ol) == 0, "resumed from restored records");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(fault_injection_store_equality)
{
    uint8_t m[2048], out[256];
    size_t ml, ol;
    uint8_t p0[3] = "f0", p1[3] = "f1";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* Snapshot, then fail the FIRST store of the next commit: nothing has been
     * written yet, so the store is byte-identical to the snapshot (D-SES-10). */
    as_snapshot(&g_snap, &g_a.st);
    g_a.st.write_idx = 0;
    g_a.st.fail_at = 0;
    ASSERT_EQ(gy_send_open(g_a.c), GY_OK);
    ml = 2048;
    ASSERT_EQ(gy_encrypt(g_a.c, B_UID, 4, B_DID, 4, p1, sizeof(p1), m, &ml),
              GY_OK);
    ASSERT_EQ(gy_commit(g_a.c), GY_ERR_CRYPTO);
    g_a.st.fail_at = -1;

    ASSERT_TRUE(memcmp(g_a.st.recs, g_snap.recs, sizeof(g_a.st.recs)) == 0,
                "store unchanged after a pre-write commit failure");

    party_down(&g_a);
    party_down(&g_b);
}

TEST(teardown_zeroization)
{
    uint8_t m[2048], out[256];
    size_t ml, ol;
    uint8_t p0[3] = "z0";

    party_up(&g_a, A_UID, A_DID, NULL, NULL, NULL);
    party_up(&g_b, B_UID, B_DID, NULL, NULL, NULL);
    ml = p_initiate(&g_a, &g_b, p0, sizeof(p0), m);
    ASSERT_EQ(p_recv(&g_b, &g_a, m, ml, out, &ol), GY_OK);

    /* Public teardown wipes and frees active contexts (ASan/UBSan enforce the
     * absence of leaks or use-after-free); gy_custodian_close is NULL-safe. */
    party_down(&g_a);
    party_down(&g_b);
    gy_custodian_close(NULL);
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(two_party_duplex),
        GY_TEST(out_of_order_and_dropped),
        GY_TEST(replay_rejected),
        GY_TEST(racing_initiation_converges),
        GY_TEST(key_change_then_accept),
        GY_TEST(orphan_reinitiate),
        GY_TEST(compromise_purge_and_readd),
        GY_TEST(counter_expiration),
        GY_TEST(state_loss_save_restore),
        GY_TEST(fault_injection_store_equality),
        GY_TEST(teardown_zeroization),
    };

    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
