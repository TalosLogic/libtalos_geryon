/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * property soak (seeded; `slow` label): randomized Alice->Bob traffic
 * with per-block reorder, drop, and duplicate, plus periodic record-blob
 * save/restore, through include/geryon.h only.  Invariants each round: every
 * delivered message recovers its exact plaintext, a duplicate is rejected
 * uniformly, exactly one session persists (no fork), and the store stays within
 * its blob bound (no unbounded growth).
 */

#include <string.h>

#include "geryon.h"

#include "apistore.h"
#include "gy_test.h"

/* ---- deterministic PRNG ------------------------------------------------ */

static uint32_t g_rs = 0xC0FFEE11u;

static uint32_t
rnd(void)
{
    g_rs = g_rs * 1664525u + 1013904223u;
    return g_rs >> 8;
}

/* ---- party helpers (public API only) ----------------------------------- */

static const uint8_t A_UID[4] = {0xA1, 1, 1, 1};
static const uint8_t A_DID[4] = {0xA1, 2, 2, 2};
static const uint8_t B_UID[4] = {0xB2, 1, 1, 1};
static const uint8_t B_DID[4] = {0xB2, 2, 2, 2};

static gy_custodian *g_ac, *g_bc;
static struct apistore g_as, g_bs, g_snap;
static gy_store_callbacks g_acb, g_bcb;

static void
bring_up(void)
{
    uint8_t bundle[1024];
    size_t blen = 0, ml, ol;
    uint8_t out[64], pt[4] = "init";
    static const uint8_t a_cred[] = "alice soak credential";
    static const uint8_t b_cred[] = "bob soak credential";

    as_bind(&g_as, &g_acb);
    as_bind(&g_bs, &g_bcb);
    ASSERT_EQ(gy_custodian_create(&g_ac, GY_SUITE_C25519, &g_acb, a_cred,
                                  sizeof(a_cred) - 1, A_UID, 4, A_DID, 4, NULL,
                                  NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_create(&g_bc, GY_SUITE_C25519, &g_bcb, b_cred,
                                  sizeof(b_cred) - 1, B_UID, 4, B_DID, 4, NULL,
                                  NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(g_ac, 1000, 4), GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(g_bc, 1000, 4), GY_OK);

    ASSERT_EQ(gy_publish_bundle(g_bc, NULL, &blen), GY_OK);
    ASSERT_EQ(gy_publish_bundle(g_bc, bundle, &blen), GY_OK);

    ASSERT_EQ(gy_send_open(g_ac), GY_OK);
    ml = 2048;
    {
        uint8_t m[2048];

        ASSERT_EQ(gy_initiate(g_ac, B_UID, 4, B_DID, 4, bundle, blen, pt,
                              sizeof(pt), NULL, m, &ml),
                  GY_OK);
        ASSERT_EQ(gy_commit(g_ac), GY_OK);
        ol = sizeof(out);
        ASSERT_EQ(gy_receive(g_bc, A_UID, 4, A_DID, 4, m, ml, out, &ol), GY_OK);
    }
}

/* Alice encrypts a 4-byte big-endian sequence tag; returns enveloped length. */
static size_t
a_send(uint32_t seq, uint8_t *msg)
{
    uint8_t pt[4];
    size_t ml = 2048;

    pt[0] = (uint8_t)(seq >> 24);
    pt[1] = (uint8_t)(seq >> 16);
    pt[2] = (uint8_t)(seq >> 8);
    pt[3] = (uint8_t)seq;
    ASSERT_EQ(gy_send_open(g_ac), GY_OK);
    ASSERT_EQ(gy_encrypt(g_ac, B_UID, 4, B_DID, 4, pt, sizeof(pt), msg, &ml),
              GY_OK);
    ASSERT_EQ(gy_commit(g_ac), GY_OK);
    return ml;
}

static int
b_recv(const uint8_t *msg, size_t mlen, uint8_t *out, size_t *ol)
{
    *ol = 64;
    return gy_receive(g_bc, A_UID, 4, A_DID, 4, msg, mlen, out, ol);
}

/* ---- soak -------------------------------------------------------------- */

#define ROUNDS 100
#define BLOCK_MAX 5

TEST(randomized_traffic)
{
    uint8_t envs[BLOCK_MAX][2048];
    uint32_t seqs[BLOCK_MAX];
    size_t lens[BLOCK_MAX];
    uint8_t out[64];
    uint32_t seq = 0;
    int r;

    bring_up();

    for (r = 0; r < ROUNDS; r++) {
        int b = 1 + (int)(rnd() % BLOCK_MAX);
        int order[BLOCK_MAX];
        int i;
        size_t ol;

        for (i = 0; i < b; i++) {
            seqs[i] = seq;
            lens[i] = a_send(seq, envs[i]);
            order[i] = i;
            seq++;
        }
        /* Fisher-Yates shuffle for per-block reorder. */
        for (i = b - 1; i > 0; i--) {
            int j = (int)(rnd() % (uint32_t)(i + 1));
            int t = order[i];

            order[i] = order[j];
            order[j] = t;
        }

        for (i = 0; i < b; i++) {
            int k = order[i];
            uint32_t got;
            int rc;

            if (rnd() % 6 == 0)
                continue; /* dropped: never delivered */
            rc = b_recv(envs[k], lens[k], out, &ol);
            ASSERT_EQ(rc, GY_OK);
            ASSERT_EQ(ol, 4u);
            got = ((uint32_t)out[0] << 24) | ((uint32_t)out[1] << 16) |
                  ((uint32_t)out[2] << 8) | out[3];
            ASSERT_EQ(got, seqs[k]);

            /* Occasionally deliver a duplicate: it must be rejected. */
            if (rnd() % 5 == 0)
                ASSERT_EQ(b_recv(envs[k], lens[k], out, &ol), GY_ERR_VERIFY);
        }

        /* Invariants: exactly one session, store within its blob bound. */
        ASSERT_EQ(as_count(&g_bs, GY_RECORD_SESSION), 1);
        ASSERT_TRUE(as_bytes(&g_bs) < (size_t)AS_MAX * AS_BLOB,
                    "store within bound");

        /* Periodic save/restore: prove resume from restored record blobs. */
        if (r % 25 == 24) {
            uint8_t m[2048];
            size_t lm;

            as_snapshot(&g_snap, &g_bs);
            lm = a_send(seq, m);
            ASSERT_EQ(b_recv(m, lm, out, &ol), GY_OK);
            as_snapshot(&g_bs, &g_snap); /* crash back to the snapshot */
            ASSERT_EQ(b_recv(m, lm, out, &ol), GY_OK); /* re-deliver, resume */
            ASSERT_EQ(ol, 4u);
            seq++;
        }
    }

    gy_custodian_close(g_ac);
    gy_custodian_close(g_bc);
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(randomized_traffic),
    };

    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
