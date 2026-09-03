/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Public-API cross-suite rejection matrix (HYBRID_SPEC 11.3): a cross-suite
 * object is rejected before any cryptographic processing.
 * The suite is pinned per identity and bound into every wire object at byte
 * offset 1; it is never negotiated at runtime and there is no
 * hybrid-to-classical fallback path in code.
 *
 * This drives the full 4x4 of {c25519, h25519_512, c448, h448_1024} through
 * the public API: each suite's published bundle and a valid same-suite initial
 * message are captured, then presented, via gy_initiate / gy_receive, to a
 * custodian of every OTHER suite.  Every off-diagonal cell must be rejected at
 * the suite_id check (GY_ERR_STATE) BEFORE any cryptographic processing
 * (gy_bundle_parse / gy_hybrid_bundle_parse on the initiator side, the envelope
 * suite check inside gy_recv / gy_hybrid_recv on the responder side).  The
 * cells that cross the classical/hybrid boundary exercise the downgrade split
 * in both directions.  The diagonal (same-suite) cells validate the harness end
 * to end (first-contact TOFU receive).
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "geryon.h"

#include "apistore.h"

#include "gy_test.h"

#define NSUITES 4
/* h448_1024 is the largest tier: ~12 KB bundle, ~9 KB initial-message prefix.
 */
#define BUNDLE_MAX 16384
#define MSG_MAX 16384

static const uint8_t g_suites[NSUITES] = {
    GY_SUITE_C25519,
    GY_SUITE_H25519_512,
    GY_SUITE_C448,
    GY_SUITE_H448_1024,
};

/* Responder and sender identities.  Each custodian owns its own store, so the
 * same id bytes may repeat across suites without collision. */
static const uint8_t RUID[4] = {0x51, 0x01, 0x01, 0x01};
static const uint8_t RDID[4] = {0x51, 0x0D, 0x0D, 0x0D};
static const uint8_t SUID[4] = {0x52, 0x02, 0x02, 0x02};
static const uint8_t SDID[4] = {0x52, 0x0D, 0x0D, 0x0D};
static const uint8_t CRED[] = "suite matrix credential";

struct party {
    gy_custodian *c;
    struct apistore st;
    gy_store_callbacks cb;
};

static void
party_up(struct party *p, uint8_t suite, const uint8_t *uid, const uint8_t *did)
{
    as_bind(&p->st, &p->cb);
    ASSERT_EQ(gy_custodian_create(&p->c, suite, &p->cb, CRED, sizeof(CRED) - 1,
                                  uid, 4, did, 4, NULL, NULL, NULL),
              GY_OK);
    ASSERT_EQ(gy_custodian_generate_identity(p->c, 1000, 4), GY_OK);
}

static void
party_down(struct party *p)
{
    if (p->c != NULL)
        gy_custodian_close(p->c);
    p->c = NULL;
}

static size_t
party_bundle(struct party *p, uint8_t *buf, size_t cap)
{
    size_t n = 0;

    ASSERT_EQ(gy_publish_bundle(p->c, NULL, &n), GY_OK);
    ASSERT_TRUE(n <= cap, "bundle fits buffer");
    ASSERT_EQ(gy_publish_bundle(p->c, buf, &n), GY_OK);
    return n;
}

TEST(cross_suite_matrix)
{
    /* Static: each apistore is ~1 MB, so 8 parties live in BSS, not on stack.
     */
    static struct party resp[NSUITES];
    static struct party snd[NSUITES];
    static uint8_t bundle[NSUITES][BUNDLE_MAX];
    static uint8_t init[NSUITES][MSG_MAX];
    size_t blen[NSUITES], ilen[NSUITES];
    uint8_t out[256];
    size_t olen;
    int x, y;

    /*
     * Phase 1: bring up a responder + sender per suite; capture each suite's
     * published bundle and a valid same-suite initial message (the diagonal),
     * confirming the matching responder accepts it (first-contact TOFU).
     */
    for (x = 0; x < NSUITES; x++) {
        party_up(&resp[x], g_suites[x], RUID, RDID);
        party_up(&snd[x], g_suites[x], SUID, SDID);

        blen[x] = party_bundle(&resp[x], bundle[x], BUNDLE_MAX);

        ilen[x] = MSG_MAX;
        ASSERT_EQ(gy_send_open(snd[x].c), GY_OK);
        ASSERT_EQ(gy_initiate(snd[x].c, RUID, 4, RDID, 4, bundle[x], blen[x],
                              (const uint8_t *)"hi", 2, NULL, init[x],
                              &ilen[x]),
                  GY_OK);
        ASSERT_EQ(gy_commit(snd[x].c), GY_OK);

        olen = sizeof(out);
        ASSERT_EQ(gy_receive(resp[x].c, SUID, 4, SDID, 4, init[x], ilen[x], out,
                             &olen),
                  GY_OK);
        ASSERT_TRUE(olen == 2 && memcmp(out, "hi", 2) == 0,
                    "diagonal plaintext round-trips");
    }

    /*
     * Phase 2: every off-diagonal cell must reject a cross-suite object, and
     * the two directions reject with DIFFERENT codes by design.  x is the wire
     * object's suite, y the presented-to custodian's suite; the
     * classical<->hybrid crossings cover the downgrade split both ways.
     *
     *   - Initiate (send path, not oracle-sensitive): the structural pre-crypto
     *     error is surfaced.  GY_ERR_STATE when the parser reaches the suite_id
     *     gate, or GY_ERR_ARG when it stops earlier at the length gate (no two
     *     suites share a bundle wire length, so a foreign bundle often
     *     mismatches the parser's expected length first).
     *   - Receive (oracle-sensitive): the UNIFORM anti-oracle failure
     *     GY_ERR_VERIFY (D-SES-6.2) - gy_receive never leaks WHY a message
     *     failed, so a cross-suite mismatch surfaces the same code as any other
     *     bad message.  Rejection still happens before crypto internally.
     *
     * The parse-seam test (proto/test_cross_suite_seam.c) pins the suite_id
     * gate itself, below this uniform-failure layer.
     */
    for (x = 0; x < NSUITES; x++) {
        for (y = 0; y < NSUITES; y++) {
            int rc;

            if (x == y)
                continue;

            /* Suite-x bundle presented to a suite-y initiator. */
            {
                static uint8_t msg[MSG_MAX];
                size_t mlen = sizeof(msg);

                ASSERT_EQ(gy_send_open(snd[y].c), GY_OK);
                rc = gy_initiate(snd[y].c, RUID, 4, RDID, 4, bundle[x], blen[x],
                                 (const uint8_t *)"x", 1, NULL, msg, &mlen);
                ASSERT_TRUE(rc == GY_ERR_STATE || rc == GY_ERR_ARG,
                            "foreign bundle rejected before crypto");
                gy_rollback(snd[y].c);
            }

            /* Suite-x initial message presented to a suite-y responder: the
             * uniform anti-oracle failure (D-SES-6.2). */
            olen = sizeof(out);
            rc = gy_receive(resp[y].c, SUID, 4, SDID, 4, init[x], ilen[x], out,
                            &olen);
            ASSERT_EQ(rc, GY_ERR_VERIFY);
        }
    }

    for (x = 0; x < NSUITES; x++) {
        party_down(&resp[x]);
        party_down(&snd[x]);
    }
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(cross_suite_matrix),
    };

    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
