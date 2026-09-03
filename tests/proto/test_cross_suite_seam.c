/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Cross-suite rejection at the parse SEAM (HYBRID_SPEC 11.3): the suite is
 * pinned per identity, never negotiated, with no hybrid-to-classical fallback.
 * The public-API matrix (tests/api/test_suite_matrix.c) proves the end-to-end
 * wiring; this pins the exact reject point at the parse functions themselves,
 * fast and independent of the API layer, across the full 4x4 of
 * {c25519, h25519_512, c448, h448_1024} including every classical<->hybrid
 * crossing.  Each wire object carries its suite at byte offset 1; the parser
 * for a given suite rejects a foreign suite_id with GY_ERR_STATE before any
 * body parsing:
 *   - gy_frame_check   : the initial-message / DR frame seam (suite-generic),
 *   - gy_bundle_parse / gy_hybrid_bundle_parse : the prekey-bundle seam.
 * A zero body suffices: the length and suite gates precede all content parsing,
 * so no key material is generated here.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h"
#include "envelope.h"
#include "prekeys.h"

#include "gy_test.h"

#define NSUITES 4

static const uint8_t g_suites[NSUITES] = {
    GY_SUITE_C25519,
    GY_SUITE_H25519_512,
    GY_SUITE_C448,
    GY_SUITE_H448_1024,
};

TEST(cross_suite_seam)
{
    /* Large enough to clear every suite's minimum bundle length, so each parser
     * reaches the suite gate instead of short-circuiting on length. */
    static uint8_t buf[16384];
    struct gy_prekey_bundle cb;
    struct gy_hybrid_prekey_bundle hb;
    int x, y;

    memset(buf, 0, sizeof(buf));
    buf[0] = GY_WIRE_VERSION;

    for (x = 0; x < NSUITES; x++) {
        buf[1] = g_suites[x]; /* the wire object's suite */
        for (y = 0; y < NSUITES; y++) {
            const struct gy_suite_desc *dy = gy_suite_desc(g_suites[y]);

            ASSERT_TRUE(dy != NULL, "suite descriptor present");

            /*
             * Initial-message / DR frame seam: the matching suite passes the
             * gate, every foreign suite (including the classical<->hybrid
             * crossings) is GY_ERR_STATE.
             */
            ASSERT_EQ(gy_frame_check(buf, sizeof(buf), g_suites[y]),
                      x == y ? GY_OK : GY_ERR_STATE);

            if (x == y)
                continue; /* a same-suite bundle passes the gate then fails
                           * deeper on the zero body: not this test's concern.
                           */

            /*
             * Bundle seam: the parser bound to suite y rejects a suite-x bundle
             * at the suite_id gate, before any body parsing.  The buffer must
             * carry suite y's expected wire length so the parser reaches the
             * suite gate rather than the length gate (gy_hybrid_bundle_parse
             * requires an EXACT length, gy_bundle_parse a minimum); the foreign
             * suite byte at offset 1 is then the discriminator.  Route to the
             * parser matching suite y's classical/hybrid shape.
             */
            if (dy->is_hybrid) {
                size_t wl = gy_hybrid_bundle_wire_len(dy);

                ASSERT_TRUE(wl <= sizeof(buf), "hybrid bundle fits buffer");
                ASSERT_EQ(gy_hybrid_bundle_parse(&hb, dy, buf, wl),
                          GY_ERR_STATE);
            } else {
                size_t wl = gy_bundle_wire_len(dy, 1);

                ASSERT_TRUE(wl <= sizeof(buf), "bundle fits buffer");
                ASSERT_EQ(gy_bundle_parse(&cb, dy, buf, wl), GY_ERR_STATE);
            }
        }
    }
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(cross_suite_seam),
    };

    if (gy_core_init() != GY_OK)
        return 1;
    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
