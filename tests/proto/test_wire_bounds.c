/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The public wire-buffer bounds (include/geryon.h) must never be smaller than
 * the actual wire size a caller can encounter, for every suite in each family.
 * The bundle/cert/OPK sizes come from runtime wire_len functions (so this is a
 * test, not a _Static_assert like the store bounds), and the per-message
 * overhead comes from the envelope + handshake/DR-header + AEAD-tag maxima.
 * If a wire formula ever outgrows its public bound this test fails, so the
 * public constant is bumped deliberately rather than silently overflowing a
 * caller that trusted it.
 */

#include <stdint.h>
#include <stdio.h>

#include "geryon.h"

#include "double_ratchet.h"
#include "envelope.h"
#include "hybrid_double_ratchet.h"
#include "x3dh.h"

#include "gy_test.h"

/* Per-OPK wire cost = the growth of a published batch from n=0 to n=1. */
static size_t
classical_opk_wire(const struct gy_suite_desc *d)
{
    return gy_opk_batch_wire_len(d, 1) - gy_opk_batch_wire_len(d, 0);
}

static size_t
hybrid_opk_wire(const struct gy_suite_desc *d)
{
    return gy_hybrid_opk_batch_wire_len(d, 1) -
           gy_hybrid_opk_batch_wire_len(d, 0);
}

TEST(wire_bounds_cover_every_suite)
{
    static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_H25519_512,
                                     GY_SUITE_C448, GY_SUITE_H448_1024};
    size_t s;

    for (s = 0; s < sizeof(suites) / sizeof(suites[0]); s++) {
        const struct gy_suite_desc *d = gy_suite_desc(suites[s]);

        ASSERT_TRUE(d != NULL, "suite descriptor present");
        printf("== suite %s ==\n", d->name);

        if (d->is_hybrid) {
            ASSERT_TRUE(gy_hybrid_bundle_wire_len(d) <= GY_BUNDLE_MAX_HYBRID,
                        "hybrid bundle within bound");
            ASSERT_TRUE(gy_hybrid_appkey_cert_wire_len(d) <=
                            GY_APPKEY_CERT_MAX_HYBRID,
                        "hybrid appkey cert within bound");
            ASSERT_TRUE(hybrid_opk_wire(d) <= GY_OPK_WIRE_MAX_HYBRID,
                        "hybrid per-OPK within bound");
            ASSERT_TRUE((size_t)(GY_ENVELOPE_HDR_LEN +
                                 GY_HYBRID_X3DH_PREFIX_MAX + GY_AEAD_MAX_TAG) <=
                            GY_MESSAGE_OVERHEAD_MAX_HYBRID,
                        "hybrid initial-message overhead within bound");
            ASSERT_TRUE((size_t)(GY_ENVELOPE_HDR_LEN +
                                 GY_DR_HYBRID_HDR_WIRE_MAX + GY_AEAD_MAX_TAG) <=
                            GY_MESSAGE_OVERHEAD_MAX_HYBRID,
                        "hybrid DR-message overhead within bound");
            ASSERT_TRUE(d->sig_len + d->dsa_sig_len + 64 <=
                            GY_APPKEY_SIG_MAX_HYBRID,
                        "hybrid request signature within bound");
        } else {
            ASSERT_TRUE(gy_bundle_wire_len(d, 1) <= GY_BUNDLE_MAX_CLASSICAL,
                        "classical bundle within bound");
            ASSERT_TRUE(gy_appkey_cert_wire_len(d) <=
                            GY_APPKEY_CERT_MAX_CLASSICAL,
                        "classical appkey cert within bound");
            ASSERT_TRUE(classical_opk_wire(d) <= GY_OPK_WIRE_MAX_CLASSICAL,
                        "classical per-OPK within bound");
            ASSERT_TRUE((size_t)(GY_ENVELOPE_HDR_LEN + GY_X3DH_PREFIX_MAX +
                                 GY_AEAD_MAX_TAG) <=
                            GY_MESSAGE_OVERHEAD_MAX_CLASSICAL,
                        "classical initial-message overhead within bound");
            ASSERT_TRUE((size_t)(GY_ENVELOPE_HDR_LEN + GY_DR_HDR_WIRE_MAX +
                                 GY_AEAD_MAX_TAG) <=
                            GY_MESSAGE_OVERHEAD_MAX_CLASSICAL,
                        "classical DR-message overhead within bound");
            ASSERT_TRUE(d->sig_len + d->dsa_sig_len + 64 <=
                            GY_APPKEY_SIG_MAX_CLASSICAL,
                        "classical request signature within bound");
        }
    }
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(wire_bounds_cover_every_suite),
    };

    if (gy_core_init() != GY_OK)
        return 1;
    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
