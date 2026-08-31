/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * 448 gf-smoke unit: prove a GERYON-side translation unit can include
 * libdecaf's INTERNAL gf field header (src/include/field.h -> the generated
 * p448 f_field.h + arch f_impl.h) via GERYON_DECAF448_INTERNAL_INCLUDES and
 * link a non-inline field body (gf_mul, gf_serialize) from the geryon-owned
 * decaf448 archive. This is the exact mechanism src/core/ed448.c
 * (D-XED-13 approach #3) uses; it de-risks that work and
 * verifies the internal include wiring without waiting for the XEd448 code.
 *
 * The internal gf API is macro-mapped for p448: gf == gf_448_t, ONE/ZERO are
 * file-local constants from f_field.h, gf_mul(out, a, b) and
 * gf_serialize(bytes, x) link from decaf448. 1 * 1 serializes to 0x01 || 0*55.
 */

#include <stdint.h>

/*
 * field.h (via word.h) sets __STDC_WANT_LIB_EXT1__ to 1, which macOS needs
 * before <string.h> to declare memset_s (word.h really_memset calls it).  So
 * field.h precedes <string.h> here; we do not set the macro ourselves (that
 * would redefine word.h's under -Werror).  Harmless where Annex K is absent.
 */
#include "field.h"

#include <string.h>

#include "gy_test.h"

TEST(decaf448_gf_mul_links_and_computes)
{
    gf r;
    uint8_t out[SER_BYTES];
    uint8_t want[SER_BYTES];

    gf_mul(r, ONE, ONE);
    gf_serialize(out, r);

    memset(want, 0, sizeof want);
    want[0] = 1;
    ASSERT_MEMEQ(out, want, (int)SER_BYTES);
}

int
main(void)
{
    static const struct gy_test_case cases[] = {
        GY_TEST(decaf448_gf_mul_links_and_computes),
    };
    return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
}
