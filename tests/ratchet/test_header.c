/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/ratchet/header.c (D-DR-5).
 */

#include <stdint.h>
#include <string.h>

#include "header.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;

TEST(round_trip_and_wire_size)
{
    struct gy_dr_header h, g;
    uint8_t buf[GY_DR_HEADER_MAX];
    size_t outlen, consumed;

    memset(&h, 0, sizeof(h));
    h.flags = D->curve_type;
    memset(h.ratchet_pk, 0xa5, D->curve_pk_len);
    h.pn = 0x01020304;
    h.n = 0x0a0b0c0d;

    ASSERT_EQ(gy_dr_header_encode(D, &h, buf, sizeof(buf), &outlen), GY_OK);
    /* Classical wire size: flags(4) + curve_pk(32) + pn(4) + n(4) = 44. */
    ASSERT_EQ(outlen, 4 + D->curve_pk_len + 8);
    ASSERT_TRUE(outlen <= GY_DR_HEADER_MAX, "fits max");

    ASSERT_EQ(gy_dr_header_decode(D, &g, buf, outlen, &consumed), GY_OK);
    ASSERT_EQ(consumed, outlen);
    ASSERT_EQ(g.flags, h.flags);
    ASSERT_EQ(g.pn, h.pn);
    ASSERT_EQ(g.n, h.n);
    ASSERT_MEMEQ(g.ratchet_pk, h.ratchet_pk, D->curve_pk_len);
}

TEST(flag_and_suite_checks)
{
    struct gy_dr_header h, g;
    uint8_t buf[GY_DR_HEADER_MAX];
    size_t outlen, consumed;

    memset(&h, 0, sizeof(h));
    h.flags = D->curve_type;
    memset(h.ratchet_pk, 0x11, D->curve_pk_len);
    ASSERT_EQ(gy_dr_header_encode(D, &h, buf, sizeof(buf), &outlen), GY_OK);

    /* Wrong curve_type in the low byte is a cross-suite abort (pick a type that
     * differs from the running suite so this holds at both tiers). */
    buf[3] = (D->curve_type == GY_CURVE_TYPE_448) ? GY_CURVE_TYPE_25519
                                                  : GY_CURVE_TYPE_448;
    ASSERT_EQ(gy_dr_header_decode(D, &g, buf, outlen, &consumed), GY_ERR_STATE);

    /* A reserved / HE flag bit set is rejected (must be zero on the wire). */
    gy_be32_put(buf, D->curve_type | GY_DR_FLAG_MLKEM_EK_PRESENT);
    ASSERT_EQ(gy_dr_header_decode(D, &g, buf, outlen, &consumed), GY_ERR_ARG);
    gy_be32_put(buf, D->curve_type | (1u << 10));
    ASSERT_EQ(gy_dr_header_decode(D, &g, buf, outlen, &consumed), GY_ERR_ARG);
}

TEST(bounds)
{
    struct gy_dr_header h, g;
    uint8_t buf[GY_DR_HEADER_MAX];
    size_t outlen, consumed;

    memset(&h, 0, sizeof(h));
    h.flags = D->curve_type;

    /* Encode into a too-small buffer and decode a truncated one both reject. */
    ASSERT_EQ(gy_dr_header_encode(D, &h, buf, 4 + D->curve_pk_len + 7, &outlen),
              GY_ERR_ARG);
    ASSERT_EQ(gy_dr_header_encode(D, &h, buf, sizeof(buf), &outlen), GY_OK);
    ASSERT_EQ(gy_dr_header_decode(D, &g, buf, outlen - 1, &consumed),
              GY_ERR_ARG);
}

int
main(void)
{
    /* Every case is descriptor-driven (D->curve_pk_len), so the
     * header vertical runs unchanged under both classical suites. */
    static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};
    static const struct gy_test_case cases[] = {
        GY_TEST(round_trip_and_wire_size),
        GY_TEST(flag_and_suite_checks),
        GY_TEST(bounds),
    };
    size_t s;
    int rc = 0;

    if (gy_core_init() != GY_OK)
        return 1;
    for (s = 0; s < sizeof(suites) / sizeof(suites[0]); s++) {
        D = gy_suite_desc(suites[s]);
        if (D == NULL)
            return 1;
        printf("== suite %s ==\n", D->name);
        rc |= gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
    return rc;
}
