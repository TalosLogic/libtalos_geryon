/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen byte KATs for the QSPGS key hierarchy, both tiers.
 * Reproducible from fixed muk / gk / ep / UID; the derivations are pure tier
 * HKDF, so the bytes are portable across backends and machines.
 *
 * Two modes:
 *   (default)  self-check the derivations against the committed vectors
 *              (qspgs_keys_kat.h); SKIP (exit 77) while UNPOPULATED.
 *   --dump     emit a populated qspgs_keys_kat.h on stdout, to capture the
 *              vectors once on a trusted build (see that header).
 *
 * Fixed inputs (this file is their sole definition): muk[i] = 0x40 + i,
 * gk[i] = 0x50 + i (over the tier's 2*kappa width), ep = 7, UID = 00..0f.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "qspgs_keys.h"
#include "util.h"

#include "gy_test.h"
#include "qspgs_keys_kat.h"

#define KAT_EP 7

static const uint8_t kat_uid[16] = {0, 1, 2,  3,  4,  5,  6,  7,
                                    8, 9, 10, 11, 12, 13, 14, 15};

/* All derived outputs for one tier. */
struct kat_out {
    uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t acq[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t exp[GY_QSPGS_EXPKEY_BYTES];
    uint8_t ek[GY_QSPGS_EK_BYTES];
    uint8_t rrs[GY_QSPGS_RRS_BYTES];
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    uint8_t fet[GY_QSPGS_FET_BYTES];   /* section 6.5 fetch token. */
    uint8_t send[GY_QSPGS_SEND_BYTES]; /* section 6.5 send token. */
    size_t mk;
};

static int
kat_compute(uint8_t suite, struct kat_out *o)
{
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], gk[GY_QSPGS_MASTER_KEY_MAX];
    size_t i;
    int rc;

    o->mk = gy_qspgs_master_key_len(suite);
    if (o->mk == 0)
        return GY_ERR_ARG;
    for (i = 0; i < o->mk; i++) {
        muk[i] = (uint8_t)(0x40 + i);
        gk[i] = (uint8_t)(0x50 + i);
    }

    rc = gy_qspgs_derive_uk(suite, muk, KAT_EP, o->uk);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_acq(suite, o->uk, o->acq);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_exp_key(suite, o->uk, o->exp);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_sub_key(suite, gk, o->ek, o->rrs);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_rho(suite, o->rrs, kat_uid, sizeof(kat_uid),
                                 o->rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_fet(suite, gk, o->fet);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_send(suite, gk, o->send);
    return rc;
}

static void
emit_hex(const char *name, const uint8_t *b, size_t n)
{
    size_t i;

    printf("#define %s \"", name);
    for (i = 0; i < n; i++)
        printf("%02x", b[i]);
    printf("\"\n");
}

#define GEN(set, suite)                                                        \
    static void kat##set##_check(void)                                         \
    {                                                                          \
        struct kat_out o;                                                      \
        uint8_t e[GY_QSPGS_RHO_BYTES];                                         \
        ASSERT_EQ(kat_compute(suite, &o), GY_OK);                              \
        ASSERT_TRUE(gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_UK) ==         \
                        (int)o.mk,                                             \
                    "uk vector width");                                        \
        ASSERT_MEMEQ(o.uk, e, o.mk);                                           \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_ACQ);                      \
        ASSERT_MEMEQ(o.acq, e, o.mk);                                          \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_EXP);                      \
        ASSERT_MEMEQ(o.exp, e, sizeof(o.exp));                                 \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_EK);                       \
        ASSERT_MEMEQ(o.ek, e, sizeof(o.ek));                                   \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_RRS);                      \
        ASSERT_MEMEQ(o.rrs, e, sizeof(o.rrs));                                 \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_RHO);                      \
        ASSERT_MEMEQ(o.rho, e, sizeof(o.rho));                                 \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_FET);                      \
        ASSERT_MEMEQ(o.fet, e, sizeof(o.fet));                                 \
        gy_hex_decode(e, sizeof(e), GY_Q##set##_KAT_SEND);                     \
        ASSERT_MEMEQ(o.send, e, sizeof(o.send));                               \
    }                                                                          \
                                                                               \
    static void kat##set##_dump(void)                                          \
    {                                                                          \
        struct kat_out o;                                                      \
        if (kat_compute(suite, &o) != GY_OK) {                                 \
            fprintf(stderr, "compute " #set " failed\n");                      \
            return;                                                            \
        }                                                                      \
        emit_hex("GY_Q" #set "_KAT_UK", o.uk, o.mk);                           \
        emit_hex("GY_Q" #set "_KAT_ACQ", o.acq, o.mk);                         \
        emit_hex("GY_Q" #set "_KAT_EXP", o.exp, sizeof(o.exp));                \
        emit_hex("GY_Q" #set "_KAT_EK", o.ek, sizeof(o.ek));                   \
        emit_hex("GY_Q" #set "_KAT_RRS", o.rrs, sizeof(o.rrs));                \
        emit_hex("GY_Q" #set "_KAT_RHO", o.rho, sizeof(o.rho));                \
        emit_hex("GY_Q" #set "_KAT_FET", o.fet, sizeof(o.fet));                \
        emit_hex("GY_Q" #set "_KAT_SEND", o.send, sizeof(o.send));             \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)

static void
dump_header(void)
{
    printf("/*\n"
           " * Copyright (c) 2026 Jason Crawford\n"
           " * SPDX-License-Identifier: AGPL-3.0-only\n"
           " *\n"
           " * QSPGS key-hierarchy KAT vectors, self-generated (D-QGS-10).\n"
           " * FROZEN 2026-09-16 (v1.5.0 close-out): pinned to geryon's\n"
           " * reading of the [CFG+] 2026/453 preprint; no longer regenerated\n"
           " * on refactor.  A re-cut is a deliberate D-QGS-12 format_version\n"
           " * event.\n"
           " */\n\n");
    printf("#ifndef GY_QSPGS_KEYS_KAT_H\n#define GY_QSPGS_KEYS_KAT_H\n\n");
    printf("#define QSPGS_KEYS_KAT_POPULATED 1\n\n");
    kat44_dump();
    printf("\n");
    kat87_dump();
    printf("\n#endif /* GY_QSPGS_KEYS_KAT_H */\n");
}

int
main(int argc, char **argv)
{
    if (gy_core_init() != GY_OK)
        return 1;

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        dump_header();
        return 0;
    }

    if (!QSPGS_KEYS_KAT_POPULATED)
        return 77; /* CTest SKIP until the vectors are captured. */

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(kat44_check),
            GY_TEST(kat87_check),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
