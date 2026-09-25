/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen byte KATs for the QSPGS group-structure wire,
 * both tiers.  The captured bytes are the DETERMINISTIC ones: the C_UID
 * commitment, the H(vkpsdn) list hash, and the canonical core to-be-signed
 * string (which embeds the header, member-list, and vk-lst object encodings and
 * the versions).  The signatures over the TBS are randomized (production
 * ML-DSA) and are covered by the sign/verify round-trip tests, not here.
 *
 * Two modes:
 *   (default)  self-check against the committed vectors (qspgs_wire_kat.h);
 *              SKIP (exit 77) while UNPOPULATED.
 *   --dump     emit a populated qspgs_wire_kat.h on stdout.
 *
 * Fixed inputs (this file is their sole definition): base-pair seed 0x11*32,
 * rrs 0x24*32, UID = w_uid_a (0xa0..0xaf), r_c = 0x1a*32, GID = 0x77*16, vMaj
 * = 5, sa_ct = 0x3c*8, one admin member with mct = 0x2a*16, a one-entry
 * vk-lst = H(vkpsdn), signer_index = 0, last_vMin = 3.
 *
 * NOTE (SEC-v1.5.0 LOW-1, INFO-6): the header object changed twice, so the
 * committed GY_QW*_KAT_TBS vectors in qspgs_wire_kat.h MUST be regenerated with
 * --dump.  LOW-1 removed fet from the header; INFO-6 added the pinned aead_id
 * byte after format_version.  Both shift the header encoding and hence the TBS
 * that embeds it.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aead.h"   /* GY_AEAD_CHACHA20POLY1305 (pinned group AEAD, INFO-6) */
#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "qspgs_keys.h"
#include "qspgs_wire.h"
#include "suite.h"
#include "util.h"

#include "gy_test.h"
#include "qspgs_wire_kat.h"

static const uint8_t kat_uid[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
                                    0xac, 0xad, 0xae, 0xaf};

struct wkat_out {
    size_t hlen;
    uint8_t cuid[GY_QSPGS_HASH_MAX];
    uint8_t vkhash[GY_QSPGS_HASH_MAX];
    uint8_t tbs[4096];
    size_t tbslen;
};

static int
wkat_compute(uint8_t suite, struct wkat_out *o)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite);
    uint8_t base_seed[32], rrs[32], rc_open[GY_QSPGS_RC_LEN];
    uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];
    uint8_t vkr[GY_QSPGS_VKR_MAX], rho[GY_QSPGS_RHO_BYTES];
    uint8_t sa_ct[8], mct[16];
    struct gy_qspgs_member mem[1];
    struct gy_qspgs_core core;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    o->hlen = desc->hash_len;
    memset(base_seed, 0x11, sizeof(base_seed));
    memset(rrs, 0x24, sizeof(rrs));
    memset(rc_open, 0x1a, sizeof(rc_open));
    memset(sa_ct, 0x3c, sizeof(sa_ct));
    memset(mct, 0x2a, sizeof(mct));

    rc = gy_qspgs_base_keygen_seed(suite, vkb, skb, base_seed);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_rho(suite, rrs, kat_uid, sizeof(kat_uid), rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho);
    if (rc == GY_OK)
        rc = gy_qspgs_vkpsdn_hash(suite, vkr, o->vkhash);
    if (rc == GY_OK)
        rc = gy_qspgs_cuid_commit(suite, kat_uid, sizeof(kat_uid), rc_open,
                                  o->cuid);
    if (rc != GY_OK)
        return rc;

    memset(&core, 0, sizeof(core));
    core.suite_id = suite;
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    core.aead_id = GY_AEAD_CHACHA20POLY1305;
    memset(core.gid, 0x77, sizeof(core.gid));
    core.vmaj = 5;
    memset(core.fet, 0x66, sizeof(core.fet));
    core.sa_ct = sa_ct;
    core.sa_ct_len = sizeof(sa_ct);
    core.last_vmin = 3;
    memset(mem, 0, sizeof(mem));
    memcpy(mem[0].cuid, o->cuid, o->hlen);
    mem[0].admn = 1;
    mem[0].mct = mct;
    mem[0].mct_len = sizeof(mct);
    core.members = mem;
    core.n_members = 1;
    core.vkhash = o->vkhash;
    core.n_vk = 1;

    return gy_qspgs_core_tbs(&core, 0, o->tbs, sizeof(o->tbs), &o->tbslen);
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
    static void wkat##set##_check(void)                                        \
    {                                                                          \
        struct wkat_out o;                                                     \
        uint8_t e[4096];                                                       \
        int el;                                                                \
        ASSERT_EQ(wkat_compute(suite, &o), GY_OK);                             \
        el = gy_hex_decode(e, sizeof(e), GY_QW##set##_KAT_CUID);               \
        ASSERT_TRUE(el == (int)o.hlen, "cuid vector width");                   \
        ASSERT_MEMEQ(o.cuid, e, o.hlen);                                       \
        el = gy_hex_decode(e, sizeof(e), GY_QW##set##_KAT_VKHASH);             \
        ASSERT_TRUE(el == (int)o.hlen, "vkhash vector width");                 \
        ASSERT_MEMEQ(o.vkhash, e, o.hlen);                                     \
        el = gy_hex_decode(e, sizeof(e), GY_QW##set##_KAT_TBS);                \
        ASSERT_TRUE(el == (int)o.tbslen, "tbs vector width");                  \
        ASSERT_MEMEQ(o.tbs, e, o.tbslen);                                      \
    }                                                                          \
                                                                               \
    static void wkat##set##_dump(void)                                         \
    {                                                                          \
        struct wkat_out o;                                                     \
        if (wkat_compute(suite, &o) != GY_OK) {                                \
            fprintf(stderr, "compute " #set " failed\n");                      \
            return;                                                            \
        }                                                                      \
        emit_hex("GY_QW" #set "_KAT_CUID", o.cuid, o.hlen);                    \
        emit_hex("GY_QW" #set "_KAT_VKHASH", o.vkhash, o.hlen);                \
        emit_hex("GY_QW" #set "_KAT_TBS", o.tbs, o.tbslen);                    \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)

/*
 * Appendix-line TBS (section 4 item 5).  Suite-INDEPENDENT: the canonical bytes
 * are apx-hdr GID(16) || vMaj(BE32) || vMin(BE32) || line_type(1) ||
 * author_index(BE32) || payload, with no tier hash, so one vector covers both
 * tiers.  The apx-hdr binds the line to its group and version (D-QGS-13 E1).
 * Fixed input: a 16-byte GID, vMaj = 2, vMin = 5, line_type = REFRESH,
 * author_index = 3, a 12-byte fixed payload standing in for the ek ciphertext.
 */
#define KAT_APX_LINE GY_QAPX_REFRESH
#define KAT_APX_AUTHOR 3
#define KAT_APX_VMAJ 2
#define KAT_APX_VMIN 5
static const uint8_t kat_apx_gid[GY_QSPGS_GID_LEN] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
static const uint8_t kat_apx_payload[12] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                                            0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb};

static void
apx_tbs_check(void)
{
    uint8_t tbs[64], e[64];
    size_t tl;
    int el;

    ASSERT_EQ(gy_qspgs_apx_line_tbs(kat_apx_gid, KAT_APX_VMAJ, KAT_APX_VMIN,
                                    KAT_APX_LINE, KAT_APX_AUTHOR,
                                    kat_apx_payload, sizeof(kat_apx_payload),
                                    tbs, sizeof(tbs), &tl),
              GY_OK);
    el = gy_hex_decode(e, sizeof(e), GY_QW_KAT_APX_TBS);
    ASSERT_TRUE(el == (int)tl, "apx tbs vector width");
    ASSERT_MEMEQ(tbs, e, tl);
}

static void
apx_tbs_dump(void)
{
    uint8_t tbs[64];
    size_t tl;

    if (gy_qspgs_apx_line_tbs(kat_apx_gid, KAT_APX_VMAJ, KAT_APX_VMIN,
                              KAT_APX_LINE, KAT_APX_AUTHOR, kat_apx_payload,
                              sizeof(kat_apx_payload), tbs, sizeof(tbs),
                              &tl) != GY_OK) {
        fprintf(stderr, "apx tbs failed\n");
        return;
    }
    emit_hex("GY_QW_KAT_APX_TBS", tbs, tl);
}

static void
dump_header(void)
{
    printf("/*\n"
           " * Copyright (c) 2026 Jason Crawford\n"
           " * SPDX-License-Identifier: AGPL-3.0-only\n"
           " *\n"
           " * QSPGS group-structure wire KAT vectors, self-generated\n"
           " * (D-QGS-10).  RE-CUT 2026-09-16 for D-QGS-13 E1: the "
           "appendix-line\n"
           " * TBS now binds the apx-hdr (GID || vMaj || vMin) ahead of the "
           "line,\n"
           " * so GY_QW_KAT_APX_TBS was deliberately regenerated at\n"
           " * format_version 1 (v1.5.0 is untagged; nothing consumed the old\n"
           " * bytes).  Otherwise pinned to geryon's reading of the [CFG+]\n"
           " * 2026/453 preprint; not regenerated on refactor.  A further "
           "re-cut\n"
           " * is a deliberate D-QGS-12 format_version event.\n"
           " */\n\n");
    printf("#ifndef GY_QSPGS_WIRE_KAT_H\n#define GY_QSPGS_WIRE_KAT_H\n\n");
    printf("#define QSPGS_WIRE_KAT_POPULATED 1\n\n");
    wkat44_dump();
    printf("\n");
    wkat87_dump();
    printf("\n");
    apx_tbs_dump();
    printf("\n#endif /* GY_QSPGS_WIRE_KAT_H */\n");
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

    if (!QSPGS_WIRE_KAT_POPULATED)
        return 77; /* CTest SKIP until the vectors are captured. */

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(wkat44_check),
            GY_TEST(wkat87_check),
            GY_TEST(apx_tbs_check),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
