/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * QSPGS group data structure wire tests, both tiers.
 *
 * Covered per suite (GEN macro keeps the tiers in lockstep):
 *   - header / member-list / vk-lst encode -> decode round-trips (fields and
 *     opaque blobs preserved), and decode is strict (trailing byte rejected);
 *   - the C_UID commitment and H(vkpsdn) helpers are deterministic and the
 *     vk-hash resolution accepts the right vkr and rejects a wrong one;
 *   - the admin core signature over the canonical TBS verifies with a REAL
 *     skpsdn (RandSK) / vkpsdn (RandVK) pair from the key hierarchy, and
 *     a single-field tamper (a member cuid) is rejected;
 *   - the core-signature object round-trips;
 *   - the appendix object round-trips, each line's author signature verifies
 *     with a real skpsdn, and a payload tamper is rejected;
 *   - the invite queue round-trips and a decoded entry still opens through the
 *     join PKE (framing preserves the opaque ciphertext).
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "qspgs_join.h"
#include "qspgs_keys.h"
#include "qspgs_labels.h"
#include "qspgs_wire.h"
#include "suite.h"
#include "util.h"

#include "gy_test.h"

static const uint8_t w_uid_a[16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5,
                                    0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab,
                                    0xac, 0xad, 0xae, 0xaf};
static const uint8_t w_uid_b[16] = {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
                                    0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb,
                                    0xbc, 0xbd, 0xbe, 0xbf};

#define GEN(set, suite)                                                             \
    TEST(q##set##_wire_core_roundtrip)                                              \
    {                                                                               \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                       \
        size_t hlen = d->hash_len;                                                  \
        uint8_t rc_a[GY_QSPGS_RC_LEN], rc_b[GY_QSPGS_RC_LEN];                       \
        uint8_t mct_a[24], mct_b[24];                                               \
        uint8_t sa_ct[40];                                                          \
        uint8_t vkhash[2 * GY_QSPGS_HASH_MAX];                                      \
        struct gy_qspgs_member mem[2];                                              \
        struct gy_qspgs_core core;                                                  \
        uint8_t buf[512];                                                           \
        size_t n;                                                                   \
        memset(&core, 0, sizeof(core));                                             \
        memset(rc_a, 0x1a, sizeof(rc_a));                                           \
        memset(rc_b, 0x1b, sizeof(rc_b));                                           \
        memset(mct_a, 0x2a, sizeof(mct_a));                                         \
        memset(mct_b, 0x2b, sizeof(mct_b));                                         \
        memset(sa_ct, 0x3c, sizeof(sa_ct));                                         \
                                                                                    \
        core.suite_id = suite;                                                      \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                              \
        memset(core.gid, 0x77, sizeof(core.gid));                                   \
        core.vmaj = 5;                                                              \
        memset(core.fet, 0x66, sizeof(core.fet));                                   \
        core.sa_ct = sa_ct;                                                         \
        core.sa_ct_len = sizeof(sa_ct);                                             \
        core.last_vmin = 3;                                                         \
                                                                                    \
        memset(mem, 0, sizeof(mem));                                                \
        ASSERT_EQ(gy_qspgs_cuid_commit(suite, w_uid_a, 16, rc_a, mem[0].cuid),      \
                  GY_OK);                                                           \
        mem[0].admn = 1;                                                            \
        mem[0].mct = mct_a;                                                         \
        mem[0].mct_len = sizeof(mct_a);                                             \
        ASSERT_EQ(gy_qspgs_cuid_commit(suite, w_uid_b, 16, rc_b, mem[1].cuid),      \
                  GY_OK);                                                           \
        mem[1].admn = 0;                                                            \
        mem[1].mct = mct_b;                                                         \
        mem[1].mct_len = sizeof(mct_b);                                             \
        core.members = mem;                                                         \
        core.n_members = 2;                                                         \
                                                                                    \
        /* Two placeholder vk-lst hashes (packed hlen each). */                     \
        memset(vkhash, 0x5e, sizeof(vkhash));                                       \
        core.vkhash = vkhash;                                                       \
        core.n_vk = 2;                                                              \
                                                                                    \
        /* Header round-trip. */                                                    \
        ASSERT_EQ(gy_qspgs_header_encode(&core, buf, sizeof(buf), &n), GY_OK);      \
        {                                                                           \
            struct gy_qspgs_core dec;                                               \
            size_t consumed;                                                        \
            memset(&dec, 0, sizeof(dec));                                           \
            dec.suite_id = suite;                                                   \
            ASSERT_EQ(gy_qspgs_header_decode(&dec, buf, n, &consumed), GY_OK);      \
            ASSERT_EQ(consumed, n);                                                 \
            ASSERT_MEMEQ(dec.gid, core.gid, sizeof(core.gid));                      \
            ASSERT_EQ(dec.vmaj, core.vmaj);                                         \
            ASSERT_EQ(dec.format_version, core.format_version);                     \
            /* SEC-v1.5.0 LOW-1: fet is no longer carried in the header. */         \
            ASSERT_EQ(dec.sa_ct_len, core.sa_ct_len);                               \
            ASSERT_MEMEQ(dec.sa_ct, sa_ct, sizeof(sa_ct));                          \
            ASSERT_EQ(dec.join_ct_len, (size_t)0);                                  \
            /* Strict: a trailing byte breaks decode. */                            \
            ASSERT_EQ(gy_qspgs_header_decode(&dec, buf, n + 1, &consumed),          \
                      GY_ERR_VERIFY);                                               \
            /* Format epoch outside [MIN, MAX] is refused (0 < MIN). */             \
            buf[GY_QSPGS_OBJ_HDR_LEN + GY_QSPGS_GID_LEN] = 0;                       \
            buf[GY_QSPGS_OBJ_HDR_LEN + GY_QSPGS_GID_LEN + 1] = 0;                   \
            ASSERT_EQ(gy_qspgs_header_decode(&dec, buf, n, &consumed),              \
                      GY_ERR_UNSUPPORTED);                                          \
        }                                                                           \
                                                                                    \
        /* Member-list round-trip. */                                               \
        ASSERT_EQ(gy_qspgs_member_list_encode(&core, buf, sizeof(buf), &n),         \
                  GY_OK);                                                           \
        {                                                                           \
            struct gy_qspgs_core dec;                                               \
            struct gy_qspgs_member out[4];                                          \
            size_t consumed;                                                        \
            memset(&dec, 0, sizeof(dec));                                           \
            dec.suite_id = suite;                                                   \
            ASSERT_EQ(                                                              \
                gy_qspgs_member_list_decode(&dec, out, 4, buf, n, &consumed),       \
                GY_OK);                                                             \
            ASSERT_EQ(dec.n_members, (size_t)2);                                    \
            ASSERT_MEMEQ(out[0].cuid, mem[0].cuid, hlen);                           \
            ASSERT_EQ(out[0].admn, (uint8_t)1);                                     \
            ASSERT_EQ(out[0].mct_len, sizeof(mct_a));                               \
            ASSERT_MEMEQ(out[0].mct, mct_a, sizeof(mct_a));                         \
            ASSERT_EQ(out[1].admn, (uint8_t)0);                                     \
            ASSERT_MEMEQ(out[1].mct, mct_b, sizeof(mct_b));                         \
        }                                                                           \
                                                                                    \
        /* vk-lst round-trip. */                                                    \
        ASSERT_EQ(gy_qspgs_vk_lst_encode(&core, buf, sizeof(buf), &n), GY_OK);      \
        {                                                                           \
            struct gy_qspgs_core dec;                                               \
            size_t consumed;                                                        \
            memset(&dec, 0, sizeof(dec));                                           \
            dec.suite_id = suite;                                                   \
            ASSERT_EQ(gy_qspgs_vk_lst_decode(&dec, buf, n, &consumed), GY_OK);      \
            ASSERT_EQ(dec.n_vk, (size_t)2);                                         \
            ASSERT_MEMEQ(dec.vkhash, vkhash, 2 * hlen);                             \
        }                                                                           \
    }                                                                               \
                                                                                    \
    TEST(q##set##_wire_vkhash_resolution)                                           \
    {                                                                               \
        uint8_t seed[32], rho[GY_QSPGS_RHO_BYTES];                                  \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                       \
        uint8_t vkr[GY_QSPGS_VKR_MAX], vkr_other[GY_QSPGS_VKR_MAX];                 \
        uint8_t h1[GY_QSPGS_HASH_MAX], h2[GY_QSPGS_HASH_MAX];                       \
        memset(seed, 0x24, sizeof(seed));                                           \
                                                                                    \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, w_uid_a, 16, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);            \
                                                                                    \
        /* Deterministic, and resolution accepts the right vkr. */                  \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, vkr, h1), GY_OK);                     \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, vkr, h2), GY_OK);                     \
        ASSERT_MEMEQ(h1, h2, gy_suite_desc(suite)->hash_len);                       \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash_check(suite, vkr, h1), GY_OK);               \
                                                                                    \
        /* A different pseudonym key does not resolve to the stored hash. */        \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, w_uid_b, 16, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr_other, vkb, rho), GY_OK);      \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash_check(suite, vkr_other, h1),                 \
                  GY_ERR_VERIFY);                                                   \
    }                                                                               \
                                                                                    \
    TEST(q##set##_wire_core_signature)                                              \
    {                                                                               \
        static const uint8_t ctx[] = GY_QSPGS_CTX_CORE;                             \
        uint8_t seed[32], rho[GY_QSPGS_RHO_BYTES];                                  \
        uint8_t rc_a[GY_QSPGS_RC_LEN];                                              \
        uint8_t mct_a[24];                                                          \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                       \
        uint8_t vkr[GY_QSPGS_VKR_MAX];                                              \
        uint8_t vkhash[GY_QSPGS_HASH_MAX];                                          \
        uint8_t sig[GY_KR##set##_SIG];                                              \
        uint8_t scratch[4096], sigbuf[GY_QSPGS_SIG_MAX + 32];                       \
        struct gy_qspgs_member mem[1];                                              \
        struct gy_qspgs_core core;                                                  \
        gy_qspgs_psdn_sk_t sk;                                                      \
        size_t tbslen, n;                                                           \
        memset(seed, 0x31, sizeof(seed));                                           \
        memset(rc_a, 0x41, sizeof(rc_a));                                           \
        memset(mct_a, 0x42, sizeof(mct_a));                                         \
                                                                                    \
        /* A real base pair + pseudonym key for the (single, admin) signer. */      \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, w_uid_a, 16, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);            \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, vkr, vkhash), GY_OK);                 \
                                                                                    \
        memset(&core, 0, sizeof(core));                                             \
        core.suite_id = suite;                                                      \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                              \
        memset(core.gid, 0x09, sizeof(core.gid));                                   \
        core.vmaj = 1;                                                              \
        memset(core.fet, 0x08, sizeof(core.fet));                                   \
        core.last_vmin = 0;                                                         \
        memset(mem, 0, sizeof(mem));                                                \
        ASSERT_EQ(gy_qspgs_cuid_commit(suite, w_uid_a, 16, rc_a, mem[0].cuid),      \
                  GY_OK);                                                           \
        mem[0].admn = 1;                                                            \
        mem[0].mct = mct_a;                                                         \
        mem[0].mct_len = sizeof(mct_a);                                             \
        core.members = mem;                                                         \
        core.n_members = 1;                                                         \
        core.vkhash = vkhash;                                                       \
        core.n_vk = 1;                                                              \
                                                                                    \
        /* Sign the canonical TBS under skpsdn, verify through the codec. */        \
        ASSERT_EQ(                                                                  \
            gy_qspgs_core_tbs(&core, 0, scratch, sizeof(scratch), &tbslen),         \
            GY_OK);                                                                 \
        ASSERT_EQ(gy_qspgs_derive_sk_psdn(suite, &sk, skb, vkb, rho), GY_OK);       \
        ASSERT_EQ(gy_kr##set##_sign(sig, &sk.rsk.k##set, scratch, tbslen, ctx,      \
                                    sizeof(ctx) - 1),                               \
                  GY_OK);                                                           \
        gy_qspgs_psdn_sk_clear(&sk);                                                \
                                                                                    \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig),             \
                                       scratch, sizeof(scratch)),                   \
                  GY_OK);                                                           \
                                                                                    \
        /* Core-signature object round-trip. */                                     \
        ASSERT_EQ(gy_qspgs_core_sig_encode(suite, 0, core.last_vmin, sig,           \
                                           sizeof(sig), sigbuf,                     \
                                           sizeof(sigbuf), &n),                     \
                  GY_OK);                                                           \
        {                                                                           \
            uint32_t si, lv;                                                        \
            const uint8_t *sp;                                                      \
            size_t sl, consumed;                                                    \
            ASSERT_EQ(gy_qspgs_core_sig_decode(suite, sigbuf, n, &si, &lv,          \
                                               &sp, &sl, &consumed),                \
                      GY_OK);                                                       \
            ASSERT_EQ(si, (uint32_t)0);                                             \
            ASSERT_EQ(lv, core.last_vmin);                                          \
            ASSERT_EQ(sl, (size_t)sizeof(sig));                                     \
            ASSERT_MEMEQ(sp, sig, sizeof(sig));                                     \
        }                                                                           \
                                                                                    \
        /* Tamper a single covered field (a member cuid) => reject. */              \
        mem[0].cuid[0] ^= 0x01;                                                     \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig),             \
                                       scratch, sizeof(scratch)),                   \
                  GY_ERR_VERIFY);                                                   \
        mem[0].cuid[0] ^= 0x01;                                                     \
        /* Undamaged still verifies. */                                             \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig),             \
                                       scratch, sizeof(scratch)),                   \
                  GY_OK);                                                           \
    }                                                                               \
                                                                                    \
    TEST(q##set##_wire_appendix)                                                    \
    {                                                                               \
        static const uint8_t ctx[] = GY_QSPGS_CTX_APPENDIX;                         \
        uint8_t seed[32], rho[GY_QSPGS_RHO_BYTES];                                  \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                       \
        uint8_t vkr[GY_QSPGS_VKR_MAX];                                              \
        uint8_t pay0[20], pay1[8];                                                  \
        uint8_t sig0[GY_KR##set##_SIG], sig1[GY_KR##set##_SIG];                     \
        uint8_t scratch[2048], buf[16384];                                          \
        uint8_t agid[GY_QSPGS_GID_LEN];                                             \
        struct gy_qspgs_apx_line lines[2];                                          \
        struct gy_qspgs_appendix apx;                                               \
        gy_qspgs_psdn_sk_t sk;                                                      \
        size_t tbslen, n;                                                           \
        memset(seed, 0x51, sizeof(seed));                                           \
        memset(pay0, 0x60, sizeof(pay0));                                           \
        memset(pay1, 0x61, sizeof(pay1));                                           \
        memset(agid, 0x0a, sizeof(agid));                                           \
                                                                                    \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, w_uid_a, 16, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);            \
        ASSERT_EQ(gy_qspgs_derive_sk_psdn(suite, &sk, skb, vkb, rho), GY_OK);       \
                                                                                    \
        /* Line 0: modAttr with a payload; line 1: leave with none. */              \
        memset(lines, 0, sizeof(lines));                                            \
        lines[0].line_type = GY_QAPX_MODATTR;                                       \
        lines[0].author_index = 2;                                                  \
        lines[0].payload = pay0;                                                    \
        lines[0].payload_len = sizeof(pay0);                                        \
        ASSERT_EQ(gy_qspgs_apx_line_tbs(                                            \
                      agid, 4, 7, lines[0].line_type, lines[0].author_index,        \
                      pay0, sizeof(pay0), scratch, sizeof(scratch), &tbslen),       \
                  GY_OK);                                                           \
        ASSERT_EQ(gy_kr##set##_sign(sig0, &sk.rsk.k##set, scratch, tbslen,          \
                                    ctx, sizeof(ctx) - 1),                          \
                  GY_OK);                                                           \
        lines[0].sig = sig0;                                                        \
        lines[0].sig_len = sizeof(sig0);                                            \
                                                                                    \
        lines[1].line_type = GY_QAPX_LEAVE;                                         \
        lines[1].author_index = 2;                                                  \
        lines[1].payload = NULL;                                                    \
        lines[1].payload_len = 0;                                                   \
        ASSERT_EQ(gy_qspgs_apx_line_tbs(agid, 4, 7, lines[1].line_type,             \
                                        lines[1].author_index, NULL, 0,             \
                                        scratch, sizeof(scratch), &tbslen),         \
                  GY_OK);                                                           \
        ASSERT_EQ(gy_kr##set##_sign(sig1, &sk.rsk.k##set, scratch, tbslen,          \
                                    ctx, sizeof(ctx) - 1),                          \
                  GY_OK);                                                           \
        lines[1].sig = sig1;                                                        \
        lines[1].sig_len = sizeof(sig1);                                            \
        gy_qspgs_psdn_sk_clear(&sk);                                                \
                                                                                    \
        memset(&apx, 0, sizeof(apx));                                               \
        apx.suite_id = suite;                                                       \
        memset(apx.gid, 0x0a, sizeof(apx.gid));                                     \
        apx.vmaj = 4;                                                               \
        apx.vmin = 7;                                                               \
        apx.lines = lines;                                                          \
        apx.n_lines = 2;                                                            \
                                                                                    \
        ASSERT_EQ(gy_qspgs_appendix_encode(&apx, buf, sizeof(buf), &n),             \
                  GY_OK);                                                           \
        {                                                                           \
            struct gy_qspgs_appendix dec;                                           \
            struct gy_qspgs_apx_line out[4];                                        \
            size_t consumed;                                                        \
            memset(&dec, 0, sizeof(dec));                                           \
            dec.suite_id = suite;                                                   \
            ASSERT_EQ(                                                              \
                gy_qspgs_appendix_decode(&dec, out, 4, buf, n, &consumed),          \
                GY_OK);                                                             \
            ASSERT_EQ(dec.n_lines, (size_t)2);                                      \
            ASSERT_EQ(dec.vmaj, (uint32_t)4);                                       \
            ASSERT_EQ(dec.vmin, (uint32_t)7);                                       \
            ASSERT_EQ(out[0].line_type, (uint8_t)GY_QAPX_MODATTR);                  \
            ASSERT_MEMEQ(out[0].payload, pay0, sizeof(pay0));                       \
            ASSERT_EQ(out[1].payload_len, (size_t)0);                               \
            /* Each decoded line's author signature verifies over the decoded  \
             * apx-hdr (gid, vmaj, vmin) and the line (D-QGS-13 E1). */    \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj,            \
                                               dec.vmin, &out[0], vkr,              \
                                               scratch, sizeof(scratch)),           \
                      GY_OK);                                                       \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj,            \
                                               dec.vmin, &out[1], vkr,              \
                                               scratch, sizeof(scratch)),           \
                      GY_OK);                                                       \
            /* A different apx-hdr version => the line signature fails          \
             * (anti-replay across versions, D-QGS-13 E1). */   \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj,            \
                                               dec.vmin + 1, &out[0], vkr,          \
                                               scratch, sizeof(scratch)),           \
                      GY_ERR_VERIFY);                                               \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj + 1,        \
                                               dec.vmin, &out[0], vkr,              \
                                               scratch, sizeof(scratch)),           \
                      GY_ERR_VERIFY);                                               \
            /* A different GID on the empty-payload Leave line fails too, so    \
             * the header-only coverage (no payload) is exercised. */   \
            dec.gid[0] ^= 0x01;                                                     \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj,            \
                                               dec.vmin, &out[1], vkr,              \
                                               scratch, sizeof(scratch)),           \
                      GY_ERR_VERIFY);                                               \
            dec.gid[0] ^= 0x01;                                                     \
            /* Tamper the payload => the line signature fails. */                   \
            ((uint8_t *)out[0].payload)[0] ^= 0x01;                                 \
            ASSERT_EQ(gy_qspgs_apx_line_verify(suite, dec.gid, dec.vmaj,            \
                                               dec.vmin, &out[0], vkr,              \
                                               scratch, sizeof(scratch)),           \
                      GY_ERR_VERIFY);                                               \
        }                                                                           \
    }                                                                               \
                                                                                    \
    TEST(q##set##_wire_sig_width)                                                   \
    {                                                                               \
        /* HIGH-1: the verifiers hand a FIXED tier signature length to liboqs,    \
         * so a declared width other than the tier width must be refused before   \
         * the dispatch (else liboqs reads past the wire buffer), and the two     \
         * decoders must reject a non-canonical width. */ \
        static const uint8_t ctx[] = GY_QSPGS_CTX_CORE;                             \
        uint8_t seed[32], rho[GY_QSPGS_RHO_BYTES];                                  \
        uint8_t rc_a[GY_QSPGS_RC_LEN], mct_a[24];                                   \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                       \
        uint8_t vkr[GY_QSPGS_VKR_MAX], vkhash[GY_QSPGS_HASH_MAX];                   \
        uint8_t sig[GY_KR##set##_SIG];                                              \
        uint8_t scratch[4096], sigbuf[GY_QSPGS_SIG_MAX + 32];                       \
        uint8_t fake[GY_KR##set##_SIG + 1];                                         \
        struct gy_qspgs_member mem[1];                                              \
        struct gy_qspgs_core core;                                                  \
        gy_qspgs_psdn_sk_t sk;                                                      \
        size_t tbslen, n;                                                           \
        memset(seed, 0x71, sizeof(seed));                                           \
        memset(rc_a, 0x72, sizeof(rc_a));                                           \
        memset(mct_a, 0x73, sizeof(mct_a));                                         \
        memset(fake, 0x74, sizeof(fake));                                           \
                                                                                    \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);         \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, seed, w_uid_a, 16, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);            \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, vkr, vkhash), GY_OK);                 \
                                                                                    \
        memset(&core, 0, sizeof(core));                                             \
        core.suite_id = suite;                                                      \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                              \
        memset(core.gid, 0x0c, sizeof(core.gid));                                   \
        core.vmaj = 1;                                                              \
        memset(core.fet, 0x0d, sizeof(core.fet));                                   \
        core.last_vmin = 0;                                                         \
        memset(mem, 0, sizeof(mem));                                                \
        ASSERT_EQ(gy_qspgs_cuid_commit(suite, w_uid_a, 16, rc_a, mem[0].cuid),      \
                  GY_OK);                                                           \
        mem[0].admn = 1;                                                            \
        mem[0].mct = mct_a;                                                         \
        mem[0].mct_len = sizeof(mct_a);                                             \
        core.members = mem;                                                         \
        core.n_members = 1;                                                         \
        core.vkhash = vkhash;                                                       \
        core.n_vk = 1;                                                              \
                                                                                    \
        ASSERT_EQ(                                                                  \
            gy_qspgs_core_tbs(&core, 0, scratch, sizeof(scratch), &tbslen),         \
            GY_OK);                                                                 \
        ASSERT_EQ(gy_qspgs_derive_sk_psdn(suite, &sk, skb, vkb, rho), GY_OK);       \
        ASSERT_EQ(gy_kr##set##_sign(sig, &sk.rsk.k##set, scratch, tbslen, ctx,      \
                                    sizeof(ctx) - 1),                               \
                  GY_OK);                                                           \
        gy_qspgs_psdn_sk_clear(&sk);                                                \
                                                                                    \
        /* Correct width verifies; a short or over-long declared width is         \
         * refused with GY_ERR_VERIFY before the KR verifier runs. */ \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig),             \
                                       scratch, sizeof(scratch)),                   \
                  GY_OK);                                                           \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, 1, scratch,              \
                                       sizeof(scratch)),                            \
                  GY_ERR_VERIFY);                                                   \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig) - 1,         \
                                       scratch, sizeof(scratch)),                   \
                  GY_ERR_VERIFY);                                                   \
        ASSERT_EQ(gy_qspgs_core_verify(&core, 0, vkr, sig, sizeof(sig) + 1,         \
                                       scratch, sizeof(scratch)),                   \
                  GY_ERR_VERIFY);                                                   \
                                                                                    \
        /* Core-signature decoder: a short signature width is non-canonical. */     \
        ASSERT_EQ(gy_qspgs_core_sig_encode(suite, 0, core.last_vmin, fake, 16,      \
                                           sigbuf, sizeof(sigbuf), &n),             \
                  GY_OK);                                                           \
        {                                                                           \
            uint32_t si, lv;                                                        \
            const uint8_t *sp;                                                      \
            size_t sl, consumed;                                                    \
            ASSERT_EQ(gy_qspgs_core_sig_decode(suite, sigbuf, n, &si, &lv,          \
                                               &sp, &sl, &consumed),                \
                      GY_ERR_VERIFY);                                               \
        }                                                                           \
        /* And an over-long width. */                                               \
        ASSERT_EQ(gy_qspgs_core_sig_encode(suite, 0, core.last_vmin, fake,          \
                                           sizeof(sig) + 1, sigbuf,                 \
                                           sizeof(sigbuf), &n),                     \
                  GY_OK);                                                           \
        {                                                                           \
            uint32_t si, lv;                                                        \
            const uint8_t *sp;                                                      \
            size_t sl, consumed;                                                    \
            ASSERT_EQ(gy_qspgs_core_sig_decode(suite, sigbuf, n, &si, &lv,          \
                                               &sp, &sl, &consumed),                \
                      GY_ERR_VERIFY);                                               \
        }                                                                           \
                                                                                    \
        /* Appendix decoder: a line whose signature width is not the tier width   \
         * is non-canonical and rejected. */ \
        {                                                                           \
            struct gy_qspgs_apx_line lines[1];                                      \
            struct gy_qspgs_appendix apx;                                           \
            struct gy_qspgs_apx_line lout[2];                                       \
            uint8_t abuf[16384];                                                    \
            size_t consumed;                                                        \
            memset(lines, 0, sizeof(lines));                                        \
            lines[0].line_type = GY_QAPX_LEAVE;                                     \
            lines[0].author_index = 0;                                              \
            lines[0].payload = NULL;                                                \
            lines[0].payload_len = 0;                                               \
            lines[0].sig = fake;                                                    \
            lines[0].sig_len = 16;                                                  \
            memset(&apx, 0, sizeof(apx));                                           \
            apx.suite_id = suite;                                                   \
            memset(apx.gid, 0x0e, sizeof(apx.gid));                                 \
            apx.vmaj = 1;                                                           \
            apx.vmin = 1;                                                           \
            apx.lines = lines;                                                      \
            apx.n_lines = 1;                                                        \
            ASSERT_EQ(gy_qspgs_appendix_encode(&apx, abuf, sizeof(abuf), &n),       \
                      GY_OK);                                                       \
            {                                                                       \
                struct gy_qspgs_appendix adec;                                      \
                memset(&adec, 0, sizeof(adec));                                     \
                adec.suite_id = suite;                                              \
                ASSERT_EQ(gy_qspgs_appendix_decode(&adec, lout, 2, abuf, n,         \
                                                   &consumed),                      \
                          GY_ERR_VERIFY);                                           \
            }                                                                       \
        }                                                                           \
    }                                                                               \
                                                                                    \
    TEST(q##set##_wire_invite_queue)                                                \
    {                                                                               \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                        \
        gy_qspgs_join_pk_t ipk;                                                     \
        gy_qspgs_join_sk_t isk;                                                     \
        const uint8_t p0[] = "UID||uk||skpers-sig #0";                              \
        const uint8_t p1[] = "UID||uk||skpers-sig #1";                              \
        uint8_t c0[4096], c1[4096];                                                 \
        uint8_t buf[16384];                                                         \
        struct gy_qspgs_invite_entry ent[2];                                        \
        size_t c0len = sizeof(c0), c1len = sizeof(c1), n;                           \
        memset(gk, 0x2d, sizeof(gk));                                               \
                                                                                    \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk, &isk), GY_OK);              \
        ASSERT_EQ(                                                                  \
            gy_qspgs_join_seal(&ipk, p0, sizeof(p0) - 1, c0, c0len, &c0len),        \
            GY_OK);                                                                 \
        ASSERT_EQ(                                                                  \
            gy_qspgs_join_seal(&ipk, p1, sizeof(p1) - 1, c1, c1len, &c1len),        \
            GY_OK);                                                                 \
        ent[0].ct = c0;                                                             \
        ent[0].ct_len = c0len;                                                      \
        ent[1].ct = c1;                                                             \
        ent[1].ct_len = c1len;                                                      \
                                                                                    \
        ASSERT_EQ(                                                                  \
            gy_qspgs_invite_queue_encode(suite, ent, 2, buf, sizeof(buf), &n),      \
            GY_OK);                                                                 \
        {                                                                           \
            struct gy_qspgs_invite_entry out[4];                                    \
            uint8_t pt[256];                                                        \
            size_t n_out, consumed, ptlen = sizeof(pt);                             \
            ASSERT_EQ(gy_qspgs_invite_queue_decode(suite, out, 4, buf, n,           \
                                                   &n_out, &consumed),              \
                      GY_OK);                                                       \
            ASSERT_EQ(n_out, (size_t)2);                                            \
            ASSERT_EQ(out[0].ct_len, c0len);                                        \
            ASSERT_MEMEQ(out[0].ct, c0, c0len);                                     \
            /* A decoded entry still opens to its plaintext (framing intact). */    \
            ASSERT_EQ(gy_qspgs_join_open(&isk, out[1].ct, out[1].ct_len, pt,        \
                                         sizeof(pt), &ptlen),                       \
                      GY_OK);                                                       \
            ASSERT_EQ(ptlen, sizeof(p1) - 1);                                       \
            ASSERT_MEMEQ(pt, p1, sizeof(p1) - 1);                                   \
        }                                                                           \
        gy_qspgs_join_sk_clear(&isk);                                               \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)

TEST(wire_reject_null_classical)
{
    struct gy_qspgs_core core;
    uint8_t buf[64];
    size_t n;
    memset(&core, 0, sizeof(core));

    /* Hybrid-only: a classical suite has no QSPGS structure. */
    core.suite_id = GY_SUITE_C25519;
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    ASSERT_EQ(gy_qspgs_header_encode(&core, buf, sizeof(buf), &n), GY_ERR_ARG);

    /* NULL arguments. */
    core.suite_id = GY_SUITE_H25519_512;
    core.format_version = GY_QSPGS_FORMAT_VERSION;
    ASSERT_EQ(gy_qspgs_header_encode(NULL, buf, sizeof(buf), &n), GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_vkpsdn_hash(GY_SUITE_H25519_512, NULL, buf), GY_ERR_ARG);

    /* Short buffer => TOOLONG. */
    ASSERT_EQ(gy_qspgs_header_encode(&core, buf, 4, &n), GY_ERR_TOOLONG);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(q44_wire_core_roundtrip),
            GY_TEST(q44_wire_vkhash_resolution),
            GY_TEST(q44_wire_core_signature),
            GY_TEST(q44_wire_appendix),
            GY_TEST(q44_wire_sig_width),
            GY_TEST(q44_wire_invite_queue),
            GY_TEST(q87_wire_core_roundtrip),
            GY_TEST(q87_wire_vkhash_resolution),
            GY_TEST(q87_wire_core_signature),
            GY_TEST(q87_wire_appendix),
            GY_TEST(q87_wire_sig_width),
            GY_TEST(q87_wire_invite_queue),
            GY_TEST(wire_reject_null_classical),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
