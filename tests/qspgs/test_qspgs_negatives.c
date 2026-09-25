/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The QSPGS negative matrix, consolidated (QSPGS_SPEC §12).
 * The seven required rejections and where each is exercised:
 *
 *   1. foreign rho (attributing a line to the wrong identity)   -> test_qspgs_ops
 *      GEN7 (q{44,87}_server): resolve-verify under B's (uid, vkb) fails A's
 *      line (needs a real signed core).
 *   2. forged / replayed pseudonym signature                    -> test_qspgs_ops
 *      GEN7: a flipped signature byte and a cross-group GID replay both fail
 *      core resolve-verify (needs a real signature).
 *   3. wrong-vkpsdn line (supplied key not resolving to stored  -> HERE
 *      H(vkpsdn)): server_core_check rejects at the hash check, before verify.
 *   4. tampered appendix or core line                           -> test_qspgs_ops
 *      GEN7: a tampered core / appendix payload fails its signature; the
 *      format-epoch tamper (D-QGS-12) is there too (needs a real signature).
 *   5. stale version under compare-and-swap                     -> HERE
 *      (server_version_check).
 *   6. non-admin admin-only edit                                -> HERE
 *      (server_core_check admn gate, before any crypto).
 *   7. over-cap member list                                     -> HERE
 *      (member_list_decode rejects count > GY_QSPGS_MAX_ENTRIES).
 *
 * Items 3, 5, 6, 7 plus the bearer-token mismatch are pure / cheap (no signed
 * core) and run here as the standalone matrix; items 1, 2, 4 need a validly
 * signed fixture and are covered, green, by the client-linked GEN7 above.  This
 * file therefore makes the matrix COMPLETE and adds the previously-untested
 * over-cap case; it links both facades via the qspgs test helper.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_*, gy_be16_put */
#include "error.h"
#include "qspgs_server.h"
#include "qspgs_wire.h"
#include "suite.h" /* gy_suite_desc */
#include "util.h"  /* gy_core_init */

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_H25519_512, GY_SUITE_H448_1024};

TEST(init)
{
    ASSERT_EQ(gy_core_init(), GY_OK);
}

/* Item 5: stale / non-advancing version under compare-and-swap. */
TEST(neg_stale_version)
{
    /* Extends the head and strictly advances: accepted. */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 0, 1, 0, 1, 1), GY_OK);
    /* Duplicate (new == cur): does not advance. */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 1, 1, 1, 1, 1), GY_ERR_STATE);
    /* Regression (new < cur). */
    ASSERT_EQ(gy_qspgs_server_version_check(2, 0, 2, 0, 1, 9), GY_ERR_STATE);
    /* Stale writer: extends (1,0) but the head moved to (1,1). */
    ASSERT_EQ(gy_qspgs_server_version_check(1, 1, 1, 0, 2, 0), GY_ERR_STATE);
}

/* Item 4-adjacent: bearer-token / fetch-token mismatch. */
TEST(neg_token_mismatch)
{
    uint8_t stored[GY_QSPGS_FET_LEN], presented[GY_QSPGS_FET_LEN];
    struct gy_qspgs_core core;
    size_t i;

    for (i = 0; i < GY_QSPGS_FET_LEN; i++)
        stored[i] = (uint8_t)(0x40 + i);
    memcpy(presented, stored, sizeof(presented));
    presented[GY_QSPGS_FET_LEN - 1] ^= 0x01;
    ASSERT_EQ(gy_qspgs_server_token_check(presented, stored, sizeof(stored)),
              GY_ERR_VERIFY);

    memset(&core, 0, sizeof(core));
    memcpy(core.fet, stored, sizeof(stored));
    ASSERT_EQ(gy_qspgs_server_fetch_check(core.fet, presented), GY_ERR_VERIFY);
}

/*
 * Items 3 and 6, both tiers: a non-admin signer (admn gate, before any crypto)
 * and a supplied vkpsdn that does not resolve to the stored H(vkpsdn) (hash
 * check, before signature verify).  Neither needs a valid signature.
 */
TEST(neg_admn_and_wrong_vkpsdn)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        uint8_t vkr[GY_QSPGS_VKR_MAX], sig[GY_QSPGS_SIG_MAX];
        uint8_t vkhash[GY_QSPGS_HASH_MAX], scratch[4096];
        struct gy_qspgs_member mem[1];
        struct gy_qspgs_core core;

        memset(vkr, 0x5a, sizeof(vkr));
        memset(sig, 0x6b, sizeof(sig));
        memset(vkhash, 0x11, sizeof(vkhash)); /* will not equal H(vkr). */
        memset(mem, 0, sizeof(mem));

        memset(&core, 0, sizeof(core));
        core.suite_id = suite;
        core.format_version = GY_QSPGS_FORMAT_VERSION;
        core.members = mem;
        core.n_members = 1;
        core.vkhash = vkhash;
        core.n_vk = 1;

        /* Item 6 (D-QGS-13 E2): the admn gate reads the PRIOR mem-lst, so a
         * non-admin PRIOR signer is rejected before any crypto.  prior == next
         * here (a would-be UNCHANGED edit). */
        mem[0].admn = 0;
        ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED,
                                             &core, 0, vkr, sig, sizeof(sig),
                                             scratch, sizeof(scratch)),
                  GY_ERR_VERIFY);

        /* Item 3: admin PRIOR signer, but the supplied vkr does not hash to the
         * stored H(vkpsdn) -> rejected at the hash check, before verify. */
        mem[0].admn = 1;
        ASSERT_EQ(gy_qspgs_server_core_check(&core, GY_QSPGS_OP_UNCHANGED,
                                             &core, 0, vkr, sig, sizeof(sig),
                                             scratch, sizeof(scratch)),
                  GY_ERR_VERIFY);
    }
}

/*
 * Item 7, both tiers: a member-list object whose declared count exceeds
 * GY_QSPGS_MAX_ENTRIES is rejected by the decoder before any entry is read.
 * The buffer is crafted by hand (a valid encoder never emits an over-cap list).
 */
TEST(neg_over_cap_member_list)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        size_t hlen = gy_suite_desc(suite)->hash_len;
        uint8_t buf[GY_QSPGS_OBJ_HDR_LEN + 1 + 2];
        struct gy_qspgs_member out[4];
        struct gy_qspgs_core dec;
        size_t consumed;

        /* obj header || hash_len(1) || count(BE16 = MAX + 1). */
        buf[0] = GY_QOBJ_MEMBER_LIST;
        buf[1] = GY_QSPGS_WIRE_VERSION;
        buf[2] = suite;
        buf[3] = (uint8_t)hlen;
        gy_be16_put(buf + 4, (uint16_t)(GY_QSPGS_MAX_ENTRIES + 1));

        memset(&dec, 0, sizeof(dec));
        dec.suite_id = suite;
        ASSERT_EQ(gy_qspgs_member_list_decode(&dec, out, 4, buf, sizeof(buf),
                                              &consumed),
                  GY_ERR_VERIFY);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(neg_stale_version),
             GY_TEST(neg_token_mismatch), GY_TEST(neg_admn_and_wrong_vkpsdn),
             GY_TEST(neg_over_cap_member_list))
