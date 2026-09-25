/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The gy_qspgs_store *_stored wrappers (QSPGS_SPEC section 9,
 * D-QGS-8).  Round-trips muk, the base pair (skbase || vkbase), and gk through
 * the shared in-memory mock store on both hybrid tiers, then checks the record
 * framing: format_version read-back, rejection of a truncated / version-flipped
 * blob, absent-record NOT_FOUND, the too-small out buffer, argument validation,
 * and idempotent removal.  The rederive-only and zeroization guarantees (tasks
 * 2 and 3) are exercised by their own increments; this proves the framing.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "qspgs_keys.h"
#include "qspgs_mock_store.h"
#include "qspgs_ops.h" /* gy_qspgs_member_ctx */
#include "qspgs_store.h"
#include "util.h" /* gy_core_init */

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_H25519_512, GY_SUITE_H448_1024};

/* UIDs are a fixed GY_QSPGS_UID_LEN width (SEC-v1.5.0 LOW-2). */
static const uint8_t UID[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2,
                                              0xa3, 0xa4, 0xa5};
static const uint8_t GID[GY_QSPGS_GID_LEN] = {0xc0, 1, 2,  3,  4,  5,  6,  7,
                                              8,    9, 10, 11, 12, 13, 14, 15};

TEST(init)
{
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(store_roundtrip)
{
    struct qmock_store m;
    struct gy_qspgs_store store;
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        size_t mklen = gy_qspgs_master_key_len(suite);
        size_t skblen = gy_qspgs_base_skb_len(suite);
        size_t vkblen = gy_qspgs_base_vkb_len(suite);
        uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], gk[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t skb[GY_QSPGS_SKB_MAX], vkb[GY_QSPGS_VKB_MAX];
        uint8_t out[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t out_skb[GY_QSPGS_SKB_MAX], out_vkb[GY_QSPGS_VKB_MAX];
        size_t out_len = 0, i;
        uint16_t fmt = 0;

        qmock_init(&m, &store);
        for (i = 0; i < mklen; i++) {
            muk[i] = (uint8_t)(0x10 + i);
            gk[i] = (uint8_t)(0x90 + i);
        }
        for (i = 0; i < skblen; i++)
            skb[i] = (uint8_t)(0x30 + (i & 0x3f));
        for (i = 0; i < vkblen; i++)
            vkb[i] = (uint8_t)(0x50 + (i & 0x3f));

        /* MUK: store, read format version, load back. */
        ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, sizeof(UID), muk),
                  GY_OK);
        ASSERT_EQ(gy_qspgs_format_version_load(&store, GY_QREC_MUK, UID,
                                               sizeof(UID), &fmt),
                  GY_OK);
        ASSERT_EQ((int)fmt, GY_QSPGS_FORMAT_VERSION);
        memset(out, 0, sizeof(out));
        ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out,
                                    sizeof(out), &out_len),
                  GY_OK);
        ASSERT_EQ(out_len, mklen);
        ASSERT_EQ(memcmp(out, muk, mklen), 0);

        /* BASE_KEY: store skbase || vkbase, load both halves back. */
        ASSERT_EQ(
            gy_qspgs_base_key_store(&store, suite, UID, sizeof(UID), skb, vkb),
            GY_OK);
        memset(out_skb, 0, sizeof(out_skb));
        memset(out_vkb, 0, sizeof(out_vkb));
        ASSERT_EQ(gy_qspgs_base_key_load(&store, suite, UID, sizeof(UID),
                                         out_skb, out_vkb),
                  GY_OK);
        ASSERT_EQ(memcmp(out_skb, skb, skblen), 0);
        ASSERT_EQ(memcmp(out_vkb, vkb, vkblen), 0);

        /* GROUP_KEY: store, load back. */
        ASSERT_EQ(gy_qspgs_group_key_store(&store, suite, GID, gk), GY_OK);
        memset(out, 0, sizeof(out));
        ASSERT_EQ(gy_qspgs_group_key_load(&store, suite, GID, out, sizeof(out),
                                          &out_len),
                  GY_OK);
        ASSERT_EQ(out_len, mklen);
        ASSERT_EQ(memcmp(out, gk, mklen), 0);

        /* Delete: user records gone, then the group record. */
        ASSERT_EQ(gy_qspgs_user_delete_stored(&store, UID, sizeof(UID)), GY_OK);
        ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out,
                                    sizeof(out), &out_len),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(gy_qspgs_base_key_load(&store, suite, UID, sizeof(UID),
                                         out_skb, out_vkb),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(gy_qspgs_group_delete_stored(&store, GID), GY_OK);
        ASSERT_EQ(gy_qspgs_group_key_load(&store, suite, GID, out, sizeof(out),
                                          &out_len),
                  GY_ERR_NOT_FOUND);
        /* Removing an already-absent record is idempotent. */
        ASSERT_EQ(gy_qspgs_user_delete_stored(&store, UID, sizeof(UID)), GY_OK);
    }
}

/*
 * Framing rejection: a truncated blob, a flipped record-version byte, and an
 * absent-record load, plus the too-small out buffer and argument validation.
 */
TEST(store_framing)
{
    struct qmock_store m;
    struct gy_qspgs_store store;
    const uint8_t suite = GY_SUITE_H25519_512;
    size_t mklen = gy_qspgs_master_key_len(suite);
    uint8_t muk[GY_QSPGS_MASTER_KEY_MAX], out[GY_QSPGS_MASTER_KEY_MAX];
    size_t out_len = 0, i;
    uint16_t fmt = 0;
    struct qmock_rec *r;

    qmock_init(&m, &store);
    for (i = 0; i < mklen; i++)
        muk[i] = (uint8_t)(0x10 + i);

    /* Absent record: NOT_FOUND, not an error. */
    ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out,
                                sizeof(out), &out_len),
              GY_ERR_NOT_FOUND);
    ASSERT_EQ(gy_qspgs_format_version_load(&store, GY_QREC_MUK, UID,
                                           sizeof(UID), &fmt),
              GY_ERR_NOT_FOUND);

    ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, sizeof(UID), muk), GY_OK);
    r = qmock_find(&m, GY_QREC_MUK, UID, sizeof(UID));
    ASSERT_TRUE(r != NULL, "stored MUK record present");

    /* Flip the record-version byte: rejected as malformed. */
    r->blob[0] ^= 0xff;
    ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out,
                                sizeof(out), &out_len),
              GY_ERR_VERIFY);
    r->blob[0] ^= 0xff; /* restore */

    /* Truncate below the payload width: rejected. */
    r->blob_len -= 1;
    ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out,
                                sizeof(out), &out_len),
              GY_ERR_VERIFY);
    r->blob_len += 1; /* restore */

    /* Out buffer smaller than the key: TOOLONG. */
    ASSERT_EQ(gy_qspgs_muk_load(&store, suite, UID, sizeof(UID), out, mklen - 1,
                                &out_len),
              GY_ERR_TOOLONG);

    /* Argument validation: NULLs, a classical suite, a UID out of range. */
    ASSERT_EQ(gy_qspgs_muk_store(NULL, suite, UID, sizeof(UID), muk),
              GY_ERR_ARG);
    ASSERT_EQ(
        gy_qspgs_muk_store(&store, GY_SUITE_C25519, UID, sizeof(UID), muk),
        GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, 0, muk), GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, GY_QSPGS_UID_MAX + 1, muk),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, sizeof(UID), NULL),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_group_key_store(&store, GY_SUITE_C448, GID, muk),
              GY_ERR_ARG);
}

/*
 * Rederive-only open (task 2, D-GRP-7): a member context opened from the store
 * (loading only gk and the base pair) must rederive exactly the working set a
 * direct open produces - proving the derived secrets (ek, rrs, rho, skpsdn, vkr)
 * are recomputed, never persisted.  Also: an absent gk or base record is
 * NOT_FOUND, not a garbage open.
 */
TEST(open_stored_rederives)
{
    struct qmock_store m;
    struct gy_qspgs_store store;
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t skb[GY_QSPGS_SKB_MAX], vkb[GY_QSPGS_VKB_MAX];
        struct gy_qspgs_member_ctx from_store, direct;

        qmock_init(&m, &store);
        ASSERT_EQ(gy_qspgs_group_key_gen(suite, gk), GY_OK);
        ASSERT_EQ(gy_qspgs_base_keygen(suite, vkb, skb), GY_OK);

        /* An open before anything is stored: NOT_FOUND (gk record absent). */
        ASSERT_EQ(gy_qspgs_member_ctx_open_stored(&from_store, &store, suite,
                                                  GID, UID, sizeof(UID)),
                  GY_ERR_NOT_FOUND);

        ASSERT_EQ(gy_qspgs_group_key_store(&store, suite, GID, gk), GY_OK);
        /* gk present but base pair still absent: NOT_FOUND. */
        ASSERT_EQ(gy_qspgs_member_ctx_open_stored(&from_store, &store, suite,
                                                  GID, UID, sizeof(UID)),
                  GY_ERR_NOT_FOUND);
        ASSERT_EQ(
            gy_qspgs_base_key_store(&store, suite, UID, sizeof(UID), skb, vkb),
            GY_OK);

        /* Open from the store (rederived) and directly (from the same at-rest
         * material); the derived working set must match byte-for-byte. */
        ASSERT_EQ(gy_qspgs_member_ctx_open_stored(&from_store, &store, suite,
                                                  GID, UID, sizeof(UID)),
                  GY_OK);
        ASSERT_EQ(gy_qspgs_member_ctx_open(&direct, suite, gk, skb, vkb, UID,
                                           sizeof(UID)),
                  GY_OK);

        ASSERT_EQ((int)from_store.suite_id, (int)direct.suite_id);
        ASSERT_EQ(memcmp(from_store.ek, direct.ek, GY_QSPGS_EK_BYTES), 0);
        ASSERT_EQ(memcmp(from_store.rrs, direct.rrs, GY_QSPGS_RRS_BYTES), 0);
        ASSERT_EQ(memcmp(from_store.rho, direct.rho, GY_QSPGS_RHO_BYTES), 0);
        ASSERT_EQ(memcmp(from_store.vkr, direct.vkr, GY_QSPGS_VKR_MAX), 0);

        gy_qspgs_member_ctx_clear(&from_store);
        gy_qspgs_member_ctx_clear(&direct);
        gy_secure_zero(gk, sizeof(gk));
        gy_secure_zero(skb, sizeof(skb));
    }
}

/*
 * Storage KAT (task 4): freeze the record byte layout on both tiers.  Each
 * record is ver(0x01) || format_version(BE16 = 0x0001) || payload, and the
 * payload is the raw secret verbatim (the store adds no obfuscation of its own;
 * the app owns the AEAD wrap).  A pure framing KAT: the exact stored bytes are a
 * deterministic function of the header constants and the input, independent of
 * the key values, so fixed patterns stand in for real key material.
 */
TEST(store_kat)
{
    struct qmock_store m;
    struct gy_qspgs_store store;
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        size_t mklen = gy_qspgs_master_key_len(suite);
        size_t skblen = gy_qspgs_base_skb_len(suite);
        size_t vkblen = gy_qspgs_base_vkb_len(suite);
        uint8_t muk[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t skb[GY_QSPGS_SKB_MAX], vkb[GY_QSPGS_VKB_MAX];
        struct qmock_rec *r;
        size_t i;

        qmock_init(&m, &store);
        for (i = 0; i < mklen; i++)
            muk[i] = (uint8_t)(0x11 * (i + 1));
        for (i = 0; i < skblen; i++)
            skb[i] = (uint8_t)(0x30 + (i & 0x3f));
        for (i = 0; i < vkblen; i++)
            vkb[i] = (uint8_t)(0x50 + (i & 0x3f));

        /* MUK: header || muk. */
        ASSERT_EQ(gy_qspgs_muk_store(&store, suite, UID, sizeof(UID), muk),
                  GY_OK);
        r = qmock_find(&m, GY_QREC_MUK, UID, sizeof(UID));
        ASSERT_TRUE(r != NULL, "MUK record present");
        ASSERT_EQ(r->blob_len, GY_QSPGS_REC_HDR_LEN + mklen);
        ASSERT_EQ((int)r->blob[0], GY_QSPGS_REC_VERSION);
        ASSERT_EQ((int)r->blob[1], 0x00);
        ASSERT_EQ((int)r->blob[2], GY_QSPGS_FORMAT_VERSION);
        ASSERT_EQ(memcmp(r->blob + GY_QSPGS_REC_HDR_LEN, muk, mklen), 0);

        /* BASE_KEY: header || skbase || vkbase (that concatenation order). */
        ASSERT_EQ(
            gy_qspgs_base_key_store(&store, suite, UID, sizeof(UID), skb, vkb),
            GY_OK);
        r = qmock_find(&m, GY_QREC_BASE_KEY, UID, sizeof(UID));
        ASSERT_TRUE(r != NULL, "BASE_KEY record present");
        ASSERT_EQ(r->blob_len, GY_QSPGS_REC_HDR_LEN + skblen + vkblen);
        ASSERT_EQ((int)r->blob[0], GY_QSPGS_REC_VERSION);
        ASSERT_EQ(memcmp(r->blob + GY_QSPGS_REC_HDR_LEN, skb, skblen), 0);
        ASSERT_EQ(memcmp(r->blob + GY_QSPGS_REC_HDR_LEN + skblen, vkb, vkblen),
                  0);
    }
}

/*
 * Zeroization sweep (tasks 3 and 4): every secret-bearing structure the client
 * hands out is all-zero after its clear, on both tiers.  The member context is
 * exercised through a real open (so the sk_r blob, ek, rrs, rho, and vkr are
 * genuinely populated before the clear); the invite and member-view structs are
 * filled with a nonzero pattern to prove the whole-struct wipe.
 */
TEST(zeroization_sweep)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        uint8_t suite = suites[si];
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];
        uint8_t skb[GY_QSPGS_SKB_MAX], vkb[GY_QSPGS_VKB_MAX];
        struct gy_qspgs_member_ctx ctx;
        struct gy_qspgs_invite inv;
        struct gy_qspgs_member_view view;

        ASSERT_EQ(gy_qspgs_group_key_gen(suite, gk), GY_OK);
        ASSERT_EQ(gy_qspgs_base_keygen(suite, vkb, skb), GY_OK);

        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctx, suite, gk, skb, vkb, UID,
                                           sizeof(UID)),
                  GY_OK);
        gy_qspgs_member_ctx_clear(&ctx);
        ASSERT_TRUE(gy_is_zero(&ctx, sizeof(ctx)), "member ctx zeroized");

        memset(&inv, 0xab, sizeof(inv));
        gy_qspgs_invite_clear(&inv);
        ASSERT_TRUE(gy_is_zero(&inv, sizeof(inv)), "invite zeroized");

        memset(&view, 0xcd, sizeof(view));
        gy_qspgs_member_view_clear(&view);
        ASSERT_TRUE(gy_is_zero(&view, sizeof(view)), "member view zeroized");

        gy_secure_zero(gk, sizeof(gk));
        gy_secure_zero(skb, sizeof(skb));
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(store_roundtrip), GY_TEST(store_framing),
             GY_TEST(open_stored_rederives), GY_TEST(store_kat),
             GY_TEST(zeroization_sweep))
