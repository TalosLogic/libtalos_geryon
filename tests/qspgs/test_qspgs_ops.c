/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The QSPGS client-operation crypto engine, the
 * registration / invitation operations, and the Fetch read path, both tiers.
 *
 * Covered per suite (GEN..GEN6 keep the tiers in lockstep):
 *   - negative matrix (section 6): a forged pseudonym signature, a cross-group
 *     replay (GID changed after signing), and a foreign-rho attribution (A's
 *     line claimed for B) are each rejected;
 *   - join link: ToggleJoinLink seals (gk, fet) under a link secret; JoinViaLink
 *     recovers them; a wrong secret and a tampered slot are rejected;
 *   - appendix lines: a Refresh line by an existing member resolve/verifies
 *     against its vk-lst hash (a wrong stored hash and a tampered payload are
 *     rejected), and a JOIN line by a newcomer (no vk-lst entry) verifies with
 *     the stored-hash check skipped;
 *   - core lifecycle: Create (A admin) -> AddMember (B) -> RemoveMember (B) with
 *     gk rotation; every admin core re-sign resolve/verifies, B attributes to
 *     its vk-lst line while present, and after removal the rotated rrs changes
 *     B's pseudonym so its old vk-lst hash no longer resolves;
 *   - Fetch: a member entry decrypts to a plaintext view and its C_UID opens
 *     (a non-opening C_UID is rejected); the admin core signature verifies
 *     after resolving the signer's vkr from (rrs, vkbase, UID), while a wrong
 *     signer UID (vk-lst hash mismatch) and a tampered covered field are
 *     rejected;
 *   - RegisterUser emits an Acct record whose dual identity signature verifies;
 *     a tampered record and a wrong identity key are rejected (GrantAcquaintance
 *     accept is that same verify);
 *   - Invite seals (UID, uk, sigma) to the group ipk; a member holding isk opens
 *     it, recovers (UID, uk), and verifies sigma; a wrong GID and a tampered
 *     ciphertext are rejected;
 * and, from increment 1:
 *   - ek-field seal / open round-trips; two seals of the same plaintext differ
 *     (fresh random nonce); the overhead matches gy_qspgs_field_overhead(QAEAD);
 *   - a field opens ONLY under the right ek, field-kind tag, and GID: a wrong
 *     ek, a wrong tag, a flipped GID byte, and a tampered ciphertext each fail
 *     with GY_ERR_VERIFY;
 *   - the structured member tuple (UID, r_c, uk) round-trips through
 *     mct seal / open; a too-small UID buffer is GY_ERR_TOOLONG;
 *   - a member context derives the same (ek, rrs, rho -> vkr) as the standalone
 *     hierarchy, and its skpsdn / vkr are a working KR-ML-DSA pair (sign then
 *     verify); clearing it zeroes the tag;
 *   - attribution recomputes the same H(vkpsdn) a member's own context holds,
 *     and a different UID yields a different hash.
 */

#include <stdint.h>
#include <string.h>

#include "aead.h"   /* GY_AEAD_CHACHA20POLY1305 (group field AEAD, INFO-6) */
#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "qspgs_field.h"
#include "qspgs_keys.h"
#include "qspgs_labels.h" /* GY_QSPGS_CTX_CORE */
#include "qspgs_ops.h"
#include "qspgs_server.h" /* gy_qspgs_server_core_check / _apx_check */
#include "qspgs_wire.h"   /* gy_qspgs_vkpsdn_hash, GID/RC/HASH constants */
#include "suite.h"
#include "util.h"

#include "gy_test.h"

/* The group field AEAD these white-box tests seal under (INFO-6). */
#define QAEAD GY_AEAD_CHACHA20POLY1305

static const uint8_t ops_gid[GY_QSPGS_GID_LEN] = {
    0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
    0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78};

#define GEN(set, suite)                                                        \
    TEST(q##set##_field_roundtrip)                                             \
    {                                                                          \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                \
        const uint8_t pt[] = "settings || attributes plaintext";               \
        uint8_t ct[256], ct2[256], out[256];                                   \
        size_t ctlen = sizeof(ct), ct2len = sizeof(ct2), outlen = sizeof(out); \
        memset(gk, 0x42, sizeof(gk));                                          \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);         \
                                                                               \
        ASSERT_EQ(gy_qspgs_field_seal(suite, QAEAD, ek, GY_QSPGS_FIELD_HEADER, \
                                      ops_gid, pt, sizeof(pt) - 1, ct, ctlen,  \
                                      &ctlen),                                 \
                  GY_OK);                                                      \
        ASSERT_EQ(ctlen, gy_qspgs_field_overhead(QAEAD) + (sizeof(pt) - 1));   \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_HEADER, \
                                      ops_gid, ct, ctlen, out, sizeof(out),    \
                                      &outlen),                                \
                  GY_OK);                                                      \
        ASSERT_EQ(outlen, sizeof(pt) - 1);                                     \
        ASSERT_MEMEQ(out, pt, sizeof(pt) - 1);                                 \
                                                                               \
        /* A second seal differs (random nonce). */                            \
        ASSERT_EQ(gy_qspgs_field_seal(suite, QAEAD, ek, GY_QSPGS_FIELD_HEADER, \
                                      ops_gid, pt, sizeof(pt) - 1, ct2,        \
                                      ct2len, &ct2len),                        \
                  GY_OK);                                                      \
        ASSERT_EQ(ct2len, ctlen);                                              \
        ASSERT_TRUE(memcmp(ct, ct2, ctlen) != 0, "fresh seals must differ");   \
    }                                                                          \
                                                                               \
    TEST(q##set##_field_reject)                                                \
    {                                                                          \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                \
        uint8_t gid2[GY_QSPGS_GID_LEN];                                        \
        const uint8_t pt[] = "modAttr plaintext";                              \
        uint8_t ct[256], out[256];                                             \
        size_t ctlen = sizeof(ct), outlen = sizeof(out);                       \
        memset(gk, 0x91, sizeof(gk));                                          \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);         \
        ASSERT_EQ(gy_qspgs_field_seal(suite, QAEAD, ek, GY_QSPGS_FIELD_ATTR,   \
                                      ops_gid, pt, sizeof(pt) - 1, ct, ctlen,  \
                                      &ctlen),                                 \
                  GY_OK);                                                      \
                                                                               \
        /* Right ek/tag/GID opens. */                                          \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_ATTR,   \
                                      ops_gid, ct, ctlen, out, sizeof(out),    \
                                      &outlen),                                \
                  GY_OK);                                                      \
        /* Wrong field-kind tag. */                                            \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_UK,     \
                                      ops_gid, ct, ctlen, out, sizeof(out),    \
                                      &outlen),                                \
                  GY_ERR_VERIFY);                                              \
        /* Wrong GID. */                                                       \
        memcpy(gid2, ops_gid, sizeof(gid2));                                   \
        gid2[0] ^= 0x01;                                                       \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_ATTR,   \
                                      gid2, ct, ctlen, out, sizeof(out),       \
                                      &outlen),                                \
                  GY_ERR_VERIFY);                                              \
        /* Wrong ek. */                                                        \
        ek[0] ^= 0x01;                                                         \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_ATTR,   \
                                      ops_gid, ct, ctlen, out, sizeof(out),    \
                                      &outlen),                                \
                  GY_ERR_VERIFY);                                              \
        ek[0] ^= 0x01;                                                         \
        /* Tampered ciphertext. */                                             \
        ct[ctlen - 1] ^= 0x01;                                                 \
        ASSERT_EQ(gy_qspgs_field_open(suite, QAEAD, ek, GY_QSPGS_FIELD_ATTR,   \
                                      ops_gid, ct, ctlen, out, sizeof(out),    \
                                      &outlen),                                \
                  GY_ERR_VERIFY);                                              \
        ct[ctlen - 1] ^= 0x01;                                                 \
    }                                                                          \
                                                                               \
    TEST(q##set##_member_ct_roundtrip)                                         \
    {                                                                          \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                \
        const uint8_t uid[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2,               \
                                               0xa3, 0xa4, 0xa5};              \
        uint8_t rc_open[GY_QSPGS_RC_LEN], uk[GY_QSPGS_MASTER_KEY_MAX];         \
        uint8_t ct[256];                                                       \
        uint8_t o_uid[GY_QSPGS_UID_MAX], o_rc[GY_QSPGS_RC_LEN];                \
        uint8_t o_uk[GY_QSPGS_MASTER_KEY_MAX];                                 \
        uint8_t o_form = 0xff;                                                 \
        size_t mklen = gy_qspgs_master_key_len(suite);                         \
        size_t ctlen = sizeof(ct), o_uidlen = 0;                               \
        memset(gk, 0x33, sizeof(gk));                                          \
        memset(rc_open, 0x1a, sizeof(rc_open));                                \
        memset(uk, 0x2b, sizeof(uk));                                          \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);         \
                                                                               \
        ASSERT_EQ(gy_qspgs_member_ct_seal(suite, QAEAD, ek, ops_gid, uid,      \
                                          sizeof(uid), rc_open, uk, ct, ctlen, \
                                          &ctlen),                             \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_member_ct_open(                                     \
                      suite, QAEAD, ek, ops_gid, ct, ctlen, &o_form, o_uid,    \
                      sizeof(o_uid), &o_uidlen, o_rc, o_uk),                   \
                  GY_OK);                                                      \
        ASSERT_EQ(o_form, GY_QSPGS_MEMBER_FORM_PRESENT);                       \
        ASSERT_EQ(o_uidlen, sizeof(uid));                                      \
        ASSERT_MEMEQ(o_uid, uid, sizeof(uid));                                 \
        ASSERT_MEMEQ(o_rc, rc_open, GY_QSPGS_RC_LEN);                          \
        ASSERT_MEMEQ(o_uk, uk, mklen);                                         \
                                                                               \
        /* A UID buffer smaller than the recovered UID is TOOLONG. */          \
        o_uidlen = 0;                                                          \
        ASSERT_EQ(gy_qspgs_member_ct_open(                                     \
                      suite, QAEAD, ek, ops_gid, ct, ctlen, &o_form, o_uid,    \
                      sizeof(uid) - 1, &o_uidlen, o_rc, o_uk),                 \
                  GY_ERR_TOOLONG);                                             \
    }                                                                          \
                                                                               \
    TEST(q##set##_member_ctx)                                                  \
    {                                                                          \
        static const uint8_t kctx[] = GY_QSPGS_CTX_CORE;                       \
        uint8_t base_seed[32];                                                 \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                  \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        const uint8_t uid[GY_QSPGS_UID_LEN] = {0xb0, 0xb1, 0xb2, 0xb3};        \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                \
        uint8_t rho[GY_QSPGS_RHO_BYTES], vkr[GY_KR##set##_VKR];                \
        struct gy_qspgs_member_ctx ctx;                                        \
        const uint8_t msg[] = "core TBS bytes";                                \
        uint8_t sig[GY_KR##set##_SIG];                                         \
        memset(base_seed, 0x11, sizeof(base_seed));                            \
        memset(gk, 0x5a, sizeof(gk));                                          \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, base_seed),       \
                  GY_OK);                                                      \
                                                                               \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctx, suite, gk, skb, vkb, uid,     \
                                           sizeof(uid)),                       \
                  GY_OK);                                                      \
        ASSERT_EQ(ctx.suite_id, suite);                                        \
                                                                               \
        /* The context matches the standalone hierarchy. */                    \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);         \
        ASSERT_MEMEQ(ctx.ek, ek, GY_QSPGS_EK_BYTES);                           \
        ASSERT_MEMEQ(ctx.rrs, rrs, GY_QSPGS_RRS_BYTES);                        \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, rrs, uid, sizeof(uid), rho),      \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);       \
        ASSERT_MEMEQ(ctx.vkr, vkr, GY_KR##set##_VKR);                          \
                                                                               \
        /* skpsdn and vkr are a working pair. */                               \
        ASSERT_EQ(gy_kr##set##_sign(sig, &ctx.sk.rsk.k##set, msg,              \
                                    sizeof(msg) - 1, kctx, sizeof(kctx) - 1),  \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_kr##set##_verify(sig, ctx.vkr, msg, sizeof(msg) - 1,      \
                                      kctx, sizeof(kctx) - 1),                 \
                  GY_OK);                                                      \
                                                                               \
        gy_qspgs_member_ctx_clear(&ctx);                                       \
        ASSERT_EQ(ctx.suite_id, 0);                                            \
    }                                                                          \
                                                                               \
    TEST(q##set##_attribute)                                                   \
    {                                                                          \
        uint8_t base_seed[32];                                                 \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                  \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        const uint8_t uid[GY_QSPGS_UID_LEN] = {0xc0, 0xc1, 0xc2};              \
        const uint8_t uid2[GY_QSPGS_UID_LEN] = {0xc0, 0xc1, 0xc3};             \
        struct gy_qspgs_member_ctx ctx;                                        \
        uint8_t h_attr[GY_QSPGS_HASH_MAX], h_own[GY_QSPGS_HASH_MAX];           \
        uint8_t h_other[GY_QSPGS_HASH_MAX];                                    \
        size_t hlen = gy_suite_desc(suite)->hash_len;                          \
        memset(base_seed, 0x22, sizeof(base_seed));                            \
        memset(gk, 0x6b, sizeof(gk));                                          \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, base_seed),       \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctx, suite, gk, skb, vkb, uid,     \
                                           sizeof(uid)),                       \
                  GY_OK);                                                      \
                                                                               \
        /* attribute_hash equals H(vkpsdn) of the member's own context vkr. */ \
        ASSERT_EQ(gy_qspgs_attribute_hash(suite, ctx.rrs, vkb, uid,            \
                                          sizeof(uid), h_attr),                \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, ctx.vkr, h_own), GY_OK);         \
        ASSERT_MEMEQ(h_attr, h_own, hlen);                                     \
                                                                               \
        /* A different UID gives a different hash. */                          \
        ASSERT_EQ(gy_qspgs_attribute_hash(suite, ctx.rrs, vkb, uid2,           \
                                          sizeof(uid2), h_other),              \
                  GY_OK);                                                      \
        ASSERT_TRUE(memcmp(h_attr, h_other, hlen) != 0,                        \
                    "distinct UID must attribute distinctly");                 \
        gy_qspgs_member_ctx_clear(&ctx);                                       \
    }

/*
 * Increment 2: RegisterUser / GrantAcquaintance (the Acct record) and
 * Invite / AcceptInvitation (the ipk-sealed invite entry).
 */
#define GEN2(set, suite)                                                       \
    TEST(q##set##_register_verify)                                             \
    {                                                                          \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                  \
        uint8_t base_seed[32];                                                 \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                  \
        uint8_t cpk[GY_CURVE_PK_MAX], csk[GY_CURVE_SK_MAX];                    \
        uint8_t mpk[GY_DSA_PK_MAX], msk[GY_DSA_SK_MAX];                        \
        uint8_t acq[GY_QSPGS_MASTER_KEY_MAX];                                  \
        uint8_t acct[16384];                                                   \
        const uint8_t *rvkb, *racq;                                            \
        uint64_t rep = 0;                                                      \
        size_t acctlen = sizeof(acct);                                         \
        size_t vkblen = gy_qspgs_base_vkb_len(suite);                          \
        size_t mklen = gy_qspgs_master_key_len(suite);                         \
        memset(base_seed, 0x11, sizeof(base_seed));                            \
        memset(acq, 0x9a, sizeof(acq));                                        \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, base_seed),       \
                  GY_OK);                                                      \
        ASSERT_EQ(d->keypair(cpk, csk), GY_OK);                                \
        ASSERT_EQ(d->dsa_keypair(mpk, msk), GY_OK);                            \
                                                                               \
        ASSERT_EQ(gy_qspgs_register(suite, vkb, acq, 7, csk, msk, acct,        \
                                    acctlen, &acctlen),                        \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_acct_verify(suite, cpk, mpk, acct, acctlen, &rvkb,  \
                                       &racq, &rep),                           \
                  GY_OK);                                                      \
        ASSERT_EQ(rep, (uint64_t)7);                                           \
        ASSERT_MEMEQ(rvkb, vkb, vkblen);                                       \
        ASSERT_MEMEQ(racq, acq, mklen);                                        \
                                                                               \
        /* Tampered record => reject. */                                       \
        acct[GY_QSPGS_OBJ_HDR_LEN] ^= 0x01;                                    \
        ASSERT_EQ(gy_qspgs_acct_verify(suite, cpk, mpk, acct, acctlen, &rvkb,  \
                                       &racq, &rep),                           \
                  GY_ERR_VERIFY);                                              \
        acct[GY_QSPGS_OBJ_HDR_LEN] ^= 0x01;                                    \
        /* Wrong identity key => reject. */                                    \
        cpk[0] ^= 0x01;                                                        \
        ASSERT_EQ(gy_qspgs_acct_verify(suite, cpk, mpk, acct, acctlen, &rvkb,  \
                                       &racq, &rep),                           \
                  GY_ERR_VERIFY);                                              \
        cpk[0] ^= 0x01;                                                        \
    }                                                                          \
                                                                               \
    TEST(q##set##_invite_roundtrip)                                            \
    {                                                                          \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                  \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        gy_qspgs_join_pk_t ipk;                                                \
        gy_qspgs_join_sk_t isk;                                                \
        uint8_t cpk[GY_CURVE_PK_MAX], csk[GY_CURVE_SK_MAX];                    \
        uint8_t mpk[GY_DSA_PK_MAX], msk[GY_DSA_SK_MAX];                        \
        const uint8_t uid[GY_QSPGS_UID_LEN] = {0xd0, 0xd1, 0xd2, 0xd3, 0xd4};  \
        uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t gid2[GY_QSPGS_GID_LEN];                                        \
        uint8_t ct[8192];                                                      \
        struct gy_qspgs_invite inv;                                            \
        size_t ctlen = sizeof(ct);                                             \
        size_t mklen = gy_qspgs_master_key_len(suite);                         \
        memset(gk, 0x5a, sizeof(gk));                                          \
        memset(uk, 0x3c, sizeof(uk));                                          \
        ASSERT_EQ(gy_qspgs_join_derive(suite, gk, &ipk, &isk), GY_OK);         \
        ASSERT_EQ(d->keypair(cpk, csk), GY_OK);                                \
        ASSERT_EQ(d->dsa_keypair(mpk, msk), GY_OK);                            \
                                                                               \
        ASSERT_EQ(gy_qspgs_invite_seal(suite, &ipk, ops_gid, uid, sizeof(uid), \
                                       uk, csk, msk, ct, ctlen, &ctlen),       \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_invite_open(suite, &isk, ct, ctlen, &inv), GY_OK);  \
        ASSERT_EQ(inv.uidlen, sizeof(uid));                                    \
        ASSERT_MEMEQ(inv.uid, uid, sizeof(uid));                               \
        ASSERT_MEMEQ(inv.uk, uk, mklen);                                       \
        ASSERT_EQ(gy_qspgs_invite_verify(suite, ops_gid, cpk, mpk, &inv),      \
                  GY_OK);                                                      \
        /* Wrong GID in the signed tuple => reject. */                         \
        memcpy(gid2, ops_gid, sizeof(gid2));                                   \
        gid2[0] ^= 0x01;                                                       \
        ASSERT_EQ(gy_qspgs_invite_verify(suite, gid2, cpk, mpk, &inv),         \
                  GY_ERR_VERIFY);                                              \
        gy_qspgs_invite_clear(&inv);                                           \
                                                                               \
        /* Tampered ciphertext => open fails. */                               \
        ct[ctlen - 1] ^= 0x01;                                                 \
        ASSERT_EQ(gy_qspgs_invite_open(suite, &isk, ct, ctlen, &inv),          \
                  GY_ERR_VERIFY);                                              \
        ct[ctlen - 1] ^= 0x01;                                                 \
        gy_qspgs_join_sk_clear(&isk);                                          \
    }

/*
 * Increment 2b: the Fetch read path (member-list decrypt to a view, and the
 * admin core-signature resolve/verify).
 */
#define GEN3(set, suite)                                                       \
    TEST(q##set##_fetch_read)                                                  \
    {                                                                          \
        static const uint8_t ctx[] = GY_QSPGS_CTX_CORE;                        \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX], seed[32];                         \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                \
        uint8_t vkb[GY_QSPGS_VKB_MAX], skb[GY_QSPGS_SKB_MAX];                  \
        uint8_t vkr[GY_QSPGS_VKR_MAX], vkhash[GY_QSPGS_HASH_MAX];              \
        uint8_t rho[GY_QSPGS_RHO_BYTES], rc_open[GY_QSPGS_RC_LEN];             \
        uint8_t uk[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t mct[256], sig[GY_KR##set##_SIG], scratch[4096];                \
        const uint8_t uid[GY_QSPGS_UID_LEN] = {0xe0, 0xe1, 0xe2, 0xe3};        \
        const uint8_t uid2[GY_QSPGS_UID_LEN] = {0xe0, 0xe1, 0xe2, 0xe4};       \
        struct gy_qspgs_member mem[1];                                         \
        struct gy_qspgs_member_view view;                                      \
        struct gy_qspgs_core core;                                             \
        gy_qspgs_psdn_sk_t sk;                                                 \
        size_t mklen = gy_qspgs_master_key_len(suite);                         \
        size_t mctlen = sizeof(mct), tbslen;                                   \
        memset(gk, 0x24, sizeof(gk));                                          \
        memset(seed, 0x31, sizeof(seed));                                      \
        memset(rc_open, 0x41, sizeof(rc_open));                                \
        memset(uk, 0x55, sizeof(uk));                                          \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);         \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkb, skb, seed), GY_OK);    \
                                                                               \
        /* Build one real member entry: mct = Enc_ek(UID, r_c, uk), C_UID. */  \
        memset(mem, 0, sizeof(mem));                                           \
        ASSERT_EQ(gy_qspgs_member_ct_seal(suite, QAEAD, ek, ops_gid, uid,      \
                                          sizeof(uid), rc_open, uk, mct,       \
                                          mctlen, &mctlen),                    \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_cuid_commit(suite, uid, sizeof(uid), rc_open,       \
                                       mem[0].cuid),                           \
                  GY_OK);                                                      \
        mem[0].admn = 1;                                                       \
        mem[0].mct = mct;                                                      \
        mem[0].mct_len = mctlen;                                               \
                                                                               \
        /* Decrypt to a view; C_UID opens. */                                  \
        ASSERT_EQ(gy_qspgs_member_decrypt(suite, QAEAD, ek, ops_gid, &mem[0],  \
                                          &view),                              \
                  GY_OK);                                                      \
        ASSERT_EQ(view.uidlen, sizeof(uid));                                   \
        ASSERT_MEMEQ(view.uid, uid, sizeof(uid));                              \
        ASSERT_MEMEQ(view.uk, uk, mklen);                                      \
        ASSERT_EQ(view.admn, 1);                                               \
        gy_qspgs_member_view_clear(&view);                                     \
        /* A C_UID that does not open the commitment is rejected. */           \
        mem[0].cuid[0] ^= 0x01;                                                \
        ASSERT_EQ(gy_qspgs_member_decrypt(suite, QAEAD, ek, ops_gid, &mem[0],  \
                                          &view),                              \
                  GY_ERR_VERIFY);                                              \
        mem[0].cuid[0] ^= 0x01;                                                \
                                                                               \
        /* Assemble the core and admin-sign it under the member's skpsdn. */   \
        ASSERT_EQ(gy_qspgs_derive_rho(suite, rrs, uid, sizeof(uid), rho),      \
                  GY_OK);                                                      \
        ASSERT_EQ(gy_qspgs_derive_vk_psdn(suite, vkr, vkb, rho), GY_OK);       \
        ASSERT_EQ(gy_qspgs_vkpsdn_hash(suite, vkr, vkhash), GY_OK);            \
        memset(&core, 0, sizeof(core));                                        \
        core.suite_id = suite;                                                 \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                         \
        memcpy(core.gid, ops_gid, sizeof(core.gid));                           \
        core.vmaj = 1;                                                         \
        memset(core.fet, 0x08, sizeof(core.fet));                              \
        core.last_vmin = 0;                                                    \
        core.members = mem;                                                    \
        core.n_members = 1;                                                    \
        core.vkhash = vkhash;                                                  \
        core.n_vk = 1;                                                         \
        ASSERT_EQ(                                                             \
            gy_qspgs_core_tbs(&core, 0, scratch, sizeof(scratch), &tbslen),    \
            GY_OK);                                                            \
        ASSERT_EQ(gy_qspgs_derive_sk_psdn(suite, &sk, skb, vkb, rho), GY_OK);  \
        ASSERT_EQ(gy_kr##set##_sign(sig, &sk.rsk.k##set, scratch, tbslen, ctx, \
                                    sizeof(ctx) - 1),                          \
                  GY_OK);                                                      \
        gy_qspgs_psdn_sk_clear(&sk);                                           \
                                                                               \
        /* Resolve the signer's vkr from (rrs, vkb, UID) and verify. */        \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkb, uid,        \
                                               sizeof(uid), sig, sizeof(sig),  \
                                               scratch, sizeof(scratch)),      \
                  GY_OK);                                                      \
        /* A wrong signer UID resolves to a key the vk-lst hash rejects. */    \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkb, uid2,       \
                                               sizeof(uid2), sig, sizeof(sig), \
                                               scratch, sizeof(scratch)),      \
                  GY_ERR_VERIFY);                                              \
        /* A tampered covered field fails the signature. */                    \
        mem[0].admn ^= 0x01;                                                   \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkb, uid,        \
                                               sizeof(uid), sig, sizeof(sig),  \
                                               scratch, sizeof(scratch)),      \
                  GY_ERR_VERIFY);                                              \
        mem[0].admn ^= 0x01;                                                   \
    }

GEN(44, GY_SUITE_H25519_512)
GEN(87, GY_SUITE_H448_1024)
GEN2(44, GY_SUITE_H25519_512)
GEN2(87, GY_SUITE_H448_1024)
/*
 * Increment 3: the core admin-edit lifecycle.  Create (A, admin) -> AddMember
 * (B) -> RemoveMember (B) with gk rotation, each ending in an admin core
 * re-sign that resolve/verifies, and the removed member's pseudonym no longer
 * resolving to its old vk-lst line.
 */
#define GEN4(set, suite)                                                         \
    TEST(q##set##_core_lifecycle)                                                \
    {                                                                            \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                    \
        size_t hlen = d->hash_len;                                               \
        size_t mklen = gy_qspgs_master_key_len(suite);                           \
        uint8_t seedA[32], seedB[32];                                            \
        uint8_t vkbA[GY_QSPGS_VKB_MAX], skbA[GY_QSPGS_SKB_MAX];                  \
        uint8_t vkbB[GY_QSPGS_VKB_MAX], skbB[GY_QSPGS_SKB_MAX];                  \
        const uint8_t uidA[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2, 0xa3};         \
        const uint8_t uidB[GY_QSPGS_UID_LEN] = {0xb0, 0xb1, 0xb2, 0xb3};         \
        uint8_t ukA[GY_QSPGS_MASTER_KEY_MAX], ukB[GY_QSPGS_MASTER_KEY_MAX];      \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                     \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                  \
        uint8_t vkhash[2 * GY_QSPGS_HASH_MAX], oldB[GY_QSPGS_HASH_MAX];          \
        uint8_t view_hash[GY_QSPGS_HASH_MAX];                                    \
        uint8_t mctA[256], mctB[256];                                            \
        struct gy_qspgs_member mem[2];                                           \
        struct gy_qspgs_member_view view;                                        \
        struct gy_qspgs_core core;                                               \
        struct gy_qspgs_member_ctx ctxA;                                         \
        uint8_t coresig[8192], scratch[4096];                                    \
        size_t mctlen, n;                                                        \
        uint32_t si, lv;                                                         \
        const uint8_t *sp;                                                       \
        size_t sl, consumed;                                                     \
        memset(seedA, 0x11, sizeof(seedA));                                      \
        memset(seedB, 0x22, sizeof(seedB));                                      \
        memset(ukA, 0x33, sizeof(ukA));                                          \
        memset(ukB, 0x44, sizeof(ukB));                                          \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbA, skbA, seedA), GY_OK);   \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbB, skbB, seedB), GY_OK);   \
                                                                                 \
        /* Create: A generates gk, builds itself as sole admin, signs. */        \
        ASSERT_EQ(gy_qspgs_group_key_gen(suite, gk), GY_OK);                     \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);           \
        memset(mem, 0, sizeof(mem));                                             \
        ASSERT_EQ(gy_qspgs_member_build(suite, QAEAD, ek, ops_gid, rrs, uidA,    \
                                        sizeof(uidA), ukA, vkbA, 1, &mem[0],     \
                                        mctA, sizeof(mctA), &mctlen, vkhash),    \
                  GY_OK);                                                        \
        memset(&core, 0, sizeof(core));                                          \
        core.suite_id = suite;                                                   \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                           \
        memcpy(core.gid, ops_gid, sizeof(core.gid));                             \
        core.vmaj = 1;                                                           \
        memset(core.fet, 0x08, sizeof(core.fet));                                \
        core.last_vmin = 0;                                                      \
        core.members = mem;                                                      \
        core.n_members = 1;                                                      \
        core.vkhash = vkhash;                                                    \
        core.n_vk = 1;                                                           \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxA, suite, gk, skbA, vkbA, uidA,   \
                                           sizeof(uidA)),                        \
                  GY_OK);                                                        \
        n = sizeof(coresig);                                                     \
        ASSERT_EQ(gy_qspgs_core_sign(&core, 0, &ctxA, coresig,                   \
                                     sizeof(coresig), &n, scratch,               \
                                     sizeof(scratch)),                           \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_core_sig_decode(suite, coresig, n, &si, &lv, &sp,     \
                                           &sl, &consumed),                      \
                  GY_OK);                                                        \
        ASSERT_EQ(si, (uint32_t)0);                                              \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,        \
                                               sizeof(uidA), sp, sl, scratch,    \
                                               sizeof(scratch)),                 \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_member_decrypt(suite, QAEAD, ek, ops_gid, &mem[0],    \
                                          &view),                                \
                  GY_OK);                                                        \
        ASSERT_MEMEQ(view.uid, uidA, sizeof(uidA));                              \
        ASSERT_MEMEQ(view.uk, ukA, mklen);                                       \
        ASSERT_EQ(view.admn, 1);                                                 \
        gy_qspgs_member_view_clear(&view);                                       \
                                                                                 \
        /* AddMember: A appends B as a non-admin, re-signs. */                   \
        ASSERT_EQ(gy_qspgs_member_build(suite, QAEAD, ek, ops_gid, rrs, uidB,    \
                                        sizeof(uidB), ukB, vkbB, 0, &mem[1],     \
                                        mctB, sizeof(mctB), &mctlen,             \
                                        vkhash + hlen),                          \
                  GY_OK);                                                        \
        core.n_members = 2;                                                      \
        core.n_vk = 2;                                                           \
        n = sizeof(coresig);                                                     \
        ASSERT_EQ(gy_qspgs_core_sign(&core, 0, &ctxA, coresig,                   \
                                     sizeof(coresig), &n, scratch,               \
                                     sizeof(scratch)),                           \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_core_sig_decode(suite, coresig, n, &si, &lv, &sp,     \
                                           &sl, &consumed),                      \
                  GY_OK);                                                        \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,        \
                                               sizeof(uidA), sp, sl, scratch,    \
                                               sizeof(scratch)),                 \
                  GY_OK);                                                        \
        /* B's line attributes to B, and B's entry decrypts. */                  \
        ASSERT_EQ(gy_qspgs_attribute_hash(suite, rrs, vkbB, uidB,                \
                                          sizeof(uidB), view_hash),              \
                  GY_OK);                                                        \
        ASSERT_MEMEQ(view_hash, vkhash + hlen, hlen);                            \
        ASSERT_EQ(gy_qspgs_member_decrypt(suite, QAEAD, ek, ops_gid, &mem[1],    \
                                          &view),                                \
                  GY_OK);                                                        \
        ASSERT_MEMEQ(view.uid, uidB, sizeof(uidB));                              \
        ASSERT_MEMEQ(view.uk, ukB, mklen);                                       \
        ASSERT_EQ(view.admn, 0);                                                 \
        gy_qspgs_member_view_clear(&view);                                       \
        memcpy(oldB, vkhash + hlen, hlen); /* B's pre-rotation vk-lst hash. */   \
        gy_qspgs_member_ctx_clear(&ctxA);                                        \
                                                                                 \
        /* RemoveMember B: rotate gk, rebuild survivor A, bump vMaj, re-sign. */ \
        {                                                                        \
            uint8_t gk2[GY_QSPGS_MASTER_KEY_MAX];                                \
            uint8_t ek2[GY_QSPGS_EK_BYTES], rrs2[GY_QSPGS_RRS_BYTES];            \
            uint8_t vkhash2[GY_QSPGS_HASH_MAX], mctA2[256];                      \
            struct gy_qspgs_member mem2[1];                                      \
            struct gy_qspgs_member_ctx ctxA2;                                    \
            struct gy_qspgs_core core2;                                          \
            ASSERT_EQ(gy_qspgs_group_key_gen(suite, gk2), GY_OK);                \
            ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk2, ek2, rrs2), GY_OK);    \
            memset(mem2, 0, sizeof(mem2));                                       \
            ASSERT_EQ(gy_qspgs_member_build(suite, QAEAD, ek2, ops_gid, rrs2,    \
                                            uidA, sizeof(uidA), ukA, vkbA, 1,    \
                                            &mem2[0], mctA2, sizeof(mctA2),      \
                                            &mctlen, vkhash2),                   \
                      GY_OK);                                                    \
            memset(&core2, 0, sizeof(core2));                                    \
            core2.suite_id = suite;                                              \
            core2.format_version = GY_QSPGS_FORMAT_VERSION;                      \
            memcpy(core2.gid, ops_gid, sizeof(core2.gid));                       \
            core2.vmaj = 2;                                                      \
            memset(core2.fet, 0x08, sizeof(core2.fet));                          \
            core2.last_vmin = 0;                                                 \
            core2.members = mem2;                                                \
            core2.n_members = 1;                                                 \
            core2.vkhash = vkhash2;                                              \
            core2.n_vk = 1;                                                      \
            ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxA2, suite, gk2, skbA, vkbA,   \
                                               uidA, sizeof(uidA)),              \
                      GY_OK);                                                    \
            n = sizeof(coresig);                                                 \
            ASSERT_EQ(gy_qspgs_core_sign(&core2, 0, &ctxA2, coresig,             \
                                         sizeof(coresig), &n, scratch,           \
                                         sizeof(scratch)),                       \
                      GY_OK);                                                    \
            ASSERT_EQ(gy_qspgs_core_sig_decode(suite, coresig, n, &si, &lv,      \
                                               &sp, &sl, &consumed),             \
                      GY_OK);                                                    \
            ASSERT_EQ(gy_qspgs_core_resolve_verify(&core2, 0, rrs2, vkbA,        \
                                                   uidA, sizeof(uidA), sp, sl,   \
                                                   scratch, sizeof(scratch)),    \
                      GY_OK);                                                    \
            /* The removed member's pseudonym is invalidated by the new rrs. */  \
            ASSERT_EQ(gy_qspgs_attribute_hash(suite, rrs2, vkbB, uidB,           \
                                              sizeof(uidB), view_hash),          \
                      GY_OK);                                                    \
            ASSERT_TRUE(memcmp(view_hash, oldB, hlen) != 0,                      \
                        "gk rotation must change the removed pseudonym");        \
            gy_qspgs_member_ctx_clear(&ctxA2);                                   \
        }                                                                        \
    }

GEN3(44, GY_SUITE_H25519_512)
GEN3(87, GY_SUITE_H448_1024)
/*
 * Increment 4: the join link and the appendix (non-admin) lines.
 */
#define GEN5(set, suite)                                                        \
    TEST(q##set##_joinlink)                                                     \
    {                                                                           \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX], fet[GY_QSPGS_FET_LEN];             \
        uint8_t jls[GY_QSPGS_JOINLINK_SECRET], jls2[GY_QSPGS_JOINLINK_SECRET];  \
        uint8_t slot[256];                                                      \
        uint8_t gk_out[GY_QSPGS_MASTER_KEY_MAX], fet_out[GY_QSPGS_FET_LEN];     \
        size_t mklen = gy_qspgs_master_key_len(suite);                          \
        size_t slotlen = sizeof(slot);                                          \
        memset(gk, 0x71, sizeof(gk));                                           \
        memset(fet, 0x62, sizeof(fet));                                         \
        memset(jls, 0x53, sizeof(jls));                                         \
                                                                                \
        ASSERT_EQ(gy_qspgs_joinlink_seal(suite, QAEAD, jls, ops_gid, gk, fet,   \
                                         slot, slotlen, &slotlen),              \
                  GY_OK);                                                       \
        ASSERT_EQ(gy_qspgs_joinlink_open(suite, QAEAD, jls, ops_gid, slot,      \
                                         slotlen, gk_out, fet_out),             \
                  GY_OK);                                                       \
        ASSERT_MEMEQ(gk_out, gk, mklen);                                        \
        ASSERT_MEMEQ(fet_out, fet, GY_QSPGS_FET_LEN);                           \
        /* Wrong link secret => reject. */                                      \
        memcpy(jls2, jls, sizeof(jls2));                                        \
        jls2[0] ^= 0x01;                                                        \
        ASSERT_EQ(gy_qspgs_joinlink_open(suite, QAEAD, jls2, ops_gid, slot,     \
                                         slotlen, gk_out, fet_out),             \
                  GY_ERR_VERIFY);                                               \
        /* Tampered slot => reject. */                                          \
        slot[slotlen - 1] ^= 0x01;                                              \
        ASSERT_EQ(gy_qspgs_joinlink_open(suite, QAEAD, jls, ops_gid, slot,      \
                                         slotlen, gk_out, fet_out),             \
                  GY_ERR_VERIFY);                                               \
        slot[slotlen - 1] ^= 0x01;                                              \
    }                                                                           \
                                                                                \
    TEST(q##set##_appendix)                                                     \
    {                                                                           \
        const struct gy_suite_desc *d = gy_suite_desc(suite);                   \
        size_t hlen = d->hash_len;                                              \
        size_t mklen = gy_qspgs_master_key_len(suite);                          \
        uint8_t seedA[32], seedC[32];                                           \
        uint8_t vkbA[GY_QSPGS_VKB_MAX], skbA[GY_QSPGS_SKB_MAX];                 \
        uint8_t vkbC[GY_QSPGS_VKB_MAX], skbC[GY_QSPGS_SKB_MAX];                 \
        const uint8_t uidA[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2, 0xa3};        \
        const uint8_t uidC[GY_QSPGS_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3};        \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                    \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                 \
        uint8_t ukp[GY_QSPGS_MASTER_KEY_MAX], rc_open[GY_QSPGS_RC_LEN];         \
        uint8_t vkhashA[GY_QSPGS_HASH_MAX], badhash[GY_QSPGS_HASH_MAX];         \
        uint8_t payload[256], sig[GY_QSPGS_SIG_MAX], scratch[4096];             \
        struct gy_qspgs_member_ctx ctxA, ctxC;                                  \
        struct gy_qspgs_apx_line line;                                          \
        size_t plen = sizeof(payload), siglen;                                  \
        memset(seedA, 0x11, sizeof(seedA));                                     \
        memset(seedC, 0x33, sizeof(seedC));                                     \
        memset(gk, 0x24, sizeof(gk));                                           \
        memset(ukp, 0x77, sizeof(ukp));                                         \
        memset(rc_open, 0x1a, sizeof(rc_open));                                 \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbA, skbA, seedA), GY_OK);  \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbC, skbC, seedC), GY_OK);  \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);          \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxA, suite, gk, skbA, vkbA, uidA,  \
                                           sizeof(uidA)),                       \
                  GY_OK);                                                       \
        ASSERT_EQ(gy_qspgs_attribute_hash(suite, rrs, vkbA, uidA,               \
                                          sizeof(uidA), vkhashA),               \
                  GY_OK);                                                       \
                                                                                \
        /* Refresh line by an existing member (A, index 0). */                  \
        ASSERT_EQ(gy_qspgs_field_seal(suite, QAEAD, ek, GY_QSPGS_FIELD_UK,      \
                                      ops_gid, ukp, mklen, payload, plen,       \
                                      &plen),                                   \
                  GY_OK);                                                       \
        ASSERT_EQ(gy_qspgs_apx_line_sign(suite, &ctxA, ops_gid, 3, 1,           \
                                         GY_QAPX_REFRESH, 0, payload, plen,     \
                                         sig, sizeof(sig), &siglen, scratch,    \
                                         sizeof(scratch)),                      \
                  GY_OK);                                                       \
        memset(&line, 0, sizeof(line));                                         \
        line.line_type = GY_QAPX_REFRESH;                                       \
        line.author_index = 0;                                                  \
        line.payload = payload;                                                 \
        line.payload_len = plen;                                                \
        line.sig = sig;                                                         \
        line.sig_len = siglen;                                                  \
        ASSERT_EQ(gy_qspgs_apx_line_resolve_verify(                             \
                      suite, ops_gid, 3, 1, &line, rrs, vkbA, uidA,             \
                      sizeof(uidA), vkhashA, scratch, sizeof(scratch)),         \
                  GY_OK);                                                       \
        /* A different apx-hdr version fails the line signature (E1). */        \
        ASSERT_EQ(gy_qspgs_apx_line_resolve_verify(                             \
                      suite, ops_gid, 3, 2, &line, rrs, vkbA, uidA,             \
                      sizeof(uidA), vkhashA, scratch, sizeof(scratch)),         \
                  GY_ERR_VERIFY);                                               \
        /* A wrong stored vk-lst hash => reject. */                             \
        memcpy(badhash, vkhashA, hlen);                                         \
        badhash[0] ^= 0x01;                                                     \
        ASSERT_EQ(gy_qspgs_apx_line_resolve_verify(                             \
                      suite, ops_gid, 3, 1, &line, rrs, vkbA, uidA,             \
                      sizeof(uidA), badhash, scratch, sizeof(scratch)),         \
                  GY_ERR_VERIFY);                                               \
        /* A tampered payload fails the line signature (hash check skipped). */ \
        payload[0] ^= 0x01;                                                     \
        ASSERT_EQ(gy_qspgs_apx_line_resolve_verify(                             \
                      suite, ops_gid, 3, 1, &line, rrs, vkbA, uidA,             \
                      sizeof(uidA), NULL, scratch, sizeof(scratch)),            \
                  GY_ERR_VERIFY);                                               \
        payload[0] ^= 0x01;                                                     \
                                                                                \
        /* Join line by a newcomer (C) whose vkpsdn is NOT in the vk-lst. */    \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxC, suite, gk, skbC, vkbC, uidC,  \
                                           sizeof(uidC)),                       \
                  GY_OK);                                                       \
        {                                                                       \
            uint8_t jpl[256], jsig[GY_QSPGS_SIG_MAX];                           \
            struct gy_qspgs_apx_line jline;                                     \
            size_t jplen = sizeof(jpl), jsiglen;                                \
            ASSERT_EQ(gy_qspgs_member_ct_seal(suite, QAEAD, ek, ops_gid, uidC,  \
                                              sizeof(uidC), rc_open, ukp, jpl,  \
                                              jplen, &jplen),                   \
                      GY_OK);                                                   \
            ASSERT_EQ(gy_qspgs_apx_line_sign(suite, &ctxC, ops_gid, 3, 1,       \
                                             GY_QAPX_JOIN, 1, jpl, jplen,       \
                                             jsig, sizeof(jsig), &jsiglen,      \
                                             scratch, sizeof(scratch)),         \
                      GY_OK);                                                   \
            memset(&jline, 0, sizeof(jline));                                   \
            jline.line_type = GY_QAPX_JOIN;                                     \
            jline.author_index = 1;                                             \
            jline.payload = jpl;                                                \
            jline.payload_len = jplen;                                          \
            jline.sig = jsig;                                                   \
            jline.sig_len = jsiglen;                                            \
            ASSERT_EQ(gy_qspgs_apx_line_resolve_verify(                         \
                          suite, ops_gid, 3, 1, &jline, rrs, vkbC, uidC,        \
                          sizeof(uidC), NULL, scratch, sizeof(scratch)),        \
                      GY_OK);                                                   \
        }                                                                       \
        gy_qspgs_member_ctx_clear(&ctxA);                                       \
        gy_qspgs_member_ctx_clear(&ctxC);                                       \
    }

GEN4(44, GY_SUITE_H25519_512)
GEN4(87, GY_SUITE_H448_1024)
/*
 * Increment 5: the client-side negative matrix (section 6).  A forged
 * pseudonym signature, a cross-group replay, and a foreign-rho (wrong signer)
 * attribution are each rejected.  (The non-admin admin-only edit and the
 * stale-version compare-and-swap are section 7.3 SERVER checks.)
 */
#define GEN6(set, suite)                                                        \
    TEST(q##set##_negatives)                                                    \
    {                                                                           \
        uint8_t seedA[32], seedB[32];                                           \
        uint8_t vkbA[GY_QSPGS_VKB_MAX], skbA[GY_QSPGS_SKB_MAX];                 \
        uint8_t vkbB[GY_QSPGS_VKB_MAX], skbB[GY_QSPGS_SKB_MAX];                 \
        const uint8_t uidA[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2, 0xa3};        \
        const uint8_t uidB[GY_QSPGS_UID_LEN] = {0xb0, 0xb1, 0xb2, 0xb3};        \
        uint8_t ukA[GY_QSPGS_MASTER_KEY_MAX];                                   \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                    \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                 \
        uint8_t vkhash[GY_QSPGS_HASH_MAX], mctA[256];                           \
        struct gy_qspgs_member mem[1];                                          \
        struct gy_qspgs_core core;                                              \
        struct gy_qspgs_member_ctx ctxA;                                        \
        uint8_t coresig[8192], scratch[4096];                                   \
        size_t mctlen, n;                                                       \
        uint32_t si, lv;                                                        \
        const uint8_t *sp;                                                      \
        size_t sl, consumed;                                                    \
        memset(seedA, 0x11, sizeof(seedA));                                     \
        memset(seedB, 0x22, sizeof(seedB));                                     \
        memset(ukA, 0x33, sizeof(ukA));                                         \
        memset(gk, 0x24, sizeof(gk));                                           \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbA, skbA, seedA), GY_OK);  \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbB, skbB, seedB), GY_OK);  \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);          \
        memset(mem, 0, sizeof(mem));                                            \
        ASSERT_EQ(gy_qspgs_member_build(suite, QAEAD, ek, ops_gid, rrs, uidA,   \
                                        sizeof(uidA), ukA, vkbA, 1, &mem[0],    \
                                        mctA, sizeof(mctA), &mctlen, vkhash),   \
                  GY_OK);                                                       \
        memset(&core, 0, sizeof(core));                                         \
        core.suite_id = suite;                                                  \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                          \
        memcpy(core.gid, ops_gid, sizeof(core.gid));                            \
        core.vmaj = 1;                                                          \
        memset(core.fet, 0x08, sizeof(core.fet));                               \
        core.members = mem;                                                     \
        core.n_members = 1;                                                     \
        core.vkhash = vkhash;                                                   \
        core.n_vk = 1;                                                          \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxA, suite, gk, skbA, vkbA, uidA,  \
                                           sizeof(uidA)),                       \
                  GY_OK);                                                       \
        n = sizeof(coresig);                                                    \
        ASSERT_EQ(gy_qspgs_core_sign(&core, 0, &ctxA, coresig,                  \
                                     sizeof(coresig), &n, scratch,              \
                                     sizeof(scratch)),                          \
                  GY_OK);                                                       \
        ASSERT_EQ(gy_qspgs_core_sig_decode(suite, coresig, n, &si, &lv, &sp,    \
                                           &sl, &consumed),                     \
                  GY_OK);                                                       \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,       \
                                               sizeof(uidA), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_OK);                                                       \
                                                                                \
        /* Forged pseudonym signature (a signature byte flipped). */            \
        coresig[n - 1] ^= 0x01;                                                 \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,       \
                                               sizeof(uidA), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_ERR_VERIFY);                                               \
        coresig[n - 1] ^= 0x01;                                                 \
        /* Cross-group replay (GID no longer matches the signed TBS). */        \
        core.gid[0] ^= 0x01;                                                    \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,       \
                                               sizeof(uidA), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_ERR_VERIFY);                                               \
        core.gid[0] ^= 0x01;                                                    \
        /* Format-epoch tamper (format_version rides the signed header TBS). */ \
        core.format_version ^= 0x01;                                            \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,       \
                                               sizeof(uidA), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_ERR_VERIFY);                                               \
        core.format_version ^= 0x01;                                            \
        /* Foreign rho: attributing A's line to B's identity fails the hash. */ \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbB, uidB,       \
                                               sizeof(uidB), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_ERR_VERIFY);                                               \
        /* Undamaged still verifies. */                                         \
        ASSERT_EQ(gy_qspgs_core_resolve_verify(&core, 0, rrs, vkbA, uidA,       \
                                               sizeof(uidA), sp, sl, scratch,   \
                                               sizeof(scratch)),                \
                  GY_OK);                                                       \
        gy_qspgs_member_ctx_clear(&ctxA);                                       \
    }

/*
 * The section 7.3 SERVER acceptance checks (items 1-3),
 * exercised against a real client-signed core and a real client-signed appendix
 * line.  The server has no rrs: it verifies under the FULL vkpsdn the member
 * supplies (here the admin's ctxA.vkr), resolves it against the stored vk-lst
 * hash, and gates a core edit on the signer's admn flag.  The non-admin
 * admin-only edit negative (item 1) lives here; the stale-version negative is
 * increment 3 (version discipline).
 */
#define GEN7(set, suite)                                                              \
    TEST(q##set##_server)                                                             \
    {                                                                                 \
        uint8_t seedA[32];                                                            \
        uint8_t vkbA[GY_QSPGS_VKB_MAX], skbA[GY_QSPGS_SKB_MAX];                       \
        const uint8_t uidA[GY_QSPGS_UID_LEN] = {0xa0, 0xa1, 0xa2, 0xa3};              \
        uint8_t ukA[GY_QSPGS_MASTER_KEY_MAX];                                         \
        uint8_t gk[GY_QSPGS_MASTER_KEY_MAX];                                          \
        uint8_t ek[GY_QSPGS_EK_BYTES], rrs[GY_QSPGS_RRS_BYTES];                       \
        uint8_t vkhash[GY_QSPGS_HASH_MAX], mctA[256];                                 \
        uint8_t badvkr[GY_KR##set##_VKR];                                             \
        struct gy_qspgs_member mem[1], pmem[1];                                       \
        struct gy_qspgs_core core, prior;                                             \
        struct gy_qspgs_member_ctx ctxA;                                              \
        struct gy_qspgs_apx_line line;                                                \
        uint8_t coresig[8192], scratch[4096];                                         \
        uint8_t payload[256], apxsig[GY_QSPGS_SIG_MAX];                               \
        size_t mctlen, n, plen = sizeof(payload), apxlen;                             \
        size_t mklen = gy_qspgs_master_key_len(suite);                                \
        uint32_t si, lv;                                                              \
        const uint8_t *sp;                                                            \
        size_t sl, consumed;                                                          \
        memset(seedA, 0x11, sizeof(seedA));                                           \
        memset(ukA, 0x33, sizeof(ukA));                                               \
        memset(gk, 0x24, sizeof(gk));                                                 \
        ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbA, skbA, seedA), GY_OK);        \
        ASSERT_EQ(gy_qspgs_derive_sub_key(suite, gk, ek, rrs), GY_OK);                \
        memset(mem, 0, sizeof(mem));                                                  \
        ASSERT_EQ(gy_qspgs_member_build(suite, QAEAD, ek, ops_gid, rrs, uidA,         \
                                        sizeof(uidA), ukA, vkbA, 1, &mem[0],          \
                                        mctA, sizeof(mctA), &mctlen, vkhash),         \
                  GY_OK);                                                             \
        memset(&core, 0, sizeof(core));                                               \
        core.suite_id = suite;                                                        \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                                \
        core.aead_id = QAEAD;                                                         \
        memcpy(core.gid, ops_gid, sizeof(core.gid));                                  \
        core.vmaj = 1;                                                                \
        memset(core.fet, 0x08, sizeof(core.fet));                                     \
        core.members = mem;                                                           \
        core.n_members = 1;                                                           \
        core.vkhash = vkhash;                                                         \
        core.n_vk = 1;                                                                \
        ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxA, suite, gk, skbA, vkbA, uidA,        \
                                           sizeof(uidA)),                             \
                  GY_OK);                                                             \
        n = sizeof(coresig);                                                          \
        ASSERT_EQ(gy_qspgs_core_sign(&core, 0, &ctxA, coresig,                        \
                                     sizeof(coresig), &n, scratch,                    \
                                     sizeof(scratch)),                                \
                  GY_OK);                                                             \
        ASSERT_EQ(gy_qspgs_core_sig_decode(suite, coresig, n, &si, &lv, &sp,          \
                                           &sl, &consumed),                           \
                  GY_OK);                                                             \
                                                                                      \
        /* The signed core is a CREATE (vMaj 1, sole admin member): accepted    \
         * with no prior, the signer resolving against the submitted vk-lst. */     \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_OK);                                                             \
        /* CREATE with a non-admin sole member is rejected. */                        \
        mem[0].admn = 0;                                                              \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_ERR_VERIFY);                                                     \
        mem[0].admn = 1;                                                              \
        /* Item 3: a supplied key that does not hash to the stored H(vkpsdn). */      \
        memcpy(badvkr, ctxA.vkr, sizeof(badvkr));                                     \
        badvkr[0] ^= 0x01;                                                            \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, badvkr, sp, sl, scratch,              \
                                             sizeof(scratch)),                        \
                  GY_ERR_VERIFY);                                                     \
        /* A forged signature under the resolved key. */                              \
        coresig[n - 1] ^= 0x01;                                                       \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_ERR_VERIFY);                                                     \
        coresig[n - 1] ^= 0x01;                                                       \
        /* signer_index != 0 for a CREATE, and NULL inputs. */                        \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             1, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_ERR_ARG);                                                        \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, NULL,          \
                                             0, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_ERR_ARG);                                                        \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, NULL, sp, sl, scratch,                \
                                             sizeof(scratch)),                        \
                  GY_ERR_ARG);                                                        \
        /* Undamaged CREATE still accepted. */                                        \
        ASSERT_EQ(gy_qspgs_server_core_check(NULL, GY_QSPGS_OP_CREATE, &core,         \
                                             0, ctxA.vkr, sp, sl, scratch,            \
                                             sizeof(scratch)),                        \
                  GY_OK);                                                             \
        /* D-QGS-13 E2 self-promotion: a member that is a NON-ADMIN in the        \
         * prior version signs a next core (validly, under its own key) that      \
         * flips its own admn bit.  The admn gate reads the PRIOR mem-lst, so     \
         * the edit is rejected though the signature verifies.  prior mirrors     \
         * core with admn 0; next is the validly signed core (admn 1) and its     \
         * vk-lst equals prior's (UNCHANGED). */   \
        pmem[0] = mem[0];                                                             \
        pmem[0].admn = 0;                                                             \
        prior = core;                                                                 \
        prior.members = pmem;                                                         \
        prior.vmaj = core.vmaj - 1; /* next advances vMaj by one (E13). */            \
        ASSERT_EQ(gy_qspgs_server_core_check(&prior, GY_QSPGS_OP_UNCHANGED,           \
                                             &core, 0, ctxA.vkr, sp, sl,              \
                                             scratch, sizeof(scratch)),               \
                  GY_ERR_VERIFY);                                                     \
        /* Same next, but now the prior DID make this member an admin: the        \
         * UNCHANGED edit is accepted (lineage holds). */   \
        pmem[0].admn = 1;                                                             \
        ASSERT_EQ(gy_qspgs_server_core_check(&prior, GY_QSPGS_OP_UNCHANGED,           \
                                             &core, 0, ctxA.vkr, sp, sl,              \
                                             scratch, sizeof(scratch)),               \
                  GY_OK);                                                             \
        /* SEC-v1.5.0 INFO-2: format_version and the GID are immutable across  \
         * versions; perturbing either on the otherwise-valid next is rejected \
         * before any signature check (defense in depth, D-QGS-12). */      \
        core.format_version = GY_QSPGS_FORMAT_VERSION + 1;                            \
        ASSERT_EQ(gy_qspgs_server_core_check(&prior, GY_QSPGS_OP_UNCHANGED,           \
                                             &core, 0, ctxA.vkr, sp, sl,              \
                                             scratch, sizeof(scratch)),               \
                  GY_ERR_VERIFY);                                                     \
        core.format_version = GY_QSPGS_FORMAT_VERSION;                                \
        core.gid[0] ^= 0x01;                                                          \
        ASSERT_EQ(gy_qspgs_server_core_check(&prior, GY_QSPGS_OP_UNCHANGED,           \
                                             &core, 0, ctxA.vkr, sp, sl,              \
                                             scratch, sizeof(scratch)),               \
                  GY_ERR_VERIFY);                                                     \
        core.gid[0] ^= 0x01;                                                          \
        /* D-QGS-14 E13: the same next against a prior at the SAME vMaj (no         \
         * one-major advance) is rejected by the server lineage check. */ \
        prior.vmaj = core.vmaj;                                                       \
        ASSERT_EQ(gy_qspgs_server_core_check(&prior, GY_QSPGS_OP_UNCHANGED,           \
                                             &core, 0, ctxA.vkr, sp, sl,              \
                                             scratch, sizeof(scratch)),               \
                  GY_ERR_VERIFY);                                                     \
        prior.vmaj = core.vmaj - 1; /* restore the valid lineage. */                  \
                                                                                      \
        /* Item 2: an appendix line (A's Refresh) accepted, then rejected under \
         * a wrong stored hash and a tampered payload. */     \
        ASSERT_EQ(gy_qspgs_field_seal(suite, QAEAD, ek, GY_QSPGS_FIELD_UK,            \
                                      ops_gid, ukA, mklen, payload, plen,             \
                                      &plen),                                         \
                  GY_OK);                                                             \
        ASSERT_EQ(gy_qspgs_apx_line_sign(suite, &ctxA, ops_gid, 3, 1,                 \
                                         GY_QAPX_REFRESH, 0, payload, plen,           \
                                         apxsig, sizeof(apxsig), &apxlen,             \
                                         scratch, sizeof(scratch)),                   \
                  GY_OK);                                                             \
        memset(&line, 0, sizeof(line));                                               \
        line.line_type = GY_QAPX_REFRESH;                                             \
        line.author_index = 0;                                                        \
        line.payload = payload;                                                       \
        line.payload_len = plen;                                                      \
        line.sig = apxsig;                                                            \
        line.sig_len = apxlen;                                                        \
        ASSERT_EQ(gy_qspgs_server_apx_check(suite, ops_gid, 3, 1, &line,              \
                                            ctxA.vkr, vkhash, scratch,                \
                                            sizeof(scratch)),                         \
                  GY_OK);                                                             \
        /* A different apx-hdr version fails the server-side check (E1). */           \
        ASSERT_EQ(gy_qspgs_server_apx_check(suite, ops_gid, 4, 1, &line,              \
                                            ctxA.vkr, vkhash, scratch,                \
                                            sizeof(scratch)),                         \
                  GY_ERR_VERIFY);                                                     \
        vkhash[0] ^= 0x01;                                                            \
        ASSERT_EQ(gy_qspgs_server_apx_check(suite, ops_gid, 3, 1, &line,              \
                                            ctxA.vkr, vkhash, scratch,                \
                                            sizeof(scratch)),                         \
                  GY_ERR_VERIFY);                                                     \
        vkhash[0] ^= 0x01;                                                            \
        payload[0] ^= 0x01;                                                           \
        ASSERT_EQ(gy_qspgs_server_apx_check(suite, ops_gid, 3, 1, &line,              \
                                            ctxA.vkr, NULL, scratch,                  \
                                            sizeof(scratch)),                         \
                  GY_ERR_VERIFY);                                                     \
        payload[0] ^= 0x01;                                                           \
                                                                                      \
        /* Item 2 newcomer path: a JoinViaLink newcomer (C) whose vkpsdn is not  \
         * yet in the vk-lst is accepted with the stored-hash resolution skipped  \
         * (stored_vkhash NULL); the deployer appends H(vkr) on acceptance. */    \
        {                                                                             \
            uint8_t seedC[32], vkbC[GY_QSPGS_VKB_MAX], skbC[GY_QSPGS_SKB_MAX];        \
            const uint8_t uidC[GY_QSPGS_UID_LEN] = {0xc0, 0xc1, 0xc2, 0xc3};          \
            uint8_t rc_open[GY_QSPGS_RC_LEN], jpl[256],                               \
                jsig[GY_QSPGS_SIG_MAX];                                               \
            struct gy_qspgs_member_ctx ctxC;                                          \
            struct gy_qspgs_apx_line jline;                                           \
            size_t jplen = sizeof(jpl), jsiglen;                                      \
            memset(seedC, 0x5c, sizeof(seedC));                                       \
            memset(rc_open, 0x1a, sizeof(rc_open));                                   \
            ASSERT_EQ(gy_qspgs_base_keygen_seed(suite, vkbC, skbC, seedC),            \
                      GY_OK);                                                         \
            ASSERT_EQ(gy_qspgs_member_ctx_open(&ctxC, suite, gk, skbC, vkbC,          \
                                               uidC, sizeof(uidC)),                   \
                      GY_OK);                                                         \
            ASSERT_EQ(gy_qspgs_member_ct_seal(suite, QAEAD, ek, ops_gid, uidC,        \
                                              sizeof(uidC), rc_open, ukA, jpl,        \
                                              jplen, &jplen),                         \
                      GY_OK);                                                         \
            ASSERT_EQ(gy_qspgs_apx_line_sign(suite, &ctxC, ops_gid, 3, 1,             \
                                             GY_QAPX_JOIN, 1, jpl, jplen,             \
                                             jsig, sizeof(jsig), &jsiglen,            \
                                             scratch, sizeof(scratch)),               \
                      GY_OK);                                                         \
            memset(&jline, 0, sizeof(jline));                                         \
            jline.line_type = GY_QAPX_JOIN;                                           \
            jline.author_index = 1;                                                   \
            jline.payload = jpl;                                                      \
            jline.payload_len = jplen;                                                \
            jline.sig = jsig;                                                         \
            jline.sig_len = jsiglen;                                                  \
            ASSERT_EQ(gy_qspgs_server_apx_check(suite, ops_gid, 3, 1, &jline,         \
                                                ctxC.vkr, NULL, scratch,              \
                                                sizeof(scratch)),                     \
                      GY_OK);                                                         \
            gy_qspgs_member_ctx_clear(&ctxC);                                         \
        }                                                                             \
        gy_qspgs_member_ctx_clear(&ctxA);                                             \
    }

GEN5(44, GY_SUITE_H25519_512)
GEN5(87, GY_SUITE_H448_1024)
GEN6(44, GY_SUITE_H25519_512)
GEN6(87, GY_SUITE_H448_1024)
GEN7(44, GY_SUITE_H25519_512)
GEN7(87, GY_SUITE_H448_1024)

TEST(reject_ops_null_classical)
{
    struct gy_qspgs_member_ctx ctx;
    uint8_t ek[GY_QSPGS_EK_BYTES], gk[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t out[256];
    const uint8_t uid[GY_QSPGS_UID_LEN] = {0x01, 0x02};
    size_t outlen = sizeof(out);
    memset(ek, 0, sizeof(ek));
    memset(gk, 0, sizeof(gk));

    /* Hybrid-only. */
    ASSERT_EQ(gy_qspgs_field_seal(GY_SUITE_C25519, QAEAD, ek,
                                  GY_QSPGS_FIELD_ATTR, ops_gid, uid,
                                  sizeof(uid), out, outlen, &outlen),
              GY_ERR_ARG);
    ASSERT_EQ(gy_qspgs_member_ctx_open(&ctx, GY_SUITE_C448, gk, ek, ek, uid,
                                       sizeof(uid)),
              GY_ERR_ARG);

    /* Unknown field tag. */
    ASSERT_EQ(gy_qspgs_field_seal(GY_SUITE_H25519_512, QAEAD, ek, 0x7f, ops_gid,
                                  uid, sizeof(uid), out, outlen, &outlen),
              GY_ERR_ARG);

    /* NULL arguments. */
    ASSERT_EQ(gy_qspgs_member_ctx_open(NULL, GY_SUITE_H25519_512, gk, ek, ek,
                                       uid, sizeof(uid)),
              GY_ERR_ARG);

    /* clear is NULL-safe. */
    gy_qspgs_member_ctx_clear(NULL);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(q44_field_roundtrip),
            GY_TEST(q44_field_reject),
            GY_TEST(q44_member_ct_roundtrip),
            GY_TEST(q44_member_ctx),
            GY_TEST(q44_attribute),
            GY_TEST(q87_field_roundtrip),
            GY_TEST(q87_field_reject),
            GY_TEST(q87_member_ct_roundtrip),
            GY_TEST(q87_member_ctx),
            GY_TEST(q87_attribute),
            GY_TEST(q44_register_verify),
            GY_TEST(q44_invite_roundtrip),
            GY_TEST(q87_register_verify),
            GY_TEST(q87_invite_roundtrip),
            GY_TEST(q44_fetch_read),
            GY_TEST(q87_fetch_read),
            GY_TEST(q44_core_lifecycle),
            GY_TEST(q87_core_lifecycle),
            GY_TEST(q44_joinlink),
            GY_TEST(q44_appendix),
            GY_TEST(q87_joinlink),
            GY_TEST(q87_appendix),
            GY_TEST(q44_negatives),
            GY_TEST(q87_negatives),
            GY_TEST(q44_server),
            GY_TEST(q87_server),
            GY_TEST(reject_ops_null_classical),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
