/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Wire-format tests (GROUP_SPEC section 9): round-trip, strict-parse
 * negatives, and Table 1 wire footprints for the blind-issuance objects - the
 * section 3.3 blind-issuance objects (ProfileKeyCommitment / Request /
 * Response), the ProfileKeyVersion (grp-pkv), and the GROUP_KEY_DISTRIBUTION
 * envelope frame (section 9 item 4).  Both classical tiers.
 *
 * The codecs are pure fixed-layout byte shuffles (no crypto), so each field is
 * filled with a DISTINCT per-field, per-byte pattern (tag*7 + i) over exactly
 * the tier width, leaving the GY_GROUP_*_MAX tail zero as the real sub-calls
 * do.  A round-trip that permuted or misaligned any field would then fail the
 * whole-struct compare.  The AuthCredentialResponse / presentation / ciphertext
 * objects are covered by test_group_sizes and test_group_ops and are not
 * repeated here.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_issue.h"
#include "group_ops.h" /* GY_GROUP_PK_VERSION_BYTES */
#include "group_tier.h"
#include "group_wire.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* Fill n bytes with a distinct pattern keyed on tag (per-field, per-byte). */
static void
fillp(uint8_t *dst, size_t n, uint8_t tag)
{
    size_t i;
    for (i = 0; i < n; i++)
        dst[i] = (uint8_t)(tag * 7u + i);
}

/*
 * Thin uniform-signature decode wrappers so the header/length negative checks
 * can be shared across the objects (test scaffolding only, not a KAT seam).
 */
static int
dec_commit(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    struct gy_group_pk_commitment c;
    return gy_group_pk_commit_decode(t, &c, in, len);
}
static int
dec_request(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    struct gy_group_pk_request r;
    return gy_group_pk_request_decode(t, &r, in, len);
}
static int
dec_response(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    struct gy_group_pk_blind_response r;
    return gy_group_pk_response_decode(t, &r, in, len);
}
static int
dec_version(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    uint8_t v[GY_GROUP_PK_VERSION_BYTES];
    return gy_group_pk_version_decode(t, v, in, len);
}
static int
dec_kd(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    uint8_t mk[GY_GROUP_SCALAR_MAX];
    uint16_t fmtver;
    size_t mklen;
    return gy_group_key_distribution_decode(t, in, len, &fmtver, mk, sizeof(mk),
                                            &mklen);
}
static int
dec_memberlist(const struct gy_group_tier *t, const uint8_t *in, size_t len)
{
    struct gy_group_member_ct out[8];
    size_t n;
    return gy_group_member_list_decode(t, out, 8, &n, in, len);
}

/*
 * Shared strict-parse negatives on a 3-byte-header framed object: a truncated
 * frame, a trailing byte, and each of the three header bytes flipped, all
 * reject with GY_ERR_VERIFY.  good[0..len) is a valid encoding.
 */
static void
check_negatives(const struct gy_group_tier *tier,
                int (*dec)(const struct gy_group_tier *, const uint8_t *,
                           size_t),
                const uint8_t *good, size_t len)
{
    uint8_t tmp[1200];
    size_t i;

    ASSERT_EQ(dec(tier, good, len - 1), GY_ERR_VERIFY); /* truncated */

    memcpy(tmp, good, len);
    tmp[len] = 0xAB;
    ASSERT_EQ(dec(tier, tmp, len + 1), GY_ERR_VERIFY); /* trailing byte */

    for (i = 0; i < 3; i++) { /* each header byte corrupted */
        memcpy(tmp, good, len);
        tmp[i] ^= 0xFF;
        ASSERT_EQ(dec(tier, tmp, len), GY_ERR_VERIFY);
    }
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

TEST(wire_roundtrip)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        size_t plen, slen, mklen, hdr = GY_GROUP_OBJ_HDR_LEN;
        size_t need, outlen, i;
        uint8_t buf[1200];

        ASSERT_TRUE(tier != NULL, "tier");
        plen = tier->point_len;
        slen = tier->scalar_len;
        mklen = tier->master_key_len;

        /* --- ProfileKeyCommitment (3 points) --- */
        {
            struct gy_group_pk_commitment a, b;
            memset(&a, 0, sizeof(a));
            fillp(a.J1, plen, 1);
            fillp(a.J2, plen, 2);
            fillp(a.J3, plen, 3);
            need = hdr + 3 * plen;
            ASSERT_EQ(
                gy_group_pk_commit_encode(tier, &a, buf, sizeof(buf), &outlen),
                GY_OK);
            ASSERT_EQ(outlen, need);
            ASSERT_EQ(gy_group_pk_commit_decode(tier, &b, buf, outlen), GY_OK);
            ASSERT_MEMEQ(&a, &b, sizeof(a));
            check_negatives(tier, dec_commit, buf, outlen);
            /* short output buffer */
            ASSERT_EQ(
                gy_group_pk_commit_encode(tier, &a, buf, need - 1, &outlen),
                GY_ERR_TOOLONG);
        }

        /* --- ProfileKeyCredentialRequest (5 pts + BR_M pts + BR_K scalars) */
        {
            struct gy_group_pk_request a, b;
            memset(&a, 0, sizeof(a));
            fillp(a.Y, plen, 1);
            fillp(a.D1, plen, 2);
            fillp(a.D2, plen, 3);
            fillp(a.E1, plen, 4);
            fillp(a.E2, plen, 5);
            for (i = 0; i < GY_GROUP_PI_BR_M; i++)
                fillp(a.proof_V[i], plen, (uint8_t)(10 + i));
            for (i = 0; i < GY_GROUP_PI_BR_K; i++)
                fillp(a.proof_r[i], slen, (uint8_t)(20 + i));
            need = hdr + 5 * plen + GY_GROUP_PI_BR_M * plen +
                   GY_GROUP_PI_BR_K * slen;
            ASSERT_EQ(
                gy_group_pk_request_encode(tier, &a, buf, sizeof(buf), &outlen),
                GY_OK);
            ASSERT_EQ(outlen, need);
            ASSERT_EQ(gy_group_pk_request_decode(tier, &b, buf, outlen), GY_OK);
            ASSERT_MEMEQ(&a, &b, sizeof(a));
            check_negatives(tier, dec_request, buf, outlen);
        }

        /* --- ProfileKeyCredentialResponse (S1,S2,t,U + BI_M pts + BI_K sc) */
        {
            struct gy_group_pk_blind_response a, b;
            memset(&a, 0, sizeof(a));
            fillp(a.S1, plen, 1);
            fillp(a.S2, plen, 2);
            fillp(a.t, slen, 3);
            fillp(a.U, plen, 4);
            for (i = 0; i < GY_GROUP_PI_BI_M; i++)
                fillp(a.proof_V[i], plen, (uint8_t)(10 + i));
            for (i = 0; i < GY_GROUP_PI_BI_K; i++)
                fillp(a.proof_r[i], slen, (uint8_t)(20 + i));
            need = hdr + 3 * plen + slen + GY_GROUP_PI_BI_M * plen +
                   GY_GROUP_PI_BI_K * slen;
            ASSERT_EQ(gy_group_pk_response_encode(tier, &a, buf, sizeof(buf),
                                                  &outlen),
                      GY_OK);
            ASSERT_EQ(outlen, need);
            ASSERT_EQ(gy_group_pk_response_decode(tier, &b, buf, outlen),
                      GY_OK);
            ASSERT_MEMEQ(&a, &b, sizeof(a));
            check_negatives(tier, dec_response, buf, outlen);
        }

        /* --- ProfileKeyVersion (fixed 32 bytes) --- */
        {
            uint8_t v[GY_GROUP_PK_VERSION_BYTES], w[GY_GROUP_PK_VERSION_BYTES];
            fillp(v, sizeof(v), 7);
            need = hdr + GY_GROUP_PK_VERSION_BYTES;
            ASSERT_EQ(
                gy_group_pk_version_encode(tier, v, buf, sizeof(buf), &outlen),
                GY_OK);
            ASSERT_EQ(outlen, need);
            ASSERT_EQ(gy_group_pk_version_decode(tier, w, buf, outlen), GY_OK);
            ASSERT_MEMEQ(v, w, sizeof(v));
            check_negatives(tier, dec_version, buf, outlen);
        }

        /* --- GROUP_KEY_DISTRIBUTION envelope frame --- */
        {
            uint8_t mk[GY_GROUP_SCALAR_MAX], out_mk[GY_GROUP_SCALAR_MAX];
            uint16_t ver_in = 0x0102, ver_out = 0; /* BE16 carriage check */
            size_t out_mklen;
            memset(mk, 0, sizeof(mk));
            fillp(mk, mklen, 9);
            need = GY_GROUP_ENVELOPE_HDR_LEN + GY_GROUP_ENVELOPE_FMTVER_LEN +
                   mklen;
            ASSERT_EQ(gy_group_key_distribution_encode(
                          tier, ver_in, mk, mklen, buf, sizeof(buf), &outlen),
                      GY_OK);
            ASSERT_EQ(outlen, need);
            /* header is version || suite || msg_type (D-GEN-1, not obj order) */
            ASSERT_EQ(buf[0], GY_WIRE_VERSION);
            ASSERT_EQ(buf[1], tier->suite_id);
            ASSERT_EQ(buf[2], GY_MSG_GROUP_KEY_DISTRIBUTION);
            /* format version (BE16) rides ahead of the key */
            ASSERT_EQ(buf[3], 0x01);
            ASSERT_EQ(buf[4], 0x02);
            memset(out_mk, 0, sizeof(out_mk));
            ASSERT_EQ(gy_group_key_distribution_decode(
                          tier, buf, outlen, &ver_out, out_mk, sizeof(out_mk),
                          &out_mklen),
                      GY_OK);
            ASSERT_EQ(ver_out, ver_in);
            ASSERT_EQ(out_mklen, mklen);
            ASSERT_MEMEQ(mk, out_mk, mklen);
            check_negatives(tier, dec_kd, buf, outlen);
            /* wrong master-key length rejected at encode (GY_ERR_ARG) */
            ASSERT_EQ(gy_group_key_distribution_encode(tier, ver_in, mk,
                                                       mklen - 1, buf,
                                                       sizeof(buf), &outlen),
                      GY_ERR_ARG);
            /* undersized output caller buffer rejected */
            ASSERT_EQ(gy_group_key_distribution_decode(tier, buf, outlen,
                                                       &ver_out, out_mk,
                                                       mklen - 1, &out_mklen),
                      GY_ERR_ARG);
        }
    }
}

/*
 * Table 1 wire footprints (GROUP_SPEC section 9 acceptance).  The 255-tier
 * byte counts are pinned as explicit constants; both tiers are also checked
 * against the element-count formula.  These are geryon's own footprints (the
 * blind-issuance objects are not in the [CPZ] paper Table 1, which covers the
 * credential/ciphertext objects only), frozen here at first KATs.
 */
TEST(wire_footprints)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        size_t p, s, hdr = GY_GROUP_OBJ_HDR_LEN;
        size_t commit_len, request_len, response_len, version_len, kd_len;

        ASSERT_TRUE(tier != NULL, "tier");
        p = tier->point_len;
        s = tier->scalar_len;

        commit_len = hdr + 3 * p;
        request_len = hdr + 5 * p + GY_GROUP_PI_BR_M * p + GY_GROUP_PI_BR_K * s;
        response_len =
            hdr + 3 * p + s + GY_GROUP_PI_BI_M * p + GY_GROUP_PI_BI_K * s;
        version_len = hdr + GY_GROUP_PK_VERSION_BYTES;
        kd_len = GY_GROUP_ENVELOPE_HDR_LEN + GY_GROUP_ENVELOPE_FMTVER_LEN +
                 tier->master_key_len;

        if (tier->suite_id == GY_SUITE_C25519) {
            ASSERT_EQ(commit_len, 99);    /* 3 + 3*32 */
            ASSERT_EQ(request_len, 483);  /* 3 + 11*32 + 4*32 */
            ASSERT_EQ(response_len, 547); /* 3 + 7*32 + 10*32 */
            ASSERT_EQ(version_len, 35);   /* 3 + 32 */
            ASSERT_EQ(kd_len, 37);        /* 3 + 2 + 32 */
        } else {                          /* GY_SUITE_C448 */
            ASSERT_EQ(commit_len, 171);   /* 3 + 3*56 */
            ASSERT_EQ(request_len, 843);  /* 3 + 11*56 + 4*56 */
            ASSERT_EQ(response_len, 955); /* 3 + 7*56 + 10*56 */
            ASSERT_EQ(version_len, 35);   /* 3 + 32 (tier-independent) */
            ASSERT_EQ(kd_len, 61);        /* 3 + 2 + 56 */
        }
    }
}

/*
 * Member-entry list (Split C, section 9 item 2): fixed-width entries, the only
 * variability being the count.  Round-trip a mix of full and invited members,
 * then the member-specific strict-parse negatives (count over the bound, a bad
 * has_profile_key flag, a non-zero invited pk slot, an undersized caller view).
 */
TEST(member_list)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_member_ct ents[3], out[8];
        size_t plen, entry, need, outlen, n, hdr = GY_GROUP_OBJ_HDR_LEN;
        uint8_t buf[1200], tmp[1200];

        ASSERT_TRUE(tier != NULL, "tier");
        plen = tier->point_len;
        entry = 2 + 4 * plen;

        memset(ents, 0, sizeof(ents));
        /* Roles must be defined (<= GY_GROUP_ROLE_MAX); the strict codec rejects
         * any other value (see the member_list_role test). */
        ents[0].has_profile_key = 1;
        ents[0].role = GY_GROUP_ROLE_MAX; /* administrator */
        fillp(ents[0].uid_ct.E_A1, plen, 1);
        fillp(ents[0].uid_ct.E_A2, plen, 2);
        fillp(ents[0].pk_ct.E_B1, plen, 3);
        fillp(ents[0].pk_ct.E_B2, plen, 4);
        ents[1].has_profile_key = 1;
        ents[1].role = 0; /* default */
        fillp(ents[1].uid_ct.E_A1, plen, 5);
        fillp(ents[1].uid_ct.E_A2, plen, 6);
        fillp(ents[1].pk_ct.E_B1, plen, 7);
        fillp(ents[1].pk_ct.E_B2, plen, 8);
        ents[2].has_profile_key = 0; /* invited: uid only, pk slot stays zero */
        ents[2].role = 0;            /* default */
        fillp(ents[2].uid_ct.E_A1, plen, 9);
        fillp(ents[2].uid_ct.E_A2, plen, 10);

        need = hdr + 2 + 3 * entry;
        ASSERT_EQ(gy_group_member_list_encode(tier, ents, 3, buf, sizeof(buf),
                                              &outlen),
                  GY_OK);
        ASSERT_EQ(outlen, need);
        ASSERT_EQ(gy_group_member_list_decode(tier, out, 8, &n, buf, outlen),
                  GY_OK);
        ASSERT_EQ(n, 3);
        ASSERT_MEMEQ(ents, out, 3 * sizeof(ents[0]));

        /* empty list round-trips (count 0). */
        ASSERT_EQ(gy_group_member_list_encode(tier, NULL, 0, tmp, sizeof(tmp),
                                              &outlen),
                  GY_OK);
        ASSERT_EQ(outlen, hdr + 2);
        ASSERT_EQ(gy_group_member_list_decode(tier, out, 8, &n, tmp, outlen),
                  GY_OK);
        ASSERT_EQ(n, 0);

        /* shared header/length negatives. */
        check_negatives(tier, dec_memberlist, buf, need);

        /* count over GY_GROUP_MAX_ENTRIES (rejected before the length check). */
        memcpy(tmp, buf, need);
        tmp[hdr] = (uint8_t)((GY_GROUP_MAX_ENTRIES + 1) >> 8);
        tmp[hdr + 1] = (uint8_t)((GY_GROUP_MAX_ENTRIES + 1) & 0xff);
        ASSERT_EQ(dec_memberlist(tier, tmp, need), GY_ERR_VERIFY);

        /* has_profile_key byte outside {0,1}. */
        memcpy(tmp, buf, need);
        tmp[hdr + 2] = 2; /* first entry's flag */
        ASSERT_EQ(dec_memberlist(tier, tmp, need), GY_ERR_VERIFY);

        /* invited entry with a non-zero ProfileKeyCiphertext slot: entry 2 is
         * at offset hdr + 2 + 2*entry; its pk slot follows the flag/role and
         * the two uid-ct points. */
        memcpy(tmp, buf, need);
        tmp[hdr + 2 + 2 * entry + 2 + 2 * plen] ^= 0x01;
        ASSERT_EQ(dec_memberlist(tier, tmp, need), GY_ERR_VERIFY);

        /* caller view too small for the entry count. */
        ASSERT_EQ(gy_group_member_list_decode(tier, out, 1, &n, buf, need),
                  GY_ERR_TOOLONG);
    }
}

/*
 * Role-field validity (LOW-1): the member-list codec is strict on the role byte
 * in BOTH directions.  Every DEFINED role (0 .. GY_GROUP_ROLE_MAX) must
 * round-trip, and the first UNDEFINED value (GY_GROUP_ROLE_MAX + 1) must be
 * rejected - by the encoder with GY_ERR_ARG and by the decoder with the uniform
 * GY_ERR_VERIFY.  Written against GY_GROUP_ROLE_MAX so that adding a role (which
 * bumps the bound) keeps this test honest: the new role must then round-trip
 * here, and only values above the new bound are rejected.
 */
TEST(member_list_role)
{
    size_t si;

    for (si = 0; si < sizeof(suites); si++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[si]);
        struct gy_group_member_ct ent, out[2];
        size_t plen, outlen, n, hdr = GY_GROUP_OBJ_HDR_LEN;
        unsigned r;
        uint8_t buf[1200];

        ASSERT_TRUE(tier != NULL, "tier");
        plen = tier->point_len;

        /* Every defined role round-trips (invited entry keeps it short). */
        for (r = 0; r <= GY_GROUP_ROLE_MAX; r++) {
            memset(&ent, 0, sizeof(ent));
            ent.has_profile_key = 0;
            ent.role = (uint8_t)r;
            fillp(ent.uid_ct.E_A1, plen, 1);
            fillp(ent.uid_ct.E_A2, plen, 2);
            ASSERT_EQ(gy_group_member_list_encode(tier, &ent, 1, buf,
                                                  sizeof(buf), &outlen),
                      GY_OK);
            ASSERT_EQ(
                gy_group_member_list_decode(tier, out, 2, &n, buf, outlen),
                GY_OK);
            ASSERT_EQ(n, 1);
            ASSERT_EQ(out[0].role, (uint8_t)r);
        }

        /* An undefined role is rejected on ENCODE (GY_ERR_ARG): never emit a
         * roster a conforming decoder would reject. */
        memset(&ent, 0, sizeof(ent));
        ent.role = (uint8_t)(GY_GROUP_ROLE_MAX + 1);
        fillp(ent.uid_ct.E_A1, plen, 1);
        fillp(ent.uid_ct.E_A2, plen, 2);
        ASSERT_EQ(gy_group_member_list_encode(tier, &ent, 1, buf, sizeof(buf),
                                              &outlen),
                  GY_ERR_ARG);

        /* An undefined role in the WIRE is rejected on DECODE (GY_ERR_VERIFY):
         * encode a valid role-0 entry, then corrupt the first entry's role byte
         * (at hdr + count(2) + has_profile_key(1)). */
        memset(&ent, 0, sizeof(ent));
        ent.role = 0;
        fillp(ent.uid_ct.E_A1, plen, 1);
        fillp(ent.uid_ct.E_A2, plen, 2);
        ASSERT_EQ(gy_group_member_list_encode(tier, &ent, 1, buf, sizeof(buf),
                                              &outlen),
                  GY_OK);
        buf[hdr + 3] = (uint8_t)(GY_GROUP_ROLE_MAX + 1);
        ASSERT_EQ(gy_group_member_list_decode(tier, out, 2, &n, buf, outlen),
                  GY_ERR_VERIFY);
        buf[hdr + 3] = 0xFF; /* far out of range, also rejected */
        ASSERT_EQ(gy_group_member_list_decode(tier, out, 2, &n, buf, outlen),
                  GY_ERR_VERIFY);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(wire_roundtrip), GY_TEST(wire_footprints),
             GY_TEST(member_list), GY_TEST(member_list_role))
