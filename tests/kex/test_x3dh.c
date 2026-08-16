/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/kex/x3dh.c (D-X3DH-6/7/8/9/13/15, D-DR-13).
 * Built with -DGY_TEST_HOOKS: gy_kex_ctr proves parse/lookup failures abort
 * before any DH, and gy_x3dh_expand_secrets exposes the D-DR-13 expansion.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h"
#include "x3dh.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;

#define RESET_CTR() memset(&gy_kex_ctr, 0, sizeof(gy_kex_ctr))
static const uint64_t TS = 0x0000000155667788ull;

/* Classical c25519 prefix field offsets (curve_pk_len = 32, kw = 37). */
#define KW 37
#define OFF_IK 2
#define OFF_EK (2 + KW)
#define OFF_IKID (2 + 2 * KW)
#define OFF_SPKID (OFF_IKID + 4)
#define OFF_OPKID (OFF_SPKID + 4)
#define PREFIX_LEN (2 + 2 * KW + 16)

struct party {
    struct gy_keypair alice_ik;
    struct gy_keypair bob_ik;
    struct gy_signed_prekey bob_spk;
    struct gy_keypair bob_opk[1];
    struct gy_prekey_bundle bundle;
};

static void
setup(struct party *p, int with_opk)
{
    ASSERT_EQ(gy_keypair_generate(D, &p->alice_ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &p->bob_ik), GY_OK);
    ASSERT_EQ(gy_spk_create(D, &p->bob_spk, p->bob_ik.sk, TS), GY_OK);

    memset(&p->bundle, 0, sizeof(p->bundle));
    p->bundle.ik = p->bob_ik.pub;
    p->bundle.spk = p->bob_spk.kp.pub;
    p->bundle.spk_timestamp = TS;
    memcpy(p->bundle.spk_sig, p->bob_spk.sig, GY_SIG_MAX);
    if (with_opk) {
        ASSERT_EQ(gy_opk_batch(D, p->bob_opk, 1, NULL, 0), GY_OK);
        p->bundle.opk = p->bob_opk[0].pub;
    }
}

static void
bob_local(struct party *p, struct gy_x3dh_local *l, int with_opk)
{
    l->ik = &p->bob_ik;
    l->spk = &p->bob_spk.kp;
    l->opks = with_opk ? p->bob_opk : NULL;
    l->n_opks = with_opk ? 1 : 0;
}

TEST(two_party_agreement)
{
    int with_opk;

    for (with_opk = 0; with_opk <= 1; with_opk++) {
        struct party p;
        struct gy_keypair ek;
        struct gy_dr_secrets sa, sb;
        struct gy_x3dh_opk_ref ref;
        struct gy_x3dh_local l;
        uint8_t ada[GY_X3DH_AD_MAX], adb[GY_X3DH_AD_MAX];
        uint8_t prefix[GY_X3DH_PREFIX_MAX];
        size_t adal, adbl, prefl;

        setup(&p, with_opk);
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);

        ASSERT_EQ(gy_x3dh_initiate(D, &sa, ada, &adal, prefix, &prefl,
                                   &p.alice_ik, &p.bundle, &ek),
                  GY_OK);
        /* D-X3DH-13: EK private is zeroized after SK derivation. */
        ASSERT_EQ(gy_is_zero(ek.sk, 32), 1);

        bob_local(&p, &l, with_opk);
        ASSERT_EQ(gy_x3dh_respond(D, &sb, adb, &adbl, &ref, &l, prefix, prefl),
                  GY_OK);

        /* Both sides derive the identical seed triple and AD. */
        ASSERT_MEMEQ(sa.sk_dr, sb.sk_dr, GY_DR_SECRET_LEN);
        ASSERT_MEMEQ(sa.shared_hka, sb.shared_hka, GY_DR_SECRET_LEN);
        ASSERT_MEMEQ(sa.shared_nhkb, sb.shared_nhkb, GY_DR_SECRET_LEN);
        ASSERT_EQ(adal, adbl);
        ASSERT_MEMEQ(ada, adb, adal);
        ASSERT_EQ(ref.present, with_opk);
    }
}

/* Reconstruct SKdr from raw DH outputs, with or without the F prefix. */
static void
ref_skdr(const uint8_t dh[][GY_DH_MAX], size_t ndh, int with_f,
         uint8_t out[GY_DR_SECRET_LEN])
{
    uint8_t salt[GY_HASH_MAX], prk[GY_HASH_MAX], sk[GY_HASH_MAX];
    uint8_t f[GY_F_MAX], info[48];
    struct gy_iov iov[5];
    size_t infolen, k, i;

    memset(salt, 0, D->hash_len);
    k = 0;
    if (with_f) {
        gy_suite_f(D, f);
        iov[k].p = f;
        iov[k].len = D->f_len;
        k++;
    }
    for (i = 0; i < ndh; i++) {
        iov[k].p = dh[i];
        iov[k].len = D->dh_len;
        k++;
    }
    ASSERT_EQ(D->hkdf_extract(prk, salt, D->hash_len, iov, k), GY_OK);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "x3dh"),
              GY_OK);
    ASSERT_EQ(D->hkdf_expand(sk, D->hash_len, prk, info, infolen), GY_OK);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "dr.sk"),
              GY_OK);
    ASSERT_EQ(D->hkdf_expand(out, GY_DR_SECRET_LEN, sk, info, infolen), GY_OK);
}

TEST(f_prefix_guard)
{
    struct party p;
    struct gy_keypair ek;
    struct gy_dr_secrets sa;
    struct gy_x3dh_local l;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    uint8_t dh[4][GY_DH_MAX];
    uint8_t with_f[GY_DR_SECRET_LEN], no_f[GY_DR_SECRET_LEN];
    size_t adl, prefl;

    (void)l;
    setup(&p, 0);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);

    /* Reference DHs (Alice side) before initiate zeroizes ek.sk. */
    ASSERT_EQ(D->dh(dh[0], p.alice_ik.sk, p.bundle.spk.pk), GY_OK);
    ASSERT_EQ(D->dh(dh[1], ek.sk, p.bundle.ik.pk), GY_OK);
    ASSERT_EQ(D->dh(dh[2], ek.sk, p.bundle.spk.pk), GY_OK);
    ref_skdr((const uint8_t(*)[GY_DH_MAX])dh, 3, 1, with_f);
    ref_skdr((const uint8_t(*)[GY_DH_MAX])dh, 3, 0, no_f);

    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &p.alice_ik,
                               &p.bundle, &ek),
              GY_OK);

    /* The real derivation includes F; dropping F yields a different SKdr. */
    ASSERT_MEMEQ(sa.sk_dr, with_f, GY_DR_SECRET_LEN);
    ASSERT_TRUE(memcmp(sa.sk_dr, no_f, GY_DR_SECRET_LEN) != 0, "F is mixed in");
}

TEST(expansion_kat)
{
    uint8_t sk[32];
    struct gy_dr_secrets s;
    uint8_t want[GY_DR_SECRET_LEN], info[48];
    size_t infolen, i;

    for (i = 0; i < sizeof(sk); i++)
        sk[i] = (uint8_t)i;

    ASSERT_EQ(gy_x3dh_expand_secrets(D, sk, &s), GY_OK);

    /* Each output is HKDF-Expand(SK, INFO(purpose)) (independent recompute). */
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "dr.sk"),
              GY_OK);
    ASSERT_EQ(D->hkdf_expand(want, GY_DR_SECRET_LEN, sk, info, infolen), GY_OK);
    ASSERT_MEMEQ(s.sk_dr, want, GY_DR_SECRET_LEN);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "he.hka"),
              GY_OK);
    ASSERT_EQ(D->hkdf_expand(want, GY_DR_SECRET_LEN, sk, info, infolen), GY_OK);
    ASSERT_MEMEQ(s.shared_hka, want, GY_DR_SECRET_LEN);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "he.nhkb"),
              GY_OK);
    ASSERT_EQ(D->hkdf_expand(want, GY_DR_SECRET_LEN, sk, info, infolen), GY_OK);
    ASSERT_MEMEQ(s.shared_nhkb, want, GY_DR_SECRET_LEN);

    /* Label-dependent: the three outputs are pairwise distinct. */
    ASSERT_TRUE(memcmp(s.sk_dr, s.shared_hka, GY_DR_SECRET_LEN) != 0,
                "sk!=hka");
    ASSERT_TRUE(memcmp(s.sk_dr, s.shared_nhkb, GY_DR_SECRET_LEN) != 0,
                "sk!=nhkb");
    ASSERT_TRUE(memcmp(s.shared_hka, s.shared_nhkb, GY_DR_SECRET_LEN) != 0,
                "hka!=nhkb");
}

/* Curve25519 low-order points: all yield an all-zero shared secret under a
 * clamped scalar (order 1 and order 8), forcing GY_ERR_WEAK_KEY (D-X3DH-8). */
static const char *low_order_hex[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
};

/* Overwrite a carried key in the prefix with a small-order point, fixing its
 * embedded PKID so PKID recomputation still passes (isolating the DH check). */
static void
prefix_put_small(uint8_t *prefix, size_t key_off, const uint8_t *pt)
{
    uint8_t enc[33];
    uint32_t pkid;

    memcpy(prefix + key_off + 5, pt, 32);
    enc[0] = prefix[key_off + 4];
    memcpy(enc + 1, pt, 32);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, enc, 33), GY_OK);
    gy_be32_put(prefix + key_off, pkid);
}

TEST(small_order_responder)
{
    size_t i;

    /* IK_A and EK_A in the message set to low-order points -> WEAK_KEY. */
    for (i = 0; i < sizeof(low_order_hex) / sizeof(low_order_hex[0]); i++) {
        struct party p;
        struct gy_keypair ek;
        struct gy_dr_secrets sa, sb;
        struct gy_x3dh_opk_ref ref;
        struct gy_x3dh_local l;
        uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX],
            m[GY_X3DH_PREFIX_MAX];
        uint8_t pt[32];
        size_t adl, prefl;

        ASSERT_EQ(gy_hex_decode(pt, sizeof(pt), low_order_hex[i]), 32);
        setup(&p, 0);
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
        ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl,
                                   &p.alice_ik, &p.bundle, &ek),
                  GY_OK);
        bob_local(&p, &l, 0);

        memcpy(m, prefix, prefl);
        prefix_put_small(m, OFF_IK, pt);
        ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
                  GY_ERR_WEAK_KEY);

        memcpy(m, prefix, prefl);
        prefix_put_small(m, OFF_EK, pt);
        ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
                  GY_ERR_WEAK_KEY);
    }
}

/* Re-sign the SPK after substituting a small-order key so the bundle still
 * validates and the failure lands at DH (initiator side). */
static void
bundle_small_spk(struct party *p, const uint8_t *pt)
{
    uint8_t sd[41];
    uint32_t pkid;

    memcpy(p->bundle.spk.pk, pt, 32);
    sd[0] = p->bundle.spk.curve_type;
    memcpy(sd + 1, pt, 32);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, sd, 33), GY_OK);
    p->bundle.spk.pkid = pkid;
    gy_be64_put(sd + 33, p->bundle.spk_timestamp);
    ASSERT_EQ(D->sign(p->bundle.spk_sig, p->bob_ik.sk, sd, 41), GY_OK);
}

static void
bundle_small_opk(struct party *p, const uint8_t *pt)
{
    uint8_t enc[33];
    uint32_t pkid;

    p->bundle.opk.curve_type = (uint8_t)D->curve_type;
    memcpy(p->bundle.opk.pk, pt, 32);
    enc[0] = (uint8_t)D->curve_type;
    memcpy(enc + 1, pt, 32);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, enc, 33), GY_OK);
    p->bundle.opk.pkid = pkid;
}

TEST(small_order_initiator)
{
    size_t i;

    /* SPK_B and OPK_B set to low-order points, bundle re-made valid. IK_B
     * cannot be isolated (it is the SPK signature key), so it is covered by
     * the responder-side EK_A/IK_A cases through the same desc->dh path. */
    for (i = 0; i < sizeof(low_order_hex) / sizeof(low_order_hex[0]); i++) {
        struct party p;
        struct gy_keypair ek;
        struct gy_dr_secrets sa;
        uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
        uint8_t pt[32];
        size_t adl, prefl;

        ASSERT_EQ(gy_hex_decode(pt, sizeof(pt), low_order_hex[i]), 32);

        setup(&p, 1);
        bundle_small_spk(&p, pt);
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
        ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl,
                                   &p.alice_ik, &p.bundle, &ek),
                  GY_ERR_WEAK_KEY);
        ASSERT_EQ(gy_is_zero(ek.sk, 32), 1); /* failure-path deletion */

        setup(&p, 1);
        bundle_small_opk(&p, pt);
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
        ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl,
                                   &p.alice_ik, &p.bundle, &ek),
                  GY_ERR_WEAK_KEY);
        ASSERT_EQ(gy_is_zero(ek.sk, 32), 1);
    }
}

/* Build one valid initial message and its responder context. */
static void
make_message(struct party *p, struct gy_x3dh_local *l, uint8_t *prefix,
             size_t *prefl, int with_opk)
{
    struct gy_keypair ek;
    struct gy_dr_secrets sa;
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;

    setup(p, with_opk);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, prefl, &p->alice_ik,
                               &p->bundle, &ek),
              GY_OK);
    bob_local(p, l, with_opk);
}

TEST(parse_negatives)
{
    struct party p;
    struct gy_x3dh_local l;
    struct gy_dr_secrets sb;
    struct gy_x3dh_opk_ref ref;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX],
        m[GY_X3DH_PREFIX_MAX];
    size_t prefl;

#define RESPOND(msg, len)                                                      \
    (RESET_CTR(),                                                              \
     gy_x3dh_respond(D, &sb, ad, &(size_t){0}, &ref, &l, (msg), (len)))

    make_message(&p, &l, prefix, &prefl, 1);

    /* Wrong version and wrong suite abort in gy_frame_check, before crypto. */
    memcpy(m, prefix, prefl);
    m[0] = 0x02;
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_ARG);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    memcpy(m, prefix, prefl);
    m[1] = GY_SUITE_C448;
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    /* Truncation at the last byte aborts before any DH. */
    ASSERT_EQ(RESPOND(prefix, prefl - 1), GY_ERR_ARG);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    /* Tampered IK_A key byte (embedded PKID no longer recomputes). */
    memcpy(m, prefix, prefl);
    m[OFF_IK + 5] ^= 0x01;
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    /* Wrong ik_id (message addressed to a replaced identity). */
    memcpy(m, prefix, prefl);
    gy_be32_put(m + OFF_IKID, gy_be32_get(m + OFF_IKID) ^ 0x1u);
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    /* Unknown SPK id (here zeroed) is the generic handshake error. */
    memcpy(m, prefix, prefl);
    gy_be32_put(m + OFF_SPKID, 0);
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

#undef RESPOND
}

TEST(uniform_error)
{
    struct party p;
    struct gy_x3dh_local l;
    struct gy_dr_secrets sb;
    struct gy_x3dh_opk_ref ref;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX],
        m[GY_X3DH_PREFIX_MAX];
    size_t adl, prefl;
    int err_unknown_opk, err_bad_sig;

    /* Responder: a claimed but unheld OPK. */
    make_message(&p, &l, prefix, &prefl, 1);
    memcpy(m, prefix, prefl);
    gy_be32_put(m + OFF_OPKID, gy_be32_get(m + OFF_OPKID) ^ 0xabcdu);
    err_unknown_opk = gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl);

    /* Initiator: a corrupted SPK signature (bundle validation). */
    {
        struct party q;
        struct gy_keypair ek;
        struct gy_dr_secrets sa;
        uint8_t adx[GY_X3DH_AD_MAX], px[GY_X3DH_PREFIX_MAX];
        size_t axl, pxl;

        setup(&q, 1);
        q.bundle.spk_sig[0] ^= 0x80;
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
        err_bad_sig = gy_x3dh_initiate(D, &sa, adx, &axl, px, &pxl, &q.alice_ik,
                                       &q.bundle, &ek);
    }

    /* Both surface the same external code (no prekey-existence oracle). */
    ASSERT_EQ(err_unknown_opk, GY_ERR_VERIFY);
    ASSERT_EQ(err_bad_sig, GY_ERR_VERIFY);
    ASSERT_EQ(err_unknown_opk, err_bad_sig);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;
    D = gy_suite_desc(GY_SUITE_C25519);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(two_party_agreement),   GY_TEST(f_prefix_guard),
            GY_TEST(expansion_kat),         GY_TEST(small_order_responder),
            GY_TEST(small_order_initiator), GY_TEST(parse_negatives),
            GY_TEST(uniform_error),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
