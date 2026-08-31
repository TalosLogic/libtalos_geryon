/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The c448 (X448 + XEd448, SHA-512) parameterization of the classical
 * X3DH vertical.  Mirrors tests/kex/test_x3dh.c at the 448 tier: the code paths
 * are identical (they route through the suite descriptor); only the row and the
 * sizes change.  This asserts the M1 genericity payoff holds for c448 - two
 * fresh parties derive the same seed triple with and without an OPK, the KDF
 * chain matches an independent SHA-512 recompute (F prefix mixed in), X448
 * all-zero DH is rejected (D-X3DH-8), and a cross-suite message aborts before
 * any DH.  Built with -DGY_TEST_HOOKS: gy_kex_ctr proves the pre-crypto aborts.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h"
#include "util.h"
#include "x3dh.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;

#define RESET_CTR() memset(&gy_kex_ctr, 0, sizeof(gy_kex_ctr))
static const uint64_t TS = 0x0000000155667788ull;

/* c448 prefix field offsets (curve_pk_len = 56, key wire kw = 4 + 1 + 56). */
#define KW 61
#define OFF_IK 2
#define OFF_EK (2 + KW)
#define OFF_IKID (2 + 2 * KW)
#define OFF_SPKID (OFF_IKID + 4)
#define OFF_OPKID (OFF_SPKID + 4)

/* Encoded curve key (curve_type || pk) at the 448 tier. */
#define ENC_LEN 57
/* SPK signed_data (curve_type || pk || be64 timestamp). */
#define SD_LEN 65

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
        /* D-X3DH-13: EK private is zeroized after SK derivation (56 bytes). */
        ASSERT_EQ(gy_is_zero(ek.sk, D->curve_sk_len), 1);

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

/* Reconstruct SKdr from raw DH outputs, with or without the F prefix, over the
 * c448 SHA-512 tier (D-X3DH-7: zero salt sized hash_len = 64, F = 57 x 0xFF). */
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
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    uint8_t dh[4][GY_DH_MAX];
    uint8_t with_f[GY_DR_SECRET_LEN], no_f[GY_DR_SECRET_LEN];
    size_t adl, prefl;

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
    uint8_t sk[GY_HASH_MAX]; /* SK is hash_len = 64 bytes at the 448 tier. */
    struct gy_dr_secrets s;
    uint8_t want[GY_DR_SECRET_LEN], info[48];
    size_t infolen, i;

    for (i = 0; i < D->hash_len; i++)
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

/*
 * X448 low-order u-coordinate: the all-zero point yields an all-zero shared
 * secret under any clamped scalar (X448(k, 0) = 0), forcing GY_ERR_WEAK_KEY
 * (D-X3DH-8) exactly as the 25519 tier's low-order points do.  One point is
 * enough: the check is the all-zero DH output, not the point's exact order.
 */
static const uint8_t x448_zero[56] = {0};

/* Overwrite a carried key in the prefix with the zero point, fixing its
 * embedded PKID so PKID recomputation still passes (isolating the DH check). */
static void
prefix_put_zero(uint8_t *prefix, size_t key_off)
{
    uint8_t enc[ENC_LEN];
    uint32_t pkid;

    memcpy(prefix + key_off + 5, x448_zero, 56);
    enc[0] = prefix[key_off + 4];
    memcpy(enc + 1, x448_zero, 56);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, enc, ENC_LEN), GY_OK);
    gy_be32_put(prefix + key_off, pkid);
}

TEST(small_order_responder)
{
    struct party p;
    struct gy_keypair ek;
    struct gy_dr_secrets sa, sb;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local l;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX],
        m[GY_X3DH_PREFIX_MAX];
    size_t adl, prefl;

    /* IK_A and EK_A in the message set to the zero point -> WEAK_KEY. */
    setup(&p, 0);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &p.alice_ik,
                               &p.bundle, &ek),
              GY_OK);
    bob_local(&p, &l, 0);

    memcpy(m, prefix, prefl);
    prefix_put_zero(m, OFF_IK);
    ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
              GY_ERR_WEAK_KEY);

    memcpy(m, prefix, prefl);
    prefix_put_zero(m, OFF_EK);
    ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
              GY_ERR_WEAK_KEY);
}

/* Re-sign the SPK after substituting the zero key so the bundle still validates
 * and the failure lands at DH (initiator side). */
static void
bundle_zero_spk(struct party *p)
{
    uint8_t sd[SD_LEN];
    uint32_t pkid;

    memcpy(p->bundle.spk.pk, x448_zero, 56);
    sd[0] = p->bundle.spk.curve_type;
    memcpy(sd + 1, x448_zero, 56);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, sd, ENC_LEN), GY_OK);
    p->bundle.spk.pkid = pkid;
    gy_be64_put(sd + ENC_LEN, p->bundle.spk_timestamp);
    ASSERT_EQ(D->sign(p->bundle.spk_sig, p->bob_ik.sk, sd, SD_LEN), GY_OK);
}

TEST(small_order_initiator)
{
    struct party p;
    struct gy_keypair ek;
    struct gy_dr_secrets sa;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    size_t adl, prefl;

    /* SPK_B set to the zero point, bundle re-made valid; DH1/DH3 collapse. */
    setup(&p, 1);
    bundle_zero_spk(&p);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &p.alice_ik,
                               &p.bundle, &ek),
              GY_ERR_WEAK_KEY);
    ASSERT_EQ(gy_is_zero(ek.sk, D->curve_sk_len),
              1); /* failure-path deletion */
}

TEST(cross_suite_rejected)
{
    struct party p;
    struct gy_keypair ek;
    struct gy_dr_secrets sa, sb;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local l;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX],
        m[GY_X3DH_PREFIX_MAX];
    size_t adl, prefl;

    setup(&p, 1);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &p.alice_ik,
                               &p.bundle, &ek),
              GY_OK);
    bob_local(&p, &l, 1);

    /* A valid c448 message whose suite byte is flipped to another suite is
     * refused in gy_frame_check, before any DH (downgrade/confusion guard). */
    memcpy(m, prefix, prefl);
    m[1] = GY_SUITE_C25519;
    RESET_CTR();
    ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
              GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    memcpy(m, prefix, prefl);
    m[1] = GY_SUITE_H25519_512;
    RESET_CTR();
    ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
              GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.dh, 0);

    memcpy(m, prefix, prefl);
    m[1] = GY_SUITE_H448_1024; /* reserved, not enabled */
    RESET_CTR();
    ASSERT_EQ(gy_x3dh_respond(D, &sb, ad, &adl, &ref, &l, m, prefl),
              GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.dh, 0);
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

    /* Wrong version aborts in gy_frame_check, before any crypto. */
    memcpy(m, prefix, prefl);
    m[0] = 0x02;
    ASSERT_EQ(RESPOND(m, prefl), GY_ERR_ARG);
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

/* Item 1 of the 448 negative matrix: a tampered XEd448 SPK
 * signature is rejected at bundle validation, before any DH runs, and surfaces
 * the same external code as a responder-side unheld-OPK claim (no prekey-
 * existence oracle).  The 448 mirror of test_x3dh.c::uniform_error. */
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

    /* Initiator: a corrupted XEd448 SPK signature (bundle validation).  The
     * initiator verifies the SPK signature before any DH, so the op-counter
     * must show zero DHs on the failure path. */
    {
        struct party q;
        struct gy_keypair ek;
        struct gy_dr_secrets sa;
        uint8_t adx[GY_X3DH_AD_MAX], px[GY_X3DH_PREFIX_MAX];
        size_t axl, pxl;

        setup(&q, 1);
        q.bundle.spk_sig[0] ^= 0x80;
        ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
        RESET_CTR();
        err_bad_sig = gy_x3dh_initiate(D, &sa, adx, &axl, px, &pxl, &q.alice_ik,
                                       &q.bundle, &ek);
        ASSERT_EQ(gy_kex_ctr.dh, 0);
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
    D = gy_suite_desc(GY_SUITE_C448);
    if (D == NULL)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(two_party_agreement),   GY_TEST(f_prefix_guard),
            GY_TEST(expansion_kat),         GY_TEST(small_order_responder),
            GY_TEST(small_order_initiator), GY_TEST(cross_suite_rejected),
            GY_TEST(parse_negatives),       GY_TEST(uniform_error),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
