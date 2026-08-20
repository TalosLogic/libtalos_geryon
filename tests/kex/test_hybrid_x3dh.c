/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the hybrid X3DH handshake in src/kex/x3dh.c (HYBRID_SPEC section 6),
 * built with -DGY_TEST_HOOKS.  Covers: initiator/responder interop (identical
 * seed triple and AD, with and without OPK), the pinned 4508-byte prefix,
 * hybrid_flag round-trip and validation, corrupt-ciphertext implicit rejection
 * (no KEM oracle: responder completes, SK diverges), and the embedded-PKID /
 * stale-identity / reserved-bit tamper matrix.
 */

#include <stdint.h>
#include <string.h>

#include "x3dh.h"

#include "gy_test.h"

#define FLAGS_OK ((uint64_t)1 | ((uint64_t)20 << 16) | ((uint64_t)1 << 32))
#define HFLAG ((uint32_t)20 | ((uint32_t)1 << 16)) /* interval 20, aead 0x01 */
#define TS 1723900000ULL

/* Bob's long-lived material plus a published bundle; Alice's identity. */
struct parties {
    struct gy_hybrid_identity_keypair bob_ik;
    struct gy_hybrid_signed_prekey bob_spk;
    struct gy_hybrid_keypair bob_opk;
    struct gy_hybrid_identity_keypair alice_ik;
    struct gy_hybrid_prekey_bundle bundle;
};

static int
gen_parties(const struct gy_suite_desc *desc, struct parties *p)
{
    int rc;

    rc = gy_hybrid_identity_keypair_generate(desc, &p->bob_ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_spk_create(desc, &p->bob_spk, &p->bob_ik, TS, FLAGS_OK);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_opk_batch(desc, &p->bob_opk, 1, NULL, 0);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_identity_keypair_generate(desc, &p->alice_ik);
    if (rc != GY_OK)
        return rc;

    memset(&p->bundle, 0, sizeof(p->bundle));
    p->bundle.ik = p->bob_ik.pub;
    p->bundle.spk = p->bob_spk.kp.pub;
    p->bundle.spk_timestamp = p->bob_spk.timestamp;
    p->bundle.spk_flags = p->bob_spk.flags;
    p->bundle.spk_ik_id = p->bob_spk.ik_id;
    memcpy(p->bundle.spk_ed_sig, p->bob_spk.ed_sig,
           sizeof(p->bundle.spk_ed_sig));
    memcpy(p->bundle.spk_mldsa_sig, p->bob_spk.mldsa_sig,
           sizeof(p->bundle.spk_mldsa_sig));
    p->bundle.opk = p->bob_opk.pub;
    return GY_OK;
}

static void
bob_local(const struct parties *p, struct gy_hybrid_x3dh_local *local,
          size_t n_opks)
{
    memset(local, 0, sizeof(*local));
    local->ik = &p->bob_ik;
    local->spk = &p->bob_spk.kp;
    local->spk_flags = FLAGS_OK;
    local->opks = &p->bob_opk;
    local->n_opks = n_opks;
}

/* Alice initiates into out_prefix; caller may tamper before Bob responds. */
static int
alice_initiate(const struct gy_suite_desc *desc, struct parties *p,
               struct gy_dr_secrets *sa, uint8_t *prefix, size_t *plen,
               uint32_t hflag)
{
    struct gy_keypair ek;
    uint8_t ad[GY_HYBRID_AD_MAX];
    size_t adlen;
    int rc;

    rc = gy_keypair_generate(desc, &ek);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_x3dh_initiate(desc, sa, ad, &adlen, prefix, plen,
                                 &p->alice_ik, &p->bundle, &ek, hflag);
    gy_secure_zero(&ek, sizeof(ek));
    return rc;
}

TEST(interop_with_opk)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct parties p;
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_x3dh_local local;
    struct gy_x3dh_opk_ref opk_ref;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX];
    uint8_t ad_a[GY_HYBRID_AD_MAX], ad_b[GY_HYBRID_AD_MAX];
    size_t plen, adlen_a, adlen_b;
    uint32_t flag_out;
    struct gy_keypair ek;

    ASSERT_TRUE(desc != NULL, "h25519_512 enabled");
    ASSERT_EQ(gen_parties(desc, &p), GY_OK);

    /* Initiate (capture AD by re-running with an exposed ek is unnecessary; we
     * compare the responder AD against a direct initiator AD below). */
    ASSERT_EQ(gy_keypair_generate(desc, &ek), GY_OK);
    ASSERT_EQ(gy_hybrid_x3dh_initiate(desc, &sa, ad_a, &adlen_a, prefix, &plen,
                                      &p.alice_ik, &p.bundle, &ek, HFLAG),
              GY_OK);
    gy_secure_zero(&ek, sizeof(ek));

    ASSERT_EQ((long long)plen, 4508); /* pinned h25519_512 prefix */

    bob_local(&p, &local, 1);
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_OK);

    /* Identical seed triple and AD; hybrid_flag and OPK round-trip. */
    ASSERT_MEMEQ(&sa, &sb, sizeof(sa));
    ASSERT_EQ(adlen_a, adlen_b);
    ASSERT_MEMEQ(ad_a, ad_b, adlen_a);
    ASSERT_EQ(flag_out, HFLAG);
    ASSERT_EQ(opk_ref.present, 1);
    ASSERT_EQ(opk_ref.pkid, p.bob_opk.pub.curve.pkid);
}

TEST(interop_without_opk)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct parties p;
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_x3dh_local local;
    struct gy_x3dh_opk_ref opk_ref;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX];
    uint8_t ad_b[GY_HYBRID_AD_MAX];
    size_t plen, adlen_b;
    uint32_t flag_out;

    ASSERT_EQ(gen_parties(desc, &p), GY_OK);
    memset(&p.bundle.opk, 0, sizeof(p.bundle.opk)); /* no OPK */

    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG), GY_OK);

    bob_local(&p, &local, 0);
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_OK);
    ASSERT_MEMEQ(&sa, &sb, sizeof(sa));
    ASSERT_EQ(opk_ref.present, 0);
}

TEST(corrupt_ct_implicit_rejection)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct parties p;
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_x3dh_local local;
    struct gy_x3dh_opk_ref opk_ref;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX], ad_b[GY_HYBRID_AD_MAX];
    size_t plen, adlen_b, off_ct_spk;
    uint32_t flag_out;

    ASSERT_EQ(gen_parties(desc, &p), GY_OK);
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG), GY_OK);

    /* ct_spk = after version|suite|ik|ek|ct_ik. */
    off_ct_spk =
        2 + (4 + 1 + desc->curve_pk_len + desc->kem_pk_len + desc->dsa_pk_len) +
        (4 + 1 + desc->curve_pk_len) + desc->kem_ct_len;
    prefix[off_ct_spk] ^= 0x01;

    bob_local(&p, &local, 1);
    /* No oracle: the responder completes (implicit rejection), SK diverges. */
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_OK);
    ASSERT_TRUE(memcmp(&sa, &sb, sizeof(sa)) != 0,
                "corrupt ct_spk diverges the shared secret");
}

TEST(tamper_matrix)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct parties p;
    struct gy_dr_secrets sa, sb;
    struct gy_hybrid_x3dh_local local;
    struct gy_x3dh_opk_ref opk_ref;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX], ad_b[GY_HYBRID_AD_MAX];
    size_t plen, adlen_b, off_ik_id, off_hflag;
    uint32_t flag_out;

    ASSERT_EQ(gen_parties(desc, &p), GY_OK);
    bob_local(&p, &local, 1);
    off_ik_id =
        2 + (4 + 1 + desc->curve_pk_len + desc->kem_pk_len + desc->dsa_pk_len) +
        (4 + 1 + desc->curve_pk_len) + 3 * desc->kem_ct_len;
    off_hflag = off_ik_id + 12;

    /* Embedded IK curve_pk tampered: recompute mismatch. */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG), GY_OK);
    prefix[2 + 4 + 1] ^= 0x01; /* first curve_pk byte inside ik */
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_ERR_VERIFY);

    /* ik_id addressed to a different identity: stale-identity abort. */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG), GY_OK);
    prefix[off_ik_id] ^= 0x01;
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_ERR_STATE);

    /* hybrid_flag reserved bit set (MSB of the be32): section 6.6 violation. */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG), GY_OK);
    prefix[off_hflag] |= 0x01; /* reserved bits 24..31 */
    ASSERT_EQ(gy_hybrid_x3dh_respond(desc, &sb, ad_b, &adlen_b, &opk_ref,
                                     &flag_out, &local, prefix, plen),
              GY_ERR_VERIFY);
}

TEST(bad_hybrid_flag_initiate)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct parties p;
    struct gy_dr_secrets sa;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX];
    size_t plen;

    ASSERT_EQ(gen_parties(desc, &p), GY_OK);

    /* interval 50 exceeds Bob's advertised max (20). */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen,
                             (uint32_t)50 | ((uint32_t)1 << 16)),
              GY_ERR_VERIFY);
    /* aead_id 4 is not a defined AEAD. */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen,
                             (uint32_t)20 | ((uint32_t)4 << 16)),
              GY_ERR_VERIFY);
    /* aead_id 2 (AES-256-GCM) IS defined but is not in Bob's advertised set
     * (FLAGS_OK advertises only aead 1): outside the advertised mask (§6.6). */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen,
                             (uint32_t)20 | ((uint32_t)2 << 16)),
              GY_ERR_VERIFY);
    /* reserved bit set. */
    ASSERT_EQ(alice_initiate(desc, &p, &sa, prefix, &plen, HFLAG | (1u << 24)),
              GY_ERR_VERIFY);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(interop_with_opk),
            GY_TEST(interop_without_opk),
            GY_TEST(corrupt_ct_implicit_rejection),
            GY_TEST(tamper_matrix),
            GY_TEST(bad_hybrid_flag_initiate),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
