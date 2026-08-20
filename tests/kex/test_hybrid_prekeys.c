/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the hybrid prekey path in src/kex/prekeys.c (HYBRID_SPEC sections
 * 4, 5), built with -DGY_TEST_HOOKS so the operation counters (gy_kex_ctr) and
 * the encoder views are live.  Covers: generation + bundle validation happy
 * path, encoded-size KATs, the dual-signature diagnostic matrix, PKID and
 * signer-binding recompute negatives, the flags matrix (rejected before any
 * signature verify), and end-to-end ctx (INFO("prekey")) binding.
 */

#include <stdint.h>
#include <string.h>

#include "encode.h"
#include "mldsa.h"
#include "prekeys.h"

#include "gy_test.h"

/* Valid flags: min_interval 1, max_interval 20, ChaCha20-Poly1305 MTI set. */
#define FLAGS_OK ((uint64_t)1 | ((uint64_t)20 << 16) | ((uint64_t)1 << 32))

#define TS 1723900000ULL

static void
reset_counters(void)
{
    memset(&gy_kex_ctr, 0, sizeof(gy_kex_ctr));
}

/* Generate an identity, an SPK, and one OPK; assemble a published bundle. */
static int
setup_bundle(const struct gy_suite_desc *desc,
             struct gy_hybrid_prekey_bundle *b)
{
    struct gy_hybrid_identity_keypair ik;
    struct gy_hybrid_signed_prekey spk;
    struct gy_hybrid_keypair opk;
    int rc;

    rc = gy_hybrid_identity_keypair_generate(desc, &ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_spk_create(desc, &spk, &ik, TS, FLAGS_OK);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_opk_batch(desc, &opk, 1, NULL, 0);
    if (rc != GY_OK)
        return rc;

    memset(b, 0, sizeof(*b));
    b->ik = ik.pub;
    b->spk = spk.kp.pub;
    b->spk_timestamp = spk.timestamp;
    b->spk_flags = spk.flags;
    b->spk_ik_id = spk.ik_id;
    memcpy(b->spk_ed_sig, spk.ed_sig, sizeof(b->spk_ed_sig));
    memcpy(b->spk_mldsa_sig, spk.mldsa_sig, sizeof(b->spk_mldsa_sig));
    b->opk = opk.pub;

    gy_secure_zero(&ik, sizeof(ik));
    gy_secure_zero(&spk, sizeof(spk));
    gy_secure_zero(&opk, sizeof(opk));
    return GY_OK;
}

TEST(generate_and_validate)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;
    uint8_t enc[4096];
    size_t len;
    uint8_t diag = 0xEE;

    ASSERT_TRUE(desc != NULL, "h25519_512 suite is enabled");
    ASSERT_EQ(desc->is_hybrid, 1);
    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);

    /* Encoded-key size KATs (the bytes PKIDs and signatures cover). */
    ASSERT_EQ(gy_hybrid_encode_pub(desc, &b.spk, enc, sizeof(enc), &len),
              GY_OK);
    ASSERT_EQ((long long)len, 833); /* 1 + 32 + 800 */
    ASSERT_EQ(gy_hybrid_encode_identity(desc, &b.ik, enc, sizeof(enc), &len),
              GY_OK);
    ASSERT_EQ((long long)len, 2145); /* 833 + 1312 */

    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, &diag), GY_OK);
}

TEST(dual_signature_matrix)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;
    uint8_t diag;

    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);

    /* Classical only tampered -> 0x1. */
    b.spk_ed_sig[0] ^= 0x01;
    diag = 0;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, &diag), GY_ERR_VERIFY);
    ASSERT_EQ(diag, GY_DIAG_CLASSICAL_FAILED);
    b.spk_ed_sig[0] ^= 0x01;

    /* PQ only tampered -> 0x2. */
    b.spk_mldsa_sig[0] ^= 0x01;
    diag = 0;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, &diag), GY_ERR_VERIFY);
    ASSERT_EQ(diag, GY_DIAG_PQ_FAILED);
    b.spk_mldsa_sig[0] ^= 0x01;

    /* Both tampered -> 0x3. */
    b.spk_ed_sig[0] ^= 0x01;
    b.spk_mldsa_sig[0] ^= 0x01;
    diag = 0;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, &diag), GY_ERR_VERIFY);
    ASSERT_EQ(diag, GY_DIAG_BOTH_FAILED);
    b.spk_ed_sig[0] ^= 0x01;
    b.spk_mldsa_sig[0] ^= 0x01;

    /* Restored bundle is valid again. */
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_OK);
}

TEST(pkid_and_signer_binding)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;

    /* Tampered embedded IK PKID: recompute mismatch. */
    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);
    b.ik.base.curve.pkid ^= 0x01;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_ERR_VERIFY);

    /* Tampered SPK PKID. */
    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);
    b.spk.curve.pkid ^= 0x01;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_ERR_VERIFY);

    /* Signer-binding mismatch: spk_ik_id no longer names this IK. */
    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);
    b.spk_ik_id ^= 0x01;
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_ERR_VERIFY);
}

TEST(flags_matrix)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;

    /* gy_hybrid_spk_create refuses to sign malformed flags up front. */
    {
        struct gy_hybrid_identity_keypair ik;
        struct gy_hybrid_signed_prekey spk;

        ASSERT_EQ(gy_hybrid_identity_keypair_generate(desc, &ik), GY_OK);
        ASSERT_EQ(gy_hybrid_spk_create(desc, &spk, &ik, TS, 0 /* MTI clear */),
                  GY_ERR_VERIFY);
        gy_secure_zero(&ik, sizeof(ik));
        gy_secure_zero(&spk, sizeof(spk));
    }

    /*
     * Bundle validation rejects malformed flags BEFORE any signature verify
     * (D-X3DH-14) and performs no private-key operation.
     */
    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);

    b.spk_flags = FLAGS_OK & ~((uint64_t)1 << 32); /* MTI clear */
    reset_counters();
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_EQ(gy_kex_ctr.keypair, 0);
    ASSERT_EQ(gy_kex_ctr.sign, 0);

    b.spk_flags = FLAGS_OK | ((uint64_t)1 << 35); /* reserved bit set */
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_ERR_VERIFY);

    b.spk_flags = (uint64_t)5 | ((uint64_t)3 << 16) | ((uint64_t)1 << 32);
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL),
              GY_ERR_VERIFY); /* min>max */

    b.spk_flags = (uint64_t)1 | ((uint64_t)101 << 16) | ((uint64_t)1 << 32);
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL),
              GY_ERR_VERIFY); /* max>100 */
}

TEST(ctx_load_bearing)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;
    uint8_t sd[4096], ctx[64];
    size_t sdlen, ctxlen;

    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);

    /* Rebuild signed_data = encoded_public_key || timestamp || flags. */
    ASSERT_EQ(gy_hybrid_encode_pub(desc, &b.spk, sd, sizeof(sd), &sdlen),
              GY_OK);
    gy_be64_put(sd + sdlen, b.spk_timestamp);
    gy_be64_put(sd + sdlen + 8, b.spk_flags);
    sdlen += 16;

    /* The ML-DSA prekey signature verifies ONLY under ctx = INFO("prekey"). */
    ASSERT_EQ(
        gy_mldsa_verify(b.spk_mldsa_sig, b.ik.mldsa_pk, sd, sdlen, NULL, 0),
        GY_ERR_VERIFY);
    ASSERT_EQ(gy_info(ctx, sizeof(ctx), &ctxlen, desc->suite_id, "prekey"),
              GY_OK);
    ASSERT_EQ(
        gy_mldsa_verify(b.spk_mldsa_sig, b.ik.mldsa_pk, sd, sdlen, ctx, ctxlen),
        GY_OK);
}

TEST(opk_absent_accepted)
{
    const struct gy_suite_desc *desc = gy_suite_desc(GY_SUITE_H25519_512);
    struct gy_hybrid_prekey_bundle b;

    ASSERT_EQ(setup_bundle(desc, &b), GY_OK);
    /* Zero-PKID OPK is the "no one-time prekey" sentinel; still valid. */
    memset(&b.opk, 0, sizeof(b.opk));
    ASSERT_EQ(gy_hybrid_bundle_validate(desc, &b, NULL), GY_OK);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(generate_and_validate),   GY_TEST(dual_signature_matrix),
            GY_TEST(pkid_and_signer_binding), GY_TEST(flags_matrix),
            GY_TEST(ctx_load_bearing),        GY_TEST(opk_absent_accepted),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
