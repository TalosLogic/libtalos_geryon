/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/kex/prekeys.c (D-X3DH-4/10/11/14, D-GEN-2).
 * Built with -DGY_TEST_HOOKS so the operation counters (gy_kex_ctr) are live:
 * the bundle-tampering matrix asserts each mutation aborts at the right step
 * and that validation performs NO private-key (dh/sign) operation (D-X3DH-14).
 */

#include <stdint.h>
#include <string.h>

#include "prekeys.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;

#define RESET_CTR() memset(&gy_kex_ctr, 0, sizeof(gy_kex_ctr))

/* No validation path may ever touch a private-key operation. */
#define ASSERT_NO_SECRET_OP()                                                  \
    do {                                                                       \
        ASSERT_EQ(gy_kex_ctr.dh, 0);                                           \
        ASSERT_EQ(gy_kex_ctr.sign, 0);                                         \
    } while (0)

static const uint64_t TS = 0x0000000155667788ull;

/* Build a valid bundle; id keeps the identity secret key for signing. */
static void
build_bundle(struct gy_prekey_bundle *b, struct gy_keypair *id, int with_opk)
{
    struct gy_signed_prekey spk;
    struct gy_keypair opk;

    ASSERT_EQ(gy_keypair_generate(D, id), GY_OK);
    ASSERT_EQ(gy_spk_create(D, &spk, id->sk, TS), GY_OK);

    memset(b, 0, sizeof(*b));
    b->ik = id->pub;
    b->spk = spk.kp.pub;
    b->spk_timestamp = spk.timestamp;
    memcpy(b->spk_sig, spk.sig, sizeof(b->spk_sig));

    if (with_opk) {
        ASSERT_EQ(gy_opk_batch(D, &opk, 1, NULL, 0), GY_OK);
        b->opk = opk.pub;
    }
}

TEST(validate_ok)
{
    struct gy_prekey_bundle b;
    struct gy_keypair id;

    /* Baseline: valid bundle with an OPK validates, verify runs exactly once. */
    build_bundle(&b, &id, 1);
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_OK);
    ASSERT_EQ(gy_kex_ctr.verify, 1);
    ASSERT_NO_SECRET_OP();

    /* Valid bundle without an OPK also validates (zero-PKID sentinel). */
    build_bundle(&b, &id, 0);
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_OK);
    ASSERT_EQ(gy_kex_ctr.verify, 1);
    ASSERT_NO_SECRET_OP();
}

TEST(tamper_curve_type)
{
    struct gy_prekey_bundle b;
    struct gy_keypair id;

    /* ik curve_type mismatch aborts in step (a), before any hash or verify. */
    build_bundle(&b, &id, 1);
    b.ik.curve_type = GY_CURVE_TYPE_448;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.hash, 0);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();

    /* spk curve_type mismatch likewise. */
    build_bundle(&b, &id, 1);
    b.spk.curve_type = GY_CURVE_TYPE_448;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();

    /* present-OPK curve_type mismatch aborts in step (a) too. */
    build_bundle(&b, &id, 1);
    b.opk.curve_type = GY_CURVE_TYPE_448;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_STATE);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();
}

TEST(tamper_pkid)
{
    struct gy_prekey_bundle b;
    struct gy_keypair id;

    /* ik PKID mismatch aborts in step (b): recompute ran once, no verify. */
    build_bundle(&b, &id, 1);
    b.ik.pkid ^= 1u;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.hash, 1);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();

    /* spk PKID mismatch: ik passes (hash 1), spk fails (hash 2), no verify. */
    build_bundle(&b, &id, 1);
    b.spk.pkid ^= 1u;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.hash, 2);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();

    /* opk PKID mismatch: ik, spk pass (hash 2), opk fails (hash 3). */
    build_bundle(&b, &id, 1);
    b.opk.pkid ^= 1u;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.hash, 3);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();

    /* ik PKID zeroed (sentinel on a required key) is rejected before verify. */
    build_bundle(&b, &id, 1);
    b.ik.pkid = 0;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.verify, 0);
    ASSERT_NO_SECRET_OP();
}

TEST(tamper_signature_and_timestamp)
{
    struct gy_prekey_bundle b;
    struct gy_keypair id;

    /* A flipped signature byte reaches step (c) and fails verify. */
    build_bundle(&b, &id, 1);
    b.spk_sig[0] ^= 0x80;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.verify, 1);
    ASSERT_NO_SECRET_OP();

    /* An altered timestamp changes the signed bytes, so verify fails
     * (signature-over-metadata guarantee, D-X3DH-4). */
    build_bundle(&b, &id, 1);
    b.spk_timestamp ^= 1u;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_ERR_VERIFY);
    ASSERT_EQ(gy_kex_ctr.verify, 1);
    ASSERT_NO_SECRET_OP();
}

TEST(opk_absent_present)
{
    struct gy_prekey_bundle b;
    struct gy_keypair id;

    /* A present OPK zeroed to the sentinel is simply treated as absent. */
    build_bundle(&b, &id, 1);
    b.opk.pkid = 0;
    RESET_CTR();
    ASSERT_EQ(gy_bundle_validate(D, &b), GY_OK);
    ASSERT_NO_SECRET_OP();
}

TEST(batch_uniqueness)
{
    struct gy_keypair batch[16];
    struct gy_keypair batch2[8];
    uint32_t existing[16];
    size_t i, j;

    ASSERT_EQ(gy_opk_batch(D, batch, 16, NULL, 0), GY_OK);

    /* Every PKID present and unique within the batch. */
    for (i = 0; i < 16; i++) {
        ASSERT_EQ(gy_pkid_is_present(batch[i].pub.pkid), 1);
        existing[i] = batch[i].pub.pkid;
        for (j = 0; j < i; j++)
            ASSERT_TRUE(batch[i].pub.pkid != batch[j].pub.pkid,
                        "intra-batch unique");
    }

    /* A second batch against the first as existing[] shares no PKID. */
    ASSERT_EQ(gy_opk_batch(D, batch2, 8, existing, 16), GY_OK);
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 16; j++)
            ASSERT_TRUE(batch2[i].pub.pkid != existing[j],
                        "cross-batch unique");
    }

    /* Batch-size bounds. */
    ASSERT_EQ(gy_opk_batch(D, batch, 0, NULL, 0), GY_ERR_ARG);
    ASSERT_EQ(gy_opk_batch(D, batch, GY_OPK_BATCH_MAX + 1, NULL, 0),
              GY_ERR_ARG);
}

TEST(regen_decision)
{
    struct gy_keypair kp;
    uint32_t existing[1];

    ASSERT_EQ(gy_keypair_generate(D, &kp), GY_OK);
    existing[0] = kp.pub.pkid;

    /* Zero sentinel always regenerates. */
    ASSERT_EQ(gy_kex_pkid_needs_regen(0, NULL, 0), 1);
    /* A PKID already in the existing list regenerates. */
    ASSERT_EQ(gy_kex_pkid_needs_regen(existing[0], existing, 1), 1);
    /* A fresh non-zero PKID with no existing list does not. */
    ASSERT_EQ(gy_kex_pkid_needs_regen(existing[0] ^ 0x5a5au, NULL, 0), 0);
}

TEST(fingerprint)
{
    struct gy_keypair a, b;
    uint8_t fa[GY_HASH_MAX], fb[GY_HASH_MAX], fa2[GY_HASH_MAX];

    ASSERT_EQ(gy_keypair_generate(D, &a), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &b), GY_OK);

    ASSERT_EQ(gy_fingerprint(D, fa, &a.pub), GY_OK);
    ASSERT_EQ(gy_fingerprint(D, fb, &b.pub), GY_OK);

    /* Distinct identities yield distinct fingerprints; same one is stable. */
    ASSERT_TRUE(memcmp(fa, fb, D->hash_len) != 0, "distinct fingerprints");
    ASSERT_EQ(gy_fingerprint(D, fa2, &a.pub), GY_OK);
    ASSERT_MEMEQ(fa, fa2, D->hash_len);

    /* Flipping any identity byte changes the fingerprint. */
    a.pub.pk[0] ^= 0x01;
    ASSERT_EQ(gy_fingerprint(D, fa2, &a.pub), GY_OK);
    ASSERT_TRUE(memcmp(fa, fa2, D->hash_len) != 0, "fingerprint tracks key");
}

TEST(arg_rejects)
{
    struct gy_keypair kp;
    struct gy_signed_prekey spk;
    struct gy_prekey_bundle b;

    ASSERT_EQ(gy_keypair_generate(NULL, &kp), GY_ERR_ARG);
    ASSERT_EQ(gy_keypair_generate(D, NULL), GY_ERR_ARG);
    ASSERT_EQ(gy_spk_create(D, &spk, NULL, TS), GY_ERR_ARG);
    ASSERT_EQ(gy_bundle_validate(D, NULL), GY_ERR_ARG);
    ASSERT_EQ(gy_fingerprint(D, NULL, &kp.pub), GY_ERR_ARG);
    memset(&b, 0, sizeof(b));
    ASSERT_EQ(gy_opk_batch(D, NULL, 4, NULL, 0), GY_ERR_ARG);
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
            GY_TEST(validate_ok),
            GY_TEST(tamper_curve_type),
            GY_TEST(tamper_pkid),
            GY_TEST(tamper_signature_and_timestamp),
            GY_TEST(opk_absent_present),
            GY_TEST(batch_uniqueness),
            GY_TEST(regen_decision),
            GY_TEST(fingerprint),
            GY_TEST(arg_rejects),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
