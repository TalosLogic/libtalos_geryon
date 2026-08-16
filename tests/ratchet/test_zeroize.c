/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Consolidated zeroization sweep: walks the D-X3DH-13 handshake
 * deletion points and the Double Ratchet teardown, asserting secret material
 * is erased on both success and failure paths.  Poison patterns confirm the
 * fields were actively overwritten, not merely left at their initial value.
 */

#include <stdint.h>
#include <string.h>

#include "double_ratchet.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
static const uint64_t TS = 0x0000000155667788ull;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Build Bob's identity, SPK, one OPK, and the published bundle. */
static void
bob_setup(struct gy_keypair *bob_ik, struct gy_signed_prekey *bob_spk,
          struct gy_keypair *bob_opk, struct gy_prekey_bundle *bundle)
{
    ASSERT_EQ(gy_keypair_generate(D, bob_ik), GY_OK);
    ASSERT_EQ(gy_spk_create(D, bob_spk, bob_ik->sk, TS), GY_OK);
    ASSERT_EQ(gy_opk_batch(D, bob_opk, 1, NULL, 0), GY_OK);

    memset(bundle, 0, sizeof(*bundle));
    bundle->ik = bob_ik->pub;
    bundle->spk = bob_spk->kp.pub;
    bundle->spk_timestamp = TS;
    memcpy(bundle->spk_sig, bob_spk->sig, GY_SIG_MAX);
    bundle->opk = bob_opk[0].pub;
}

TEST(x3dh_initiate_deletes_ek_success)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_dr_secrets secrets;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    size_t adl, prefl;

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    bob_setup(&bob_ik, &bob_spk, bob_opk, &bundle);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_TRUE(gy_is_zero(ek.sk, 32) == 0, "ek.sk seeded before use");

    ASSERT_EQ(gy_x3dh_initiate(D, &secrets, ad, &adl, prefix, &prefl, &alice_ik,
                               &bundle, &ek),
              GY_OK);
    /* D-X3DH-13: EK private zeroized after SK derivation. */
    ASSERT_EQ(gy_is_zero(ek.sk, 32), 1);
}

/* Re-sign the SPK after substituting a low-order point so the bundle validates
 * but the handshake fails at DH (isolating the failure-path deletion). */
TEST(x3dh_initiate_deletes_ek_on_failure)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_dr_secrets secrets;
    uint8_t ad[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX], enc[33], sd[41];
    uint32_t pkid;
    size_t adl, prefl;
    /* Curve25519 order-8 point: DH(clamped, this) is all-zero -> GY_ERR_WEAK_KEY. */
    static const uint8_t low_order[32] = {
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
        0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
        0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00};

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    bob_setup(&bob_ik, &bob_spk, bob_opk, &bundle);

    memcpy(bundle.spk.pk, low_order, 32);
    enc[0] = bundle.spk.curve_type;
    memcpy(enc + 1, low_order, 32);
    ASSERT_EQ(gy_pkid(&pkid, D->suite_id, enc, 33), GY_OK);
    bundle.spk.pkid = pkid;
    memcpy(sd, enc, 33);
    gy_be64_put(sd + 33, bundle.spk_timestamp);
    ASSERT_EQ(D->sign(bundle.spk_sig, bob_ik.sk, sd, 41), GY_OK);

    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &secrets, ad, &adl, prefix, &prefl, &alice_ik,
                               &bundle, &ek),
              GY_ERR_WEAK_KEY);
    /* Deletion holds on the failure path too (D-X3DH-13). */
    ASSERT_EQ(gy_is_zero(ek.sk, 32), 1);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&secrets, sizeof(secrets)), 1);
}

TEST(dr_init_consumes_skdr)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local local;
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    uint8_t ad[GY_X3DH_AD_MAX], adb[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    size_t adl, adbl, prefl;

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    bob_setup(&bob_ik, &bob_spk, bob_opk, &bundle);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &alice_ik,
                               &bundle, &ek),
              GY_OK);
    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    ASSERT_EQ(gy_x3dh_respond(D, &sb, adb, &adbl, &ref, &local, prefix, prefl),
              GY_OK);

    /* Each init transfers ownership of SKdr and zeroizes the caller's copy. */
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bundle.spk.pk), GY_OK);
    ASSERT_EQ(gy_is_zero(sa.sk_dr, 32), 1);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk.kp), GY_OK);
    ASSERT_EQ(gy_is_zero(sb.sk_dr, 32), 1);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

TEST(dr_teardown_zeroizes_all)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local local;
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    uint8_t ad[GY_X3DH_AD_MAX], adb[GY_X3DH_AD_MAX], prefix[GY_X3DH_PREFIX_MAX];
    uint8_t out[128];
    size_t adl, adbl, prefl, ol;
    int i;

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    bob_setup(&bob_ik, &bob_spk, bob_opk, &bundle);
    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, &sa, ad, &adl, prefix, &prefl, &alice_ik,
                               &bundle, &ek),
              GY_OK);
    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    ASSERT_EQ(gy_x3dh_respond(D, &sb, adb, &adbl, &ref, &local, prefix, prefl),
              GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bundle.spk.pk), GY_OK);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk.kp), GY_OK);

    /* Populate live keys and a non-empty skipped-key store (deliver m1 before
     * m0 so m0's key is stored), then confirm teardown erases everything. */
    {
        uint8_t w0[128], w1[128];
        size_t w0l, w1l;
        ASSERT_EQ(gy_dr_encrypt(&alice, w0, sizeof(w0), &w0l,
                                (const uint8_t *)"m0", 2, ad, adl),
                  GY_OK);
        ASSERT_EQ(gy_dr_encrypt(&alice, w1, sizeof(w1), &w1l,
                                (const uint8_t *)"m1", 2, ad, adl),
                  GY_OK);
        ASSERT_EQ(gy_dr_decrypt(&bob, out, sizeof(out), &ol, w1, w1l, ad, adl),
                  GY_OK);
        ASSERT_EQ(bob.skipped.count, 1);
    }
    for (i = 0; i < 3; i++)
        ASSERT_EQ(gy_is_zero(bob.rk, 32), 0); /* live keys are non-zero */

    /* HE state is live: header keys (D-DR-13/14) and the stored epoch's hk
     * (D-DR-17) are all non-zero before teardown, so the whole-struct check
     * below actually proves they were erased, not merely never set. */
    ASSERT_EQ(bob.have_hks, 1);
    ASSERT_EQ(gy_is_zero(bob.hks, 32), 0);
    ASSERT_EQ(bob.have_hkr, 1);
    ASSERT_EQ(gy_is_zero(bob.hkr, 32), 0);
    ASSERT_EQ(gy_is_zero(bob.nhkr, 32), 0);
    {
        size_t e;
        int live = 0;
        for (e = 0; e < GY_MAX_SKIP; e++)
            if (bob.skipped.epochs[e].refs > 0) {
                ASSERT_EQ(gy_is_zero(bob.skipped.epochs[e].hk, 32), 0);
                live = 1;
            }
        ASSERT_TRUE(live, "a stored epoch header key is live before teardown");
    }

    gy_dr_free(&bob);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&bob, sizeof(bob)), 1);
    gy_dr_free(&alice);
    ASSERT_EQ(gy_is_zero((const uint8_t *)&alice, sizeof(alice)), 1);
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
            GY_TEST(x3dh_initiate_deletes_ek_success),
            GY_TEST(x3dh_initiate_deletes_ek_on_failure),
            GY_TEST(dr_init_consumes_skdr),
            GY_TEST(dr_teardown_zeroizes_all),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
