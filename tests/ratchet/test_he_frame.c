/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Header-encryption wire and state tests (D-DR-13/14/16/17).  Built with
 * -DGY_TEST_HOOKS for the ratchet-keypair and
 * hdr_salt seams and for reading header-key state.  The full (hk, n) skipped
 * re-key and cross-epoch out-of-order receive follow D-DR-17.
 */

#include <stdint.h>
#include <string.h>

#include "double_ratchet.h"
#include "he.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
static const uint64_t TS = 0x0000000155667788ull;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Classical frame overhead before the payload: version || suite_id ||
 * hdr_salt(16) || enc_header_len(2) || enc_header(60).  enc_header is the
 * 44-byte c25519 header plus a 16-byte tag. */
#define C25519_ENC_HEADER 60
#define C25519_FRAME_OVERHEAD (2 + GY_HE_SALT_LEN + 2 + C25519_ENC_HEADER)

static void
do_handshake(struct gy_dr_secrets *sa, struct gy_dr_secrets *sb, uint8_t *ad,
             size_t *adlen, uint8_t bob_spk_pub[32],
             struct gy_keypair *bob_spk_kp)
{
    struct gy_keypair alice_ik, bob_ik, ek, bob_opk[1];
    struct gy_signed_prekey bob_spk;
    struct gy_prekey_bundle bundle;
    struct gy_x3dh_opk_ref ref;
    struct gy_x3dh_local local;
    uint8_t prefix[GY_X3DH_PREFIX_MAX], adb[GY_X3DH_AD_MAX];
    size_t prefl, adbl;

    ASSERT_EQ(gy_keypair_generate(D, &alice_ik), GY_OK);
    ASSERT_EQ(gy_keypair_generate(D, &bob_ik), GY_OK);
    ASSERT_EQ(gy_spk_create(D, &bob_spk, bob_ik.sk, TS), GY_OK);
    ASSERT_EQ(gy_opk_batch(D, bob_opk, 1, NULL, 0), GY_OK);

    memset(&bundle, 0, sizeof(bundle));
    bundle.ik = bob_ik.pub;
    bundle.spk = bob_spk.kp.pub;
    bundle.spk_timestamp = TS;
    memcpy(bundle.spk_sig, bob_spk.sig, GY_SIG_MAX);
    bundle.opk = bob_opk[0].pub;

    ASSERT_EQ(gy_keypair_generate(D, &ek), GY_OK);
    ASSERT_EQ(gy_x3dh_initiate(D, sa, ad, adlen, prefix, &prefl, &alice_ik,
                               &bundle, &ek),
              GY_OK);

    local.ik = &bob_ik;
    local.spk = &bob_spk.kp;
    local.opks = bob_opk;
    local.n_opks = 1;
    ASSERT_EQ(gy_x3dh_respond(D, sb, adb, &adbl, &ref, &local, prefix, prefl),
              GY_OK);

    memcpy(bob_spk_pub, bundle.spk.pk, 32);
    *bob_spk_kp = bob_spk.kp;
}

/* The classical frame carries a fixed overhead and a plaintext-free header. */
TEST(frame_overhead)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t wire[256];
    size_t adl, wirelen, ptlen = 5;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    ASSERT_EQ(gy_dr_encrypt(&alice, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)"hello", ptlen, ad, adl),
              GY_OK);

    /* version || suite_id || salt || len || enc_header || payload(pt + tag). */
    ASSERT_EQ(wirelen, (size_t)(C25519_FRAME_OVERHEAD + ptlen + 16));
    ASSERT_EQ(wire[0], GY_WIRE_VERSION);
    ASSERT_EQ(wire[1], GY_SUITE_C25519);
    ASSERT_EQ((size_t)gy_be16_get(wire + 2 + GY_HE_SALT_LEN),
              C25519_ENC_HEADER);

    gy_dr_free(&alice);
}

/* HE from message one: Bob decrypts Alice's first header via NHKr (= hka),
 * which becomes his HKr after the ratchet; the reverse holds for Alice. */
TEST(init_mapping_roles)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t exp_hka[32], exp_nhkb[32];
    uint8_t wire[256], out[256];
    size_t adl, wirelen, outlen;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    memcpy(exp_hka, sb.shared_hka, 32);
    memcpy(exp_nhkb, sb.shared_nhkb, 32);

    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    /* Mapping at init (D-DR-13): Alice HKs = hka; Bob NHKr = hka, NHKs = nhkb. */
    ASSERT_EQ(alice.have_hks, 1);
    ASSERT_MEMEQ(alice.hks, exp_hka, 32);
    ASSERT_EQ(alice.have_hkr, 0);
    ASSERT_MEMEQ(alice.nhkr, exp_nhkb, 32);
    ASSERT_EQ(bob.have_hkr, 0);
    ASSERT_MEMEQ(bob.nhkr, exp_hka, 32);
    ASSERT_MEMEQ(bob.nhks, exp_nhkb, 32);

    /* Alice -> Bob: header decrypts via Bob's NHKr, which rotates into HKr. */
    ASSERT_EQ(gy_dr_encrypt(&alice, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)"a1", 2, ad, adl),
              GY_OK);
    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_OK);
    ASSERT_EQ(bob.have_hkr, 1);
    ASSERT_MEMEQ(bob.hkr, exp_hka, 32);

    /* Bob -> Alice: his first send established HKs = nhkb (rotated from NHKs);
     * Alice decrypts it via her NHKr (= nhkb), which rotates into her HKr. */
    ASSERT_MEMEQ(bob.hks, exp_nhkb, 32);
    ASSERT_EQ(gy_dr_encrypt(&bob, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)"b1", 2, ad, adl),
              GY_OK);
    ASSERT_EQ(gy_dr_decrypt(&alice, out, sizeof(out), &outlen, wire, wirelen,
                            ad, adl),
              GY_OK);
    ASSERT_EQ(alice.have_hkr, 1);
    ASSERT_MEMEQ(alice.hkr, exp_nhkb, 32);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

/* A wrong enc_header_len is rejected before any key derivation (section 7.8.4). */
TEST(enc_header_len_rejected)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t wire[256], out[256];
    size_t adl, wirelen, outlen;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    ASSERT_EQ(gy_dr_encrypt(&alice, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)"x", 1, ad, adl),
              GY_OK);
    /* Claim a different (still <= 65535) enc_header length. */
    gy_be16_put(wire + 2 + GY_HE_SALT_LEN, C25519_ENC_HEADER + 1);
    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_ERR_ARG);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

/* A cross-suite/version prefix is rejected by gy_frame_check (D-GEN-1). */
TEST(bad_prefix_rejected)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t wire[256], out[256], save;
    size_t adl, wirelen, outlen;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    ASSERT_EQ(gy_dr_encrypt(&alice, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)"x", 1, ad, adl),
              GY_OK);
    save = wire[1];
    wire[1] = GY_SUITE_C448; /* cross-suite */
    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_ERR_STATE);
    wire[1] = save;
    wire[0] = 0x7f; /* bad version */
    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_ERR_ARG);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

/* Splicing message B's header wire unit onto message A's payload fails the
 * payload tag: AD_payload binds the whole header unit (D-DR-16). */
TEST(cross_splice_rejected)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t wa[256], wb[256], spliced[256], out[256];
    size_t adl, la, lb, slen, outlen;
    size_t hwlen = GY_HE_SALT_LEN + 2 + C25519_ENC_HEADER;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    /* Two Alice sends in the same epoch (same HKs, n = 0 and n = 1). */
    ASSERT_EQ(gy_dr_encrypt(&alice, wa, sizeof(wa), &la, (const uint8_t *)"a1",
                            2, ad, adl),
              GY_OK);
    ASSERT_EQ(gy_dr_encrypt(&alice, wb, sizeof(wb), &lb, (const uint8_t *)"b2",
                            2, ad, adl),
              GY_OK);

    /* prefix || B's header unit || A's payload. */
    memcpy(spliced, wa, 2);
    memcpy(spliced + 2, wb + 2, hwlen); /* B's salt/len/enc_header */
    memcpy(spliced + 2 + hwlen, wa + 2 + hwlen, la - 2 - hwlen); /* A payload */
    slen = 2 + hwlen + (la - 2 - hwlen);

    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, spliced, slen, ad, adl),
        GY_ERR_VERIFY);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

/* No plaintext header field (the ratchet public key) appears on the wire. */
TEST(no_plaintext_header)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    uint8_t wire[256], rpk[32];
    size_t adl, wirelen, i, msg;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);
    memcpy(rpk, alice.dhs.pub.pk, 32);

    for (msg = 0; msg < 4; msg++) {
        ASSERT_EQ(gy_dr_encrypt(&alice, wire, sizeof(wire), &wirelen,
                                (const uint8_t *)"payload", 7, ad, adl),
                  GY_OK);
        /* The 32-byte ratchet pk never appears in the emitted frame. */
        for (i = 0; i + 32 <= wirelen; i++)
            ASSERT_TRUE(memcmp(wire + i, rpk, 32) != 0, "ratchet pk on wire");
    }

    gy_dr_free(&alice);
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
            GY_TEST(frame_overhead),          GY_TEST(init_mapping_roles),
            GY_TEST(enc_header_len_rejected), GY_TEST(bad_prefix_rejected),
            GY_TEST(cross_splice_rejected),   GY_TEST(no_plaintext_header),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
