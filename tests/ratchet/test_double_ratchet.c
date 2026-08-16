/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for src/ratchet/double_ratchet.c (D-DR-1/2/3/7/9/13).
 * Built with -DGY_TEST_HOOKS for the
 * KDF exposures and the ratchet-keypair seam.
 */

#include <stdint.h>
#include <string.h>

#include "double_ratchet.h"
#include "hash.h"
#include "he.h"

#include "gy_test.h"

static const struct gy_suite_desc *D;
static const uint64_t TS = 0x0000000155667788ull;
#define AEAD GY_AEAD_CHACHA20POLY1305

/* Run a full classical handshake; return both seed triples, AD, and the
 * responder's SPK public and key pair (Bob's initial ratchet material). */
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

TEST(init_mapping)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32], skdr[32];
    size_t adl;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);

    /* Bob's initial root key equals SKdr (section 7.2 mapping, D-DR-13). */
    memcpy(skdr, sb.sk_dr, 32);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_MEMEQ(bob.rk, skdr, 32);
    ASSERT_EQ(bob.have_cks, 0);
    ASSERT_EQ(bob.have_ckr, 0);

    /* Alice ratchets on init, so her state carries a sending chain. */
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);
    ASSERT_EQ(alice.have_cks, 1);
    /* SKdr is consumed by both inits. */
    ASSERT_EQ(gy_is_zero(sa.sk_dr, 32), 1);
    ASSERT_EQ(gy_is_zero(sb.sk_dr, 32), 1);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

/* Encrypt pt on `from`, decrypt on `to`, assert the plaintext round-trips. */
static void
relay(struct gy_dr_state *from, struct gy_dr_state *to, const uint8_t *ad,
      size_t adl, const char *pt)
{
    uint8_t wire[256], out[256];
    size_t wirelen, outlen, ptlen = strlen(pt);

    ASSERT_EQ(gy_dr_encrypt(from, wire, sizeof(wire), &wirelen,
                            (const uint8_t *)pt, ptlen, ad, adl),
              GY_OK);
    ASSERT_EQ(
        gy_dr_decrypt(to, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_OK);
    ASSERT_EQ(outlen, ptlen);
    ASSERT_MEMEQ(out, pt, ptlen);
}

TEST(ping_pong)
{
    struct gy_dr_secrets sa, sb;
    struct gy_dr_state alice, bob;
    struct gy_keypair bob_spk_kp;
    uint8_t ad[GY_X3DH_AD_MAX], bob_spk_pub[32];
    size_t adl;

    do_handshake(&sa, &sb, ad, &adl, bob_spk_pub, &bob_spk_kp);
    ASSERT_EQ(gy_dr_init_bob(&bob, D, AEAD, &sb, &bob_spk_kp), GY_OK);
    ASSERT_EQ(gy_dr_init_alice(&alice, D, AEAD, &sa, bob_spk_pub), GY_OK);

    /* Alice -> Bob (two in the same chain), then epoch flips both ways. */
    relay(&alice, &bob, ad, adl, "a1");
    relay(&alice, &bob, ad, adl, "a2");
    relay(&bob, &alice, ad, adl, "b1"); /* Bob's first send: DH ratchet */
    relay(&bob, &alice, ad, adl, "b2");
    relay(&alice, &bob, ad, adl, "a3"); /* epoch flip back */
    relay(&bob, &alice, ad, adl, "b3");
    relay(&alice, &bob, ad, adl, "a4");

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

TEST(tamper_rejected)
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
                            (const uint8_t *)"secret", 6, ad, adl),
              GY_OK);
    /* Flip a ciphertext byte: the tag fails. */
    wire[wirelen - 1] ^= 0x01;
    ASSERT_EQ(
        gy_dr_decrypt(&bob, out, sizeof(out), &outlen, wire, wirelen, ad, adl),
        GY_ERR_VERIFY);

    gy_dr_free(&alice);
    gy_dr_free(&bob);
}

TEST(kdf_rk_hkdf_path)
{
    uint8_t rk[32], dh[32];
    uint8_t out_rk[32], out_ck[32], out_nhk[32];
    uint8_t prk[32], okm[96], info[48];
    size_t infolen, i;

    for (i = 0; i < 32; i++) {
        rk[i] = (uint8_t)(0x10 + i);
        dh[i] = (uint8_t)(0x80 + i);
    }

    ASSERT_EQ(gy_dr_kdf_rk(D, rk, dh, out_rk, out_ck, out_nhk), GY_OK);

    /* Independent recompute through the RFC 5869 primitives (salt = rk). */
    ASSERT_EQ(gy_hkdf_sha256_extract(prk, rk, 32, dh, 32), GY_OK);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "dr.root"),
              GY_OK);
    ASSERT_EQ(gy_hkdf_sha256_expand(okm, 96, prk, info, infolen), GY_OK);
    ASSERT_MEMEQ(out_rk, okm, 32);
    ASSERT_MEMEQ(out_ck, okm + 32, 32);
    ASSERT_MEMEQ(out_nhk, okm + 64, 32);
}

TEST(kdf_ck_ctr_path)
{
    uint8_t ck[32], mk[32], ckn[32], want[32], info[48];
    size_t infolen, i;

    for (i = 0; i < 32; i++)
        ck[i] = (uint8_t)(0x30 + i);

    ASSERT_EQ(gy_dr_kdf_ck(D, ck, mk, ckn), GY_OK);

    /* Independent recompute through the SP 800-108 KDF-CTR (dr.msg/dr.chain). */
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "dr.msg"),
              GY_OK);
    ASSERT_EQ(gy_kdf_ctr(D, want, 32, ck, 32, info, infolen, NULL, 0), GY_OK);
    ASSERT_MEMEQ(mk, want, 32);
    ASSERT_EQ(gy_info(info, sizeof(info), &infolen, D->suite_id, "dr.chain"),
              GY_OK);
    ASSERT_EQ(gy_kdf_ctr(D, want, 32, ck, 32, info, infolen, NULL, 0), GY_OK);
    ASSERT_MEMEQ(ckn, want, 32);
}

TEST(nonce_uniqueness)
{
    enum { NMK = 3, NN = 100, TOTAL = NMK * NN };
    uint8_t nonces[TOTAL][GY_AEAD_MAX_NONCE];
    uint8_t mk[32], key[32];
    size_t nl, idx, a, b;
    int m, n;

    idx = 0;
    for (m = 0; m < NMK; m++) {
        memset(mk, 0, sizeof(mk));
        mk[0] = (uint8_t)(m + 1);
        for (n = 0; n < NN; n++) {
            ASSERT_EQ(gy_dr_derive_aead(D, mk, AEAD, (uint32_t)n, key,
                                        nonces[idx], &nl),
                      GY_OK);
            idx++;
        }
    }

    /* Distinct (mk, n) never collide on the derived nonce. */
    for (a = 0; a < TOTAL; a++)
        for (b = a + 1; b < TOTAL; b++)
            ASSERT_TRUE(memcmp(nonces[a], nonces[b], nl) != 0, "nonce unique");
}

/* Deterministic ratchet-keypair source for the determinism KAT. */
static struct gy_keypair g_fixed[4];
static size_t g_fixed_idx;

static int
fixed_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
    (void)desc;
    *out = g_fixed[g_fixed_idx % 4];
    g_fixed_idx++;
    return GY_OK;
}

/* Deterministic hdr_salt source so the header ciphertext is reproducible. */
static int
fixed_salt(uint8_t *out, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++)
        out[i] = (uint8_t)(0xA0 + i);
    return GY_OK;
}

TEST(determinism)
{
    struct gy_dr_secrets s1, s2;
    struct gy_dr_state st1, st2;
    uint8_t remote[32], ad[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t w1[128], w2[128];
    size_t l1, l2, i;

    for (i = 0; i < 4; i++)
        ASSERT_EQ(gy_keypair_generate(D, &g_fixed[i]), GY_OK);
    memcpy(remote, g_fixed[1].pub.pk, 32);

    /* Fixed seed triple so the only randomness would be ratchet keys. */
    memset(&s1, 0, sizeof(s1));
    for (i = 0; i < 32; i++) {
        s1.sk_dr[i] = (uint8_t)(0x40 + i);
        s1.shared_hka[i] = (uint8_t)(0x60 + i);
        s1.shared_nhkb[i] = (uint8_t)(0x80 + i);
    }
    s2 = s1;

    gy_dr_test_keypair = fixed_keypair;
    gy_he_test_salt = fixed_salt; /* both RNG seams fixed (D-DR-11) */

    g_fixed_idx = 0;
    ASSERT_EQ(gy_dr_init_alice(&st1, D, AEAD, &s1, remote), GY_OK);
    ASSERT_EQ(gy_dr_encrypt(&st1, w1, sizeof(w1), &l1, (const uint8_t *)"det",
                            3, ad, sizeof(ad)),
              GY_OK);

    g_fixed_idx = 0;
    ASSERT_EQ(gy_dr_init_alice(&st2, D, AEAD, &s2, remote), GY_OK);
    ASSERT_EQ(gy_dr_encrypt(&st2, w2, sizeof(w2), &l2, (const uint8_t *)"det",
                            3, ad, sizeof(ad)),
              GY_OK);

    gy_dr_test_keypair = NULL; /* restore production generation */
    gy_he_test_salt = NULL;

    /* Same inputs and same injected ratchet keys -> identical wire bytes. */
    ASSERT_EQ(l1, l2);
    ASSERT_MEMEQ(w1, w2, l1);

    gy_dr_free(&st1);
    gy_dr_free(&st2);
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
            GY_TEST(init_mapping),    GY_TEST(ping_pong),
            GY_TEST(tamper_rejected), GY_TEST(kdf_rk_hkdf_path),
            GY_TEST(kdf_ck_ctr_path), GY_TEST(nonce_uniqueness),
            GY_TEST(determinism),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
