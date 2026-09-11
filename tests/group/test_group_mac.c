/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the [CPZ] section 3.1 algebraic MAC (GROUP_SPEC section 4,
 * GER-M8-03): ServerSecretParams KeyGen, ServerPublicParams iparams (C_W, I),
 * MAC and Verify over group-element attributes, and the section 9 object
 * encodings, on both classical tiers and both credential-family key shapes
 * (n' = 3 for sk_A, n' = 4 for sk_P).
 *
 * There is no external oracle (D-GRP-9); this suite validates the spec-required
 * PROPERTIES: KeyGen determinism through the KAT core, iparams recomputation,
 * MAC correctness, rejection of tampered attributes / tampered tags / the wrong
 * key, encoding round-trip, and [CPZ] Table 1 element counts.  The byte-exact
 * frozen vectors are pinned separately (test_group_mac_vectors).
 */

#include <stdint.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_tier.h"
#include "group_wire.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

static const uint8_t suites[] = {GY_SUITE_C25519, GY_SUITE_C448};

/* Fill eight fixed canonical scalars: low bytes carry a per-scalar pattern,
 * high bytes stay zero so the value is < l on both tiers (< 2^128 < l). */
static void
fixed_scalars(const struct gy_group_tier *tier,
              uint8_t s[8][GY_GROUP_SCALAR_MAX], uint8_t base)
{
    size_t j, k;

    memset(s, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++)
        for (k = 0; k < 12; k++)
            s[j][k] = (uint8_t)(base + j * 13 + k + 1);
    (void)tier;
}

/* n distinct attribute points from a fixed seed (index-separated). */
static void
make_attrs(const struct gy_group_tier *tier, uint8_t M[][GY_GROUP_POINT_MAX],
           size_t n)
{
    static const uint8_t seed[7] = {'g', 'r', 'p', 'a', 't', 't', 'r'};
    size_t i;

    for (i = 0; i < n; i++)
        (void)tier->hash_to_group(M[i], seed, sizeof(seed), (uint32_t)i);
}

TEST(init)
{
    ASSERT_EQ(talos_schnorr_init(), 0);
    ASSERT_EQ(gy_core_init(), GY_OK);
}

/* KeyGen core is deterministic and W = G_w^w recomputes; iparams derive. */
TEST(keygen_iparams)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret k1, k2;
        struct gy_group_server_public pp;
        uint8_t w_chk[GY_GROUP_POINT_MAX];

        ASSERT_TRUE(tier != NULL, "tier");
        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(tier, sc, 0x10);

        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &k1),
                  GY_OK);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &k2),
                  GY_OK);
        ASSERT_MEMEQ(&k1, &k2, sizeof(k1));
        ASSERT_EQ(k1.n_bound, 4);

        /* W = G_w^w recomputes independently. */
        ASSERT_EQ(tier->point_scalarmul(w_chk, k1.w, gens.g[GY_GEN_W]), 0);
        ASSERT_TRUE(tier->point_eq(w_chk, k1.W) == 0, "W = G_w^w");

        /* iparams derive, non-degenerate, deterministic. */
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &k1, &pp),
                  GY_OK);
        ASSERT_TRUE(!gy_is_zero(pp.C_W, tier->point_len), "C_W nonzero");
        ASSERT_TRUE(!gy_is_zero(pp.I, tier->point_len), "I nonzero");

        /* n_bound out of range rejected. */
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 2, sc, &k1),
                  GY_ERR_ARG);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 5, sc, &k1),
                  GY_ERR_ARG);

        gy_group_server_secret_clear(&k1);
        gy_group_server_secret_clear(&k2);
    }
}

/* iparams n' binding differs between the auth (3) and profile (4) shapes. */
TEST(iparams_bound_count)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret ka, kp;
        struct gy_group_server_public pa, pp;

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(tier, sc, 0x20);

        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 3, sc, &ka),
                  GY_OK);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &kp),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &ka, &pa),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &kp, &pp),
                  GY_OK);

        /* Same scalars, different n' -> I binds a different generator product,
         * so I differs; C_W is independent of n' and matches. */
        ASSERT_TRUE(tier->point_eq(pa.C_W, pp.C_W) == 0,
                    "C_W independent of n'");
        ASSERT_TRUE(tier->point_eq(pa.I, pp.I) != 0, "I depends on n'");
    }
}

/* MAC verifies on honest inputs and rejects tampering, both families. */
TEST(mac_verify_reject)
{
    static const unsigned nb[2] = {3, 4};
    size_t s, f;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);

        for (f = 0; f < 2; f++) {
            struct gy_group_server_secret sk, sk2;
            struct gy_group_mac_tag tag;
            uint8_t M[GY_GROUP_MAC_ATTRS][GY_GROUP_POINT_MAX];
            unsigned n = nb[f];

            fixed_scalars(tier, sc, (uint8_t)(0x30 + f));
            ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, n, sc, &sk),
                      GY_OK);
            make_attrs(tier, M, n);

            /* Honest MAC verifies. */
            ASSERT_EQ(gy_group_mac(tier, &sk,
                                   (const uint8_t(*)[GY_GROUP_POINT_MAX])M, n,
                                   &tag),
                      GY_OK);
            ASSERT_EQ(gy_group_verify(tier, &sk,
                                      (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                                      n, &tag),
                      GY_OK);

            /* Tampered attribute rejected: swap in a different attribute point. */
            {
                uint8_t Mt[GY_GROUP_MAC_ATTRS][GY_GROUP_POINT_MAX];
                memcpy(Mt, M, sizeof(Mt));
                (void)tier->hash_to_group(Mt[0], (const uint8_t *)"x", 1, 99);
                ASSERT_EQ(
                    gy_group_verify(tier, &sk,
                                    (const uint8_t(*)[GY_GROUP_POINT_MAX])Mt, n,
                                    &tag),
                    GY_ERR_VERIFY);
            }

            /* Tampered tag rejected: flip a byte of t, and of V. */
            {
                struct gy_group_mac_tag bad = tag;
                bad.t[0] ^= 0x01;
                ASSERT_EQ(gy_group_verify(
                              tier, &sk,
                              (const uint8_t(*)[GY_GROUP_POINT_MAX])M, n, &bad),
                          GY_ERR_VERIFY);
                bad = tag;
                bad.V[0] ^= 0x01;
                ASSERT_EQ(gy_group_verify(
                              tier, &sk,
                              (const uint8_t(*)[GY_GROUP_POINT_MAX])M, n, &bad),
                          GY_ERR_VERIFY);
            }

            /* Wrong key rejected. */
            fixed_scalars(tier, sc, (uint8_t)(0x70 + f));
            ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, n, sc, &sk2),
                      GY_OK);
            ASSERT_EQ(gy_group_verify(tier, &sk2,
                                      (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                                      n, &tag),
                      GY_ERR_VERIFY);

            /* n_attr must equal n_bound. */
            ASSERT_EQ(gy_group_mac(tier, &sk,
                                   (const uint8_t(*)[GY_GROUP_POINT_MAX])M,
                                   n == 4 ? 3 : 4, &tag),
                      GY_ERR_ARG);

            gy_group_server_secret_clear(&sk);
            gy_group_server_secret_clear(&sk2);
        }
    }
}

/* The deterministic MAC core reproduces its tag for fixed (t, u). */
TEST(mac_core_deterministic)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret sk;
        struct gy_group_mac_tag a, b;
        uint8_t M[GY_GROUP_MAC_ATTRS][GY_GROUP_POINT_MAX];
        uint8_t t[GY_GROUP_SCALAR_MAX], u[GY_GROUP_SCALAR_MAX];

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(tier, sc, 0x40);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &sk),
                  GY_OK);
        make_attrs(tier, M, 4);

        memset(t, 0, sizeof(t));
        memset(u, 0, sizeof(u));
        t[0] = 0x09;
        t[1] = 0x11;
        u[0] = 0x07;
        u[1] = 0x2a;

        ASSERT_EQ(gy_group_mac_tu(tier, &sk,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4, t,
                                  u, &a),
                  GY_OK);
        ASSERT_EQ(gy_group_mac_tu(tier, &sk,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4, t,
                                  u, &b),
                  GY_OK);
        ASSERT_MEMEQ(&a, &b, sizeof(a));
        ASSERT_EQ(gy_group_verify(tier, &sk,
                                  (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4,
                                  &a),
                  GY_OK);

        gy_group_server_secret_clear(&sk);
    }
}

/* Object encodings round-trip and carry the right sizes ([CPZ] Table 1). */
TEST(object_encoding)
{
    size_t s;

    for (s = 0; s < sizeof(suites); s++) {
        const struct gy_group_tier *tier = gy_group_tier_for(suites[s]);
        struct gy_group_generators gens;
        uint8_t sc[8][GY_GROUP_SCALAR_MAX];
        struct gy_group_server_secret sk;
        struct gy_group_server_public pp, pp2;
        struct gy_group_mac_tag tag, tag2;
        uint8_t M[GY_GROUP_MAC_ATTRS][GY_GROUP_POINT_MAX];
        uint8_t buf[GY_GROUP_SERVER_PUBLIC_ENC_MAX];
        uint8_t tbuf[GY_GROUP_MAC_TAG_ENC_MAX];
        size_t n, plen, slen;

        plen = tier->point_len;
        slen = tier->scalar_len;

        ASSERT_EQ(gy_group_generators_derive(tier, &gens), GY_OK);
        fixed_scalars(tier, sc, 0x50);
        ASSERT_EQ(gy_group_server_keygen_scalars(tier, &gens, 4, sc, &sk),
                  GY_OK);
        ASSERT_EQ(gy_group_server_public_from_secret(tier, &gens, &sk, &pp),
                  GY_OK);
        make_attrs(tier, M, 4);
        ASSERT_EQ(gy_group_mac(tier, &sk,
                               (const uint8_t(*)[GY_GROUP_POINT_MAX])M, 4,
                               &tag),
                  GY_OK);

        /* ServerPublicParams: 3-byte header + 2 group elements (Table 1). */
        ASSERT_EQ(
            gy_group_server_public_encode(tier, &pp, buf, sizeof(buf), &n),
            GY_OK);
        ASSERT_EQ(n, GY_GROUP_OBJ_HDR_LEN + 2 * plen);
        ASSERT_EQ(buf[0], GY_GOBJ_SERVER_PUBLIC);
        ASSERT_EQ(buf[1], GY_GROUP_WIRE_VERSION);
        ASSERT_EQ(buf[2], tier->suite_id);
        ASSERT_EQ(gy_group_server_public_decode(tier, &pp2, buf, n), GY_OK);
        ASSERT_MEMEQ(&pp, &pp2, sizeof(pp));

        /* Strict parse: trailing byte and wrong suite tag rejected. */
        ASSERT_EQ(gy_group_server_public_decode(tier, &pp2, buf, n + 1),
                  GY_ERR_VERIFY);
        buf[2] ^= 0xff;
        ASSERT_EQ(gy_group_server_public_decode(tier, &pp2, buf, n),
                  GY_ERR_VERIFY);

        /* MAC tag: untagged, 1 scalar + 2 group elements (Table 1). */
        ASSERT_EQ(gy_group_mac_tag_encode(tier, &tag, tbuf, sizeof(tbuf), &n),
                  GY_OK);
        ASSERT_EQ(n, slen + 2 * plen);
        ASSERT_EQ(gy_group_mac_tag_decode(tier, &tag2, tbuf, n), GY_OK);
        ASSERT_MEMEQ(&tag, &tag2, sizeof(tag));
        ASSERT_EQ(gy_group_mac_tag_decode(tier, &tag2, tbuf, n - 1),
                  GY_ERR_VERIFY);

        gy_group_server_secret_clear(&sk);
    }
}

GY_TEST_MAIN(GY_TEST(init), GY_TEST(keygen_iparams),
             GY_TEST(iparams_bound_count), GY_TEST(mac_verify_reject),
             GY_TEST(mac_core_deterministic), GY_TEST(object_encoding))
