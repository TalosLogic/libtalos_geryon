/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen self-KAT check for the algebraic MAC (GROUP_SPEC section 4).  For
 * fixed ServerSecretParams scalars, fixed attribute points,
 * and fixed MAC randomness (t, u), recomputes iparams (C_W, I) and the MAC tag
 * (t, U, V) for both credential-family shapes (auth n' = 3, profile n' = 4) on
 * both tiers, and asserts they reproduce the committed bytes in
 * group_mac_vectors.h.  There is no external oracle (D-GRP-9); the vectors are
 * geryon's own frozen constants.
 *
 * Until captured (GROUP_MAC_VECTORS_POPULATED == 0) this test SKIPs (exit 77).
 * To capture, run with --dump and redirect over group_mac_vectors.h.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_mac.h"
#include "group_params.h"
#include "group_tier.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

#include "group_mac_vectors.h"

/* Scalar width equals point width on both classical tiers, so every emitted row
 * is tier->point_len wide. */

/* Eight fixed canonical scalars for a family: low bytes carry a per-scalar
 * pattern keyed by base, high bytes zero (value < 2^128 < l). */
static void
fixed_scalars(uint8_t s[8][GY_GROUP_SCALAR_MAX], uint8_t base)
{
    size_t j, k;

    memset(s, 0, 8 * GY_GROUP_SCALAR_MAX);
    for (j = 0; j < 8; j++)
        for (k = 0; k < 12; k++)
            s[j][k] = (uint8_t)(base + j * 13 + k + 1);
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

/* Fixed MAC randomness (t, u): small canonical scalars. */
static void
fixed_tu(uint8_t t[GY_GROUP_SCALAR_MAX], uint8_t u[GY_GROUP_SCALAR_MAX])
{
    memset(t, 0, GY_GROUP_SCALAR_MAX);
    memset(u, 0, GY_GROUP_SCALAR_MAX);
    t[0] = 0x09;
    t[1] = 0x11;
    u[0] = 0x07;
    u[1] = 0x2a;
}

/*
 * Recompute one family's iparams and MAC tag.  base selects the scalar set,
 * n the bound-position count (3 = auth, 4 = profile).  ip receives (C_W, I)
 * flattened at cols stride; tg receives (t, U, V).
 */
static int
compute_family(const struct gy_group_tier *tier, uint8_t base, unsigned n,
               uint8_t *ip, uint8_t *tg, size_t cols)
{
    struct gy_group_generators gens;
    struct gy_group_server_secret sk;
    struct gy_group_server_public pp;
    struct gy_group_mac_tag tag;
    uint8_t sc[8][GY_GROUP_SCALAR_MAX];
    uint8_t M[GY_GROUP_MAC_ATTRS][GY_GROUP_POINT_MAX];
    uint8_t t[GY_GROUP_SCALAR_MAX], u[GY_GROUP_SCALAR_MAX];
    int rc = -1;

    if (gy_group_generators_derive(tier, &gens) != GY_OK)
        return -1;
    fixed_scalars(sc, base);
    if (gy_group_server_keygen_scalars(tier, &gens, n, sc, &sk) != GY_OK)
        goto out;
    if (gy_group_server_public_from_secret(tier, &gens, &sk, &pp) != GY_OK)
        goto out;
    make_attrs(tier, M, n);
    fixed_tu(t, u);
    if (gy_group_mac_tu(tier, &sk, (const uint8_t(*)[GY_GROUP_POINT_MAX])M, n,
                        t, u, &tag) != GY_OK)
        goto out;

    memcpy(ip, pp.C_W, cols);
    memcpy(ip + cols, pp.I, cols);
    memcpy(tg, tag.t, cols);
    memcpy(tg + cols, tag.U, cols);
    memcpy(tg + 2 * cols, tag.V, cols);
    rc = 0;

out:
    gy_group_server_secret_clear(&sk);
    return rc;
}

/* Assert one tier's recomputed objects match the committed vectors. */
static void
check(uint8_t suite_id, size_t cols, const uint8_t *tv_ip_a,
      const uint8_t *tv_ip_p, const uint8_t *tv_tag_a, const uint8_t *tv_tag_p)
{
    const struct gy_group_tier *tier = gy_group_tier_for(suite_id);
    uint8_t ip[2 * GY_GROUP_POINT_MAX];
    uint8_t tg[3 * GY_GROUP_POINT_MAX];

    ASSERT_TRUE(tier != NULL, "tier");
    ASSERT_EQ(cols, tier->point_len);

    ASSERT_EQ(compute_family(tier, 0xa0, 3, ip, tg, cols), 0);
    ASSERT_MEMEQ(ip, tv_ip_a, 2 * cols);
    ASSERT_MEMEQ(tg, tv_tag_a, 3 * cols);

    ASSERT_EQ(compute_family(tier, 0xb0, 4, ip, tg, cols), 0);
    ASSERT_MEMEQ(ip, tv_ip_p, 2 * cols);
    ASSERT_MEMEQ(tg, tv_tag_p, 3 * cols);
}

/* Emit one "static const uint8_t NAME[rows][cols] = {...};" block. */
static void
emit(const char *name, const uint8_t *src, size_t rows, size_t cols)
{
    size_t r, c;

    printf("static const uint8_t %s[%zu][%zu] = {\n", name, rows, cols);
    for (r = 0; r < rows; r++) {
        printf("    {");
        for (c = 0; c < cols; c++)
            printf("0x%02x%s", src[r * cols + c], c + 1 < cols ? ", " : "");
        printf("},\n");
    }
    printf("};\n");
}

static int
dump_tier(uint8_t suite_id, const char *tag)
{
    const struct gy_group_tier *tier = gy_group_tier_for(suite_id);
    uint8_t ip_a[2 * GY_GROUP_POINT_MAX], ip_p[2 * GY_GROUP_POINT_MAX];
    uint8_t tg_a[3 * GY_GROUP_POINT_MAX], tg_p[3 * GY_GROUP_POINT_MAX];
    size_t cols;
    char name[40];

    if (tier == NULL)
        return -1;
    cols = tier->point_len;
    if (compute_family(tier, 0xa0, 3, ip_a, tg_a, cols) != 0 ||
        compute_family(tier, 0xb0, 4, ip_p, tg_p, cols) != 0)
        return -1;

    printf("\n/* %s tier. */\n", tag);
    snprintf(name, sizeof(name), "TV_MAC_%s_IPARAMS_A", tag);
    emit(name, ip_a, 2, cols);
    snprintf(name, sizeof(name), "TV_MAC_%s_IPARAMS_P", tag);
    emit(name, ip_p, 2, cols);
    snprintf(name, sizeof(name), "TV_MAC_%s_TAG_A", tag);
    emit(name, tg_a, 3, cols);
    snprintf(name, sizeof(name), "TV_MAC_%s_TAG_P", tag);
    emit(name, tg_p, 3, cols);
    return 0;
}

static void
dump(void)
{
    printf("/*\n"
           " * Copyright (c) 2026 Jason Crawford\n"
           " * SPDX-License-Identifier: AGPL-3.0-only\n"
           " *\n"
           " * Frozen self-KAT vectors for the algebraic MAC (GROUP_SPEC\n"
           " * section 4).  Captured from a clean build for the\n"
           " * fixed ServerSecretParams scalars, attributes, and (t, u) in\n"
           " * test_group_mac_vectors.c.\n"
           " */\n\n");
    printf("#ifndef GROUP_MAC_VECTORS_H\n#define GROUP_MAC_VECTORS_H\n\n");
    printf("#include <stdint.h>\n\n");
    printf("#define GROUP_MAC_VECTORS_POPULATED 1\n");
    dump_tier(GY_SUITE_C25519, "255");
    dump_tier(GY_SUITE_C448, "448");
    printf("\n#endif /* GROUP_MAC_VECTORS_H */\n");
}

int
main(int argc, char **argv)
{
    (void)gy_test_run;
    (void)check; /* unused when the vectors are not yet populated */

    if (talos_schnorr_init() != 0 || gy_core_init() != GY_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        dump();
        return 0;
    }

    if (!GROUP_MAC_VECTORS_POPULATED) {
        fprintf(stderr,
                "group MAC vectors not captured; SKIP.\n"
                "  Capture: ./tests/test_group_mac_vectors --dump > \\\n"
                "    tests/group/group_mac_vectors.h\n");
        return 77;
    }

#if GROUP_MAC_VECTORS_POPULATED
    check(GY_SUITE_C25519, 32, &TV_MAC_255_IPARAMS_A[0][0],
          &TV_MAC_255_IPARAMS_P[0][0], &TV_MAC_255_TAG_A[0][0],
          &TV_MAC_255_TAG_P[0][0]);
    check(GY_SUITE_C448, 56, &TV_MAC_448_IPARAMS_A[0][0],
          &TV_MAC_448_IPARAMS_P[0][0], &TV_MAC_448_TAG_A[0][0],
          &TV_MAC_448_TAG_P[0][0]);
#endif

    printf("%d assertions, %d failures\n", gy_test_asserts, gy_test_failures);
    return gy_test_failures == 0 ? 0 : 1;
}
