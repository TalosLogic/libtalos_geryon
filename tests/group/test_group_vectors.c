/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen self-KAT check for the classical group system parameters
 * (GROUP_SPEC section 2).  Recomputes the NUMS generators,
 * GroupSecretParams, and GroupPublicParams for the fixed GroupMasterKey on both
 * tiers and asserts they reproduce the committed bytes in
 * group_params_vectors.h.  There is no external oracle (D-GRP-9); the vectors
 * are geryon's own frozen constants.
 *
 * Until the vectors are captured (GROUP_PARAMS_VECTORS_POPULATED == 0) this
 * test SKIPs (exit 77).  To capture, run with --dump and redirect over
 * tests/group/group_params_vectors.h, review, and rebuild.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "error.h"
#include "group_params.h"
#include "group_tier.h"
#include "util.h"

#include "encode.h" /* GY_SUITE_* */
#include "talos_schnorr.h"

#include "gy_test.h"

#include "group_params_vectors.h"

/* Fixed GroupMasterKey for a tier: master_key_len bytes 0x01, 0x02, ... */
static void
fixed_gmk(const struct gy_group_tier *tier,
          uint8_t out[GY_GROUP_MASTER_KEY_MAX])
{
    size_t i;

    for (i = 0; i < tier->master_key_len; i++)
        out[i] = (uint8_t)(i + 1);
}

/* Compute the three parameter objects for a tier from the fixed GroupMasterKey. */
static int
compute(const struct gy_group_tier *tier, struct gy_group_generators *gens,
        struct gy_group_secret_params *sp, struct gy_group_public_params *pp)
{
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];

    fixed_gmk(tier, gmk);
    if (gy_group_generators_derive(tier, gens) != GY_OK)
        return -1;
    if (gy_group_secret_derive(tier, gmk, tier->master_key_len, sp) != GY_OK)
        return -1;
    if (gy_group_public_derive(tier, gens, sp, pp) != GY_OK)
        return -1;
    return 0;
}

/*
 * Assert one tier's recomputed objects match the committed vectors.  The TV_*
 * arrays are tier-width ([..][32] or [..][56]); the caller passes cols and flat
 * row pointers so this stays width-generic.
 */
static void
check(uint8_t suite_id, size_t cols, const uint8_t *tv_gen,
      const uint8_t *tv_sec, const uint8_t *tv_pub)
{
    const struct gy_group_tier *tier = gy_group_tier_for(suite_id);
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    const uint8_t *sec[4];
    const uint8_t *pub[2];
    size_t i;

    ASSERT_TRUE(tier != NULL, "tier");
    ASSERT_EQ(compute(tier, &gens, &sp, &pp), 0);
    ASSERT_EQ(cols, tier->point_len);

    for (i = 0; i < GY_GROUP_GEN_COUNT; i++)
        ASSERT_MEMEQ(gens.g[i], tv_gen + i * cols, cols);

    sec[0] = sp.a1;
    sec[1] = sp.a2;
    sec[2] = sp.b1;
    sec[3] = sp.b2;
    for (i = 0; i < 4; i++)
        ASSERT_MEMEQ(sec[i], tv_sec + i * cols, cols);

    pub[0] = pp.A;
    pub[1] = pp.B;
    for (i = 0; i < 2; i++)
        ASSERT_MEMEQ(pub[i], tv_pub + i * cols, cols);

    gy_group_secret_clear(&sp);
}

/* Emit one "static const uint8_t NAME[rows][cols] = {...};" block. rows are the
 * contiguous flat buffer src (rows * cols bytes). */
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

/* Flatten a tier's objects into tightly (cols-strided) packed buffers and emit
 * its three arrays. */
static int
dump_tier(uint8_t suite_id, const char *tag)
{
    const struct gy_group_tier *tier = gy_group_tier_for(suite_id);
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_public_params pp;
    uint8_t gen[GY_GROUP_GEN_COUNT * GY_GROUP_POINT_MAX];
    uint8_t sec[4 * GY_GROUP_SCALAR_MAX];
    uint8_t pub[2 * GY_GROUP_POINT_MAX];
    const uint8_t *sp_rows[4], *pp_rows[2];
    size_t cols, i;
    char name[32];

    if (tier == NULL || compute(tier, &gens, &sp, &pp) != 0)
        return -1;
    cols = tier->point_len;

    for (i = 0; i < GY_GROUP_GEN_COUNT; i++)
        memcpy(gen + i * cols, gens.g[i], cols);
    sp_rows[0] = sp.a1;
    sp_rows[1] = sp.a2;
    sp_rows[2] = sp.b1;
    sp_rows[3] = sp.b2;
    for (i = 0; i < 4; i++)
        memcpy(sec + i * cols, sp_rows[i], cols);
    pp_rows[0] = pp.A;
    pp_rows[1] = pp.B;
    for (i = 0; i < 2; i++)
        memcpy(pub + i * cols, pp_rows[i], cols);

    printf("\n/* %s tier. */\n", tag);
    snprintf(name, sizeof(name), "TV_%s_GEN", tag);
    emit(name, gen, GY_GROUP_GEN_COUNT, cols);
    snprintf(name, sizeof(name), "TV_%s_SECRET", tag);
    emit(name, sec, 4, cols);
    snprintf(name, sizeof(name), "TV_%s_PUBLIC", tag);
    emit(name, pub, 2, cols);

    gy_group_secret_clear(&sp);
    return 0;
}

static void
dump(void)
{
    printf("/*\n"
           " * Copyright (c) 2026 Jason Crawford\n"
           " * SPDX-License-Identifier: AGPL-3.0-only\n"
           " *\n"
           " * Frozen self-KAT vectors for the classical group system\n"
           " * parameters (GROUP_SPEC section 2).  Captured from a\n"
           " * clean build for the fixed GroupMasterKey k0[i] = i + 1.\n"
           " */\n\n");
    printf(
        "#ifndef GROUP_PARAMS_VECTORS_H\n#define GROUP_PARAMS_VECTORS_H\n\n");
    printf("#include <stdint.h>\n\n");
    printf("#define GROUP_PARAMS_VECTORS_POPULATED 1\n");
    dump_tier(GY_SUITE_C25519, "255");
    dump_tier(GY_SUITE_C448, "448");
    printf("\n#endif /* GROUP_PARAMS_VECTORS_H */\n");
}

int
main(int argc, char **argv)
{
    /* This test uses a custom main (for --dump / SKIP) instead of
     * GY_TEST_MAIN, so gy_test_run() from gy_test.h is otherwise unused; mark
     * it referenced to satisfy -Werror=unused-function. */
    (void)gy_test_run;

    if (talos_schnorr_init() != 0 || gy_core_init() != GY_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        dump();
        return 0;
    }

    if (!GROUP_PARAMS_VECTORS_POPULATED) {
        fprintf(stderr, "group param vectors not captured; SKIP.\n"
                        "  Capture: ./tests/test_group_vectors --dump > \\\n"
                        "    tests/group/group_params_vectors.h\n");
        return 77;
    }

    /* The emitted arrays are tier-width; reinterpret as [.][64] flat rows is not
     * safe, so pass the true row stride via the flat pointer + cols. */
    check(GY_SUITE_C25519, 32, &TV_255_GEN[0][0], &TV_255_SECRET[0][0],
          &TV_255_PUBLIC[0][0]);
    check(GY_SUITE_C448, 56, &TV_448_GEN[0][0], &TV_448_SECRET[0][0],
          &TV_448_PUBLIC[0][0]);

    printf("%d assertions, %d failures\n", gy_test_asserts, gy_test_failures);
    return gy_test_failures == 0 ? 0 : 1;
}
