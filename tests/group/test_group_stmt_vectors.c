/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Frozen self-KAT check for the credential/presentation STATEMENT surface
 * (GROUP_SPEC sections 3.2/3.3/6).  Every credential-layer proof
 * (pi_I, pi_A, pi_P, pi_BR, pi_BI) is a randomized Fiat-Shamir transcript and so
 * cannot be byte-frozen directly; what CAN be frozen is the DETERMINISTIC data
 * the proofs bind.  For a fixed UID, ProfileKey, redemption date, and
 * GroupMasterKey this recomputes, on both tiers:
 *
 *   - the AuthCredential attribute vector (M1, M2, M3_auth),
 *   - the ProfileKeyCredential attribute vector (M1, M2, M3_prof, M4),
 *   - the redemption scalar m3,
 *   - the ProfileKeyCommitment (J1, J2, J3),
 *   - the UidCiphertext (E_A1, E_A2), and
 *   - the ProfileKeyCiphertext (E_B1, E_B2),
 *
 * and asserts they reproduce the committed bytes in group_stmt_vectors.h.
 * There is no external byte-compat oracle (geryon's group layer is clean-room
 * and deliberately not zkgroup-byte-compatible, D-GRP-4 / D-GEN-6); the vectors
 * are geryon's own frozen constants.  The randomized proofs are cross-validated
 * by the round-trip property tests (test_group_{cred,pres,ppres,issue}.c) and,
 * on the 255 tier, by the independent [CPZ] verify-equation oracle
 * (tools/oracles/group_kvac, tests/group/test_group_kvac_oracle.c).
 *
 * Until captured (GROUP_STMT_VECTORS_POPULATED == 0) this test SKIPs (exit 77).
 * To capture, run with --dump and redirect over group_stmt_vectors.h.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h" /* GY_SUITE_* */
#include "error.h"
#include "group_attr.h"
#include "group_issue.h" /* gy_group_pk_commit, gy_group_pk_commitment */
#include "group_params.h"
#include "group_tier.h"
#include "group_venc.h"
#include "util.h"

#include "talos_schnorr.h"

#include "gy_test.h"

#include "group_stmt_vectors.h"

/* Fixed statement inputs (shared with the property tests). */
static const uint8_t UID[GY_GROUP_UID_BYTES] = {1, 2,  3,  4,  5,  6,  7,  8,
                                                9, 10, 11, 12, 13, 14, 15, 16};
static const uint8_t PK[GY_GROUP_PROFILEKEY_BYTES] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
    0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
    0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};

/* 2024-01-01T00:00:00Z = 19723 * 86400: a day-aligned redemption date. */
#define STMT_DATE 1704067200ull

/* Row counts for the emitted blocks. */
#define STMT_ROWS_ATTR_AUTH GY_GROUP_ATTR_AUTH    /* M1, M2, M3_auth        */
#define STMT_ROWS_ATTR_PROF GY_GROUP_ATTR_PROFILE /* M1, M2, M3_prof, M4    */
#define STMT_ROWS_MREDEEM 1                       /* the redemption scalar  */
#define STMT_ROWS_COMMIT 3                        /* J1, J2, J3             */
#define STMT_ROWS_UIDCT 2                         /* E_A1, E_A2             */
#define STMT_ROWS_PKCT 2                          /* E_B1, E_B2             */

#define STMT_ROWS_TOTAL                                                        \
    (STMT_ROWS_ATTR_AUTH + STMT_ROWS_ATTR_PROF + STMT_ROWS_MREDEEM +           \
     STMT_ROWS_COMMIT + STMT_ROWS_UIDCT + STMT_ROWS_PKCT)

/*
 * Recompute every deterministic statement object for one tier into out (a flat
 * STMT_ROWS_TOTAL * cols buffer), in the fixed emission order above.  cols is
 * tier->point_len (= tier->scalar_len on both classical tiers).  Returns 0 on
 * success, -1 on any provider error.
 */
static int
compute_stmt(const struct gy_group_tier *tier, uint8_t *out, size_t cols)
{
    struct gy_group_generators gens;
    struct gy_group_secret_params sp;
    struct gy_group_pk_commitment cm;
    struct gy_group_uid_ct uct;
    struct gy_group_pk_ct pct;
    uint8_t Ma[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX];
    uint8_t Mp[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX];
    uint8_t m3[GY_GROUP_SCALAR_MAX];
    uint8_t gmk[GY_GROUP_MASTER_KEY_MAX];
    uint8_t *p = out;
    size_t i;
    int rc = -1;

    if (gy_group_generators_derive(tier, &gens) != GY_OK)
        return -1;
    for (i = 0; i < tier->master_key_len; i++)
        gmk[i] = (uint8_t)(i + 1);
    if (gy_group_secret_derive(tier, gmk, tier->master_key_len, &sp) != GY_OK)
        return -1;

    if (gy_group_attr_auth(tier, &gens, UID, STMT_DATE, Ma) != GY_OK)
        goto out;
    for (i = 0; i < STMT_ROWS_ATTR_AUTH; i++, p += cols)
        memcpy(p, Ma[i], cols);

    if (gy_group_attr_profile(tier, UID, PK, Mp) != GY_OK)
        goto out;
    for (i = 0; i < STMT_ROWS_ATTR_PROF; i++, p += cols)
        memcpy(p, Mp[i], cols);

    if (gy_group_redemption_scalar(tier, STMT_DATE, m3) != GY_OK)
        goto out;
    memcpy(p, m3, cols);
    p += cols;

    if (gy_group_pk_commit(tier, &gens, UID, PK, &cm) != GY_OK)
        goto out;
    memcpy(p, cm.J1, cols);
    memcpy(p + cols, cm.J2, cols);
    memcpy(p + 2 * cols, cm.J3, cols);
    p += 3 * cols;

    if (gy_group_uid_encrypt(tier, &sp, UID, &uct) != GY_OK)
        goto out;
    memcpy(p, uct.E_A1, cols);
    memcpy(p + cols, uct.E_A2, cols);
    p += 2 * cols;

    if (gy_group_pk_encrypt(tier, &sp, PK, UID, &pct) != GY_OK)
        goto out;
    memcpy(p, pct.E_B1, cols);
    memcpy(p + cols, pct.E_B2, cols);
    p += 2 * cols;

    rc = 0;
out:
    gy_group_secret_clear(&sp);
    gy_secure_zero(m3, sizeof(m3));
    return rc;
}

/* Assert one tier's recomputed statement matches the committed vectors. */
static void
check(uint8_t suite_id, size_t cols, const uint8_t *tv)
{
    const struct gy_group_tier *tier = gy_group_tier_for(suite_id);
    uint8_t got[STMT_ROWS_TOTAL * GY_GROUP_POINT_MAX];

    ASSERT_TRUE(tier != NULL, "tier");
    ASSERT_EQ(cols, tier->point_len);
    ASSERT_EQ(compute_stmt(tier, got, cols), 0);
    ASSERT_MEMEQ(got, tv, STMT_ROWS_TOTAL * cols);
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
    uint8_t buf[STMT_ROWS_TOTAL * GY_GROUP_POINT_MAX];
    const uint8_t *p = buf;
    size_t cols;
    char name[48];

    if (tier == NULL)
        return -1;
    cols = tier->point_len;
    if (compute_stmt(tier, buf, cols) != 0)
        return -1;

    printf("\n/* %s tier. */\n", tag);
    snprintf(name, sizeof(name), "TV_STMT_%s_ATTR_AUTH", tag);
    emit(name, p, STMT_ROWS_ATTR_AUTH, cols);
    p += STMT_ROWS_ATTR_AUTH * cols;
    snprintf(name, sizeof(name), "TV_STMT_%s_ATTR_PROF", tag);
    emit(name, p, STMT_ROWS_ATTR_PROF, cols);
    p += STMT_ROWS_ATTR_PROF * cols;
    snprintf(name, sizeof(name), "TV_STMT_%s_MREDEEM", tag);
    emit(name, p, STMT_ROWS_MREDEEM, cols);
    p += STMT_ROWS_MREDEEM * cols;
    snprintf(name, sizeof(name), "TV_STMT_%s_COMMIT", tag);
    emit(name, p, STMT_ROWS_COMMIT, cols);
    p += STMT_ROWS_COMMIT * cols;
    snprintf(name, sizeof(name), "TV_STMT_%s_UIDCT", tag);
    emit(name, p, STMT_ROWS_UIDCT, cols);
    p += STMT_ROWS_UIDCT * cols;
    snprintf(name, sizeof(name), "TV_STMT_%s_PKCT", tag);
    emit(name, p, STMT_ROWS_PKCT, cols);
    return 0;
}

/* Concatenate one tier's six blocks into a flat expected buffer for check(). */
#if GROUP_STMT_VECTORS_POPULATED
/*
 * Concatenate one tier's six committed blocks into a flat expected buffer.
 * Each argument is the tier-width 2D array flattened (aa points at
 * TV_STMT_<t>_ATTR_AUTH[0], etc.); the tier-specific column stride is passed as
 * cols, so a single set of flat pointers serves both the 32- and 56-wide tiers.
 * A [rows][cols] array is contiguous at that stride, so each block copies whole.
 */
static void
flatten(uint8_t *dst, size_t cols, const uint8_t *aa, const uint8_t *ap,
        const uint8_t *mr, const uint8_t *cm, const uint8_t *uc,
        const uint8_t *pc)
{
    uint8_t *p = dst;

    memcpy(p, aa, STMT_ROWS_ATTR_AUTH * cols);
    p += STMT_ROWS_ATTR_AUTH * cols;
    memcpy(p, ap, STMT_ROWS_ATTR_PROF * cols);
    p += STMT_ROWS_ATTR_PROF * cols;
    memcpy(p, mr, STMT_ROWS_MREDEEM * cols);
    p += STMT_ROWS_MREDEEM * cols;
    memcpy(p, cm, STMT_ROWS_COMMIT * cols);
    p += STMT_ROWS_COMMIT * cols;
    memcpy(p, uc, STMT_ROWS_UIDCT * cols);
    p += STMT_ROWS_UIDCT * cols;
    memcpy(p, pc, STMT_ROWS_PKCT * cols);
}
#endif

static void
dump(void)
{
    printf("/*\n"
           " * Copyright (c) 2026 Jason Crawford\n"
           " * SPDX-License-Identifier: AGPL-3.0-only\n"
           " *\n"
           " * Frozen self-KAT vectors for the credential/presentation\n"
           " * statement surface (GROUP_SPEC sections 3.2/3.3/6).  Captured\n"
           " * from a clean build for the fixed UID,\n"
           " * ProfileKey, redemption date, and GroupMasterKey in\n"
           " * test_group_stmt_vectors.c.\n"
           " */\n\n");
    printf("#ifndef GROUP_STMT_VECTORS_H\n#define GROUP_STMT_VECTORS_H\n\n");
    printf("#include <stdint.h>\n\n");
    printf("#define GROUP_STMT_VECTORS_POPULATED 1\n");
    dump_tier(GY_SUITE_C25519, "255");
    dump_tier(GY_SUITE_C448, "448");
    printf("\n#endif /* GROUP_STMT_VECTORS_H */\n");
}

int
main(int argc, char **argv)
{
    (void)gy_test_run;
    (void)check;

    if (talos_schnorr_init() != 0 || gy_core_init() != GY_OK) {
        fprintf(stderr, "init failed\n");
        return 1;
    }

    if (argc > 1 && strcmp(argv[1], "--dump") == 0) {
        dump();
        return 0;
    }

    if (!GROUP_STMT_VECTORS_POPULATED) {
        fprintf(stderr,
                "group statement vectors not captured; SKIP.\n"
                "  Capture: ./tests/test_group_stmt_vectors --dump > \\\n"
                "    tests/group/group_stmt_vectors.h\n");
        return 77;
    }

#if GROUP_STMT_VECTORS_POPULATED
    {
        uint8_t exp[STMT_ROWS_TOTAL * GY_GROUP_POINT_MAX];

        flatten(exp, 32, &TV_STMT_255_ATTR_AUTH[0][0],
                &TV_STMT_255_ATTR_PROF[0][0], &TV_STMT_255_MREDEEM[0][0],
                &TV_STMT_255_COMMIT[0][0], &TV_STMT_255_UIDCT[0][0],
                &TV_STMT_255_PKCT[0][0]);
        check(GY_SUITE_C25519, 32, exp);

        flatten(exp, 56, &TV_STMT_448_ATTR_AUTH[0][0],
                &TV_STMT_448_ATTR_PROF[0][0], &TV_STMT_448_MREDEEM[0][0],
                &TV_STMT_448_COMMIT[0][0], &TV_STMT_448_UIDCT[0][0],
                &TV_STMT_448_PKCT[0][0]);
        check(GY_SUITE_C448, 56, exp);
    }
#endif

    printf("%d assertions, %d failures\n", gy_test_asserts, gy_test_failures);
    return gy_test_failures == 0 ? 0 : 1;
}
