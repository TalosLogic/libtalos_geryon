/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Spec-derived hybrid X3DH self-KATs (D-GEN-6, HYBRID_SPEC §11.2): the handshake
 * key schedule pinned from fixed inputs.  For the live hybrid suite this pins
 *
 *   - HDH_i = HASH(kem_ss_i || dh_i), the §3.1 combiner (PQ-first ordering),
 *   - the seed triple SK derives to, with an OPK (4 combiners) and without it
 *     (3 combiners), i.e. "the full handshake through SK",
 *   - AD_first = IKhash(A) || IKhash(B) || hybrid_flag_be32 (§6.7).
 *
 * The combiner/DH inputs are FIXED literal bytes, so no curve or KEM primitive
 * runs and no liboqs/libsodium behavior is frozen into the vector; only geryon's
 * own fusion ordering, F prefix, HKDF wiring, D-DR-13 expansion, and AD layout
 * determine the bytes (the SHA-256/HKDF that run are standard, single-answer
 * functions of those fixed inputs, exactly as in the ratchet self-KAT).  A
 * SELF-KAT, not an oracle: the hybrid schedule has no external generator.
 *
 * When tests/vectors/x3dh_self.vec is absent the test writes it directly (the
 * records are multi-KB; a terminal copy-paste hard-wraps them), then passes;
 * review the file and record its sha256 in the vectors README.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "encode.h"
#include "prekeys.h"
#include "x3dh.h"

#include "gy_test.h"

#define VEC_PATH GERYON_TEST_SOURCE_DIR "/tests/vectors/x3dh_self.vec"

/* Fixed first-message hybrid_flag: aead_id 1 (ChaCha20-Poly1305), interval 20. */
#define HFLAG ((uint32_t)20 | ((uint32_t)1 << 16))

#define MAXREC 16
#define RECBUF 512

static char g_name[MAXREC][24];
static uint8_t g_buf[MAXREC][RECBUF];
static size_t g_len[MAXREC];
static size_t g_nrec;

static void
add_rec(const char *name, const uint8_t *b, size_t n)
{
    ASSERT_TRUE(g_nrec < MAXREC, "record table not full");
    ASSERT_TRUE(n <= RECBUF, "record fits buffer");
    snprintf(g_name[g_nrec], sizeof(g_name[0]), "%s", name);
    memcpy(g_buf[g_nrec], b, n);
    g_len[g_nrec] = n;
    g_nrec++;
}

/* Deterministic filler: byte i = base + i (mod 256). */
static void
fill(uint8_t *b, size_t n, uint8_t base)
{
    size_t i;

    for (i = 0; i < n; i++)
        b[i] = (uint8_t)(base + i);
}

/* Fabricate a fixed hybrid identity public key from a base byte. */
static void
fake_identity(const struct gy_suite_desc *d,
              struct gy_hybrid_identity_public_key *id, uint8_t base)
{
    memset(id, 0, sizeof(*id));
    id->base.curve.curve_type = d->curve_type;
    fill(id->base.curve.pk, d->curve_pk_len, base);
    fill(id->base.mlkem_ek, d->kem_pk_len, (uint8_t)(base + 0x20));
    fill(id->mldsa_pk, d->dsa_pk_len, (uint8_t)(base + 0x40));
}

static void
gen(void)
{
    const struct gy_suite_desc *d = gy_suite_desc(GY_SUITE_H25519_512);
    uint8_t kem_ss[GY_KEM_SS_MAX], dh[GY_DH_MAX];
    uint8_t hdh[4][GY_HASH_MAX];
    uint8_t ad[GY_HYBRID_AD_MAX];
    struct gy_hybrid_identity_public_key a, b;
    struct gy_dr_secrets s;
    char nm[24];
    size_t i, adlen;

    ASSERT_TRUE(d != NULL, "hybrid suite present");

    /* Four §3.1 combiners over fixed (kem_ss, dh) pairs; pin each HDH. */
    for (i = 0; i < 4; i++) {
        fill(kem_ss, d->kem_ss_len, (uint8_t)(0x11 * (i + 1)));
        fill(dh, d->dh_len, (uint8_t)(0x22 * (i + 1) + 1));
        ASSERT_EQ(gy_x3dh_hybrid_combine(d, kem_ss, dh, hdh[i]), GY_OK);
        snprintf(nm, sizeof(nm), "hdh%zu", i);
        add_rec(nm, hdh[i], d->hash_len);
    }

    /* SK->seed triple with an OPK (4 combiners) and without one (3). */
    ASSERT_EQ(gy_x3dh_hybrid_derive_secrets(
                  d, (const uint8_t(*)[GY_HASH_MAX])hdh, 4, &s),
              GY_OK);
    add_rec("sk_opk", (const uint8_t *)&s, sizeof(s));
    ASSERT_EQ(gy_x3dh_hybrid_derive_secrets(
                  d, (const uint8_t(*)[GY_HASH_MAX])hdh, 3, &s),
              GY_OK);
    add_rec("sk_noopk", (const uint8_t *)&s, sizeof(s));

    /* AD_first over two fixed identities and the fixed flag. */
    fake_identity(d, &a, 0x10);
    fake_identity(d, &b, 0x30);
    ASSERT_EQ(gy_x3dh_hybrid_build_ad(d, &a, &b, HFLAG, ad, &adlen), GY_OK);
    add_rec("ad_first", ad, adlen);
}

/* Write the generated records to the vector file (one NAME=hex line each). */
static int
write_records(void)
{
    FILE *f;
    size_t i, j;

    f = fopen(VEC_PATH, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "# hybrid X3DH key-schedule self-KATs (HYBRID_SPEC 11.2); see"
               " tests/vectors/README.md\n");
    for (i = 0; i < g_nrec; i++) {
        fprintf(f, "%s=", g_name[i]);
        for (j = 0; j < g_len[i]; j++)
            fprintf(f, "%02x", g_buf[i][j]);
        fprintf(f, "\n");
    }
    fclose(f);
    return 0;
}

static int
find_rec(const char *name)
{
    size_t i;

    for (i = 0; i < g_nrec; i++) {
        if (strcmp(g_name[i], name) == 0)
            return (int)i;
    }
    return -1;
}

TEST(hybrid_x3dh_self_vectors)
{
    uint8_t exp[RECBUF];
    static char line[RECBUF * 2 + 64];
    FILE *f;
    size_t seen = 0;

    g_nrec = 0;
    gen();

    f = fopen(VEC_PATH, "r");
    if (f == NULL) {
        ASSERT_EQ(write_records(), 0);
        fprintf(stderr, "  (wrote %s; review and record its sha256)\n",
                VEC_PATH);
        return;
    }

    while (gy_read_line(f, line, sizeof(line))) {
        char name[24];
        const char *eq;
        size_t namelen;
        int idx, elen;

        if (line[0] == '#' || line[0] == '\0')
            continue;
        eq = strchr(line, '=');
        if (eq == NULL) {
            ASSERT_TRUE(0, "record line has '=' (a wrapped long line?)");
            continue;
        }
        namelen = (size_t)(eq - line);
        if (namelen >= sizeof(name)) {
            ASSERT_TRUE(0, "record name fits");
            continue;
        }
        memcpy(name, line, namelen);
        name[namelen] = '\0';

        idx = find_rec(name);
        if (idx < 0) {
            ASSERT_TRUE(0, "vector names a generated record");
            continue;
        }
        elen = gy_hex_decode(exp, sizeof(exp), eq + 1);
        ASSERT_TRUE(elen >= 0, "valid hex in vector");
        ASSERT_EQ((size_t)elen, g_len[idx]);
        if (elen >= 0 && (size_t)elen == g_len[idx])
            ASSERT_MEMEQ(exp, g_buf[idx], (size_t)elen);
        seen++;
    }
    fclose(f);
    ASSERT_EQ(seen, g_nrec);
}

int
main(void)
{
    if (gy_core_init() != GY_OK)
        return 1;

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(hybrid_x3dh_self_vectors),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
