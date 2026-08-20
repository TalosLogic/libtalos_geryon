/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Spec-derived prekey self-KATs (D-GEN-6, HYBRID_SPEC §11.2): the pure byte
 * constructions a prekey bundle is built from, pinned against fixed input keys.
 * For every suite this pins EncodeEC / the hybrid public and identity encodings,
 * the PKID over that encoding, and the signed_data a prekey signature covers.
 *
 * The signature records follow the split agreed for §11.2: the XEdDSA signature
 * is geryon's own in-house layer, so it is byte-pinned via gy_xeddsa_sign_z
 * (deterministic core, fixed nonce Z), and the ML-DSA prekey CONTEXT string
 * (INFO("prekey")) is byte-pinned since it too is geryon's construction.  The
 * ML-DSA signature BYTES are deliberately NOT pinned: ML-DSA is a liboqs
 * primitive (hedged, no derand entry point), so pinning its output would freeze
 * library behavior, not ours; that path is covered behaviorally by the dual-
 * signature matrix in test_hybrid_prekeys.
 *
 * The encoding/PKID/signed_data/ctx records are pure composition functions: bytes
 * in, bytes out, no primitive run.  The XEdDSA record runs geryon's own Ed25519-
 * based signer with a fixed Z.  So the vectors freeze geryon's own construction
 * only - a libsodium/liboqs version bump cannot move them - and there is no RNG
 * seam or function pointer anywhere in the path.  This is a SELF-KAT, not an
 * oracle: geryon's hybrid wire has no external generator.
 *
 * When tests/vectors/prekey_self.vec is absent the test prints the generated
 * records (paste them into the file, then record its sha256 in the vectors
 * README) and passes, matching the print-if-unpinned pattern used elsewhere.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ed25519.h"
#include "encode.h"
#include "prekeys.h"

#include "gy_test.h"

#define VEC_PATH GERYON_TEST_SOURCE_DIR "/tests/vectors/prekey_self.vec"

/* Fixed inputs shared by every record (owner-supplied, not secret). */
#define TS 1723900000ULL
#define FLAGS ((uint64_t)1 | ((uint64_t)20 << 16) | ((uint64_t)1 << 32))

#define MAXREC 32
#define RECBUF 8192

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

static void
add_pkid(const char *name, uint8_t suite_id, const uint8_t *enc, size_t enclen)
{
    uint8_t be[4];
    uint32_t pkid;

    ASSERT_EQ(gy_pkid(&pkid, suite_id, enc, enclen), GY_OK);
    be[0] = (uint8_t)(pkid >> 24);
    be[1] = (uint8_t)(pkid >> 16);
    be[2] = (uint8_t)(pkid >> 8);
    be[3] = (uint8_t)pkid;
    add_rec(name, be, sizeof(be));
}

/*
 * XEdDSA signature over msg under a fixed identity scalar and fixed nonce Z
 * (Ed25519-based; applies to the 25519 tier).  gy_xeddsa_sign_z is the
 * deterministic KAT core, so the 64-byte signature is reproducible.
 */
static void
add_xeddsa(const char *name, const uint8_t *msg, size_t msglen)
{
    uint8_t sk[32], z[64], sig[64];

    fill(sk, sizeof(sk), 0x20);
    fill(z, sizeof(z), 0x50);
    ASSERT_EQ(gy_xeddsa_sign_z(sig, sk, msg, msglen, z), GY_OK);
    add_rec(name, sig, sizeof(sig));
}

/* Emit the construction records for one suite, prefixed by its wire byte. */
static void
gen_suite(uint8_t suite_id)
{
    const struct gy_suite_desc *d = gy_suite_desc(suite_id);
    uint8_t enc[RECBUF], enc2[RECBUF], sd[RECBUF];
    char nm[24];
    size_t el, el2, sl;
    int n;

    /* A suite absent from this build (e.g. the 448 tier before M6) is skipped;
     * when it lands it generates records the vec does not yet pin, which the
     * seen-vs-generated count below flags as needing pinning. */
    if (d == NULL)
        return;

    if (!d->is_hybrid) {
        struct gy_public_key pub;

        memset(&pub, 0, sizeof(pub));
        pub.curve_type = d->curve_type;
        fill(pub.pk, d->curve_pk_len, 0x10);

        n = gy_encode_ec(enc, sizeof(enc), pub.curve_type, pub.pk);
        ASSERT_TRUE(n > 0, "EncodeEC succeeds");
        snprintf(nm, sizeof(nm), "%02x_enc", suite_id);
        add_rec(nm, enc, (size_t)n);

        snprintf(nm, sizeof(nm), "%02x_pkid", suite_id);
        add_pkid(nm, suite_id, enc, (size_t)n);

        ASSERT_EQ(gy_kex_spk_signed_data(&pub, TS, sd, sizeof(sd), &sl), GY_OK);
        snprintf(nm, sizeof(nm), "%02x_signed", suite_id);
        add_rec(nm, sd, sl);

        snprintf(nm, sizeof(nm), "%02x_xeddsa", suite_id);
        add_xeddsa(nm, sd, sl);
        return;
    }

    {
        struct gy_hybrid_identity_public_key id;

        memset(&id, 0, sizeof(id));
        id.base.curve.curve_type = d->curve_type;
        fill(id.base.curve.pk, d->curve_pk_len, 0x10);
        fill(id.base.mlkem_ek, d->kem_pk_len, 0x40);
        fill(id.mldsa_pk, d->dsa_pk_len, 0x80);

        ASSERT_EQ(gy_hybrid_encode_pub(d, &id.base, enc, sizeof(enc), &el),
                  GY_OK);
        snprintf(nm, sizeof(nm), "%02x_encpub", suite_id);
        add_rec(nm, enc, el);

        snprintf(nm, sizeof(nm), "%02x_pkid", suite_id);
        add_pkid(nm, suite_id, enc, el);

        ASSERT_EQ(gy_hybrid_encode_identity(d, &id, enc2, sizeof(enc2), &el2),
                  GY_OK);
        snprintf(nm, sizeof(nm), "%02x_encid", suite_id);
        add_rec(nm, enc2, el2);

        ASSERT_EQ(gy_kex_hybrid_signed_data(d, &id.base, TS, FLAGS, sd,
                                            sizeof(sd), &sl),
                  GY_OK);
        snprintf(nm, sizeof(nm), "%02x_signed", suite_id);
        add_rec(nm, sd, sl);

        /* XEdDSA signature over signed_data (geryon's in-house 25519 layer). */
        snprintf(nm, sizeof(nm), "%02x_xeddsa", suite_id);
        add_xeddsa(nm, sd, sl);

        /* ML-DSA prekey context string INFO("prekey") (geryon construction;
         * the ML-DSA signature bytes themselves are not pinned, see header). */
        {
            uint8_t ctx[64];
            size_t ctxlen;

            ASSERT_EQ(gy_info(ctx, sizeof(ctx), &ctxlen, suite_id, "prekey"),
                      GY_OK);
            snprintf(nm, sizeof(nm), "%02x_ctx", suite_id);
            add_rec(nm, ctx, ctxlen);
        }
    }
}

/*
 * Write the generated records to the vector file (one NAME=hex line each) when
 * it is absent.  Records run to several KB of hex, so the test emits the file
 * directly rather than asking for a terminal copy-paste that hard-wraps long
 * lines.  Returns 0 on success, -1 if the file cannot be opened.
 */
static int
write_records(void)
{
    FILE *f;
    size_t i, j;

    f = fopen(VEC_PATH, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "# prekey construction self-KATs (HYBRID_SPEC 11.2); see"
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

/* Locate a generated record by name; -1 if none. */
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

TEST(prekey_self_vectors)
{
    uint8_t exp[RECBUF];
    static char line[RECBUF * 2 + 64];
    FILE *f;
    size_t seen = 0;

    g_nrec = 0;
    gen_suite(GY_SUITE_C25519);
    gen_suite(GY_SUITE_H25519_512);
    gen_suite(GY_SUITE_C448);
    gen_suite(GY_SUITE_H448_1024);

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
            GY_TEST(prekey_self_vectors),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
