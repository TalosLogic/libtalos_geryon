/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gy_bundle_assemble: the custodian-less link proof.  This
 * file deliberately does NOT include custodian.h and never calls any
 * gy_custodian_* symbol - it builds its own registration/OPK wire bytes via
 * gy_bundle_put/gy_opk_batch_put (proto/envelope.c, no custodian object
 * needed either), exactly like a server target that has no custodian would.
 * Since static-library linking is demand-driven per translation unit, a
 * test binary built ONLY from this file plus what it actually calls never
 * pulls custodian.o out of libgeryon_proto.a; `nm` on the built test binary
 * confirms no gy_custodian_* symbol is present (verify manually with
 * `nm build/tests/test_bundle_assemble_link | grep gy_custodian`).
 */

#include <stdint.h>
#include <string.h>

#include "geryon.h"

#include "envelope.h"
#include "facade.h"
#include "gy_test.h"

static void
make_key(struct gy_public_key *k, uint32_t pkid, uint8_t curve_type,
         size_t pk_len, uint8_t fill)
{
    memset(k, 0, sizeof(*k));
    k->pkid = pkid;
    k->curve_type = curve_type;
    memset(k->pk, fill, pk_len);
}

TEST(assemble_with_and_without_opk)
{
    const struct gy_suite_desc *desc = gy_suite_lookup(GY_SUITE_C25519);
    struct gy_prekey_bundle reg;
    struct gy_public_key opk1, opk2;
    uint8_t regbuf[512], opk1_wire[128], opk2_wire[128];
    uint8_t out1[512], out2[512], out_noopk[512];
    size_t reglen, opk1_len, opk2_len, out1_len, out2_len, out_noopk_len;
    size_t cpl = desc->curve_pk_len;

    ASSERT_TRUE(desc != NULL, "classical suite resolves without a custodian");

    memset(&reg, 0, sizeof(reg));
    make_key(&reg.ik, 0x11111111u, desc->curve_type, cpl, 0xA1);
    make_key(&reg.spk, 0x22222222u, desc->curve_type, cpl, 0xA2);
    reg.spk_timestamp = 123456789;
    memset(reg.spk_sig, 0xA3, desc->sig_len);
    reg.opk.pkid = 0; /* a registration: no OPK */

    reglen = sizeof(regbuf);
    ASSERT_EQ(gy_bundle_put(regbuf, reglen, &reglen, desc, &reg), GY_OK);

    make_key(&opk1, 0x33333333u, desc->curve_type, cpl, 0xB1);
    make_key(&opk2, 0x44444444u, desc->curve_type, cpl, 0xB2);
    opk1_len = sizeof(opk1_wire);
    ASSERT_EQ(gy_opk_batch_put(opk1_wire, opk1_len, &opk1_len, desc, &opk1, 1),
              GY_OK);
    opk2_len = sizeof(opk2_wire);
    ASSERT_EQ(gy_opk_batch_put(opk2_wire, opk2_len, &opk2_len, desc, &opk2, 1),
              GY_OK);
    /* The per-key encoding starts 4 bytes in (version, suite_id, count_be16
     * with count == 1 here); slice past that header to get one raw
     * pkid||curve_type||pk entry, exactly what gy_bundle_assemble wants. */

    /* Size query, then assemble with the first OPK. */
    out1_len = 0;
    ASSERT_EQ(gy_bundle_assemble(regbuf, reglen, opk1_wire + 4, opk1_len - 4,
                                 NULL, &out1_len),
              GY_OK);
    ASSERT_TRUE(out1_len > 0, "size query reports a size");
    out1_len = sizeof(out1);
    ASSERT_EQ(gy_bundle_assemble(regbuf, reglen, opk1_wire + 4, opk1_len - 4,
                                 out1, &out1_len),
              GY_OK);

    /* A second OPK yields a distinct bundle. */
    out2_len = sizeof(out2);
    ASSERT_EQ(gy_bundle_assemble(regbuf, reglen, opk2_wire + 4, opk2_len - 4,
                                 out2, &out2_len),
              GY_OK);
    ASSERT_TRUE(out1_len == out2_len, "same-shape bundles are the same size");
    ASSERT_TRUE(memcmp(out1, out2, out1_len) != 0,
                "different OPKs assemble to different bundles");

    /* opk_pub may be NULL/0 to assemble a bundle with no OPK at all. */
    out_noopk_len = sizeof(out_noopk);
    ASSERT_EQ(
        gy_bundle_assemble(regbuf, reglen, NULL, 0, out_noopk, &out_noopk_len),
        GY_OK);
    ASSERT_TRUE(out_noopk_len < out1_len, "no-OPK bundle is smaller");

    /* A bundle that already carries an OPK is not a valid "registration". */
    {
        struct gy_prekey_bundle full;
        uint8_t fullbuf[512];
        size_t fulllen;

        full = reg;
        make_key(&full.opk, 0x55555555u, desc->curve_type, cpl, 0xC1);
        fulllen = sizeof(fullbuf);
        ASSERT_EQ(gy_bundle_put(fullbuf, fulllen, &fulllen, desc, &full),
                  GY_OK);
        out1_len = sizeof(out1);
        ASSERT_EQ(
            gy_bundle_assemble(fullbuf, fulllen, NULL, 0, out1, &out1_len),
            GY_ERR_ARG);
    }
}

TEST(opk_batch_enumerate_and_slice)
{
    const struct gy_suite_desc *desc = gy_suite_lookup(GY_SUITE_C25519);
    static const uint32_t pkids[3] = {0xAAAA0001u, 0xBBBB0002u, 0xCCCC0003u};
    struct gy_public_key opks[3];
    struct gy_prekey_bundle reg;
    const uint8_t *slice;
    uint8_t batch[512], regbuf[512], out[512];
    size_t cpl = desc->curve_pk_len;
    size_t kw, batchlen, reglen, slicelen, out_len, count, i;

    ASSERT_TRUE(desc != NULL, "classical suite resolves without a custodian");
    kw = 4 + 1 + cpl;

    for (i = 0; i < 3; i++)
        make_key(&opks[i], pkids[i], desc->curve_type, cpl,
                 (uint8_t)(0xD0 + i));
    batchlen = sizeof(batch);
    ASSERT_EQ(gy_opk_batch_put(batch, batchlen, &batchlen, desc, opks, 3),
              GY_OK);

    ASSERT_EQ(gy_opk_batch_count(batch, batchlen, &count), GY_OK);
    ASSERT_TRUE(count == 3, "count reflects the three published OPKs");

    memset(&reg, 0, sizeof(reg));
    make_key(&reg.ik, 0x11111111u, desc->curve_type, cpl, 0xA1);
    make_key(&reg.spk, 0x22222222u, desc->curve_type, cpl, 0xA2);
    reg.spk_timestamp = 123456789;
    memset(reg.spk_sig, 0xA3, desc->sig_len);
    reg.opk.pkid = 0;
    reglen = sizeof(regbuf);
    ASSERT_EQ(gy_bundle_put(regbuf, reglen, &reglen, desc, &reg), GY_OK);

    for (i = 0; i < 3; i++) {
        uint32_t got;

        ASSERT_EQ(gy_opk_batch_get(batch, batchlen, i, &slice, &slicelen),
                  GY_OK);
        ASSERT_TRUE(slicelen == kw, "each slice is exactly one key wide");
        /* The zero-copy slice is the raw pkid||curve_type||pk entry, the
         * supported replacement for the manual "batch + 4 + i*kw" header
         * skip the assemble test above does by hand. */
        ASSERT_TRUE(slice == batch + 4 + i * kw, "slice points in place");
        got = ((uint32_t)slice[0] << 24) | ((uint32_t)slice[1] << 16) |
              ((uint32_t)slice[2] << 8) | (uint32_t)slice[3];
        ASSERT_TRUE(got == pkids[i], "slice leads with the OPK PKID");
        out_len = sizeof(out);
        ASSERT_EQ(
            gy_bundle_assemble(regbuf, reglen, slice, slicelen, out, &out_len),
            GY_OK);
    }

    /* An index at or past the count is NOT_FOUND, never an out-of-bounds read. */
    ASSERT_EQ(gy_opk_batch_get(batch, batchlen, 3, &slice, &slicelen),
              GY_ERR_NOT_FOUND);

    /* A truncated / malformed batch is a uniform GY_ERR_ARG on both calls. */
    ASSERT_EQ(gy_opk_batch_count(batch, batchlen - 1, &count), GY_ERR_ARG);
    ASSERT_EQ(gy_opk_batch_get(batch, batchlen - 1, 0, &slice, &slicelen),
              GY_ERR_ARG);

    /* NULL out-params are rejected. */
    ASSERT_EQ(gy_opk_batch_count(batch, batchlen, NULL), GY_ERR_ARG);
    ASSERT_EQ(gy_opk_batch_get(batch, batchlen, 0, NULL, &slicelen),
              GY_ERR_ARG);
}

TEST(bundle_fingerprint_matches_self_and_validates)
{
    const struct gy_suite_desc *desc = gy_suite_lookup(GY_SUITE_C25519);
    struct gy_prekey_bundle reg, reg2;
    struct gy_public_key opk;
    uint8_t regbuf[512], reg2buf[512], opk_wire[128], asm_buf[512];
    uint8_t fp_reg[GY_FINGERPRINT_MAX], fp_asm[GY_FINGERPRINT_MAX];
    uint8_t fp_exp[GY_FINGERPRINT_MAX], fp_other[GY_FINGERPRINT_MAX];
    size_t reglen, reg2len, opk_len, asm_len, need, fplen;
    size_t cpl = desc->curve_pk_len;

    ASSERT_TRUE(desc != NULL, "classical suite resolves without a custodian");

    memset(&reg, 0, sizeof(reg));
    make_key(&reg.ik, 0x11111111u, desc->curve_type, cpl, 0xA1);
    make_key(&reg.spk, 0x22222222u, desc->curve_type, cpl, 0xA2);
    reg.spk_timestamp = 123456789;
    memset(reg.spk_sig, 0xA3, desc->sig_len);
    reg.opk.pkid = 0;
    reglen = sizeof(regbuf);
    ASSERT_EQ(gy_bundle_put(regbuf, reglen, &reglen, desc, &reg), GY_OK);

    /* Size query reports the suite hash length. */
    need = 0;
    ASSERT_EQ(gy_bundle_fingerprint(regbuf, reglen, NULL, &need), GY_OK);
    ASSERT_TRUE(need == desc->hash_len, "size query reports hash_len");

    /* The value is byte-identical to fingerprinting the IK directly, the same
     * primitive gy_self_fingerprint / gy_keychange use. */
    ASSERT_EQ(gy_proto_fingerprint(desc, fp_exp, &reg.ik), GY_OK);
    fplen = sizeof(fp_reg);
    ASSERT_EQ(gy_bundle_fingerprint(regbuf, reglen, fp_reg, &fplen), GY_OK);
    ASSERT_TRUE(fplen == desc->hash_len, "fills hash_len bytes");
    ASSERT_TRUE(memcmp(fp_reg, fp_exp, fplen) == 0,
                "bundle fingerprint equals a direct IK fingerprint");

    /* An assembled bundle (registration + OPK) carries the same IK, so it
     * fingerprints to the same value the registration does. */
    make_key(&opk, 0x33333333u, desc->curve_type, cpl, 0xB1);
    opk_len = sizeof(opk_wire);
    ASSERT_EQ(gy_opk_batch_put(opk_wire, opk_len, &opk_len, desc, &opk, 1),
              GY_OK);
    asm_len = sizeof(asm_buf);
    ASSERT_EQ(gy_bundle_assemble(regbuf, reglen, opk_wire + 4, opk_len - 4,
                                 asm_buf, &asm_len),
              GY_OK);
    fplen = sizeof(fp_asm);
    ASSERT_EQ(gy_bundle_fingerprint(asm_buf, asm_len, fp_asm, &fplen), GY_OK);
    ASSERT_TRUE(memcmp(fp_asm, fp_reg, fplen) == 0,
                "a bundle and its registration fingerprint identically");

    /* A different identity key yields a different fingerprint. */
    memset(&reg2, 0, sizeof(reg2));
    make_key(&reg2.ik, 0x99999999u, desc->curve_type, cpl, 0x5C);
    make_key(&reg2.spk, 0x22222222u, desc->curve_type, cpl, 0xA2);
    reg2.spk_timestamp = 123456789;
    memset(reg2.spk_sig, 0xA3, desc->sig_len);
    reg2.opk.pkid = 0;
    reg2len = sizeof(reg2buf);
    ASSERT_EQ(gy_bundle_put(reg2buf, reg2len, &reg2len, desc, &reg2), GY_OK);
    fplen = sizeof(fp_other);
    ASSERT_EQ(gy_bundle_fingerprint(reg2buf, reg2len, fp_other, &fplen), GY_OK);
    ASSERT_TRUE(memcmp(fp_other, fp_reg, fplen) != 0,
                "a different IK fingerprints differently");

    /* Robustness: malformed/short input, unknown suite, undersized out, and
     * NULL args are all a uniform GY_ERR_ARG, never an out-of-bounds read. */
    fplen = sizeof(fp_reg);
    ASSERT_EQ(gy_bundle_fingerprint(regbuf, 1, fp_reg, &fplen), GY_ERR_ARG);
    {
        uint8_t bad[512];

        memcpy(bad, regbuf, reglen);
        bad[1] = 0x7F; /* not a known suite id */
        fplen = sizeof(fp_reg);
        ASSERT_EQ(gy_bundle_fingerprint(bad, reglen, fp_reg, &fplen),
                  GY_ERR_ARG);
    }
    fplen = desc->hash_len - 1;
    ASSERT_EQ(gy_bundle_fingerprint(regbuf, reglen, fp_reg, &fplen),
              GY_ERR_ARG);
    fplen = sizeof(fp_reg);
    ASSERT_EQ(gy_bundle_fingerprint(NULL, reglen, fp_reg, &fplen), GY_ERR_ARG);
    ASSERT_EQ(gy_bundle_fingerprint(regbuf, reglen, fp_reg, NULL), GY_ERR_ARG);
}

int
main(void)
{
    /* gy_runtime_init (session/), not gy_core_init (core/): this file stays
     * within the session/proto symbol set a custodian-less server target
     * would actually link. */
    ASSERT_EQ(gy_runtime_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(assemble_with_and_without_opk),
            GY_TEST(opk_batch_enumerate_and_slice),
            GY_TEST(bundle_fingerprint_matches_self_and_validates),
        };

        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
