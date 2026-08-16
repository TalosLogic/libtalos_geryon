/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * proto/ wire format: typed-envelope round-trip and negative matrix
 * (version, suite, reserved type, inner/outer mismatch, truncation), prekey
 * bundle round-trip with and without an OPK plus structural negatives, and the
 * layer seam: a tampered bundle parses structurally in proto/ but fails the
 * kex/ cryptographic validation, proving proto/ does no crypto.
 */

#include <string.h>

#include "envelope.h"

#include "gy_sim.h"
#include "gy_test.h"

static const struct gy_suite_desc *D;

static int
key_eq(const struct gy_public_key *a, const struct gy_public_key *b, size_t cpl)
{
    return a->pkid == b->pkid && a->curve_type == b->curve_type &&
           memcmp(a->pk, b->pk, cpl) == 0;
}

/* ---- envelope ---------------------------------------------------------- */

TEST(envelope_roundtrip)
{
    uint8_t inner[6] = {GY_WIRE_VERSION, 0, 0x11, 0x22, 0x33, 0x44};
    uint8_t env[16];
    const uint8_t *pin;
    size_t elen = 0, pil = 0;
    uint8_t type = 0;

    inner[1] = D->suite_id;
    ASSERT_EQ(gy_envelope_put(env, sizeof(env), &elen, D->suite_id, GY_MSG_DR,
                              inner, sizeof(inner)),
              GY_OK);
    ASSERT_EQ(elen, GY_ENVELOPE_HDR_LEN + sizeof(inner));

    ASSERT_EQ(gy_envelope_parse(env, elen, D->suite_id, &type, &pin, &pil),
              GY_OK);
    ASSERT_EQ(type, GY_MSG_DR);
    ASSERT_EQ(pil, sizeof(inner));
    ASSERT_TRUE(memcmp(pin, inner, sizeof(inner)) == 0, "inner preserved");
}

TEST(envelope_negatives)
{
    uint8_t inner[4] = {GY_WIRE_VERSION, 0, 0xAB, 0xCD};
    uint8_t env[16];
    const uint8_t *pin;
    size_t elen = 0, pil = 0;
    uint8_t type = 0;

    inner[1] = D->suite_id;
    ASSERT_EQ(gy_envelope_put(env, sizeof(env), &elen, D->suite_id, GY_MSG_INIT,
                              inner, sizeof(inner)),
              GY_OK);

    /* Too short, bad version, wrong suite, reserved type, inner/outer split. */
    ASSERT_EQ(gy_envelope_parse(env, 2, D->suite_id, &type, &pin, &pil),
              GY_ERR_ARG);
    env[0] ^= 0xFF;
    ASSERT_EQ(gy_envelope_parse(env, elen, D->suite_id, &type, &pin, &pil),
              GY_ERR_ARG);
    env[0] = GY_WIRE_VERSION;
    ASSERT_EQ(gy_envelope_parse(env, elen, (uint8_t)(D->suite_id + 1), &type,
                                &pin, &pil),
              GY_ERR_STATE);
    env[2] = 0x7F; /* reserved msg_type */
    ASSERT_EQ(gy_envelope_parse(env, elen, D->suite_id, &type, &pin, &pil),
              GY_ERR_ARG);
    env[2] = GY_MSG_INIT;
    env[3] ^= 0xFF; /* inner version no longer matches outer */
    ASSERT_EQ(gy_envelope_parse(env, elen, D->suite_id, &type, &pin, &pil),
              GY_ERR_ARG);

    /* put rejects a reserved type and a short buffer. */
    ASSERT_EQ(gy_envelope_put(env, sizeof(env), &elen, D->suite_id, 0x7F, inner,
                              sizeof(inner)),
              GY_ERR_ARG);
    ASSERT_EQ(gy_envelope_put(env, 3, &elen, D->suite_id, GY_MSG_INIT, inner,
                              sizeof(inner)),
              GY_ERR_ARG);
}

/* ---- bundle ------------------------------------------------------------ */

TEST(bundle_roundtrip_with_and_without_opk)
{
    struct gy_sim sim;
    struct gy_prekey_bundle b2;
    uint8_t buf[1024];
    size_t cpl = D->curve_pk_len, wlen = 0;

    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);

    /* With OPK: the with-OPK wire is one key wider than the without. */
    ASSERT_TRUE(gy_bundle_wire_len(D, 1) > gy_bundle_wire_len(D, 0),
                "OPK adds a key to the wire");
    ASSERT_EQ(gy_bundle_put(buf, sizeof(buf), &wlen, D, &sim.bundle), GY_OK);
    ASSERT_EQ(wlen, gy_bundle_wire_len(D, 1));
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen), GY_OK);
    ASSERT_TRUE(key_eq(&b2.ik, &sim.bundle.ik, cpl), "ik preserved");
    ASSERT_TRUE(key_eq(&b2.spk, &sim.bundle.spk, cpl), "spk preserved");
    ASSERT_TRUE(b2.spk_timestamp == sim.bundle.spk_timestamp, "ts preserved");
    ASSERT_TRUE(memcmp(b2.spk_sig, sim.bundle.spk_sig, D->sig_len) == 0,
                "sig preserved");
    ASSERT_TRUE(key_eq(&b2.opk, &sim.bundle.opk, cpl), "opk preserved");
    /* A faithfully round-tripped bundle still validates cryptographically. */
    ASSERT_EQ(gy_bundle_validate(D, &b2), GY_OK);

    /* Without OPK (absent sentinel pkid 0). */
    sim.bundle.opk.pkid = 0;
    ASSERT_EQ(gy_bundle_put(buf, sizeof(buf), &wlen, D, &sim.bundle), GY_OK);
    ASSERT_EQ(wlen, gy_bundle_wire_len(D, 0));
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen), GY_OK);
    ASSERT_EQ(b2.opk.pkid, 0u);

    gy_sim_free(&sim);
}

TEST(bundle_structural_negatives)
{
    struct gy_sim sim;
    struct gy_prekey_bundle b2;
    uint8_t buf[1024];
    size_t wlen = 0;

    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);
    ASSERT_EQ(gy_bundle_put(buf, sizeof(buf), &wlen, D, &sim.bundle), GY_OK);

    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen - 1), GY_ERR_ARG); /* short */
    buf[0] ^= 0xFF;
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen), GY_ERR_ARG); /* version */
    buf[0] = GY_WIRE_VERSION;
    buf[1] ^= 0xFF;
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen), GY_ERR_STATE); /* suite */
    buf[1] = D->suite_id;
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen + 1),
              GY_ERR_ARG); /* trailing */

    gy_sim_free(&sim);
}

TEST(seam_tampered_bundle_parses_but_fails_validation)
{
    struct gy_sim sim;
    struct gy_prekey_bundle b2;
    uint8_t buf[1024];
    size_t cpl = D->curve_pk_len, wlen = 0;
    size_t sig_off;

    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 1), GY_OK);
    ASSERT_EQ(gy_bundle_put(buf, sizeof(buf), &wlen, D, &sim.bundle), GY_OK);

    /* Flip one byte inside the SPK signature: after ver||suite||IK||SPK||ts. */
    sig_off = 2 + 2 * (4 + 1 + cpl) + 8;
    buf[sig_off] ^= 0x01;

    /* proto/ parse is structural: it succeeds on the tampered bytes ... */
    ASSERT_EQ(gy_bundle_parse(&b2, D, buf, wlen), GY_OK);
    /* ... but the kex/ cryptographic check rejects it (proto does no crypto). */
    ASSERT_EQ(gy_bundle_validate(D, &b2), GY_ERR_VERIFY);

    gy_sim_free(&sim);
}

TEST(fingerprint_surface)
{
    struct gy_sim sim;
    uint8_t fp1[GY_HASH_MAX], fp2[GY_HASH_MAX];

    ASSERT_EQ(gy_sim_setup(&sim, D, GY_AEAD_CHACHA20POLY1305, 0), GY_OK);
    ASSERT_EQ(gy_proto_fingerprint(D, fp1, &sim.bundle.ik), GY_OK);
    ASSERT_EQ(gy_fingerprint(D, fp2, &sim.bundle.ik), GY_OK);
    ASSERT_TRUE(memcmp(fp1, fp2, D->hash_len) == 0,
                "proto surface matches kex");
    gy_sim_free(&sim);
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
            GY_TEST(envelope_roundtrip),
            GY_TEST(envelope_negatives),
            GY_TEST(bundle_roundtrip_with_and_without_opk),
            GY_TEST(bundle_structural_negatives),
            GY_TEST(seam_tampered_bundle_parses_but_fails_validation),
            GY_TEST(fingerprint_surface),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
