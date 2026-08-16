/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gy_appkey_verify: the custodian-less link proof.  This file
 * deliberately does NOT include custodian.h and never calls any
 * gy_custodian_* symbol - it mints its own identity/SAK keypairs (via
 * gy_identity_generate, session/facade.h) and signs directly through
 * struct gy_suite_desc's sign function pointer (also reachable without a
 * custodian), exactly like a server target that has no custodian would.
 * Since static-library linking is demand-driven per translation unit, a
 * test binary built ONLY from this file plus what it actually calls never
 * pulls custodian.o out of libgeryon_proto.a; `nm` on the built test binary
 * confirms no gy_custodian_* symbol is present (verify manually with
 * `nm build/tests/test_appkey_verify_link | grep gy_custodian`).
 */

#include <stdint.h>
#include <string.h>

#include "geryon.h"

#include "envelope.h"
#include "facade.h"
#include "gy_test.h"

static void
put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void
put_be64(uint8_t *p, uint64_t v)
{
    int i;

    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

/* Build a real, validly-signed certificate the way gy_custodian.c does
 * internally, without a custodian: sign
 * gy_suite_info(suite,"appkey-cert") || EncodeEC(sak.pub) || issued_at_be64
 * || expiry_be64 || identity_pkid_be32 under the identity's private key. */
static void
make_cert(const struct gy_suite_desc *desc, const struct gy_keypair *ik,
          const struct gy_keypair *sak, uint64_t issued_at, uint64_t expiry,
          uint8_t *cert, size_t *cert_len)
{
    uint8_t info[64], signed_data[64 + 1 + GY_CURVE_PK_MAX + 8 + 8 + 4];
    uint8_t sig[GY_SIG_MAX];
    size_t infolen, off;

    ASSERT_EQ(gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                            "appkey-cert"),
              GY_OK);
    off = 0;
    memcpy(signed_data + off, info, infolen);
    off += infolen;
    signed_data[off++] = sak->pub.curve_type;
    memcpy(signed_data + off, sak->pub.pk, desc->curve_pk_len);
    off += desc->curve_pk_len;
    put_be64(signed_data + off, issued_at);
    off += 8;
    put_be64(signed_data + off, expiry);
    off += 8;
    put_be32(signed_data + off, ik->pub.pkid);
    off += 4;

    ASSERT_EQ(desc->sign(sig, ik->sk, signed_data, off), GY_OK);
    ASSERT_EQ(gy_appkey_cert_put(cert, 512, cert_len, desc, &sak->pub,
                                 issued_at, expiry, ik->pub.pkid, sig),
              GY_OK);
}

TEST(verify_accepts_a_real_cert_and_signature_end_to_end)
{
    const struct gy_suite_desc *desc = gy_suite_lookup(GY_SUITE_C25519);
    struct gy_keypair ik, sak;
    uint8_t cert[512];
    size_t cert_len;
    static const uint8_t app_ctx[] = "rest-api-v1";
    static const uint8_t msg[] = "GET /v1/whoami\nnonce=abc123\nts=1000";
    uint8_t sig[GY_SIG_MAX], info[64], req[64 + 256];
    size_t infolen, off;

    ASSERT_TRUE(desc != NULL, "classical suite resolves without a custodian");
    ASSERT_EQ(gy_identity_generate(desc, &ik), GY_OK);
    ASSERT_EQ(gy_identity_generate(desc, &sak), GY_OK);

    cert_len = sizeof(cert);
    /* Rebuild identity_pkid correctly (make_cert's placeholder write above
     * used put_be64 as a 4-byte no-op spacer; gy_appkey_cert_put writes the
     * real identity PKID). */
    make_cert(desc, &ik, &sak, 1000, 0, cert, &cert_len);

    /* Sign a request the same way gy_custodian_sign would: info ||
     * be32(app_ctx_len) || app_ctx || msg (the be32 delimiter is
     * verify must see the identical framing). */
    ASSERT_EQ(
        gy_suite_info(info, sizeof(info), &infolen, desc->suite_id, "appkey"),
        GY_OK);
    off = 0;
    memcpy(req + off, info, infolen);
    off += infolen;
    put_be32(req + off, (uint32_t)(sizeof(app_ctx) - 1));
    off += 4;
    memcpy(req + off, app_ctx, sizeof(app_ctx) - 1);
    off += sizeof(app_ctx) - 1;
    memcpy(req + off, msg, sizeof(msg) - 1);
    off += sizeof(msg) - 1;
    ASSERT_EQ(desc->sign(sig, sak.sk, req, off), GY_OK);

    ASSERT_EQ(gy_appkey_verify(ik.pub.pk, desc->curve_pk_len, cert, cert_len,
                               app_ctx, sizeof(app_ctx) - 1, msg,
                               sizeof(msg) - 1, sig, desc->sig_len, 500),
              GY_OK);

    /* Past expiry is rejected uniformly. */
    cert_len = sizeof(cert);
    make_cert(desc, &ik, &sak, 1000, 2000, cert, &cert_len);
    ASSERT_EQ(gy_appkey_verify(ik.pub.pk, desc->curve_pk_len, cert, cert_len,
                               app_ctx, sizeof(app_ctx) - 1, msg,
                               sizeof(msg) - 1, sig, desc->sig_len, 2001),
              GY_ERR_EXPIRED);

    /* A tampered cert fails the identity check: byte 7 is the first byte of
     * the SAK's curve_pk (wire layout version(1)||suite_id(1)||pkid_be32(4)
     * ||curve_type(1)||curve_pk), which IS covered by EncodeEC(sak_pub) and
     * so by the identity signature - unlike the pkid bytes (2..6), which
     * are carried as metadata only and are not themselves signed. */
    cert_len = sizeof(cert);
    make_cert(desc, &ik, &sak, 1000, 0, cert, &cert_len);
    cert[7] ^= 0x01;
    ASSERT_EQ(gy_appkey_verify(ik.pub.pk, desc->curve_pk_len, cert, cert_len,
                               app_ctx, sizeof(app_ctx) - 1, msg,
                               sizeof(msg) - 1, sig, desc->sig_len, 500),
              GY_ERR_VERIFY);
}

int
main(void)
{
    ASSERT_EQ(gy_runtime_init(), GY_OK);

    {
        static const struct gy_test_case cases[] = {
            GY_TEST(verify_accepts_a_real_cert_and_signature_end_to_end),
        };
        return gy_test_run(cases, sizeof(cases) / sizeof(cases[0]));
    }
}
