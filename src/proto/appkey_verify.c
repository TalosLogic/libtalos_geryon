/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gy_appkey_verify: the custodian-less verification half of
 * the application signing key, a FREE function like gy_bundle_assemble -
 * needs no gy_custodian and no private key, so a server target links this
 * translation unit WITHOUT pulling in custodian.o (nothing here references
 * any gy_custodian_* symbol; this file deliberately does not include
 * custodian.h).  It verifies the identity's certificate signature over a
 * SAK (the caller pins identity_pub out of band or via TOFU, CUSTODY_SPEC
 * section 10), checks expiry, then verifies a per-request SAK signature
 * under the same domain-separated framing gy_custodian_sign used.
 */

#include <string.h>

#include "geryon.h"

#include "envelope.h"
#include "facade.h"

#define GY_APPKEY_INFO_MAX                                                     \
    64 /* matches custodian.c's own copy: the
                               * GY_INFO_MAX convention duplicated per file,
                               * as x3dh.c/he.c/double_ratchet.c already do */
#define GY_APPKEY_SIGN_MAX                                                     \
    8000 /* matches custodian.h's GY_CUSTODIAN_SIGN_MAX;
                                 * this file cannot include custodian.h
                                 * (custodian-less), so the bound is
                                 * duplicated, not shared */

/* ---- local endian helpers (no core/ dependency, matching envelope.c) --- */

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

/* Rebuild the identity's cert-signing input exactly as custodian.c's
 * cust_appkey_cert_signed_data does: appkey-cert info || EncodeEC(sak_pub)
 * || issued_at_be64 || expiry_be64 || identity_pkid_be32. */
static int
cert_signed_data(uint8_t *out, size_t cap, size_t *outlen,
                 const struct gy_suite_desc *desc,
                 const struct gy_public_key *sak_pub, uint64_t issued_at,
                 uint64_t expiry, uint32_t identity_pkid)
{
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, need, off;
    int rc;

    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                       "appkey-cert");
    if (rc != GY_OK)
        return rc;
    need = infolen + 1 + desc->curve_pk_len + 8 + 8 + 4;
    if (need > cap)
        return GY_ERR_TOOLONG;

    off = 0;
    memcpy(out + off, info, infolen);
    off += infolen;
    out[off++] = sak_pub->curve_type;
    memcpy(out + off, sak_pub->pk, desc->curve_pk_len);
    off += desc->curve_pk_len;
    put_be64(out + off, issued_at);
    off += 8;
    put_be64(out + off, expiry);
    off += 8;
    put_be32(out + off, identity_pkid);
    off += 4;

    *outlen = off;
    return GY_OK;
}

/* Hybrid cert-signing input, mirroring custodian.c's
 * cust_hybrid_appkey_cert_signed_data: appkey-cert info || curve_type ||
 * curve_pk || mldsa_pk || issued_at_be64 || expiry_be64 || identity_pkid_be32.
 * Both the XEdDSA and the ML-DSA identity signatures cover these bytes. */
static int
hybrid_cert_signed_data(uint8_t *out, size_t cap, size_t *outlen,
                        const struct gy_suite_desc *desc,
                        const struct gy_public_key *sak_curve_pub,
                        const uint8_t *sak_mldsa_pk, uint64_t issued_at,
                        uint64_t expiry, uint32_t identity_pkid)
{
    uint8_t info[GY_APPKEY_INFO_MAX];
    size_t infolen, need, off;
    int rc;

    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                       "appkey-cert");
    if (rc != GY_OK)
        return rc;
    need = infolen + 1 + desc->curve_pk_len + desc->dsa_pk_len + 8 + 8 + 4;
    if (need > cap)
        return GY_ERR_TOOLONG;

    off = 0;
    memcpy(out + off, info, infolen);
    off += infolen;
    out[off++] = sak_curve_pub->curve_type;
    memcpy(out + off, sak_curve_pub->pk, desc->curve_pk_len);
    off += desc->curve_pk_len;
    memcpy(out + off, sak_mldsa_pk, desc->dsa_pk_len);
    off += desc->dsa_pk_len;
    put_be64(out + off, issued_at);
    off += 8;
    put_be64(out + off, expiry);
    off += 8;
    put_be32(out + off, identity_pkid);
    off += 4;

    *outlen = off;
    return GY_OK;
}

/*
 * Hybrid (dual-scheme) verification.  identity_pub is the FULL hybrid identity
 * public key encoding (curve_type || curve_pk || mlkem_ek || mldsa_pk), the
 * same bytes gy_registration_identity_pub returns and gy_hybrid_identity_
 * fingerprint hashes; both the identity's XEdDSA curve key and its ML-DSA key
 * are needed to check the two cert signatures.  sig is ed_sig || mldsa_sig.
 * Both signatures of each pair MUST pass (no single-scheme acceptance).
 */
static int
appkey_verify_hybrid(const struct gy_suite_desc *desc,
                     const uint8_t *identity_pub, size_t identity_pub_len,
                     const uint8_t *cert, size_t cert_len,
                     const uint8_t *app_ctx, size_t app_ctx_len,
                     const uint8_t *msg, size_t msg_len, const uint8_t *sig,
                     size_t sig_len, uint64_t now)
{
    struct gy_public_key sak_pub;
    uint8_t sak_mldsa_pk[GY_DSA_PK_MAX];
    uint8_t identity_ed_sig[GY_SIG_MAX];
    uint8_t identity_mldsa_sig[GY_DSA_SIG_MAX];
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 1 + GY_CURVE_PK_MAX +
                        GY_DSA_PK_MAX + 8 + 8 + 4];
    uint8_t req_data[GY_APPKEY_INFO_MAX + 4 + GY_APPKEY_SIGN_MAX];
    uint8_t info[GY_APPKEY_INFO_MAX];
    const uint8_t *id_curve_pk, *id_mldsa_pk;
    uint64_t issued_at, expiry;
    uint32_t identity_pkid;
    size_t cpl = desc->curve_pk_len, ekl = desc->kem_pk_len;
    size_t dpl = desc->dsa_pk_len, infolen, signed_len, off;
    int rc;

    /* identity_pub = curve_type(1) || curve_pk || mlkem_ek || mldsa_pk. */
    if (identity_pub_len != 1 + cpl + ekl + dpl)
        return GY_ERR_ARG;
    if (sig_len != desc->sig_len + desc->dsa_sig_len)
        return GY_ERR_ARG;
    if (app_ctx_len > GY_APPKEY_SIGN_MAX ||
        msg_len > GY_APPKEY_SIGN_MAX - app_ctx_len)
        return GY_ERR_TOOLONG;
    id_curve_pk = identity_pub + 1;
    id_mldsa_pk = identity_pub + 1 + cpl + ekl;

    rc = gy_hybrid_appkey_cert_parse(
        desc, cert, cert_len, &sak_pub, sak_mldsa_pk, &issued_at, &expiry,
        &identity_pkid, identity_ed_sig, identity_mldsa_sig);
    if (rc != GY_OK)
        return rc;

    /* Identity signatures over the cert (both required). */
    rc = hybrid_cert_signed_data(signed_data, sizeof(signed_data), &signed_len,
                                 desc, &sak_pub, sak_mldsa_pk, issued_at,
                                 expiry, identity_pkid);
    if (rc != GY_OK)
        return rc;
    rc = desc->verify(identity_ed_sig, id_curve_pk, signed_data, signed_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id,
                       "appkey-cert");
    if (rc != GY_OK)
        return rc;
    rc = desc->dsa_verify(identity_mldsa_sig, id_mldsa_pk, signed_data,
                          signed_len, info, infolen);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    if (expiry != 0 && now > expiry)
        return GY_ERR_EXPIRED;

    /* Per-request signatures over the same framed input (both required). */
    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id, "appkey");
    if (rc != GY_OK)
        return rc;
    off = 0;
    memcpy(req_data + off, info, infolen);
    off += infolen;
    put_be32(req_data + off, (uint32_t)app_ctx_len);
    off += 4;
    if (app_ctx_len > 0)
        memcpy(req_data + off, app_ctx, app_ctx_len);
    off += app_ctx_len;
    if (msg_len > 0)
        memcpy(req_data + off, msg, msg_len);
    off += msg_len;

    rc = desc->verify(sig, sak_pub.pk, req_data, off);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;
    rc = desc->dsa_verify(sig + desc->sig_len, sak_mldsa_pk, req_data, off,
                          info, infolen);
    return rc == GY_OK ? GY_OK : GY_ERR_VERIFY;
}

int
gy_appkey_verify(const uint8_t *identity_pub, size_t identity_pub_len,
                 const uint8_t *cert, size_t cert_len, const uint8_t *app_ctx,
                 size_t app_ctx_len, const uint8_t *msg, size_t msg_len,
                 const uint8_t *sig, size_t sig_len, uint64_t now)
{
    const struct gy_suite_desc *desc;
    struct gy_public_key sak_pub;
    uint8_t signed_data[GY_APPKEY_INFO_MAX + 1 + GY_CURVE_PK_MAX + 8 + 8 + 4];
    uint8_t req_data[GY_APPKEY_INFO_MAX + 4 + GY_APPKEY_SIGN_MAX];
    uint8_t info[GY_APPKEY_INFO_MAX];
    uint64_t issued_at, expiry;
    uint32_t identity_pkid;
    uint8_t identity_sig[GY_SIG_MAX];
    size_t signed_len, infolen, off;
    int rc;

    if (identity_pub == NULL || cert == NULL || sig == NULL)
        return GY_ERR_ARG;
    if (app_ctx == NULL && app_ctx_len != 0)
        return GY_ERR_ARG;
    if (msg == NULL && msg_len != 0)
        return GY_ERR_ARG;
    if (cert_len < 2)
        return GY_ERR_ARG;

    desc = gy_suite_lookup(cert[1]);
    if (desc == NULL)
        return GY_ERR_ARG;
    if (desc->is_hybrid)
        return appkey_verify_hybrid(desc, identity_pub, identity_pub_len, cert,
                                    cert_len, app_ctx, app_ctx_len, msg,
                                    msg_len, sig, sig_len, now);
    if (identity_pub_len != desc->curve_pk_len || sig_len != desc->sig_len)
        return GY_ERR_ARG;
    if (app_ctx_len > GY_APPKEY_SIGN_MAX ||
        msg_len > GY_APPKEY_SIGN_MAX - app_ctx_len)
        return GY_ERR_TOOLONG;

    rc = gy_appkey_cert_parse(desc, cert, cert_len, &sak_pub, &issued_at,
                              &expiry, &identity_pkid, identity_sig);
    if (rc != GY_OK)
        return rc;

    /* Identity signature over the cert (D-GEN-3 "appkey-cert" label). */
    rc = cert_signed_data(signed_data, sizeof(signed_data), &signed_len, desc,
                          &sak_pub, issued_at, expiry, identity_pkid);
    if (rc != GY_OK)
        return rc;
    rc = desc->verify(identity_sig, identity_pub, signed_data, signed_len);
    if (rc != GY_OK)
        return GY_ERR_VERIFY;

    /* Expiry (0 = no expiry, CUSTODY_SPEC section 10). */
    if (expiry != 0 && now > expiry)
        return GY_ERR_EXPIRED;

    /* The per-request SAK signature (D-GEN-3 "appkey" label, the SAME
     * framing gy_custodian_sign used). */
    rc = gy_suite_info(info, sizeof(info), &infolen, desc->suite_id, "appkey");
    if (rc != GY_OK)
        return rc;
    off = 0;
    memcpy(req_data + off, info, infolen);
    off += infolen;
    /* Length-delimit app_ctx: must match gy_custodian_sign's
     * be32 app_ctx_len prefix exactly, or the request signature will not
     * verify. */
    put_be32(req_data + off, (uint32_t)app_ctx_len);
    off += 4;
    if (app_ctx_len > 0)
        memcpy(req_data + off, app_ctx, app_ctx_len);
    off += app_ctx_len;
    if (msg_len > 0)
        memcpy(req_data + off, msg, msg_len);
    off += msg_len;

    rc = desc->verify(sig, sak_pub.pk, req_data, off);
    return rc == GY_OK ? GY_OK : GY_ERR_VERIFY;
}
