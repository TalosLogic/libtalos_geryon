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
