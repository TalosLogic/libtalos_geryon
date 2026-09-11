/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_wire.h"

#include "group_cred.h"  /* AuthCredentialResponse */
#include "group_issue.h" /* blind-issuance objects (section 3.3) */
#include "group_mac.h"   /* ServerPublicParams, MAC tag */
#include "group_ops.h"   /* GY_GROUP_PK_VERSION_BYTES (grp-pkv) */
#include "group_pres.h"  /* Auth / ProfileKey presentations */

#include "encode.h" /* GY_WIRE_VERSION (the D-GEN-1 envelope version byte) */
#include "error.h"
#include "util.h" /* gy_is_zero (invited pk-slot check) */

/*
 * Common canonical wire encodings for the group objects (GROUP_SPEC section 9).
 * These are sk-free (they only serialize/parse public objects), so they are
 * COMMON to the client and server facades (GER-M8-07): the client decodes what
 * it receives and the server encodes what it sends, but neither needs
 * ServerSecretParams.  Keeping them here, off both the client-only and
 * server-only crypto TUs, is what lets the object-size and round-trip helpers be
 * linked by either facade.  The object header helpers live at the top; the
 * per-object encode/decode follow.  GER-M8-08 added the blind-issuance objects
 * (section 3.3), the ProfileKeyVersion, and the GROUP_KEY_DISTRIBUTION envelope
 * frame (section 9 item 4) at the bottom.  The one variable-length wire object,
 * the member-entry list (section 9 item 2), is deferred to GER-M8-09 with the
 * persisted member-list shape it shares (Split C).
 */

int
gy_group_obj_put_header(const struct gy_group_tier *tier, uint8_t obj_type,
                        uint8_t *out, size_t cap)
{
    if (tier == NULL || out == NULL)
        return GY_ERR_ARG;
    if (cap < GY_GROUP_OBJ_HDR_LEN)
        return GY_ERR_TOOLONG;

    out[0] = obj_type;
    out[1] = GY_GROUP_WIRE_VERSION;
    out[2] = tier->suite_id;
    return GY_OK;
}

int
gy_group_obj_check_header(const struct gy_group_tier *tier, uint8_t obj_type,
                          const uint8_t *in, size_t len)
{
    if (tier == NULL || in == NULL)
        return GY_ERR_ARG;
    if (len < GY_GROUP_OBJ_HDR_LEN)
        return GY_ERR_VERIFY;

    if (in[0] != obj_type || in[1] != GY_GROUP_WIRE_VERSION ||
        in[2] != tier->suite_id)
        return GY_ERR_VERIFY;
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * ServerPublicParams (tagged) and the MAC tag (untagged, nested).
 * ------------------------------------------------------------------------- */

int
gy_group_server_public_encode(const struct gy_group_tier *tier,
                              const struct gy_group_server_public *pp,
                              uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, need;
    int rc;

    if (tier == NULL || pp == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    need = GY_GROUP_OBJ_HDR_LEN + 2 * plen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_SERVER_PUBLIC, out, cap);
    if (rc != GY_OK)
        return rc;
    memcpy(out + GY_GROUP_OBJ_HDR_LEN, pp->C_W, plen);
    memcpy(out + GY_GROUP_OBJ_HDR_LEN + plen, pp->I, plen);
    *outlen = need;
    return GY_OK;
}

int
gy_group_server_public_decode(const struct gy_group_tier *tier,
                              struct gy_group_server_public *pp,
                              const uint8_t *in, size_t len)
{
    size_t plen;
    int rc;

    if (tier == NULL || pp == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    if (len != GY_GROUP_OBJ_HDR_LEN + 2 * plen)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_SERVER_PUBLIC, in, len);
    if (rc != GY_OK)
        return rc;

    memset(pp, 0, sizeof(*pp));
    memcpy(pp->C_W, in + GY_GROUP_OBJ_HDR_LEN, plen);
    memcpy(pp->I, in + GY_GROUP_OBJ_HDR_LEN + plen, plen);
    return GY_OK;
}

int
gy_group_public_params_encode(const struct gy_group_tier *tier,
                              const struct gy_group_public_params *pp,
                              uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, need;
    int rc;

    if (tier == NULL || pp == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    need = GY_GROUP_OBJ_HDR_LEN + 2 * plen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_GROUP_PUBLIC, out, cap);
    if (rc != GY_OK)
        return rc;
    memcpy(out + GY_GROUP_OBJ_HDR_LEN, pp->A, plen);
    memcpy(out + GY_GROUP_OBJ_HDR_LEN + plen, pp->B, plen);
    *outlen = need;
    return GY_OK;
}

int
gy_group_public_params_decode(const struct gy_group_tier *tier,
                              struct gy_group_public_params *pp,
                              const uint8_t *in, size_t len)
{
    size_t plen;
    int rc;

    if (tier == NULL || pp == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    if (len != GY_GROUP_OBJ_HDR_LEN + 2 * plen)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_GROUP_PUBLIC, in, len);
    if (rc != GY_OK)
        return rc;

    memset(pp, 0, sizeof(*pp));
    memcpy(pp->A, in + GY_GROUP_OBJ_HDR_LEN, plen);
    memcpy(pp->B, in + GY_GROUP_OBJ_HDR_LEN + plen, plen);
    return GY_OK;
}

int
gy_group_mac_tag_encode(const struct gy_group_tier *tier,
                        const struct gy_group_mac_tag *tag, uint8_t *out,
                        size_t cap, size_t *outlen)
{
    size_t plen, slen, need;

    if (tier == NULL || tag == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = slen + 2 * plen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    memcpy(out, tag->t, slen);
    memcpy(out + slen, tag->U, plen);
    memcpy(out + slen + plen, tag->V, plen);
    *outlen = need;
    return GY_OK;
}

int
gy_group_mac_tag_decode(const struct gy_group_tier *tier,
                        struct gy_group_mac_tag *tag, const uint8_t *in,
                        size_t len)
{
    size_t plen, slen;

    if (tier == NULL || tag == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    if (len != slen + 2 * plen)
        return GY_ERR_VERIFY;

    memset(tag, 0, sizeof(*tag));
    memcpy(tag->t, in, slen);
    memcpy(tag->U, in + slen, plen);
    memcpy(tag->V, in + slen + plen, plen);
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * AuthCredentialResponse (tagged).
 * ------------------------------------------------------------------------- */

int
gy_group_auth_response_encode(const struct gy_group_tier *tier,
                              const struct gy_group_auth_response *resp,
                              uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, slen, need, off;
    size_t j, i;
    int rc;

    if (tier == NULL || resp == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + slen + 2 * plen + GY_GROUP_PI_I_M * plen +
           GY_GROUP_PI_I_K * slen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_AUTH_RESPONSE, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(out + off, resp->mac.t, slen);
    off += slen;
    memcpy(out + off, resp->mac.U, plen);
    off += plen;
    memcpy(out + off, resp->mac.V, plen);
    off += plen;
    for (j = 0; j < GY_GROUP_PI_I_M; j++) {
        memcpy(out + off, resp->proof_V[j], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_I_K; i++) {
        memcpy(out + off, resp->proof_r[i], slen);
        off += slen;
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_auth_response_decode(const struct gy_group_tier *tier,
                              struct gy_group_auth_response *resp,
                              const uint8_t *in, size_t len)
{
    size_t plen, slen, need, off;
    size_t j, i;
    int rc;

    if (tier == NULL || resp == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + slen + 2 * plen + GY_GROUP_PI_I_M * plen +
           GY_GROUP_PI_I_K * slen;
    if (len != need)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_AUTH_RESPONSE, in, len);
    if (rc != GY_OK)
        return rc;

    memset(resp, 0, sizeof(*resp));
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(resp->mac.t, in + off, slen);
    off += slen;
    memcpy(resp->mac.U, in + off, plen);
    off += plen;
    memcpy(resp->mac.V, in + off, plen);
    off += plen;
    for (j = 0; j < GY_GROUP_PI_I_M; j++) {
        memcpy(resp->proof_V[j], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_I_K; i++) {
        memcpy(resp->proof_r[i], in + off, slen);
        off += slen;
    }
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * AuthCredentialPresentation and ProfileKeyCredentialPresentation (tagged).
 * ------------------------------------------------------------------------- */

static void
put_be64(uint8_t *p, uint64_t v)
{
    size_t i;
    for (i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
}

static uint64_t
get_be64(const uint8_t *p)
{
    uint64_t v = 0;
    size_t i;
    for (i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

int
gy_group_auth_pres_encode(const struct gy_group_tier *tier,
                          const struct gy_group_auth_presentation *pres,
                          uint8_t *out, size_t cap, size_t *outlen)
{
    const uint8_t *pts[8];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || pres == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 8 * plen + 8 + GY_GROUP_PI_A_M * plen +
           GY_GROUP_PI_A_K * slen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_AUTH_PRESENTATION, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;

    pts[0] = pres->C_x0;
    pts[1] = pres->C_x1;
    pts[2] = pres->C_y1;
    pts[3] = pres->C_y2;
    pts[4] = pres->C_y3;
    pts[5] = pres->C_V;
    pts[6] = pres->E_A1;
    pts[7] = pres->E_A2;
    for (i = 0; i < 8; i++) {
        memcpy(out + off, pts[i], plen);
        off += plen;
    }
    put_be64(out + off, pres->date);
    off += 8;
    for (i = 0; i < GY_GROUP_PI_A_M; i++) {
        memcpy(out + off, pres->proof_V[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_A_K; i++) {
        memcpy(out + off, pres->proof_r[i], slen);
        off += slen;
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_auth_pres_decode(const struct gy_group_tier *tier,
                          struct gy_group_auth_presentation *pres,
                          const uint8_t *in, size_t len)
{
    uint8_t *pts[8];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || pres == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 8 * plen + 8 + GY_GROUP_PI_A_M * plen +
           GY_GROUP_PI_A_K * slen;
    if (len != need)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_AUTH_PRESENTATION, in, len);
    if (rc != GY_OK)
        return rc;

    memset(pres, 0, sizeof(*pres));
    off = GY_GROUP_OBJ_HDR_LEN;
    pts[0] = pres->C_x0;
    pts[1] = pres->C_x1;
    pts[2] = pres->C_y1;
    pts[3] = pres->C_y2;
    pts[4] = pres->C_y3;
    pts[5] = pres->C_V;
    pts[6] = pres->E_A1;
    pts[7] = pres->E_A2;
    for (i = 0; i < 8; i++) {
        memcpy(pts[i], in + off, plen);
        off += plen;
    }
    pres->date = get_be64(in + off);
    off += 8;
    for (i = 0; i < GY_GROUP_PI_A_M; i++) {
        memcpy(pres->proof_V[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_A_K; i++) {
        memcpy(pres->proof_r[i], in + off, slen);
        off += slen;
    }
    return GY_OK;
}

int
gy_group_pk_pres_encode(const struct gy_group_tier *tier,
                        const struct gy_group_pk_presentation *pres,
                        uint8_t *out, size_t cap, size_t *outlen)
{
    const uint8_t *pts[11];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || pres == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 11 * plen + GY_GROUP_PI_P_M * plen +
           GY_GROUP_PI_P_K * slen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_PK_PRESENTATION, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;

    pts[0] = pres->C_y1;
    pts[1] = pres->C_y2;
    pts[2] = pres->C_y3;
    pts[3] = pres->C_y4;
    pts[4] = pres->C_x0;
    pts[5] = pres->C_x1;
    pts[6] = pres->C_V;
    pts[7] = pres->E_A1;
    pts[8] = pres->E_A2;
    pts[9] = pres->E_B1;
    pts[10] = pres->E_B2;
    for (i = 0; i < 11; i++) {
        memcpy(out + off, pts[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_P_M; i++) {
        memcpy(out + off, pres->proof_V[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_P_K; i++) {
        memcpy(out + off, pres->proof_r[i], slen);
        off += slen;
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_pk_pres_decode(const struct gy_group_tier *tier,
                        struct gy_group_pk_presentation *pres,
                        const uint8_t *in, size_t len)
{
    uint8_t *pts[11];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || pres == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 11 * plen + GY_GROUP_PI_P_M * plen +
           GY_GROUP_PI_P_K * slen;
    if (len != need)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_PK_PRESENTATION, in, len);
    if (rc != GY_OK)
        return rc;

    memset(pres, 0, sizeof(*pres));
    off = GY_GROUP_OBJ_HDR_LEN;
    pts[0] = pres->C_y1;
    pts[1] = pres->C_y2;
    pts[2] = pres->C_y3;
    pts[3] = pres->C_y4;
    pts[4] = pres->C_x0;
    pts[5] = pres->C_x1;
    pts[6] = pres->C_V;
    pts[7] = pres->E_A1;
    pts[8] = pres->E_A2;
    pts[9] = pres->E_B1;
    pts[10] = pres->E_B2;
    for (i = 0; i < 11; i++) {
        memcpy(pts[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_P_M; i++) {
        memcpy(pres->proof_V[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_P_K; i++) {
        memcpy(pres->proof_r[i], in + off, slen);
        off += slen;
    }
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * Blind-issuance objects (section 3.3 / 5.3, GER-M8-08): ProfileKeyCommitment,
 * ProfileKeyCredentialRequest, ProfileKeyCredentialResponse.  Each is tagged;
 * fields are serialized in struct-declaration order.
 * ------------------------------------------------------------------------- */

int
gy_group_pk_commit_encode(const struct gy_group_tier *tier,
                          const struct gy_group_pk_commitment *commit,
                          uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, need, off;
    int rc;

    if (tier == NULL || commit == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    need = GY_GROUP_OBJ_HDR_LEN + 3 * plen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_PK_COMMITMENT, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(out + off, commit->J1, plen);
    off += plen;
    memcpy(out + off, commit->J2, plen);
    off += plen;
    memcpy(out + off, commit->J3, plen);
    *outlen = need;
    return GY_OK;
}

int
gy_group_pk_commit_decode(const struct gy_group_tier *tier,
                          struct gy_group_pk_commitment *commit,
                          const uint8_t *in, size_t len)
{
    size_t plen, off;
    int rc;

    if (tier == NULL || commit == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    if (len != GY_GROUP_OBJ_HDR_LEN + 3 * plen)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_PK_COMMITMENT, in, len);
    if (rc != GY_OK)
        return rc;

    memset(commit, 0, sizeof(*commit));
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(commit->J1, in + off, plen);
    off += plen;
    memcpy(commit->J2, in + off, plen);
    off += plen;
    memcpy(commit->J3, in + off, plen);
    return GY_OK;
}

int
gy_group_pk_request_encode(const struct gy_group_tier *tier,
                           const struct gy_group_pk_request *req, uint8_t *out,
                           size_t cap, size_t *outlen)
{
    const uint8_t *pts[5];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || req == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 5 * plen + GY_GROUP_PI_BR_M * plen +
           GY_GROUP_PI_BR_K * slen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_PK_REQUEST, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;

    pts[0] = req->Y;
    pts[1] = req->D1;
    pts[2] = req->D2;
    pts[3] = req->E1;
    pts[4] = req->E2;
    for (i = 0; i < 5; i++) {
        memcpy(out + off, pts[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BR_M; i++) {
        memcpy(out + off, req->proof_V[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BR_K; i++) {
        memcpy(out + off, req->proof_r[i], slen);
        off += slen;
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_pk_request_decode(const struct gy_group_tier *tier,
                           struct gy_group_pk_request *req, const uint8_t *in,
                           size_t len)
{
    uint8_t *pts[5];
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || req == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 5 * plen + GY_GROUP_PI_BR_M * plen +
           GY_GROUP_PI_BR_K * slen;
    if (len != need)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_PK_REQUEST, in, len);
    if (rc != GY_OK)
        return rc;

    memset(req, 0, sizeof(*req));
    off = GY_GROUP_OBJ_HDR_LEN;
    pts[0] = req->Y;
    pts[1] = req->D1;
    pts[2] = req->D2;
    pts[3] = req->E1;
    pts[4] = req->E2;
    for (i = 0; i < 5; i++) {
        memcpy(pts[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BR_M; i++) {
        memcpy(req->proof_V[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BR_K; i++) {
        memcpy(req->proof_r[i], in + off, slen);
        off += slen;
    }
    return GY_OK;
}

int
gy_group_pk_response_encode(const struct gy_group_tier *tier,
                            const struct gy_group_pk_blind_response *resp,
                            uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || resp == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 3 * plen + slen + GY_GROUP_PI_BI_M * plen +
           GY_GROUP_PI_BI_K * slen;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_PK_RESPONSE, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(out + off, resp->S1, plen);
    off += plen;
    memcpy(out + off, resp->S2, plen);
    off += plen;
    memcpy(out + off, resp->t, slen);
    off += slen;
    memcpy(out + off, resp->U, plen);
    off += plen;
    for (i = 0; i < GY_GROUP_PI_BI_M; i++) {
        memcpy(out + off, resp->proof_V[i], plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BI_K; i++) {
        memcpy(out + off, resp->proof_r[i], slen);
        off += slen;
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_pk_response_decode(const struct gy_group_tier *tier,
                            struct gy_group_pk_blind_response *resp,
                            const uint8_t *in, size_t len)
{
    size_t plen, slen, need, off, i;
    int rc;

    if (tier == NULL || resp == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    slen = tier->scalar_len;
    need = GY_GROUP_OBJ_HDR_LEN + 3 * plen + slen + GY_GROUP_PI_BI_M * plen +
           GY_GROUP_PI_BI_K * slen;
    if (len != need)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_PK_RESPONSE, in, len);
    if (rc != GY_OK)
        return rc;

    memset(resp, 0, sizeof(*resp));
    off = GY_GROUP_OBJ_HDR_LEN;
    memcpy(resp->S1, in + off, plen);
    off += plen;
    memcpy(resp->S2, in + off, plen);
    off += plen;
    memcpy(resp->t, in + off, slen);
    off += slen;
    memcpy(resp->U, in + off, plen);
    off += plen;
    for (i = 0; i < GY_GROUP_PI_BI_M; i++) {
        memcpy(resp->proof_V[i], in + off, plen);
        off += plen;
    }
    for (i = 0; i < GY_GROUP_PI_BI_K; i++) {
        memcpy(resp->proof_r[i], in + off, slen);
        off += slen;
    }
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * ProfileKeyVersion (section 3.3, grp-pkv; GER-M8-08 Split B): a tagged object
 * wrapping the fixed 32-byte identifier.  Tier-independent payload width, but
 * the object header still carries the suite_id tag for a uniform wire surface.
 * ------------------------------------------------------------------------- */

int
gy_group_pk_version_encode(const struct gy_group_tier *tier,
                           const uint8_t version[GY_GROUP_PK_VERSION_BYTES],
                           uint8_t *out, size_t cap, size_t *outlen)
{
    size_t need;
    int rc;

    if (tier == NULL || version == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    need = GY_GROUP_OBJ_HDR_LEN + GY_GROUP_PK_VERSION_BYTES;
    if (cap < need)
        return GY_ERR_TOOLONG;

    rc = gy_group_obj_put_header(tier, GY_GOBJ_PK_VERSION, out, cap);
    if (rc != GY_OK)
        return rc;
    memcpy(out + GY_GROUP_OBJ_HDR_LEN, version, GY_GROUP_PK_VERSION_BYTES);
    *outlen = need;
    return GY_OK;
}

int
gy_group_pk_version_decode(const struct gy_group_tier *tier,
                           uint8_t version[GY_GROUP_PK_VERSION_BYTES],
                           const uint8_t *in, size_t len)
{
    int rc;

    if (tier == NULL || version == NULL || in == NULL)
        return GY_ERR_ARG;
    if (len != GY_GROUP_OBJ_HDR_LEN + GY_GROUP_PK_VERSION_BYTES)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_PK_VERSION, in, len);
    if (rc != GY_OK)
        return rc;

    memcpy(version, in + GY_GROUP_OBJ_HDR_LEN, GY_GROUP_PK_VERSION_BYTES);
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * GROUP_KEY_DISTRIBUTION envelope frame (section 9 item 4, GER-M8-08 Path A):
 * a D-GEN-1 typed envelope (version || suite || msg_type || GroupMasterKey)
 * framed and validated here in the group vertical so proto/envelope.c stays
 * group-unaware.  The payload is exactly the GroupMasterKey; strict parse.
 * ------------------------------------------------------------------------- */

int
gy_group_key_distribution_encode(const struct gy_group_tier *tier,
                                 uint16_t format_version,
                                 const uint8_t *master_key, size_t mk_len,
                                 uint8_t *out, size_t cap, size_t *outlen)
{
    size_t need, off;

    if (tier == NULL || master_key == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (mk_len != tier->master_key_len)
        return GY_ERR_ARG;
    need = GY_GROUP_ENVELOPE_HDR_LEN + GY_GROUP_ENVELOPE_FMTVER_LEN +
           tier->master_key_len;
    if (cap < need)
        return GY_ERR_TOOLONG;

    out[0] = GY_WIRE_VERSION;
    out[1] = tier->suite_id;
    out[2] = GY_MSG_GROUP_KEY_DISTRIBUTION;
    off = GY_GROUP_ENVELOPE_HDR_LEN;
    out[off++] = (uint8_t)(format_version >> 8); /* format version, BE16 */
    out[off++] = (uint8_t)(format_version & 0xff);
    memcpy(out + off, master_key, tier->master_key_len);
    *outlen = need;
    return GY_OK;
}

int
gy_group_key_distribution_decode(const struct gy_group_tier *tier,
                                 const uint8_t *in, size_t len,
                                 uint16_t *out_format_version,
                                 uint8_t *out_master_key, size_t mk_cap,
                                 size_t *out_mk_len)
{
    size_t off;

    if (tier == NULL || in == NULL || out_format_version == NULL ||
        out_master_key == NULL || out_mk_len == NULL)
        return GY_ERR_ARG;
    if (mk_cap < tier->master_key_len)
        return GY_ERR_ARG;
    if (len != GY_GROUP_ENVELOPE_HDR_LEN + GY_GROUP_ENVELOPE_FMTVER_LEN +
                   tier->master_key_len)
        return GY_ERR_VERIFY;
    if (in[0] != GY_WIRE_VERSION || in[1] != tier->suite_id ||
        in[2] != GY_MSG_GROUP_KEY_DISTRIBUTION)
        return GY_ERR_VERIFY;

    off = GY_GROUP_ENVELOPE_HDR_LEN;
    *out_format_version = (uint16_t)(((uint16_t)in[off] << 8) | in[off + 1]);
    off += GY_GROUP_ENVELOPE_FMTVER_LEN;
    memcpy(out_master_key, in + off, tier->master_key_len);
    *out_mk_len = tier->master_key_len;
    return GY_OK;
}

/* ------------------------------------------------------------------------- *
 * FetchGroupMembers member-entry list (section 7.7 / 9 item 2, GER-M8-09
 * Split C): the ONE variable-length group wire object.  Tagged, a 2-byte BE
 * count, then fixed-width entries (has_profile_key || role || UidCiphertext ||
 * ProfileKeyCiphertext), the invited pk slot all-zero.  Membership is transient
 * transport only, never persisted (D-GRP-7).
 * ------------------------------------------------------------------------- */

int
gy_group_member_list_encode(const struct gy_group_tier *tier,
                            const struct gy_group_member_ct *entries, size_t n,
                            uint8_t *out, size_t cap, size_t *outlen)
{
    size_t plen, entry, need, off, i;
    int rc;

    if (tier == NULL || (entries == NULL && n != 0) || out == NULL ||
        outlen == NULL)
        return GY_ERR_ARG;
    if (n > GY_GROUP_MAX_ENTRIES)
        return GY_ERR_ARG;
    plen = tier->point_len;
    entry = 2 + 4 * plen;
    need = GY_GROUP_OBJ_HDR_LEN + 2 + n * entry;
    if (cap < need)
        return GY_ERR_TOOLONG;

    /* Reject an undefined role before writing anything (symmetry with the strict
     * decoder): never emit a roster a conforming decoder would reject. */
    for (i = 0; i < n; i++) {
        if (entries[i].role > GY_GROUP_ROLE_MAX)
            return GY_ERR_ARG;
    }

    rc = gy_group_obj_put_header(tier, GY_GOBJ_MEMBER_LIST, out, cap);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;
    out[off++] = (uint8_t)(n >> 8);
    out[off++] = (uint8_t)(n & 0xff);
    for (i = 0; i < n; i++) {
        const struct gy_group_member_ct *e = &entries[i];
        out[off++] = e->has_profile_key ? 1 : 0;
        out[off++] = e->role;
        memcpy(out + off, e->uid_ct.E_A1, plen);
        off += plen;
        memcpy(out + off, e->uid_ct.E_A2, plen);
        off += plen;
        if (e->has_profile_key) {
            memcpy(out + off, e->pk_ct.E_B1, plen);
            off += plen;
            memcpy(out + off, e->pk_ct.E_B2, plen);
            off += plen;
        } else {
            memset(out + off, 0, 2 * plen); /* invited: zero pk slot */
            off += 2 * plen;
        }
    }
    *outlen = need;
    return GY_OK;
}

int
gy_group_member_list_decode(const struct gy_group_tier *tier,
                            struct gy_group_member_ct *out, size_t out_cap,
                            size_t *out_n, const uint8_t *in, size_t len)
{
    size_t plen, entry, off, i, n;
    int rc;

    if (tier == NULL || out == NULL || out_n == NULL || in == NULL)
        return GY_ERR_ARG;
    plen = tier->point_len;
    entry = 2 + 4 * plen;
    if (len < GY_GROUP_OBJ_HDR_LEN + 2)
        return GY_ERR_VERIFY;

    rc = gy_group_obj_check_header(tier, GY_GOBJ_MEMBER_LIST, in, len);
    if (rc != GY_OK)
        return rc;
    off = GY_GROUP_OBJ_HDR_LEN;
    n = ((size_t)in[off] << 8) | in[off + 1];
    off += 2;
    if (n > GY_GROUP_MAX_ENTRIES)
        return GY_ERR_VERIFY;
    if (n > out_cap)
        return GY_ERR_TOOLONG;
    if (len != GY_GROUP_OBJ_HDR_LEN + 2 + n * entry)
        return GY_ERR_VERIFY; /* strict: exact length, no trailing bytes */

    memset(out, 0, out_cap * sizeof(*out));
    for (i = 0; i < n; i++) {
        struct gy_group_member_ct *e = &out[i];
        uint8_t hpk = in[off++];
        uint8_t role = in[off++];

        /* Strict: the flag is boolean and the role is a known GY_GROUP_ROLE_*
         * value; an out-of-range byte from an untrusted roster fails the whole
         * fetch rather than reaching the application view. */
        if (hpk > 1 || role > GY_GROUP_ROLE_MAX) {
            rc = GY_ERR_VERIFY;
            goto fail;
        }
        e->has_profile_key = hpk;
        e->role = role;
        memcpy(e->uid_ct.E_A1, in + off, plen);
        off += plen;
        memcpy(e->uid_ct.E_A2, in + off, plen);
        off += plen;
        if (hpk) {
            memcpy(e->pk_ct.E_B1, in + off, plen);
            off += plen;
            memcpy(e->pk_ct.E_B2, in + off, plen);
            off += plen;
        } else {
            if (!gy_is_zero(in + off, 2 * plen)) { /* invited slot must be 0 */
                rc = GY_ERR_VERIFY;
                goto fail;
            }
            off += 2 * plen; /* pk_ct stays zero from the memset above */
        }
    }
    *out_n = n;
    return GY_OK;

fail:
    memset(out, 0, out_cap * sizeof(*out));
    return rc;
}
