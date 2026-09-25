/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_ops.h"

#include "qspgs_field.h" /* gy_qspgs_member_ct_open / _seal */
#include "qspgs_join.h"
#include "qspgs_keys.h"
#include "qspgs_labels.h" /* GY_QSPGS_CTX_REGUSER / _INVACCEPT / _CORE */
#include "qspgs_pers.h"
#include "qspgs_wire.h" /* gy_qspgs_vkpsdn_hash, acct/core-sig codecs */

#include "encode.h" /* gy_be16_put/get */
#include "error.h"
#include "krmldsa44.h"
#include "krmldsa87.h"
#include "rng.h"   /* gy_random_bytes */
#include "suite.h" /* gy_suite_desc */
#include "util.h"

/*
 * The client-operation crypto engine.  Pure
 * composition of the key-hierarchy derivations, the tier-hash / wire
 * helpers, the skpers dual signer, and the join PKE; no new primitive.
 */

/* Registration object skpers signs: vkbase || acq. */
#define QSPGS_REGUSER_TBS_MAX (GY_QSPGS_VKB_MAX + GY_QSPGS_MASTER_KEY_MAX)

/* Invite-acceptance object skpers signs: uidlen(1) || UID || uk || GID. */
#define QSPGS_INVACCEPT_TBS_MAX                                                \
    (1 + GY_QSPGS_UID_MAX + GY_QSPGS_MASTER_KEY_MAX + GY_QSPGS_GID_LEN)

/* Invite plaintext sealed to ipk: uidlen(1) || UID || uk || ed_sig_len(2) ||
 * ed_sig || mldsa_sig_len(2) || mldsa_sig. */
#define QSPGS_INVITE_PT_MAX                                                    \
    (1 + GY_QSPGS_UID_MAX + GY_QSPGS_MASTER_KEY_MAX + 2 +                      \
     GY_QSPGS_PERS_ED_SIG_MAX + 2 + GY_QSPGS_PERS_MLDSA_SIG_MAX)

/* Build vkbase || acq into out; returns the length. */
size_t
gy_qspgs_reguser_tbs(uint8_t suite_id, const uint8_t *vkb, const uint8_t *acq,
                     uint8_t *out)
{
    size_t vkblen = gy_qspgs_base_vkb_len(suite_id);
    size_t mklen = gy_qspgs_master_key_len(suite_id);

    memcpy(out, vkb, vkblen);
    memcpy(out + vkblen, acq, mklen);
    return vkblen + mklen;
}

/* Build uidlen(1) || UID || uk || GID into out; returns the length. */
size_t
gy_qspgs_invaccept_tbs(uint8_t suite_id, const uint8_t *uid, size_t uidlen,
                       const uint8_t *uk, const uint8_t gid[GY_QSPGS_GID_LEN],
                       uint8_t *out)
{
    size_t mklen = gy_qspgs_master_key_len(suite_id);

    out[0] = (uint8_t)uidlen;
    memcpy(out + 1, uid, uidlen);
    memcpy(out + 1 + uidlen, uk, mklen);
    memcpy(out + 1 + uidlen + mklen, gid, GY_QSPGS_GID_LEN);
    return 1 + uidlen + mklen + GY_QSPGS_GID_LEN;
}

int
gy_qspgs_member_ctx_open(struct gy_qspgs_member_ctx *ctx, uint8_t suite_id,
                         const uint8_t *gk, const uint8_t *skb,
                         const uint8_t *vkb, const uint8_t *uid, size_t uidlen)
{
    int rc;

    if (ctx == NULL || gk == NULL || skb == NULL || vkb == NULL || uid == NULL)
        return GY_ERR_ARG;
    if (gy_qspgs_master_key_len(suite_id) == 0)
        return GY_ERR_ARG;

    memset(ctx, 0, sizeof(*ctx));

    rc = gy_qspgs_derive_sub_key(suite_id, gk, ctx->ek, ctx->rrs);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_rho(suite_id, ctx->rrs, uid, uidlen, ctx->rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_vk_psdn(suite_id, ctx->vkr, vkb, ctx->rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_sk_psdn(suite_id, &ctx->sk, skb, vkb, ctx->rho);
    if (rc != GY_OK) {
        gy_qspgs_member_ctx_clear(ctx);
        return rc;
    }

    ctx->suite_id = suite_id;
    return GY_OK;
}

void
gy_qspgs_member_ctx_clear(struct gy_qspgs_member_ctx *ctx)
{
    if (ctx == NULL)
        return;
    gy_qspgs_psdn_sk_clear(&ctx->sk);
    gy_secure_zero(ctx->ek, sizeof(ctx->ek));
    gy_secure_zero(ctx->rrs, sizeof(ctx->rrs));
    gy_secure_zero(ctx->rho, sizeof(ctx->rho));
    gy_secure_zero(ctx->vkr, sizeof(ctx->vkr));
    ctx->suite_id = 0;
}

int
gy_qspgs_attribute_hash(uint8_t suite_id, const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                        const uint8_t *vkb, const uint8_t *uid, size_t uidlen,
                        uint8_t *out)
{
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    uint8_t vkr[GY_QSPGS_VKR_MAX];
    int rc;

    if (rrs == NULL || vkb == NULL || uid == NULL || out == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_derive_rho(suite_id, rrs, uid, uidlen, rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_vk_psdn(suite_id, vkr, vkb, rho);
    if (rc == GY_OK)
        rc = gy_qspgs_vkpsdn_hash(suite_id, vkr, out);

    gy_secure_zero(rho, sizeof(rho));
    gy_secure_zero(vkr, sizeof(vkr));
    return rc;
}

/* ---- core admin edits (section 6.3) ------------------------------------- */

int
gy_qspgs_group_key_gen(uint8_t suite_id, uint8_t *gk)
{
    size_t n = gy_qspgs_master_key_len(suite_id);

    if (n == 0 || gk == NULL)
        return GY_ERR_ARG;
    return gy_random_bytes(gk, n);
}

/* Shared body: seal the member tuple in the given form (key is uk for PRESENT,
 * gk' for PENDING), commit C_UID, and compute H(vkpsdn) from the base key. */
static int
member_build_form(uint8_t suite_id, uint8_t aead_id,
                  const uint8_t ek[GY_QSPGS_EK_BYTES],
                  const uint8_t gid[GY_QSPGS_GID_LEN],
                  const uint8_t rrs[GY_QSPGS_RRS_BYTES], uint8_t form,
                  const uint8_t *uid, size_t uidlen, const uint8_t *key,
                  const uint8_t *vkb, uint8_t admn,
                  struct gy_qspgs_member *out_member, uint8_t *mct_buf,
                  size_t mct_cap, size_t *mct_len, uint8_t *vkhash_out)
{
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    int rc;

    if (ek == NULL || gid == NULL || rrs == NULL || uid == NULL ||
        key == NULL || vkb == NULL || out_member == NULL || mct_buf == NULL ||
        mct_len == NULL || vkhash_out == NULL)
        return GY_ERR_ARG;
    if (gy_qspgs_master_key_len(suite_id) == 0)
        return GY_ERR_ARG;

    memset(out_member, 0, sizeof(*out_member));
    *mct_len = 0;

    rc = gy_random_bytes(rc_open, sizeof(rc_open));
    if (rc != GY_OK)
        goto out;
    if (form == GY_QSPGS_MEMBER_FORM_PENDING)
        rc = gy_qspgs_member_ct_seal_pending(suite_id, aead_id, ek, gid, uid,
                                             uidlen, rc_open, key, mct_buf,
                                             mct_cap, mct_len);
    else
        rc = gy_qspgs_member_ct_seal(suite_id, aead_id, ek, gid, uid, uidlen,
                                     rc_open, key, mct_buf, mct_cap, mct_len);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_cuid_commit(suite_id, uid, uidlen, rc_open, out_member->cuid);
    if (rc != GY_OK)
        goto out;
    rc = gy_qspgs_attribute_hash(suite_id, rrs, vkb, uid, uidlen, vkhash_out);
    if (rc != GY_OK)
        goto out;

    out_member->admn = admn ? 1 : 0;
    out_member->mct = mct_buf;
    out_member->mct_len = *mct_len;
    rc = GY_OK;

out:
    gy_secure_zero(rc_open, sizeof(rc_open));
    if (rc != GY_OK) {
        memset(out_member, 0, sizeof(*out_member));
        *mct_len = 0;
    }
    return rc;
}

int
gy_qspgs_member_build(uint8_t suite_id, uint8_t aead_id,
                      const uint8_t ek[GY_QSPGS_EK_BYTES],
                      const uint8_t gid[GY_QSPGS_GID_LEN],
                      const uint8_t rrs[GY_QSPGS_RRS_BYTES], const uint8_t *uid,
                      size_t uidlen, const uint8_t *uk, const uint8_t *vkb,
                      uint8_t admn, struct gy_qspgs_member *out_member,
                      uint8_t *mct_buf, size_t mct_cap, size_t *mct_len,
                      uint8_t *vkhash_out)
{
    return member_build_form(suite_id, aead_id, ek, gid, rrs,
                             GY_QSPGS_MEMBER_FORM_PRESENT, uid, uidlen, uk, vkb,
                             admn, out_member, mct_buf, mct_cap, mct_len,
                             vkhash_out);
}

int
gy_qspgs_member_build_pending(
    uint8_t suite_id, uint8_t aead_id, const uint8_t ek[GY_QSPGS_EK_BYTES],
    const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t rrs[GY_QSPGS_RRS_BYTES],
    const uint8_t *uid, size_t uidlen, const uint8_t *gk_prime,
    const uint8_t *vkb, struct gy_qspgs_member *out_member, uint8_t *mct_buf,
    size_t mct_cap, size_t *mct_len, uint8_t *vkhash_out)
{
    /* A pending invite is never an admin line; admn is 0. */
    return member_build_form(suite_id, aead_id, ek, gid, rrs,
                             GY_QSPGS_MEMBER_FORM_PENDING, uid, uidlen,
                             gk_prime, vkb, 0, out_member, mct_buf, mct_cap,
                             mct_len, vkhash_out);
}

/*
 * Sign msg under the member context's skpsdn with the given context string,
 * into sig (GY_QSPGS_SIG_MAX); *siglen holds the tier signature length.  The
 * one place the KR-ML-DSA sign is dispatched by suite.  Returns GY_OK,
 * GY_ERR_CRYPTO on a sign failure, or GY_ERR_ARG for a bad context.
 */
static int
ctx_sign(const struct gy_qspgs_member_ctx *ctx, const uint8_t *msg,
         size_t msglen, const uint8_t *sctx, size_t sctxlen,
         uint8_t sig[GY_QSPGS_SIG_MAX], size_t *siglen)
{
    int rc;

    switch (ctx->suite_id) {
    case GY_SUITE_H25519_512:
        rc = gy_kr44_sign(sig, &ctx->sk.rsk.k44, msg, msglen, sctx, sctxlen);
        *siglen = GY_KR44_SIG;
        break;
    case GY_SUITE_H448_1024:
        rc = gy_kr87_sign(sig, &ctx->sk.rsk.k87, msg, msglen, sctx, sctxlen);
        *siglen = GY_KR87_SIG;
        break;
    default:
        return GY_ERR_ARG;
    }
    return rc == GY_OK ? GY_OK : GY_ERR_CRYPTO;
}

int
gy_qspgs_core_sign(const struct gy_qspgs_core *core, uint32_t signer_index,
                   const struct gy_qspgs_member_ctx *ctx, uint8_t *out,
                   size_t cap, size_t *outlen, uint8_t *scratch,
                   size_t scratch_cap)
{
    static const uint8_t sctx[] = GY_QSPGS_CTX_CORE;
    uint8_t sig[GY_QSPGS_SIG_MAX];
    size_t tbslen, siglen;
    int rc;

    if (core == NULL || ctx == NULL || out == NULL || outlen == NULL ||
        scratch == NULL)
        return GY_ERR_ARG;
    if (ctx->suite_id == 0 || ctx->suite_id != core->suite_id)
        return GY_ERR_ARG;

    rc = gy_qspgs_core_tbs(core, signer_index, scratch, scratch_cap, &tbslen);
    if (rc != GY_OK)
        return rc;

    rc = ctx_sign(ctx, scratch, tbslen, sctx, sizeof(sctx) - 1, sig, &siglen);
    if (rc != GY_OK) {
        gy_secure_zero(sig, sizeof(sig));
        return rc;
    }

    rc = gy_qspgs_core_sig_encode(core->suite_id, signer_index, core->last_vmin,
                                  sig, siglen, out, cap, outlen);
    gy_secure_zero(sig, sizeof(sig));
    return rc;
}

int
gy_qspgs_apx_line_sign(uint8_t suite_id, const struct gy_qspgs_member_ctx *ctx,
                       const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
                       uint32_t vmin, uint8_t line_type, uint32_t author_index,
                       const uint8_t *payload, size_t payload_len,
                       uint8_t *sig_out, size_t sig_cap, size_t *sig_len,
                       uint8_t *scratch, size_t scratch_cap)
{
    static const uint8_t actx[] = GY_QSPGS_CTX_APPENDIX;
    uint8_t sig[GY_QSPGS_SIG_MAX];
    size_t tbslen, siglen;
    int rc;

    if (ctx == NULL || gid == NULL || sig_out == NULL || sig_len == NULL ||
        scratch == NULL)
        return GY_ERR_ARG;
    if (payload == NULL && payload_len != 0)
        return GY_ERR_ARG;
    if (ctx->suite_id == 0 || ctx->suite_id != suite_id)
        return GY_ERR_ARG;

    rc =
        gy_qspgs_apx_line_tbs(gid, vmaj, vmin, line_type, author_index, payload,
                              payload_len, scratch, scratch_cap, &tbslen);
    if (rc != GY_OK)
        return rc;

    rc = ctx_sign(ctx, scratch, tbslen, actx, sizeof(actx) - 1, sig, &siglen);
    if (rc != GY_OK)
        goto out;
    if (sig_cap < siglen) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    memcpy(sig_out, sig, siglen);
    *sig_len = siglen;
    rc = GY_OK;

out:
    gy_secure_zero(sig, sizeof(sig));
    return rc;
}

int
gy_qspgs_apx_line_resolve_verify(
    uint8_t suite_id, const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t vmaj,
    uint32_t vmin, const struct gy_qspgs_apx_line *line,
    const uint8_t rrs[GY_QSPGS_RRS_BYTES], const uint8_t *author_vkb,
    const uint8_t *author_uid, size_t author_uidlen,
    const uint8_t *stored_vkhash, uint8_t *scratch, size_t scratch_cap)
{
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    uint8_t vkr[GY_QSPGS_VKR_MAX];
    int rc;

    if (gid == NULL || line == NULL || rrs == NULL || author_vkb == NULL ||
        author_uid == NULL || scratch == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_derive_rho(suite_id, rrs, author_uid, author_uidlen, rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_vk_psdn(suite_id, vkr, author_vkb, rho);
    if (rc == GY_OK && stored_vkhash != NULL)
        rc = gy_qspgs_vkpsdn_hash_check(suite_id, vkr, stored_vkhash);
    if (rc == GY_OK)
        rc = gy_qspgs_apx_line_verify(suite_id, gid, vmaj, vmin, line, vkr,
                                      scratch, scratch_cap);

    gy_secure_zero(rho, sizeof(rho));
    gy_secure_zero(vkr, sizeof(vkr));
    return rc;
}

int
gy_qspgs_leave_token_sign(uint8_t suite_id,
                          const struct gy_qspgs_member_ctx *ctx,
                          const uint8_t gid[GY_QSPGS_GID_LEN], uint32_t k,
                          uint8_t *sig_out, size_t sig_cap, size_t *sig_len)
{
    static const uint8_t sctx[] = GY_QSPGS_CTX_LEAVEFETCH;
    uint8_t tbs[GY_QSPGS_GID_LEN + 4];
    uint8_t sig[GY_QSPGS_SIG_MAX];
    size_t tbslen, siglen;
    int rc;

    if (ctx == NULL || gid == NULL || sig_out == NULL || sig_len == NULL)
        return GY_ERR_ARG;
    if (ctx->suite_id == 0 || ctx->suite_id != suite_id)
        return GY_ERR_ARG;

    rc = gy_qspgs_leave_token_tbs(gid, k, tbs, sizeof(tbs), &tbslen);
    if (rc != GY_OK)
        return rc;
    rc = ctx_sign(ctx, tbs, tbslen, sctx, sizeof(sctx) - 1, sig, &siglen);
    if (rc != GY_OK)
        goto out;
    if (sig_cap < siglen) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    memcpy(sig_out, sig, siglen);
    *sig_len = siglen;
    rc = GY_OK;
out:
    gy_secure_zero(sig, sizeof(sig));
    return rc;
}

/* ---- RegisterUser / GrantAcquaintance (section 7.2) --------------------- */

int
gy_qspgs_register(uint8_t suite_id, const uint8_t *vkb, const uint8_t *acq,
                  uint64_t ep, const uint8_t *id_curve_sk,
                  const uint8_t *id_mldsa_sk, uint8_t *out, size_t cap,
                  size_t *outlen)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t tbs[QSPGS_REGUSER_TBS_MAX];
    uint8_t ed_sig[GY_QSPGS_PERS_ED_SIG_MAX];
    uint8_t mldsa_sig[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    size_t tbslen;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (vkb == NULL || acq == NULL || id_curve_sk == NULL ||
        id_mldsa_sk == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;

    tbslen = gy_qspgs_reguser_tbs(suite_id, vkb, acq, tbs);
    rc = gy_qspgs_pers_sign(suite_id, id_curve_sk, id_mldsa_sk,
                            GY_QSPGS_CTX_REGUSER, tbs, tbslen, ed_sig,
                            mldsa_sig);
    if (rc == GY_OK)
        rc = gy_qspgs_acct_encode(suite_id, vkb, acq, ep, ed_sig, desc->sig_len,
                                  mldsa_sig, desc->dsa_sig_len, out, cap,
                                  outlen);

    gy_secure_zero(tbs, sizeof(tbs));
    return rc;
}

int
gy_qspgs_acct_verify(uint8_t suite_id, const uint8_t *id_curve_pk,
                     const uint8_t *id_mldsa_pk, const uint8_t *in,
                     size_t inlen, const uint8_t **vkb, const uint8_t **acq,
                     uint64_t *ep)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    const uint8_t *dvkb, *dacq, *ed_sig, *mldsa_sig;
    uint8_t tbs[QSPGS_REGUSER_TBS_MAX];
    size_t ed_sig_len, mldsa_sig_len, consumed, tbslen;
    uint64_t dep;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (id_curve_pk == NULL || id_mldsa_pk == NULL || in == NULL ||
        vkb == NULL || acq == NULL || ep == NULL)
        return GY_ERR_ARG;

    rc = gy_qspgs_acct_decode(suite_id, in, inlen, &dvkb, &dacq, &dep, &ed_sig,
                              &ed_sig_len, &mldsa_sig, &mldsa_sig_len,
                              &consumed);
    if (rc != GY_OK)
        return rc;
    /* Reject a record whose signature widths are not the tier's. */
    if (ed_sig_len != desc->sig_len || mldsa_sig_len != desc->dsa_sig_len)
        return GY_ERR_VERIFY;

    tbslen = gy_qspgs_reguser_tbs(suite_id, dvkb, dacq, tbs);
    rc = gy_qspgs_pers_verify(suite_id, id_curve_pk, id_mldsa_pk,
                              GY_QSPGS_CTX_REGUSER, tbs, tbslen, ed_sig,
                              mldsa_sig);
    gy_secure_zero(tbs, sizeof(tbs));
    if (rc != GY_OK)
        return rc;

    *vkb = dvkb;
    *acq = dacq;
    *ep = dep;
    return GY_OK;
}

/* ---- Invite / AcceptInvitation (section 4 item 6) ----------------------- */

int
gy_qspgs_invite_seal_signed(uint8_t suite_id, const gy_qspgs_join_pk_t *ipk,
                            const uint8_t *uid, size_t uidlen,
                            const uint8_t *uk, const uint8_t *ed_sig,
                            size_t ed_sig_len, const uint8_t *mldsa_sig,
                            size_t mldsa_sig_len, uint8_t *out, size_t cap,
                            size_t *outlen)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t pt[QSPGS_INVITE_PT_MAX];
    size_t mklen, off;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (ipk == NULL || uid == NULL || uk == NULL || ed_sig == NULL ||
        mldsa_sig == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    if (ipk->suite_id != suite_id)
        return GY_ERR_ARG;
    if (uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;
    if (ed_sig_len != desc->sig_len || mldsa_sig_len != desc->dsa_sig_len)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);

    /* pt = uidlen(1) || UID || uk || ed_sig_len(2) || ed_sig ||
     *      mldsa_sig_len(2) || mldsa_sig. */
    pt[0] = (uint8_t)uidlen;
    off = 1;
    memcpy(pt + off, uid, uidlen);
    off += uidlen;
    memcpy(pt + off, uk, mklen);
    off += mklen;
    gy_be16_put(pt + off, (uint16_t)ed_sig_len);
    off += 2;
    memcpy(pt + off, ed_sig, ed_sig_len);
    off += ed_sig_len;
    gy_be16_put(pt + off, (uint16_t)mldsa_sig_len);
    off += 2;
    memcpy(pt + off, mldsa_sig, mldsa_sig_len);
    off += mldsa_sig_len;

    rc = gy_qspgs_join_seal(ipk, pt, off, out, cap, outlen);
    gy_secure_zero(pt, sizeof(pt));
    return rc;
}

int
gy_qspgs_invite_seal(uint8_t suite_id, const gy_qspgs_join_pk_t *ipk,
                     const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *uid,
                     size_t uidlen, const uint8_t *uk,
                     const uint8_t *id_curve_sk, const uint8_t *id_mldsa_sk,
                     uint8_t *out, size_t cap, size_t *outlen)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t tbs[QSPGS_INVACCEPT_TBS_MAX];
    uint8_t ed_sig[GY_QSPGS_PERS_ED_SIG_MAX];
    uint8_t mldsa_sig[GY_QSPGS_PERS_MLDSA_SIG_MAX];
    size_t tbslen;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (gid == NULL || uid == NULL || uk == NULL || id_curve_sk == NULL ||
        id_mldsa_sk == NULL)
        return GY_ERR_ARG;
    if (uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;

    tbslen = gy_qspgs_invaccept_tbs(suite_id, uid, uidlen, uk, gid, tbs);
    rc = gy_qspgs_pers_sign(suite_id, id_curve_sk, id_mldsa_sk,
                            GY_QSPGS_CTX_INVACCEPT, tbs, tbslen, ed_sig,
                            mldsa_sig);
    if (rc == GY_OK)
        rc = gy_qspgs_invite_seal_signed(suite_id, ipk, uid, uidlen, uk, ed_sig,
                                         desc->sig_len, mldsa_sig,
                                         desc->dsa_sig_len, out, cap, outlen);
    gy_secure_zero(tbs, sizeof(tbs));
    return rc;
}

int
gy_qspgs_invite_open(uint8_t suite_id, const gy_qspgs_join_sk_t *isk,
                     const uint8_t *in, size_t inlen,
                     struct gy_qspgs_invite *out)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t pt[QSPGS_INVITE_PT_MAX];
    size_t mklen, ptlen, off, ul, esl, msl;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (isk == NULL || in == NULL || out == NULL)
        return GY_ERR_ARG;
    if (isk->suite_id != suite_id)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);

    memset(out, 0, sizeof(*out));
    ptlen = 0;
    rc = gy_qspgs_join_open(isk, in, inlen, pt, sizeof(pt), &ptlen);
    if (rc != GY_OK)
        goto out;

    /* Parse the invite plaintext; reject a malformed one. */
    if (ptlen < 1) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    ul = pt[0];
    off = 1;
    if (ul != GY_QSPGS_UID_LEN || off + ul + mklen + 2 > ptlen) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    memcpy(out->uid, pt + off, ul);
    out->uidlen = ul;
    off += ul;
    memcpy(out->uk, pt + off, mklen);
    off += mklen;
    esl = gy_be16_get(pt + off);
    off += 2;
    if (esl != desc->sig_len || off + esl + 2 > ptlen) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    memcpy(out->ed_sig, pt + off, esl);
    out->ed_sig_len = esl;
    off += esl;
    msl = gy_be16_get(pt + off);
    off += 2;
    if (msl != desc->dsa_sig_len || off + msl != ptlen) {
        rc = GY_ERR_VERIFY; /* strict: exact plaintext length. */
        goto out;
    }
    memcpy(out->mldsa_sig, pt + off, msl);
    out->mldsa_sig_len = msl;
    rc = GY_OK;

out:
    gy_secure_zero(pt, sizeof(pt));
    if (rc != GY_OK)
        gy_qspgs_invite_clear(out);
    return rc;
}

int
gy_qspgs_invite_verify(uint8_t suite_id, const uint8_t gid[GY_QSPGS_GID_LEN],
                       const uint8_t *id_curve_pk, const uint8_t *id_mldsa_pk,
                       const struct gy_qspgs_invite *inv)
{
    uint8_t tbs[QSPGS_INVACCEPT_TBS_MAX];
    size_t mklen, tbslen;
    int rc;

    if (gid == NULL || id_curve_pk == NULL || id_mldsa_pk == NULL ||
        inv == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;
    if (inv->uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;

    tbslen = gy_qspgs_invaccept_tbs(suite_id, inv->uid, inv->uidlen, inv->uk,
                                    gid, tbs);
    rc = gy_qspgs_pers_verify(suite_id, id_curve_pk, id_mldsa_pk,
                              GY_QSPGS_CTX_INVACCEPT, tbs, tbslen, inv->ed_sig,
                              inv->mldsa_sig);
    gy_secure_zero(tbs, sizeof(tbs));
    return rc;
}

void
gy_qspgs_invite_clear(struct gy_qspgs_invite *inv)
{
    if (inv == NULL)
        return;
    gy_secure_zero(inv, sizeof(*inv));
}

/* ---- Fetch read path (section 5) ---------------------------------------- */

int
gy_qspgs_member_decrypt(uint8_t suite_id, uint8_t aead_id,
                        const uint8_t ek[GY_QSPGS_EK_BYTES],
                        const uint8_t gid[GY_QSPGS_GID_LEN],
                        const struct gy_qspgs_member *m,
                        struct gy_qspgs_member_view *out)
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t rc_open[GY_QSPGS_RC_LEN];
    uint8_t computed[GY_QSPGS_HASH_MAX];
    uint8_t key[GY_QSPGS_MASTER_KEY_MAX];
    uint8_t form;
    size_t mklen;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (ek == NULL || gid == NULL || m == NULL || m->mct == NULL || out == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);

    memset(out, 0, sizeof(*out));
    rc = gy_qspgs_member_ct_open(suite_id, aead_id, ek, gid, m->mct, m->mct_len,
                                 &form, out->uid, sizeof(out->uid),
                                 &out->uidlen, rc_open, key);
    if (rc != GY_OK)
        goto out;
    /* PRESENT: key is the member's uk. PENDING (an unaccepted invite): key is
     * the per-invite gk', not a user key, so leave uk zeroed and flag it. */
    if (form == GY_QSPGS_MEMBER_FORM_PRESENT)
        memcpy(out->uk, key, mklen);
    else
        out->pending = 1;

    /* The stored C_UID must open to (r_c, UID). */
    rc = gy_qspgs_cuid_commit(suite_id, out->uid, out->uidlen, rc_open,
                              computed);
    if (rc != GY_OK)
        goto out;
    if (gy_const_memcmp(computed, m->cuid, desc->hash_len) != 0) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    out->admn = m->admn;
    rc = GY_OK;

out:
    gy_secure_zero(rc_open, sizeof(rc_open));
    gy_secure_zero(computed, sizeof(computed));
    gy_secure_zero(key, sizeof(key));
    if (rc != GY_OK)
        gy_qspgs_member_view_clear(out);
    return rc;
}

void
gy_qspgs_member_view_clear(struct gy_qspgs_member_view *v)
{
    if (v == NULL)
        return;
    gy_secure_zero(v, sizeof(*v));
}

int
gy_qspgs_core_resolve_verify(const struct gy_qspgs_core *core,
                             uint32_t signer_index,
                             const uint8_t rrs[GY_QSPGS_RRS_BYTES],
                             const uint8_t *signer_vkb,
                             const uint8_t *signer_uid, size_t signer_uidlen,
                             const uint8_t *sig, size_t sig_len,
                             uint8_t *scratch, size_t scratch_cap)
{
    const struct gy_suite_desc *desc;
    uint8_t rho[GY_QSPGS_RHO_BYTES];
    uint8_t vkr[GY_QSPGS_VKR_MAX];
    int rc;

    if (core == NULL || rrs == NULL || signer_vkb == NULL ||
        signer_uid == NULL || sig == NULL || scratch == NULL)
        return GY_ERR_ARG;
    desc = gy_suite_desc(core->suite_id);
    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    if (core->vkhash == NULL || signer_index >= core->n_vk)
        return GY_ERR_ARG;

    rc = gy_qspgs_derive_rho(core->suite_id, rrs, signer_uid, signer_uidlen,
                             rho);
    if (rc == GY_OK)
        rc = gy_qspgs_derive_vk_psdn(core->suite_id, vkr, signer_vkb, rho);
    if (rc == GY_OK)
        rc = gy_qspgs_vkpsdn_hash_check(
            core->suite_id, vkr, core->vkhash + signer_index * desc->hash_len);
    if (rc == GY_OK)
        rc = gy_qspgs_core_verify(core, signer_index, vkr, sig, sig_len,
                                  scratch, scratch_cap);

    gy_secure_zero(rho, sizeof(rho));
    gy_secure_zero(vkr, sizeof(vkr));
    return rc;
}
