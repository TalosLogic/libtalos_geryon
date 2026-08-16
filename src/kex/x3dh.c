/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "x3dh.h"

/* Largest info string: "geryon.1." || suite_name || "." || purpose. */
#define GY_INFO_MAX 48

/* Largest EncodeEC output: curve_type byte + curve public key. */
#define GY_ENC_MAX (1 + GY_CURVE_PK_MAX)

/*
 * D-DR-13 expansion: SKdr / shared_hka / shared_nhkb = HKDF-Expand(SK, INFO)
 * for the three purposes, each GY_DR_SECRET_LEN bytes.  SK is treated as the
 * PRK (it is exactly hash_len bytes).
 */
static int
expand_one(const struct gy_suite_desc *desc, const uint8_t *sk,
           const char *purpose, uint8_t *out)
{
    uint8_t info[GY_INFO_MAX];
    size_t infolen;
    int rc;

    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, purpose);
    if (rc != GY_OK)
        return rc;
    return desc->hkdf_expand(out, GY_DR_SECRET_LEN, sk, info, infolen);
}

static int
expand_secrets(const struct gy_suite_desc *desc, const uint8_t *sk,
               struct gy_dr_secrets *out)
{
    int rc;

    rc = expand_one(desc, sk, "dr.sk", out->sk_dr);
    if (rc != GY_OK)
        return rc;
    rc = expand_one(desc, sk, "he.hka", out->shared_hka);
    if (rc != GY_OK)
        return rc;
    return expand_one(desc, sk, "he.nhkb", out->shared_nhkb);
}

/*
 * SK = HKDF(salt = zeros(hash_len), IKM = F || DH1 || DH2 || DH3 [|| DH4],
 * info = INFO("x3dh"), L = hash_len), then the D-DR-13 expansion into the
 * seed triple.
 * All secret intermediates are zeroized before returning.
 */
static int
derive_secrets(const struct gy_suite_desc *desc, const uint8_t dh[][GY_DH_MAX],
               size_t ndh, struct gy_dr_secrets *out)
{
    uint8_t f[GY_F_MAX];
    uint8_t salt[GY_HASH_MAX];
    uint8_t prk[GY_HASH_MAX];
    uint8_t sk[GY_HASH_MAX];
    uint8_t info[GY_INFO_MAX];
    struct gy_iov iov[1 + 4];
    size_t infolen, i;
    int rc;

    gy_suite_f(desc, f);
    memset(salt, 0, desc->hash_len);

    iov[0].p = f;
    iov[0].len = desc->f_len;
    for (i = 0; i < ndh; i++) {
        iov[i + 1].p = dh[i];
        iov[i + 1].len = desc->dh_len;
    }

    rc = desc->hkdf_extract(prk, salt, desc->hash_len, iov, 1 + ndh);
    if (rc != GY_OK)
        goto out;
    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, "x3dh");
    if (rc != GY_OK)
        goto out;
    rc = desc->hkdf_expand(sk, desc->hash_len, prk, info, infolen);
    if (rc != GY_OK)
        goto out;

    rc = expand_secrets(desc, sk, out);

out:
    gy_secure_zero(f, sizeof(f));
    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(sk, sizeof(sk));
    return rc;
}

/* AD = EncodeEC(IK_A) || EncodeEC(IK_B) (D-X3DH-6). */
static int
build_ad(const struct gy_public_key *ik_a, const struct gy_public_key *ik_b,
         uint8_t *out, size_t *outlen)
{
    int n1, n2;

    n1 = gy_encode_ec(out, GY_X3DH_AD_MAX, ik_a->curve_type, ik_a->pk);
    if (n1 < 0)
        return n1;
    n2 = gy_encode_ec(out + n1, GY_X3DH_AD_MAX - (size_t)n1, ik_b->curve_type,
                      ik_b->pk);
    if (n2 < 0)
        return n2;
    *outlen = (size_t)(n1 + n2);
    return GY_OK;
}

/* Serialize pkid_be32 || curve_type || curve_pk. */
static void
put_pubkey(uint8_t *o, const struct gy_public_key *k, size_t pk_len)
{
    gy_be32_put(o, k->pkid);
    o[4] = k->curve_type;
    memcpy(o + 5, k->pk, pk_len);
}

static void
parse_pubkey(struct gy_public_key *k, const uint8_t *in, size_t pk_len)
{
    memset(k, 0, sizeof(*k));
    k->pkid = gy_be32_get(in);
    k->curve_type = in[4];
    memcpy(k->pk, in + 5, pk_len);
}

/* Recompute the PKID over EncodeEC(k) and confirm it matches the carried one. */
static int
pkid_matches(const struct gy_suite_desc *desc, const struct gy_public_key *k)
{
    uint8_t enc[GY_ENC_MAX];
    uint32_t recomputed;
    int n;

    n = gy_encode_ec(enc, sizeof(enc), k->curve_type, k->pk);
    if (n < 0)
        return n;
    GY_KEX_COUNT(hash);
    if (gy_pkid(&recomputed, desc->suite_id, enc, (size_t)n) != GY_OK)
        return GY_ERR_ARG;
    return recomputed == k->pkid ? GY_OK : GY_ERR_VERIFY;
}

int
gy_x3dh_initiate(const struct gy_suite_desc *desc,
                 struct gy_dr_secrets *out_secrets, uint8_t *out_ad,
                 size_t *out_ad_len, uint8_t *out_prefix,
                 size_t *out_prefix_len, const struct gy_keypair *local_ik,
                 const struct gy_prekey_bundle *peer, struct gy_keypair *ek)
{
    uint8_t dh[4][GY_DH_MAX];
    size_t kw, o;
    int have_opk, ndh, rc;

    if (desc == NULL || out_secrets == NULL || out_ad == NULL ||
        out_ad_len == NULL || out_prefix == NULL || out_prefix_len == NULL ||
        local_ik == NULL || peer == NULL || ek == NULL)
        return GY_ERR_ARG;

    /* Validate the bundle before ANY private-key operation (D-X3DH-14). */
    rc = gy_bundle_validate(desc, peer);
    if (rc != GY_OK)
        return rc;

    have_opk = gy_pkid_is_present(peer->opk.pkid);
    ndh = have_opk ? 4 : 3;

    /* DH1=(IK_A,SPK_B), DH2=(EK,IK_B), DH3=(EK,SPK_B), DH4=(EK,OPK_B). */
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[0], local_ik->sk, peer->spk.pk);
    if (rc != GY_OK)
        goto out;
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[1], ek->sk, peer->ik.pk);
    if (rc != GY_OK)
        goto out;
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[2], ek->sk, peer->spk.pk);
    if (rc != GY_OK)
        goto out;
    if (have_opk) {
        GY_KEX_COUNT(dh);
        rc = desc->dh(dh[3], ek->sk, peer->opk.pk);
        if (rc != GY_OK)
            goto out;
    }

    rc = derive_secrets(desc, (const uint8_t(*)[GY_DH_MAX])dh, (size_t)ndh,
                        out_secrets);
    if (rc != GY_OK)
        goto out;

    rc = build_ad(&local_ik->pub, &peer->ik, out_ad, out_ad_len);
    if (rc != GY_OK)
        goto out;

    /* Prefix: version || suite || ik || ek || ik_id || spk_id || opk_id || 0. */
    kw = 4 + 1 + desc->curve_pk_len;
    o = 0;
    out_prefix[o++] = GY_WIRE_VERSION;
    out_prefix[o++] = desc->suite_id;
    put_pubkey(out_prefix + o, &local_ik->pub, desc->curve_pk_len);
    o += kw;
    put_pubkey(out_prefix + o, &ek->pub, desc->curve_pk_len);
    o += kw;
    gy_be32_put(out_prefix + o, peer->ik.pkid);
    o += 4;
    gy_be32_put(out_prefix + o, peer->spk.pkid);
    o += 4;
    gy_be32_put(out_prefix + o, have_opk ? peer->opk.pkid : 0);
    o += 4;
    gy_be32_put(out_prefix + o, 0); /* ciphertext_len placeholder */
    o += 4;
    *out_prefix_len = o;

out:
    /* D-X3DH-13 deletion points: EK private and all DH outputs, both paths. */
    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(ek->sk, sizeof(ek->sk));
    if (rc != GY_OK)
        gy_secure_zero(out_secrets, sizeof(*out_secrets));
    return rc;
}

/* Find the OPK pair whose PKID matches, or NULL. */
static const struct gy_keypair *
find_opk(const struct gy_x3dh_local *local, uint32_t opk_id)
{
    size_t i;

    for (i = 0; i < local->n_opks; i++) {
        if (local->opks[i].pub.pkid == opk_id)
            return &local->opks[i];
    }
    return NULL;
}

int
gy_x3dh_respond(const struct gy_suite_desc *desc,
                struct gy_dr_secrets *out_secrets, uint8_t *out_ad,
                size_t *out_ad_len, struct gy_x3dh_opk_ref *out_opk_ref,
                const struct gy_x3dh_local *local, const uint8_t *msg,
                size_t msg_len)
{
    struct gy_public_key ik, ek;
    const struct gy_keypair *opk;
    uint8_t dh[4][GY_DH_MAX];
    uint32_t ik_id, spk_id, opk_id;
    size_t kw, prefix_len, o;
    int have_opk, ndh, rc;

    if (desc == NULL || out_secrets == NULL || out_ad == NULL ||
        out_ad_len == NULL || out_opk_ref == NULL || local == NULL ||
        local->ik == NULL || local->spk == NULL || msg == NULL)
        return GY_ERR_ARG;

    /* Frame (version/suite) before any crypto (D-GEN-1). */
    rc = gy_frame_check(msg, msg_len, desc->suite_id);
    if (rc != GY_OK)
        return rc;

    kw = 4 + 1 + desc->curve_pk_len;
    prefix_len = 2 + 2 * kw + 16;
    if (msg_len < prefix_len)
        return GY_ERR_ARG;

    o = 2;
    parse_pubkey(&ik, msg + o, desc->curve_pk_len);
    o += kw;
    parse_pubkey(&ek, msg + o, desc->curve_pk_len);
    o += kw;
    ik_id = gy_be32_get(msg + o);
    o += 4;
    spk_id = gy_be32_get(msg + o);
    o += 4;
    opk_id = gy_be32_get(msg + o);

    /* Cross-suite curve_type check. */
    if (ik.curve_type != desc->curve_type || ek.curve_type != desc->curve_type)
        return GY_ERR_STATE;

    /* Embedded PKIDs are never trusted: recompute and abort on mismatch. */
    rc = pkid_matches(desc, &ik);
    if (rc != GY_OK)
        return rc;
    rc = pkid_matches(desc, &ek);
    if (rc != GY_OK)
        return rc;

    /* Stale-identity fast fail: ik_id must be our current identity PKID. */
    if (ik_id != local->ik->pub.pkid)
        return GY_ERR_STATE;

    /* Select the SPK by PKID; unknown SPK is the generic handshake error. */
    if (spk_id != local->spk->pub.pkid)
        return GY_ERR_VERIFY;

    have_opk = gy_pkid_is_present(opk_id);
    opk = NULL;
    if (have_opk) {
        opk = find_opk(local, opk_id);
        if (opk == NULL)
            return GY_ERR_VERIFY;
    }
    ndh = have_opk ? 4 : 3;

    /* Mirror the DHs on Bob's private keys. */
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[0], local->spk->sk, ik.pk);
    if (rc != GY_OK)
        goto out;
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[1], local->ik->sk, ek.pk);
    if (rc != GY_OK)
        goto out;
    GY_KEX_COUNT(dh);
    rc = desc->dh(dh[2], local->spk->sk, ek.pk);
    if (rc != GY_OK)
        goto out;
    if (have_opk) {
        GY_KEX_COUNT(dh);
        rc = desc->dh(dh[3], opk->sk, ek.pk);
        if (rc != GY_OK)
            goto out;
    }

    rc = derive_secrets(desc, (const uint8_t(*)[GY_DH_MAX])dh, (size_t)ndh,
                        out_secrets);
    if (rc != GY_OK)
        goto out;

    rc = build_ad(&ik, &local->ik->pub, out_ad, out_ad_len);
    if (rc != GY_OK)
        goto out;

    out_opk_ref->present = (uint8_t)have_opk;
    out_opk_ref->pkid = have_opk ? opk_id : 0;

out:
    gy_secure_zero(dh, sizeof(dh));
    if (rc != GY_OK)
        gy_secure_zero(out_secrets, sizeof(*out_secrets));
    return rc;
}

#ifdef GY_TEST_HOOKS
int
gy_x3dh_expand_secrets(const struct gy_suite_desc *desc, const uint8_t *sk,
                       struct gy_dr_secrets *out)
{
    if (desc == NULL || sk == NULL || out == NULL)
        return GY_ERR_ARG;
    return expand_secrets(desc, sk, out);
}
#endif
