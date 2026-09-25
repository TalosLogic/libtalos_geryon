/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_field.h"

#include "qspgs_keys.h" /* gy_qspgs_master_key_len */
#include "qspgs_labels.h"

#include "aead.h"
#include "encode.h" /* gy_info */
#include "error.h"
#include "rng.h" /* gy_random_bytes */
#include "suite.h"
#include "util.h"

/*
 * The ek-encrypted field layer.  These are the
 * AEAD-internal plaintext layouts the wire grammar deferred; they freeze
 * here.  No
 * arithmetic lives in this file: one AEAD seal / open per field, keyed by the
 * group key ek, domain-separated by a field-kind tag and the GID.
 */

/*
 * Group-approved AEADs (SEC-v1.5.0 INFO-6): the admin pins one at Create and it
 * is immutable for the group's life (carried in the signed header aead_id byte,
 * enforced by gy_qspgs_server_core_check).  Only ChaCha20-Poly1305 (the MTI
 * default) and AEGIS-256 are allowed: both are always available on every build
 * (libsodium does not hardware-gate either), so the choice never fragments
 * membership.  AES-256-GCM is deliberately excluded, being hardware-gated. */
int
gy_qspgs_group_aead_ok(uint8_t aead_id)
{
    return aead_id == GY_AEAD_CHACHA20POLY1305 || aead_id == GY_AEAD_AEGIS256;
}

/* Longest gy_info domain: "geryon.1." (9) + "geryon_h448_1024" (16) + "." (1)
 * + "qspgs-field" (11) = 37; rounded up. */
#define QSPGS_FIELD_DOMAIN_MAX 48

/* Associated data: domain || field_tag(1) || GID. */
#define QSPGS_FIELD_AAD_MAX (QSPGS_FIELD_DOMAIN_MAX + 1 + GY_QSPGS_GID_LEN)

static int
field_tag_ok(uint8_t t)
{
    return t == GY_QSPGS_FIELD_MEMBER || t == GY_QSPGS_FIELD_HEADER ||
           t == GY_QSPGS_FIELD_ATTR || t == GY_QSPGS_FIELD_UK ||
           t == GY_QSPGS_FIELD_JOINSLOT;
}

/*
 * Build the associated data for (suite, field_tag, gid) into aad, returning its
 * length via *aadlen, and validate the suite is an enabled hybrid.
 */
static int
field_aad(uint8_t suite_id, uint8_t field_tag,
          const uint8_t gid[GY_QSPGS_GID_LEN], uint8_t aad[QSPGS_FIELD_AAD_MAX],
          size_t *aadlen)
{
    size_t dlen;
    int rc;

    if (gy_qspgs_master_key_len(suite_id) == 0)
        return GY_ERR_ARG;
    if (!field_tag_ok(field_tag))
        return GY_ERR_ARG;

    rc = gy_info(aad, QSPGS_FIELD_DOMAIN_MAX, &dlen, suite_id,
                 GY_QSPGS_LBL_FIELD);
    if (rc != GY_OK)
        return rc;
    aad[dlen] = field_tag;
    memcpy(aad + dlen + 1, gid, GY_QSPGS_GID_LEN);
    *aadlen = dlen + 1 + GY_QSPGS_GID_LEN;
    return GY_OK;
}

size_t
gy_qspgs_field_overhead(uint8_t aead_id)
{
    if (!gy_qspgs_group_aead_ok(aead_id))
        return 0;
    return gy_aead_nonce_len(aead_id) + gy_aead_tag_len(aead_id);
}

int
gy_qspgs_field_seal(uint8_t suite_id, uint8_t aead_id,
                    const uint8_t ek[GY_QSPGS_EK_BYTES], uint8_t field_tag,
                    const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *pt,
                    size_t ptlen, uint8_t *out, size_t cap, size_t *outlen)
{
    uint8_t aad[QSPGS_FIELD_AAD_MAX];
    size_t aadlen, nlen, ctcap, ctlen;
    int rc;

    if (ek == NULL || gid == NULL || pt == NULL || out == NULL ||
        outlen == NULL)
        return GY_ERR_ARG;
    if (!gy_qspgs_group_aead_ok(aead_id))
        return GY_ERR_ARG;
    rc = field_aad(suite_id, field_tag, gid, aad, &aadlen);
    if (rc != GY_OK)
        return rc;

    nlen = gy_aead_nonce_len(aead_id);
    if (cap < nlen + ptlen + gy_aead_tag_len(aead_id))
        return GY_ERR_TOOLONG;

    /* Fresh random nonce prepended (ek is a long-lived group key). */
    rc = gy_random_bytes(out, nlen);
    if (rc != GY_OK)
        return rc;

    ctcap = cap - nlen;
    ctlen = ctcap;
    rc = gy_aead_encrypt(aead_id, out + nlen, &ctlen, ek, out, nlen, aad,
                         aadlen, pt, ptlen);
    if (rc == GY_OK)
        *outlen = nlen + ctlen;
    return rc;
}

int
gy_qspgs_field_open(uint8_t suite_id, uint8_t aead_id,
                    const uint8_t ek[GY_QSPGS_EK_BYTES], uint8_t field_tag,
                    const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *in,
                    size_t inlen, uint8_t *pt, size_t cap, size_t *ptlen)
{
    uint8_t aad[QSPGS_FIELD_AAD_MAX];
    size_t aadlen, nlen, ptcap;
    int rc;

    if (ek == NULL || gid == NULL || in == NULL || pt == NULL || ptlen == NULL)
        return GY_ERR_ARG;
    if (!gy_qspgs_group_aead_ok(aead_id))
        return GY_ERR_ARG;
    rc = field_aad(suite_id, field_tag, gid, aad, &aadlen);
    if (rc != GY_OK)
        return rc;

    nlen = gy_aead_nonce_len(aead_id);
    if (inlen < nlen + gy_aead_tag_len(aead_id))
        return GY_ERR_TOOLONG;

    ptcap = cap;
    rc = gy_aead_decrypt(aead_id, pt, &ptcap, ek, in, nlen, aad, aadlen,
                         in + nlen, inlen - nlen);
    if (rc == GY_OK)
        *ptlen = ptcap;
    return rc;
}

/* Shared body for the two member-tuple forms; key is uk (PRESENT) or gk'
 * (PENDING). */
static int
member_ct_seal_form(uint8_t suite_id, uint8_t aead_id,
                    const uint8_t ek[GY_QSPGS_EK_BYTES],
                    const uint8_t gid[GY_QSPGS_GID_LEN], uint8_t form,
                    const uint8_t *uid, size_t uidlen,
                    const uint8_t rc_open[GY_QSPGS_RC_LEN], const uint8_t *key,
                    uint8_t *out, size_t cap, size_t *outlen)
{
    uint8_t pt[GY_QSPGS_MEMBER_PT_MAX];
    size_t mklen, ptlen;
    int rc;

    if (uid == NULL || rc_open == NULL || key == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;
    if (uidlen != GY_QSPGS_UID_LEN)
        return GY_ERR_ARG;

    /* pt = form(1) || uidlen(1) || UID || r_c(32) || key(mklen). */
    pt[0] = form;
    pt[1] = (uint8_t)uidlen;
    memcpy(pt + 2, uid, uidlen);
    memcpy(pt + 2 + uidlen, rc_open, GY_QSPGS_RC_LEN);
    memcpy(pt + 2 + uidlen + GY_QSPGS_RC_LEN, key, mklen);
    ptlen = 2 + uidlen + GY_QSPGS_RC_LEN + mklen;

    rc = gy_qspgs_field_seal(suite_id, aead_id, ek, GY_QSPGS_FIELD_MEMBER, gid,
                             pt, ptlen, out, cap, outlen);
    gy_secure_zero(pt, sizeof(pt));
    return rc;
}

int
gy_qspgs_member_ct_seal(uint8_t suite_id, uint8_t aead_id,
                        const uint8_t ek[GY_QSPGS_EK_BYTES],
                        const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *uid,
                        size_t uidlen, const uint8_t rc_open[GY_QSPGS_RC_LEN],
                        const uint8_t *uk, uint8_t *out, size_t cap,
                        size_t *outlen)
{
    return member_ct_seal_form(suite_id, aead_id, ek, gid,
                               GY_QSPGS_MEMBER_FORM_PRESENT, uid, uidlen,
                               rc_open, uk, out, cap, outlen);
}

int
gy_qspgs_member_ct_seal_pending(uint8_t suite_id, uint8_t aead_id,
                                const uint8_t ek[GY_QSPGS_EK_BYTES],
                                const uint8_t gid[GY_QSPGS_GID_LEN],
                                const uint8_t *uid, size_t uidlen,
                                const uint8_t rc_open[GY_QSPGS_RC_LEN],
                                const uint8_t *gk_prime, uint8_t *out,
                                size_t cap, size_t *outlen)
{
    return member_ct_seal_form(suite_id, aead_id, ek, gid,
                               GY_QSPGS_MEMBER_FORM_PENDING, uid, uidlen,
                               rc_open, gk_prime, out, cap, outlen);
}

int
gy_qspgs_member_ct_open(uint8_t suite_id, uint8_t aead_id,
                        const uint8_t ek[GY_QSPGS_EK_BYTES],
                        const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *in,
                        size_t inlen, uint8_t *form_out, uint8_t *uid,
                        size_t uid_cap, size_t *uidlen,
                        uint8_t rc_open[GY_QSPGS_RC_LEN], uint8_t *key)
{
    uint8_t pt[GY_QSPGS_MEMBER_PT_MAX];
    size_t mklen, ptlen, ul;
    uint8_t form;
    int rc;

    if (form_out == NULL || uid == NULL || uidlen == NULL || rc_open == NULL ||
        key == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    ptlen = 0;
    rc = gy_qspgs_field_open(suite_id, aead_id, ek, GY_QSPGS_FIELD_MEMBER, gid,
                             in, inlen, pt, sizeof(pt), &ptlen);
    if (rc != GY_OK)
        goto out;

    /* Parse form(1) || uidlen(1) || UID || r_c(32) || key(mklen); reject a
     * malformed one. */
    if (ptlen < 2) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    form = pt[0];
    if (form != GY_QSPGS_MEMBER_FORM_PRESENT &&
        form != GY_QSPGS_MEMBER_FORM_PENDING) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    ul = pt[1];
    if (ul != GY_QSPGS_UID_LEN || ptlen != 2 + ul + GY_QSPGS_RC_LEN + mklen) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    if (ul > uid_cap) {
        rc = GY_ERR_TOOLONG;
        goto out;
    }
    memcpy(uid, pt + 2, ul);
    memcpy(rc_open, pt + 2 + ul, GY_QSPGS_RC_LEN);
    memcpy(key, pt + 2 + ul + GY_QSPGS_RC_LEN, mklen);
    *uidlen = ul;
    *form_out = form;
    rc = GY_OK;

out:
    gy_secure_zero(pt, sizeof(pt));
    return rc;
}

/* ---- join slot (section 4 item 1) --------------------------------------- */

/* Join-slot plaintext: gk(2*kappa) || fet(32). */
#define QSPGS_JOINSLOT_PT_MAX (GY_QSPGS_MASTER_KEY_MAX + GY_QSPGS_FET_LEN)

/*
 * Derive the join-link key jlk = HKDF(jls): PRK = Extract(salt = domain,
 * jls); jlk = Expand(PRK, domain, 32).  domain = gy_info(suite, "qspgs-joinlink").
 */
static int
joinlink_key(uint8_t suite_id, const uint8_t jls[GY_QSPGS_JOINLINK_SECRET],
             uint8_t jlk[GY_AEAD_KEY_LEN])
{
    const struct gy_suite_desc *desc = gy_suite_desc(suite_id);
    uint8_t domain[QSPGS_FIELD_DOMAIN_MAX];
    uint8_t prk[GY_HASH_MAX];
    struct gy_iov ikm;
    size_t dlen;
    int rc;

    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;
    rc =
        gy_info(domain, sizeof(domain), &dlen, suite_id, GY_QSPGS_LBL_JOINLINK);
    if (rc != GY_OK)
        return rc;

    ikm.p = jls;
    ikm.len = GY_QSPGS_JOINLINK_SECRET;
    rc = desc->hkdf_extract(prk, domain, dlen, &ikm, 1);
    if (rc == GY_OK)
        rc = desc->hkdf_expand(jlk, GY_AEAD_KEY_LEN, prk, domain, dlen);

    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(domain, sizeof(domain));
    return rc;
}

int
gy_qspgs_joinlink_seal(uint8_t suite_id, uint8_t aead_id,
                       const uint8_t jls[GY_QSPGS_JOINLINK_SECRET],
                       const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *gk,
                       const uint8_t fet[GY_QSPGS_FET_LEN], uint8_t *out,
                       size_t cap, size_t *outlen)
{
    uint8_t jlk[GY_AEAD_KEY_LEN];
    uint8_t pt[QSPGS_JOINSLOT_PT_MAX];
    size_t mklen;
    int rc;

    if (jls == NULL || gid == NULL || gk == NULL || fet == NULL ||
        out == NULL || outlen == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    rc = joinlink_key(suite_id, jls, jlk);
    if (rc != GY_OK)
        return rc;

    memcpy(pt, gk, mklen);
    memcpy(pt + mklen, fet, GY_QSPGS_FET_LEN);
    rc = gy_qspgs_field_seal(suite_id, aead_id, jlk, GY_QSPGS_FIELD_JOINSLOT,
                             gid, pt, mklen + GY_QSPGS_FET_LEN, out, cap,
                             outlen);

    gy_secure_zero(jlk, sizeof(jlk));
    gy_secure_zero(pt, sizeof(pt));
    return rc;
}

int
gy_qspgs_joinlink_open(uint8_t suite_id, uint8_t aead_id,
                       const uint8_t jls[GY_QSPGS_JOINLINK_SECRET],
                       const uint8_t gid[GY_QSPGS_GID_LEN], const uint8_t *in,
                       size_t inlen, uint8_t *gk_out,
                       uint8_t fet_out[GY_QSPGS_FET_LEN])
{
    uint8_t jlk[GY_AEAD_KEY_LEN];
    uint8_t pt[QSPGS_JOINSLOT_PT_MAX];
    size_t mklen, ptlen;
    int rc;

    if (jls == NULL || gid == NULL || in == NULL || gk_out == NULL ||
        fet_out == NULL)
        return GY_ERR_ARG;
    mklen = gy_qspgs_master_key_len(suite_id);
    if (mklen == 0)
        return GY_ERR_ARG;

    rc = joinlink_key(suite_id, jls, jlk);
    if (rc != GY_OK)
        return rc;

    ptlen = 0;
    rc = gy_qspgs_field_open(suite_id, aead_id, jlk, GY_QSPGS_FIELD_JOINSLOT,
                             gid, in, inlen, pt, sizeof(pt), &ptlen);
    if (rc == GY_OK && ptlen != mklen + GY_QSPGS_FET_LEN)
        rc = GY_ERR_VERIFY;
    if (rc == GY_OK) {
        memcpy(gk_out, pt, mklen);
        memcpy(fet_out, pt + mklen, GY_QSPGS_FET_LEN);
    }

    gy_secure_zero(jlk, sizeof(jlk));
    gy_secure_zero(pt, sizeof(pt));
    return rc;
}
