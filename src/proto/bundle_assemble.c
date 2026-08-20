/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gy_bundle_assemble: server-side bundle assembly, a FREE
 * function like gy_appkey_verify - no gy_custodian, so a
 * server target links this translation unit (plus envelope.o and the
 * session/kex/core libraries it needs for suite lookup and wire structure)
 * WITHOUT pulling in custodian.o, since nothing here references any
 * gy_custodian_* symbol.  This file intentionally does NOT include
 * custodian.h.  It combines a client's published registration (IK + signed
 * SPK, gy_custodian_publish_registration) with one OPK public key (sliced
 * from a gy_custodian_publish_opk_batch batch) into the bundle gy_initiate
 * consumes (CUSTODY_SPEC section 9).  Pure repackaging: the fetcher's
 * gy_initiate re-validates the assembled bundle (D-X3DH-14), so this need
 * not re-verify the registration's signature.
 */

#include <string.h>

#include "geryon.h"

#include "envelope.h"
#include "facade.h"

/* ---- local endian helper (no core/ dependency, matching envelope.c) ---- */

static uint32_t
get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int
gy_bundle_assemble(const uint8_t *registration, size_t reg_len,
                   const uint8_t *opk_pub, size_t opk_len, uint8_t *out,
                   size_t *out_len)
{
    const struct gy_suite_desc *desc;
    struct gy_prekey_bundle b;
    size_t kw;
    int rc;

    if (registration == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (reg_len < 2)
        return GY_ERR_ARG;

    desc = gy_suite_lookup(registration[1]);
    if (desc == NULL)
        return GY_ERR_ARG;

    /*
     * Hybrid suites carry a paired ECDH+ML-KEM OPK (hpub section 4.1), so the
     * parse, the OPK width, and the emit all use the hybrid codecs.  The
     * assembled bundle is byte-identical to a full hybrid registration with
     * its OPK slot filled in; gy_initiate re-validates it.  The OPK-slice
     * parse mirrors the classical branch below, adding only the mlkem_ek field
     * that hpub appends after the curve public key.
     */
    if (desc->is_hybrid) {
        struct gy_hybrid_prekey_bundle hb;

        rc = gy_hybrid_bundle_parse(&hb, desc, registration, reg_len);
        if (rc != GY_OK)
            return rc;
        if (hb.opk.curve.pkid != 0)
            return GY_ERR_ARG; /* already carries an OPK: not a registration */

        if (opk_pub != NULL) {
            kw = 4 + 1 + desc->curve_pk_len + desc->kem_pk_len;
            if (opk_len != kw)
                return GY_ERR_ARG;
            hb.opk.curve.pkid = get_be32(opk_pub);
            if (hb.opk.curve.pkid == 0)
                return GY_ERR_ARG; /* the absent sentinel is not a real PKID */
            hb.opk.curve.curve_type = opk_pub[4];
            memcpy(hb.opk.curve.pk, opk_pub + 5, desc->curve_pk_len);
            memcpy(hb.opk.mlkem_ek, opk_pub + 5 + desc->curve_pk_len,
                   desc->kem_pk_len);
        }

        if (out == NULL) {
            *out_len = gy_hybrid_bundle_wire_len(desc);
            return GY_OK;
        }
        return gy_hybrid_bundle_put(out, *out_len, out_len, desc, &hb);
    }

    rc = gy_bundle_parse(&b, desc, registration, reg_len);
    if (rc != GY_OK)
        return rc;
    if (b.opk.pkid != 0)
        return GY_ERR_ARG; /* not a registration: it already carries an OPK */

    if (opk_pub != NULL) {
        kw = 4 + 1 + desc->curve_pk_len;
        if (opk_len != kw)
            return GY_ERR_ARG;
        b.opk.pkid = get_be32(opk_pub);
        if (b.opk.pkid == 0)
            return GY_ERR_ARG; /* the absent sentinel is not a real PKID */
        b.opk.curve_type = opk_pub[4];
        memcpy(b.opk.pk, opk_pub + 5, desc->curve_pk_len);
    }

    if (out == NULL) {
        *out_len = gy_bundle_wire_len(desc, opk_pub != NULL);
        return GY_OK;
    }
    return gy_bundle_put(out, *out_len, out_len, desc, &b);
}

int
gy_registration_identity_pub(const uint8_t *registration, size_t reg_len,
                             const uint8_t **ik_pub, size_t *ik_len)
{
    const struct gy_suite_desc *desc;
    struct gy_prekey_bundle b;
    struct gy_hybrid_prekey_bundle hb;
    int rc;

    if (registration == NULL || ik_pub == NULL || ik_len == NULL)
        return GY_ERR_ARG;
    if (reg_len < 2)
        return GY_ERR_ARG;

    desc = gy_suite_lookup(registration[1]);
    if (desc == NULL)
        return GY_ERR_ARG;

    /*
     * Hybrid returns the FULL identity encoding (curve_type || curve_pk ||
     * mlkem_ek || mldsa_pk), the bytes gy_appkey_verify needs to check both the
     * XEdDSA and the ML-DSA cert signatures (and the same bytes
     * gy_hybrid_identity_fingerprint hashes, section 4.2).  On the wire the IK
     * is pkid(4) || curve_type(1) || curve_pk || mlkem_ek || mldsa_pk, so the
     * encoding is the contiguous slice just past version(1) || suite(1) ||
     * pkid(4).  Parse first to reject a malformed/short buffer.
     */
    if (desc->is_hybrid) {
        rc = gy_hybrid_bundle_parse(&hb, desc, registration, reg_len);
        if (rc != GY_OK)
            return rc;
        *ik_pub = registration + 2 + 4;
        *ik_len = 1 + desc->curve_pk_len + desc->kem_pk_len + desc->dsa_pk_len;
        return GY_OK;
    }

    /* Parse to validate structure (and reject a malformed/short buffer)
     * before handing back an in-place slice. */
    rc = gy_bundle_parse(&b, desc, registration, reg_len);
    if (rc != GY_OK)
        return rc;

    /* Zero-copy slice: the IK's raw public key bytes sit at a fixed wire
     * offset, version(1) || suite(1) || pkid(4) || curve_type(1) || pk,
     * valid while registration stays alive. */
    *ik_pub = registration + 2 + 4 + 1;
    *ik_len = desc->curve_pk_len;
    return GY_OK;
}

int
gy_bundle_fingerprint(const uint8_t *bundle, size_t bundle_len, uint8_t *out,
                      size_t *out_len)
{
    const struct gy_suite_desc *desc;
    struct gy_prekey_bundle b;
    struct gy_hybrid_prekey_bundle hb;
    int rc;

    if (bundle == NULL || out_len == NULL)
        return GY_ERR_ARG;
    if (bundle_len < 2)
        return GY_ERR_ARG;

    desc = gy_suite_lookup(bundle[1]);
    if (desc == NULL)
        return GY_ERR_ARG;

    /* Parse to validate structure (and reject a malformed/short buffer)
     * before touching the identity key; a published registration and an
     * assembled bundle share the same wire prefix, so either is accepted.  A
     * hybrid registration is bundle-shaped (section 4.1), so the hybrid
     * analogue parses it. */
    if (desc->is_hybrid)
        rc = gy_hybrid_bundle_parse(&hb, desc, bundle, bundle_len);
    else
        rc = gy_bundle_parse(&b, desc, bundle, bundle_len);
    if (rc != GY_OK)
        return rc;

    if (out == NULL) {
        *out_len = desc->hash_len;
        return GY_OK;
    }
    if (*out_len < desc->hash_len)
        return GY_ERR_ARG;
    *out_len = desc->hash_len;

    /* Byte-identical to the peer's own gy_self_fingerprint and to
     * gy_keychange.new_fp for this identity: all fingerprint the IK through the
     * same suite primitive.  Hybrid hashes the complete identity
     * (curve || mlkem_ek || mldsa_pk, section 4.2), matching the hybrid
     * gy_self_fingerprint so the safety-number cross-check holds. */
    if (desc->is_hybrid)
        return gy_hybrid_identity_fingerprint(desc, out, &hb.ik);
    return gy_proto_fingerprint(desc, out, &b.ik);
}

/*
 * Validate a published OPK batch header (gy_custodian_publish_opk_batch):
 * version || suite_id || count_be16 || count keys, each key kw bytes.  The
 * header is identical across suites; only the per-key width differs: a
 * classical key is pkid_be32 || curve_type || curve_pk, and a hybrid key
 * (hpub section 4.1) appends the ML-KEM ek.  Fills *desc, *kw, *count on
 * success; a structurally malformed batch is GY_ERR_ARG.
 */
static int
opk_batch_dims(const uint8_t *batch, size_t batch_len,
               const struct gy_suite_desc **desc, size_t *kw, size_t *count)
{
    const struct gy_suite_desc *d;
    size_t keyw, n;

    if (batch == NULL || batch_len < 4)
        return GY_ERR_ARG;
    if (batch[0] != GY_PROTOCOL_VERSION)
        return GY_ERR_ARG;
    d = gy_suite_lookup(batch[1]);
    if (d == NULL)
        return GY_ERR_ARG;
    keyw = 4 + 1 + d->curve_pk_len;
    if (d->is_hybrid)
        keyw += d->kem_pk_len;
    n = ((size_t)batch[2] << 8) | (size_t)batch[3];
    if (batch_len != 4 + n * keyw)
        return GY_ERR_ARG;

    *desc = d;
    *kw = keyw;
    *count = n;
    return GY_OK;
}

int
gy_opk_batch_count(const uint8_t *batch, size_t batch_len, size_t *count)
{
    const struct gy_suite_desc *desc;
    size_t kw, n;
    int rc;

    if (count == NULL)
        return GY_ERR_ARG;
    rc = opk_batch_dims(batch, batch_len, &desc, &kw, &n);
    if (rc != GY_OK)
        return rc;
    *count = n;
    return GY_OK;
}

int
gy_opk_batch_get(const uint8_t *batch, size_t batch_len, size_t index,
                 const uint8_t **opk_pub, size_t *opk_len)
{
    const struct gy_suite_desc *desc;
    size_t kw, n;
    int rc;

    if (opk_pub == NULL || opk_len == NULL)
        return GY_ERR_ARG;
    rc = opk_batch_dims(batch, batch_len, &desc, &kw, &n);
    if (rc != GY_OK)
        return rc;
    if (index >= n)
        return GY_ERR_NOT_FOUND;

    /* Zero-copy slice into batch: the exact kw-byte key form
     * gy_bundle_assemble's opk_pub argument consumes, valid while batch
     * stays alive.  The leading 4 bytes are the PKID (big-endian), so a
     * directory can track which OPK it has handed out. */
    *opk_pub = batch + 4 + index * kw;
    *opk_len = kw;
    return GY_OK;
}
