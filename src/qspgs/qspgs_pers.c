/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "qspgs_pers.h"

#include "qspgs_labels.h"

#include "encode.h" /* gy_info */
#include "error.h"
#include "suite.h" /* gy_suite_desc */
#include "util.h"

/*
 * The skpers dual-scheme sign/verify.  Both halves go through the
 * suite descriptor (desc->sign / desc->verify for XEdDSA, desc->dsa_sign /
 * desc->dsa_verify for ML-DSA), exactly as the custodian's hybrid SAK cert path
 * does, so QSPGS reaches no core primitive directly.
 */

/* Longest gy_info domain for a ctx purpose ("qspgs-invaccept", 15): 41; up. */
#define QSPGS_PERS_INFO_MAX 48
#define QSPGS_PERS_SIGNED_MAX (QSPGS_PERS_INFO_MAX + GY_QSPGS_PERS_OBJ_MAX)

/* The two frozen context labels are the only accepted purposes. */
static int
pers_ctx_ok(const char *ctx_purpose)
{
    return ctx_purpose != NULL &&
           (strcmp(ctx_purpose, GY_QSPGS_CTX_REGUSER) == 0 ||
            strcmp(ctx_purpose, GY_QSPGS_CTX_INVACCEPT) == 0);
}

/*
 * Resolve to a hybrid descriptor and build the context info string.  Returns
 * GY_ERR_ARG for a non-hybrid suite or an unknown purpose.
 */
static int
pers_prepare(uint8_t suite_id, const char *ctx_purpose,
             const struct gy_suite_desc **descp,
             uint8_t info[QSPGS_PERS_INFO_MAX], size_t *infolen)
{
    const struct gy_suite_desc *desc;

    if (!pers_ctx_ok(ctx_purpose))
        return GY_ERR_ARG;
    desc = gy_suite_desc(suite_id);
    if (desc == NULL || !desc->is_hybrid)
        return GY_ERR_ARG;

    *descp = desc;
    return gy_info(info, QSPGS_PERS_INFO_MAX, infolen, suite_id, ctx_purpose);
}

int
gy_qspgs_pers_sign(uint8_t suite_id, const uint8_t *curve_sk,
                   const uint8_t *mldsa_sk, const char *ctx_purpose,
                   const uint8_t *obj, size_t objlen, uint8_t *ed_sig,
                   uint8_t *mldsa_sig)
{
    const struct gy_suite_desc *desc;
    uint8_t info[QSPGS_PERS_INFO_MAX];
    uint8_t signed_data[QSPGS_PERS_SIGNED_MAX];
    size_t infolen;
    int rc;

    if (curve_sk == NULL || mldsa_sk == NULL || obj == NULL || ed_sig == NULL ||
        mldsa_sig == NULL)
        return GY_ERR_ARG;
    if (objlen > GY_QSPGS_PERS_OBJ_MAX)
        return GY_ERR_TOOLONG;
    rc = pers_prepare(suite_id, ctx_purpose, &desc, info, &infolen);
    if (rc != GY_OK)
        return rc;

    /* XEdDSA half: sign info || obj (prepended-info domain separation). */
    memcpy(signed_data, info, infolen);
    memcpy(signed_data + infolen, obj, objlen);
    rc = desc->sign(ed_sig, curve_sk, signed_data, infolen + objlen);
    if (rc != GY_OK)
        goto out;

    /* ML-DSA half: sign obj with FIPS 204 ctx = info. */
    rc = desc->dsa_sign(mldsa_sig, mldsa_sk, obj, objlen, info, infolen);

out:
    gy_secure_zero(signed_data, sizeof(signed_data));
    gy_secure_zero(info, sizeof(info));
    return rc;
}

int
gy_qspgs_pers_verify(uint8_t suite_id, const uint8_t *curve_pk,
                     const uint8_t *mldsa_pk, const char *ctx_purpose,
                     const uint8_t *obj, size_t objlen, const uint8_t *ed_sig,
                     const uint8_t *mldsa_sig)
{
    const struct gy_suite_desc *desc;
    uint8_t info[QSPGS_PERS_INFO_MAX];
    uint8_t signed_data[QSPGS_PERS_SIGNED_MAX];
    size_t infolen;
    int rc;

    if (curve_pk == NULL || mldsa_pk == NULL || obj == NULL || ed_sig == NULL ||
        mldsa_sig == NULL)
        return GY_ERR_ARG;
    if (objlen > GY_QSPGS_PERS_OBJ_MAX)
        return GY_ERR_TOOLONG;
    rc = pers_prepare(suite_id, ctx_purpose, &desc, info, &infolen);
    if (rc != GY_OK)
        return rc;

    /* Both must verify; there is no single-signature accept path. */
    memcpy(signed_data, info, infolen);
    memcpy(signed_data + infolen, obj, objlen);
    if (desc->verify(ed_sig, curve_pk, signed_data, infolen + objlen) !=
        GY_OK) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    if (desc->dsa_verify(mldsa_sig, mldsa_pk, obj, objlen, info, infolen) !=
        GY_OK) {
        rc = GY_ERR_VERIFY;
        goto out;
    }
    rc = GY_OK;

out:
    gy_secure_zero(signed_data, sizeof(signed_data));
    gy_secure_zero(info, sizeof(info));
    return rc;
}
