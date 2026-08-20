/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <oqs/oqs.h>

#include "error.h"
#include "mldsa.h"
#include "util.h"

/*
 * The direct OQS_SIG_ml_dsa_44_* entry points are stateless and take no OQS_SIG
 * object, so there is no allocation.  Only the *_with_ctx_str variants are used
 * (D-PQ-1); the bare sign/verify entry points are never called.  The
 * rejection-loop iteration count is the sole permitted timing variation
 * (FIPS 204), handled inside the backend; liboqs validates its own
 * constant-timeness, so geryon does not re-time ML-DSA (docs/decisions/pq.md
 * D-PQ-4).  These wrappers branch only on public quantities (the OQS return
 * code, the fixed signature length, and context/argument checks), never on the
 * secret signing key.
 */

int
gy_mldsa_keypair(uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL)
        return GY_ERR_ARG;

    if (OQS_SIG_ml_dsa_44_keypair(pk, sk) != OQS_SUCCESS) {
        gy_secure_zero(sk, GY_MLDSA44_SK);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mldsa_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg, size_t mlen,
              const uint8_t *ctx, size_t ctxlen)
{
    size_t siglen = 0;

    if (sk == NULL || sig == NULL)
        return GY_ERR_ARG;
    if (msg == NULL && mlen != 0)
        return GY_ERR_ARG;
    if (ctx == NULL && ctxlen != 0)
        return GY_ERR_ARG;
    if (ctxlen > GY_MLDSA_CTX_MAX)
        return GY_ERR_TOOLONG;

    if (OQS_SIG_ml_dsa_44_sign_with_ctx_str(sig, &siglen, msg, mlen, ctx,
                                            ctxlen, sk) != OQS_SUCCESS) {
        gy_secure_zero(sig, GY_MLDSA44_SIG);
        return GY_ERR_CRYPTO;
    }
    /* ML-DSA signatures are fixed length; a short write is a provider fault. */
    if (siglen != GY_MLDSA44_SIG) {
        gy_secure_zero(sig, GY_MLDSA44_SIG);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mldsa_verify(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg,
                size_t mlen, const uint8_t *ctx, size_t ctxlen)
{
    if (pk == NULL || sig == NULL)
        return GY_ERR_ARG;
    if (msg == NULL && mlen != 0)
        return GY_ERR_ARG;
    if (ctx == NULL && ctxlen != 0)
        return GY_ERR_ARG;
    if (ctxlen > GY_MLDSA_CTX_MAX)
        return GY_ERR_TOOLONG;

    if (OQS_SIG_ml_dsa_44_verify_with_ctx_str(msg, mlen, sig, GY_MLDSA44_SIG,
                                              ctx, ctxlen, pk) != OQS_SUCCESS)
        return GY_ERR_VERIFY;
    return GY_OK;
}
