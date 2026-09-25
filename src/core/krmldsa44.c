/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <oqs/oqs.h>

#include "error.h"
#include "krmldsa/krmldsa_backend.h"
#include "krmldsa44.h"
#include "mldsa44.h"
#include "rng.h"
#include "util.h"

/*
 * Backend dispatch.  liboqs compiles its mldsa-native ML-DSA-44 once per
 * backend (C always; x86_64 AVX2 / aarch64 NEON when enabled) and, under
 * OQS_DIST_BUILD, picks one at runtime in OQS_SIG_ml_dsa_44_* with the CPU
 * probe below.  The KR routines are compiled the same way
 * (cmake/krmldsa.cmake) and this file applies the SAME predicate, so the KR
 * signer runs on exactly the backend liboqs itself would use on this CPU.
 *
 * The selection is cached in a function-table pointer on first use.  The
 * store is idempotent (every caller computes the same answer from the same
 * CPU), so a first-call race between threads is benign.  Once selected the
 * backend never changes for the life of the process: rerandomized signing
 * keys are backend-affine (krmldsa_backend.h) and that affinity is what makes
 * them safe to hold in memory.
 *
 * Verification needs no dispatch: it is the unmodified public liboqs verifier.
 */

static const gy_kr_backend_t *gy_kr44_impl;

static const gy_kr_backend_t *
gy_kr44_select(void)
{
#if defined(OQS_ENABLE_SIG_ml_dsa_44_x86_64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) &&
        OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) &&
        OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT))
#endif /* OQS_DIST_BUILD */
        return &gy_kr44_x86_64_backend;
#elif defined(OQS_ENABLE_SIG_ml_dsa_44_aarch64)
#if defined(OQS_DIST_BUILD)
    if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON))
#endif /* OQS_DIST_BUILD */
        return &gy_kr44_aarch64_backend;
#endif
    return &gy_kr44_c_backend;
}

static const gy_kr_backend_t *
gy_kr44_backend(void)
{
    if (gy_kr44_impl == NULL)
        gy_kr44_impl = gy_kr44_select();
    return gy_kr44_impl;
}

int
gy_kr44_keygen_base_seed(uint8_t *vkb, uint8_t *skb, const uint8_t *seed)
{
    int rc;

    if (vkb == NULL || skb == NULL || seed == NULL)
        return GY_ERR_ARG;

    rc = gy_kr44_backend()->keygen_base(vkb, skb, seed);
    if (rc != GY_OK)
        gy_secure_zero(skb, GY_KR44_SKB);
    return rc;
}

int
gy_kr44_keygen_base(uint8_t *vkb, uint8_t *skb)
{
    uint8_t seed[GY_KR44_SEED];
    int rc;

    if (vkb == NULL || skb == NULL)
        return GY_ERR_ARG;

    if (gy_random_bytes(seed, sizeof(seed)) != GY_OK)
        return GY_ERR_CRYPTO;
    rc = gy_kr44_keygen_base_seed(vkb, skb, seed);
    gy_secure_zero(seed, sizeof(seed));
    return rc;
}

int
gy_kr44_randvk(uint8_t *vkr, const uint8_t *vkb, const uint8_t *rho)
{
    if (vkr == NULL || vkb == NULL || rho == NULL)
        return GY_ERR_ARG;

    return gy_kr44_backend()->randvk(vkr, vkb, rho);
}

int
gy_kr44_randsk(gy_kr44_rsk_t *rsk, const uint8_t *skb, const uint8_t *vkb,
               const uint8_t *rho)
{
    int rc;

    if (rsk == NULL || skb == NULL || vkb == NULL || rho == NULL)
        return GY_ERR_ARG;

    rc = gy_kr44_backend()->randsk(rsk->opaque, skb, vkb, rho);
    if (rc != GY_OK)
        gy_kr44_rsk_clear(rsk);
    return rc;
}

void
gy_kr44_rsk_clear(gy_kr44_rsk_t *rsk)
{
    if (rsk != NULL)
        gy_secure_zero(rsk->opaque, sizeof(rsk->opaque));
}

int
gy_kr44_sign_rnd(uint8_t *sig, const gy_kr44_rsk_t *rsk, const uint8_t *msg,
                 size_t mlen, const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *rnd)
{
    /* FIPS 204 Algorithm 2: M' = 0x00 || |ctx| || ctx || M. */
    uint8_t pre[2 + GY_MLDSA_CTX_MAX];
    size_t i;

    if (sig == NULL || rsk == NULL || rnd == NULL)
        return GY_ERR_ARG;
    if (msg == NULL && mlen != 0)
        return GY_ERR_ARG;
    if (ctx == NULL && ctxlen != 0)
        return GY_ERR_ARG;
    if (ctxlen > GY_MLDSA_CTX_MAX)
        return GY_ERR_TOOLONG;

    pre[0] = 0;
    pre[1] = (uint8_t)ctxlen;
    for (i = 0; i < ctxlen; i++)
        pre[2 + i] = ctx[i];

    return gy_kr44_backend()->sign(sig, rsk->opaque, msg, mlen, pre, 2 + ctxlen,
                                   rnd);
}

int
gy_kr44_sign(uint8_t *sig, const gy_kr44_rsk_t *rsk, const uint8_t *msg,
             size_t mlen, const uint8_t *ctx, size_t ctxlen)
{
    uint8_t rnd[GY_KR44_SIGN_RND];
    int rc;

    /*
     * Hedged path: draw the rnd here (like gy_kr44_keygen_base draws its seed)
     * and delegate to the deterministic core.  Arg checks live in the core.
     */
    if (gy_random_bytes(rnd, sizeof(rnd)) != GY_OK)
        return GY_ERR_CRYPTO;
    rc = gy_kr44_sign_rnd(sig, rsk, msg, mlen, ctx, ctxlen, rnd);
    gy_secure_zero(rnd, sizeof(rnd));
    return rc;
}

int
gy_kr44_verify(const uint8_t *sig, const uint8_t *vkr, const uint8_t *msg,
               size_t mlen, const uint8_t *ctx, size_t ctxlen)
{
    /* [CFG+] Section 2.2: the standard verifier is kept unchanged. */
    return gy_mldsa44_verify(sig, vkr, msg, mlen, ctx, ctxlen);
}
