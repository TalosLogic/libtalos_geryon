/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KRMLDSA_BACKEND_H
#define GY_KRMLDSA_BACKEND_H

#include <stddef.h>
#include <stdint.h>

/*
 * Internal contract between the KR-ML-DSA per-backend implementation
 * (krmldsa_impl.c, compiled once per liboqs mldsa-native backend) and the
 * per-parameter-set dispatchers (core/krmldsa44.c, core/krmldsa87.c).
 *
 * This header is deliberately free of mldsa-native types so the dispatchers
 * can include it against the public liboqs headers only.  The rerandomized
 * signing key is passed as an opaque, 32-byte-aligned blob whose layout is
 * private to krmldsa_impl.c (see GY_KR*_RSK_BYTES in the public headers).
 *
 * Backend-affinity rule: a blob written by randsk of one backend must only be
 * read by sign of the SAME backend.  The native NTT backends keep polynomials
 * in a backend-specific coefficient order, so the blob is not portable across
 * backends and must never be serialized.  The dispatchers guarantee affinity
 * by selecting one backend per process on first call and never changing it.
 */

#define GY_KR_SEED 32     /* base keygen seed */
#define GY_KR_RAND 64     /* rerandomizer rho: ExpandS seed width (CRHBYTES) */
#define GY_KR_SIGN_RND 32 /* hedged-sign rnd: FIPS 204 MLDSA_RNDBYTES */
#define GY_KR_RSK_ALIGN 32

typedef struct {
    /* Base keypair from a 32-byte seed: vkb (uncompressed t), skb. */
    int (*keygen_base)(uint8_t *vkb, uint8_t *skb, const uint8_t *seed);
    /* RandVK: standard-format ML-DSA verifying key from (vkb, rho). */
    int (*randvk)(uint8_t *vkr, const uint8_t *vkb, const uint8_t *rho);
    /* RandSK: in-memory rerandomized signing key from (skb, vkb, rho). */
    int (*randsk)(void *rsk, const uint8_t *skb, const uint8_t *vkb,
                  const uint8_t *rho);
    /*
     * Sign with the 2*beta rejection bound; pre is the FIPS 204 M' prefix.
     * rnd (GY_KR_SIGN_RND bytes) is the hedge, supplied by the caller: the
     * dispatcher draws it from gy_random_bytes for the public path and the KATs
     * pass a fixed value, so this is a deterministic core (no RNG draw inside),
     * matching keygen_base and gy_xeddsa_sign_z.
     */
    int (*sign)(uint8_t *sig, const void *rsk, const uint8_t *msg, size_t mlen,
                const uint8_t *pre, size_t prelen, const uint8_t *rnd);
} gy_kr_backend_t;

/*
 * One table per (parameter set, backend).  Only the tables whose backend is
 * compiled (cmake/krmldsa.cmake) exist; the dispatchers reference them under
 * the same OQS_ENABLE_SIG_ml_dsa_*_<arch> macros liboqs uses for its own
 * dispatch, so an unreferenced table is never an unresolved symbol.
 */
extern const gy_kr_backend_t gy_kr44_c_backend;
extern const gy_kr_backend_t gy_kr44_x86_64_backend;
extern const gy_kr_backend_t gy_kr44_aarch64_backend;
extern const gy_kr_backend_t gy_kr87_c_backend;
extern const gy_kr_backend_t gy_kr87_x86_64_backend;
extern const gy_kr_backend_t gy_kr87_aarch64_backend;

#endif /* GY_KRMLDSA_BACKEND_H */
