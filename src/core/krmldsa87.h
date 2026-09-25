/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KRMLDSA87_H
#define GY_KRMLDSA87_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

/*
 * KR-ML-DSA-87: the ML-DSA-87 instantiation of key-rerandomizable ML-DSA for
 * the h448_1024 tier.  See krmldsa44.h for the construction and posture; the
 * two files are separate wrappers exactly as mldsa44.c / mldsa87.c are
 * (D-PQ-3).  [CFG+] Table 1 gives eta = 2, beta = 120 at NIST level 5, so the
 * rerandomized signing bound is 240 and the expected attempt count is about
 * 3.85^2 (~15).
 */

#define GY_KR87_SEED 32
#define GY_KR87_RAND 64
#define GY_KR87_SIGN_RND 32 /* hedged-sign rnd (FIPS 204 MLDSA_RNDBYTES) */
#define GY_KR87_VKB 5920    /* rho_A(32) || t1(8*320) || t0(8*416) */
#define GY_KR87_SKB 1472    /* s1(7*96) || s2(8*96) || K(32) */
#define GY_KR87_VKR 2592    /* standard ML-DSA-87 pk */
#define GY_KR87_SIG 4627    /* standard ML-DSA-87 signature */

#define GY_KR87_RSK_BYTES 23680
typedef struct gy_kr87_rsk {
    alignas(32) uint8_t opaque[GY_KR87_RSK_BYTES];
} gy_kr87_rsk_t;

#ifndef GY_MLDSA_CTX_MAX
#define GY_MLDSA_CTX_MAX 255
#endif

int gy_kr87_keygen_base(uint8_t *vkb, uint8_t *skb);
int gy_kr87_keygen_base_seed(uint8_t *vkb, uint8_t *skb, const uint8_t *seed);
int gy_kr87_randvk(uint8_t *vkr, const uint8_t *vkb, const uint8_t *rho);
int gy_kr87_randsk(gy_kr87_rsk_t *rsk, const uint8_t *skb, const uint8_t *vkb,
                   const uint8_t *rho);
void gy_kr87_rsk_clear(gy_kr87_rsk_t *rsk);
int gy_kr87_sign(uint8_t *sig, const gy_kr87_rsk_t *rsk, const uint8_t *msg,
                 size_t mlen, const uint8_t *ctx, size_t ctxlen);
int gy_kr87_verify(const uint8_t *sig, const uint8_t *vkr, const uint8_t *msg,
                   size_t mlen, const uint8_t *ctx, size_t ctxlen);

/* Deterministic signing core; see gy_kr44_sign_rnd (krmldsa44.h). */
int gy_kr87_sign_rnd(uint8_t *sig, const gy_kr87_rsk_t *rsk, const uint8_t *msg,
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *rnd);

#endif /* GY_KRMLDSA87_H */
