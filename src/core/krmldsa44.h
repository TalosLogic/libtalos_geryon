/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KRMLDSA44_H
#define GY_KRMLDSA44_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

/*
 * KR-ML-DSA-44: key-rerandomizable ML-DSA per ePrint 2026/453 [CFG+] Figures
 * 3 and 4, instantiated over the ML-DSA-44 parameter set for the h25519_512
 * tier of the quantum-safe private group system (QSPGS).
 *
 * The scheme is standard ML-DSA with three changes on the key side and one on
 * the signing side:
 *   1. A is expanded from a FIXED public seed rho_A (one per parameter set),
 *      not from a per-key seed, so every key in the system shares A.
 *   2. The base verifying key carries the FULL t (t1 and t0), so a rerandomized
 *      t_r = t + A*s1' + s2' can be recomputed exactly.
 *   3. RandSK adds a fresh small (s1', s2') to the base secret, RandVK adds the
 *      matching A*s1' + s2' to t and rounds; the rerandomized verifying key is
 *      a byte-standard ML-DSA-44 public key.
 *   4. Signing under a rerandomized key uses the rejection bound 2*beta
 *      (secret coefficients are in [-2eta, 2eta]); the expected attempt count
 *      is the square of standard ML-DSA's.
 *
 * VERIFICATION IS UNCHANGED: [CFG+] Section 2.2 keeps the standard verifier
 * (bound gamma1 - beta) and absorbs the +beta into the SelfTargetMSIS bound
 * (< 1 bit of loss).  gy_kr44_verify is therefore the public liboqs verifier
 * via gy_mldsa44_verify, and the server side of QSPGS needs nothing below the
 * public liboqs API.  Only keygen_base / randvk / randsk / sign reach liboqs'
 * mldsa-native internals (src/core/krmldsa/krmldsa_impl.c).
 *
 * Library-first posture: geryon owns the four routines above as composition
 * glue (about the size of the corresponding mldsa-native routines); every
 * polynomial, NTT, sampler, packer, and SHAKE call is liboqs code, in whichever
 * native backend liboqs itself selected for this CPU.
 */

#define GY_KR44_SEED 32     /* base keygen seed */
#define GY_KR44_RAND 64     /* rerandomizer rho (input to ExpandS) */
#define GY_KR44_SIGN_RND 32 /* hedged-sign rnd (FIPS 204 MLDSA_RNDBYTES) */
#define GY_KR44_VKB 2976    /* base vk: rho_A(32) || t1(4*320) || t0(4*416) */
#define GY_KR44_SKB 800     /* base sk: s1(4*96) || s2(4*96) || K(32) */
#define GY_KR44_VKR 1312    /* rerandomized vk: standard ML-DSA-44 pk */
#define GY_KR44_SIG 2420    /* standard ML-DSA-44 signature */

/* Opaque rerandomized signing key: never serialized (see krmldsa_backend.h). */
#define GY_KR44_RSK_BYTES 12544
typedef struct gy_kr44_rsk {
    alignas(32) uint8_t opaque[GY_KR44_RSK_BYTES];
} gy_kr44_rsk_t;

#ifndef GY_MLDSA_CTX_MAX
#define GY_MLDSA_CTX_MAX 255
#endif

/*
 * Base keypair.  gy_kr44_keygen_base draws the seed internally (hedged, like
 * gy_mldsa44_keypair); the _seed variant is deterministic for KATs.  skb is
 * zeroized on failure.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_kr44_keygen_base(uint8_t *vkb, uint8_t *skb);
int gy_kr44_keygen_base_seed(uint8_t *vkb, uint8_t *skb, const uint8_t *seed);

/*
 * RandVK: derive the standard-format verifying key for rerandomizer rho
 * (64 bytes, e.g. H(UID, rrs) per [CFG+]).  Rejects a vkb whose rho_A field is
 * not this parameter set's fixed seed (GY_ERR_ARG).
 */
int gy_kr44_randvk(uint8_t *vkr, const uint8_t *vkb, const uint8_t *rho);

/*
 * RandSK: derive the in-memory signing key for rho.  The result is valid only
 * in this process and only with the backend selected at first call; clear it
 * with gy_kr44_rsk_clear when done.  Matches gy_kr44_randvk(vkb, rho).
 */
int gy_kr44_randsk(gy_kr44_rsk_t *rsk, const uint8_t *skb, const uint8_t *vkb,
                   const uint8_t *rho);
void gy_kr44_rsk_clear(gy_kr44_rsk_t *rsk);

/*
 * Sign / verify with the same contract as gy_mldsa44_sign / gy_mldsa44_verify
 * (hedged, context string is a parameter, ctxlen > 255 is GY_ERR_TOOLONG).
 * Signatures are byte-standard ML-DSA-44 and verify under the rerandomized
 * key with the unmodified verifier.
 */
int gy_kr44_sign(uint8_t *sig, const gy_kr44_rsk_t *rsk, const uint8_t *msg,
                 size_t mlen, const uint8_t *ctx, size_t ctxlen);
int gy_kr44_verify(const uint8_t *sig, const uint8_t *vkr, const uint8_t *msg,
                   size_t mlen, const uint8_t *ctx, size_t ctxlen);

/*
 * Deterministic signing core: identical to gy_kr44_sign but the hedge rnd
 * (GY_KR44_SIGN_RND bytes) is supplied by the caller instead of drawn from the
 * RNG.  gy_kr44_sign is the rnd = gy_random_bytes(...) wrapper over it.  This
 * is the KAT seam (fixed rnd => reproducible, cross-backend-comparable
 * signature bytes); no global test hook, matching gy_xeddsa_sign_z.
 */
int gy_kr44_sign_rnd(uint8_t *sig, const gy_kr44_rsk_t *rsk, const uint8_t *msg,
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,
                     const uint8_t *rnd);

#endif /* GY_KRMLDSA44_H */
