/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/*
 * KR-ML-DSA over liboqs' mldsa-native internals.
 *
 * This translation unit is compiled ONCE PER BACKEND (cmake/krmldsa.cmake):
 * against the mldsa-native_ml-dsa-<set>_<ref|x86_64|aarch64> header tree with
 * the identical -DMLD_CONFIG_PARAMETER_SET / -DMLD_CONFIG_FILE liboqs used for
 * that backend.  mldsa-native routes every internal symbol through its
 * MLD_NAMESPACE macros, so the same source below links against the C, AVX2, or
 * NEON object set purely by include path and config file; nothing here names
 * a backend.  GY_KR_BACKEND (c | x86_64 | aarch64) only suffixes OUR symbols.
 *
 * What is geryon-owned here is the [CFG+] Figures 3 and 4 composition:
 * keygen_base, RandVK, RandSK, and the signing loop with the 2*beta bound.
 * Every polynomial operation, sampler, packer, and hash is liboqs code.  The
 * routines mirror mldsa-native's sign.c step for step (same helper calls, same
 * order, same declassification points) so that a reviewer can diff them
 * against sign.c and see only the four [CFG+] deltas.
 *
 * Constant time: the secret-dependent work is entirely inside mldsa-native
 * helpers (D-PQ-4: liboqs validates its own constant-timeness).  This file
 * branches only on public quantities: the rejection outcomes (public per
 * FIPS 204 Section 5.5, exactly as in sign.c), argument checks, and fixed
 * lengths.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* mldsa-native internals (include path set per backend by CMake). */
#include "common.h"
#include "packing.h"
#include "poly.h"
#include "poly_kl.h"
#include "polyvec.h"
#include "polyvec_lazy.h"
#include "symmetric.h"

/* geryon core. */
#include "error.h"
#include "krmldsa_backend.h"
#include "util.h"

#ifndef GY_KR_BACKEND
#error "GY_KR_BACKEND (c | x86_64 | aarch64) must be defined"
#endif

#define GY_KR_CAT_(a, b) a##b
#define GY_KR_CAT(a, b) GY_KR_CAT_(a, b)
#define GY_KR_PREFIX                                                           \
    GY_KR_CAT(GY_KR_CAT(gy_kr, MLD_CONFIG_PARAMETER_SET),                      \
              GY_KR_CAT(_, GY_KR_BACKEND))
#define GY_KR_SYM(x) GY_KR_CAT(GY_KR_PREFIX, GY_KR_CAT(_, x))

/*
 * [CFG+] Figure 3: the rerandomized secret has coefficients in [-2eta, 2eta],
 * so ||c * s|| <= 2 * tau * eta = 2 * beta and the rejection bounds become
 * gamma1 - 2beta and gamma2 - 2beta.  The verifier keeps gamma1 - beta.
 */
#define GY_KR_BETA (2 * MLDSA_BETA)

/*
 * Attempt bound.  mldsa-native's default (814 minimum) is sized for the
 * standard expected attempt count (4.25 at level 2).  [CFG+] Table 1 squares
 * it (18 / 15 attempts at levels 2 / 5); 4096 attempts gives a failure
 * probability below e^-227 at level 2 and e^-273 at level 5.
 */
#define GY_KR_MAX_ATTEMPTS 4096

#if MLD_CONFIG_PARAMETER_SET == 44
#include "krmldsa44.h"
#define GY_KR_RHO_A_LABEL "geryon-QSPGS-KR-ML-DSA-44-v1"
#define GY_KR_PUB_VKB GY_KR44_VKB
#define GY_KR_PUB_SKB GY_KR44_SKB
#define GY_KR_PUB_VKR GY_KR44_VKR
#define GY_KR_PUB_SIG GY_KR44_SIG
#define GY_KR_PUB_RSK GY_KR44_RSK_BYTES
#elif MLD_CONFIG_PARAMETER_SET == 87
#include "krmldsa87.h"
#define GY_KR_RHO_A_LABEL "geryon-QSPGS-KR-ML-DSA-87-v1"
#define GY_KR_PUB_VKB GY_KR87_VKB
#define GY_KR_PUB_SKB GY_KR87_SKB
#define GY_KR_PUB_VKR GY_KR87_VKR
#define GY_KR_PUB_SIG GY_KR87_SIG
#define GY_KR_PUB_RSK GY_KR87_RSK_BYTES
#else
#error "KR-ML-DSA is instantiated for ML-DSA-44 and ML-DSA-87 only"
#endif

/* Base verifying key: rho_A || t1 (packed, K rows) || t0 (packed, K rows). */
#define GY_KR_VKB_T1_OFF MLDSA_SEEDBYTES
#define GY_KR_VKB_T0_OFF (MLDSA_SEEDBYTES + MLDSA_K * MLDSA_POLYT1_PACKEDBYTES)
#define GY_KR_VKB_BYTES (GY_KR_VKB_T0_OFF + MLDSA_K * MLDSA_POLYT0_PACKEDBYTES)

/* Base signing key: s1 (eta-packed, L rows) || s2 (eta-packed, K rows) || K. */
#define GY_KR_SKB_S1_OFF 0
#define GY_KR_SKB_S2_OFF (MLDSA_L * MLDSA_POLYETA_PACKEDBYTES)
#define GY_KR_SKB_KEY_OFF                                                      \
    (GY_KR_SKB_S2_OFF + MLDSA_K * MLDSA_POLYETA_PACKEDBYTES)
#define GY_KR_SKB_BYTES (GY_KR_SKB_KEY_OFF + MLDSA_SEEDBYTES)

/*
 * Rerandomized signing key, held in memory only.  [CFG+] Figure 4 line 39:
 * sk_r = (rho_A, K, tr, s1_r, s2_r, t0_r).  Stored NTT-domain (s1hat, s2hat,
 * t0hat) so signing needs no per-call transform, exactly the eager shape
 * mldsa-native unpacks into.  Not packable with the standard sk format: s_r
 * coefficients reach 2eta, beyond the eta-packer's width, which is one reason
 * the key is never serialized.
 */
struct gy_kr_rsk_impl {
    mld_polyvecl s1hat;
    mld_polyveck s2hat;
    mld_polyveck t0hat;
    uint8_t rho[MLDSA_SEEDBYTES];
    uint8_t tr[MLDSA_TRBYTES];
    uint8_t key[MLDSA_SEEDBYTES];
};

_Static_assert(GY_KR_VKB_BYTES == GY_KR_PUB_VKB, "vkb size drift");
_Static_assert(GY_KR_SKB_BYTES == GY_KR_PUB_SKB, "skb size drift");
_Static_assert(MLDSA_CRYPTO_PUBLICKEYBYTES == GY_KR_PUB_VKR, "vkr size drift");
_Static_assert(MLDSA_CRYPTO_BYTES == GY_KR_PUB_SIG, "sig size drift");
_Static_assert(sizeof(struct gy_kr_rsk_impl) <= GY_KR_PUB_RSK,
               "rsk blob too small");
_Static_assert(MLDSA_CRHBYTES == GY_KR_RAND, "rho width drift");
_Static_assert(MLDSA_SEEDBYTES == GY_KR_SEED, "seed width drift");
_Static_assert(MLDSA_RNDBYTES == GY_KR_SIGN_RND, "sign rnd width drift");
_Static_assert(MLD_DEFAULT_ALIGN <= GY_KR_RSK_ALIGN, "rsk alignment drift");
_Static_assert(MLDSA_L + MLDSA_K <= 255, "ExpandS nonce width");
#ifdef MLD_NONCE_UB
_Static_assert(GY_KR_MAX_ATTEMPTS <= MLD_NONCE_UB, "attempt bound");
#endif

/* --------------------------------------------------------------------------
 * Hash helpers (SHAKE256 via mldsa-native's symmetric.h, i.e. liboqs SHA3).
 * -------------------------------------------------------------------------- */

static void
kr_H(uint8_t *out, size_t outlen, const uint8_t *in1, size_t in1len,
     const uint8_t *in2, size_t in2len, const uint8_t *in3, size_t in3len)
{
    mld_shake256ctx st;

    mld_shake256_init(&st);
    mld_shake256_absorb(&st, in1, in1len);
    if (in2len != 0)
        mld_shake256_absorb(&st, in2, in2len);
    if (in3len != 0)
        mld_shake256_absorb(&st, in3, in3len);
    mld_shake256_finalize(&st);
    mld_shake256_squeeze(out, outlen, &st);
    mld_shake256_release(&st);
}

/* rho_A: fixed public seed for A ([CFG+] Figure 4 caption), one per set. */
static void
kr_rho_a(uint8_t rho[MLDSA_SEEDBYTES])
{
    mld_shake256(rho, MLDSA_SEEDBYTES, (const uint8_t *)GY_KR_RHO_A_LABEL,
                 sizeof(GY_KR_RHO_A_LABEL) - 1);
}

/* --------------------------------------------------------------------------
 * Polynomial helpers.
 * -------------------------------------------------------------------------- */

/*
 * ExpandS (FIPS 204 Algorithm 33): (s1, s2) in S_eta^L x S_eta^K from seed,
 * nonces 0..L+K-1.  Mirrors mldsa-native's mld_sample_s1_s2 exactly: liboqs
 * builds mldsa-native with the 4-way SHAKE batch, under which only
 * mld_poly_uniform_eta_4x is declared (the single-poly sampler exists only
 * under MLD_CONFIG_SERIAL_FIPS202_ONLY).  The batched call is byte-identical
 * to sampling each polynomial with its nonce; the "irrelevant" fourth slot
 * (nonce 0xFF) is a scratch output that is overwritten by the next call.
 */
static void
kr_expand_s(mld_polyvecl *s1, mld_polyveck *s2,
            const uint8_t seed[MLDSA_CRHBYTES])
{
#if defined(MLD_CONFIG_SERIAL_FIPS202_ONLY)
    unsigned int i;

    for (i = 0; i < MLDSA_L; i++)
        mld_poly_uniform_eta(&s1->vec[i], seed, (uint8_t)i);
    for (i = 0; i < MLDSA_K; i++)
        mld_poly_uniform_eta(&s2->vec[i], seed, (uint8_t)(MLDSA_L + i));
#elif MLD_CONFIG_PARAMETER_SET == 44
    mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                            seed, 0, 1, 2, 3);
    mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                            seed, 4, 5, 6, 7);
#elif MLD_CONFIG_PARAMETER_SET == 87
    mld_poly_uniform_eta_4x(&s1->vec[0], &s1->vec[1], &s1->vec[2], &s1->vec[3],
                            seed, 0, 1, 2, 3);
    mld_poly_uniform_eta_4x(&s1->vec[4], &s1->vec[5], &s1->vec[6],
                            &s2->vec[0] /* scratch, overwritten below */, seed,
                            4, 5, 6, 0xFF);
    mld_poly_uniform_eta_4x(&s2->vec[0], &s2->vec[1], &s2->vec[2], &s2->vec[3],
                            seed, 7, 8, 9, 10);
    mld_poly_uniform_eta_4x(&s2->vec[4], &s2->vec[5], &s2->vec[6], &s2->vec[7],
                            seed, 11, 12, 13, 14);
#else
#error "kr_expand_s: unsupported parameter set"
#endif
}

/*
 * t = A*s1 + s2 in the normal domain, coefficients in [0, q).  s1hat receives
 * NTT(s1); mat receives ExpandA(rho).  Mirrors mld_compute_pack_t0_t1 up to
 * the rounding step, which the callers do themselves.
 */
static void
kr_compute_t(mld_polyveck *t, mld_polymat *mat, mld_polyvecl *s1hat,
             const mld_polyvecl *s1, const mld_polyveck *s2,
             const uint8_t rho[MLDSA_SEEDBYTES])
{
    unsigned int k;

    *s1hat = *s1;
    mld_polyvecl_ntt(s1hat);
    mld_polyvec_matrix_expand(mat, rho);
    for (k = 0; k < MLDSA_K; k++) {
        mld_polyvec_matrix_pointwise_montgomery_row(&t->vec[k], mat, s1hat, k);
        mld_poly_invntt_tomont(&t->vec[k]);
        mld_poly_add(&t->vec[k], &s2->vec[k]);
        mld_poly_reduce(&t->vec[k]);
        mld_poly_caddq(&t->vec[k]);
    }
}

/*
 * [CFG+] Figure 4 lines 42-43: t_r = (t1 * 2^d + t0) + A*s1' + s2', with
 * (t1, t0) unpacked from the base verifying key.  Output in [0, q).
 */
static void
kr_rerand_t(mld_polyveck *tr, mld_polymat *mat, mld_polyvecl *s1hat,
            const uint8_t *vkb, const mld_polyvecl *s1p,
            const mld_polyveck *s2p)
{
    mld_poly tmp;
    unsigned int k;

    kr_compute_t(tr, mat, s1hat, s1p, s2p, vkb); /* rho_A is vkb[0..32) */
    for (k = 0; k < MLDSA_K; k++) {
        mld_polyt1_unpack(&tmp, vkb + GY_KR_VKB_T1_OFF +
                                    k * MLDSA_POLYT1_PACKEDBYTES);
        mld_poly_shiftl(&tmp); /* t1 * 2^d */
        mld_poly_add(&tr->vec[k], &tmp);
        mld_polyt0_unpack(&tmp, vkb + GY_KR_VKB_T0_OFF +
                                    k * MLDSA_POLYT0_PACKEDBYTES);
        mld_poly_add(&tr->vec[k], &tmp);
        mld_poly_reduce(&tr->vec[k]);
        mld_poly_caddq(&tr->vec[k]);
    }
    gy_secure_zero(&tmp, sizeof(tmp));
}

/* Standard pk bytes from rho and t_r; t0 rows returned for RandSK. */
static void
kr_pack_vkr(uint8_t *vkr, mld_polyveck *t0, const uint8_t rho[MLDSA_SEEDBYTES],
            mld_polyveck *tr)
{
    mld_poly t1;
    unsigned int k;

    memcpy(vkr, rho, MLDSA_SEEDBYTES);
    for (k = 0; k < MLDSA_K; k++) {
        mld_poly_power2round(&t1, &t0->vec[k], &tr->vec[k]);
        mld_polyt1_pack(vkr + MLDSA_SEEDBYTES + k * MLDSA_POLYT1_PACKEDBYTES,
                        &t1);
    }
}

/* --------------------------------------------------------------------------
 * Gen ([CFG+] Figure 3, base keygen).
 * -------------------------------------------------------------------------- */

static int
GY_KR_SYM(keygen_base)(uint8_t *vkb, uint8_t *skb, const uint8_t *seed)
{
    /* rhoprime(64) || key(32), as FIPS 204 keygen but with rho unused. */
    uint8_t seedbuf[MLDSA_CRHBYTES + MLDSA_SEEDBYTES];
    uint8_t inbuf[MLDSA_SEEDBYTES + 2];
    uint8_t rho[MLDSA_SEEDBYTES];
    _Alignas(GY_KR_RSK_ALIGN) mld_polymat mat;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyvecl s1, s1hat;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyveck s2, t;
    _Alignas(GY_KR_RSK_ALIGN) mld_poly t1, t0;
    unsigned int i;

    memcpy(inbuf, seed, MLDSA_SEEDBYTES);
    inbuf[MLDSA_SEEDBYTES + 0] = MLDSA_K;
    inbuf[MLDSA_SEEDBYTES + 1] = MLDSA_L;
    mld_shake256(seedbuf, sizeof(seedbuf), inbuf, sizeof(inbuf));

    kr_expand_s(&s1, &s2, seedbuf);
    kr_rho_a(rho);
    kr_compute_t(&t, &mat, &s1hat, &s1, &s2, rho);

    /* vkb = rho_A || t1 || t0: the full t, [CFG+] Section 2 ("entire y"). */
    memcpy(vkb, rho, MLDSA_SEEDBYTES);
    for (i = 0; i < MLDSA_K; i++) {
        mld_poly_power2round(&t1, &t0, &t.vec[i]);
        mld_polyt1_pack(vkb + GY_KR_VKB_T1_OFF + i * MLDSA_POLYT1_PACKEDBYTES,
                        &t1);
        mld_polyt0_pack(vkb + GY_KR_VKB_T0_OFF + i * MLDSA_POLYT0_PACKEDBYTES,
                        &t0);
    }

    /* skb = s1 || s2 || K (base coefficients are in [-eta, eta]). */
    for (i = 0; i < MLDSA_L; i++)
        mld_polyeta_pack(skb + GY_KR_SKB_S1_OFF + i * MLDSA_POLYETA_PACKEDBYTES,
                         &s1.vec[i]);
    for (i = 0; i < MLDSA_K; i++)
        mld_polyeta_pack(skb + GY_KR_SKB_S2_OFF + i * MLDSA_POLYETA_PACKEDBYTES,
                         &s2.vec[i]);
    memcpy(skb + GY_KR_SKB_KEY_OFF, seedbuf + MLDSA_CRHBYTES, MLDSA_SEEDBYTES);

    gy_secure_zero(seedbuf, sizeof(seedbuf));
    gy_secure_zero(inbuf, sizeof(inbuf));
    gy_secure_zero(&s1, sizeof(s1));
    gy_secure_zero(&s1hat, sizeof(s1hat));
    gy_secure_zero(&s2, sizeof(s2));
    gy_secure_zero(&t, sizeof(t));
    gy_secure_zero(&t0, sizeof(t0));
    return GY_OK;
}

/* --------------------------------------------------------------------------
 * RandVK ([CFG+] Figure 4 lines 40-45).
 * -------------------------------------------------------------------------- */

static int
GY_KR_SYM(randvk)(uint8_t *vkr, const uint8_t *vkb, const uint8_t *rho)
{
    uint8_t rho_a[MLDSA_SEEDBYTES];
    _Alignas(GY_KR_RSK_ALIGN) mld_polymat mat;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyvecl s1p, s1hat;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyveck s2p, tr, t0;

    /* Policy: a base key must carry this set's fixed A seed. */
    kr_rho_a(rho_a);
    if (gy_const_memcmp(vkb, rho_a, MLDSA_SEEDBYTES) != 0)
        return GY_ERR_ARG;

    kr_expand_s(&s1p, &s2p, rho);
    kr_rerand_t(&tr, &mat, &s1hat, vkb, &s1p, &s2p);
    kr_pack_vkr(vkr, &t0, rho_a, &tr);

    /*
     * (s1', s2') are derived from rho, which the group shares, so they are
     * not secret to group members; they are still secret to the server, and
     * clearing them costs nothing.
     */
    gy_secure_zero(&s1p, sizeof(s1p));
    gy_secure_zero(&s1hat, sizeof(s1hat));
    gy_secure_zero(&s2p, sizeof(s2p));
    gy_secure_zero(&t0, sizeof(t0));
    return GY_OK;
}

/* --------------------------------------------------------------------------
 * RandSK ([CFG+] Figure 4 lines 34-39).
 * -------------------------------------------------------------------------- */

static int
GY_KR_SYM(randsk)(void *rsk_blob, const uint8_t *skb, const uint8_t *vkb,
                  const uint8_t *rho)
{
    struct gy_kr_rsk_impl *rsk = rsk_blob;
    uint8_t vkr[MLDSA_CRYPTO_PUBLICKEYBYTES];
    uint8_t rho_a[MLDSA_SEEDBYTES];
    _Alignas(GY_KR_RSK_ALIGN) mld_polymat mat;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyvecl s1p, s1hat, s1;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyveck s2p, s2, tr;
    unsigned int i;

    kr_rho_a(rho_a);
    if (gy_const_memcmp(vkb, rho_a, MLDSA_SEEDBYTES) != 0)
        return GY_ERR_ARG;

    /* Public half, identical to RandVK: vk_r, and t0_r from the rounding. */
    kr_expand_s(&s1p, &s2p, rho);
    kr_rerand_t(&tr, &mat, &s1hat, vkb, &s1p, &s2p);
    kr_pack_vkr(vkr, &rsk->t0hat, rho_a, &tr);

    /* s_r = s_b + s': coefficients in [-2eta, 2eta]. */
    for (i = 0; i < MLDSA_L; i++) {
        mld_polyeta_unpack(&s1.vec[i], skb + GY_KR_SKB_S1_OFF +
                                           i * MLDSA_POLYETA_PACKEDBYTES);
        mld_poly_add(&s1.vec[i], &s1p.vec[i]);
    }
    for (i = 0; i < MLDSA_K; i++) {
        mld_polyeta_unpack(&s2.vec[i], skb + GY_KR_SKB_S2_OFF +
                                           i * MLDSA_POLYETA_PACKEDBYTES);
        mld_poly_add(&s2.vec[i], &s2p.vec[i]);
    }

    /* NTT-domain copies, the shape mld_sign_signature_internal unpacks to. */
    rsk->s1hat = s1;
    mld_polyvecl_ntt(&rsk->s1hat);
    rsk->s2hat = s2;
    mld_polyveck_ntt(&rsk->s2hat);
    mld_polyveck_ntt(&rsk->t0hat);

    /* rho_A, tr = H(vk_r), and the signing seed K carried UNCHANGED from the
     * base key ([CFG+] Fig. 4 line 39: sk_r reuses K_b verbatim).  The hedged
     * nonce rho' = H(K || rnd || mu) is already pseudonym-specific because mu
     * binds tr = H(vk_r); no per-pseudonym K derivation is needed and none is
     * prescribed, so we stay inside the Theorems 1/2 construction. */
    memcpy(rsk->rho, rho_a, MLDSA_SEEDBYTES);
    mld_shake256(rsk->tr, MLDSA_TRBYTES, vkr, MLDSA_CRYPTO_PUBLICKEYBYTES);
    memcpy(rsk->key, skb + GY_KR_SKB_KEY_OFF, MLDSA_SEEDBYTES);

    gy_secure_zero(&s1, sizeof(s1));
    gy_secure_zero(&s2, sizeof(s2));
    gy_secure_zero(&s1p, sizeof(s1p));
    gy_secure_zero(&s1hat, sizeof(s1hat));
    gy_secure_zero(&s2p, sizeof(s2p));
    gy_secure_zero(&tr, sizeof(tr));
    return GY_OK;
}

/* --------------------------------------------------------------------------
 * Sgn ([CFG+] Figure 3 with the 2*beta bound).  Mirrors mldsa-native
 * mld_attempt_signature_generation / mld_sign_signature_internal.
 * -------------------------------------------------------------------------- */

static int
kr_attempt(uint8_t sig[MLDSA_CRYPTO_BYTES], const uint8_t mu[MLDSA_CRHBYTES],
           const uint8_t rhoprime[MLDSA_CRHBYTES], uint16_t nonce,
           mld_polymat *mat, const struct gy_kr_rsk_impl *rsk)
{
    uint8_t c[MLDSA_CTILDEBYTES];
    _Alignas(GY_KR_RSK_ALIGN) mld_yvec y;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyveck w0, w1;
    _Alignas(GY_KR_RSK_ALIGN) mld_polyvecl scratch;
    _Alignas(GY_KR_RSK_ALIGN) mld_poly cp, z, tmp;
    unsigned int i;
    int ret = GY_ERR_VERIFY; /* internal marker: reject, retry */

    /* y, w = A*y, (w1, w0), c~ = H(mu || w1). */
    mld_yvec_init(&y, rhoprime, nonce);
    mld_polyvec_matrix_pointwise_montgomery_yvec(&w0, mat, &y, &scratch);
    mld_polyveck_caddq(&w0);
    mld_polyveck_decompose(&w1, &w0);
    mld_polyveck_pack_w1(sig, &w1); /* sig doubles as scratch, as in sign.c */
    kr_H(c, MLDSA_CTILDEBYTES, mu, MLDSA_CRHBYTES, sig,
         MLDSA_K * MLDSA_POLYW1_PACKEDBYTES, NULL, 0);
    mld_poly_challenge(&cp, c);
    mld_poly_ntt(&cp);

    /* z = y + c*s1_r, rejected against gamma1 - 2beta. */
    for (i = 0; i < MLDSA_L; i++) {
        z = rsk->s1hat.vec[i];
        mld_poly_pointwise_montgomery(&z, &cp);
        mld_poly_invntt_tomont(&z);
        mld_yvec_get_poly(&tmp, &y, i);
        mld_poly_add(&z, &tmp);
        mld_poly_reduce(&z);
        if (mld_poly_chknorm(&z, MLDSA_GAMMA1 - GY_KR_BETA))
            goto out;
        mld_pack_sig_z(sig, &z, i);
    }

    /* w0 - c*s2_r against gamma2 - 2beta; c*t0_r against gamma2. */
    for (i = 0; i < MLDSA_K; i++) {
        z = rsk->s2hat.vec[i];
        mld_poly_pointwise_montgomery(&z, &cp);
        mld_poly_invntt_tomont(&z);
        mld_poly_sub(&w0.vec[i], &z);
        mld_poly_reduce(&w0.vec[i]);
        if (mld_poly_chknorm(&w0.vec[i], MLDSA_GAMMA2 - GY_KR_BETA))
            goto out;

        z = rsk->t0hat.vec[i];
        mld_poly_pointwise_montgomery(&z, &cp);
        mld_poly_invntt_tomont(&z);
        mld_poly_reduce(&z);
        if (mld_poly_chknorm(&z, MLDSA_GAMMA2))
            goto out;
        mld_poly_add(&w0.vec[i], &z);
    }

    /* c~ and the hint vector (mld_pack_sig_h enforces the omega bound). */
    mld_pack_sig_c(sig, c);
    if (mld_pack_sig_h(sig, &w0, &w1) != 0)
        goto out;
    ret = GY_OK;

out:
    gy_secure_zero(&y, sizeof(y));
    gy_secure_zero(&w0, sizeof(w0));
    gy_secure_zero(&scratch, sizeof(scratch));
    gy_secure_zero(&z, sizeof(z));
    gy_secure_zero(&tmp, sizeof(tmp));
    return ret;
}

/*
 * Deterministic signing core: the hedge rnd is supplied by the caller (the
 * dispatcher draws it from gy_random_bytes; KATs pass a fixed value), so this
 * routine draws no randomness itself.  Same shape as GY_KR_SYM(keygen_base)
 * taking the seed, and as gy_xeddsa_sign_z taking z.
 */
static int
GY_KR_SYM(sign)(uint8_t *sig, const void *rsk_blob, const uint8_t *msg,
                size_t mlen, const uint8_t *pre, size_t prelen,
                const uint8_t *rnd)
{
    const struct gy_kr_rsk_impl *rsk = rsk_blob;
    uint8_t mu[MLDSA_CRHBYTES];
    uint8_t rhoprime[MLDSA_CRHBYTES];
    _Alignas(GY_KR_RSK_ALIGN) mld_polymat mat;
    uint16_t nonce;
    int ret = GY_ERR_CRYPTO;

    /* mu = H(tr || M'), M' = pre || msg (FIPS 204 Algorithm 2, hedged). */
    kr_H(mu, MLDSA_CRHBYTES, rsk->tr, MLDSA_TRBYTES, pre, prelen, msg, mlen);
    kr_H(rhoprime, MLDSA_CRHBYTES, rsk->key, MLDSA_SEEDBYTES, rnd,
         MLDSA_RNDBYTES, mu, MLDSA_CRHBYTES);

    mld_polyvec_matrix_expand(&mat, rsk->rho);

    for (nonce = 0; nonce < GY_KR_MAX_ATTEMPTS; nonce++) {
        ret = kr_attempt(sig, mu, rhoprime, nonce, &mat, rsk);
        if (ret == GY_OK)
            break;
    }
    if (ret != GY_OK)
        ret = GY_ERR_CRYPTO; /* attempts exhausted */

    if (ret != GY_OK)
        gy_secure_zero(sig, MLDSA_CRYPTO_BYTES);
    gy_secure_zero(rhoprime, sizeof(rhoprime));
    return ret;
}

/* --------------------------------------------------------------------------
 * Backend table (gy_kr<set>_<backend>_backend).
 * -------------------------------------------------------------------------- */

const gy_kr_backend_t GY_KR_SYM(backend) = {
    GY_KR_SYM(keygen_base),
    GY_KR_SYM(randvk),
    GY_KR_SYM(randsk),
    GY_KR_SYM(sign),
};
