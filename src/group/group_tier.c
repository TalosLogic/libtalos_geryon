/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "group_tier.h"

#include "encode.h" /* GY_SUITE_*, GY_CURVE_TYPE_* */
#include "error.h"

#include "talos_encode.h"
#include "talos_schnorr_255.h"
#include "talos_schnorr_448.h"

/* ------------------------------------------------------------------------- *
 * Conjunction-proof adapters (GROUP_SPEC section 5).  The provider
 * gen_prove_conj / gen_verify_conj take matrices whose innermost dimension is
 * the tier point/scalar width (32 on 255, 56 on 448), so - unlike the 1-D vtable
 * ops - they cannot be assigned directly to a width-normalized function pointer.
 * These adapters accept the group maxima (GY_GROUP_POINT_MAX / _SCALAR_MAX,
 * GY_GROUP_MAX_K) and bridge to the native call: a direct cast on 448 (56 == 56),
 * a leading-bytes repack on 255 (56 -> 32).  witness_mask is byte-per-slot and
 * MAX_K = 8 on both tiers, so it always casts through.
 * ------------------------------------------------------------------------- */

/* The MAX_K dimension is 8 on both tiers; assert the group constant agrees so a
 * future provider change is caught at compile time, not silently mis-strided. */
_Static_assert(GY_GROUP_MAX_K == TALOS_SCHNORR_255_MAX_K &&
                   GY_GROUP_MAX_K == TALOS_SCHNORR_448_MAX_K,
               "conj matrix width GY_GROUP_MAX_K must match both providers");

static int
gy_conj_prove_448(uint8_t V[][GY_GROUP_POINT_MAX],
                  uint8_t r[][GY_GROUP_SCALAR_MAX],
                  const uint8_t witness_mask[][GY_GROUP_MAX_K],
                  const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
                  const uint8_t P[][GY_GROUP_POINT_MAX],
                  const uint8_t w[][GY_GROUP_SCALAR_MAX], size_t k, size_t m,
                  const uint8_t *user_id, size_t user_id_len,
                  const uint8_t *other_info, size_t other_info_len)
{
    /* 448 point/scalar width equals GY_GROUP_POINT_MAX (56); cast through. */
    return talos_schnorr_448_gen_prove_conj(
        (uint8_t(*)[TALOS_SCHNORR_448_POINT_BYTES])V,
        (uint8_t(*)[TALOS_SCHNORR_448_SCALAR_BYTES])r,
        (const uint8_t(*)[TALOS_SCHNORR_448_MAX_K])witness_mask,
        (const uint8_t(*)[TALOS_SCHNORR_448_MAX_K]
                         [TALOS_SCHNORR_448_POINT_BYTES])gens,
        (const uint8_t(*)[TALOS_SCHNORR_448_POINT_BYTES])P,
        (const uint8_t(*)[TALOS_SCHNORR_448_SCALAR_BYTES])w, k, m, user_id,
        user_id_len, other_info, other_info_len);
}

static int
gy_conj_verify_448(const uint8_t V[][GY_GROUP_POINT_MAX],
                   const uint8_t r[][GY_GROUP_SCALAR_MAX],
                   const uint8_t witness_mask[][GY_GROUP_MAX_K],
                   const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
                   const uint8_t P[][GY_GROUP_POINT_MAX], size_t k, size_t m,
                   const uint8_t *user_id, size_t user_id_len,
                   const uint8_t *other_info, size_t other_info_len)
{
    return talos_schnorr_448_gen_verify_conj(
        (const uint8_t(*)[TALOS_SCHNORR_448_POINT_BYTES])V,
        (const uint8_t(*)[TALOS_SCHNORR_448_SCALAR_BYTES])r,
        (const uint8_t(*)[TALOS_SCHNORR_448_MAX_K])witness_mask,
        (const uint8_t(*)[TALOS_SCHNORR_448_MAX_K]
                         [TALOS_SCHNORR_448_POINT_BYTES])gens,
        (const uint8_t(*)[TALOS_SCHNORR_448_POINT_BYTES])P, k, m, user_id,
        user_id_len, other_info, other_info_len);
}

/* Repack a group-width point/scalar matrix down to the 255 native width (32),
 * copying the leading 32 bytes of each slot.  Helpers keep the two 255 adapters
 * short; m, k <= 8. */
static void
pack255_pts(uint8_t dst[][TALOS_SCHNORR_255_POINT_BYTES],
            const uint8_t src[][GY_GROUP_POINT_MAX], size_t n)
{
    for (size_t i = 0; i < n; i++)
        memcpy(dst[i], src[i], TALOS_SCHNORR_255_POINT_BYTES);
}

static int
gy_conj_prove_255(uint8_t V[][GY_GROUP_POINT_MAX],
                  uint8_t r[][GY_GROUP_SCALAR_MAX],
                  const uint8_t witness_mask[][GY_GROUP_MAX_K],
                  const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
                  const uint8_t P[][GY_GROUP_POINT_MAX],
                  const uint8_t w[][GY_GROUP_SCALAR_MAX], size_t k, size_t m,
                  const uint8_t *user_id, size_t user_id_len,
                  const uint8_t *other_info, size_t other_info_len)
{
    uint8_t g[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_MAX_K]
             [TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t p[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t v[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t ww[GY_GROUP_MAX_K][TALOS_SCHNORR_255_SCALAR_BYTES];
    uint8_t rr[GY_GROUP_MAX_K][TALOS_SCHNORR_255_SCALAR_BYTES];
    int rc;

    if (k > GY_GROUP_MAX_K || m > GY_GROUP_MAX_EQ)
        return GY_ERR_ARG;

    for (size_t j = 0; j < m; j++)
        pack255_pts(g[j], gens[j], k);
    pack255_pts(p, P, m);
    pack255_pts(ww, w, k);

    rc = talos_schnorr_255_gen_prove_conj(
        v, rr, (const uint8_t(*)[TALOS_SCHNORR_255_MAX_K])witness_mask,
        (const uint8_t(*)[TALOS_SCHNORR_255_MAX_K]
                         [TALOS_SCHNORR_255_POINT_BYTES])g,
        (const uint8_t(*)[TALOS_SCHNORR_255_POINT_BYTES])p,
        (const uint8_t(*)[TALOS_SCHNORR_255_SCALAR_BYTES])ww, k, m, user_id,
        user_id_len, other_info, other_info_len);
    if (rc != 0)
        return rc;

    /* Widen outputs back to GY_GROUP_POINT_MAX, zeroing the unused tail. */
    for (size_t j = 0; j < m; j++) {
        memset(V[j], 0, GY_GROUP_POINT_MAX);
        memcpy(V[j], v[j], TALOS_SCHNORR_255_POINT_BYTES);
    }
    for (size_t i = 0; i < k; i++) {
        memset(r[i], 0, GY_GROUP_SCALAR_MAX);
        memcpy(r[i], rr[i], TALOS_SCHNORR_255_SCALAR_BYTES);
    }
    return 0;
}

static int
gy_conj_verify_255(const uint8_t V[][GY_GROUP_POINT_MAX],
                   const uint8_t r[][GY_GROUP_SCALAR_MAX],
                   const uint8_t witness_mask[][GY_GROUP_MAX_K],
                   const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
                   const uint8_t P[][GY_GROUP_POINT_MAX], size_t k, size_t m,
                   const uint8_t *user_id, size_t user_id_len,
                   const uint8_t *other_info, size_t other_info_len)
{
    uint8_t g[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_MAX_K]
             [TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t p[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t v[GY_GROUP_MAX_EQ][TALOS_SCHNORR_255_POINT_BYTES];
    uint8_t rr[GY_GROUP_MAX_K][TALOS_SCHNORR_255_SCALAR_BYTES];

    if (k > GY_GROUP_MAX_K || m > GY_GROUP_MAX_EQ)
        return GY_ERR_ARG;

    for (size_t j = 0; j < m; j++)
        pack255_pts(g[j], gens[j], k);
    pack255_pts(p, P, m);
    pack255_pts(v, V, m);
    pack255_pts(rr, r, k);

    return talos_schnorr_255_gen_verify_conj(
        (const uint8_t(*)[TALOS_SCHNORR_255_POINT_BYTES])v,
        (const uint8_t(*)[TALOS_SCHNORR_255_SCALAR_BYTES])rr,
        (const uint8_t(*)[TALOS_SCHNORR_255_MAX_K])witness_mask,
        (const uint8_t(*)[TALOS_SCHNORR_255_MAX_K]
                         [TALOS_SCHNORR_255_POINT_BYTES])g,
        (const uint8_t(*)[TALOS_SCHNORR_255_POINT_BYTES])p, k, m, user_id,
        user_id_len, other_info, other_info_len);
}

/*
 * The two classical proof-group tiers (GROUP_SPEC section 2.1, D-GRP-3).  Ops are
 * the libtalos_schnorr provider wrappers; schnorr's fixed-size array parameters
 * adjust to the descriptor's uint8_t * pointer types with no cast.  Hybrid
 * suites hold no objects of this system and are absent from the table.
 */
static const struct gy_group_tier gy_group_tiers[] = {
    {
        .suite_id = GY_SUITE_C25519,
        .curve_type = GY_CURVE_TYPE_25519,
        .point_len = TALOS_SCHNORR_255_POINT_BYTES,
        .scalar_len = TALOS_SCHNORR_255_SCALAR_BYTES,
        .master_key_len = 32,
        .pk_max_candidates = TALOS_ENCODE_255_MAX_CANDIDATES,

        .hash_to_group = talos_schnorr_255_hash_to_group,
        .hash_to_scalar = talos_schnorr_255_hash_to_scalar,
        .hash_to_g1 = talos_hash_to_g1_255,
        .encode_uid = talos_encode_255_uid,
        .encode_pk = talos_encode_255_pk,
        .decode_uid = talos_decode_255_uid,
        .decode_pk = talos_decode_255_pk,

        .scalar_random = talos_schnorr_255_scalar_random,
        .scalar_add = talos_schnorr_255_scalar_add,
        .scalar_mul = talos_schnorr_255_scalar_mul,
        .scalar_negate = talos_schnorr_255_scalar_negate,
        .scalar_eq = talos_schnorr_255_scalar_eq,

        .point_add = talos_schnorr_255_point_add,
        .point_sub = talos_schnorr_255_point_sub,
        .point_scalarmul = talos_schnorr_255_point_scalarmul,
        .point_eq = talos_schnorr_255_point_eq,
        .scalarmul_base = talos_schnorr_255_sk_to_pk,
        .gen_prove_conj = gy_conj_prove_255,
        .gen_verify_conj = gy_conj_verify_255,
    },
    {
        .suite_id = GY_SUITE_C448,
        .curve_type = GY_CURVE_TYPE_448,
        .point_len = TALOS_SCHNORR_448_POINT_BYTES,
        .scalar_len = TALOS_SCHNORR_448_SCALAR_BYTES,
        .master_key_len = 56,
        .pk_max_candidates = TALOS_ENCODE_448_MAX_CANDIDATES,

        .hash_to_group = talos_schnorr_448_hash_to_group,
        .hash_to_scalar = talos_schnorr_448_hash_to_scalar,
        .hash_to_g1 = talos_hash_to_g1_448,
        .encode_uid = talos_encode_448_uid,
        .encode_pk = talos_encode_448_pk,
        .decode_uid = talos_decode_448_uid,
        .decode_pk = talos_decode_448_pk,

        .scalar_random = talos_schnorr_448_scalar_random,
        .scalar_add = talos_schnorr_448_scalar_add,
        .scalar_mul = talos_schnorr_448_scalar_mul,
        .scalar_negate = talos_schnorr_448_scalar_negate,
        .scalar_eq = talos_schnorr_448_scalar_eq,

        .point_add = talos_schnorr_448_point_add,
        .point_sub = talos_schnorr_448_point_sub,
        .point_scalarmul = talos_schnorr_448_point_scalarmul,
        .point_eq = talos_schnorr_448_point_eq,
        .scalarmul_base = talos_schnorr_448_sk_to_pk,
        .gen_prove_conj = gy_conj_prove_448,
        .gen_verify_conj = gy_conj_verify_448,
    },
};

const struct gy_group_tier *
gy_group_tier_for(uint8_t suite_id)
{
    size_t i;

    for (i = 0; i < sizeof(gy_group_tiers) / sizeof(gy_group_tiers[0]); i++) {
        if (gy_group_tiers[i].suite_id == suite_id)
            return &gy_group_tiers[i];
    }
    return NULL;
}
