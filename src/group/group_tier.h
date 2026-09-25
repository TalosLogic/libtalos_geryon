/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_TIER_H
#define GY_GROUP_TIER_H

#include <stddef.h>
#include <stdint.h>

/*
 * Proof-group tier binding for the classical private-group vertical
 * (GROUP_SPEC section 2.1, D-GRP-3).  The group system runs over libtalos_schnorr,
 * which exposes two compile-time provider families (talos_schnorr_255_* and
 * talos_schnorr_448_*) with no runtime tier argument.  This descriptor is the
 * one indirection through which the rest of the vertical reaches the right
 * family, mirroring core/suite.h's gy_suite_desc (D-GEN-7): group code operates
 * on a const struct gy_group_tier * and never names a _255_/_448_ symbol
 * directly.
 *
 * The table is static const rodata (group_tier.c); dispatch keys on the public
 * classical suite id, so there is no constant-time concern.  Only the two
 * CLASSICAL suites hold objects of this system: geryon_c25519 -> Ristretto255,
 * geryon_c448 -> Decaf448.  Hybrid suites use the QSPGS type (QSPGS_SPEC.md) and
 * gy_group_tier_for() returns NULL for them (structural exclusion, D-GRP-3).
 */

/*
 * Compile-time maxima across the two classical tiers; the 448 tier sets them.
 * Callers stack-allocate to these and operate on the tier's actual lengths, no
 * dynamic allocation.  GroupMasterKey is 2*kappa bytes (kappa = 16 on 255,
 * 28 on 448), which coincides with the point/scalar width on each tier.
 */
#define GY_GROUP_POINT_MAX 56
#define GY_GROUP_SCALAR_MAX 56
#define GY_GROUP_MASTER_KEY_MAX 56

/* Per-tier GroupMasterKey widths (2*kappa); the 448 value is the max above.
 * Exposed for compile-time buffer-bound assertions (the key-distribution
 * envelope bound in geryon_group.h). */
#define GY_GROUP_MASTER_KEY_255 32
#define GY_GROUP_MASTER_KEY_448 56

/* ProfileKey decode fan-out on the 255 tier ([CPZ] section 6); 8 on 448. */
#define GY_GROUP_PK_MAX_CANDIDATES 64

/*
 * Conjunction-proof matrix dimensions (both tiers use TALOS_SCHNORR_<t>_MAX_K =
 * GEN_MAX_EQUATIONS = 8).  The group vertical normalizes every conj argument on
 * GY_GROUP_POINT_MAX / GY_GROUP_SCALAR_MAX widths and lets the per-tier adapters
 * repack to the provider's native point width (a no-op on 448, 56 -> 32 on 255).
 */
#define GY_GROUP_MAX_K 16
#define GY_GROUP_MAX_EQ 16

/*
 * One classical proof-group tier.  The op pointers are the libtalos_schnorr
 * provider wrappers; the fixed-size array parameters in schnorr's prototypes
 * decay to uint8_t * and assign to these generic pointer types with no cast,
 * exactly as core/suite.c relies on for gy_suite_desc.  Core-side HKDF/HMAC and
 * the tier hash are NOT duplicated here: group_params.c reaches them through
 * gy_suite_desc(suite_id) (GROUP_SPEC section 2.3 routes those to core/).
 */
struct gy_group_tier {
    uint8_t suite_id;      /* GY_SUITE_C25519 (0x01) or GY_SUITE_C448 (0x03). */
    uint8_t curve_type;    /* GY_CURVE_TYPE_* (also the point width). */
    size_t point_len;      /* 32 / 56 */
    size_t scalar_len;     /* 32 / 56 */
    size_t master_key_len; /* GroupMasterKey width, 2*kappa: 32 / 56. */
    size_t pk_max_candidates; /* ProfileKey decode fan-out: 64 / 8. */

    /* Hashing (provider). */
    int (*hash_to_group)(uint8_t *point, const uint8_t *seed, size_t seed_len,
                         uint32_t index);
    int (*hash_to_scalar)(uint8_t *s, const uint8_t *input, size_t input_len,
                          const uint8_t *dst, size_t dst_len);
    int (*hash_to_g1)(uint8_t *point, const uint8_t *seed, size_t seed_len);

    /* EncodeToG, encode direction (provider talos_encode_<t>_{uid,pk}): the
     * reversible group encodings of a 16-byte UID and a 32-byte ProfileKey,
     * each a single deterministic point. */
    int (*encode_uid)(uint8_t *point, const uint8_t *uid);
    int (*encode_pk)(uint8_t *point, const uint8_t *pk);

    /* EncodeToG, decode direction (verifiable encryption).  UID
     * decode is self-disambiguating (single answer).  ProfileKey decode returns
     * the full candidate list (ProfileKey is 32 bytes on both tiers, so the
     * candidate width is tier-uniform); *count is a public function of the
     * point and cap must be >= tier->pk_max_candidates.  geryon owns the
     * constant-time candidate-test loop over the returned list (group_venc.c),
     * never the provider's enumeration (D-GRP-8). */
    int (*decode_uid)(uint8_t *uid, const uint8_t *point);
    int (*decode_pk)(uint8_t (*candidates)[32], size_t *count, size_t cap,
                     const uint8_t *point);

    /* Scalar arithmetic (provider); mod l, all constant-time. */
    void (*scalar_random)(uint8_t *s);
    void (*scalar_add)(uint8_t *z, const uint8_t *x, const uint8_t *y);
    void (*scalar_mul)(uint8_t *z, const uint8_t *x, const uint8_t *y);
    void (*scalar_negate)(uint8_t *z, const uint8_t *x); /* z = -x mod l */
    int (*scalar_eq)(const uint8_t *s1, const uint8_t *s2);

    /* Point arithmetic (provider). */
    int (*point_add)(uint8_t *r, const uint8_t *p, const uint8_t *q);
    int (*point_sub)(uint8_t *r, const uint8_t *p, const uint8_t *q);
    int (*point_scalarmul)(uint8_t *out, const uint8_t *scalar,
                           const uint8_t *point);
    int (*point_eq)(const uint8_t *p1, const uint8_t *p2);

    /* Fixed-base scalar mult over the standard basepoint G: out = G^scalar
     * (provider sk_to_pk).  The algebraic MAC (group_mac.c) draws U = G^u for a
     * uniform group element; iparams and the MAC otherwise use variable-base
     * point_scalarmul against the NUMS generators. */
    int (*scalarmul_base)(uint8_t *out, const uint8_t *scalar);

    /*
     * Sound conjunction NIZK (provider gen_prove_conj / gen_verify_conj, the
     * shared per-witness-nonce family; NEVER the _masked family, which does not
     * link a witness across equations).  Arguments are normalized on the group
     * maxima (GY_GROUP_POINT_MAX / GY_GROUP_SCALAR_MAX, GY_GROUP_MAX_K); the
     * per-tier adapter repacks to the provider width.  Proves / verifies
     *   P[j] = prod_{i : mask[j][i]=1} gens[j][i]^{w_i}
     * with witness-indexed responses r[k].  user_id and other_info carry the
     * GROUP_SPEC section 5.0 role string and proof-type label.  Return 0 / OK
     * or negative.
     */
    int (*gen_prove_conj)(
        uint8_t V[][GY_GROUP_POINT_MAX], uint8_t r[][GY_GROUP_SCALAR_MAX],
        const uint8_t witness_mask[][GY_GROUP_MAX_K],
        const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
        const uint8_t P[][GY_GROUP_POINT_MAX],
        const uint8_t w[][GY_GROUP_SCALAR_MAX], size_t k, size_t m,
        const uint8_t *user_id, size_t user_id_len, const uint8_t *other_info,
        size_t other_info_len);
    int (*gen_verify_conj)(
        const uint8_t V[][GY_GROUP_POINT_MAX],
        const uint8_t r[][GY_GROUP_SCALAR_MAX],
        const uint8_t witness_mask[][GY_GROUP_MAX_K],
        const uint8_t gens[][GY_GROUP_MAX_K][GY_GROUP_POINT_MAX],
        const uint8_t P[][GY_GROUP_POINT_MAX], size_t k, size_t m,
        const uint8_t *user_id, size_t user_id_len, const uint8_t *other_info,
        size_t other_info_len);
};

/*
 * Look up the classical tier for a suite id, or NULL if the byte is not an
 * enabled CLASSICAL suite (hybrid suites and every other byte return NULL).
 * This is the sole tier-lookup function for the group vertical.
 */
const struct gy_group_tier *gy_group_tier_for(uint8_t suite_id);

#endif /* GY_GROUP_TIER_H */
