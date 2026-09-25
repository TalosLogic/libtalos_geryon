/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_PARAMS_H
#define GY_GROUP_PARAMS_H

#include <stddef.h>
#include <stdint.h>

#include "group_tier.h"

/*
 * System parameters for the classical group vertical (GROUP_SPEC section 2.2,
 * D-GRP-5): the NUMS generator set, the GroupMasterKey and its Derive into
 * GroupSecretParams, and the derived GroupPublicParams.  All of this is
 * [CPZ]-protocol material owned by geryon; libtalos_schnorr contributes only
 * primitives (hash_to_group, hash_to_scalar), so D-GRP-5 creates no new schnorr
 * work item.  Everything here is deterministic and reproducible from its
 * inputs, and is rederived on demand, never cached (D-GRP-7).
 */

/*
 * The 20 NUMS generators (section 2.2 item 1): the full [CPZ] section 3.1 MAC
 * set at n = 4 plus the section 5.8 system additions.  The index order is the
 * frozen seed-string order (section 2.2 item 2); the three unused G_mi
 * (m2..m4 for the ProfileKey scheme are unused, but m1..m4 are all derived for
 * scheme fidelity).  Do not reorder: the ordinal is not itself hashed, but the
 * struct layout and the KAT vectors depend on it.
 */
enum {
    GY_GEN_W = 0,
    GY_GEN_WPRIME,
    GY_GEN_X0,
    GY_GEN_X1,
    GY_GEN_Y1,
    GY_GEN_Y2,
    GY_GEN_Y3,
    GY_GEN_Y4,
    GY_GEN_M1,
    GY_GEN_M2,
    GY_GEN_M3,
    GY_GEN_M4,
    GY_GEN_V,
    GY_GEN_A1,
    GY_GEN_A2,
    GY_GEN_B1,
    GY_GEN_B2,
    GY_GEN_J1,
    GY_GEN_J2,
    GY_GEN_J3,
    GY_GROUP_GEN_COUNT
};

/* The NUMS generator set for one tier: GY_GROUP_GEN_COUNT points, each
 * tier->point_len bytes (leading bytes; the tail is unused on the 255 tier). */
struct gy_group_generators {
    uint8_t g[GY_GROUP_GEN_COUNT][GY_GROUP_POINT_MAX];
};

/* GroupSecretParams = (a1, a2, b1, b2) (section 3.4), rederived from the
 * GroupMasterKey via Derive, never cached (D-GRP-7).  Secret; zeroize after
 * use with gy_group_secret_clear(). */
struct gy_group_secret_params {
    uint8_t a1[GY_GROUP_SCALAR_MAX];
    uint8_t a2[GY_GROUP_SCALAR_MAX];
    uint8_t b1[GY_GROUP_SCALAR_MAX];
    uint8_t b2[GY_GROUP_SCALAR_MAX];
};

/* GroupPublicParams = (A, B) with A = G_a1^a1 G_a2^a2 and B = G_b1^b1 G_b2^b2
 * (section 3.4).  Public; the group's server-registered representation. */
struct gy_group_public_params {
    uint8_t A[GY_GROUP_POINT_MAX];
    uint8_t B[GY_GROUP_POINT_MAX];
};

/*
 * Derive the 20 NUMS generators for the tier (section 2.2 item 2):
 * G_<name> = hash_to_group("geryon.1.<suite_name>.sysparams.<name>", index 0).
 * Every suite gets a structurally distinct generator set.  Returns GY_OK or a
 * negative code; gens is left partially written on failure (caller discards).
 */
int gy_group_generators_derive(const struct gy_group_tier *tier,
                               struct gy_group_generators *gens);

/*
 * Generate a fresh GroupMasterKey: tier->master_key_len (2*kappa) random bytes
 * from core/ rng (section 2.2 item 3).  out must hold master_key_len bytes.
 */
int gy_group_master_key(const struct gy_group_tier *tier, uint8_t *out);

/*
 * Derive GroupSecretParams (a1, a2, b1, b2) from a GroupMasterKey (section 2.2
 * item 3, section 6.2).  gmk_len must equal tier->master_key_len.  One HKDF
 * expansion per encryption scheme (uid -> (a1,a2), pk -> (b1,b2)), okm
 * partitioned into wide segments and reduced to canonical scalars via the
 * provider hash_to_scalar.  Deterministic: the KAT anchor for group params.
 * Returns GY_OK or a negative code; sp is zeroized on failure.
 */
int gy_group_secret_derive(const struct gy_group_tier *tier, const uint8_t *gmk,
                           size_t gmk_len, struct gy_group_secret_params *sp);

/*
 * Derive GroupPublicParams (A, B) from the generators and GroupSecretParams
 * (section 3.4): A = G_a1^a1 G_a2^a2, B = G_b1^b1 G_b2^b2.  Returns GY_OK or a
 * negative code; pp is zeroized on failure.
 */
int gy_group_public_derive(const struct gy_group_tier *tier,
                           const struct gy_group_generators *gens,
                           const struct gy_group_secret_params *sp,
                           struct gy_group_public_params *pp);

/* Encoded GroupPublicParams size: the 3-byte object header plus (A, B). */
#define GY_GROUP_PUBLIC_ENC_MAX (3 + 2 * GY_GROUP_POINT_MAX)

/*
 * Canonically encode GroupPublicParams (A, B) as the tagged object
 * GY_GOBJ_GROUP_PUBLIC (section 3.4), for the founder to register a group with
 * the server.  out holds GY_GROUP_OBJ_HDR_LEN + 2*tier->point_len
 * bytes.  Returns GY_OK and sets *outlen, GY_ERR_TOOLONG on a short buffer, or
 * GY_ERR_ARG on bad input.
 */
int gy_group_public_params_encode(const struct gy_group_tier *tier,
                                  const struct gy_group_public_params *pp,
                                  uint8_t *out, size_t cap, size_t *outlen);

/*
 * Strictly parse a GY_GOBJ_GROUP_PUBLIC object into pp.  Returns GY_OK,
 * GY_ERR_VERIFY on any header or length mismatch, or GY_ERR_ARG on bad input.
 */
int gy_group_public_params_decode(const struct gy_group_tier *tier,
                                  struct gy_group_public_params *pp,
                                  const uint8_t *in, size_t len);

/* Zeroize GroupSecretParams (part of the protocol, not cleanup, D-GRP-7). */
void gy_group_secret_clear(struct gy_group_secret_params *sp);

#endif /* GY_GROUP_PARAMS_H */
