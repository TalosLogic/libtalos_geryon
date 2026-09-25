/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_MAC_H
#define GY_GROUP_MAC_H

#include <stddef.h>
#include <stdint.h>

#include "group_params.h" /* struct gy_group_generators, GY_GEN_* */
#include "group_tier.h"

/*
 * The [CPZ] section 3.1 keyed algebraic MAC (GROUP_SPEC section 4), the
 * primitive under both credential families.  This layer is deliberately
 * credential-agnostic: it operates on an array of group-element attributes Mi
 * and a bound-position count n', exactly the section 4.1 model.  The families
 * (AuthCredential, ProfileKeyCredential) live in the credential
 * layer, where the attribute vectors are assembled (scalar
 * attributes such as the auth redemption date are
 * pre-converted by the caller to their group element G_mi^mi before entering
 * the MAC).  No protocol logic, proofs, or wire objects beyond section 3.1 here.
 *
 * All arithmetic is in the section 2.1 proof group of the tier; every point is
 * tier->point_len bytes and every scalar tier->scalar_len bytes (leading bytes;
 * the tail is unused on the 255 tier and zeroed for byte-determinism, as in
 * group_params.c).  Objects are rederived, never cached (D-GRP-7).
 */

/* n = 4 attribute positions (section 4.1); the profile family binds all four,
 * the auth family the first three (section 4.4). */
#define GY_GROUP_MAC_ATTRS 4

/*
 * One MAC secret key sk (section 4.2): the eight scalars (w, wprime, x0, x1,
 * y1..y4) plus the precomputed W = G_w^w that section 4.2 names "part of sk".
 * n_bound is the number of attribute positions this key BINDS (section 4.4):
 * 4 for sk_P (ProfileKeyCredentials), 3 for sk_A (AuthCredentials, y4 sampled
 * for the uniform 16-scalar ServerSecretParams shape but bound by no equation).
 * Secret material (D-GEN-4); zeroize with gy_group_server_secret_clear().
 * ServerSecretParams (section 3.1) is two of these, sk_A and sk_P.
 */
struct gy_group_server_secret {
    uint8_t w[GY_GROUP_SCALAR_MAX];
    uint8_t wprime[GY_GROUP_SCALAR_MAX];
    uint8_t x0[GY_GROUP_SCALAR_MAX];
    uint8_t x1[GY_GROUP_SCALAR_MAX];
    uint8_t y[GY_GROUP_MAC_ATTRS][GY_GROUP_SCALAR_MAX];
    uint8_t W[GY_GROUP_POINT_MAX];
    uint8_t n_bound;
};

/*
 * The issuer parameters iparams = (C_W, I) for one key (section 4.2), the
 * public half of ServerSecretParams:
 *   C_W = G_w^w G_wprime^wprime
 *   I   = G_V / (G_x0^x0 G_x1^x1 G_y1^y1 ... G_yn'^yn')
 * ServerPublicParams (section 3.1) is the pair (iparams_A, iparams_P).  Public.
 */
struct gy_group_server_public {
    uint8_t C_W[GY_GROUP_POINT_MAX];
    uint8_t I[GY_GROUP_POINT_MAX];
};

/*
 * A MAC tag (t, U, V) (section 4.3).  Appears only nested inside credential
 * responses; carries no standalone object header.
 */
struct gy_group_mac_tag {
    uint8_t t[GY_GROUP_SCALAR_MAX];
    uint8_t U[GY_GROUP_POINT_MAX];
    uint8_t V[GY_GROUP_POINT_MAX];
};

/*
 * KeyGen (section 4.2, D-GRP-5): sample the full eight-scalar sk uniformly from
 * core/ rng and precompute W = G_w^w.  n_bound in {3, 4} selects the family key
 * shape (section 4.4); it changes which positions iparams and the MAC bind, not
 * how many scalars are drawn (always eight, for the uniform ServerSecretParams
 * shape).  There is no production seed path; deterministic KATs use
 * gy_group_server_keygen_scalars.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_server_keygen(const struct gy_group_tier *tier,
                           const struct gy_group_generators *gens,
                           unsigned n_bound, struct gy_group_server_secret *sk);

/*
 * Deterministic KeyGen core taking the eight scalars explicitly (w, wprime, x0,
 * x1, y1..y4, each tier->scalar_len canonical bytes, in the array order above).
 * Precomputes W and stores n_bound.  Exposed for known-answer tests ONLY;
 * production must use gy_group_server_keygen so the key is unpredictable.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_server_keygen_scalars(
    const struct gy_group_tier *tier, const struct gy_group_generators *gens,
    unsigned n_bound, const uint8_t scalars[8][GY_GROUP_SCALAR_MAX],
    struct gy_group_server_secret *sk);

/*
 * Derive ServerPublicParams iparams (C_W, I) from a secret key and the tier
 * generators (section 4.2).  I binds exactly sk->n_bound of the y positions.
 * Returns GY_OK or a negative GY_ERR_*; pp is zeroized on failure.
 */
int gy_group_server_public_from_secret(const struct gy_group_tier *tier,
                                       const struct gy_group_generators *gens,
                                       const struct gy_group_server_secret *sk,
                                       struct gy_group_server_public *pp);

/*
 * MAC (section 4.3): V = W U^(x0+x1 t) prod_{i=1..n'} Mi^yi with t random in Zq
 * and U = G^u for a fresh random u (uniform in G).  M points to n_attr group
 * elements (the bound attributes, in position order); n_attr must equal
 * sk->n_bound.  Returns GY_OK or a negative GY_ERR_*.  Deterministic KATs use
 * gy_group_mac_tu.
 */
int gy_group_mac(const struct gy_group_tier *tier,
                 const struct gy_group_server_secret *sk,
                 const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                 struct gy_group_mac_tag *tag);

/*
 * Deterministic MAC core taking the tag scalar t and the base exponent u
 * explicitly (U = G^u), each tier->scalar_len canonical bytes.  Exposed for
 * known-answer tests ONLY; production must use gy_group_mac so t and u are
 * unpredictable.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_mac_tu(const struct gy_group_tier *tier,
                    const struct gy_group_server_secret *sk,
                    const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                    const uint8_t *t, const uint8_t *u,
                    struct gy_group_mac_tag *tag);

/*
 * Verify (section 4.3): recompute V' = W U^(x0+x1 t) prod Mi^yi from the tag's
 * (t, U) and compare to the tag's V under constant-time canonical-encoding
 * comparison.  n_attr must equal sk->n_bound.  Returns GY_OK if the tag is
 * valid, GY_ERR_VERIFY on mismatch, or a negative GY_ERR_* on bad input.
 */
int gy_group_verify(const struct gy_group_tier *tier,
                    const struct gy_group_server_secret *sk,
                    const uint8_t (*M)[GY_GROUP_POINT_MAX], size_t n_attr,
                    const struct gy_group_mac_tag *tag);

/* Zeroize a ServerSecretParams key (part of the protocol, D-GRP-7). */
void gy_group_server_secret_clear(struct gy_group_server_secret *sk);

/* ------------------------------------------------------------------------- *
 * Canonical byte encodings (GROUP_SPEC section 9).  Points and scalars are the
 * tier's RFC 9496 / fixed-width encodings, concatenated with no TLV; parsing is
 * strict (length-exact, no trailing bytes).  ServerPublicParams is a top-level
 * client-server object and carries the section 9 item 3 object header; the MAC
 * tag is only ever nested and is written untagged.  ServerSecretParams is
 * server-internal storage (never on the client-server wire) and is likewise
 * untagged.
 * ------------------------------------------------------------------------- */

/* Encoded sizes for the 448 tier (the maximum); callers pass the tier length. */
#define GY_GROUP_SERVER_PUBLIC_ENC_MAX (3 + 2 * GY_GROUP_POINT_MAX)
#define GY_GROUP_MAC_TAG_ENC_MAX (GY_GROUP_SCALAR_MAX + 2 * GY_GROUP_POINT_MAX)

/*
 * Encode ServerPublicParams: object header (section 9 item 3) || C_W || I.
 * Writes 3 + 2*tier->point_len bytes to out; *outlen receives the count.
 * Returns GY_OK, GY_ERR_ARG on bad input, or GY_ERR_TOOLONG if cap is short.
 */
int gy_group_server_public_encode(const struct gy_group_tier *tier,
                                  const struct gy_group_server_public *pp,
                                  uint8_t *out, size_t cap, size_t *outlen);

/*
 * Decode ServerPublicParams, validating the object header against the tier.
 * len must equal the exact encoded length (no trailing bytes).  Returns GY_OK,
 * GY_ERR_ARG on bad input, or GY_ERR_VERIFY on a header/length mismatch.
 */
int gy_group_server_public_decode(const struct gy_group_tier *tier,
                                  struct gy_group_server_public *pp,
                                  const uint8_t *in, size_t len);

/*
 * Encode a MAC tag (untagged, nested): t || U || V, scalar_len + 2*point_len
 * bytes.  Returns GY_OK, GY_ERR_ARG, or GY_ERR_TOOLONG.
 */
int gy_group_mac_tag_encode(const struct gy_group_tier *tier,
                            const struct gy_group_mac_tag *tag, uint8_t *out,
                            size_t cap, size_t *outlen);

/*
 * Decode a MAC tag (untagged).  len must equal the exact encoded length.
 * Returns GY_OK, GY_ERR_ARG, or GY_ERR_VERIFY on a length mismatch.
 */
int gy_group_mac_tag_decode(const struct gy_group_tier *tier,
                            struct gy_group_mac_tag *tag, const uint8_t *in,
                            size_t len);

#endif /* GY_GROUP_MAC_H */
