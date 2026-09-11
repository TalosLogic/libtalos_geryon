/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_CRED_H
#define GY_GROUP_CRED_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES, attribute assembly */
#include "group_mac.h"    /* mac tag, ServerSecretParams/PublicParams */
#include "group_params.h" /* generators */
#include "group_tier.h"
#include "group_wire.h" /* GY_GROUP_OBJ_HDR_LEN, object-type registry */

/*
 * AuthCredential issuance and its correctness proof (GROUP_SPEC section 5.1,
 * [CPZ] section 3.2/5.9), GER-M8-04.  Non-blind issuance: the issuer MACs the
 * AuthCredential attributes (M1, M2, M3) under sk_A and proves the MAC is
 * consistent with the published ServerPublicParams iparams_A, so a malicious
 * issuer cannot hand out a credential keyed to anything other than iparams_A.
 *
 * pi_I is a single sound conjunction proof (the shared-per-witness-nonce
 * gen_*_conj family, D-GRP-1) over k = 7 witnesses (w, wprime, x0, x1, y1, y2,
 * y3) and m = 3 equations, per section 5.1:
 *
 *   eq0  C_W_A = G_w^w G_wprime^wprime
 *   eq1  G_V / I_A = G_x0^x0 G_x1^x1 G_y1^y1 G_y2^y2 G_y3^y3
 *   eq2  V = G_w^w U^x0 (U^t)^x1 M1^y1 M2^y2 M3^y3
 *
 * FS binding (frozen at first published KATs): UserID = "geryon-group-server"
 * (section 5.0), OtherInfo = the D-GEN-3 domain "geryon.1.<suite>.pi_I" (the
 * proof-type label folded with the full suite_id, D-GRP-3).  t and U are public
 * MAC outputs; U^t is recomputed by both sides.
 */

#define GY_GROUP_PI_I_K 7
#define GY_GROUP_PI_I_M 3

/*
 * AuthCredentialResponse (section 3.2): the MAC (t, U, V) plus the issuance
 * proof pi_I = (proof_V[m], proof_r[k]).  Sent issuer -> user; the user verifies
 * pi_I and stores (t, U, V) as its AuthCredential (D-GRP-7).
 */
struct gy_group_auth_response {
    struct gy_group_mac_tag mac;
    uint8_t proof_V[GY_GROUP_PI_I_M][GY_GROUP_POINT_MAX];
    uint8_t proof_r[GY_GROUP_PI_I_K][GY_GROUP_SCALAR_MAX];
};

/*
 * Issue an AuthCredential for (uid, redemption date) under sk_A (n_bound must be
 * GY_GROUP_ATTR_AUTH = 3): MAC the attributes (M1, M2, M3) and produce pi_I.
 * date must be day-aligned (section 9 item 6) or GY_ERR_ARG is returned.  The
 * MAC randomness (t, u) and the proof nonces are drawn internally.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
int gy_group_auth_issue(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const struct gy_group_server_secret *sk_A,
                        const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                        struct gy_group_auth_response *out);

/*
 * User-side verification (section 5.1): recompute (M1, M2, M3) from the user's
 * OWN uid and the requested date, rebuild the pi_I statement from the public
 * ServerPublicParams iparams_A (pp_A) and the response's (t, U, V), and verify
 * pi_I.  No secret key is used.  Returns GY_OK if valid, GY_ERR_VERIFY if the
 * proof fails, GY_ERR_ARG on bad input (incl. a non-day-aligned date).
 */
int gy_group_auth_verify(const struct gy_group_tier *tier,
                         const struct gy_group_generators *gens,
                         const struct gy_group_server_public *pp_A,
                         const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                         const struct gy_group_auth_response *resp);

/* ------------------------------------------------------------------------- *
 * Canonical encoding (GROUP_SPEC section 9): a top-level tagged object,
 * header || t || U || V || proof_V[0..m) || proof_r[0..k), all tier-width.
 * ------------------------------------------------------------------------- */

#define GY_GROUP_AUTH_RESPONSE_ENC_MAX                                         \
    (GY_GROUP_OBJ_HDR_LEN + GY_GROUP_SCALAR_MAX + 2 * GY_GROUP_POINT_MAX +     \
     GY_GROUP_PI_I_M * GY_GROUP_POINT_MAX +                                    \
     GY_GROUP_PI_I_K * GY_GROUP_SCALAR_MAX)

int gy_group_auth_response_encode(const struct gy_group_tier *tier,
                                  const struct gy_group_auth_response *resp,
                                  uint8_t *out, size_t cap, size_t *outlen);

int gy_group_auth_response_decode(const struct gy_group_tier *tier,
                                  struct gy_group_auth_response *resp,
                                  const uint8_t *in, size_t len);

#endif /* GY_GROUP_CRED_H */
