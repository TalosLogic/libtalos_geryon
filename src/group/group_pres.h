/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_PRES_H
#define GY_GROUP_PRES_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES */
#include "group_mac.h"    /* mac tag, ServerSecretParams/PublicParams */
#include "group_params.h" /* generators, GroupSecretParams, GroupPublicParams */
#include "group_tier.h"
#include "group_wire.h"

/*
 * AuthCredentialPresentation pi_A (GROUP_SPEC section 5.2 / 5.2.1, [CPZ]
 * section 5.12).  A group member presents its AuthCredential (t,U,V)
 * to the server, hiding M1, M2 (its UID's group attributes) while revealing the
 * redemption date, and jointly proving the credential is valid AND that the
 * attached UidCiphertext (E_A1, E_A2) encrypts the same UID (the section 6.5
 * encryption predicate).  Deniable: no transcript signature.
 *
 * pi_A is a single sound conjunction proof (gen_*_conj) over k = 6 witnesses
 * (z, a1, a2, z0, z1, t) and m = 6 equations (section 5.2.1):
 *
 *   eq0  Z = I_A^z
 *   eq1  C_x1 = C_x0^t G_x0^z0 G_x1^z
 *   eq2  A = G_a1^a1 G_a2^a2
 *   eq3  C_y2 / E_A2 = G_y2^z / E_A1^a2
 *   eq4  E_A1 = C_y1^a1 G_y1^z1
 *   eq5  C_y3 = G_y3^z
 *
 * Z is never transmitted: the prover sets P0 = I_A^z, the verifier recomputes
 * Z = C_V / (W_A C_x0^x0 C_x1^x1 C_y1^y1 C_y2^y2 (C_y3 G_m3^m3)^y3) from sk_A and
 * the revealed date; the two agree iff the credential is valid, so the FS check
 * IS the credential check (section 5.2).  FS binding: UserID =
 * "geryon-group-member" (section 5.0), OtherInfo = "geryon.1.<suite>.pi_A".
 */

#define GY_GROUP_PI_A_K 6
#define GY_GROUP_PI_A_M 6

/*
 * AuthCredentialPresentation (section 3.2): the commitments, the UidCiphertext,
 * the revealed redemption date, and pi_A.  Sent member -> server.
 */
struct gy_group_auth_presentation {
    uint8_t C_x0[GY_GROUP_POINT_MAX];
    uint8_t C_x1[GY_GROUP_POINT_MAX];
    uint8_t C_y1[GY_GROUP_POINT_MAX];
    uint8_t C_y2[GY_GROUP_POINT_MAX];
    uint8_t C_y3[GY_GROUP_POINT_MAX];
    uint8_t C_V[GY_GROUP_POINT_MAX];
    uint8_t E_A1[GY_GROUP_POINT_MAX];
    uint8_t E_A2[GY_GROUP_POINT_MAX];
    uint64_t date;
    uint8_t proof_V[GY_GROUP_PI_A_M][GY_GROUP_POINT_MAX];
    uint8_t proof_r[GY_GROUP_PI_A_K][GY_GROUP_SCALAR_MAX];
};

/*
 * Produce an AuthCredentialPresentation for the member's credential (cred =
 * stored MAC (t,U,V)), UID, and redemption date.  sp holds the GroupSecretParams
 * (a1, a2 used); pp_pub the GroupPublicParams (A); pp_srv the ServerPublicParams
 * (I_A).  date must be day-aligned.  Randomness (z and the proof nonces) is
 * internal.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_auth_present(const struct gy_group_tier *tier,
                          const struct gy_group_generators *gens,
                          const struct gy_group_secret_params *sp,
                          const struct gy_group_public_params *pp_pub,
                          const struct gy_group_server_public *pp_srv,
                          const struct gy_group_mac_tag *cred,
                          const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                          struct gy_group_auth_presentation *out);

/*
 * Server-side verification: recompute Z from sk_A and the revealed date, rebuild
 * the pi_A statement, and verify.  pp_pub provides A.  Returns GY_OK if valid
 * (the deployer then receives the authenticated (E_A1, E_A2)), GY_ERR_VERIFY on
 * failure, GY_ERR_* on bad input (incl. a non-day-aligned date).
 */
int gy_group_auth_present_verify(const struct gy_group_tier *tier,
                                 const struct gy_group_generators *gens,
                                 const struct gy_group_server_secret *sk_A,
                                 const struct gy_group_public_params *pp_pub,
                                 const struct gy_group_auth_presentation *pres);

/* ------------------------------------------------------------------------- *
 * Canonical encoding (GROUP_SPEC section 9): a tagged top-level object,
 * header || C_x0 C_x1 C_y1 C_y2 C_y3 C_V E_A1 E_A2 || date_be64 ||
 * proof_V[0..m) || proof_r[0..k).
 * ------------------------------------------------------------------------- */

#define GY_GROUP_AUTH_PRES_ENC_MAX                                             \
    (GY_GROUP_OBJ_HDR_LEN + 8 * GY_GROUP_POINT_MAX + 8 +                       \
     GY_GROUP_PI_A_M * GY_GROUP_POINT_MAX +                                    \
     GY_GROUP_PI_A_K * GY_GROUP_SCALAR_MAX)

int gy_group_auth_pres_encode(const struct gy_group_tier *tier,
                              const struct gy_group_auth_presentation *pres,
                              uint8_t *out, size_t cap, size_t *outlen);
int gy_group_auth_pres_decode(const struct gy_group_tier *tier,
                              struct gy_group_auth_presentation *pres,
                              const uint8_t *in, size_t len);

/* ------------------------------------------------------------------------- *
 * ProfileKeyCredentialPresentation pi_P (GROUP_SPEC section 5.2.2, [CPZ]
 * section 5.13).  A member presents its ProfileKeyCredential (t,U,V) with ALL
 * four attributes (M1..M4) hidden, and the encryption predicates for BOTH the
 * UidCiphertext (E_A1,E_A2) and the ProfileKeyCiphertext (E_B1,E_B2).  Single
 * sound conjunction proof over k = 9 witnesses (z, a1, a2, b1, b2, z0, z1, z2,
 * t) and m = 8 equations (section 5.2.2):
 *
 *   eq0 Z = I_P^z                          eq4 C_y2/E_A2 = G_y2^z / E_A1^a2
 *   eq1 C_x1 = C_x0^t G_x0^z0 G_x1^z        eq5 E_A1 = C_y1^a1 G_y1^z1
 *   eq2 A = G_a1^a1 G_a2^a2                 eq6 C_y4/E_B2 = G_y4^z / E_B1^b2
 *   eq3 B = G_b1^b1 G_b2^b2                 eq7 E_B1 = C_y3^b1 G_y3^z2
 *
 * Z is recomputed by the verifier as C_V / (W_P C_x0^x0 C_x1^x1 prod_i C_yi^yi);
 * no redemption date (M3 is a hidden group attribute here).  FS: UserID =
 * "geryon-group-member", OtherInfo = "geryon.1.<suite>.pi_P".
 * ------------------------------------------------------------------------- */

#define GY_GROUP_PI_P_K 9
#define GY_GROUP_PI_P_M 8

struct gy_group_pk_presentation {
    uint8_t C_y1[GY_GROUP_POINT_MAX];
    uint8_t C_y2[GY_GROUP_POINT_MAX];
    uint8_t C_y3[GY_GROUP_POINT_MAX];
    uint8_t C_y4[GY_GROUP_POINT_MAX];
    uint8_t C_x0[GY_GROUP_POINT_MAX];
    uint8_t C_x1[GY_GROUP_POINT_MAX];
    uint8_t C_V[GY_GROUP_POINT_MAX];
    uint8_t E_A1[GY_GROUP_POINT_MAX];
    uint8_t E_A2[GY_GROUP_POINT_MAX];
    uint8_t E_B1[GY_GROUP_POINT_MAX];
    uint8_t E_B2[GY_GROUP_POINT_MAX];
    uint8_t proof_V[GY_GROUP_PI_P_M][GY_GROUP_POINT_MAX];
    uint8_t proof_r[GY_GROUP_PI_P_K][GY_GROUP_SCALAR_MAX];
};

/*
 * Produce a ProfileKeyCredentialPresentation for the member's ProfileKey
 * credential (cred = stored MAC (t,U,V)), UID, and ProfileKey.  sp holds the
 * GroupSecretParams (a1,a2,b1,b2); pp_pub the GroupPublicParams (A, B); pp_srv
 * the ServerPublicParams for the profile family (I_P).  Returns GY_OK or a
 * negative GY_ERR_*.
 */
int gy_group_pk_present(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const struct gy_group_secret_params *sp,
                        const struct gy_group_public_params *pp_pub,
                        const struct gy_group_server_public *pp_srv,
                        const struct gy_group_mac_tag *cred,
                        const uint8_t uid[GY_GROUP_UID_BYTES],
                        const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                        struct gy_group_pk_presentation *out);

/* Server-side verification with sk_P (n_bound = 4).  Returns GY_OK / GY_ERR_*. */
int gy_group_pk_present_verify(const struct gy_group_tier *tier,
                               const struct gy_group_generators *gens,
                               const struct gy_group_server_secret *sk_P,
                               const struct gy_group_public_params *pp_pub,
                               const struct gy_group_pk_presentation *pres);

#define GY_GROUP_PK_PRES_ENC_MAX                                               \
    (GY_GROUP_OBJ_HDR_LEN + 11 * GY_GROUP_POINT_MAX +                          \
     GY_GROUP_PI_P_M * GY_GROUP_POINT_MAX +                                    \
     GY_GROUP_PI_P_K * GY_GROUP_SCALAR_MAX)

int gy_group_pk_pres_encode(const struct gy_group_tier *tier,
                            const struct gy_group_pk_presentation *pres,
                            uint8_t *out, size_t cap, size_t *outlen);
int gy_group_pk_pres_decode(const struct gy_group_tier *tier,
                            struct gy_group_pk_presentation *pres,
                            const uint8_t *in, size_t len);

#endif /* GY_GROUP_PRES_H */
