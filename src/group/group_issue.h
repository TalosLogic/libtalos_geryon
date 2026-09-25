/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_ISSUE_H
#define GY_GROUP_ISSUE_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES, GY_GROUP_PROFILEKEY_BYTES */
#include "group_mac.h"    /* mac tag, ServerSecretParams/PublicParams */
#include "group_params.h" /* generators */
#include "group_tier.h"

/*
 * Blind issuance of ProfileKeyCredentials (GROUP_SPEC section 5.3, [CPZ]
 * section 5.10).  The requester ElGamal-encrypts the blind
 * attributes M3, M4 under an ephemeral key and proves (pi_BR) the ciphertexts
 * are consistent with its ProfileKeyCommitment; the server MACs the revealed
 * attributes (M1, M2), homomorphically folds in y3, y4 to obtain an encryption
 * of the full MAC, and proves (pi_BI) that it did so correctly.  The requester
 * decrypts the credential (t, U, V) - never revealing its ProfileKey to the
 * server (harvest-now-decrypt-later posture aside, D-GRP-11).  Both proofs are
 * sound conjunction proofs (gen_*_conj); FS UserID = "geryon-group-member"
 * (pi_BR) / "geryon-group-server" (pi_BI), OtherInfo = "geryon.1.<suite>.pi_BR"
 * / ".pi_BI".
 */

#define GY_GROUP_PI_BR_K 4 /* (y, r1, r2, j3) */
#define GY_GROUP_PI_BR_M 6
#define GY_GROUP_PI_BI_K 9 /* (w, wprime, y1, y2, y3, y4, x0, x1, r') */
#define GY_GROUP_PI_BI_M 4

/*
 * ProfileKeyCommitment (section 3.3): J1 = G_j1^j3 M3, J2 = G_j2^j3 M4,
 * J3 = G_j3^j3, with j3 = HashToZq("grp-j3", ProfileKey || UID).  Deterministic;
 * anyone with (ProfileKey, UID) recomputes it.
 */
struct gy_group_pk_commitment {
    uint8_t J1[GY_GROUP_POINT_MAX];
    uint8_t J2[GY_GROUP_POINT_MAX];
    uint8_t J3[GY_GROUP_POINT_MAX];
};

/*
 * ProfileKeyCredentialRequest (section 3.3 / 5.3): the ElGamal public key
 * Y = G^y, the ciphertexts (D1, D2) = (G^r1, Y^r1 M3), (E1, E2) = (G^r2,
 * Y^r2 M4), and pi_BR.
 */
struct gy_group_pk_request {
    uint8_t Y[GY_GROUP_POINT_MAX];
    uint8_t D1[GY_GROUP_POINT_MAX];
    uint8_t D2[GY_GROUP_POINT_MAX];
    uint8_t E1[GY_GROUP_POINT_MAX];
    uint8_t E2[GY_GROUP_POINT_MAX];
    uint8_t proof_V[GY_GROUP_PI_BR_M][GY_GROUP_POINT_MAX];
    uint8_t proof_r[GY_GROUP_PI_BR_K][GY_GROUP_SCALAR_MAX];
};

/*
 * ProfileKeyCredentialResponse (section 3.3 / 5.3): the homomorphic ciphertext
 * (S1, S2) of the full credential MAC V, the public (t, U), and pi_BI.
 */
struct gy_group_pk_blind_response {
    uint8_t S1[GY_GROUP_POINT_MAX];
    uint8_t S2[GY_GROUP_POINT_MAX];
    uint8_t t[GY_GROUP_SCALAR_MAX];
    uint8_t U[GY_GROUP_POINT_MAX];
    uint8_t proof_V[GY_GROUP_PI_BI_M][GY_GROUP_POINT_MAX];
    uint8_t proof_r[GY_GROUP_PI_BI_K][GY_GROUP_SCALAR_MAX];
};

/* Compute the ProfileKeyCommitment for (uid, pk).  Returns GY_OK or negative. */
int gy_group_pk_commit(const struct gy_group_tier *tier,
                       const struct gy_group_generators *gens,
                       const uint8_t uid[GY_GROUP_UID_BYTES],
                       const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                       struct gy_group_pk_commitment *out);

/*
 * Requester: build the blind request (ciphertexts + pi_BR) for (uid, pk).  The
 * ephemeral secret y (needed later to decrypt the credential) is written to
 * y_out (tier->scalar_len bytes); the ephemeral r1, r2 are zeroized internally.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_pk_request(const struct gy_group_tier *tier,
                        const struct gy_group_generators *gens,
                        const uint8_t uid[GY_GROUP_UID_BYTES],
                        const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                        struct gy_group_pk_request *out,
                        uint8_t y_out[GY_GROUP_SCALAR_MAX]);

/*
 * Server: verify pi_BR against the STORED commitment, MAC the revealed
 * attributes under sk_P (n_bound = 4), homomorphically form (S1, S2), and prove
 * pi_BI.  uid supplies the revealed M1, M2.  Returns GY_OK, GY_ERR_VERIFY if
 * pi_BR fails, or a negative GY_ERR_*.
 */
int gy_group_pk_blind_issue(const struct gy_group_tier *tier,
                            const struct gy_group_generators *gens,
                            const struct gy_group_server_secret *sk_P,
                            const uint8_t uid[GY_GROUP_UID_BYTES],
                            const struct gy_group_pk_commitment *commit,
                            const struct gy_group_pk_request *req,
                            struct gy_group_pk_blind_response *out);

/*
 * Requester: verify pi_BI against ServerPublicParams (pp_srv = iparams_P), then
 * decrypt V = S2 / S1^y and output the ProfileKeyCredential (t, U, V).  req
 * supplies the ciphertexts the proof binds; uid the revealed M1, M2; y the
 * ephemeral secret from gy_group_pk_request.  Returns GY_OK, GY_ERR_VERIFY if
 * pi_BI fails, or a negative GY_ERR_*.
 */
int gy_group_pk_blind_receive(const struct gy_group_tier *tier,
                              const struct gy_group_generators *gens,
                              const struct gy_group_server_public *pp_srv,
                              const uint8_t uid[GY_GROUP_UID_BYTES],
                              const struct gy_group_pk_request *req,
                              const uint8_t y[GY_GROUP_SCALAR_MAX],
                              const struct gy_group_pk_blind_response *resp,
                              struct gy_group_mac_tag *out_cred);

/* ------------------------------------------------------------------------- *
 * Canonical wire encodings (GROUP_SPEC section 9).  Each is a
 * tagged top-level object (GY_GOBJ_PK_COMMITMENT / _REQUEST / _RESPONSE); the
 * layout is the object header followed by the struct fields in declaration
 * order, tier-canonical points and scalars, fixed width, no TLV.  Decode is
 * strict: exact length, correct header, trailing bytes rejected.
 * ------------------------------------------------------------------------- */

int gy_group_pk_commit_encode(const struct gy_group_tier *tier,
                              const struct gy_group_pk_commitment *commit,
                              uint8_t *out, size_t cap, size_t *outlen);
int gy_group_pk_commit_decode(const struct gy_group_tier *tier,
                              struct gy_group_pk_commitment *commit,
                              const uint8_t *in, size_t len);
int gy_group_pk_request_encode(const struct gy_group_tier *tier,
                               const struct gy_group_pk_request *req,
                               uint8_t *out, size_t cap, size_t *outlen);
int gy_group_pk_request_decode(const struct gy_group_tier *tier,
                               struct gy_group_pk_request *req,
                               const uint8_t *in, size_t len);
int gy_group_pk_response_encode(const struct gy_group_tier *tier,
                                const struct gy_group_pk_blind_response *resp,
                                uint8_t *out, size_t cap, size_t *outlen);
int gy_group_pk_response_decode(const struct gy_group_tier *tier,
                                struct gy_group_pk_blind_response *resp,
                                const uint8_t *in, size_t len);

#endif /* GY_GROUP_ISSUE_H */
