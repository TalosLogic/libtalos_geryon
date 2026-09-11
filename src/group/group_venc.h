/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_VENC_H
#define GY_GROUP_VENC_H

#include <stddef.h>
#include <stdint.h>

#include "group_attr.h"   /* GY_GROUP_UID_BYTES, GY_GROUP_PROFILEKEY_BYTES */
#include "group_params.h" /* struct gy_group_secret_params (a1,a2,b1,b2) */
#include "group_tier.h"

/*
 * Verifiable encryption of UID and ProfileKey under GroupSecretParams
 * (GROUP_SPEC section 6, [CPZ] section 4/5.11), GER-M8-05.  A deterministic,
 * unique-ciphertext symmetric scheme (CCA-secure in the ROM under DDH): the
 * group server stores and routes member identities without learning them, and
 * the encryption relations later become predicate lines inside the credential
 * presentations (section 6.5, in GER-M8-04's pi_A / pi_P).  This unit provides
 * Enc / Dec and the ciphertext objects; the presentation predicates live with
 * the presentations.
 *
 * Both schemes key off GroupSecretParams: the UID scheme on (a1, a2), the
 * ProfileKey scheme on (b1, b2).  Points/scalars are the tier's canonical
 * encodings; objects are rederived, never cached (D-GRP-7).
 */

/* UidCiphertext (E_A1, E_A2), section 3.4 / 6.3: 2 group elements. */
struct gy_group_uid_ct {
    uint8_t E_A1[GY_GROUP_POINT_MAX];
    uint8_t E_A2[GY_GROUP_POINT_MAX];
};

/* ProfileKeyCiphertext (E_B1, E_B2), section 3.4 / 6.4: 2 group elements. */
struct gy_group_pk_ct {
    uint8_t E_B1[GY_GROUP_POINT_MAX];
    uint8_t E_B2[GY_GROUP_POINT_MAX];
};

/*
 * UID Enc (section 6.3): M1 = HashToG("grp-m1", UID), M2 = EncodeToG(UID),
 * E_A1 = M1^a1, E_A2 = E_A1^a2 M2.  Deterministic and unique-ciphertext.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_uid_encrypt(const struct gy_group_tier *tier,
                         const struct gy_group_secret_params *sp,
                         const uint8_t uid[GY_GROUP_UID_BYTES],
                         struct gy_group_uid_ct *out);

/*
 * UID Dec (section 6.3): M2' = E_A2 / E_A1^a2, decode to UID', accept iff
 * E_A1 != identity AND E_A1 = HashToG(UID')^a1.  Decode failure and check
 * failure are the same error (no decode oracle) and the path is constant-time
 * (D-GRP-8).  Returns GY_OK and writes uid on success, GY_ERR_VERIFY on any
 * failure, GY_ERR_* on bad input.
 */
int gy_group_uid_decrypt(const struct gy_group_tier *tier,
                         const struct gy_group_secret_params *sp,
                         const struct gy_group_uid_ct *ct,
                         uint8_t uid[GY_GROUP_UID_BYTES]);

/*
 * ProfileKey Enc (section 6.4): M3 = HashToG1("grp-m3", ProfileKey || UID),
 * M4 = EncodeToG(ProfileKey), E_B1 = M3^b1, E_B2 = E_B1^b2 M4.  Returns GY_OK
 * or a negative GY_ERR_*.
 */
int gy_group_pk_encrypt(const struct gy_group_tier *tier,
                        const struct gy_group_secret_params *sp,
                        const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                        const uint8_t uid[GY_GROUP_UID_BYTES],
                        struct gy_group_pk_ct *out);

/*
 * ProfileKey Dec (section 6.4): needs the UID (decrypt it first, section 6.3).
 * M4' = E_B2 / E_B1^b2, candidate-decode M4', then over the FULL fixed
 * pk_max_candidates count (no early exit, constant-time select; D-GRP-8) test
 * E_B1 = HashToG1(ProfileKey_c, UID)^b1.  Accept iff E_B1 != identity and
 * exactly one candidate matched.  Returns GY_OK and writes pk on success,
 * GY_ERR_VERIFY on any failure, GY_ERR_* on bad input.
 */
int gy_group_pk_decrypt(const struct gy_group_tier *tier,
                        const struct gy_group_secret_params *sp,
                        const struct gy_group_pk_ct *ct,
                        const uint8_t uid[GY_GROUP_UID_BYTES],
                        uint8_t pk[GY_GROUP_PROFILEKEY_BYTES]);

/* ------------------------------------------------------------------------- *
 * Canonical encodings (GROUP_SPEC section 9): each ciphertext is 2 group
 * elements, untagged (they are nested inside presentations and member state).
 * ------------------------------------------------------------------------- */

#define GY_GROUP_UID_CT_ENC_MAX (2 * GY_GROUP_POINT_MAX)
#define GY_GROUP_PK_CT_ENC_MAX (2 * GY_GROUP_POINT_MAX)

int gy_group_uid_ct_encode(const struct gy_group_tier *tier,
                           const struct gy_group_uid_ct *ct, uint8_t *out,
                           size_t cap, size_t *outlen);
int gy_group_uid_ct_decode(const struct gy_group_tier *tier,
                           struct gy_group_uid_ct *ct, const uint8_t *in,
                           size_t len);
int gy_group_pk_ct_encode(const struct gy_group_tier *tier,
                          const struct gy_group_pk_ct *ct, uint8_t *out,
                          size_t cap, size_t *outlen);
int gy_group_pk_ct_decode(const struct gy_group_tier *tier,
                          struct gy_group_pk_ct *ct, const uint8_t *in,
                          size_t len);

#endif /* GY_GROUP_VENC_H */
