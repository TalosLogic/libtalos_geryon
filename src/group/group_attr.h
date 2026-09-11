/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_ATTR_H
#define GY_GROUP_ATTR_H

#include <stddef.h>
#include <stdint.h>

#include "group_params.h" /* struct gy_group_generators, GY_GEN_M3 */
#include "group_tier.h"

/*
 * Credential attribute assembly (GROUP_SPEC section 3.2/3.3, [CPZ] section 5.3/
 * 5.4), GER-M8-04 task 0: the group-element attribute vectors Mi that feed the
 * GER-M8-03 algebraic MAC (group_mac.h).  The MAC is generic over Mi[] points;
 * this unit builds those points from a UID, a redemption date, and a ProfileKey
 * per the two credential families.  No MAC, proof, or wire logic here.
 *
 * Attribute maps (section 2.2 frozen domains):
 *   M1 = HashToG("grp-m1", UID)             two-map, both families
 *   M2 = EncodeToG(UID)                     reversible encoding, both families
 *   M3_auth = G_m3^m3                       scalar attribute (redemption date)
 *   M3_prof = HashToG1("grp-m3", PK || UID) single-map group attribute
 *   M4 = EncodeToG(ProfileKey)              reversible encoding
 */

#define GY_GROUP_UID_BYTES 16
#define GY_GROUP_PROFILEKEY_BYTES 32

/* Redemption dates are day-aligned (section 9 item 6): a whole multiple of one
 * UTC day in seconds, enforced (rejected, never rounded) wherever a date enters
 * the algebra. */
#define GY_GROUP_DAY_SECS 86400u

/* Bound-attribute counts per family (section 4.4), = the MAC n_bound. */
#define GY_GROUP_ATTR_AUTH 3
#define GY_GROUP_ATTR_PROFILE 4

/*
 * The redemption-date scalar m3 (section 3.2 item 3, section 9 item 6): the
 * canonical scalar reduction of the day-aligned uint64 date.  date MUST be a
 * multiple of GY_GROUP_DAY_SECS or GY_ERR_ARG is returned (never rounded).  The
 * scalar is the value in the provider's canonical little-endian encoding (the
 * date occupies the low 8 bytes, the rest zero); since date < l no modular
 * reduction occurs.  out receives tier->scalar_len bytes.
 */
int gy_group_redemption_scalar(const struct gy_group_tier *tier, uint64_t date,
                               uint8_t *out);

/*
 * The auth M3 group attribute M3 = G_m3^m3 (gen GY_GEN_M3), m3 the redemption
 * scalar above.  out receives tier->point_len bytes.  Returns GY_OK, GY_ERR_ARG
 * on a non-day-aligned date or bad input, or a negative crypto code.
 */
int gy_group_auth_m3(const struct gy_group_tier *tier,
                     const struct gy_group_generators *gens, uint64_t date,
                     uint8_t *out);

/*
 * Assemble the AuthCredential attribute vector (M1, M2, M3_auth) for a UID and
 * redemption date (section 3.2).  M is GY_GROUP_ATTR_AUTH rows of tier->point_len
 * bytes (leading bytes; the 255-tier tail is defined by the provider writes and
 * unused).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_attr_auth(const struct gy_group_tier *tier,
                       const struct gy_group_generators *gens,
                       const uint8_t uid[GY_GROUP_UID_BYTES], uint64_t date,
                       uint8_t M[GY_GROUP_ATTR_AUTH][GY_GROUP_POINT_MAX]);

/*
 * Assemble the ProfileKeyCredential attribute vector (M1, M2, M3_prof, M4) for
 * a UID and ProfileKey (section 3.3): M3_prof = HashToG1("grp-m3", PK || UID),
 * M4 = EncodeToG(ProfileKey).  M is GY_GROUP_ATTR_PROFILE rows of
 * tier->point_len bytes.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_group_attr_profile(const struct gy_group_tier *tier,
                          const uint8_t uid[GY_GROUP_UID_BYTES],
                          const uint8_t pk[GY_GROUP_PROFILEKEY_BYTES],
                          uint8_t M[GY_GROUP_ATTR_PROFILE][GY_GROUP_POINT_MAX]);

#endif /* GY_GROUP_ATTR_H */
