/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_HASH_H
#define GY_GROUP_HASH_H

#include <stddef.h>
#include <stdint.h>

#include "group_tier.h"

/*
 * Hash conventions for the classical group vertical (GROUP_SPEC section 2.3,
 * D-GRP-4).  There is NO SHO: every domain is the D-GEN-3 suite-binding string
 * (core/ gy_info: "geryon.1.<suite_name>.<purpose>") optionally followed by the
 * hashed inputs, fed to the libtalos_schnorr provider.  Two distinct group
 * maps, distinguished by their frozen purpose label (section 2.2 registry):
 *
 *   - HashToG  (two-map, RFC 9496): M1 = HashToG("grp-m1", UID) and the NUMS
 *     generator derivation ("sysparams.<name>").
 *   - HashToG1 (single Elligator map): M3 = HashToG1("grp-m3", ProfileKey||UID),
 *     and its ProfileKey candidate test (section 6.1).
 *   - HashToZq (to scalar): j3 = HashToZq("grp-j3", ProfileKey||UID).
 *
 * The exact purpose strings are frozen at the first published KAT vectors
 * (section 2.2); this module does not define them, callers pass them.
 */

/* Upper bound on a group domain string: "geryon.1." + suite name + "." +
 * purpose.  Classical suite names are short ("c25519"/"c448"); the purpose
 * labels are the section 2.2 registry entries.  64 bytes is ample. */
#define GY_GROUP_DOMAIN_MAX 64

/*
 * Build the D-GEN-3 group domain string for a purpose into out (a thin,
 * import-tidy wrapper over core/ gy_info): writes
 * "geryon.1.<suite_name>.<purpose>" with no trailing NUL and stores the byte
 * length in *outlen.  Returns GY_OK, GY_ERR_ARG on a NULL/unknown suite, or
 * GY_ERR_TOOLONG if the result exceeds cap.
 */
int gy_group_domain(uint8_t suite_id, const char *purpose, uint8_t *out,
                    size_t cap, size_t *outlen);

/*
 * HashToG (two-map, RFC 9496): out = hash_to_group(domain(purpose) || input,
 * index 0).  input may be NULL only when input_len is 0 (e.g. the NUMS
 * generator seeds, which are the domain alone).  out receives tier->point_len
 * bytes.  Returns GY_OK or a negative code; out is left untouched on argument
 * errors and zeroed by the provider on a hash failure.
 */
int gy_group_hash_to_g(const struct gy_group_tier *tier, const char *purpose,
                       const uint8_t *input, size_t input_len, uint8_t *out);

/*
 * HashToG1 (single Elligator map): out = hash_to_g1(domain(purpose) || input).
 * This is the M3 attribute map and its candidate test (section 6.1).  out
 * receives tier->point_len bytes.
 */
int gy_group_hash_to_g1(const struct gy_group_tier *tier, const char *purpose,
                        const uint8_t *input, size_t input_len, uint8_t *out);

/*
 * HashToZq (to canonical scalar): out = hash_to_scalar(input, dst =
 * domain(purpose)).  The provider takes the domain as a separate dst argument,
 * so no concatenation buffer is built here.  out receives tier->scalar_len
 * bytes.
 */
int gy_group_hash_to_zq(const struct gy_group_tier *tier, const char *purpose,
                        const uint8_t *input, size_t input_len, uint8_t *out);

#endif /* GY_GROUP_HASH_H */
