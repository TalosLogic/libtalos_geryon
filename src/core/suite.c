/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ed25519.h"
#include "encode.h"
#include "error.h"
#include "hash.h"
#include "mldsa.h"
#include "mlkem.h"
#include "suite.h"
#include "x25519.h"

/*
 * The enabled suites (D-GEN-7).  geryon_c25519 (classical) and geryon_h25519_512
 * (hybrid) are enabled; the two 448-tier suites are added as their primitives
 * land.  Ops are the core wrappers; the array-to-pointer parameter adjustment
 * makes the fixed-size wrapper prototypes assignable to the generic pointer
 * types with no cast.  Reserved sizes/ops stay 0/NULL.
 */
static const struct gy_suite_desc gy_suites[] = {
    {
        .suite_id = GY_SUITE_C25519,
        .curve_type = GY_CURVE_TYPE_25519,
        .is_hybrid = 0,
        .name = "c25519",

        .curve_pk_len = 32,
        .curve_sk_len = 32,
        .dh_len = 32,
        .sig_len = 64,
        .hash_len = 32,
        .f_len = 32,

        .keypair = gy_x25519_keypair,
        .dh = gy_x25519,
        .sign = gy_xeddsa_sign,
        .verify = gy_xeddsa_verify,

        .hash = gy_sha256,
        .hmac = gy_hmac_sha256_iov,
        .hkdf_extract = gy_hkdf_sha256_extract_iov,
        .hkdf_expand = gy_hkdf_sha256_expand,
    },
    {
        .suite_id = GY_SUITE_H25519_512,
        .curve_type = GY_CURVE_TYPE_25519,
        .is_hybrid = 1,
        .name = "h25519_512",

        .curve_pk_len = 32,
        .curve_sk_len = 32,
        .dh_len = 32,
        .sig_len = 64,
        .hash_len = 32,
        .f_len = 32,

        .keypair = gy_x25519_keypair,
        .dh = gy_x25519,
        .sign = gy_xeddsa_sign,
        .verify = gy_xeddsa_verify,

        .hash = gy_sha256,
        .hmac = gy_hmac_sha256_iov,
        .hkdf_extract = gy_hkdf_sha256_extract_iov,
        .hkdf_expand = gy_hkdf_sha256_expand,

        /* ML-KEM-512 (FIPS 203) and ML-DSA-44 (FIPS 204). */
        .kem_pk_len = 800,
        .kem_sk_len = 1632,
        .kem_ct_len = 768,
        .kem_ss_len = 32,
        .dsa_pk_len = 1312,
        .dsa_sk_len = 2560,
        .dsa_sig_len = 2420,

        .kem_keypair = gy_mlkem_keypair,
        .kem_encap = gy_mlkem_encaps,
        .kem_decap = gy_mlkem_decaps,
        .dsa_keypair = gy_mldsa_keypair,
        .dsa_sign = gy_mldsa_sign,
        .dsa_verify = gy_mldsa_verify,
    },
};

const struct gy_suite_desc *
gy_suite_desc(uint8_t suite_id)
{
    size_t i;

    for (i = 0; i < sizeof(gy_suites) / sizeof(gy_suites[0]); i++) {
        if (gy_suites[i].suite_id == suite_id)
            return &gy_suites[i];
    }
    return NULL;
}

int
gy_suite_f(const struct gy_suite_desc *desc, uint8_t out[GY_F_MAX])
{
    if (desc == NULL || out == NULL)
        return GY_ERR_ARG;

    memset(out, 0xff, desc->f_len);
    return GY_OK;
}
