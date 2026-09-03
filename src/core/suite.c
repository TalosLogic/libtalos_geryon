/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ed25519.h"
#include "ed448.h"
#include "encode.h"
#include "error.h"
#include "hash.h"
#include "mldsa44.h"
#include "mldsa87.h"
#include "mlkem1024.h"
#include "mlkem512.h"
#include "suite.h"
#include "x25519.h"
#include "x448.h"

/*
 * The enabled suites (D-GEN-7).  geryon_c25519 (classical), geryon_h25519_512
 * (hybrid), geryon_c448 (classical, 448 tier), and geryon_h448_1024 (hybrid,
 * 448 tier) are all enabled.  Ops are the core wrappers; the
 * array-to-pointer parameter adjustment makes the fixed-size wrapper prototypes
 * assignable to the generic pointer types with no cast.  Hybrid-only sizes/ops
 * stay 0/NULL in classical rows.
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

        .kem_keypair = gy_mlkem512_keypair,
        .kem_encap = gy_mlkem512_encaps,
        .kem_decap = gy_mlkem512_decaps,
        .dsa_keypair = gy_mldsa44_keypair,
        .dsa_sign = gy_mldsa44_sign,
        .dsa_verify = gy_mldsa44_verify,
    },
    {
        .suite_id = GY_SUITE_C448,
        .curve_type = GY_CURVE_TYPE_448,
        .is_hybrid = 0,
        .name = "c448",

        .curve_pk_len = 56,
        .curve_sk_len = 56,
        .dh_len = 56,
        .sig_len = 114,
        .hash_len = 64,
        .f_len = 57,

        .keypair = gy_x448_keypair,
        .dh = gy_x448,
        .sign = gy_xed448_sign,
        .verify = gy_xed448_verify,

        .hash = gy_sha512,
        .hmac = gy_hmac_sha512_iov,
        .hkdf_extract = gy_hkdf_sha512_extract_iov,
        .hkdf_expand = gy_hkdf_sha512_expand,
    },
    {
        .suite_id = GY_SUITE_H448_1024,
        .curve_type = GY_CURVE_TYPE_448,
        .is_hybrid = 1,
        .name = "h448_1024",

        .curve_pk_len = 56,
        .curve_sk_len = 56,
        .dh_len = 56,
        .sig_len = 114,
        .hash_len = 64,
        .f_len = 57,

        .keypair = gy_x448_keypair,
        .dh = gy_x448,
        .sign = gy_xed448_sign,
        .verify = gy_xed448_verify,

        .hash = gy_sha512,
        .hmac = gy_hmac_sha512_iov,
        .hkdf_extract = gy_hkdf_sha512_extract_iov,
        .hkdf_expand = gy_hkdf_sha512_expand,

        /* ML-KEM-1024 (FIPS 203) and ML-DSA-87 (FIPS 204). */
        .kem_pk_len = 1568,
        .kem_sk_len = 3168,
        .kem_ct_len = 1568,
        .kem_ss_len = 32,
        .dsa_pk_len = 2592,
        .dsa_sk_len = 4896,
        .dsa_sig_len = 4627,

        .kem_keypair = gy_mlkem1024_keypair,
        .kem_encap = gy_mlkem1024_encaps,
        .kem_decap = gy_mlkem1024_decaps,
        .dsa_keypair = gy_mldsa87_keypair,
        .dsa_sign = gy_mldsa87_sign,
        .dsa_verify = gy_mldsa87_verify,
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
