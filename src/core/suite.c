/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "ed25519.h"
#include "encode.h"
#include "error.h"
#include "hash.h"
#include "suite.h"
#include "x25519.h"

/*
 * The enabled suites (D-GEN-7).  Only geryon_c25519 is enabled; the
 * other three suites are added as their primitives land.  Ops are
 * the core wrappers; the array-to-pointer parameter adjustment makes the
 * fixed-size wrapper prototypes assignable to the generic pointer types with
 * no cast.  Reserved sizes/ops stay 0/NULL.
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
