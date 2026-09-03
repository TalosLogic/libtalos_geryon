/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <decaf.h>

#include "error.h"
#include "rng.h"
#include "util.h"
#include "x448.h"

int
gy_x448_keypair(uint8_t pk[56], uint8_t sk[56])
{
    int rc;

    rc = gy_random_bytes(sk, 56);
    if (rc != GY_OK)
        return rc;

    /* RFC 7748 X448 clamp, applied once at generation (D-XED-10/12). */
    sk[0] &= 252;
    sk[55] |= 128;

    /* libdecaf's RFC 7748 base-point scalarmul; cannot fail on a 56-byte key.
     */
    decaf_x448_derive_public_key(pk, sk);
    return GY_OK;
}

int
gy_x448(uint8_t out[56], const uint8_t sk[56], const uint8_t peer_pk[56])
{
    decaf_error_t e;
    int weak;

    /*
     * libdecaf returns DECAF_FAILURE for a low-order peer point.  Independently
     * confirm the output is not all-zero so the D-X3DH-8 invariant does not
     * depend on provider behavior, mirroring gy_x25519.
     */
    e = decaf_x448(out, peer_pk, sk);
    weak = gy_is_zero(out, 56);
    if (e != DECAF_SUCCESS || weak) {
        gy_secure_zero(out, 56);
        return GY_ERR_WEAK_KEY;
    }
    return GY_OK;
}
