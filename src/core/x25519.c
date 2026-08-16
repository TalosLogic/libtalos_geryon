/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <sodium.h>

#include "error.h"
#include "rng.h"
#include "util.h"
#include "x25519.h"

int
gy_x25519_keypair(uint8_t pk[32], uint8_t sk[32])
{
    int rc;

    rc = gy_random_bytes(sk, 32);
    if (rc != GY_OK)
        return rc;

    /* RFC 7748 clamp, applied once at generation (D-XED-10). */
    sk[0] &= 248;
    sk[31] &= 127;
    sk[31] |= 64;

    if (crypto_scalarmult_curve25519_base(pk, sk) != 0) {
        gy_secure_zero(sk, 32);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_x25519(uint8_t out[32], const uint8_t sk[32], const uint8_t peer_pk[32])
{
    int rc, weak;

    /*
     * libsodium clamps the scalar internally and returns nonzero for a
     * low-order peer point.  Independently confirm the output is not all-zero
     * so the D-X3DH-8 invariant does not depend on provider behavior.
     */
    rc = crypto_scalarmult_curve25519(out, sk, peer_pk);
    weak = gy_is_zero(out, 32);
    if (rc != 0 || weak) {
        gy_secure_zero(out, 32);
        return GY_ERR_WEAK_KEY;
    }
    return GY_OK;
}
