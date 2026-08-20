/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <oqs/oqs.h>

#include "error.h"
#include "mlkem.h"
#include "util.h"

/*
 * The direct OQS_KEM_ml_kem_512_* entry points are stateless and take no
 * OQS_KEM object, so there is no allocation and no per-call setup (unlike the
 * OQS_KEM_new object API).  Constant-time behaviour, including the implicit-
 * rejection compare in decapsulation, is liboqs's own contract, validated by
 * liboqs; geryon does not re-time the primitive (docs/decisions/pq.md D-PQ-4).
 * These wrappers add NO branch, memcpy length, or index that depends on secret
 * input: the only branch is on the OQS return code, which for decaps is SUCCESS
 * for a valid AND a corrupt ciphertext (implicit rejection), so a bad ct is
 * indistinguishable to the wrapper.
 */

int
gy_mlkem_keypair(uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_512_keypair(pk, sk) != OQS_SUCCESS) {
        gy_secure_zero(sk, GY_MLKEM512_SK);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mlkem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    if (ct == NULL || ss == NULL || pk == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_512_encaps(ct, ss, pk) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM512_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mlkem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
{
    if (ss == NULL || ct == NULL || sk == NULL)
        return GY_ERR_ARG;

    /*
     * FIPS 203 implicit rejection: decaps NEVER reports a decrypt failure. A
     * corrupt ct yields OQS_SUCCESS with the deterministic pseudorandom secret,
     * which the wrapper passes through as GY_OK - converting it to an error
     * would rebuild exactly the decapsulation oracle FIPS 203 removes. An
     * OQS_ERROR here is therefore a genuine provider fault, not a bad ct.
     */
    if (OQS_KEM_ml_kem_512_decaps(ss, ct, sk) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM512_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

#ifdef GY_TEST_HOOKS
int
gy_mlkem_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    if (pk == NULL || sk == NULL || seed == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_512_keypair_derand(pk, sk, seed) != OQS_SUCCESS) {
        gy_secure_zero(sk, GY_MLKEM512_SK);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mlkem_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                       const uint8_t *seed)
{
    if (ct == NULL || ss == NULL || pk == NULL || seed == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_512_encaps_derand(ct, ss, pk, seed) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM512_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}
#endif /* GY_TEST_HOOKS */
