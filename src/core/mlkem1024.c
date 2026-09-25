/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <oqs/oqs.h>

#include "error.h"
#include "mlkem1024.h"
#include "util.h"

/*
 * The direct OQS_KEM_ml_kem_1024_* entry points are stateless and take no
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
gy_mlkem1024_keypair(uint8_t *pk, uint8_t *sk)
{
    if (pk == NULL || sk == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_1024_keypair(pk, sk) != OQS_SUCCESS) {
        gy_secure_zero(sk, GY_MLKEM1024_SK);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)
{
    if (ct == NULL || ss == NULL || pk == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_1024_encaps(ct, ss, pk) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM1024_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

int
gy_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)
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
    if (OQS_KEM_ml_kem_1024_decaps(ss, ct, sk) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM1024_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

/*
 * Deterministic (derandomized) keypair generation is a PRODUCTION entry, not a
 * test-only seam: the QSPGS join keypair (ipk, isk) is rederived by
 * every group member from group-key material (QSPGS_SPEC.md sections 2.2, 9),
 * so the seed comes from a KDF over gk, never from the RNG.  It is FIPS 203
 * KeyGen_internal(d || z) and carries the same guarantees as the randomized
 * entry.  The encaps derandomized seam below stays test-only (ACVP KATs); the
 * join seal encapsulates with fresh randomness through gy_mlkem1024_encaps.
 */
int
gy_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
    if (pk == NULL || sk == NULL || seed == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_1024_keypair_derand(pk, sk, seed) != OQS_SUCCESS) {
        gy_secure_zero(sk, GY_MLKEM1024_SK);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}

#ifdef GY_TEST_HOOKS
int
gy_mlkem1024_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                           const uint8_t *seed)
{
    if (ct == NULL || ss == NULL || pk == NULL || seed == NULL)
        return GY_ERR_ARG;

    if (OQS_KEM_ml_kem_1024_encaps_derand(ct, ss, pk, seed) != OQS_SUCCESS) {
        gy_secure_zero(ss, GY_MLKEM1024_SS);
        return GY_ERR_CRYPTO;
    }
    return GY_OK;
}
#endif /* GY_TEST_HOOKS */
