/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_SEALED_STORE_H
#define GY_SEALED_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "geryon.h"
#include "keystore.h"

/*
 * The sealed store: wraps an application's
 * gy_store_callbacks so every store_record/store_identity/load_prekey
 * payload is sealed under a gy_keystore's live KEK before it reaches the
 * application, and unsealed on the way back (D-CUST-1 item 1, CUSTODY_SPEC
 * section 8).  delete_record and consume_opk carry no payload and pass
 * straight through.  The callback SIGNATURES are unchanged; only the
 * content crossing them is sealed (D-GEN-4 refined by D-CUST-1).
 *
 * This lives in proto/ because it needs the public gy_store_callbacks type;
 * it calls only session/ keystore entry points, never a core/ sealing
 * primitive directly (the nm audit forbids proto/ objects from
 * referencing a core/ symbol).
 *
 * gy_sealed_store_bind does not take ownership of ks or real: ks must
 * outlive every call made through the bound callbacks and stay open (an
 * operation against a closed/locked keystore fails with GY_ERR_STATE, from
 * gy_keystore_seal/unseal).  Not independently thread-safe (D-GEN-8: one per
 * thread, or caller-serialized) - the wrapper keeps one shared scratch
 * buffer for the seal/unseal boundary crossing, so a gy_sealed_store is
 * large and must be heap- or statically allocated, never placed on the
 * stack (matching struct gy_op, session/store.h).
 */

struct gy_sealed_store {
    struct gy_keystore *ks;
    gy_store_callbacks real;
    uint8_t alg_id;
    uint8_t scratch[GY_SESSION_BLOB_MAX + GY_SEAL_MAX_OVERHEAD];
};

/*
 * Bind ss to ks and real, and populate *out with callbacks that route
 * through it (out->ctx = ss).  alg_id selects the wrap cipher for every
 * record/identity/prekey this binding seals (GY_SEAL_ALG_AEGIS256 default,
 * or an explicit caller choice); it is fixed for the binding's lifetime
 * (CUSTODY_SPEC section 7 immutable configuration).  Returns GY_OK or
 * GY_ERR_ARG on a NULL argument.
 */
int gy_sealed_store_bind(struct gy_sealed_store *ss, struct gy_keystore *ks,
                         const gy_store_callbacks *real, uint8_t alg_id,
                         gy_store_callbacks *out);

#endif /* GY_SEALED_STORE_H */
