/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KEYSTORE_H
#define GY_KEYSTORE_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

/*
 * The in-memory keystore: the live KEK plus the envelope-hierarchy seal/
 * unseal operations built over it (D-CUST-1 items 1-2 and 6,
 * CUSTODY_SPEC sections 3, 5, 7).  This is the crypto core the sealed-store
 * wrapper (proto/sealed_store.h) and the gy_custodian object
 * are built on.
 *
 * The keystore holds no key OBJECTS of its own (no resident slot table of
 * decoded records): every geryon record already flows through the
 * application's store per operation (D-SES-10/11), so custody's job is only
 * to seal what crosses that boundary.  This lives in session/, not proto/,
 * because it calls core/ sealing primitives directly (gy_seal, gy_kekprot_*)
 * and the nm audit forbids proto/ objects from referencing core/
 * symbols; proto/ reaches it only through these session/ entry points
 * (CUSTODY_SPEC section 14).  Not independently thread-safe (D-GEN-8: one
 * per thread, or caller-serialized).  Callers must have completed
 * gy_core_init().
 */

/* Upper bound on a gy_keystore_create/open/change_credential wrap blob, for
 * caller buffer sizing. */
#define GY_KEYSTORE_WRAP_MAX GY_KEKPROT_MAX_BLOB

/*
 * The live KEK lives in its own guarded (gy_secure_alloc) allocation,
 * independent of wherever the gy_keystore struct itself is placed, so the
 * CUSTODY_SPEC section 15 "KEK lives in guarded memory" guarantee holds
 * regardless of embedding.  unlocked is 0 in the absent/locked states
 * (D-CUST-1 section 7, CUSTODY_SPEC section 7) and 1 once a KEK is loaded;
 * kek is NULL whenever unlocked is 0.  A gy_keystore must be zero-
 * initialized before its first gy_keystore_create/open call.
 */
struct gy_keystore {
    uint8_t *kek; /* GY_KEKPROT_KEK_LEN bytes, guarded; NULL when locked */
    int unlocked;
};

/*
 * Create a fresh keystore: mint a random KEK and protect it under (cred,
 * credlen) at the given Argon2id cost (opslimit/memlimit, subject to the
 * bounds in pwhash.h) and alg_id (GY_SEAL_ALG_AEGIS256 default, or an
 * explicit caller choice), writing the wrap blob (for the caller to persist)
 * into out.  ks must be zero-initialized and not already open (GY_ERR_STATE
 * otherwise).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_keystore_create(struct gy_keystore *ks, uint8_t alg_id,
                       uint32_t opslimit, size_t memlimit, const uint8_t *cred,
                       size_t credlen, uint8_t *out, size_t *outlen);

/*
 * Open an existing keystore: recover the KEK from a gy_keystore_create /
 * gy_keystore_change_credential wrap blob and (cred, credlen).  ks must be
 * zero-initialized and not already open (GY_ERR_STATE otherwise).  A wrong
 * credential and a corrupt or tampered blob both fail with the single
 * GY_ERR_VERIFY (CUSTODY_SPEC section 15: no bad-credential-vs-corrupt-blob
 * oracle).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_keystore_open(struct gy_keystore *ks, const uint8_t *cred,
                     size_t credlen, const uint8_t *wrap, size_t wraplen);

/*
 * Lock/close: zeroize and release the guarded KEK allocation, returning ks
 * to the locked/absent state.  Safe to call on an already-closed or never-
 * opened (zero-initialized) keystore.
 */
void gy_keystore_close(struct gy_keystore *ks);

/*
 * Credential change (D-CUST-1 item 6): re-derive the PDK from the new
 * credential and re-wrap the CURRENT live KEK; the KEK bytes themselves are
 * untouched, so every record already sealed under it stays openable without
 * re-visiting it (no record enumeration needed).  ks must be open
 * (GY_ERR_STATE otherwise).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_keystore_change_credential(struct gy_keystore *ks, uint8_t alg_id,
                                  uint32_t opslimit, size_t memlimit,
                                  const uint8_t *new_cred, size_t new_credlen,
                                  uint8_t *out, size_t *outlen);

/*
 * Envelope hierarchy (D-CUST-1 item 2): seal/unseal a key object or record
 * under the live KEK.  ad is the caller's key-id/type/tier context (gy_seal
 * binds the format version/alg_id itself, D-CUST-1 item 5).  ks must be open
 * (GY_ERR_STATE otherwise).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_keystore_seal(struct gy_keystore *ks, uint8_t alg_id, const uint8_t *ad,
                     size_t adlen, const uint8_t *pt, size_t ptlen,
                     uint8_t *out, size_t *outlen);
int gy_keystore_unseal(struct gy_keystore *ks, const uint8_t *ad, size_t adlen,
                       const uint8_t *blob, size_t bloblen, uint8_t *pt,
                       size_t *ptlen);

#endif /* GY_KEYSTORE_H */
