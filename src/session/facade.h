/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_FACADE_H
#define GY_FACADE_H

#include <stddef.h>
#include <stdint.h>

#include "lifecycle.h"

/*
 * Session-layer facade: the handful of core/ and kex/ primitives
 * the Layer 5 public API needs, re-exported as session/ symbols so proto/api.c
 * references nothing below session/ (the nm audit forbids ratchet/
 * and core/ symbols in proto/ objects).  These are thin pass-throughs; all
 * policy lives in the layers they call.
 */

/* Initialize the crypto runtime (RNG); idempotent.  Wraps the core init. */
int gy_runtime_init(void);

/* Resolve a suite id to its descriptor, or NULL for an unknown suite. */
const struct gy_suite_desc *gy_suite_lookup(uint8_t suite_id);

/* Generate a fresh identity key pair for desc (secrets zeroized on error). */
int gy_identity_generate(const struct gy_suite_desc *desc,
                         struct gy_keypair *ik);

/*
 * Create a signed prekey for desc, signed under the identity private key at the
 * caller-supplied timestamp (the library never reads the clock, D-X3DH-5).
 */
int gy_signed_prekey_generate(const struct gy_suite_desc *desc,
                              struct gy_signed_prekey *spk,
                              const uint8_t *identity_sk, uint64_t timestamp);

/*
 * Generate a batch of n one-time prekeys (1 <= n <= GY_OPK_BATCH_MAX), each
 * PKID unique within the batch and against the caller's existing[] list of
 * n_existing already-held PKIDs (regenerate on collision, D-X3DH-10);
 * existing may be NULL with n_existing 0 (nothing held yet, e.g. initial
 * identity generation).
 */
int gy_opk_generate(const struct gy_suite_desc *desc, struct gy_keypair *out,
                    size_t n, const uint32_t *existing, size_t n_existing);

/* Constant-time wipe of key material (wraps the core secure-zero). */
void gy_wipe(void *p, size_t n);

/*
 * Guarded (sodium_malloc-backed) allocation for key material transiting a
 * buffer before/after sealing, wrapping the core
 * gy_secure_alloc/gy_secure_free (renamed, like gy_wipe/gy_secure_zero) so
 * proto/ reaches it through session/ (the nm audit forbids core/
 * symbols in proto/ objects).  gy_guarded_free zeroizes before releasing.
 */
void *gy_guarded_alloc(size_t n);
void gy_guarded_free(void *p);

/*
 * The mandatory-to-implement AEAD id for desc (D-DR-3): ChaCha20-Poly1305 in
 * every suite today.  Lets the public API pick the default without reaching
 * into core/aead.h.
 */
uint8_t gy_default_aead(const struct gy_suite_desc *desc);

/*
 * Suite-bound domain-separation info string "geryon.1.<suite>.<purpose>"
 * (D-GEN-3), wrapping core's gy_info (renamed, like gy_wipe/gy_secure_zero
 * and gy_guarded_alloc/gy_secure_alloc) so proto/ reaches it through
 * session/ (nm audit).  Used for the SAK domain-
 * separation labels ("appkey-cert", "appkey").
 */
int gy_suite_info(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
                  const char *purpose);

#endif /* GY_FACADE_H */
