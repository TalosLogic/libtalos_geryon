/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_KEKPROT_H
#define GY_KEKPROT_H

#include <stddef.h>
#include <stdint.h>

#include "pwhash.h"
#include "seal.h"

/*
 * The KEK-protector seam (D-CUST-1 item 3, CUSTODY_SPEC section 6):
 * wrap(KEK) -> blob / unwrap(blob) -> KEK.  This pair is the ONLY way the
 * keystore touches the KEK's outer wrap; a Stage-2 hardware
 * backend (OS keychain / TPM / Secure Enclave / HSM, deferred) replaces this
 * pair's implementation, not its callers.
 *
 * This is the Stage-1 passphrase implementation: Argon2id derives the PDK
 * from the credential (pwhash.h), and the PDK gy_seal's the KEK (seal.h).
 * Callers must have completed gy_core_init().
 */

#define GY_KEKPROT_KEK_LEN GY_SEAL_KEY_LEN

/* A wrap blob's fixed parameter header: salt || opslimit(4) || memlimit(8),
 * big-endian, ahead of the gy_seal blob. */
#define GY_KEKPROT_HDR_LEN (GY_PWHASH_SALT_LEN + 4 + 8)

/* Upper bound on a wrap blob's size, for caller buffer sizing. */
#define GY_KEKPROT_MAX_BLOB                                                    \
    (GY_KEKPROT_HDR_LEN + GY_SEAL_MAX_OVERHEAD + GY_KEKPROT_KEK_LEN)

/*
 * Wrap kek under a PDK freshly derived from (cred, credlen) with a new
 * random salt, at the given Argon2id cost (opslimit/memlimit, subject to the
 * bounds in pwhash.h), then gy_seal it with alg_id (GY_SEAL_ALG_AEGIS256
 * default, or an explicit caller choice).  ad is the caller's key-id/type/
 * tier context; gy_seal binds the format version and alg_id itself
 * (D-CUST-1 item 5).  Writes salt || opslimit || memlimit || sealed-blob
 * into out; on entry *outlen is out's capacity, on success the bytes
 * written.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_kekprot_wrap(uint8_t *out, size_t *outlen, uint8_t alg_id,
                    uint32_t opslimit, size_t memlimit, const uint8_t *cred,
                    size_t credlen, const uint8_t *ad, size_t adlen,
                    const uint8_t kek[GY_KEKPROT_KEK_LEN]);

/*
 * Recover kek from a gy_kekprot_wrap blob and the credential: re-derive the
 * PDK from the blob's own stored salt/opslimit/memlimit (a raised cost from
 * a later re-wrap is honored automatically; it is read from the blob, never
 * assumed), then gy_unseal.  ad must match what was passed to wrap.  A wrong
 * credential and a corrupt or tampered blob both fail with the single
 * GY_ERR_VERIFY (CUSTODY_SPEC section 15: the unseal tag check is the sole
 * discriminator, no bad-credential-vs-corrupt-blob oracle).  Returns GY_OK
 * or a negative GY_ERR_*.
 */
int gy_kekprot_unwrap(uint8_t kek[GY_KEKPROT_KEK_LEN], const uint8_t *cred,
                      size_t credlen, const uint8_t *ad, size_t adlen,
                      const uint8_t *blob, size_t bloblen);

#endif /* GY_KEKPROT_H */
