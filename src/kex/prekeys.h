/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_PREKEYS_H
#define GY_PREKEYS_H

#include <stddef.h>
#include <stdint.h>

#include "kex.h"

/*
 * Prekey generation, signing, bundles, validation, and fingerprints
 * (D-X3DH-4/5/10/11/14/15, D-GEN-2, D-XED-2).  Everything is
 * descriptor-driven and sized by the GY_*_MAX maxima.  Keys carry the
 * on-wire structure pkid || curve_type || curve_pk exactly (D-X3DH-15's
 * "same key structure everywhere" rule); the encoded form the PKID and
 * signature cover is EncodeEC = curve_type || curve_pk (no pkid).
 */

/* Default one-time-prekey batch cap (D-X3DH-5/10); configurable by the caller. */
#define GY_OPK_BATCH_MAX 100

/*
 * A public key as it appears on the wire: the 4-byte PKID (D-GEN-2), the
 * curve-type byte, and curve_pk_len bytes of key.  pkid == 0 is the reserved
 * "absent" sentinel for optional keys (a generated key never has pkid 0).
 */
struct gy_public_key {
    uint32_t pkid;
    uint8_t curve_type;
    uint8_t pk[GY_CURVE_PK_MAX];
};

/* A curve key pair: the public structure plus the secret scalar. */
struct gy_keypair {
    struct gy_public_key pub;
    uint8_t sk[GY_CURVE_SK_MAX];
};

/*
 * A signed prekey: the key pair, the owner-supplied creation timestamp, and
 * the identity-key signature over EncodeEC(pub) || timestamp_be64 (D-X3DH-4).
 * The signature occupies sig_len bytes of sig (desc->sig_len).
 */
struct gy_signed_prekey {
    struct gy_keypair kp;
    uint64_t timestamp;
    uint8_t sig[GY_SIG_MAX];
};

/*
 * A published prekey bundle (public material only).  opk.pkid == 0 signals no
 * one-time prekey (D-GEN-2 sentinel).  spk_sig covers
 * EncodeEC(spk) || spk_timestamp_be64 under the identity key.
 */
struct gy_prekey_bundle {
    struct gy_public_key ik;
    struct gy_public_key spk;
    uint64_t spk_timestamp;
    uint8_t spk_sig[GY_SIG_MAX];
    struct gy_public_key opk;
};

/*
 * Generate one curve key pair, computing its PKID and regenerating on the
 * zero sentinel (D-GEN-2).  out->sk is secret and zeroized on any error path.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_keypair_generate(const struct gy_suite_desc *desc,
                        struct gy_keypair *out);

/*
 * Create a signed prekey: generate the pair, build
 * signed_data = EncodeEC(pub) || timestamp_be64, and sign it under the
 * Montgomery identity private key (XEdDSA, D-XED-2).  timestamp is supplied by
 * the caller; the library never reads the clock.  Secret material is zeroized
 * on error.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_spk_create(const struct gy_suite_desc *desc,
                  struct gy_signed_prekey *out, const uint8_t *identity_sk,
                  uint64_t timestamp);

/*
 * Generate a batch of n one-time prekeys (1 <= n <= GY_OPK_BATCH_MAX).  Every
 * PKID is unique within the batch and against the caller-supplied existing[]
 * list of n_existing PKIDs (regenerate on collision, D-X3DH-10).  On any error
 * all generated secret keys are zeroized.  Returns GY_OK or a negative
 * GY_ERR_*.
 */
int gy_opk_batch(const struct gy_suite_desc *desc, struct gy_keypair *out,
                 size_t n, const uint32_t *existing, size_t n_existing);

/*
 * Validate a prekey bundle before ANY private-key operation (D-X3DH-14), in
 * this exact order: (a) every present key's curve_type matches the pinned
 * suite (GY_ERR_STATE on mismatch, a cross-suite/downgrade signal); (b) every
 * present key's PKID is non-zero and matches recomputation (GY_ERR_VERIFY);
 * (c) the SPK signature verifies over the full signed_data (GY_ERR_VERIFY);
 * (d) the OPK is checked only when present (zero-PKID sentinel).  Returns
 * GY_OK on a fully valid bundle.
 */
int gy_bundle_validate(const struct gy_suite_desc *desc,
                       const struct gy_prekey_bundle *bundle);

/*
 * Identity fingerprint (D-X3DH-11): the suite hash over EncodeEC(ik), covering
 * every identity component.  Writes desc->hash_len bytes to out; display
 * encoding is application scope.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                   const struct gy_public_key *ik);

#ifdef GY_TEST_HOOKS
/*
 * Test-only view of the regenerate decision (test acceptance):
 * returns 1 if pkid is the zero sentinel or collides with existing[], else 0.
 * Lets a test drive the zero-PKID and collision regeneration paths with a
 * crafted PKID instead of grinding the RNG.
 */
int gy_kex_pkid_needs_regen(uint32_t pkid, const uint32_t *existing,
                            size_t n_existing);
#endif

#endif /* GY_PREKEYS_H */
