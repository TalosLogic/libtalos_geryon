/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_X3DH_H
#define GY_X3DH_H

#include <stddef.h>
#include <stdint.h>

#include "prekeys.h"

/*
 * Classical X3DH (the X3DH specification, section 3, D-X3DH-6/7/8/9/13/15,
 * D-DR-13).  This
 * module produces the Double Ratchet seed triple, the associated data, and
 * the initial-message prefix, and consumes them on the responder side; DR
 * initialization itself lives in the ratchet layer.  SK is never exposed and
 * never used to encrypt (D-X3DH-9): it exists only to seed the triple below.
 */

/* Length of each derived DR secret (D-DR-13): the root/chain key width. */
#define GY_DR_SECRET_LEN 32

/*
 * Largest associated data: Encode(IK_A) || Encode(IK_B), two encoded curve
 * keys (D-X3DH-6).  Largest initial-message prefix: version || suite_id ||
 * ik || ek || ik_id || spk_id || opk_id || ciphertext_len_be32, where a
 * carried key is pkid_be32 || curve_type || curve_pk (D-X3DH-15).
 */
#define GY_X3DH_AD_MAX (2 * (1 + GY_CURVE_PK_MAX))
#define GY_X3DH_KEY_WIRE_MAX (4 + 1 + GY_CURVE_PK_MAX)
#define GY_X3DH_PREFIX_MAX (2 + 2 * GY_X3DH_KEY_WIRE_MAX + 16)

/*
 * The Double Ratchet seed triple (D-DR-13): the DR root seed and the two
 * initial header keys.  All three are secret and must be zeroized by their
 * consumer.
 */
struct gy_dr_secrets {
    uint8_t sk_dr[GY_DR_SECRET_LEN];
    uint8_t shared_hka[GY_DR_SECRET_LEN];
    uint8_t shared_nhkb[GY_DR_SECRET_LEN];
};

/*
 * Deferred OPK-deletion reference (D-X3DH-10): the responder returns which
 * one-time prekey a message consumed, but does NOT delete it.  The caller
 * commits deletion only after the first DR message decrypts; a junk message
 * therefore never burns an OPK.  present == 0 means no OPK was used.
 */
struct gy_x3dh_opk_ref {
    uint8_t present;
    uint32_t pkid;
};

/*
 * The responder's local private material.  spk is the single signed-prekey
 * pair the message may reference by PKID; opks is the batch of one-time
 * prekey pairs (NULL / 0 if none stocked).  Selection is by PKID, and an
 * unknown SPK/OPK aborts with the generic handshake error (no prekey-existence
 * oracle, D-X3DH-10).
 */
struct gy_x3dh_local {
    const struct gy_keypair *ik;
    const struct gy_keypair *spk;
    const struct gy_keypair *opks;
    size_t n_opks;
};

/*
 * Initiator side.  Validates peer's bundle FIRST (zero secret-key ops on a bad
 * bundle, D-X3DH-14), computes DH1..DH4 (DH4 only if the bundle carries an
 * OPK), derives the seed triple and AD, and writes the initial-message prefix
 * (ending in a zero ciphertext_len placeholder the caller overwrites before
 * appending the first DR message).  ek is the caller's fresh ephemeral pair;
 * its private key is zeroized here on every path (D-X3DH-13).  out_ad has room
 * for GY_X3DH_AD_MAX bytes, out_prefix for GY_X3DH_PREFIX_MAX.  Returns GY_OK,
 * GY_ERR_WEAK_KEY on a degenerate DH, or the bundle-validation error.
 */
int gy_x3dh_initiate(const struct gy_suite_desc *desc,
                     struct gy_dr_secrets *out_secrets, uint8_t *out_ad,
                     size_t *out_ad_len, uint8_t *out_prefix,
                     size_t *out_prefix_len, const struct gy_keypair *local_ik,
                     const struct gy_prekey_bundle *peer,
                     struct gy_keypair *ek);

/*
 * Responder side.  Checks the frame (version/suite) before any crypto,
 * parses the prefix, recomputes the embedded ik/ek PKIDs and aborts on
 * mismatch, requires ik_id to equal the local identity PKID, selects the SPK
 * and (if claimed) OPK privates by PKID, mirrors the DHs, and derives the
 * same seed triple and AD.  The consumed OPK is reported in out_opk_ref but
 * NOT deleted.  Returns GY_OK, GY_ERR_WEAK_KEY on a degenerate DH, GY_ERR_ARG
 * on a short/malformed frame, GY_ERR_STATE on a cross-suite or stale-identity
 * message, or GY_ERR_VERIFY on any embedded-PKID or prekey-selection failure.
 */
int gy_x3dh_respond(const struct gy_suite_desc *desc,
                    struct gy_dr_secrets *out_secrets, uint8_t *out_ad,
                    size_t *out_ad_len, struct gy_x3dh_opk_ref *out_opk_ref,
                    const struct gy_x3dh_local *local, const uint8_t *msg,
                    size_t msg_len);

#ifdef GY_TEST_HOOKS
/*
 * Test-only: the D-DR-13 expansion from a known SK to the seed triple, so a
 * KAT can pin the three outputs and show they are pairwise distinct.
 */
int gy_x3dh_expand_secrets(const struct gy_suite_desc *desc, const uint8_t *sk,
                           struct gy_dr_secrets *out);
#endif

#endif /* GY_X3DH_H */
