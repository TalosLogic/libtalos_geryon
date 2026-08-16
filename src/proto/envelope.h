/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_ENVELOPE_H
#define GY_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>

#include "recv.h"
#include "send.h"

/*
 * Layer 5 wire format (D-GEN-1 amendment, D-X3DH-15).  proto/ owns
 * the typed message envelope and the published prekey-bundle serialization and
 * NOTHING else: it moves bytes between the session/ API and the wire, does no
 * cryptography, holds no key material, and references no ratchet/ or core/
 * symbol (it does its own byte and endian work and takes the suite descriptor
 * as a parameter rather than looking it up).  Cryptographic validation of a
 * parsed bundle stays gy_bundle_validate in kex/, reached through session/;
 * proto/ parse checks STRUCTURE only.
 *
 * Envelope: version || suite_id || msg_type || inner_message, where the inner
 * message begins with its own version || suite that must match the outer
 * (D-GEN-1).  No padding.
 */

#define GY_ENVELOPE_HDR_LEN 3

/*
 * Serialize an envelope around inner[0..ilen).  msg_type must be GY_MSG_INIT or
 * GY_MSG_DR.  Writes GY_ENVELOPE_HDR_LEN + ilen bytes to out (cap must hold
 * them) and the length to *outlen.  Returns GY_OK, GY_ERR_ARG on a NULL
 * argument, a bad msg_type, or a short buffer.
 */
int gy_envelope_put(uint8_t *out, size_t cap, size_t *outlen, uint8_t suite_id,
                    uint8_t msg_type, const uint8_t *inner, size_t ilen);

/*
 * Parse and validate an envelope, entirely before any session/ call.  Rejects a
 * bad version, a suite != expected_suite (GY_ERR_STATE, a cross-suite signal),
 * a reserved msg_type, a truncated frame, and an inner/outer version-suite
 * mismatch (all GY_ERR_ARG except the suite case).  On success sets *out_type
 * and points *out_inner / *out_inner_len at the inner message (a view into buf,
 * not a copy).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_envelope_parse(const uint8_t *buf, size_t len, uint8_t expected_suite,
                      uint8_t *out_type, const uint8_t **out_inner,
                      size_t *out_inner_len);

/*
 * Exact wire length of a published bundle for desc, with or without a one-time
 * prekey.  Callers size a buffer with this before gy_bundle_put.
 */
size_t gy_bundle_wire_len(const struct gy_suite_desc *desc, int with_opk);

/*
 * Serialize a prekey bundle: version || suite_id || IK || SPK || spk_timestamp
 * || spk_sig || opk_present || [OPK], every key in the D-X3DH-15 structure
 * (pkid_be32 || curve_type || curve_pk).  An OPK with pkid 0 (the absent
 * sentinel) is written as opk_present = 0.  Returns GY_OK, or GY_ERR_ARG on a
 * NULL argument or short buffer.
 */
int gy_bundle_put(uint8_t *out, size_t cap, size_t *outlen,
                  const struct gy_suite_desc *desc,
                  const struct gy_prekey_bundle *b);

/*
 * Parse a published bundle into *out (STRUCTURE only; no signature or PKID
 * check, which is gy_bundle_validate's job).  Rejects a bad version, a suite
 * mismatch (GY_ERR_STATE), a truncation, or trailing bytes (GY_ERR_ARG).  An
 * absent OPK leaves out->opk.pkid == 0.  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_bundle_parse(struct gy_prekey_bundle *out,
                    const struct gy_suite_desc *desc, const uint8_t *buf,
                    size_t len);

/*
 * Identity fingerprint surface (D-X3DH-11): writes desc->hash_len bytes to out.
 * Display encoding is application scope.  Delegates to session/ (proto/ does no
 * crypto).  Returns GY_OK or a negative GY_ERR_*.
 */
int gy_proto_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                         const struct gy_public_key *ik);

/*
 * One-time-prekey batch wire format (D-GEN-1 framing, reusing
 * the same per-key layout gy_bundle_put/parse use - pkid_be32 || curve_type
 * || curve_pk - rather than inventing a new one): version || suite_id ||
 * count_be16 || repeated keys.  Distinct from a prekey bundle (one ik+spk+
 * optional-opk); this is a variable-count array of public keys only, for
 * the granular "publish the OPK pool" path.  gy_opk_batch_wire_len sizes a
 * buffer before gy_opk_batch_put.
 */
size_t gy_opk_batch_wire_len(const struct gy_suite_desc *desc, size_t n);

/*
 * Serialize n public keys as one batch.  Returns GY_OK, or GY_ERR_ARG on a
 * NULL argument or short buffer.
 */
int gy_opk_batch_put(uint8_t *out, size_t cap, size_t *outlen,
                     const struct gy_suite_desc *desc,
                     const struct gy_public_key *keys, size_t n);

/*
 * Parse a batch into out[0..*n) (STRUCTURE only, no PKID recomputation -
 * that is gy_bundle_validate's per-key job, not repeated here).  out_cap
 * bounds how many entries out can hold; GY_ERR_TOOLONG if the batch's own
 * count exceeds it.  Rejects a bad version, a suite mismatch (GY_ERR_STATE),
 * a truncation, or trailing bytes (GY_ERR_ARG).  Returns GY_OK or a negative
 * GY_ERR_*.
 */
int gy_opk_batch_parse(struct gy_public_key *out, size_t out_cap, size_t *n,
                       const struct gy_suite_desc *desc, const uint8_t *buf,
                       size_t len);

/*
 * Application signing key certificate wire format (D-CUST-1,
 * CUSTODY_SPEC section 10): version || suite_id || SAK pub (pkid_be32 ||
 * curve_type || curve_pk) || issued_at_be64 || expiry_be64 (0 = no expiry)
 * || identity_pkid_be32 || identity_sig.  Structure only: the identity
 * signature's validity (and what bytes it actually covers - EncodeEC(sak_pub)
 * || issued_at_be64 || expiry_be64 || identity_pkid_be32 under a domain-
 * separated label, NOT these raw wire bytes) is gy_appkey_verify's job, not
 * this file's; proto/ does no cryptography.  gy_appkey_cert_wire_len sizes a
 * buffer before gy_appkey_cert_put.
 */
size_t gy_appkey_cert_wire_len(const struct gy_suite_desc *desc);

int gy_appkey_cert_put(uint8_t *out, size_t cap, size_t *outlen,
                       const struct gy_suite_desc *desc,
                       const struct gy_public_key *sak_pub, uint64_t issued_at,
                       uint64_t expiry, uint32_t identity_pkid,
                       const uint8_t *identity_sig);

/*
 * Parse a certificate's STRUCTURE only (no signature check).  identity_sig
 * must have room for desc->sig_len bytes.  Rejects a bad version, a suite
 * mismatch (GY_ERR_STATE), a truncation, or trailing bytes (GY_ERR_ARG).
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_appkey_cert_parse(const struct gy_suite_desc *desc, const uint8_t *buf,
                         size_t len, struct gy_public_key *sak_pub,
                         uint64_t *issued_at, uint64_t *expiry,
                         uint32_t *identity_pkid, uint8_t *identity_sig);

#endif /* GY_ENVELOPE_H */
