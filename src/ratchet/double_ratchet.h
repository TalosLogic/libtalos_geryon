/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DOUBLE_RATCHET_H
#define GY_DOUBLE_RATCHET_H

#include <stddef.h>
#include <stdint.h>

#include "dr_common.h"
#include "header.h"
#include "he.h"
#include "x3dh.h"

/*
 * Classical Double Ratchet core (the Double Ratchet specification, section 3,
 * D-DR-1/2/3/5/7/9/10/13..17).  Header encryption
 * wires the D-DR-13 header keys into the state machine and puts the
 * D-DR-16 wire frame on the wire: every header travels encrypted under a
 * header key that rotates on each DH ratchet step (D-DR-14).
 * Skipped-key handling, MAX_SKIP, and commit-after-verify follow D-DR-4/8;
 * the (hk, n) skipped re-key and the full HE receive order follow D-DR-17.
 */

/*
 * Header wire unit (D-DR-16): hdr_salt || enc_header_len_be16 || enc_header,
 * where enc_header is the HENCRYPT output (header plaintext + AEAD tag).  The
 * payload AD binds this whole unit (D-DR-16), so AD_msg is AD_session
 * plus it.
 */
#define GY_DR_ENC_HEADER_MAX (GY_DR_HEADER_MAX + GY_AEAD_MAX_TAG)
#define GY_DR_HDR_WIRE_MAX (GY_HE_SALT_LEN + 2 + GY_DR_ENC_HEADER_MAX)
#define GY_DR_AD_MSG_MAX (GY_X3DH_AD_MAX + GY_DR_HDR_WIRE_MAX)

/*
 * DR session state (the Double Ratchet specification, section 3.2), sized by the GY_*_MAX
 * maxima.  aead_id flows through the state and the dr.aead KDF Context in all
 * suites (D-DR-3 amendment) so a future suite's AEAD selection is a data change, not a
 * code-path change; classical suites pin it to 0x01.  Layout is not ABI: the
 * struct is owned by the session layer and passed by pointer.
 */
struct gy_dr_state {
    const struct gy_suite_desc *desc;
    uint8_t aead_id;

    struct gy_keypair dhs;        /* own ratchet key pair (DHs) */
    uint8_t dhr[GY_CURVE_PK_MAX]; /* remote ratchet public key (DHr) */
    uint8_t rk[GY_DR_KEY_LEN];    /* root key */
    uint8_t cks[GY_DR_KEY_LEN];   /* sending chain key */
    uint8_t ckr[GY_DR_KEY_LEN];   /* receiving chain key */

    /* Header keys (D-DR-13/14): current + next, each direction. */
    uint8_t hks[GY_DR_KEY_LEN];  /* sending header key (HKs) */
    uint8_t hkr[GY_DR_KEY_LEN];  /* receiving header key (HKr) */
    uint8_t nhks[GY_DR_KEY_LEN]; /* next sending header key (NHKs) */
    uint8_t nhkr[GY_DR_KEY_LEN]; /* next receiving header key (NHKr) */

    uint32_t ns; /* messages sent in the current sending chain */
    uint32_t nr; /* messages received in the current receiving chain */
    uint32_t pn; /* length of the previous sending chain */

    uint8_t have_dhr;
    uint8_t have_cks;
    uint8_t have_ckr;
    uint8_t have_hks;
    uint8_t have_hkr;
    uint8_t have_nhks;
    uint8_t have_nhkr;

    struct gy_skip_store skipped; /* skipped message keys */
};

/*
 * Initialize the initiator (Alice): root key <- SKdr, remote ratchet key <-
 * the responder's SPK public, generate the own ratchet pair, and perform the
 * initial sending ratchet (D-DR-7).  secrets->sk_dr is zeroized
 * (ownership transfers); shared_hka/shared_nhkb seed the initial header keys
 * (D-DR-13).  Returns GY_OK or a negative GY_ERR_* (state zeroized on failure).
 */
int gy_dr_init_alice(struct gy_dr_state *st, const struct gy_suite_desc *desc,
                     uint8_t aead_id, struct gy_dr_secrets *secrets,
                     const uint8_t *remote_ratchet_pk);

/*
 * Initialize the responder (Bob): root key <- SKdr, own ratchet pair <- the
 * SPK key pair, no sending or receiving chain yet (established on his first
 * DH ratchet when Alice's first header arrives).  secrets->sk_dr is zeroized.
 */
int gy_dr_init_bob(struct gy_dr_state *st, const struct gy_suite_desc *desc,
                   uint8_t aead_id, struct gy_dr_secrets *secrets,
                   const struct gy_keypair *spk_keypair);

/*
 * Encrypt pt under the sending chain, writing the D-DR-16 wire frame
 * (version || suite_id || hdr_salt || enc_header_len_be16 || enc_header ||
 * payload) into out (capacity cap), length in *outlen.  The header travels
 * encrypted under HKs (D-DR-15); ad is AD_session (<= GY_X3DH_AD_MAX)
 * and is concatenated with the header wire unit to form the payload AD
 * (D-DR-16).
 * Returns GY_OK, GY_ERR_STATE if there is no sending chain or header key yet,
 * or GY_ERR_ARG on a short buffer.
 */
int gy_dr_encrypt(struct gy_dr_state *st, uint8_t *out, size_t cap,
                  size_t *outlen, const uint8_t *pt, size_t ptlen,
                  const uint8_t *ad, size_t adlen);

/*
 * Decrypt a D-DR-16 wire frame (skipped keys + header
 * encryption).  Validates the frame prefix and enc_header_len, HDECRYPTs the
 * header under HKr then NHKr (D-DR-17; a NHKr success drives the DH
 * ratchet step), then runs the current chain or ratchet, skipping and storing
 * intervening message keys (bounded by MAX_SKIP).  All chain work is staged;
 * the live state mutates ONLY after the payload tag verifies, so a forged
 * message is a complete no-op (D-DR-4/8).  Returns GY_OK (and
 * sets *outlen), GY_ERR_STATE on a MAX_SKIP violation, GY_ERR_ARG on a
 * malformed frame, or GY_ERR_VERIFY on a header or payload tag mismatch.  ad
 * is AD_session.  The per-epoch (hk, n) skipped re-key follows D-DR-17.
 */
int gy_dr_decrypt(struct gy_dr_state *st, uint8_t *out, size_t cap,
                  size_t *outlen, const uint8_t *msg, size_t msg_len,
                  const uint8_t *ad, size_t adlen);

/*
 * As gy_dr_decrypt, but reports whether a header key opened the encrypted
 * header (D-SES-6.3 trial-decryption association).  *header_matched is set to 1
 * if any skipped-epoch hk, HKr, or NHKr decrypted the header (even if the
 * payload tag then failed), else 0.  The session layer uses this to stop the
 * per-DeviceRecord association walk at the first session whose header matches:
 * a matched header with a failing payload is a hard error, never a
 * continue-to-next-session (that would be a padding-oracle-shaped search).
 * gy_dr_decrypt is exactly this with header_matched == NULL.
 */
int gy_dr_decrypt_assoc(struct gy_dr_state *st, uint8_t *out, size_t cap,
                        size_t *outlen, const uint8_t *msg, size_t msg_len,
                        const uint8_t *ad, size_t adlen, int *header_matched);

/* Zeroize all key material in the state (teardown). */
void gy_dr_free(struct gy_dr_state *st);

#ifdef GY_TEST_HOOKS
/*
 * Test seam: when set, ratchet key-pair generation calls this instead of
 * gy_keypair_generate, so a determinism KAT can inject fixed ratchet keys
 * (D-DR-11).  Set to NULL to restore production behavior.
 */
extern int (*gy_dr_test_keypair)(const struct gy_suite_desc *desc,
                                 struct gy_keypair *out);

/*
 * Per-receive header-decryption trial counters, by phase in
 * the D-DR-17 receive order.  gy_dr_decrypt resets these to zero on entry, so a
 * test can assert exactly (distinct stored epoch hks) skipped trials + 1 (HKr)
 * or + 2 (HKr, NHKr) header decryptions per receive.
 */
struct gy_dr_he_counters {
    unsigned skipped; /* phase 1: one trial per distinct stored epoch hk */
    unsigned hkr;     /* phase 2: current receiving header key */
    unsigned nhkr;    /* phase 3: next receiving header key */
};
extern struct gy_dr_he_counters gy_dr_he_ctr;

/* Expose the internal KDFs for the RFC 5869 / SP 800-108 code-path KATs. */
int gy_dr_kdf_rk(const struct gy_suite_desc *desc, const uint8_t *rk,
                 const uint8_t *dh, uint8_t out_rk[32], uint8_t out_ck[32],
                 uint8_t out_nhk[32]);
int gy_dr_kdf_ck(const struct gy_suite_desc *desc, const uint8_t ck[32],
                 uint8_t mk[32], uint8_t ck_next[32]);
int gy_dr_derive_aead(const struct gy_suite_desc *desc, const uint8_t mk[32],
                      uint8_t aead_id, uint32_t n, uint8_t *key, uint8_t *nonce,
                      size_t *nonce_len);
#endif

#endif /* GY_DOUBLE_RATCHET_H */
