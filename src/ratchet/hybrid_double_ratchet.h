/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_HYBRID_DOUBLE_RATCHET_H
#define GY_HYBRID_DOUBLE_RATCHET_H

#include <stddef.h>
#include <stdint.h>

#include "double_ratchet.h"
#include "header.h"
#include "he.h"

/*
 * Hybrid Double Ratchet engine (HYBRID_SPEC section 7).  This is the parallel
 * sibling of the classical engine (double_ratchet.c): identical symmetric-key
 * ratchet, skipped-key handling, header-key rotation, and commit-after-verify
 * (all shared through dr_common.{c,h}), PLUS an ML-KEM ratchet.  Every DH
 * ratchet step mixes a fresh ML-KEM shared secret into the root KDF via the
 * PQ-first combiner hdh = HASH(kem_ss || dh) (section 3.1); the sender's ML-KEM
 * ratchet keypair is refreshed every mlkem_interval steps and, when refreshed,
 * rides every header of the ensuing sending chain.  The KEM confirmation and
 * PQ-pending state (section 8) are wired in a later ticket; a CONFIRM_CT_PRESENT
 * header is rejected here.
 */

/*
 * Session role, fixed at init (section 8): the responder emits the KEM
 * confirmation in its first sending chain; the initiator consumes it.
 */
#define GY_HYBRID_ROLE_INITIATOR 0
#define GY_HYBRID_ROLE_RESPONDER 1

/*
 * Peer PQ-authentication state (HYBRID_SPEC section 8.4).  The responder's
 * session walks CLASSICAL_ONLY -> CONFIRM_SENT -> PQ_CONFIRMED; the initiator
 * goes CLASSICAL_ONLY -> PQ_CONFIRMED on processing the confirmation chain
 * (it never sends confirmation, so it never occupies CONFIRM_SENT).  The proto
 * layer maps {CLASSICAL_ONLY, CONFIRM_SENT} -> pending, PQ_CONFIRMED ->
 * confirmed.
 */
#define GY_HYBRID_PQ_CLASSICAL_ONLY 0
#define GY_HYBRID_PQ_CONFIRM_SENT 1
#define GY_HYBRID_PQ_CONFIRMED 2

/*
 * Hybrid DR session state (section 7.2, section 8).  The classical base carries
 * the curve ratchet pair, remote curve key, root/chain keys, header keys,
 * counters, and the skipped-key store; the hybrid additions carry the ML-KEM
 * ratchet and the KEM-confirmation machinery.  Layout is not ABI (session-layer
 * owned, passed by pointer).
 */
struct gy_hybrid_dr_state {
    struct gy_dr_state base; /* curve ratchet + chains + header keys + skip */

    uint8_t mlkem_ek[GY_KEM_EK_MAX];  /* own current ML-KEM ratchet ek */
    uint8_t mlkem_dk[GY_KEM_DK_MAX];  /* own current ML-KEM ratchet dk */
    uint8_t remote_ek[GY_KEM_EK_MAX]; /* cached remote ML-KEM ratchet ek */
    uint8_t kem_ct[GY_KEM_CT_MAX]; /* outbound kem_ct for this sending chain */

    uint32_t mlkem_counter; /* ratchet steps since the last keypair refresh */
    uint32_t
        mlkem_interval; /* refresh interval (section 6.6), fixed for life */

    uint8_t have_remote_ek; /* remote_ek holds a valid cached key */
    uint8_t have_kem_ct;    /* kem_ct holds the current sending ciphertext */
    uint8_t
        send_ek_pending; /* include mlkem_ek in this sending chain's headers */

    /* KEM confirmation (section 8). */
    uint8_t role;     /* GY_HYBRID_ROLE_* */
    uint8_t pq_state; /* GY_HYBRID_PQ_* */
    /*
     * Responder: the initiator identity ML-KEM ek to encapsulate to (public).
     * Initiator: its own identity ML-KEM dk to decapsulate with (secret,
     * transient - zeroized once confirmation completes).
     */
    uint8_t id_mlkem_ek[GY_KEM_EK_MAX];
    uint8_t id_mlkem_dk[GY_KEM_DK_MAX];
    uint8_t confirm_ct[GY_KEM_CT_MAX]; /* responder: confirm ct for its chain */

    uint8_t confirm_pending; /* responder: emit confirm in first send chain */
    uint8_t send_confirm_pending; /* current send chain carries confirm_ct */
    uint8_t have_confirm_ct;      /* confirm_ct populated */
    uint8_t have_id_dk;           /* initiator: id_mlkem_dk still held */
};

/* Largest hybrid enc_header (both optional fields) plus the AEAD tag. */
#define GY_DR_HYBRID_ENC_HEADER_MAX (GY_DR_HYBRID_HEADER_MAX + GY_AEAD_MAX_TAG)
#define GY_DR_HYBRID_HDR_WIRE_MAX                                              \
    (GY_HE_SALT_LEN + 2 + GY_DR_HYBRID_ENC_HEADER_MAX)
#define GY_DR_HYBRID_AD_MSG_MAX (GY_HYBRID_AD_MAX + GY_DR_HYBRID_HDR_WIRE_MAX)

/*
 * Initialize the initiator (Alice) for a hybrid session: root key <- SKdr,
 * remote curve ratchet key <- Bob's SPK curve key, cached remote ML-KEM key <-
 * Bob's SPK ML-KEM key, generate the own hybrid ratchet keypair, and perform
 * the initial sending ratchet (section 7.2/7.3).  remote_spk is Bob's signed
 * prekey public (curve + mlkem_ek); mlkem_interval is the negotiated refresh
 * interval (section 6.6).  secrets->sk_dr is zeroized (ownership transfers).
 * id_mlkem_dk is Alice's own identity ML-KEM decapsulation key (kem_sk_len
 * bytes), used once to open the responder's KEM confirmation (section 8.3);
 * it is copied into the state and zeroized there when confirmation completes.
 * Returns GY_OK or a negative GY_ERR_* (state zeroized on failure).
 */
int gy_hybrid_dr_init_alice(struct gy_hybrid_dr_state *st,
                            const struct gy_suite_desc *desc, uint8_t aead_id,
                            struct gy_dr_secrets *secrets,
                            const struct gy_hybrid_public_key *remote_spk,
                            uint32_t mlkem_interval,
                            const uint8_t *id_mlkem_dk);

/*
 * Initialize the responder (Bob): root key <- SKdr, own hybrid ratchet keypair
 * <- his SPK hybrid keypair (curve + ML-KEM), remote ML-KEM key invalid until
 * Alice's first header, ML-KEM ratchet counter <- interval (forces a fresh
 * ML-KEM keypair on his first ratchet, section 7.2).  initiator_id_mlkem_ek is
 * Alice's identity ML-KEM encapsulation key (kem_pk_len bytes, public), which
 * Bob encapsulates the KEM confirmation to in his first sending chain (section
 * 8.2).  secrets->sk_dr is zeroized.
 */
int gy_hybrid_dr_init_bob(struct gy_hybrid_dr_state *st,
                          const struct gy_suite_desc *desc, uint8_t aead_id,
                          struct gy_dr_secrets *secrets,
                          const struct gy_hybrid_keypair *spk_keypair,
                          uint32_t mlkem_interval,
                          const uint8_t *initiator_id_mlkem_ek);

/*
 * The peer PQ-authentication state (GY_HYBRID_PQ_*, section 8.4).  Returns
 * GY_HYBRID_PQ_CLASSICAL_ONLY for a NULL argument.
 */
uint8_t gy_hybrid_dr_pq_state(const struct gy_hybrid_dr_state *st);

/*
 * Encrypt pt under the sending chain, writing the D-DR-16 wire frame with a
 * hybrid header (kem_ct always; mlkem_ek when this sending chain refreshed its
 * ML-KEM keypair).  ad is AD_session (<= GY_HYBRID_AD_MAX).  Returns GY_OK,
 * GY_ERR_STATE if there is no sending chain yet, or GY_ERR_ARG on a short
 * buffer.
 */
int gy_hybrid_dr_encrypt(struct gy_hybrid_dr_state *st, uint8_t *out,
                         size_t cap, size_t *outlen, const uint8_t *pt,
                         size_t ptlen, const uint8_t *ad, size_t adlen);

/*
 * Decrypt a hybrid D-DR-16 wire frame (skipped keys + header encryption + the
 * ML-KEM ratchet).  Mirrors gy_dr_decrypt: header trial-decryption in the
 * D-DR-17 order, MAX_SKIP checks before any key derivation, and a fully staged
 * chain/ratchet that mutates the live state (including the ML-KEM ratchet
 * fields) only after the payload tag verifies.  Returns GY_OK, GY_ERR_STATE on
 * a MAX_SKIP violation or a missing-ek header, GY_ERR_ARG on a malformed frame,
 * or GY_ERR_VERIFY on a header or payload tag mismatch.
 */
int gy_hybrid_dr_decrypt(struct gy_hybrid_dr_state *st, uint8_t *out,
                         size_t cap, size_t *outlen, const uint8_t *msg,
                         size_t msg_len, const uint8_t *ad, size_t adlen);

/*
 * As gy_hybrid_dr_decrypt, but reports whether a header key opened the header
 * (D-SES-6.3 association walk), identical contract to gy_dr_decrypt_assoc.
 */
int gy_hybrid_dr_decrypt_assoc(struct gy_hybrid_dr_state *st, uint8_t *out,
                               size_t cap, size_t *outlen, const uint8_t *msg,
                               size_t msg_len, const uint8_t *ad, size_t adlen,
                               int *header_matched);

/* Zeroize all key material in the state (teardown). */
void gy_hybrid_dr_free(struct gy_hybrid_dr_state *st);

#ifdef GY_TEST_HOOKS
/*
 * Test seams for the ML-KEM ratchet (D-PQ-3): when set, the hybrid engine calls
 * these instead of desc->kem_keypair / desc->kem_encap, so a determinism KAT can
 * pin every wire byte of the ML-KEM ratchet.  The curve ratchet keypair uses the
 * classical gy_dr_test_keypair seam (double_ratchet.h).  Set to NULL to restore
 * production behavior.
 */
extern int (*gy_hybrid_dr_test_kem_keypair)(const struct gy_suite_desc *desc,
                                            uint8_t *ek, uint8_t *dk);
extern int (*gy_hybrid_dr_test_kem_encaps)(const struct gy_suite_desc *desc,
                                           uint8_t *ct, uint8_t *ss,
                                           const uint8_t *ek);

/*
 * ML-KEM ratchet operation counters, reset to zero on every
 * gy_hybrid_dr_decrypt entry, so a test can assert that a pre-derivation
 * rejection (bad enc_header_len, missing mlkem_ek) performed NO ML-KEM
 * operation and NO root KDF (all four fields stay zero).  Header
 * trial-decryption counts reuse gy_dr_he_ctr (double_ratchet.h).
 */
struct gy_hybrid_dr_counters {
    unsigned kem_keypair;
    unsigned kem_encaps;
    unsigned kem_decaps;
    unsigned kdf_rk;
};
extern struct gy_hybrid_dr_counters gy_hybrid_dr_ctr;
#endif

#endif /* GY_HYBRID_DOUBLE_RATCHET_H */
