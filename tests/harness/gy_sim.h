/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Thin two-party simulator: it owns the wiring the library
 * deliberately leaves to the session layer (Sesame): carrying the first DR
 * message with the handshake, committing OPK deletion only after that message
 * decrypts (D-X3DH-10), and base-key dedupe of re-sent initial messages
 * (D-X3DH-3).  It is test-only; production dedupe and session
 * management live in the session layer.
 */

#ifndef GY_SIM_H
#define GY_SIM_H

#include <stddef.h>
#include <stdint.h>

#include "double_ratchet.h"
#include "hybrid_double_ratchet.h"

#define GY_SIM_MAX_OPK 4

/* Largest initial message: prefix || first DR message (header + ct + tag). */
#define GY_SIM_MSG_MAX                                                         \
    (GY_X3DH_PREFIX_MAX + GY_DR_HEADER_MAX + 512 + GY_AEAD_MAX_TAG)

/* The responder (Bob): identity, prekeys, OPK stock, and its one session. */
struct gy_sim {
    const struct gy_suite_desc *desc;
    uint8_t aead_id;

    struct gy_keypair bob_ik;
    struct gy_signed_prekey bob_spk;
    struct gy_keypair opk_stock[GY_SIM_MAX_OPK];
    size_t opk_count;
    struct gy_prekey_bundle bundle;

    struct gy_dr_state bob_dr;
    int bob_up;
    uint8_t base[2 * GY_CURVE_PK_MAX]; /* IK_A || EK_A of the live session */
    int have_base;

    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;
};

/* An initiator (Alice): a fresh identity/ephemeral and its own DR state. */
struct gy_sim_initiator {
    const struct gy_suite_desc *desc;
    uint8_t aead_id;
    struct gy_keypair ik;
    struct gy_keypair ek;
    struct gy_dr_state dr;
    int up;
    uint8_t ad[GY_X3DH_AD_MAX];
    size_t adl;
};

/*
 * Set up the responder: generate its identity, signed prekey, and (if with_opk)
 * a one-time prekey, and publish the bundle.  Returns GY_OK or a GY_ERR_*.
 */
int gy_sim_setup(struct gy_sim *sim, const struct gy_suite_desc *desc,
                 uint8_t aead_id, int with_opk);

/*
 * Initiator side: create a fresh Alice bound to sim's bundle, run X3DH, start
 * her DR, and assemble the initial message (prefix || first DR message carrying
 * pt).  Writes it to out (capacity cap).  Returns GY_OK or a GY_ERR_*.
 */
int gy_sim_start(struct gy_sim_initiator *init, const struct gy_sim *sim,
                 uint8_t *out, size_t cap, size_t *outlen, const uint8_t *pt,
                 size_t ptlen);

/*
 * Responder side: process an initial message.  On a base-key match with the
 * live session it is treated as a re-delivery and routed to the existing DR
 * (a consumed first message then fails to decrypt).  Otherwise X3DH responds,
 * a pending DR is built, and the first message is decrypted; ONLY on success
 * is the session committed and the consumed OPK deleted (D-X3DH-10).  Writes
 * the recovered plaintext to out.  Returns GY_OK, or the handshake/decrypt
 * error (the OPK is retained on any failure).
 */
int gy_sim_bob_recv_initial(struct gy_sim *sim, const uint8_t *msg,
                            size_t msglen, uint8_t *out, size_t cap,
                            size_t *outlen);

/*
 * D-DR-16 frame fields, for the frame-granularity tamper matrix.
 * The frame is version || suite_id || hdr_salt(16) || enc_header_len_be16 ||
 * enc_header || payload; gy_sim_corrupt flips one byte inside the named field.
 */
enum gy_sim_field {
    GY_SIM_F_VERSION,
    GY_SIM_F_SUITE,
    GY_SIM_F_SALT,
    GY_SIM_F_LEN,
    GY_SIM_F_ENC_HEADER,
    GY_SIM_F_PAYLOAD
};

/*
 * Flip one byte in the named field of a D-DR-16 frame in place.  enc_header_len
 * is read from the frame to locate enc_header and payload.  Returns GY_OK, or
 * GY_ERR_ARG if the frame is too short to hold the field.
 */
int gy_sim_corrupt(uint8_t *frame, size_t flen, enum gy_sim_field field);

/* Zeroizing teardown. */
void gy_sim_free(struct gy_sim *sim);
void gy_sim_initiator_free(struct gy_sim_initiator *init);

/* ------------------------------------------------------------------------- *
 * Hybrid two-party simulator (HYBRID_SPEC).  The hybrid analogue of the
 * classical sim above: it drives the hybrid X3DH handshake, the KEM
 * confirmation, and the hybrid Double Ratchet, carrying the first frame with
 * the handshake, committing OPK deletion only after that frame decrypts
 * (D-X3DH-10), and base-key deduping re-sent initial messages.  Real primitives
 * throughout (no fixed seams): the sim exercises behavior, not byte KATs.
 * ------------------------------------------------------------------------- */

/* Largest hybrid initial message: prefix || first hybrid DR frame. */
#define GY_SIM_HYBRID_MSG_MAX                                                  \
    (GY_HYBRID_X3DH_PREFIX_MAX + GY_DR_HYBRID_HEADER_MAX + 512 +               \
     GY_AEAD_MAX_TAG)

/* Responder (Bob): hybrid identity, prekeys, OPK stock, and its one session. */
struct gy_sim_hybrid {
    const struct gy_suite_desc *desc;
    uint8_t aead_id;
    uint32_t interval; /* negotiated ML-KEM refresh interval */

    struct gy_hybrid_identity_keypair bob_ik;
    struct gy_hybrid_signed_prekey bob_spk;
    struct gy_hybrid_keypair opk_stock[GY_SIM_MAX_OPK];
    size_t opk_count;
    struct gy_hybrid_prekey_bundle bundle;

    struct gy_hybrid_dr_state bob_dr;
    int bob_up;
    uint8_t
        base[2 * GY_CURVE_PK_MAX]; /* IK_A || EK_A curve of the live session */
    int have_base;

    uint8_t ad[GY_HYBRID_AD_MAX];
    size_t adl;
};

/* Initiator (Alice): a fresh hybrid identity/ephemeral and its own DR state.
 * ik carries Alice's identity ML-KEM dk, needed to open Bob's confirmation. */
struct gy_sim_hybrid_initiator {
    const struct gy_suite_desc *desc;
    uint8_t aead_id;
    uint32_t interval;
    struct gy_hybrid_identity_keypair ik;
    struct gy_keypair ek;
    struct gy_hybrid_dr_state dr;
    int up;
    uint8_t ad[GY_HYBRID_AD_MAX];
    size_t adl;
};

/*
 * Set up the responder: generate its hybrid identity and signed prekey (its SPK
 * advertises intervals 1..100 and aead_id), optionally a one-time prekey, and
 * publish the hybrid bundle.  Returns GY_OK or a GY_ERR_*.
 */
int gy_sim_hybrid_setup(struct gy_sim_hybrid *sim,
                        const struct gy_suite_desc *desc, uint8_t aead_id,
                        uint32_t interval, int with_opk);

/*
 * Initiator side: create a fresh Alice bound to sim's bundle, run hybrid X3DH,
 * start her hybrid DR, and assemble the initial message (prefix || first hybrid
 * DR frame carrying pt).  Returns GY_OK or a GY_ERR_*.
 */
int gy_sim_hybrid_start(struct gy_sim_hybrid_initiator *init,
                        const struct gy_sim_hybrid *sim, uint8_t *out,
                        size_t cap, size_t *outlen, const uint8_t *pt,
                        size_t ptlen);

/*
 * Responder side: process a hybrid initial message.  On a base-key match it
 * routes to the live session (a consumed first frame no longer decrypts).
 * Otherwise hybrid X3DH responds, a pending hybrid DR is built (confirming to
 * Alice's identity ML-KEM ek), and the first frame is decrypted; ONLY on
 * success is the session committed and the consumed OPK deleted (D-X3DH-10).
 * Returns GY_OK, or the handshake/decrypt error (OPK retained on any failure).
 */
int gy_sim_hybrid_bob_recv_initial(struct gy_sim_hybrid *sim,
                                   const uint8_t *msg, size_t msglen,
                                   uint8_t *out, size_t cap, size_t *outlen);

/*
 * Per-field corruption for the hybrid frame tamper matrix.  MLKEM_EK / KEM_CT /
 * FLAGS address the cleartext hybrid X3DH INITIAL prefix; CONFIRM_CT addresses
 * the encrypted header of Bob's first ratchet REPLY (confirm_ct is header-
 * encrypted on the wire, so this flips a byte in that enc_header region).  The
 * caller passes the frame the field belongs to.
 */
enum gy_sim_hybrid_field {
    GY_SIM_HF_MLKEM_EK,  /* initial: Alice's identity ML-KEM ek (in IK_A) */
    GY_SIM_HF_KEM_CT,    /* initial: ct_ik, the first per-DH KEM ciphertext */
    GY_SIM_HF_FLAGS,     /* initial: hybrid_flag (reserved-bit byte) */
    GY_SIM_HF_CONFIRM_CT /* reply: enc_header carrying confirm_ct */
};

/*
 * Flip one byte in the named field.  Returns GY_OK, or GY_ERR_ARG if the frame
 * is too short to hold the field.
 */
int gy_sim_hybrid_corrupt(const struct gy_suite_desc *desc, uint8_t *frame,
                          size_t flen, enum gy_sim_hybrid_field field);

/* Zeroizing teardown. */
void gy_sim_hybrid_free(struct gy_sim_hybrid *sim);
void gy_sim_hybrid_initiator_free(struct gy_sim_hybrid_initiator *init);

#endif /* GY_SIM_H */
