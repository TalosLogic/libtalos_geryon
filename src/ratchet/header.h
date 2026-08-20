/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_HEADER_H
#define GY_HEADER_H

#include <stddef.h>
#include <stdint.h>

#include "kex.h"

/*
 * Double Ratchet message header (D-DR-5),
 * classical form.  This ticket ships PLAINTEXT headers with the exact byte
 * layout header encryption will wrap; the version/suite_id frame bytes
 * live in the envelope layer, not here.  Classical layout:
 *
 *   flags (u32 BE) || curve_pk (curve_pk_len) || pn (u32 BE) || n (u32 BE)
 *
 * Flags carry the curve_type in the low byte (D-DR-5); the reserved
 * (future-suite) flag bits are zero in classical suites and are verified
 * zero on receive, so any flag tampering is rejected at decode.  The complete
 * encoded header is appended to the AEAD associated data of its own message,
 * so tampering of the other fields fails authentication instead.
 */

/* Largest encoded classical header across suites. */
#define GY_DR_HEADER_MAX (4 + GY_CURVE_PK_MAX + 4 + 4)

/* Flag bit assignments (D-DR-5, HYBRID_SPEC section 7.6). */
#define GY_DR_FLAG_CURVE_MASK 0x000000ffu
#define GY_DR_FLAG_MLKEM_EK_PRESENT (1u << 8)
#define GY_DR_FLAG_CONFIRM_CT_PRESENT (1u << 9)
/* Everything from bit 8 up must be zero in a classical header. */
#define GY_DR_FLAG_NONCURVE_MASK 0xffffff00u
/*
 * Reserved bits in a HYBRID header: bit 8 (MLKEM_EK_PRESENT) and bit 9
 * (CONFIRM_CT_PRESENT) are defined; bits 10..31 MUST be zero on the wire
 * (HYBRID_SPEC section 7.6).
 */
#define GY_DR_FLAG_RESERVED_MASK 0xfffffc00u

struct gy_dr_header {
    uint32_t flags;
    uint8_t ratchet_pk[GY_CURVE_PK_MAX];
    uint32_t pn;
    uint32_t n;
};

/*
 * Hybrid Double Ratchet header (HYBRID_SPEC section 7.6), plaintext form under
 * header encryption:
 *
 *   flags (u32 BE) || curve_pk || kem_ct || pn (u32 BE) || n (u32 BE)
 *     [|| mlkem_ek]   (iff flags & GY_DR_FLAG_MLKEM_EK_PRESENT)
 *     [|| confirm_ct] (iff flags & GY_DR_FLAG_CONFIRM_CT_PRESENT)
 *
 * kem_ct is always present (the per-step encapsulation, section 7.3); mlkem_ek
 * rides every header of a sending chain whose ML-KEM ratchet keypair was just
 * (re)generated; confirm_ct rides the responder's first sending chain (section
 * 8, wired in a later ticket).  The mlkem_ek / confirm_ct buffers are valid
 * only when their flag bit is set.
 */
#define GY_DR_HYBRID_HEADER_MAX                                                \
    (4 + GY_CURVE_PK_MAX + GY_KEM_CT_MAX + 4 + 4 + GY_KEM_EK_MAX +             \
     GY_KEM_CT_MAX)

struct gy_dr_hybrid_header {
    uint32_t flags;
    uint8_t ratchet_pk[GY_CURVE_PK_MAX];
    uint8_t kem_ct[GY_KEM_CT_MAX];
    uint32_t pn;
    uint32_t n;
    uint8_t mlkem_ek[GY_KEM_EK_MAX];
    uint8_t confirm_ct[GY_KEM_CT_MAX];
};

/*
 * Encode h into out (capacity cap), storing the encoded length in *outlen.
 * curve_pk_len bytes of ratchet_pk are written.  Returns GY_OK or GY_ERR_ARG
 * on a NULL argument or short buffer.
 */
int gy_dr_header_encode(const struct gy_suite_desc *desc,
                        const struct gy_dr_header *h, uint8_t *out, size_t cap,
                        size_t *outlen);

/*
 * Decode a header from in (length len) into h, storing the number of bytes
 * consumed in *consumed.  Rejects a short buffer (GY_ERR_ARG), a curve_type
 * that is not the pinned suite's (GY_ERR_STATE, cross-suite), and any nonzero
 * non-curve flag bit (GY_ERR_ARG, reserved/HE bits must be zero on the wire).
 */
int gy_dr_header_decode(const struct gy_suite_desc *desc,
                        struct gy_dr_header *h, const uint8_t *in, size_t len,
                        size_t *consumed);

/*
 * Plaintext length of a hybrid header (HYBRID_SPEC section 7.6) with the given
 * optional fields present.  desc must be a hybrid suite.  The four combinations
 * (ek/confirm each 0 or 1) are the valid enc_header plaintext lengths a receiver
 * validates against BEFORE any key derivation (D-DR-16); adding the AEAD tag
 * gives the enc_header wire length.  Returns 0 if desc is NULL or not hybrid.
 */
size_t gy_dr_hybrid_header_len(const struct gy_suite_desc *desc, int ek_present,
                               int confirm_present);

/*
 * Encode/decode a hybrid header.  Optional fields are written/read according to
 * the flag bits (encode) or the decoded flags (decode).  encode writes *outlen
 * bytes; decode sets *consumed.  decode rejects a curve_type mismatch
 * (GY_ERR_STATE, cross-suite) and any reserved bit 10..31 set (GY_ERR_ARG), and
 * a buffer too short for the flagged fields (GY_ERR_ARG).
 */
int gy_dr_hybrid_header_encode(const struct gy_suite_desc *desc,
                               const struct gy_dr_hybrid_header *h,
                               uint8_t *out, size_t cap, size_t *outlen);
int gy_dr_hybrid_header_decode(const struct gy_suite_desc *desc,
                               struct gy_dr_hybrid_header *h, const uint8_t *in,
                               size_t len, size_t *consumed);

#endif /* GY_HEADER_H */
