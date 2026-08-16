/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_SUITE_H
#define GY_SUITE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Suite descriptor (D-GEN-7): the single indirection through which kex/ and
 * ratchet/ reach every suite-specific constant and primitive.  Those layers
 * carry NO 25519-specific constant and make NO direct call to a core
 * primitive; they operate on `const struct gy_suite_desc *` and size buffers
 * with the GY_*_MAX maxima below.
 *
 * The table is `static const` rodata (suite.c): function pointers in read-only
 * memory are not a writable hijack surface, and dispatch keys on the public
 * suite ID, so there is no constant-time concern.  The suite set is CLOSED at
 * the four suites; only geryon_c25519 is enabled, the rest are
 * filled in as their primitives land
 */

/*
 * Compile-time maxima across all four suites (D-GEN-7).  Callers stack-allocate
 * to these and operate on the row's actual lengths; no dynamic allocation.
 * The maxima are set by the X448 tier (56-byte keys/DH, 114-byte Ed448
 * signatures, 64-byte SHA-512, 57-byte X3DH F prefix).
 */
#define GY_CURVE_PK_MAX 56
#define GY_CURVE_SK_MAX 56
#define GY_DH_MAX 56
#define GY_SIG_MAX 114
#define GY_HASH_MAX 64
#define GY_F_MAX 57

/*
 * Scatter/gather element (D-X3DH-7): the multi-input hash ops take an array of
 * these so a caller can feed logically-concatenated inputs without ever
 * building a concatenation buffer in memory.  p may be NULL only when len is 0.
 */
struct gy_iov {
    const uint8_t *p;
    size_t len;
};

/*
 * One cipher suite.  The shape is complete up front: reserved (future-suite)
 * sizes are 0 and ops NULL in classical rows, so later suites fill rows in rather than
 * reshaping the struct.  AEAD is deliberately absent (D-DR-3 makes it a
 * per-session runtime selection dispatched in aead.c, not a suite property).
 */
struct gy_suite_desc {
    /* Identity. */
    uint8_t suite_id;   /* GY_SUITE_* wire byte. */
    uint8_t curve_type; /* GY_CURVE_TYPE_* (also the curve key length). */
    uint8_t is_hybrid;  /* 0 for classical suites, 1 for hybrid. */
    const char *name;   /* Suite field of every KDF info string (D-GEN-3). */

    /* Sizes (bytes). */
    size_t curve_pk_len;
    size_t curve_sk_len;
    size_t dh_len;
    size_t sig_len;
    size_t hash_len;
    size_t f_len; /* X3DH F prefix length (D-X3DH-7). */

    /* Curve operations. */
    int (*keypair)(uint8_t *pk, uint8_t *sk);
    int (*dh)(uint8_t *out, const uint8_t *sk, const uint8_t *peer_pk);
    int (*sign)(uint8_t *sig, const uint8_t *sk, const uint8_t *msg,
                size_t msg_len);
    int (*verify)(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg,
                  size_t msg_len);

    /*
     * Tier hash/KDF operations.  hmac and hkdf_extract take iovec arrays so the
     * D-X3DH-7 no-concatenation rule is generic over suites; hash and
     * hkdf_expand are single-input.  SP 800-108 KDF-CTR (D-DR-2) is built once
     * over hmac and is NOT a per-suite pointer.
     */
    int (*hash)(uint8_t *out, const uint8_t *in, size_t len);
    int (*hmac)(uint8_t *out, const uint8_t *key, size_t klen,
                const struct gy_iov *iov, size_t niov);
    int (*hkdf_extract)(uint8_t *prk, const uint8_t *salt, size_t slen,
                        const struct gy_iov *iov, size_t niov);
    int (*hkdf_expand)(uint8_t *out, size_t outlen, const uint8_t *prk,
                       const uint8_t *info, size_t infolen);

    /* Reserved component sizes for future suites (0 in classical rows). */
    size_t kem_pk_len;
    size_t kem_sk_len;
    size_t kem_ct_len;
    size_t kem_ss_len;
    size_t dsa_pk_len;
    size_t dsa_sk_len;
    size_t dsa_sig_len;

    /* Reserved operations for future suites (NULL in classical rows). */
    int (*kem_keypair)(uint8_t *pk, uint8_t *sk);
    int (*kem_encap)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*kem_decap)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
    int (*dsa_sign)(uint8_t *sig, const uint8_t *sk, const uint8_t *msg,
                    size_t msg_len);
    int (*dsa_verify)(const uint8_t *sig, const uint8_t *pk, const uint8_t *msg,
                      size_t msg_len);
};

/*
 * Look up the descriptor for a suite identifier, or NULL if the byte is not an
 * enabled suite.  Only geryon_c25519 (0x01) is enabled; every other
 * byte, including the reserved 0x00 and the not-yet-enabled 0x02..0x04,
 * returns NULL.  This is the one suite-lookup function in the library
 * (gy_suite folded in here).
 */
const struct gy_suite_desc *gy_suite_desc(uint8_t suite_id);

/*
 * Fill out with the suite's X3DH F prefix: f_len bytes of 0xFF (D-X3DH-7).
 * out must have room for f_len bytes (at most GY_F_MAX).  Returns GY_OK, or
 * GY_ERR_ARG on a NULL argument.
 */
int gy_suite_f(const struct gy_suite_desc *desc, uint8_t out[GY_F_MAX]);

#endif /* GY_SUITE_H */
