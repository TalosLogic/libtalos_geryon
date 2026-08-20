/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DR_COMMON_H
#define GY_DR_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "kex.h"

/*
 * Suite-agnostic Double Ratchet primitives shared by the classical engine
 * (double_ratchet.c) and the hybrid engine (hybrid_double_ratchet.c): the
 * root/chain/AEAD KDFs and the skipped-message-key store.  None of these carry
 * suite branching - the KDF_RK combiner (hdh for hybrid) lives in each engine's
 * ratchet step and is passed in as the IKM (gy_drc_kdf_rk).  Section references
 * are to HYBRID_SPEC / the Double Ratchet spec via docs/decisions/double_ratchet.md.
 */

#define GY_DR_KEY_LEN 32
#define GY_DR_INFO_MAX 48   /* "geryon.1." || suite_name || "." || purpose */
#define GY_DR_RK_OUT_LEN 96 /* new_rk || ck || nhk, 32 each (D-DR-1) */

/*
 * Skipped-message-key store bounds (D-DR-4/8).  MAX_SKIP bounds both a single
 * header's key jump and the store capacity; an entry is additionally aged out
 * after GY_SKIP_AGE_LIMIT later successful decryptions.
 */
#define GY_MAX_SKIP 1000
#define GY_SKIP_AGE_LIMIT 1000

/*
 * One skipped message key, indexed by (epoch header key, message number) under
 * header encryption (D-DR-17): `epoch` is a slot in the store's epoch table,
 * which holds the receiving header key `hk` that encrypted this message's
 * header.  The nonce is re-derived at use, so only the message key is stored
 * (D-DR-4).  age is the store's decrypt counter at insertion (D-DR-8).
 */
struct gy_skipped_key {
    uint32_t epoch;
    uint32_t n;
    uint64_t age;
    uint8_t mk[GY_DR_KEY_LEN];
};

/*
 * One epoch's header key, shared by every skipped entry from that receiving
 * chain (D-DR-17).  A slot is live while refs > 0 and its hk is zeroized the
 * moment its last entry is consumed or evicted; two live epochs never share an
 * hk.  The table is slotted (never compacted) so `epoch` indices stay stable.
 */
struct gy_skip_epoch {
    uint8_t hk[GY_DR_KEY_LEN];
    size_t refs;
};

/*
 * Fixed-capacity skipped-key store: entries are kept compacted in [0, count),
 * oldest first, so insertion at capacity evicts ent[0].  Because each live
 * entry holds one epoch ref, the live-epoch count never exceeds `count`, so an
 * epoch table of GY_MAX_SKIP slots always has room (no new capacity constant,
 * D-DR-17).  recv_count counts successful decryptions over the session's life
 * (aging clock).
 */
struct gy_skip_store {
    struct gy_skipped_key ent[GY_MAX_SKIP];
    size_t count;
    struct gy_skip_epoch epochs[GY_MAX_SKIP];
    uint64_t recv_count;
};

/*
 * KDF_RK (D-DR-1/14): HKDF(salt = rk, IKM = ikm, info = INFO("dr.root"),
 * L = 96) -> out_rk || out_ck || out_nhk.  out_rk may alias rk.  The IKM is
 * protocol-agnostic: classical suites pass the DH output (dh_len bytes), hybrid
 * suites pass hdh = HASH(kem_ss || dh) (hash_len bytes, HYBRID_SPEC section 7.3).
 */
int gy_drc_kdf_rk(const struct gy_suite_desc *desc, const uint8_t *rk,
                  const uint8_t *ikm, size_t ikm_len, uint8_t out_rk[32],
                  uint8_t out_ck[32], uint8_t out_nhk[32]);

/* mk = KDF_CK(ck, dr.msg); ck_next = KDF_CK(ck, dr.chain) (D-DR-2). */
int gy_drc_kdf_ck(const struct gy_suite_desc *desc, const uint8_t ck[32],
                  uint8_t mk[32], uint8_t ck_next[32]);

/*
 * Per-message AEAD key/nonce (D-DR-3): KDF-CTR(mk, Label = INFO("dr.aead"),
 * Context = aead_id || n_be32, L = 32 + nonce_len) split into key || nonce.
 */
int gy_drc_derive_aead(const struct gy_suite_desc *desc, const uint8_t mk[32],
                       uint8_t aead_id, uint32_t n, uint8_t *key,
                       uint8_t *nonce, size_t *nonce_len);

/*
 * Advance a receiving chain from *nr to `to` (exclusive), storing each skipped
 * message key under the epoch header key `hk`; leaves ck and *nr at `to`.
 */
int gy_drc_skip_forward(const struct gy_suite_desc *desc,
                        struct gy_skip_store *store, uint8_t ck[32],
                        uint32_t *nr, uint32_t to, const uint8_t hk[32]);

/* Zeroize and drop the entry at idx, keeping [0, count) compacted. */
void gy_drc_store_remove(struct gy_skip_store *s, size_t idx);

/* On a successful decrypt: advance the aging clock and evict aged entries. */
void gy_drc_store_post_success(struct gy_skip_store *s);

#endif /* GY_DR_COMMON_H */
