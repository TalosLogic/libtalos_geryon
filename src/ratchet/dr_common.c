/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "dr_common.h"

int
gy_drc_kdf_rk(const struct gy_suite_desc *desc, const uint8_t *rk,
              const uint8_t *ikm, size_t ikm_len, uint8_t out_rk[32],
              uint8_t out_ck[32], uint8_t out_nhk[32])
{
    uint8_t prk[GY_HASH_MAX];
    uint8_t okm[GY_DR_RK_OUT_LEN];
    uint8_t info[GY_DR_INFO_MAX];
    struct gy_iov iov;
    size_t infolen;
    int rc;

    iov.p = ikm;
    iov.len = ikm_len;

    rc = desc->hkdf_extract(prk, rk, GY_DR_KEY_LEN, &iov, 1);
    if (rc != GY_OK)
        goto out;
    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, "dr.root");
    if (rc != GY_OK)
        goto out;
    rc = desc->hkdf_expand(okm, GY_DR_RK_OUT_LEN, prk, info, infolen);
    if (rc != GY_OK)
        goto out;

    memcpy(out_rk, okm, 32);
    memcpy(out_ck, okm + 32, 32);
    memcpy(out_nhk, okm + 64, 32);

out:
    gy_secure_zero(prk, sizeof(prk));
    gy_secure_zero(okm, sizeof(okm));
    return rc;
}

/* One symmetric-key ratchet purpose (D-DR-2): single-block KDF-CTR over ck. */
static int
kdf_ck_one(const struct gy_suite_desc *desc, const uint8_t ck[32],
           const char *purpose, uint8_t out[32])
{
    uint8_t info[GY_DR_INFO_MAX];
    size_t infolen;
    int rc;

    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, purpose);
    if (rc != GY_OK)
        return rc;
    return gy_kdf_ctr(desc, out, 32, ck, 32, info, infolen, NULL, 0);
}

int
gy_drc_kdf_ck(const struct gy_suite_desc *desc, const uint8_t ck[32],
              uint8_t mk[32], uint8_t ck_next[32])
{
    int rc;

    rc = kdf_ck_one(desc, ck, "dr.msg", mk);
    if (rc != GY_OK)
        return rc;
    return kdf_ck_one(desc, ck, "dr.chain", ck_next);
}

int
gy_drc_derive_aead(const struct gy_suite_desc *desc, const uint8_t mk[32],
                   uint8_t aead_id, uint32_t n, uint8_t *key, uint8_t *nonce,
                   size_t *nonce_len)
{
    uint8_t info[GY_DR_INFO_MAX];
    uint8_t ctx[5];
    uint8_t buf[32 + GY_AEAD_MAX_NONCE];
    size_t infolen, nl;
    int rc;

    nl = gy_aead_nonce_len(aead_id);
    if (nl == 0)
        return GY_ERR_UNSUPPORTED;

    ctx[0] = aead_id;
    gy_be32_put(ctx + 1, n);

    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, "dr.aead");
    if (rc != GY_OK)
        return rc;
    rc =
        gy_kdf_ctr(desc, buf, 32 + nl, mk, 32, info, infolen, ctx, sizeof(ctx));
    if (rc != GY_OK) {
        gy_secure_zero(buf, sizeof(buf));
        return rc;
    }

    memcpy(key, buf, 32);
    memcpy(nonce, buf + 32, nl);
    *nonce_len = nl;
    gy_secure_zero(buf, sizeof(buf));
    return GY_OK;
}

/*
 * Drop one reference to epoch slot `ep`; when its last entry is gone the slot
 * is freed and its header key zeroized (D-DR-17).
 */
static void
epoch_unref(struct gy_skip_store *s, uint32_t ep)
{
    if (s->epochs[ep].refs > 0 && --s->epochs[ep].refs == 0)
        gy_secure_zero(&s->epochs[ep], sizeof(s->epochs[ep]));
}

void
gy_drc_store_remove(struct gy_skip_store *s, size_t idx)
{
    epoch_unref(s, s->ent[idx].epoch);
    gy_secure_zero(&s->ent[idx], sizeof(s->ent[idx]));
    if (idx + 1 < s->count)
        memmove(&s->ent[idx], &s->ent[idx + 1],
                (s->count - idx - 1) * sizeof(s->ent[0]));
    s->count--;
    gy_secure_zero(&s->ent[s->count], sizeof(s->ent[s->count]));
}

/*
 * Find the live epoch slot holding header key hk, or allocate a free one and
 * copy hk in.  A free slot always exists (live epochs <= count < GY_MAX_SKIP at
 * call time).  Returns the slot index.
 */
static uint32_t
epoch_intern(struct gy_skip_store *s, const uint8_t hk[32])
{
    size_t i, free_slot = GY_MAX_SKIP;

    for (i = 0; i < GY_MAX_SKIP; i++) {
        if (s->epochs[i].refs == 0) {
            if (free_slot == GY_MAX_SKIP)
                free_slot = i;
        } else if (gy_const_memcmp(s->epochs[i].hk, hk, 32) == 0) {
            return (uint32_t)i;
        }
    }
    memcpy(s->epochs[free_slot].hk, hk, 32);
    return (uint32_t)free_slot;
}

/*
 * Append a skipped key under epoch header key hk, evicting the oldest entry
 * (ent[0]) at capacity so an epoch slot is always free.
 */
static void
store_insert(struct gy_skip_store *s, const uint8_t hk[32], uint32_t n,
             const uint8_t mk[32])
{
    struct gy_skipped_key *e;
    uint32_t ep;

    if (s->count == GY_MAX_SKIP)
        gy_drc_store_remove(s, 0);
    ep = epoch_intern(s, hk);
    e = &s->ent[s->count++];
    e->epoch = ep;
    e->n = n;
    e->age = s->recv_count;
    memcpy(e->mk, mk, 32);
    s->epochs[ep].refs++;
}

void
gy_drc_store_post_success(struct gy_skip_store *s)
{
    size_t i;

    s->recv_count++;
    i = 0;
    while (i < s->count) {
        if (s->recv_count - s->ent[i].age >= GY_SKIP_AGE_LIMIT)
            gy_drc_store_remove(s, i);
        else
            i++;
    }
}

int
gy_drc_skip_forward(const struct gy_suite_desc *desc,
                    struct gy_skip_store *store, uint8_t ck[32], uint32_t *nr,
                    uint32_t to, const uint8_t hk[32])
{
    uint8_t mk[32], ckn[32];
    int rc = GY_OK;

    while (*nr < to) {
        rc = gy_drc_kdf_ck(desc, ck, mk, ckn);
        if (rc != GY_OK)
            break;
        memcpy(ck, ckn, 32);
        store_insert(store, hk, *nr, mk);
        (*nr)++;
    }
    gy_secure_zero(mk, sizeof(mk));
    gy_secure_zero(ckn, sizeof(ckn));
    return rc;
}
