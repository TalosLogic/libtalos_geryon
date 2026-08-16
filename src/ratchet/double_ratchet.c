/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "double_ratchet.h"

#define GY_INFO_MAX 48
#define GY_RK_OUT_LEN 96 /* new_rk || ck || nhk, 32 each (D-DR-1) */

#ifdef GY_TEST_HOOKS
int (*gy_dr_test_keypair)(const struct gy_suite_desc *desc,
                          struct gy_keypair *out);
struct gy_dr_he_counters gy_dr_he_ctr;
#define GY_DR_HE_COUNT(field) (gy_dr_he_ctr.field++)
#define GY_DR_HE_COUNT_RESET() (memset(&gy_dr_he_ctr, 0, sizeof(gy_dr_he_ctr)))
#else
#define GY_DR_HE_COUNT(field) ((void)0)
#define GY_DR_HE_COUNT_RESET() ((void)0)
#endif

/* Generate a ratchet key pair, honoring the test seam when present. */
static int
gen_ratchet_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
#ifdef GY_TEST_HOOKS
    if (gy_dr_test_keypair != NULL)
        return gy_dr_test_keypair(desc, out);
#endif
    return gy_keypair_generate(desc, out);
}

/*
 * KDF_RK (D-DR-1/14): HKDF(salt = rk, IKM = dh, info = INFO("dr.root"),
 * L = 96) -> new_rk || ck || nhk.  Computed via locals so out_rk may alias rk.
 */
static int
kdf_rk(const struct gy_suite_desc *desc, const uint8_t *rk, const uint8_t *dh,
       uint8_t out_rk[32], uint8_t out_ck[32], uint8_t out_nhk[32])
{
    uint8_t prk[GY_HASH_MAX];
    uint8_t okm[GY_RK_OUT_LEN];
    uint8_t info[GY_INFO_MAX];
    struct gy_iov iov;
    size_t infolen;
    int rc;

    iov.p = dh;
    iov.len = desc->dh_len;

    rc = desc->hkdf_extract(prk, rk, GY_DR_KEY_LEN, &iov, 1);
    if (rc != GY_OK)
        goto out;
    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, "dr.root");
    if (rc != GY_OK)
        goto out;
    rc = desc->hkdf_expand(okm, GY_RK_OUT_LEN, prk, info, infolen);
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
    uint8_t info[GY_INFO_MAX];
    size_t infolen;
    int rc;

    rc = gy_info(info, sizeof(info), &infolen, desc->suite_id, purpose);
    if (rc != GY_OK)
        return rc;
    return gy_kdf_ctr(desc, out, 32, ck, 32, info, infolen, NULL, 0);
}

/* mk = KDF_CK(ck, dr.msg); ck_next = KDF_CK(ck, dr.chain). */
static int
kdf_ck(const struct gy_suite_desc *desc, const uint8_t ck[32], uint8_t mk[32],
       uint8_t ck_next[32])
{
    int rc;

    rc = kdf_ck_one(desc, ck, "dr.msg", mk);
    if (rc != GY_OK)
        return rc;
    return kdf_ck_one(desc, ck, "dr.chain", ck_next);
}

/*
 * Per-message AEAD key/nonce (D-DR-3): KDF-CTR(mk, Label = INFO("dr.aead"),
 * Context = aead_id || n_be32, L = 32 + nonce_len) split into key || nonce.
 */
static int
derive_aead(const struct gy_suite_desc *desc, const uint8_t mk[32],
            uint8_t aead_id, uint32_t n, uint8_t *key, uint8_t *nonce,
            size_t *nonce_len)
{
    uint8_t info[GY_INFO_MAX];
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

int
gy_dr_init_alice(struct gy_dr_state *st, const struct gy_suite_desc *desc,
                 uint8_t aead_id, struct gy_dr_secrets *secrets,
                 const uint8_t *remote_ratchet_pk)
{
    uint8_t dh[GY_DH_MAX];
    int rc;

    if (st == NULL || desc == NULL || secrets == NULL ||
        remote_ratchet_pk == NULL)
        return GY_ERR_ARG;

    memset(st, 0, sizeof(*st));
    st->desc = desc;
    st->aead_id = aead_id;
    memcpy(st->rk, secrets->sk_dr, GY_DR_KEY_LEN);
    memcpy(st->dhr, remote_ratchet_pk, desc->curve_pk_len);
    st->have_dhr = 1;

    /*
     * Initial header-key mapping (D-DR-13): Alice's
     * HKs = shared_hka and NHKr = shared_nhkb; HKr stays unset until Bob's
     * first reply ratchets her receiving side, and NHKs is filled by the
     * initial sending ratchet.
     */
    memcpy(st->hks, secrets->shared_hka, GY_DR_KEY_LEN);
    memcpy(st->nhkr, secrets->shared_nhkb, GY_DR_KEY_LEN);
    st->have_hks = 1;
    st->have_nhkr = 1;

    rc = gen_ratchet_keypair(desc, &st->dhs);
    if (rc != GY_OK)
        goto err;

    /*
     * Initial sending ratchet (D-DR-7).  This is the special init case
     * of D-DR-14's sending step: HKs is already shared_hka (not rotated
     * from NHKs, which does not exist yet), so KDF_RK_HE only fills NHKs.
     */
    rc = desc->dh(dh, st->dhs.sk, st->dhr);
    if (rc != GY_OK)
        goto err;
    rc = kdf_rk(desc, st->rk, dh, st->rk, st->cks, st->nhks);
    gy_secure_zero(dh, sizeof(dh));
    if (rc != GY_OK)
        goto err;
    st->have_cks = 1;
    st->have_nhks = 1;

    gy_secure_zero(secrets->sk_dr, sizeof(secrets->sk_dr));
    return GY_OK;

err:
    gy_secure_zero(st, sizeof(*st));
    return rc;
}

int
gy_dr_init_bob(struct gy_dr_state *st, const struct gy_suite_desc *desc,
               uint8_t aead_id, struct gy_dr_secrets *secrets,
               const struct gy_keypair *spk_keypair)
{
    if (st == NULL || desc == NULL || secrets == NULL || spk_keypair == NULL)
        return GY_ERR_ARG;

    memset(st, 0, sizeof(*st));
    st->desc = desc;
    st->aead_id = aead_id;
    memcpy(st->rk, secrets->sk_dr, GY_DR_KEY_LEN);

    /*
     * Initial header-key mapping (D-DR-13): Bob's
     * NHKs = shared_nhkb and NHKr = shared_hka; HKs/HKr stay unset until his
     * ratchet steps assign them.  His first receive decrypts Alice's header
     * via NHKr (= shared_hka).
     */
    memcpy(st->nhks, secrets->shared_nhkb, GY_DR_KEY_LEN);
    memcpy(st->nhkr, secrets->shared_hka, GY_DR_KEY_LEN);
    st->have_nhks = 1;
    st->have_nhkr = 1;

    /* Own ratchet pair is the SPK pair; no chains until the first ratchet. */
    st->dhs = *spk_keypair;

    gy_secure_zero(secrets->sk_dr, sizeof(secrets->sk_dr));
    return GY_OK;
}

/*
 * DH ratchet step (D-DR-1).  Advances pn/counters,
 * derives the receiving chain from the new remote key, generates a fresh
 * ratchet pair, and derives the new sending chain.
 */
static int
dh_ratchet(struct gy_dr_state *st, const uint8_t *new_rpk, uint32_t remote_pn)
{
    const struct gy_suite_desc *desc = st->desc;
    uint8_t dh[GY_DH_MAX];
    int rc;

    (void)remote_pn; /* used for skipped-key bounds */

    st->pn = st->ns;
    st->ns = 0;
    st->nr = 0;
    memcpy(st->dhr, new_rpk, desc->curve_pk_len);
    st->have_dhr = 1;

    /*
     * Receiving step (D-DR-14): rotate HKr <- NHKr before the KDF, then
     * the receiving KDF_RK_HE's nhk output becomes the new NHKr.
     */
    memcpy(st->hkr, st->nhkr, GY_DR_KEY_LEN);
    st->have_hkr = 1;
    rc = desc->dh(dh, st->dhs.sk, st->dhr);
    if (rc != GY_OK)
        goto out;
    rc = kdf_rk(desc, st->rk, dh, st->rk, st->ckr, st->nhkr);
    if (rc != GY_OK)
        goto out;
    st->have_ckr = 1;
    st->have_nhkr = 1;

    /* Fresh curve ratchet pair (every step, D-DR-9). */
    rc = gen_ratchet_keypair(desc, &st->dhs);
    if (rc != GY_OK)
        goto out;

    /*
     * Sending step (D-DR-14): rotate HKs <- NHKs, then the sending
     * KDF_RK_HE's nhk output becomes the new NHKs.
     */
    memcpy(st->hks, st->nhks, GY_DR_KEY_LEN);
    st->have_hks = 1;
    rc = desc->dh(dh, st->dhs.sk, st->dhr);
    if (rc != GY_OK)
        goto out;
    rc = kdf_rk(desc, st->rk, dh, st->rk, st->cks, st->nhks);
    if (rc != GY_OK)
        goto out;
    st->have_cks = 1;
    st->have_nhks = 1;

out:
    gy_secure_zero(dh, sizeof(dh));
    return rc;
}

int
gy_dr_encrypt(struct gy_dr_state *st, uint8_t *out, size_t cap, size_t *outlen,
              const uint8_t *pt, size_t ptlen, const uint8_t *ad, size_t adlen)
{
    const struct gy_suite_desc *desc;
    struct gy_dr_header h;
    uint8_t hdrp[GY_DR_HEADER_MAX];
    uint8_t mk[32], ckn[32], key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t adm[GY_DR_AD_MSG_MAX];
    size_t hplen, ehl, hwlen, ppos, admlen, ctlen, taglen, nl;
    uint32_t n;
    int rc;

    if (st == NULL || out == NULL || outlen == NULL || (pt == NULL && ptlen) ||
        (ad == NULL && adlen))
        return GY_ERR_ARG;
    if (!st->have_cks || !st->have_hks)
        return GY_ERR_STATE;
    if (adlen > GY_X3DH_AD_MAX)
        return GY_ERR_ARG;

    desc = st->desc;
    taglen = gy_aead_tag_len(st->aead_id);

    /* Header plaintext (D-DR-5): flags || curve_pk || pn || n. */
    memset(&h, 0, sizeof(h));
    h.flags = desc->curve_type;
    memcpy(h.ratchet_pk, st->dhs.pub.pk, desc->curve_pk_len);
    h.pn = st->pn;
    h.n = st->ns;
    rc = gy_dr_header_encode(desc, &h, hdrp, sizeof(hdrp), &hplen);
    if (rc != GY_OK)
        return rc;

    /*
     * Frame layout (D-DR-16): version || suite_id || hdr_salt(16) ||
     * enc_header_len_be16 || enc_header || payload.  The header ciphertext and
     * the payload are both bounds-checked below through their producers.
     */
    ehl = hplen + taglen;
    hwlen = GY_HE_SALT_LEN + 2 + ehl; /* hdr_salt || len || enc_header */
    ppos = 2 + hwlen;
    if (cap < ppos + ptlen + taglen) {
        rc = GY_ERR_ARG;
        goto out;
    }

    gy_frame_put(out, desc->suite_id); /* version || suite_id (= ad2) */

    /* HENCRYPT the header under HKs; salt and enc_header land in the frame. */
    rc = gy_he_encrypt(desc, st->aead_id, st->hks, hdrp, hplen, out, out + 2,
                       out + 2 + GY_HE_SALT_LEN + 2,
                       cap - (2 + GY_HE_SALT_LEN + 2), &ehl);
    if (rc != GY_OK)
        goto out;
    gy_be16_put(out + 2 + GY_HE_SALT_LEN, (uint16_t)ehl);

    /* Advance the sending chain (D-DR-2). */
    rc = kdf_ck(desc, st->cks, mk, ckn);
    if (rc != GY_OK)
        goto out;
    memcpy(st->cks, ckn, 32);
    n = st->ns;
    st->ns++;

    /* AD_payload = AD_session || hdr_salt || enc_header_len || enc_header. */
    if (adlen > 0)
        memcpy(adm, ad, adlen);
    memcpy(adm + adlen, out + 2, hwlen);
    admlen = adlen + hwlen;

    rc = derive_aead(desc, mk, st->aead_id, n, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;

    ctlen = cap - ppos;
    rc = gy_aead_encrypt(st->aead_id, out + ppos, &ctlen, key, nonce, nl, adm,
                         admlen, pt, ptlen);
    if (rc != GY_OK)
        goto out;
    *outlen = ppos + ctlen;

out:
    gy_secure_zero(hdrp, sizeof(hdrp));
    gy_secure_zero(mk, sizeof(mk));
    gy_secure_zero(ckn, sizeof(ckn));
    gy_secure_zero(key, sizeof(key));
    gy_secure_zero(nonce, sizeof(nonce));
    return rc;
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

/* Zeroize and drop the entry at idx, keeping [0, count) compacted. */
static void
store_remove(struct gy_skip_store *s, size_t idx)
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
        store_remove(s, 0);
    ep = epoch_intern(s, hk);
    e = &s->ent[s->count++];
    e->epoch = ep;
    e->n = n;
    e->age = s->recv_count;
    memcpy(e->mk, mk, 32);
    s->epochs[ep].refs++;
}

/* On a successful decrypt: advance the aging clock and evict aged entries. */
static void
store_post_success(struct gy_skip_store *s)
{
    size_t i;

    s->recv_count++;
    i = 0;
    while (i < s->count) {
        if (s->recv_count - s->ent[i].age >= GY_SKIP_AGE_LIMIT)
            store_remove(s, i);
        else
            i++;
    }
}

/*
 * Advance a receiving chain from *nr to `to` (exclusive), storing each skipped
 * message key under the epoch header key `hk`; leaves ck and *nr at `to`.
 */
static int
skip_forward(const struct gy_suite_desc *desc, struct gy_skip_store *store,
             uint8_t ck[32], uint32_t *nr, uint32_t to, const uint8_t hk[32])
{
    uint8_t mk[32], ckn[32];
    int rc = GY_OK;

    while (*nr < to) {
        rc = kdf_ck(desc, ck, mk, ckn);
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

int
gy_dr_decrypt_assoc(struct gy_dr_state *st, uint8_t *out, size_t cap,
                    size_t *outlen, const uint8_t *msg, size_t msg_len,
                    const uint8_t *ad, size_t adlen, int *header_matched)
{
    const struct gy_suite_desc *desc;
    struct gy_dr_header h;
    struct gy_dr_state stage;
    uint8_t hdrp[GY_DR_HEADER_MAX];
    uint8_t mk[32], ckn[32], key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t adm[GY_DR_AD_MSG_MAX];
    uint8_t old_hkr[GY_DR_KEY_LEN];
    const uint8_t *hdr_salt, *enc_header, *payload;
    size_t ehl, exp_ehl, hwlen, hplen, hdrlen, payload_len;
    size_t admlen, ptcap, taglen, nl, i, slot;
    int new_remote, got, rc;

    if (header_matched != NULL)
        *header_matched = 0;
    if (st == NULL || out == NULL || outlen == NULL || msg == NULL ||
        (ad == NULL && adlen))
        return GY_ERR_ARG;
    if (adlen > GY_X3DH_AD_MAX)
        return GY_ERR_ARG;

    desc = st->desc;
    taglen = gy_aead_tag_len(st->aead_id);
    GY_DR_HE_COUNT_RESET();

    /* Frame prefix (D-GEN-1): version || suite_id, before anything else. */
    rc = gy_frame_check(msg, msg_len, desc->suite_id);
    if (rc != GY_OK)
        return rc;

    /*
     * Parse the D-DR-16 header wire unit: hdr_salt(16) || enc_header_len_be16
     * || enc_header.  enc_header_len is validated against the suite's fixed
     * classical value BEFORE any key derivation (D-DR-16).
     */
    if (msg_len < 2 + GY_HE_SALT_LEN + 2)
        return GY_ERR_ARG;
    hdr_salt = msg + 2;
    ehl = gy_be16_get(msg + 2 + GY_HE_SALT_LEN);
    exp_ehl = 4 + desc->curve_pk_len + 8 + taglen; /* classical: fixed */
    if (ehl != exp_ehl)
        return GY_ERR_ARG;
    hwlen = GY_HE_SALT_LEN + 2 + ehl;
    if (msg_len < 2 + hwlen + taglen)
        return GY_ERR_ARG;
    enc_header = msg + 2 + GY_HE_SALT_LEN + 2;
    payload = msg + 2 + hwlen;
    payload_len = msg_len - 2 - hwlen;

    /* AD_payload = AD_session || hdr_salt || enc_header_len || enc_header. */
    if (adlen > 0)
        memcpy(adm, ad, adlen);
    memcpy(adm + adlen, msg + 2, hwlen);
    admlen = adlen + hwlen;

    /*
     * (1) Skipped-key trials (D-DR-17 step 1): one HDECRYPT per
     * DISTINCT stored epoch header key, using the received hdr_salt.  Only one
     * epoch can decrypt a given header; when a stored (epoch, n) entry matches
     * and its message key verifies the payload, consume it and commit.  The
     * live store is the only mutation, and it happens after the tag verifies.
     */
    for (slot = 0; slot < GY_MAX_SKIP; slot++) {
        if (st->skipped.epochs[slot].refs == 0)
            continue;
        GY_DR_HE_COUNT(skipped);
        rc = gy_he_decrypt(desc, st->aead_id, st->skipped.epochs[slot].hk,
                           hdr_salt, enc_header, ehl, msg, hdrp, sizeof(hdrp),
                           &hplen);
        if (rc != GY_OK)
            continue;
        if (header_matched != NULL)
            *header_matched = 1; /* a full-entropy epoch hk opened the header */
        rc = gy_dr_header_decode(desc, &h, hdrp, hplen, &hdrlen);
        gy_secure_zero(hdrp, sizeof(hdrp));
        if (rc != GY_OK)
            continue;
        for (i = 0; i < st->skipped.count; i++) {
            if (st->skipped.ent[i].epoch != slot || st->skipped.ent[i].n != h.n)
                continue;
            rc = derive_aead(desc, st->skipped.ent[i].mk, st->aead_id, h.n, key,
                             nonce, &nl);
            if (rc != GY_OK) {
                gy_secure_zero(key, sizeof(key));
                gy_secure_zero(nonce, sizeof(nonce));
                return rc;
            }
            ptcap = cap;
            rc = gy_aead_decrypt(st->aead_id, out, &ptcap, key, nonce, nl, adm,
                                 admlen, payload, payload_len);
            gy_secure_zero(key, sizeof(key));
            gy_secure_zero(nonce, sizeof(nonce));
            if (rc == GY_OK) {
                store_remove(&st->skipped, i);
                store_post_success(&st->skipped);
                *outlen = ptcap;
                return GY_OK;
            }
            /* Matching entry but payload tag failed: no-op, fall through. */
            break;
        }
        /* Header decrypted under this epoch; no other epoch will match. */
        break;
    }

    /*
     * (2) HDECRYPT under the current (HKr) then next (NHKr) receiving header
     * key (D-DR-17 steps 2-3); ad2 = the frame's version || suite_id.  A
     * NHKr success is a new epoch and drives the DH ratchet step below via the
     * ratchet_pk comparison.
     */
    got = 0;
    if (st->have_hkr) {
        GY_DR_HE_COUNT(hkr);
        rc = gy_he_decrypt(desc, st->aead_id, st->hkr, hdr_salt, enc_header,
                           ehl, msg, hdrp, sizeof(hdrp), &hplen);
        if (rc == GY_OK)
            got = 1;
    }
    if (!got && st->have_nhkr) {
        GY_DR_HE_COUNT(nhkr);
        rc = gy_he_decrypt(desc, st->aead_id, st->nhkr, hdr_salt, enc_header,
                           ehl, msg, hdrp, sizeof(hdrp), &hplen);
        if (rc == GY_OK)
            got = 1;
    }
    if (!got)
        return GY_ERR_VERIFY;
    if (header_matched != NULL)
        *header_matched = 1; /* HKr or NHKr opened the header */

    rc = gy_dr_header_decode(desc, &h, hdrp, hplen, &hdrlen);
    gy_secure_zero(hdrp, sizeof(hdrp));
    if (rc != GY_OK)
        return rc;

    /* (3) Chain path, entirely on a staged copy (commit-after-verify, 7.7). */
    stage = *st;
    new_remote = !stage.have_dhr || gy_const_memcmp(h.ratchet_pk, stage.dhr,
                                                    desc->curve_pk_len) != 0;

    if (new_remote) {
        /* MAX_SKIP checks BEFORE any key derivation (7.7 step 2). */
        if (stage.have_ckr &&
            (h.pn < stage.nr || h.pn - stage.nr > GY_MAX_SKIP)) {
            rc = GY_ERR_STATE;
            goto out;
        }
        if (h.n > GY_MAX_SKIP) {
            rc = GY_ERR_STATE;
            goto out;
        }
        /*
         * Finish the outgoing receiving chain (its skipped keys stored under
         * the pre-step HKr, D-DR-17 task 4), ratchet, then advance the
         * new chain (skipped keys under the new HKr).
         */
        if (stage.have_ckr) {
            memcpy(old_hkr, stage.hkr, GY_DR_KEY_LEN);
            rc = skip_forward(desc, &stage.skipped, stage.ckr, &stage.nr, h.pn,
                              old_hkr);
            if (rc != GY_OK)
                goto out;
        }
        rc = dh_ratchet(&stage, h.ratchet_pk, h.pn);
        if (rc != GY_OK)
            goto out;
        rc = skip_forward(desc, &stage.skipped, stage.ckr, &stage.nr, h.n,
                          stage.hkr);
        if (rc != GY_OK)
            goto out;
    } else {
        if (!stage.have_ckr) {
            rc = GY_ERR_STATE;
            goto out;
        }
        /* Old message on this chain, not in the store: reject as a no-op. */
        if (h.n < stage.nr) {
            rc = GY_ERR_VERIFY;
            goto out;
        }
        if (h.n - stage.nr > GY_MAX_SKIP) {
            rc = GY_ERR_STATE;
            goto out;
        }
        rc = skip_forward(desc, &stage.skipped, stage.ckr, &stage.nr, h.n,
                          stage.hkr);
        if (rc != GY_OK)
            goto out;
    }

    /* Derive the target message key (index h.n) and advance the chain. */
    rc = kdf_ck(desc, stage.ckr, mk, ckn);
    if (rc != GY_OK)
        goto out;
    memcpy(stage.ckr, ckn, 32);
    stage.nr++;

    rc = derive_aead(desc, mk, stage.aead_id, h.n, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;
    ptcap = cap;
    rc = gy_aead_decrypt(stage.aead_id, out, &ptcap, key, nonce, nl, adm,
                         admlen, payload, payload_len);
    if (rc != GY_OK)
        goto out;

    /* Tag verified: commit the staged state to the live session (D-DR-4). */
    store_post_success(&stage.skipped);
    *st = stage;
    *outlen = ptcap;

out:
    gy_secure_zero(&stage, sizeof(stage));
    gy_secure_zero(old_hkr, sizeof(old_hkr));
    gy_secure_zero(mk, sizeof(mk));
    gy_secure_zero(ckn, sizeof(ckn));
    gy_secure_zero(key, sizeof(key));
    gy_secure_zero(nonce, sizeof(nonce));
    return rc;
}

int
gy_dr_decrypt(struct gy_dr_state *st, uint8_t *out, size_t cap, size_t *outlen,
              const uint8_t *msg, size_t msg_len, const uint8_t *ad,
              size_t adlen)
{
    return gy_dr_decrypt_assoc(st, out, cap, outlen, msg, msg_len, ad, adlen,
                               NULL);
}

void
gy_dr_free(struct gy_dr_state *st)
{
    if (st != NULL)
        gy_secure_zero(st, sizeof(*st));
}

#ifdef GY_TEST_HOOKS
int
gy_dr_kdf_rk(const struct gy_suite_desc *desc, const uint8_t *rk,
             const uint8_t *dh, uint8_t out_rk[32], uint8_t out_ck[32],
             uint8_t out_nhk[32])
{
    return kdf_rk(desc, rk, dh, out_rk, out_ck, out_nhk);
}

int
gy_dr_kdf_ck(const struct gy_suite_desc *desc, const uint8_t ck[32],
             uint8_t mk[32], uint8_t ck_next[32])
{
    return kdf_ck(desc, ck, mk, ck_next);
}

int
gy_dr_derive_aead(const struct gy_suite_desc *desc, const uint8_t mk[32],
                  uint8_t aead_id, uint32_t n, uint8_t *key, uint8_t *nonce,
                  size_t *nonce_len)
{
    return derive_aead(desc, mk, aead_id, n, key, nonce, nonce_len);
}
#endif
