/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "hybrid_double_ratchet.h"

#ifdef GY_TEST_HOOKS
int (*gy_hybrid_dr_test_kem_keypair)(const struct gy_suite_desc *desc,
                                     uint8_t *ek, uint8_t *dk);
int (*gy_hybrid_dr_test_kem_encaps)(const struct gy_suite_desc *desc,
                                    uint8_t *ct, uint8_t *ss,
                                    const uint8_t *ek);
struct gy_hybrid_dr_counters gy_hybrid_dr_ctr;
#define HDR_COUNT(f) (gy_dr_he_ctr.f++)
#define HDR_COUNT_RESET() (memset(&gy_dr_he_ctr, 0, sizeof(gy_dr_he_ctr)))
#define KEM_COUNT(f) (gy_hybrid_dr_ctr.f++)
#define KEM_COUNT_RESET()                                                      \
    (memset(&gy_hybrid_dr_ctr, 0, sizeof(gy_hybrid_dr_ctr)))
#else
#define HDR_COUNT(f) ((void)0)
#define HDR_COUNT_RESET() ((void)0)
#define KEM_COUNT(f) ((void)0)
#define KEM_COUNT_RESET() ((void)0)
#endif

/* Generate a curve ratchet key pair, honoring the classical test seam. */
static int
gen_curve_keypair(const struct gy_suite_desc *desc, struct gy_keypair *out)
{
#ifdef GY_TEST_HOOKS
    if (gy_dr_test_keypair != NULL)
        return gy_dr_test_keypair(desc, out);
#endif
    return gy_keypair_generate(desc, out);
}

/* Generate an ML-KEM ratchet key pair, honoring the D-PQ-3 test seam. */
static int
gen_kem_keypair(const struct gy_suite_desc *desc, uint8_t *ek, uint8_t *dk)
{
    KEM_COUNT(kem_keypair);
#ifdef GY_TEST_HOOKS
    if (gy_hybrid_dr_test_kem_keypair != NULL)
        return gy_hybrid_dr_test_kem_keypair(desc, ek, dk);
#endif
    return desc->kem_keypair(ek, dk);
}

/* Encapsulate to ek, honoring the D-PQ-3 test seam. */
static int
kem_encaps(const struct gy_suite_desc *desc, uint8_t *ct, uint8_t *ss,
           const uint8_t *ek)
{
    KEM_COUNT(kem_encaps);
#ifdef GY_TEST_HOOKS
    if (gy_hybrid_dr_test_kem_encaps != NULL)
        return gy_hybrid_dr_test_kem_encaps(desc, ct, ss, ek);
#endif
    return desc->kem_encap(ct, ss, ek);
}

/* HDH = HASH(kem_ss || dh) (HYBRID_SPEC section 3.1 combiner, PQ-first). */
static int
hybrid_combine(const struct gy_suite_desc *desc, const uint8_t *kem_ss,
               const uint8_t *dh, uint8_t *hdh)
{
    uint8_t buf[GY_KEM_SS_MAX + GY_DH_MAX];
    int rc;

    memcpy(buf, kem_ss, desc->kem_ss_len);
    memcpy(buf + desc->kem_ss_len, dh, desc->dh_len);
    rc = desc->hash(hdh, buf, desc->kem_ss_len + desc->dh_len);
    gy_secure_zero(buf, sizeof(buf));
    return rc;
}

/*
 * HDH = HASH(confirm_ss || kem_ss || dh) (section 3.1 confirmation form, used
 * on the responder's first sending chain and the initiator's matching receiving
 * chain; PQ inputs first, confirmation secret outermost).
 */
static int
hybrid_combine3(const struct gy_suite_desc *desc, const uint8_t *confirm_ss,
                const uint8_t *kem_ss, const uint8_t *dh, uint8_t *hdh)
{
    uint8_t buf[2 * GY_KEM_SS_MAX + GY_DH_MAX];
    size_t p = 0;
    int rc;

    memcpy(buf + p, confirm_ss, desc->kem_ss_len);
    p += desc->kem_ss_len;
    memcpy(buf + p, kem_ss, desc->kem_ss_len);
    p += desc->kem_ss_len;
    memcpy(buf + p, dh, desc->dh_len);
    p += desc->dh_len;
    rc = desc->hash(hdh, buf, p);
    gy_secure_zero(buf, sizeof(buf));
    return rc;
}

/* Root KDF over hdh, counted for the pre-derivation-rejection tests. */
static int
root_kdf(const struct gy_suite_desc *desc, uint8_t *rk, const uint8_t *hdh,
         uint8_t out_rk[32], uint8_t out_ck[32], uint8_t out_nhk[32])
{
    KEM_COUNT(kdf_rk);
    return gy_drc_kdf_rk(desc, rk, hdh, desc->hash_len, out_rk, out_ck,
                         out_nhk);
}

int
gy_hybrid_dr_init_alice(struct gy_hybrid_dr_state *st,
                        const struct gy_suite_desc *desc, uint8_t aead_id,
                        struct gy_dr_secrets *secrets,
                        const struct gy_hybrid_public_key *remote_spk,
                        uint32_t mlkem_interval, const uint8_t *id_mlkem_dk)
{
    struct gy_dr_state *b;
    uint8_t dh[GY_DH_MAX], kem_ss[GY_KEM_SS_MAX], hdh[GY_HASH_MAX];
    int rc;

    if (st == NULL || desc == NULL || secrets == NULL || remote_spk == NULL ||
        id_mlkem_dk == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid || mlkem_interval < 1)
        return GY_ERR_ARG;

    memset(st, 0, sizeof(*st));
    b = &st->base;
    b->desc = desc;
    b->aead_id = aead_id;
    memcpy(b->rk, secrets->sk_dr, GY_DR_KEY_LEN);
    memcpy(b->dhr, remote_spk->curve.pk, desc->curve_pk_len);
    b->have_dhr = 1;
    memcpy(st->remote_ek, remote_spk->mlkem_ek, desc->kem_pk_len);
    st->have_remote_ek = 1;
    st->mlkem_interval = mlkem_interval;

    /* Initiator (section 8): hold the identity dk to open Bob's confirmation. */
    st->role = GY_HYBRID_ROLE_INITIATOR;
    st->pq_state = GY_HYBRID_PQ_CLASSICAL_ONLY;
    memcpy(st->id_mlkem_dk, id_mlkem_dk, desc->kem_sk_len);
    st->have_id_dk = 1;

    /*
     * Initial header-key mapping (D-DR-13): HKs = shared_hka, NHKr =
     * shared_nhkb.  The initial sending ratchet fills NHKs; HKs is not rotated.
     */
    memcpy(b->hks, secrets->shared_hka, GY_DR_KEY_LEN);
    memcpy(b->nhkr, secrets->shared_nhkb, GY_DR_KEY_LEN);
    b->have_hks = 1;
    b->have_nhkr = 1;

    /* Own hybrid ratchet keypair: fresh curve + fresh ML-KEM (section 7.2). */
    rc = gen_curve_keypair(desc, &b->dhs);
    if (rc != GY_OK)
        goto err;
    rc = gen_kem_keypair(desc, st->mlkem_ek, st->mlkem_dk);
    if (rc != GY_OK)
        goto err;
    /* Fresh ML-KEM key: the first sending chain advertises the ek (section 7.3). */
    st->send_ek_pending = 1;

    /* Initial sending ratchet (section 7.3, sending half). */
    rc = kem_encaps(desc, st->kem_ct, kem_ss, st->remote_ek);
    if (rc != GY_OK)
        goto err;
    st->have_kem_ct = 1;
    rc = desc->dh(dh, b->dhs.sk, b->dhr);
    if (rc != GY_OK)
        goto err;
    rc = hybrid_combine(desc, kem_ss, dh, hdh);
    if (rc != GY_OK)
        goto err;
    rc = root_kdf(desc, b->rk, hdh, b->rk, b->cks, b->nhks);
    if (rc != GY_OK)
        goto err;
    b->have_cks = 1;
    b->have_nhks = 1;

    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(kem_ss, sizeof(kem_ss));
    gy_secure_zero(hdh, sizeof(hdh));
    gy_secure_zero(secrets->sk_dr, sizeof(secrets->sk_dr));
    return GY_OK;

err:
    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(kem_ss, sizeof(kem_ss));
    gy_secure_zero(hdh, sizeof(hdh));
    gy_secure_zero(st, sizeof(*st));
    return rc;
}

int
gy_hybrid_dr_init_bob(struct gy_hybrid_dr_state *st,
                      const struct gy_suite_desc *desc, uint8_t aead_id,
                      struct gy_dr_secrets *secrets,
                      const struct gy_hybrid_keypair *spk_keypair,
                      uint32_t mlkem_interval,
                      const uint8_t *initiator_id_mlkem_ek)
{
    struct gy_dr_state *b;

    if (st == NULL || desc == NULL || secrets == NULL || spk_keypair == NULL ||
        initiator_id_mlkem_ek == NULL)
        return GY_ERR_ARG;
    if (!desc->is_hybrid || mlkem_interval < 1)
        return GY_ERR_ARG;

    memset(st, 0, sizeof(*st));
    b = &st->base;
    b->desc = desc;
    b->aead_id = aead_id;
    memcpy(b->rk, secrets->sk_dr, GY_DR_KEY_LEN);

    /*
     * Initial header-key mapping (D-DR-13): NHKs = shared_nhkb, NHKr =
     * shared_hka.  His first receive decrypts Alice's header via NHKr.
     */
    memcpy(b->nhks, secrets->shared_nhkb, GY_DR_KEY_LEN);
    memcpy(b->nhkr, secrets->shared_hka, GY_DR_KEY_LEN);
    b->have_nhks = 1;
    b->have_nhkr = 1;

    /* Own ratchet pair is the SPK pair (curve + ML-KEM); no chains yet. */
    b->dhs.pub = spk_keypair->pub.curve;
    memcpy(b->dhs.sk, spk_keypair->curve_sk, desc->curve_sk_len);
    memcpy(st->mlkem_ek, spk_keypair->pub.mlkem_ek, desc->kem_pk_len);
    memcpy(st->mlkem_dk, spk_keypair->mlkem_dk, desc->kem_sk_len);

    st->mlkem_interval = mlkem_interval;
    /* Force a fresh ML-KEM keypair on his first ratchet (section 7.2). */
    st->mlkem_counter = mlkem_interval;
    /* remote_ek invalid until Alice's first header arrives. */

    /* Responder (section 8): confirm to Alice's identity ek in the 1st chain. */
    st->role = GY_HYBRID_ROLE_RESPONDER;
    st->pq_state = GY_HYBRID_PQ_CLASSICAL_ONLY;
    memcpy(st->id_mlkem_ek, initiator_id_mlkem_ek, desc->kem_pk_len);
    st->confirm_pending = 1;

    gy_secure_zero(secrets->sk_dr, sizeof(secrets->sk_dr));
    return GY_OK;
}

/*
 * Hybrid DH ratchet step (section 7.3), run on a staged state.  Advances
 * counters, derives the receiving chain (ML-KEM decaps with the CURRENT own dk,
 * before any regeneration), refreshes the ML-KEM keypair on the interval and the
 * curve keypair every step, then derives the sending chain (fresh encapsulation
 * to the cached remote ek).  hdh = HASH(kem_ss || dh) is mixed into each root
 * KDF.  A header lacking mlkem_ek when no valid remote key is cached is rejected
 * (section 7.3) before any derivation.
 */
static int
hybrid_dh_ratchet(struct gy_hybrid_dr_state *st,
                  const struct gy_dr_hybrid_header *h)
{
    struct gy_dr_state *b = &st->base;
    const struct gy_suite_desc *desc = b->desc;
    uint8_t dh[GY_DH_MAX], kem_ss[GY_KEM_SS_MAX], hdh[GY_HASH_MAX];
    uint8_t confirm_ss[GY_KEM_SS_MAX];
    int rc, regen, recv_confirm, send_confirm, was_confirm_sent;
    int has_confirm = (h->flags & GY_DR_FLAG_CONFIRM_CT_PRESENT) != 0;

    was_confirm_sent = (st->pq_state == GY_HYBRID_PQ_CONFIRM_SENT);

    /*
     * KEM confirmation flag validity (section 8.3): valid ONLY on the
     * responder's first sending chain, i.e. the initiator's first (confirm)
     * epoch.  The responder never receives it; the initiator requires it on the
     * confirm epoch and rejects it on any later epoch.
     */
    recv_confirm = 0;
    if (st->role == GY_HYBRID_ROLE_RESPONDER) {
        if (has_confirm)
            return GY_ERR_STATE; /* responder never receives confirmation */
    } else {                     /* initiator */
        if (st->pq_state == GY_HYBRID_PQ_CLASSICAL_ONLY) {
            if (!has_confirm)
                return GY_ERR_STATE; /* confirm epoch must carry confirmation */
            recv_confirm = 1;
        } else if (has_confirm) {
            return GY_ERR_STATE; /* confirmation only on the first Bob chain */
        }
    }

    b->pn = b->ns;
    b->ns = 0;
    b->nr = 0;
    memcpy(b->dhr, h->ratchet_pk, desc->curve_pk_len);
    b->have_dhr = 1;

    /* Step 2: cache the remote ek (bit 8) or require a valid cached one. */
    if (h->flags & GY_DR_FLAG_MLKEM_EK_PRESENT) {
        memcpy(st->remote_ek, h->mlkem_ek, desc->kem_pk_len);
        st->have_remote_ek = 1;
    } else if (!st->have_remote_ek) {
        return GY_ERR_STATE; /* missing-ek: no derivation performed */
    }

    /* Step 3: receiving chain.  Decaps uses the current own dk (pre-regen). */
    memcpy(b->hkr, b->nhkr, GY_DR_KEY_LEN);
    b->have_hkr = 1;
    KEM_COUNT(kem_decaps);
    rc = desc->kem_decap(kem_ss, h->kem_ct, st->mlkem_dk);
    if (rc != GY_OK)
        goto out;
    rc = desc->dh(dh, b->dhs.sk, b->dhr);
    if (rc != GY_OK)
        goto out;
    if (recv_confirm) {
        /* Open Bob's confirmation with the identity dk (section 8.3). */
        rc = desc->kem_decap(confirm_ss, h->confirm_ct, st->id_mlkem_dk);
        if (rc != GY_OK)
            goto out;
        rc = hybrid_combine3(desc, confirm_ss, kem_ss, dh, hdh);
    } else {
        rc = hybrid_combine(desc, kem_ss, dh, hdh);
    }
    if (rc != GY_OK)
        goto out;
    rc = root_kdf(desc, b->rk, hdh, b->rk, b->ckr, b->nhkr);
    if (rc != GY_OK)
        goto out;
    b->have_ckr = 1;
    b->have_nhkr = 1;

    /* Step 4: ML-KEM keypair refresh on interval; curve keypair every step. */
    st->mlkem_counter += 1;
    regen = 0;
    if (st->mlkem_counter >= st->mlkem_interval) {
        rc = gen_kem_keypair(desc, st->mlkem_ek, st->mlkem_dk);
        if (rc != GY_OK)
            goto out;
        st->mlkem_counter = 0;
        regen = 1;
    }
    rc = gen_curve_keypair(desc, &b->dhs);
    if (rc != GY_OK)
        goto out;

    /* Step 5: sending chain.  Fresh encapsulation to the cached remote ek. */
    memcpy(b->hks, b->nhks, GY_DR_KEY_LEN);
    b->have_hks = 1;
    rc = kem_encaps(desc, st->kem_ct, kem_ss, st->remote_ek);
    if (rc != GY_OK)
        goto out;
    st->have_kem_ct = 1; /* step 6: kem_ct rides every header of this chain */

    /*
     * KEM confirmation (section 8.2): the responder's FIRST sending chain
     * encapsulates to Alice's identity ek and fuses confirm_ss into this chain's
     * root (confirmation form).  confirm_ct rides every header of the chain.
     */
    send_confirm = st->confirm_pending;
    if (send_confirm) {
        rc = kem_encaps(desc, st->confirm_ct, confirm_ss, st->id_mlkem_ek);
        if (rc != GY_OK)
            goto out;
        st->have_confirm_ct = 1;
    }
    rc = desc->dh(dh, b->dhs.sk, b->dhr);
    if (rc != GY_OK)
        goto out;
    if (send_confirm)
        rc = hybrid_combine3(desc, confirm_ss, kem_ss, dh, hdh);
    else
        rc = hybrid_combine(desc, kem_ss, dh, hdh);
    if (rc != GY_OK)
        goto out;
    rc = root_kdf(desc, b->rk, hdh, b->rk, b->cks, b->nhks);
    if (rc != GY_OK)
        goto out;
    b->have_cks = 1;
    b->have_nhks = 1;
    /* Advertise the ek in this sending chain iff its keypair was refreshed. */
    st->send_ek_pending = regen;

    /* Section 8.4 state transitions (committed only if the payload verifies). */
    if (send_confirm) {
        st->send_confirm_pending = 1;
        st->confirm_pending = 0;
        st->pq_state = GY_HYBRID_PQ_CONFIRM_SENT;
    } else {
        st->send_confirm_pending = 0;
    }
    if (recv_confirm) {
        /* Initiator has bound its PQ identity; the dk is no longer needed. */
        st->pq_state = GY_HYBRID_PQ_CONFIRMED;
        gy_secure_zero(st->id_mlkem_dk, sizeof(st->id_mlkem_dk));
        st->have_id_dk = 0;
    }
    if (st->role == GY_HYBRID_ROLE_RESPONDER && was_confirm_sent) {
        /* A verified message on a chain descended from the confirmation. */
        st->pq_state = GY_HYBRID_PQ_CONFIRMED;
    }

out:
    gy_secure_zero(dh, sizeof(dh));
    gy_secure_zero(kem_ss, sizeof(kem_ss));
    gy_secure_zero(hdh, sizeof(hdh));
    gy_secure_zero(confirm_ss, sizeof(confirm_ss));
    return rc;
}

int
gy_hybrid_dr_encrypt(struct gy_hybrid_dr_state *st, uint8_t *out, size_t cap,
                     size_t *outlen, const uint8_t *pt, size_t ptlen,
                     const uint8_t *ad, size_t adlen)
{
    struct gy_dr_state *b;
    const struct gy_suite_desc *desc;
    struct gy_dr_hybrid_header h;
    uint8_t hdrp[GY_DR_HYBRID_HEADER_MAX];
    uint8_t mk[32], ckn[32], key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t adm[GY_DR_HYBRID_AD_MSG_MAX];
    size_t hplen, ehl, hwlen, ppos, admlen, ctlen, taglen, nl;
    uint32_t n;
    int rc;

    if (st == NULL || out == NULL || outlen == NULL || (pt == NULL && ptlen) ||
        (ad == NULL && adlen))
        return GY_ERR_ARG;
    b = &st->base;
    if (!b->have_cks || !b->have_hks || !st->have_kem_ct)
        return GY_ERR_STATE;
    if (adlen > GY_HYBRID_AD_MAX)
        return GY_ERR_ARG;

    desc = b->desc;
    taglen = gy_aead_tag_len(b->aead_id);

    /* Header plaintext (section 7.6): flags || curve_pk || kem_ct || pn || n. */
    memset(&h, 0, sizeof(h));
    h.flags = desc->curve_type;
    if (st->send_ek_pending) {
        h.flags |= GY_DR_FLAG_MLKEM_EK_PRESENT;
        memcpy(h.mlkem_ek, st->mlkem_ek, desc->kem_pk_len);
    }
    if (st->send_confirm_pending) {
        /* Every header of the responder's first chain carries confirm_ct. */
        h.flags |= GY_DR_FLAG_CONFIRM_CT_PRESENT;
        memcpy(h.confirm_ct, st->confirm_ct, desc->kem_ct_len);
    }
    memcpy(h.ratchet_pk, b->dhs.pub.pk, desc->curve_pk_len);
    memcpy(h.kem_ct, st->kem_ct, desc->kem_ct_len);
    h.pn = b->pn;
    h.n = b->ns;
    rc = gy_dr_hybrid_header_encode(desc, &h, hdrp, sizeof(hdrp), &hplen);
    if (rc != GY_OK)
        goto out;

    ehl = hplen + taglen;
    hwlen = GY_HE_SALT_LEN + 2 + ehl;
    ppos = 2 + hwlen;
    if (cap < ppos + ptlen + taglen) {
        rc = GY_ERR_ARG;
        goto out;
    }

    gy_frame_put(out, desc->suite_id); /* version || suite_id (= ad2) */

    rc = gy_he_encrypt(desc, b->aead_id, b->hks, hdrp, hplen, out, out + 2,
                       out + 2 + GY_HE_SALT_LEN + 2,
                       cap - (2 + GY_HE_SALT_LEN + 2), &ehl);
    if (rc != GY_OK)
        goto out;
    gy_be16_put(out + 2 + GY_HE_SALT_LEN, (uint16_t)ehl);

    /* Advance the sending chain (section 7.4). */
    rc = gy_drc_kdf_ck(desc, b->cks, mk, ckn);
    if (rc != GY_OK)
        goto out;
    memcpy(b->cks, ckn, 32);
    n = b->ns;
    b->ns++;

    if (adlen > 0)
        memcpy(adm, ad, adlen);
    memcpy(adm + adlen, out + 2, hwlen);
    admlen = adlen + hwlen;

    rc = gy_drc_derive_aead(desc, mk, b->aead_id, n, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;

    ctlen = cap - ppos;
    rc = gy_aead_encrypt(b->aead_id, out + ppos, &ctlen, key, nonce, nl, adm,
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

/* enc_header_len is valid iff it is one of the four section 7.6 combinations. */
static int
enc_header_len_ok(const struct gy_suite_desc *desc, size_t ehl, size_t taglen)
{
    return ehl == gy_dr_hybrid_header_len(desc, 0, 0) + taglen ||
           ehl == gy_dr_hybrid_header_len(desc, 1, 0) + taglen ||
           ehl == gy_dr_hybrid_header_len(desc, 0, 1) + taglen ||
           ehl == gy_dr_hybrid_header_len(desc, 1, 1) + taglen;
}

int
gy_hybrid_dr_decrypt_assoc(struct gy_hybrid_dr_state *st, uint8_t *out,
                           size_t cap, size_t *outlen, const uint8_t *msg,
                           size_t msg_len, const uint8_t *ad, size_t adlen,
                           int *header_matched)
{
    struct gy_dr_state *b;
    const struct gy_suite_desc *desc;
    struct gy_dr_hybrid_header h;
    struct gy_hybrid_dr_state stage;
    uint8_t hdrp[GY_DR_HYBRID_HEADER_MAX];
    uint8_t mk[32], ckn[32], key[32], nonce[GY_AEAD_MAX_NONCE];
    uint8_t adm[GY_DR_HYBRID_AD_MSG_MAX];
    uint8_t old_hkr[GY_DR_KEY_LEN];
    const uint8_t *hdr_salt, *enc_header, *payload;
    size_t ehl, hwlen, hplen, hdrlen, payload_len;
    size_t admlen, ptcap, taglen, nl, i, slot;
    int new_remote, got, rc;

    if (header_matched != NULL)
        *header_matched = 0;
    if (st == NULL || out == NULL || outlen == NULL || msg == NULL ||
        (ad == NULL && adlen))
        return GY_ERR_ARG;
    if (adlen > GY_HYBRID_AD_MAX)
        return GY_ERR_ARG;

    b = &st->base;
    desc = b->desc;
    taglen = gy_aead_tag_len(b->aead_id);
    HDR_COUNT_RESET();
    KEM_COUNT_RESET();

    /* Frame prefix (D-GEN-1): version || suite_id, before anything else. */
    rc = gy_frame_check(msg, msg_len, desc->suite_id);
    if (rc != GY_OK)
        return rc;

    /*
     * Parse the D-DR-16 header wire unit: hdr_salt(16) || enc_header_len_be16
     * || enc_header.  enc_header_len is validated against the suite's four
     * hybrid combinations BEFORE any key derivation (D-DR-16 / section 7.7).
     */
    if (msg_len < 2 + GY_HE_SALT_LEN + 2)
        return GY_ERR_ARG;
    hdr_salt = msg + 2;
    ehl = gy_be16_get(msg + 2 + GY_HE_SALT_LEN);
    if (!enc_header_len_ok(desc, ehl, taglen))
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
     * (1) Skipped-key trials (D-DR-17 step 1): one HDECRYPT per DISTINCT stored
     * epoch header key, using the received hdr_salt.  A matching (epoch, n)
     * entry whose message key verifies the payload is consumed and committed.
     */
    for (slot = 0; slot < GY_MAX_SKIP; slot++) {
        if (b->skipped.epochs[slot].refs == 0)
            continue;
        HDR_COUNT(skipped);
        rc = gy_he_decrypt(desc, b->aead_id, b->skipped.epochs[slot].hk,
                           hdr_salt, enc_header, ehl, msg, hdrp, sizeof(hdrp),
                           &hplen);
        if (rc != GY_OK)
            continue;
        if (header_matched != NULL)
            *header_matched = 1;
        rc = gy_dr_hybrid_header_decode(desc, &h, hdrp, hplen, &hdrlen);
        gy_secure_zero(hdrp, sizeof(hdrp));
        if (rc != GY_OK || hdrlen != hplen)
            continue;
        /*
         * A stored skipped key is from an already-validated epoch, so its bit 9
         * needs no re-check here (the epoch's confirmation, if any, was handled
         * at its ratchet); the (epoch, n) match and the AD-bound payload tag are
         * the arbiters.
         */
        for (i = 0; i < b->skipped.count; i++) {
            if (b->skipped.ent[i].epoch != slot || b->skipped.ent[i].n != h.n)
                continue;
            rc = gy_drc_derive_aead(desc, b->skipped.ent[i].mk, b->aead_id, h.n,
                                    key, nonce, &nl);
            if (rc != GY_OK) {
                gy_secure_zero(key, sizeof(key));
                gy_secure_zero(nonce, sizeof(nonce));
                return rc;
            }
            ptcap = cap;
            rc = gy_aead_decrypt(b->aead_id, out, &ptcap, key, nonce, nl, adm,
                                 admlen, payload, payload_len);
            gy_secure_zero(key, sizeof(key));
            gy_secure_zero(nonce, sizeof(nonce));
            if (rc == GY_OK) {
                gy_drc_store_remove(&b->skipped, i);
                gy_drc_store_post_success(&b->skipped);
                *outlen = ptcap;
                return GY_OK;
            }
            break; /* matching entry, payload failed: no-op, fall through */
        }
        break; /* header decrypted under this epoch; no other epoch matches */
    }

    /*
     * (2) HDECRYPT under HKr then NHKr (D-DR-17 steps 2-3).  A NHKr success is
     * a new epoch and drives the hybrid DH ratchet step below.
     */
    got = 0;
    if (b->have_hkr) {
        HDR_COUNT(hkr);
        rc = gy_he_decrypt(desc, b->aead_id, b->hkr, hdr_salt, enc_header, ehl,
                           msg, hdrp, sizeof(hdrp), &hplen);
        if (rc == GY_OK)
            got = 1;
    }
    if (!got && b->have_nhkr) {
        HDR_COUNT(nhkr);
        rc = gy_he_decrypt(desc, b->aead_id, b->nhkr, hdr_salt, enc_header, ehl,
                           msg, hdrp, sizeof(hdrp), &hplen);
        if (rc == GY_OK)
            got = 1;
    }
    if (!got)
        return GY_ERR_VERIFY;
    if (header_matched != NULL)
        *header_matched = 1;

    rc = gy_dr_hybrid_header_decode(desc, &h, hdrp, hplen, &hdrlen);
    gy_secure_zero(hdrp, sizeof(hdrp));
    if (rc != GY_OK)
        return rc;
    if (hdrlen != hplen)
        return GY_ERR_ARG;
    /*
     * Confirmation flag (bit 9): the responder must never receive it (the
     * initiator does not send confirmation).  For the initiator it is valid only
     * on the confirm epoch; the ratchet step enforces that (a same-epoch HKr
     * message of the confirm chain legitimately carries it and is not a ratchet).
     */
    if ((h.flags & GY_DR_FLAG_CONFIRM_CT_PRESENT) &&
        st->role == GY_HYBRID_ROLE_RESPONDER)
        return GY_ERR_STATE;

    /* (3) Chain path, entirely on a staged copy (commit-after-verify, 7.7). */
    stage = *st;
    new_remote =
        !stage.base.have_dhr ||
        gy_const_memcmp(h.ratchet_pk, stage.base.dhr, desc->curve_pk_len) != 0;

    if (new_remote) {
        /* MAX_SKIP checks BEFORE any key derivation (7.7 step 2). */
        if (stage.base.have_ckr &&
            (h.pn < stage.base.nr || h.pn - stage.base.nr > GY_MAX_SKIP)) {
            rc = GY_ERR_STATE;
            goto out;
        }
        if (h.n > GY_MAX_SKIP) {
            rc = GY_ERR_STATE;
            goto out;
        }
        if (stage.base.have_ckr) {
            memcpy(old_hkr, stage.base.hkr, GY_DR_KEY_LEN);
            rc = gy_drc_skip_forward(desc, &stage.base.skipped, stage.base.ckr,
                                     &stage.base.nr, h.pn, old_hkr);
            if (rc != GY_OK)
                goto out;
        }
        rc = hybrid_dh_ratchet(&stage, &h);
        if (rc != GY_OK)
            goto out;
        rc = gy_drc_skip_forward(desc, &stage.base.skipped, stage.base.ckr,
                                 &stage.base.nr, h.n, stage.base.hkr);
        if (rc != GY_OK)
            goto out;
    } else {
        if (!stage.base.have_ckr) {
            rc = GY_ERR_STATE;
            goto out;
        }
        if (h.n < stage.base.nr) {
            rc = GY_ERR_VERIFY;
            goto out;
        }
        if (h.n - stage.base.nr > GY_MAX_SKIP) {
            rc = GY_ERR_STATE;
            goto out;
        }
        rc = gy_drc_skip_forward(desc, &stage.base.skipped, stage.base.ckr,
                                 &stage.base.nr, h.n, stage.base.hkr);
        if (rc != GY_OK)
            goto out;
    }

    /* Derive the target message key (index h.n) and advance the chain. */
    rc = gy_drc_kdf_ck(desc, stage.base.ckr, mk, ckn);
    if (rc != GY_OK)
        goto out;
    memcpy(stage.base.ckr, ckn, 32);
    stage.base.nr++;

    rc = gy_drc_derive_aead(desc, mk, stage.base.aead_id, h.n, key, nonce, &nl);
    if (rc != GY_OK)
        goto out;
    ptcap = cap;
    rc = gy_aead_decrypt(stage.base.aead_id, out, &ptcap, key, nonce, nl, adm,
                         admlen, payload, payload_len);
    if (rc != GY_OK)
        goto out;

    /* Tag verified: commit the staged state to the live session (D-DR-4). */
    gy_drc_store_post_success(&stage.base.skipped);
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
gy_hybrid_dr_decrypt(struct gy_hybrid_dr_state *st, uint8_t *out, size_t cap,
                     size_t *outlen, const uint8_t *msg, size_t msg_len,
                     const uint8_t *ad, size_t adlen)
{
    return gy_hybrid_dr_decrypt_assoc(st, out, cap, outlen, msg, msg_len, ad,
                                      adlen, NULL);
}

uint8_t
gy_hybrid_dr_pq_state(const struct gy_hybrid_dr_state *st)
{
    return st != NULL ? st->pq_state : GY_HYBRID_PQ_CLASSICAL_ONLY;
}

void
gy_hybrid_dr_free(struct gy_hybrid_dr_state *st)
{
    if (st != NULL)
        gy_secure_zero(st, sizeof(*st));
}
