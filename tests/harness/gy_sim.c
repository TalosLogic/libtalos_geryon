/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "gy_sim.h"

static const uint64_t GY_SIM_TS = 0x0000000155667788ull;

/* Fixed classical prefix length for this suite. */
static size_t
prefix_len(const struct gy_suite_desc *desc)
{
    return 2 + 2 * (4 + 1 + desc->curve_pk_len) + 16;
}

int
gy_sim_setup(struct gy_sim *sim, const struct gy_suite_desc *desc,
             uint8_t aead_id, int with_opk)
{
    int rc;

    memset(sim, 0, sizeof(*sim));
    sim->desc = desc;
    sim->aead_id = aead_id;

    rc = gy_keypair_generate(desc, &sim->bob_ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_spk_create(desc, &sim->bob_spk, sim->bob_ik.sk, GY_SIM_TS);
    if (rc != GY_OK)
        return rc;

    memset(&sim->bundle, 0, sizeof(sim->bundle));
    sim->bundle.ik = sim->bob_ik.pub;
    sim->bundle.spk = sim->bob_spk.kp.pub;
    sim->bundle.spk_timestamp = GY_SIM_TS;
    memcpy(sim->bundle.spk_sig, sim->bob_spk.sig, GY_SIG_MAX);

    if (with_opk) {
        rc = gy_opk_batch(desc, sim->opk_stock, 1, NULL, 0);
        if (rc != GY_OK)
            return rc;
        sim->opk_count = 1;
        sim->bundle.opk = sim->opk_stock[0].pub;
    }
    return GY_OK;
}

int
gy_sim_start(struct gy_sim_initiator *init, const struct gy_sim *sim,
             uint8_t *out, size_t cap, size_t *outlen, const uint8_t *pt,
             size_t ptlen)
{
    struct gy_dr_secrets secrets;
    uint8_t prefix[GY_X3DH_PREFIX_MAX];
    uint8_t dr[GY_DR_HEADER_MAX + 512 + GY_AEAD_MAX_TAG];
    size_t prefl, drlen;
    int rc;

    memset(init, 0, sizeof(*init));
    init->desc = sim->desc;
    init->aead_id = sim->aead_id;

    rc = gy_keypair_generate(sim->desc, &init->ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_keypair_generate(sim->desc, &init->ek);
    if (rc != GY_OK)
        return rc;

    rc = gy_x3dh_initiate(sim->desc, &secrets, init->ad, &init->adl, prefix,
                          &prefl, &init->ik, &sim->bundle, &init->ek);
    if (rc != GY_OK)
        return rc;

    rc = gy_dr_init_alice(&init->dr, sim->desc, sim->aead_id, &secrets,
                          sim->bundle.spk.pk);
    if (rc != GY_OK) {
        gy_secure_zero(&secrets, sizeof(secrets));
        return rc;
    }
    init->up = 1;

    rc = gy_dr_encrypt(&init->dr, dr, sizeof(dr), &drlen, pt, ptlen, init->ad,
                       init->adl);
    gy_secure_zero(&secrets, sizeof(secrets));
    if (rc != GY_OK)
        return rc;

    if (cap < prefl + drlen)
        return GY_ERR_ARG;
    memcpy(out, prefix, prefl);
    gy_be32_put(out + prefl - 4, (uint32_t)drlen); /* fill ciphertext_len */
    memcpy(out + prefl, dr, drlen);
    *outlen = prefl + drlen;
    return GY_OK;
}

/* Delete the OPK matching pkid from the stock (delete-on-success, D-X3DH-10). */
static void
opk_delete(struct gy_sim *sim, uint32_t pkid)
{
    size_t i;

    for (i = 0; i < sim->opk_count; i++) {
        if (sim->opk_stock[i].pub.pkid != pkid)
            continue;
        gy_secure_zero(&sim->opk_stock[i], sizeof(sim->opk_stock[i]));
        if (i + 1 < sim->opk_count)
            memmove(&sim->opk_stock[i], &sim->opk_stock[i + 1],
                    (sim->opk_count - i - 1) * sizeof(sim->opk_stock[0]));
        sim->opk_count--;
        gy_secure_zero(&sim->opk_stock[sim->opk_count],
                       sizeof(sim->opk_stock[sim->opk_count]));
        return;
    }
}

int
gy_sim_bob_recv_initial(struct gy_sim *sim, const uint8_t *msg, size_t msglen,
                        uint8_t *out, size_t cap, size_t *outlen)
{
    struct gy_dr_secrets secrets;
    struct gy_x3dh_local local;
    struct gy_x3dh_opk_ref ref;
    struct gy_dr_state pending;
    uint8_t ad2[GY_X3DH_AD_MAX];
    uint8_t base[2 * GY_CURVE_PK_MAX];
    size_t adl2, prefl, cpl, kw, ctlen;
    int rc;

    cpl = sim->desc->curve_pk_len;
    kw = 4 + 1 + cpl;
    prefl = prefix_len(sim->desc);
    if (msglen < prefl)
        return GY_ERR_ARG;

    /* Base key = IK_A.pk || EK_A.pk from the carried keys (offsets past the
     * pkid+curve_type prefix of each). */
    memcpy(base, msg + 2 + 5, cpl);
    memcpy(base + cpl, msg + 2 + kw + 5, cpl);

    ctlen = gy_be32_get(msg + prefl - 4);
    if (msglen < prefl + ctlen)
        return GY_ERR_ARG;

    /* Base-key dedupe: a re-sent initial message routes to the live session,
     * where the already-consumed first message no longer decrypts. */
    if (sim->bob_up && sim->have_base && memcmp(base, sim->base, 2 * cpl) == 0)
        return gy_dr_decrypt(&sim->bob_dr, out, cap, outlen, msg + prefl, ctlen,
                             sim->ad, sim->adl);

    local.ik = &sim->bob_ik;
    local.spk = &sim->bob_spk.kp;
    local.opks = sim->opk_stock;
    local.n_opks = sim->opk_count;
    rc = gy_x3dh_respond(sim->desc, &secrets, ad2, &adl2, &ref, &local, msg,
                         msglen);
    if (rc != GY_OK)
        return rc;

    rc = gy_dr_init_bob(&pending, sim->desc, sim->aead_id, &secrets,
                        &sim->bob_spk.kp);
    gy_secure_zero(&secrets, sizeof(secrets));
    if (rc != GY_OK)
        return rc;

    /* First DR message decrypts BEFORE we commit anything (D-X3DH-10). */
    rc = gy_dr_decrypt(&pending, out, cap, outlen, msg + prefl, ctlen, ad2,
                       adl2);
    if (rc != GY_OK) {
        gy_dr_free(&pending); /* OPK retained: nothing was committed */
        return rc;
    }

    sim->bob_dr = pending;
    sim->bob_up = 1;
    memcpy(sim->ad, ad2, adl2);
    sim->adl = adl2;
    memcpy(sim->base, base, 2 * cpl);
    sim->have_base = 1;
    if (ref.present)
        opk_delete(sim, ref.pkid);
    return GY_OK;
}

int
gy_sim_corrupt(uint8_t *frame, size_t flen, enum gy_sim_field field)
{
    size_t lenoff = 2 + GY_HE_SALT_LEN;
    size_t ehoff = lenoff + 2;
    size_t ehl, payoff;

    if (frame == NULL || flen < ehoff)
        return GY_ERR_ARG;
    ehl = gy_be16_get(frame + lenoff);
    payoff = ehoff + ehl;

    switch (field) {
    case GY_SIM_F_VERSION:
        frame[0] ^= 0x01;
        return GY_OK;
    case GY_SIM_F_SUITE:
        frame[1] ^= 0x01;
        return GY_OK;
    case GY_SIM_F_SALT:
        frame[2] ^= 0x01;
        return GY_OK;
    case GY_SIM_F_LEN:
        frame[lenoff] ^= 0x01;
        return GY_OK;
    case GY_SIM_F_ENC_HEADER:
        if (flen <= ehoff)
            return GY_ERR_ARG;
        frame[ehoff] ^= 0x01;
        return GY_OK;
    case GY_SIM_F_PAYLOAD:
        if (flen <= payoff)
            return GY_ERR_ARG;
        frame[payoff] ^= 0x01;
        return GY_OK;
    }
    return GY_ERR_ARG;
}

/* ------------------------------------------------------------------------- *
 * Hybrid two-party simulator.
 * ------------------------------------------------------------------------- */

/* Length of a hybrid X3DH prefix (section 6.5); the first DR frame follows. */
static size_t
hybrid_prefix_len(const struct gy_suite_desc *desc)
{
    size_t cpl = desc->curve_pk_len;

    return 2 + (4 + 1 + cpl + desc->kem_pk_len + desc->dsa_pk_len) +
           (4 + 1 + cpl) + 3 * desc->kem_ct_len + 12 + 4;
}

/* Parse IK_A (full hybrid identity) and EK_A (curve) from a hybrid prefix. */
static void
hybrid_parse_base(const struct gy_suite_desc *desc, const uint8_t *msg,
                  struct gy_hybrid_identity_public_key *ika,
                  struct gy_public_key *ekb)
{
    size_t cpl = desc->curve_pk_len;
    size_t ekl = desc->kem_pk_len, dpl = desc->dsa_pk_len;
    size_t ik_wire = 4 + 1 + cpl + ekl + dpl;
    size_t o = 2;

    memset(ika, 0, sizeof(*ika));
    memset(ekb, 0, sizeof(*ekb));
    ika->base.curve.pkid = gy_be32_get(msg + o);
    ika->base.curve.curve_type = msg[o + 4];
    memcpy(ika->base.curve.pk, msg + o + 5, cpl);
    memcpy(ika->base.mlkem_ek, msg + o + 5 + cpl, ekl);
    memcpy(ika->mldsa_pk, msg + o + 5 + cpl + ekl, dpl);
    o += ik_wire;
    ekb->pkid = gy_be32_get(msg + o);
    ekb->curve_type = msg[o + 4];
    memcpy(ekb->pk, msg + o + 5, cpl);
}

/* SPK advertising every legal interval and aead_id (bits 32/33/34). */
static uint64_t
hybrid_advertise(uint8_t aead_id)
{
    return (uint64_t)1 | ((uint64_t)100 << 16) |
           ((uint64_t)1 << (31 + aead_id));
}

int
gy_sim_hybrid_setup(struct gy_sim_hybrid *sim, const struct gy_suite_desc *desc,
                    uint8_t aead_id, uint32_t interval, int with_opk)
{
    int rc;

    memset(sim, 0, sizeof(*sim));
    sim->desc = desc;
    sim->aead_id = aead_id;
    sim->interval = interval;

    rc = gy_hybrid_identity_keypair_generate(desc, &sim->bob_ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_hybrid_spk_create(desc, &sim->bob_spk, &sim->bob_ik, GY_SIM_TS,
                              hybrid_advertise(aead_id));
    if (rc != GY_OK)
        return rc;

    memset(&sim->bundle, 0, sizeof(sim->bundle));
    sim->bundle.ik = sim->bob_ik.pub;
    sim->bundle.spk = sim->bob_spk.kp.pub;
    sim->bundle.spk_timestamp = sim->bob_spk.timestamp;
    sim->bundle.spk_flags = sim->bob_spk.flags;
    sim->bundle.spk_ik_id = sim->bob_spk.ik_id;
    memcpy(sim->bundle.spk_ed_sig, sim->bob_spk.ed_sig, GY_SIG_MAX);
    memcpy(sim->bundle.spk_mldsa_sig, sim->bob_spk.mldsa_sig, GY_DSA_SIG_MAX);

    if (with_opk) {
        rc = gy_hybrid_opk_batch(desc, sim->opk_stock, 1, NULL, 0);
        if (rc != GY_OK)
            return rc;
        sim->opk_count = 1;
        sim->bundle.opk = sim->opk_stock[0].pub;
    }
    return GY_OK;
}

int
gy_sim_hybrid_start(struct gy_sim_hybrid_initiator *init,
                    const struct gy_sim_hybrid *sim, uint8_t *out, size_t cap,
                    size_t *outlen, const uint8_t *pt, size_t ptlen)
{
    struct gy_dr_secrets secrets;
    uint8_t prefix[GY_HYBRID_X3DH_PREFIX_MAX];
    uint8_t dr[GY_DR_HYBRID_HEADER_MAX + 512 + GY_AEAD_MAX_TAG];
    size_t prefl, drlen;
    uint32_t hflag;
    int rc;

    memset(init, 0, sizeof(*init));
    init->desc = sim->desc;
    init->aead_id = sim->aead_id;
    init->interval = sim->interval;

    rc = gy_hybrid_identity_keypair_generate(sim->desc, &init->ik);
    if (rc != GY_OK)
        return rc;
    rc = gy_keypair_generate(sim->desc, &init->ek);
    if (rc != GY_OK)
        return rc;

    hflag = sim->interval | ((uint32_t)sim->aead_id << 16);
    rc = gy_hybrid_x3dh_initiate(sim->desc, &secrets, init->ad, &init->adl,
                                 prefix, &prefl, &init->ik, &sim->bundle,
                                 &init->ek, hflag);
    if (rc != GY_OK)
        return rc;

    rc = gy_hybrid_dr_init_alice(&init->dr, sim->desc, sim->aead_id, &secrets,
                                 &sim->bundle.spk, sim->interval,
                                 init->ik.mlkem_dk);
    if (rc != GY_OK) {
        gy_secure_zero(&secrets, sizeof(secrets));
        return rc;
    }
    init->up = 1;

    rc = gy_hybrid_dr_encrypt(&init->dr, dr, sizeof(dr), &drlen, pt, ptlen,
                              init->ad, init->adl);
    gy_secure_zero(&secrets, sizeof(secrets));
    if (rc != GY_OK)
        return rc;

    if (cap < prefl + drlen)
        return GY_ERR_ARG;
    memcpy(out, prefix, prefl);
    memcpy(out + prefl, dr, drlen);
    *outlen = prefl + drlen;
    return GY_OK;
}

/* Delete the hybrid OPK matching pkid from the stock (D-X3DH-10). */
static void
hybrid_opk_delete(struct gy_sim_hybrid *sim, uint32_t pkid)
{
    size_t i;

    for (i = 0; i < sim->opk_count; i++) {
        if (sim->opk_stock[i].pub.curve.pkid != pkid)
            continue;
        gy_secure_zero(&sim->opk_stock[i], sizeof(sim->opk_stock[i]));
        if (i + 1 < sim->opk_count)
            memmove(&sim->opk_stock[i], &sim->opk_stock[i + 1],
                    (sim->opk_count - i - 1) * sizeof(sim->opk_stock[0]));
        sim->opk_count--;
        gy_secure_zero(&sim->opk_stock[sim->opk_count],
                       sizeof(sim->opk_stock[sim->opk_count]));
        return;
    }
}

int
gy_sim_hybrid_bob_recv_initial(struct gy_sim_hybrid *sim, const uint8_t *msg,
                               size_t msglen, uint8_t *out, size_t cap,
                               size_t *outlen)
{
    struct gy_dr_secrets secrets;
    struct gy_hybrid_x3dh_local local;
    struct gy_x3dh_opk_ref ref;
    struct gy_hybrid_dr_state pending;
    struct gy_hybrid_identity_public_key ika;
    struct gy_public_key ekb;
    uint8_t ad2[GY_HYBRID_AD_MAX];
    uint8_t base[2 * GY_CURVE_PK_MAX];
    uint32_t hflag = 0;
    size_t adl2, prefl, cpl, frame_len;
    int rc;

    cpl = sim->desc->curve_pk_len;
    prefl = hybrid_prefix_len(sim->desc);
    if (msglen <= prefl)
        return GY_ERR_ARG;
    frame_len = msglen - prefl;

    hybrid_parse_base(sim->desc, msg, &ika, &ekb);
    memcpy(base, ika.base.curve.pk, cpl);
    memcpy(base + cpl, ekb.pk, cpl);

    /* Base-key dedupe: a re-sent initial message routes to the live session. */
    if (sim->bob_up && sim->have_base && memcmp(base, sim->base, 2 * cpl) == 0)
        return gy_hybrid_dr_decrypt(&sim->bob_dr, out, cap, outlen, msg + prefl,
                                    frame_len, sim->ad, sim->adl);

    local.ik = &sim->bob_ik;
    local.spk = &sim->bob_spk.kp;
    local.spk_flags = sim->bob_spk.flags;
    local.opks = sim->opk_stock;
    local.n_opks = sim->opk_count;
    rc = gy_hybrid_x3dh_respond(sim->desc, &secrets, ad2, &adl2, &ref, &hflag,
                                &local, msg, msglen);
    if (rc != GY_OK)
        return rc;

    rc = gy_hybrid_dr_init_bob(
        &pending, sim->desc, (uint8_t)((hflag >> 16) & 0xFF), &secrets,
        &sim->bob_spk.kp, hflag & 0xFFFF, ika.base.mlkem_ek);
    gy_secure_zero(&secrets, sizeof(secrets));
    if (rc != GY_OK)
        return rc;

    /* First frame decrypts BEFORE we commit anything (D-X3DH-10). */
    rc = gy_hybrid_dr_decrypt(&pending, out, cap, outlen, msg + prefl,
                              frame_len, ad2, adl2);
    if (rc != GY_OK) {
        gy_hybrid_dr_free(&pending); /* OPK retained: nothing committed */
        return rc;
    }

    sim->bob_dr = pending;
    sim->bob_up = 1;
    memcpy(sim->ad, ad2, adl2);
    sim->adl = adl2;
    memcpy(sim->base, base, 2 * cpl);
    sim->have_base = 1;
    if (ref.present)
        hybrid_opk_delete(sim, ref.pkid);
    return GY_OK;
}

int
gy_sim_hybrid_corrupt(const struct gy_suite_desc *desc, uint8_t *frame,
                      size_t flen, enum gy_sim_hybrid_field field)
{
    size_t cpl = desc->curve_pk_len;
    size_t ik_wire = 4 + 1 + cpl + desc->kem_pk_len + desc->dsa_pk_len;
    size_t ek_wire = 4 + 1 + cpl;
    size_t prefl = 2 + ik_wire + ek_wire + 3 * desc->kem_ct_len + 12 + 4;
    size_t off;

    if (frame == NULL)
        return GY_ERR_ARG;

    switch (field) {
    case GY_SIM_HF_MLKEM_EK:
        off = 2 + 5 + cpl; /* start of Alice's IK ML-KEM ek */
        break;
    case GY_SIM_HF_KEM_CT:
        off = 2 + ik_wire + ek_wire; /* ct_ik */
        break;
    case GY_SIM_HF_FLAGS:
        off = prefl - 4; /* hybrid_flag MSB (reserved-bit byte) */
        break;
    case GY_SIM_HF_CONFIRM_CT:
        off = 2 + GY_HE_SALT_LEN + 2; /* enc_header (carries confirm_ct) */
        break;
    default:
        return GY_ERR_ARG;
    }
    if (flen <= off)
        return GY_ERR_ARG;
    frame[off] ^= 0x01;
    return GY_OK;
}

void
gy_sim_hybrid_free(struct gy_sim_hybrid *sim)
{
    if (sim == NULL)
        return;
    gy_hybrid_dr_free(&sim->bob_dr);
    gy_secure_zero(sim, sizeof(*sim));
}

void
gy_sim_hybrid_initiator_free(struct gy_sim_hybrid_initiator *init)
{
    if (init == NULL)
        return;
    gy_hybrid_dr_free(&init->dr);
    gy_secure_zero(init, sizeof(*init));
}

void
gy_sim_free(struct gy_sim *sim)
{
    if (sim == NULL)
        return;
    gy_dr_free(&sim->bob_dr);
    gy_secure_zero(sim, sizeof(*sim));
}

void
gy_sim_initiator_free(struct gy_sim_initiator *init)
{
    if (init == NULL)
        return;
    gy_dr_free(&init->dr);
    gy_secure_zero(init, sizeof(*init));
}
