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
