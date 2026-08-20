/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "header.h"

int
gy_dr_header_encode(const struct gy_suite_desc *desc,
                    const struct gy_dr_header *h, uint8_t *out, size_t cap,
                    size_t *outlen)
{
    size_t cpl, need;

    if (desc == NULL || h == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;

    cpl = desc->curve_pk_len;
    need = 4 + cpl + 4 + 4;
    if (cap < need)
        return GY_ERR_ARG;

    gy_be32_put(out, h->flags);
    memcpy(out + 4, h->ratchet_pk, cpl);
    gy_be32_put(out + 4 + cpl, h->pn);
    gy_be32_put(out + 8 + cpl, h->n);
    *outlen = need;
    return GY_OK;
}

int
gy_dr_header_decode(const struct gy_suite_desc *desc, struct gy_dr_header *h,
                    const uint8_t *in, size_t len, size_t *consumed)
{
    size_t cpl, need;
    uint32_t flags;

    if (desc == NULL || h == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;

    cpl = desc->curve_pk_len;
    need = 4 + cpl + 4 + 4;
    if (len < need)
        return GY_ERR_ARG;

    flags = gy_be32_get(in);
    /* Cross-suite curve mismatch, then reserved/HE bits (zero on the wire). */
    if ((flags & GY_DR_FLAG_CURVE_MASK) != desc->curve_type)
        return GY_ERR_STATE;
    if ((flags & GY_DR_FLAG_NONCURVE_MASK) != 0)
        return GY_ERR_ARG;

    memset(h, 0, sizeof(*h));
    h->flags = flags;
    memcpy(h->ratchet_pk, in + 4, cpl);
    h->pn = gy_be32_get(in + 4 + cpl);
    h->n = gy_be32_get(in + 8 + cpl);
    *consumed = need;
    return GY_OK;
}

size_t
gy_dr_hybrid_header_len(const struct gy_suite_desc *desc, int ek_present,
                        int confirm_present)
{
    if (desc == NULL || !desc->is_hybrid)
        return 0;
    return 4 + desc->curve_pk_len + desc->kem_ct_len + 4 + 4 +
           (ek_present ? desc->kem_pk_len : 0) +
           (confirm_present ? desc->kem_ct_len : 0);
}

int
gy_dr_hybrid_header_encode(const struct gy_suite_desc *desc,
                           const struct gy_dr_hybrid_header *h, uint8_t *out,
                           size_t cap, size_t *outlen)
{
    size_t cpl, ctl, ekl, pos;
    int ek_present, confirm_present;

    if (desc == NULL || h == NULL || out == NULL || outlen == NULL)
        return GY_ERR_ARG;

    cpl = desc->curve_pk_len;
    ctl = desc->kem_ct_len;
    ekl = desc->kem_pk_len;
    ek_present = (h->flags & GY_DR_FLAG_MLKEM_EK_PRESENT) != 0;
    confirm_present = (h->flags & GY_DR_FLAG_CONFIRM_CT_PRESENT) != 0;

    if (cap < 4 + cpl + ctl + 4 + 4 + (ek_present ? ekl : 0) +
                  (confirm_present ? ctl : 0))
        return GY_ERR_ARG;

    gy_be32_put(out, h->flags);
    pos = 4;
    memcpy(out + pos, h->ratchet_pk, cpl);
    pos += cpl;
    memcpy(out + pos, h->kem_ct, ctl);
    pos += ctl;
    gy_be32_put(out + pos, h->pn);
    pos += 4;
    gy_be32_put(out + pos, h->n);
    pos += 4;
    if (ek_present) {
        memcpy(out + pos, h->mlkem_ek, ekl);
        pos += ekl;
    }
    if (confirm_present) {
        memcpy(out + pos, h->confirm_ct, ctl);
        pos += ctl;
    }
    *outlen = pos;
    return GY_OK;
}

int
gy_dr_hybrid_header_decode(const struct gy_suite_desc *desc,
                           struct gy_dr_hybrid_header *h, const uint8_t *in,
                           size_t len, size_t *consumed)
{
    size_t cpl, ctl, ekl, pos, need;
    uint32_t flags;
    int ek_present, confirm_present;

    if (desc == NULL || h == NULL || in == NULL || consumed == NULL)
        return GY_ERR_ARG;

    cpl = desc->curve_pk_len;
    ctl = desc->kem_ct_len;
    ekl = desc->kem_pk_len;
    if (len < 4)
        return GY_ERR_ARG;

    flags = gy_be32_get(in);
    /* Cross-suite curve mismatch, then reserved bits 10..31 (zero on wire). */
    if ((flags & GY_DR_FLAG_CURVE_MASK) != desc->curve_type)
        return GY_ERR_STATE;
    if ((flags & GY_DR_FLAG_RESERVED_MASK) != 0)
        return GY_ERR_ARG;

    ek_present = (flags & GY_DR_FLAG_MLKEM_EK_PRESENT) != 0;
    confirm_present = (flags & GY_DR_FLAG_CONFIRM_CT_PRESENT) != 0;
    need = 4 + cpl + ctl + 4 + 4 + (ek_present ? ekl : 0) +
           (confirm_present ? ctl : 0);
    if (len < need)
        return GY_ERR_ARG;

    memset(h, 0, sizeof(*h));
    h->flags = flags;
    pos = 4;
    memcpy(h->ratchet_pk, in + pos, cpl);
    pos += cpl;
    memcpy(h->kem_ct, in + pos, ctl);
    pos += ctl;
    h->pn = gy_be32_get(in + pos);
    pos += 4;
    h->n = gy_be32_get(in + pos);
    pos += 4;
    if (ek_present) {
        memcpy(h->mlkem_ek, in + pos, ekl);
        pos += ekl;
    }
    if (confirm_present) {
        memcpy(h->confirm_ct, in + pos, ctl);
        pos += ctl;
    }
    *consumed = pos;
    return GY_OK;
}
