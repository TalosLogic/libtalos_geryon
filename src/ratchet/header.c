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
