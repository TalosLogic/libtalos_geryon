/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <string.h>

#include "sealed_store.h"

/*
 * Associated-data tags (D-CUST-1 item 5 "key type"): a fixed byte
 * discriminating which callback family an AD came from, so a record AD can
 * never be confused with an identity or prekey AD even where their other
 * bytes happen to coincide (e.g. a record kind and a prekey kind both start
 * at 1).  Internal to this file; never persisted or exposed.
 */
#define TAG_RECORD 0x01
#define TAG_IDENTITY 0x02
#define TAG_PREKEY 0x03

static int
ss_load_record(void *ctx, int kind, const uint8_t *id, size_t id_len,
               uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_sealed_store *ss = ctx;
    uint8_t ad[2 + GY_DEVICE_ID_MAX];
    size_t adlen, scratchlen;
    int rc;

    if (id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    ad[0] = TAG_RECORD;
    ad[1] = (uint8_t)kind;
    memcpy(ad + 2, id, id_len);
    adlen = 2 + id_len;

    scratchlen = sizeof(ss->scratch);
    rc = ss->real.load_record(ss->real.ctx, kind, id, id_len, ss->scratch,
                              scratchlen, &scratchlen);
    if (rc != GY_OK)
        return rc;
    if (scratchlen == 0) {
        *out_len = 0;
        return GY_OK;
    }
    *out_len = cap;
    return gy_keystore_unseal(ss->ks, ad, adlen, ss->scratch, scratchlen, out,
                              out_len);
}

static int
ss_store_record(void *ctx, int kind, const uint8_t *id, size_t id_len,
                const uint8_t *blob, size_t blob_len)
{
    struct gy_sealed_store *ss = ctx;
    uint8_t ad[2 + GY_DEVICE_ID_MAX];
    size_t adlen, sealedlen;
    int rc;

    if (id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    ad[0] = TAG_RECORD;
    ad[1] = (uint8_t)kind;
    memcpy(ad + 2, id, id_len);
    adlen = 2 + id_len;

    sealedlen = sizeof(ss->scratch);
    rc = gy_keystore_seal(ss->ks, ss->alg_id, ad, adlen, blob, blob_len,
                          ss->scratch, &sealedlen);
    if (rc != GY_OK)
        return rc;
    return ss->real.store_record(ss->real.ctx, kind, id, id_len, ss->scratch,
                                 sealedlen);
}

static int
ss_delete_record(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct gy_sealed_store *ss = ctx;

    return ss->real.delete_record(ss->real.ctx, kind, id, id_len);
}

static int
ss_load_identity(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    struct gy_sealed_store *ss = ctx;
    uint8_t ad[1];
    size_t scratchlen;
    int rc;

    ad[0] = TAG_IDENTITY;

    scratchlen = sizeof(ss->scratch);
    rc = ss->real.load_identity(ss->real.ctx, ss->scratch, scratchlen,
                                &scratchlen);
    if (rc != GY_OK)
        return rc;
    if (scratchlen == 0) {
        *out_len = 0;
        return GY_OK;
    }
    *out_len = cap;
    return gy_keystore_unseal(ss->ks, ad, sizeof(ad), ss->scratch, scratchlen,
                              out, out_len);
}

static int
ss_store_identity(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct gy_sealed_store *ss = ctx;
    uint8_t ad[1];
    size_t sealedlen;
    int rc;

    ad[0] = TAG_IDENTITY;
    sealedlen = sizeof(ss->scratch);
    rc = gy_keystore_seal(ss->ks, ss->alg_id, ad, sizeof(ad), blob, blob_len,
                          ss->scratch, &sealedlen);
    if (rc != GY_OK)
        return rc;
    return ss->real.store_identity(ss->real.ctx, ss->scratch, sealedlen);
}

static int
ss_load_prekey(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
               size_t *out_len)
{
    struct gy_sealed_store *ss = ctx;
    uint8_t ad[6];
    size_t scratchlen;
    int rc;

    ad[0] = TAG_PREKEY;
    ad[1] = (uint8_t)kind;
    ad[2] = (uint8_t)(pkid >> 24);
    ad[3] = (uint8_t)(pkid >> 16);
    ad[4] = (uint8_t)(pkid >> 8);
    ad[5] = (uint8_t)pkid;

    scratchlen = sizeof(ss->scratch);
    rc = ss->real.load_prekey(ss->real.ctx, kind, pkid, ss->scratch, scratchlen,
                              &scratchlen);
    if (rc != GY_OK)
        return rc;
    if (scratchlen == 0) {
        *out_len = 0;
        return GY_OK;
    }
    *out_len = cap;
    return gy_keystore_unseal(ss->ks, ad, sizeof(ad), ss->scratch, scratchlen,
                              out, out_len);
}

static int
ss_consume_opk(void *ctx, uint32_t pkid)
{
    struct gy_sealed_store *ss = ctx;

    return ss->real.consume_opk(ss->real.ctx, pkid);
}

int
gy_sealed_store_bind(struct gy_sealed_store *ss, struct gy_keystore *ks,
                     const gy_store_callbacks *real, uint8_t alg_id,
                     gy_store_callbacks *out)
{
    if (ss == NULL || ks == NULL || real == NULL || out == NULL)
        return GY_ERR_ARG;

    ss->ks = ks;
    ss->real = *real;
    ss->alg_id = alg_id;

    out->ctx = ss;
    out->load_record = ss_load_record;
    out->store_record = ss_store_record;
    out->delete_record = ss_delete_record;
    out->load_identity = ss_load_identity;
    out->store_identity = ss_store_identity;
    out->load_prekey = ss_load_prekey;
    out->consume_opk = ss_consume_opk;
    return GY_OK;
}
