/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Reference public-API store.  See apistore.h.
 */

#include <string.h>

#include "apistore.h"

static struct as_rec *
find(struct apistore *s, int kind, const uint8_t *id, size_t id_len)
{
    int i;

    for (i = 0; i < AS_MAX; i++)
        if (s->recs[i].in_use && s->recs[i].kind == kind &&
            s->recs[i].id_len == id_len &&
            memcmp(s->recs[i].id, id, id_len) == 0)
            return &s->recs[i];
    return NULL;
}

/* Return GY_ERR_CRYPTO if this write is the injected failure, else GY_OK. */
static int
write_gate(struct apistore *s)
{
    int idx = s->write_idx++;

    return idx == s->fail_at ? GY_ERR_CRYPTO : GY_OK;
}

static int
cb_load(void *ctx, int kind, const uint8_t *id, size_t id_len, uint8_t *out,
        size_t cap, size_t *out_len)
{
    struct apistore *s = ctx;
    struct as_rec *r;

    s->n_load++;
    r = find(s, kind, id, id_len);
    if (r == NULL) {
        *out_len = 0;
        return GY_OK;
    }
    if (r->blob_len > cap)
        return GY_ERR_ARG;
    memcpy(out, r->blob, r->blob_len);
    *out_len = r->blob_len;
    return GY_OK;
}

static int
cb_store(void *ctx, int kind, const uint8_t *id, size_t id_len,
         const uint8_t *blob, size_t blob_len)
{
    struct apistore *s = ctx;
    struct as_rec *r;

    if (write_gate(s) != GY_OK)
        return GY_ERR_CRYPTO;
    s->n_store++;
    if (blob_len > AS_BLOB)
        return GY_ERR_ARG;
    r = find(s, kind, id, id_len);
    if (r == NULL) {
        int i;

        for (i = 0; i < AS_MAX; i++)
            if (!s->recs[i].in_use) {
                r = &s->recs[i];
                break;
            }
        if (r == NULL)
            return GY_ERR_STATE;
        r->in_use = 1;
        r->kind = kind;
        r->id_len = id_len;
        memcpy(r->id, id, id_len);
    }
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static int
cb_delete(void *ctx, int kind, const uint8_t *id, size_t id_len)
{
    struct apistore *s = ctx;
    struct as_rec *r;

    if (write_gate(s) != GY_OK)
        return GY_ERR_CRYPTO;
    s->n_delete++;
    r = find(s, kind, id, id_len);
    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK;
}

static int
cb_consume(void *ctx, uint32_t pkid)
{
    struct apistore *s = ctx;

    (void)pkid;
    if (write_gate(s) != GY_OK)
        return GY_ERR_CRYPTO;
    s->n_consume++;
    return GY_OK;
}

static int
cb_load_id(void *ctx, uint8_t *out, size_t cap, size_t *out_len)
{
    struct apistore *s = ctx;

    s->n_load++;
    if (s->identity_len == 0) {
        *out_len = 0;
        return GY_OK;
    }
    if (s->identity_len > cap)
        return GY_ERR_ARG;
    memcpy(out, s->identity, s->identity_len);
    *out_len = s->identity_len;
    return GY_OK;
}

static int
cb_store_id(void *ctx, const uint8_t *blob, size_t blob_len)
{
    struct apistore *s = ctx;

    if (write_gate(s) != GY_OK)
        return GY_ERR_CRYPTO;
    s->n_store++;
    if (blob_len > AS_IDENTITY_BLOB)
        return GY_ERR_ARG;
    if (blob_len > 0)
        memcpy(s->identity, blob, blob_len);
    s->identity_len = blob_len;
    return GY_OK;
}

static int
cb_load_pk(void *ctx, int kind, uint32_t pkid, uint8_t *out, size_t cap,
           size_t *out_len)
{
    (void)ctx;
    (void)kind;
    (void)pkid;
    (void)out;
    (void)cap;
    *out_len = 0;
    return GY_OK;
}

void
as_bind(struct apistore *s, gy_store_callbacks *cb)
{
    memset(s, 0, sizeof(*s));
    s->fail_at = -1;
    cb->ctx = s;
    cb->load_record = cb_load;
    cb->store_record = cb_store;
    cb->delete_record = cb_delete;
    cb->load_identity = cb_load_id;
    cb->store_identity = cb_store_id;
    cb->load_prekey = cb_load_pk;
    cb->consume_opk = cb_consume;
}

void
as_snapshot(struct apistore *dst, const struct apistore *src)
{
    memcpy(dst, src, sizeof(*dst));
}

int
as_count(const struct apistore *s, int kind)
{
    int i, n = 0;

    for (i = 0; i < AS_MAX; i++)
        if (s->recs[i].in_use && s->recs[i].kind == kind)
            n++;
    return n;
}

size_t
as_bytes(const struct apistore *s)
{
    size_t i, total = 0;

    for (i = 0; i < AS_MAX; i++)
        if (s->recs[i].in_use)
            total += s->recs[i].blob_len;
    return total;
}
