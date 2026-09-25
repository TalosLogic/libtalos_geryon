/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Shared in-memory mock gy_group_store for the group state tests.
 * static inline so multiple test TUs can include it without a link clash or an
 * unused-function warning under -Werror.  Supports fault injection: fail_store
 * fails every store(); fail_remove_at fails the Nth remove().
 */

#ifndef GY_TEST_GROUP_MOCK_STORE_H
#define GY_TEST_GROUP_MOCK_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "error.h"
#include "group_store.h"

#define MOCK_SLOTS 16
#define MOCK_ID_MAX 48
#define MOCK_BLOB_MAX 256

struct mock_rec {
    int used;
    enum gy_group_rec_kind kind;
    uint8_t id[MOCK_ID_MAX];
    size_t id_len;
    uint8_t blob[MOCK_BLOB_MAX];
    size_t blob_len;
};

struct mock_store {
    struct mock_rec recs[MOCK_SLOTS];
    int fail_store;     /* if set, every store() fails without mutating */
    int fail_remove_at; /* if != 0, the Nth remove() fails without mutating */
    int remove_calls;   /* remove() invocation counter (for fail_remove_at) */
};

static inline struct mock_rec *
mock_find(struct mock_store *m, enum gy_group_rec_kind kind, const uint8_t *id,
          size_t id_len)
{
    size_t i;
    for (i = 0; i < MOCK_SLOTS; i++) {
        struct mock_rec *r = &m->recs[i];
        if (r->used && r->kind == kind && r->id_len == id_len &&
            memcmp(r->id, id, id_len) == 0)
            return r;
    }
    return NULL;
}

static inline int
mock_load(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
          size_t id_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct mock_rec *r = mock_find(ctx, kind, id, id_len);
    if (r == NULL) {
        *out_len = 0; /* absent */
        return GY_OK;
    }
    if (r->blob_len > cap)
        return GY_ERR_TOOLONG;
    memcpy(out, r->blob, r->blob_len);
    *out_len = r->blob_len;
    return GY_OK;
}

static inline int
mock_store_fn(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
              size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct mock_store *m = ctx;
    struct mock_rec *r = mock_find(m, kind, id, id_len);
    size_t i;

    if (m->fail_store)
        return GY_ERR_NO_SPACE; /* injected failure, no mutation */
    if (id_len > MOCK_ID_MAX || blob_len > MOCK_BLOB_MAX)
        return GY_ERR_TOOLONG;
    if (r == NULL) {
        for (i = 0; i < MOCK_SLOTS && m->recs[i].used; i++)
            ;
        if (i == MOCK_SLOTS)
            return GY_ERR_NO_SPACE;
        r = &m->recs[i];
        r->used = 1;
        r->kind = kind;
        memcpy(r->id, id, id_len);
        r->id_len = id_len;
    }
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static inline int
mock_remove(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
            size_t id_len)
{
    struct mock_store *m = ctx;
    struct mock_rec *r;

    if (m->fail_remove_at != 0 && ++m->remove_calls == m->fail_remove_at)
        return GY_ERR_NO_SPACE; /* injected failure, no mutation */
    r = mock_find(m, kind, id, id_len);
    if (r != NULL)
        memset(r, 0, sizeof(*r));
    return GY_OK; /* idempotent */
}

static inline void
mock_init(struct mock_store *m, struct gy_group_store *s)
{
    memset(m, 0, sizeof(*m));
    s->ctx = m;
    s->load = mock_load;
    s->store = mock_store_fn;
    s->remove = mock_remove;
}

static inline size_t
mock_count(const struct mock_store *m)
{
    size_t i, c = 0;
    for (i = 0; i < MOCK_SLOTS; i++)
        if (m->recs[i].used)
            c++;
    return c;
}

#endif /* GY_TEST_GROUP_MOCK_STORE_H */
