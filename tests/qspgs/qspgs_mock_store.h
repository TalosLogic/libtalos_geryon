/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Shared in-memory mock gy_qspgs_store for the QSPGS storage tests.
 * static inline so multiple test TUs can include it without a link clash or an
 * unused-function warning under -Werror.  Mirrors group_mock_store.h: fail_store
 * fails every store(); fail_remove_at fails the Nth remove().
 */

#ifndef GY_TEST_QSPGS_MOCK_STORE_H
#define GY_TEST_QSPGS_MOCK_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "error.h"
#include "qspgs_store.h"

#define QMOCK_SLOTS 16
#define QMOCK_ID_MAX 64 /* GY_QSPGS_UID_MAX (GID is 16). */
#define QMOCK_BLOB_MAX GY_QSPGS_REC_BLOB_MAX

struct qmock_rec {
    int used;
    enum gy_qspgs_rec_kind kind;
    uint8_t id[QMOCK_ID_MAX];
    size_t id_len;
    uint8_t blob[QMOCK_BLOB_MAX];
    size_t blob_len;
};

struct qmock_store {
    struct qmock_rec recs[QMOCK_SLOTS];
    int fail_store;     /* if set, every store() fails without mutating */
    int fail_remove_at; /* if != 0, the Nth remove() fails without mutating */
    int remove_calls;   /* remove() invocation counter (for fail_remove_at) */
};

static inline struct qmock_rec *
qmock_find(struct qmock_store *m, enum gy_qspgs_rec_kind kind,
           const uint8_t *id, size_t id_len)
{
    size_t i;
    for (i = 0; i < QMOCK_SLOTS; i++) {
        struct qmock_rec *r = &m->recs[i];
        if (r->used && r->kind == kind && r->id_len == id_len &&
            memcmp(r->id, id, id_len) == 0)
            return r;
    }
    return NULL;
}

static inline int
qmock_load(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
           size_t id_len, uint8_t *out, size_t cap, size_t *out_len)
{
    struct qmock_rec *r = qmock_find(ctx, kind, id, id_len);
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
qmock_store_fn(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
               size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct qmock_store *m = ctx;
    struct qmock_rec *r = qmock_find(m, kind, id, id_len);
    size_t i;

    if (m->fail_store)
        return GY_ERR_NO_SPACE; /* injected failure, no mutation */
    if (id_len > QMOCK_ID_MAX || blob_len > QMOCK_BLOB_MAX)
        return GY_ERR_TOOLONG;
    if (r == NULL) {
        for (i = 0; i < QMOCK_SLOTS; i++)
            if (!m->recs[i].used) {
                r = &m->recs[i];
                break;
            }
        if (r == NULL)
            return GY_ERR_NO_SPACE;
    }
    r->used = 1;
    r->kind = kind;
    memcpy(r->id, id, id_len);
    r->id_len = id_len;
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    return GY_OK;
}

static inline int
qmock_remove(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
             size_t id_len)
{
    struct qmock_store *m = ctx;
    struct qmock_rec *r;

    m->remove_calls++;
    if (m->fail_remove_at != 0 && m->remove_calls == m->fail_remove_at)
        return GY_ERR_NO_SPACE; /* injected failure, no mutation */
    r = qmock_find(m, kind, id, id_len);
    if (r != NULL)
        r->used = 0;
    return GY_OK; /* removing an absent record is idempotent */
}

static inline void
qmock_init(struct qmock_store *m, struct gy_qspgs_store *store)
{
    memset(m, 0, sizeof(*m));
    store->ctx = m;
    store->load = qmock_load;
    store->store = qmock_store_fn;
    store->remove = qmock_remove;
}

#endif /* GY_TEST_QSPGS_MOCK_STORE_H */
