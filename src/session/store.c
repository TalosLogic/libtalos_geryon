/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Transactional staging engine (D-SES-10).  Operations stage record
 * STOREs and deferred actions in a gy_op and flush them at a single commit
 * point in a pinned order (all STOREs, then deletions and OPK consumptions).
 * Any pre-commit failure zeroizes the stage and touches the store not at all.
 */

#include <string.h>

#include "store.h"

/*
 * Debug-build re-entrancy guard (D-GEN-8): op->active is set while a store
 * callback runs, so a callback that re-enters the engine on the same gy_op
 * trips the assertion at the next engine entry.  Compiled out under NDEBUG.
 */
#ifndef NDEBUG
#include <assert.h>
#define OP_ENTER(op) assert(!(op)->active && "session/ re-entrancy (D-GEN-8)")
#define OP_CB_BEGIN(op) ((op)->active = 1)
#define OP_CB_END(op) ((op)->active = 0)
#else
#define OP_ENTER(op) ((void)0)
#define OP_CB_BEGIN(op) ((void)0)
#define OP_CB_END(op) ((void)0)
#endif

/* ---- lifecycle --------------------------------------------------------- */

static void
op_clear(struct gy_op *op)
{
    gy_secure_zero(op->rec, sizeof(op->rec));
    gy_secure_zero(op->sess, sizeof(op->sess));
    gy_secure_zero(op->defer, sizeof(op->defer));
    gy_secure_zero(op->scratch, sizeof(op->scratch));
    op->n_defer = 0;
    op->active = 0;
}

int
gy_op_begin(struct gy_op *op, const struct gy_store *store)
{
    if (op == NULL || store == NULL)
        return GY_ERR_ARG;
    op_clear(op);
    op->store = store;
    return GY_OK;
}

void
gy_op_abort(struct gy_op *op)
{
    if (op != NULL)
        op_clear(op);
}

/* ---- record loads ------------------------------------------------------ */

/*
 * Read-your-writes: a load consults the stage before the store.  A record
 * already staged for STORE in this op is returned instead of the committed
 * copy, and a record staged for deletion shadows the store as "not found".
 * This lets lifecycle operations compose within one uncommitted transaction
 * (e.g. conditional-update stages a new DeviceRecord, then a session insert
 * must see it), which the store callbacks alone could not provide since they
 * only ever reach committed state.  Returns 1 if the stage answered (out_len
 * set), 0 if the caller should fall through to the store.
 */
static int
stage_lookup(struct gy_op *op, enum gy_rec_kind kind, const uint8_t *id,
             size_t id_len, size_t *out_len)
{
    size_t i;

    if (kind == GY_REC_SESSION) {
        for (i = 0; i < GY_OP_MAX_SESSIONS; i++) {
            struct gy_op_sess *e = &op->sess[i];

            if (e->in_use &&
                gy_const_memcmp(e->id, id, GY_SESSION_ID_LEN) == 0) {
                memcpy(op->scratch, e->blob, e->blob_len);
                *out_len = e->blob_len;
                return 1;
            }
        }
    } else {
        for (i = 0; i < GY_OP_MAX_RECORDS; i++) {
            struct gy_op_rec *r = &op->rec[i];

            if (r->in_use && r->kind == (uint8_t)kind && r->id_len == id_len &&
                gy_const_memcmp(r->id, id, id_len) == 0) {
                memcpy(op->scratch, r->blob, r->blob_len);
                *out_len = r->blob_len;
                return 1;
            }
        }
    }
    for (i = 0; i < op->n_defer; i++) {
        struct gy_op_defer *d = &op->defer[i];

        if (d->action == GY_OP_DELETE_RECORD && d->kind == (uint8_t)kind &&
            d->id_len == id_len && gy_const_memcmp(d->id, id, id_len) == 0) {
            *out_len = 0; /* staged deletion shadows the store */
            return 1;
        }
    }
    return 0;
}

static int
op_load(struct gy_op *op, enum gy_rec_kind kind, const uint8_t *id,
        size_t id_len, size_t *out_len)
{
    int rc;

    if (stage_lookup(op, kind, id, id_len, out_len))
        return GY_OK;

    OP_CB_BEGIN(op);
    rc = op->store->load_record(op->store->ctx, kind, id, id_len, op->scratch,
                                sizeof(op->scratch), out_len);
    OP_CB_END(op);
    return rc;
}

int
gy_op_load_user(struct gy_op *op, const uint8_t *id, size_t id_len,
                struct gy_user_record *out, int *found)
{
    size_t n = 0;
    int rc;

    if (op == NULL || id == NULL || out == NULL || found == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    *found = 0;
    rc = op_load(op, GY_REC_USER, id, id_len, &n);
    if (rc != GY_OK)
        return rc;
    if (n == 0)
        return GY_OK;
    rc = gy_user_record_decode(out, op->scratch, n);
    if (rc != GY_OK)
        return rc;
    *found = 1;
    return GY_OK;
}

int
gy_op_load_device(struct gy_op *op, const uint8_t *id, size_t id_len,
                  struct gy_device_record *out, int *found)
{
    size_t n = 0;
    int rc;

    if (op == NULL || id == NULL || out == NULL || found == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    *found = 0;
    rc = op_load(op, GY_REC_DEVICE, id, id_len, &n);
    if (rc != GY_OK)
        return rc;
    if (n == 0)
        return GY_OK;
    rc = gy_device_record_decode(out, op->scratch, n);
    if (rc != GY_OK)
        return rc;
    *found = 1;
    return GY_OK;
}

int
gy_op_load_session(struct gy_op *op, const uint8_t id[GY_SESSION_ID_LEN],
                   struct gy_session *out, int *found)
{
    size_t n = 0;
    int rc;

    if (op == NULL || id == NULL || out == NULL || found == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    *found = 0;
    rc = op_load(op, GY_REC_SESSION, id, GY_SESSION_ID_LEN, &n);
    if (rc != GY_OK)
        return rc;
    if (n == 0)
        return GY_OK;
    rc = gy_session_decode(out, op->scratch, n);
    if (rc != GY_OK)
        return rc;
    *found = 1;
    return GY_OK;
}

/* ---- record stages ----------------------------------------------------- */

static struct gy_op_rec *
rec_slot(struct gy_op *op, uint8_t kind, const uint8_t *id, size_t id_len)
{
    struct gy_op_rec *avail = NULL;
    size_t i;

    for (i = 0; i < GY_OP_MAX_RECORDS; i++) {
        struct gy_op_rec *r = &op->rec[i];

        if (r->in_use) {
            if (r->kind == kind && r->id_len == id_len &&
                gy_const_memcmp(r->id, id, id_len) == 0)
                return r;
        } else if (avail == NULL) {
            avail = r;
        }
    }
    return avail;
}

static int
put_rec(struct gy_op *op, enum gy_rec_kind kind, const uint8_t *id,
        size_t id_len, const uint8_t *blob, size_t blob_len)
{
    struct gy_op_rec *r = rec_slot(op, (uint8_t)kind, id, id_len);

    if (r == NULL)
        return GY_ERR_STATE; /* staging area full */
    r->kind = (uint8_t)kind;
    r->id_len = id_len;
    memcpy(r->id, id, id_len);
    memcpy(r->blob, blob, blob_len);
    r->blob_len = blob_len;
    r->in_use = 1;
    return GY_OK;
}

int
gy_op_put_user(struct gy_op *op, const struct gy_user_record *u)
{
    uint8_t blob[GY_USER_BLOB_MAX];
    size_t n;
    int rc;

    if (op == NULL || u == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    rc = gy_user_record_encode(blob, sizeof(blob), &n, u);
    if (rc != GY_OK)
        return rc;
    return put_rec(op, GY_REC_USER, u->user_id, u->user_id_len, blob, n);
}

int
gy_op_put_device(struct gy_op *op, const struct gy_device_record *d,
                 const uint8_t *key, size_t key_len)
{
    uint8_t blob[GY_DEVICE_BLOB_MAX];
    size_t n;
    int rc;

    if (op == NULL || d == NULL || key == NULL)
        return GY_ERR_ARG;
    if (key_len == 0 || key_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    OP_ENTER(op);
    rc = gy_device_record_encode(blob, sizeof(blob), &n, d);
    if (rc != GY_OK)
        return rc;
    return put_rec(op, GY_REC_DEVICE, key, key_len, blob, n);
}

int
gy_op_put_session(struct gy_op *op, const struct gy_session *s)
{
    struct gy_op_sess *slot = NULL;
    size_t i;
    int rc;

    if (op == NULL || s == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    for (i = 0; i < GY_OP_MAX_SESSIONS; i++) {
        struct gy_op_sess *e = &op->sess[i];

        if (e->in_use) {
            if (gy_const_memcmp(e->id, s->id, GY_SESSION_ID_LEN) == 0) {
                slot = e;
                break;
            }
        } else if (slot == NULL) {
            slot = e;
        }
    }
    if (slot == NULL)
        return GY_ERR_STATE;

    rc = gy_session_encode(slot->blob, sizeof(slot->blob), &slot->blob_len, s);
    if (rc != GY_OK)
        return rc;
    memcpy(slot->id, s->id, GY_SESSION_ID_LEN);
    slot->in_use = 1;
    return GY_OK;
}

/* ---- deferred actions -------------------------------------------------- */

int
gy_op_delete(struct gy_op *op, enum gy_rec_kind kind, const uint8_t *id,
             size_t id_len)
{
    struct gy_op_defer *d;

    if (op == NULL || id == NULL)
        return GY_ERR_ARG;
    if (id_len == 0 || id_len > GY_DEVICE_ID_MAX)
        return GY_ERR_ARG;
    OP_ENTER(op);
    if (op->n_defer >= GY_OP_MAX_DEFER)
        return GY_ERR_STATE;
    d = &op->defer[op->n_defer++];
    d->action = GY_OP_DELETE_RECORD;
    d->kind = (uint8_t)kind;
    d->id_len = id_len;
    memcpy(d->id, id, id_len);
    return GY_OK;
}

int
gy_op_consume_opk(struct gy_op *op, uint32_t pkid)
{
    struct gy_op_defer *d;

    if (op == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    if (op->n_defer >= GY_OP_MAX_DEFER)
        return GY_ERR_STATE;
    d = &op->defer[op->n_defer++];
    d->action = GY_OP_CONSUME_OPK;
    d->pkid = pkid;
    return GY_OK;
}

/* ---- commit ------------------------------------------------------------ */

int
gy_op_commit(struct gy_op *op)
{
    const struct gy_store *st;
    size_t i;
    int rc;

    if (op == NULL)
        return GY_ERR_ARG;
    OP_ENTER(op);
    st = op->store;

    /* Phase one: all record STOREs (users/devices, then sessions). */
    for (i = 0; i < GY_OP_MAX_RECORDS; i++) {
        struct gy_op_rec *r = &op->rec[i];

        if (!r->in_use)
            continue;
        OP_CB_BEGIN(op);
        rc = st->store_record(st->ctx, r->kind, r->id, r->id_len, r->blob,
                              r->blob_len);
        OP_CB_END(op);
        if (rc != GY_OK) {
            gy_op_abort(op);
            return rc;
        }
    }
    for (i = 0; i < GY_OP_MAX_SESSIONS; i++) {
        struct gy_op_sess *e = &op->sess[i];

        if (!e->in_use)
            continue;
        OP_CB_BEGIN(op);
        rc = st->store_record(st->ctx, GY_REC_SESSION, e->id, GY_SESSION_ID_LEN,
                              e->blob, e->blob_len);
        OP_CB_END(op);
        if (rc != GY_OK) {
            gy_op_abort(op);
            return rc;
        }
    }

    /* Phase two: deferred deletions and OPK consumptions, in list order. */
    for (i = 0; i < op->n_defer; i++) {
        struct gy_op_defer *d = &op->defer[i];

        OP_CB_BEGIN(op);
        if (d->action == GY_OP_DELETE_RECORD)
            rc = st->delete_record(st->ctx, d->kind, d->id, d->id_len);
        else
            rc = st->consume_opk(st->ctx, d->pkid);
        OP_CB_END(op);
        if (rc != GY_OK) {
            gy_op_abort(op);
            return rc;
        }
    }

    gy_op_abort(op);
    return GY_OK;
}
