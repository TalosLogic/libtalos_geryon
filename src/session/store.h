/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_STORE_H
#define GY_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "session.h"

/*
 * Store callbacks and the transactional staging engine (D-SES-10).
 * Every session/ operation runs on a gy_op: it stages the records it creates
 * or modifies in memory and commits them through the application's store
 * callbacks at a single success point.  Any failure before commit zeroizes the
 * staged key material and touches the store not at all (the record-level
 * extension of commit-after-verify, D-DR-4).
 *
 * Commit order is pinned (D-SES-10, and D-SES-6.1 replay safety): all record
 * STOREs first (complete post-operation blobs), THEN the deferred actions
 * (record deletions and OPK consumptions).  A crash between the two phases
 * re-runs safely: an OPK left unconsumed is caught by base-key dedupe
 * (D-SES-6.1) and a record left undeleted is harmless and re-cleaned.
 *
 * The staging arena is part of the gy_op struct: no dynamic allocation, a
 * compile-time-bounded footprint (the _Static_assert below ties the session
 * slot count to the D-SES-4 fan-out bound).  gy_op is large (it reserves
 * worst-case session blobs) and must be heap- or statically allocated by the
 * caller, never placed on the stack.
 */

/* Record blob kinds, keyed as noted (D-SES-11, D-SES-12). */
enum gy_rec_kind {
    GY_REC_USER = 1,   /* keyed by UserID */
    GY_REC_DEVICE = 2, /* keyed by the (UserID, DeviceID) hash, gy_devrec_key */
    GY_REC_SESSION = 3, /* keyed by SessionID (GY_SESSION_ID_LEN bytes) */
};

/* Prekey private-material kinds for the identity/prekey load callback. */
enum gy_prekey_kind {
    GY_PREKEY_SPK = 1,
    GY_PREKEY_OPK = 2,
};

/*
 * Application-supplied store.  All callbacks return GY_OK or a negative
 * GY_ERR_*; any negative return aborts the operation.  A load of an absent
 * record returns GY_OK with *out_len == 0 (a stored record blob is never
 * zero-length), which the engine treats as "not found", not an error.  The
 * identity and prekey blobs are opaque sealed material the application defines
 * (D-GEN-4 wrapping is the application's).  consume_opk marks a one-time
 * prekey used and is invoked ONLY at commit (D-X3DH-10).  ctx is passed back
 * to every callback unchanged.
 */
struct gy_store {
    void *ctx;

    int (*load_record)(void *ctx, enum gy_rec_kind kind, const uint8_t *id,
                       size_t id_len, uint8_t *out, size_t cap,
                       size_t *out_len);
    int (*store_record)(void *ctx, enum gy_rec_kind kind, const uint8_t *id,
                        size_t id_len, const uint8_t *blob, size_t blob_len);
    int (*delete_record)(void *ctx, enum gy_rec_kind kind, const uint8_t *id,
                         size_t id_len);

    int (*load_identity)(void *ctx, uint8_t *out, size_t cap, size_t *out_len);
    int (*store_identity)(void *ctx, const uint8_t *blob, size_t blob_len);
    int (*load_prekey)(void *ctx, enum gy_prekey_kind kind, uint32_t pkid,
                       uint8_t *out, size_t cap, size_t *out_len);
    int (*consume_opk)(void *ctx, uint32_t pkid);
};

/*
 * Staging capacities.  One operation touches at most a bounded set: the
 * fan-out send stages a user's DeviceRecords and one active session per
 * device (D-SES-4: 32 devices), plus a small margin for a new/initiating
 * session and the sender's own records.
 */
#define GY_OP_MAX_RECORDS 40  /* staged UserRecord + DeviceRecord slots */
#define GY_OP_MAX_SESSIONS 34 /* staged SessionRecord slots */
#define GY_OP_MAX_DEFER 64    /* deferred deletions + OPK consumptions */

_Static_assert(GY_OP_MAX_SESSIONS >= GY_DEVICE_MAX + 1,
               "session staging must cover a device fan-out (D-SES-4)");
/*
 * A single-device deletion defers every one of its sessions plus the device
 * record itself (D-SES-2 compromise recovery), so the defer arena must hold a
 * full device: 1 active + GY_SESSION_INACTIVE_MAX inactive + the record.
 */
_Static_assert(GY_OP_MAX_DEFER >= GY_SESSION_INACTIVE_MAX + 2,
               "defer arena must cover a full device deletion (D-SES-2)");

/* A staged UserRecord/DeviceRecord STORE (its complete post-operation blob). */
struct gy_op_rec {
    uint8_t in_use;
    uint8_t kind; /* enum gy_rec_kind */
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    size_t blob_len;
    uint8_t blob[GY_USER_BLOB_MAX]; /* the largest small-record blob */
};

/* A staged SessionRecord STORE (kept apart: its worst-case blob is large). */
struct gy_op_sess {
    uint8_t in_use;
    uint8_t id[GY_SESSION_ID_LEN];
    size_t blob_len;
    uint8_t blob[GY_SESSION_BLOB_MAX];
};

/* A deferred (phase-two) action. */
enum gy_op_defer_kind {
    GY_OP_DELETE_RECORD = 1,
    GY_OP_CONSUME_OPK = 2,
};

struct gy_op_defer {
    uint8_t action; /* enum gy_op_defer_kind */
    uint8_t kind;   /* enum gy_rec_kind, for GY_OP_DELETE_RECORD */
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    uint32_t pkid; /* for GY_OP_CONSUME_OPK */
};

/*
 * A staged operation.  Records and sessions accumulate as STOREs; deletions
 * and OPK consumptions accumulate in the deferred list; commit flushes them in
 * the pinned order.  `active` is the D-GEN-8 debug re-entrancy guard: it is set
 * while a store callback runs, so a callback that re-enters the engine on the
 * same gy_op trips the assertion at the next engine entry.
 */
struct gy_op {
    const struct gy_store *store;
    int active;
    struct gy_op_rec rec[GY_OP_MAX_RECORDS];
    struct gy_op_sess sess[GY_OP_MAX_SESSIONS];
    struct gy_op_defer defer[GY_OP_MAX_DEFER];
    size_t n_defer;
    uint8_t scratch[GY_SESSION_BLOB_MAX]; /* load/decode workspace */
};

/* Begin an operation against store, clearing any prior staging state. */
int gy_op_begin(struct gy_op *op, const struct gy_store *store);

/*
 * Load a record and decode it into *out.  On an absent record *found is 0 and
 * *out is untouched; on success *found is 1.  Returns GY_OK, a negative store
 * error, or a decode error (GY_ERR_ARG on a corrupt blob).
 */
int gy_op_load_user(struct gy_op *op, const uint8_t *id, size_t id_len,
                    struct gy_user_record *out, int *found);
int gy_op_load_device(struct gy_op *op, const uint8_t *id, size_t id_len,
                      struct gy_device_record *out, int *found);
int gy_op_load_session(struct gy_op *op, const uint8_t id[GY_SESSION_ID_LEN],
                       struct gy_session *out, int *found);

/*
 * Stage a record for STORE at commit (encodes the complete post-operation
 * blob now).  Re-staging the same id overwrites the earlier staged copy.
 * Returns GY_ERR_STATE if the staging area is full, or an encode error.
 */
int gy_op_put_user(struct gy_op *op, const struct gy_user_record *u);
/*
 * key/key_len is the DeviceRecord store key (gy_devrec_key over the record's
 * (UserID, DeviceID) pair, D-SES-12); the caller derives it since the pair's
 * UserID is not carried in the record.  Load and delete pass the same key as
 * the generic (id, id_len).
 */
int gy_op_put_device(struct gy_op *op, const struct gy_device_record *d,
                     const uint8_t *key, size_t key_len);
int gy_op_put_session(struct gy_op *op, const struct gy_session *s);

/* Defer a record deletion / an OPK consumption until the commit's phase two. */
int gy_op_delete(struct gy_op *op, enum gy_rec_kind kind, const uint8_t *id,
                 size_t id_len);
int gy_op_consume_opk(struct gy_op *op, uint32_t pkid);

/*
 * Commit: store every staged record (phase one), then run every deferred
 * action (phase two), in list order.  Stops at the first callback failure
 * (invoking nothing after it) and returns that error; on any exit, success or
 * failure, the staging area is zeroized.  A mid-commit failure may leave the
 * store partially written, but the pinned order keeps that state replay-safe
 * (D-SES-10 / D-SES-6.1).
 */
int gy_op_commit(struct gy_op *op);

/* Abort: zeroize the staging area, invoke no callback. */
void gy_op_abort(struct gy_op *op);

#endif /* GY_STORE_H */
