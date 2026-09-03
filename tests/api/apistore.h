/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Reference in-memory store for the public API integration tests.
 * Implements the geryon.h callback table with call recording, write
 * fault-injection, and a snapshot/restore facility for state-loss scenarios.
 * This is the first consumer of include/geryon.h other than an application.
 */

#ifndef GY_APISTORE_H
#define GY_APISTORE_H

#include <stddef.h>
#include <stdint.h>

#include "geryon.h"

#define AS_MAX 32 /* record slots (users + devices + sessions) */
/* Per-record and identity capacities come from the PUBLIC store-buffer bounds
 * (include/geryon.h), so apistore stays a pure public-API consumer yet is
 * correctly sized for every suite family.  The hybrid identity bound covers all
 * suites (classical included), so one reference store serves the whole matrix.
 */
#define AS_BLOB GY_STORE_RECORD_BLOB_MAX
#define AS_IDENTITY_BLOB GY_STORE_IDENTITY_BLOB_MAX_HYBRID

struct as_rec {
    int in_use;
    int kind;
    uint8_t id[GY_DEVICE_ID_MAX];
    size_t id_len;
    size_t blob_len;
    uint8_t blob[AS_BLOB];
};

struct apistore {
    struct as_rec recs[AS_MAX];
    uint8_t identity[AS_IDENTITY_BLOB];
    size_t identity_len;
    /* Call recording. */
    int n_store;
    int n_load;
    int n_delete;
    int n_consume;
    /* Write fault injection: fail the write callback whose index == fail_at. */
    int write_idx;
    int fail_at; /* -1 = never */
};

/* Bind s to a callback table (zeroes s, sets fail_at = -1). */
void as_bind(struct apistore *s, gy_store_callbacks *cb);

/* Deep copy for the state-loss scenarios. */
void as_snapshot(struct apistore *dst, const struct apistore *src);

/* Count live records of a kind (GY_RECORD_*). */
int as_count(const struct apistore *s, int kind);

/* Total live blob bytes across all records (store-growth invariant). */
size_t as_bytes(const struct apistore *s);

#endif /* GY_APISTORE_H */
