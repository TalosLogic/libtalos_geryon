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

#define AS_MAX 32     /* record slots (users + devices + sessions) */
#define AS_BLOB 32768 /* per-record blob capacity (holds a grown skip store) */
/* Identity slot capacity: the custodian's bootstrap header plus sealed
 * identity/prekey material; comfortably above
 * custodian.h's GY_CUST_BLOB_MAX (~12.5KB), not tied to that internal
 * constant since apistore stays within include/geryon.h only. */
#define AS_IDENTITY_BLOB 16384

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
