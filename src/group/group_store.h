/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_STORE_H
#define GY_GROUP_STORE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Group persistence callbacks (GROUP_SPEC section 10, D-GRP-7), GER-M8-09.
 *
 * A dedicated, minimal store for the group vertical: the group system is a
 * parallel vertical (D-GRP-2) over core/ + schnorr only, so it does NOT reuse
 * the messaging session/ `gy_store` (which would couple the vertical to Layer 4
 * and carry messaging-only callbacks).  The callback surface is exactly the
 * generic keyed-blob trio the group records need; there is no shared logic with
 * the messaging store, only a structurally similar signature shape.
 *
 * The library persists EXACTLY four record kinds, all secret or credential
 * material.  Membership state is NEVER stored by the library (D-GRP-7 item 2):
 * FetchGroupMembers returns a transient decrypted view, and any caching of it
 * is application territory.  Nothing DERIVED is stored either (D-GRP-7 item 1):
 * GroupSecretParams / GroupPublicParams are rederived from the GroupMasterKey on
 * demand, so the only per-group secret at rest is the GroupMasterKey.
 *
 * Blobs are OPAQUE and SEALED by the application (D-GEN-4: the
 * AEAD-under-stretched-key wrapping is the app's, exactly as for the messaging
 * identity/prekey blobs).  The library hands over and receives plaintext record
 * bytes; the app seals on store and unseals on load.
 *
 * Conventions (mirroring gy_store): every callback returns GY_OK or a negative
 * GY_ERR_*, and any negative aborts the operation.  A load of an ABSENT record
 * returns GY_OK with *out_len == 0 (a stored record blob is never zero-length),
 * which the caller treats as "not found", not an error.  ctx is passed back to
 * every callback unchanged.  Record keys are the local GroupID (16 bytes, a
 * suite-hash of suite_id || GroupPublicParams, D-SES-3 style) optionally
 * followed by a target UID for the per-UID ProfileKeyCredential.
 */

enum gy_group_rec_kind {
    GY_GREC_MASTER_KEY = 1, /* key = GroupID: the GroupMasterKey (2*kappa) */
    GY_GREC_AUTH_CRED = 2,  /* key = GroupID: own AuthCredential + redemption
                             * date */
    GY_GREC_PK_CRED = 3,    /* key = GroupID || target-UID: a target's
                             * ProfileKeyCredential */
    GY_GREC_OWN_PK = 4,     /* key = GroupID: the user's own ProfileKey */
};

struct gy_group_store {
    void *ctx;

    /*
     * Load the record (kind, id[0..id_len)) into out (cap bytes), writing its
     * length to *out_len.  An absent record is GY_OK with *out_len 0.  A record
     * that does not fit cap returns GY_ERR_TOOLONG.
     */
    int (*load)(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
                size_t id_len, uint8_t *out, size_t cap, size_t *out_len);
    /* Store (overwrite) the record (kind, id[0..id_len)) = blob[0..blob_len). */
    int (*store)(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
                 size_t id_len, const uint8_t *blob, size_t blob_len);
    /* Remove the record (kind, id[0..id_len)); removing an absent record is
     * GY_OK (idempotent). */
    int (*remove)(void *ctx, enum gy_group_rec_kind kind, const uint8_t *id,
                  size_t id_len);
};

#endif /* GY_GROUP_STORE_H */
