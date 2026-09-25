/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_QSPGS_STORE_H
#define GY_QSPGS_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "qspgs_keys.h" /* GY_QSPGS_MASTER_KEY_MAX / _SKB_MAX / _VKB_MAX */
#include "qspgs_wire.h" /* GY_QSPGS_GID_LEN */

/*
 * QSPGS persistence callbacks (QSPGS_SPEC.md section 9), the quantum-safe
 * analogue of the classical group's gy_group_store bridge (D-GRP-7).
 * gy_qspgs_store is the internal keyed-blob trio the *_stored
 * wrappers below write through; it never goes in the messaging custodian's
 * sealed idmat (which would put a group-vertical key inside the frozen custody
 * struct).  In production the public facade (geryon_qspgs.h) binds this trio to
 * the custodian's EXISTING record store under a reserved kind band, so QSPGS
 * records seal under the custodian KEK alongside identity/prekey/session
 * records, EXACTLY as the classical group vertical does (custody-hosted
 * storage, superseding the earlier separate app-store posture; recorded in the
 * D-QGS register).  Unit tests bind the trio to an in-memory mock instead.
 *
 * Either backing keeps the D-CUST-1 boundary: the *_stored wrappers hand the
 * store PLAINTEXT record bytes and receive plaintext back; the sealing (the
 * custodian KEK in production, none in the test mock) is the store's job, not
 * these wrappers'.
 *
 * Secrets at rest (nothing derived is stored; uk / acq / expKey / ek / rrs /
 * rho are all recomputed on demand, and skpsdn is NEVER stored, section 2.2):
 *   - muk: the per-user main key (2*kappa).  Root of the user hierarchy.
 *   - skbase (with vkbase): the KR-ML-DSA base pair, one per hybrid identity,
 *     independent of muk (section 2.1).
 *   - gk: the per-group key (2*kappa), refreshed on major version.
 *
 * FORMAT VERSIONING lives per-record inside the stored blob, as it does for the
 * classical vertical (gy_group_format_version_load): a leading format_version
 * byte the loader checks against a supported window.  QSPGS is new, so there is
 * nothing to migrate; the window opens at 1.
 *
 * Conventions (mirroring gy_group_store / gy_store): every callback returns
 * GY_OK or a negative GY_ERR_*, and any negative aborts the operation.  A load
 * of an ABSENT record returns GY_OK with *out_len == 0 (a stored blob is never
 * zero-length), treated as "not found", not an error.  ctx is passed back
 * unchanged.  Record keys: the per-user records key on the self-UID, the
 * per-group record on the 16-byte GID (a suite-hash, D-SES-3 style).
 *
 * The key hierarchy froze the record-kind enum and the callback
 * shape; the *_stored wrappers that read and write through it
 * (declared below) landed with the storage layer (D-QGS-8), the
 * same way gy_group_create_stored et al. landed after the
 * classical key hierarchy.
 */

enum gy_qspgs_rec_kind {
    GY_QREC_MUK = 1,       /* key = self-UID: the main user key (2*kappa). */
    GY_QREC_BASE_KEY = 2,  /* key = self-UID: skbase || vkbase. */
    GY_QREC_GROUP_KEY = 3, /* key = GID: the group key gk (2*kappa). */
    GY_QREC_ACQUAINTANCE =
        4,                 /* key = granter-UID: ep || vkbase || acq || uk. */
    GY_QREC_JOIN_LINK = 5, /* key = GID: the static join-link secret jls. */
    GY_QREC_GROUP_KEY_PENDING =
        6 /* key = GID: a gk staged by a rotating edit, promoted to
           * GY_QREC_GROUP_KEY on commit (SEC-v1.5.0 LOW-4). */
};

struct gy_qspgs_store {
    void *ctx;

    /*
     * Load the record (kind, id[0..id_len)) into out (cap bytes), writing its
     * length to *out_len.  An absent record is GY_OK with *out_len 0.  A record
     * that does not fit cap returns GY_ERR_TOOLONG.
     */
    int (*load)(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
                size_t id_len, uint8_t *out, size_t cap, size_t *out_len);
    /* Store (overwrite) the record (kind, id[0..id_len)) = blob[0..blob_len). */
    int (*store)(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
                 size_t id_len, const uint8_t *blob, size_t blob_len);
    /* Remove the record (kind, id[0..id_len)); removing an absent record is
     * GY_OK (idempotent). */
    int (*remove)(void *ctx, enum gy_qspgs_rec_kind kind, const uint8_t *id,
                  size_t id_len);
};

/* ---- stored-record wrappers (D-QGS-8) ------------------
 *
 * The *_stored wrappers over the trio above, the QSPGS analogue of
 * gy_group_create_stored et al.  Every persisted record is
 *   ver(1) || format_version(2, BE) || payload
 * so a corrupted, truncated, or version-flipped blob is rejected on load
 * (GY_ERR_VERIFY), never fed to a key schedule.  The record version byte is
 * frozen from the first storage KATs; the format_version is the QSPGS
 * capability epoch, minted at GY_QSPGS_FORMAT_VERSION and refused outside the
 * supported window.  Only the three at-rest secrets (muk, skbase || vkbase, gk)
 * are ever written; every derived secret is rederived on load (D-GRP-7), and
 * skpsdn / the sk_r blob NEVER touch storage (section 2.2, task 2).  Each
 * wrapper zeroizes its transient blob before returning.  A non-hybrid suite_id
 * is GY_ERR_ARG; an absent record on load is GY_ERR_NOT_FOUND.
 */

#define GY_QSPGS_REC_VERSION 0x01 /* record blob version byte. */

/*
 * The record's format_version is the SAME QSPGS capability epoch the wire header
 * carries (GY_QSPGS_FORMAT_VERSION and the [MIN, MAX] window, defined once in
 * qspgs_wire.h, D-QGS-12): a group's at-rest epoch and its on-wire epoch are one
 * value.  A record is stamped at GY_QSPGS_FORMAT_VERSION and carries the epoch as
 * a 2-byte big-endian header field.
 */

/* Record header: ver(1) || format_version(2, BE). */
#define GY_QSPGS_REC_HDR_LEN 3

/* Largest record blob: BASE_KEY = header || skbase || vkbase. */
#define GY_QSPGS_REC_BLOB_MAX                                                  \
    (GY_QSPGS_REC_HDR_LEN + GY_QSPGS_SKB_MAX + GY_QSPGS_VKB_MAX)

/*
 * MUK record (key = self-UID, uid[0..uid_len), exactly GY_QSPGS_UID_LEN): store /
 * load the per-user main key muk (gy_qspgs_master_key_len(suite_id) bytes).
 * The load out buffer is cap bytes; *out_len receives the key length.
 */
int gy_qspgs_muk_store(const struct gy_qspgs_store *store, uint8_t suite_id,
                       const uint8_t *uid, size_t uid_len, const uint8_t *muk);
int gy_qspgs_muk_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                      const uint8_t *uid, size_t uid_len, uint8_t *out,
                      size_t cap, size_t *out_len);

/*
 * BASE_KEY record (key = self-UID): store / load the KR-ML-DSA base pair as
 * skbase || vkbase (gy_qspgs_base_skb_len / _base_vkb_len bytes).  On load,
 * out_skb receives skbase (size to GY_QSPGS_SKB_MAX) and out_vkb receives vkbase
 * (size to GY_QSPGS_VKB_MAX).
 */
int gy_qspgs_base_key_store(const struct gy_qspgs_store *store,
                            uint8_t suite_id, const uint8_t *uid,
                            size_t uid_len, const uint8_t *skb,
                            const uint8_t *vkb);
int gy_qspgs_base_key_load(const struct gy_qspgs_store *store, uint8_t suite_id,
                           const uint8_t *uid, size_t uid_len, uint8_t *out_skb,
                           uint8_t *out_vkb);

/*
 * GROUP_KEY record (key = GID, the 16-byte suite-hash group id): store / load
 * the per-group key gk (gy_qspgs_master_key_len(suite_id) bytes).
 */
int gy_qspgs_group_key_store(const struct gy_qspgs_store *store,
                             uint8_t suite_id,
                             const uint8_t gid[GY_QSPGS_GID_LEN],
                             const uint8_t *gk);
int gy_qspgs_group_key_load(const struct gy_qspgs_store *store,
                            uint8_t suite_id,
                            const uint8_t gid[GY_QSPGS_GID_LEN], uint8_t *out,
                            size_t cap, size_t *out_len);

/*
 * Staged GROUP_KEY (SEC-v1.5.0 LOW-4): a rotating edit (RemoveMember,
 * RotateGroupKey, RevokeInvitation, or a Consolidate that folds a leave) mints a
 * fresh gk that only becomes correct once the server accepts the new core.  The
 * edit STAGES it here instead of overwriting the current gk, so a server
 * rejection leaves the current gk intact (no admin self-lockout).  This mirrors
 * the messaging send path's stage-then-commit-on-accept discipline (D-SES-10).
 *   _stage:    write gk to the pending slot (GY_ERR_STATE if one already exists
 *              for this gid, so an unresolved edit is resolved before another).
 *   _commit:   promote the pending gk to the current GROUP_KEY and drop the
 *              pending slot (GY_ERR_NOT_FOUND if nothing is staged).  The old gk
 *              is superseded here, once the rotation is confirmed (spec 9).
 *   _rollback: drop the pending slot; the current gk is unchanged.  Idempotent
 *              (a missing pending slot is GY_OK).
 */
int gy_qspgs_group_key_stage(const struct gy_qspgs_store *store,
                             uint8_t suite_id,
                             const uint8_t gid[GY_QSPGS_GID_LEN],
                             const uint8_t *gk);
int gy_qspgs_group_key_commit(const struct gy_qspgs_store *store,
                              uint8_t suite_id,
                              const uint8_t gid[GY_QSPGS_GID_LEN]);
int gy_qspgs_group_key_rollback(const struct gy_qspgs_store *store,
                                const uint8_t gid[GY_QSPGS_GID_LEN]);

/*
 * ACQUAINTANCE record (key = the GRANTER's UID, exactly GY_QSPGS_UID_LEN): store /
 * load the attested acquaintance material a member accepts via
 * GrantAcquaintance (section 2.2, 7.2) and later needs to attribute and add
 * that user.  Stored as ep(BE64) || vkbase(tier VKB) || acq(2*kappa) ||
 * uk(2*kappa); vkbase is the granter's base verification key, acq its
 * acquaintance tag (both from the verified registration record), and uk the
 * granter's group user key it conveyed over the pairwise channel (D-QGS-13 E4:
 * kept so IsCorrectUserKey can re-check acq == KDF(uk)).  On load, out_vkb
 * receives vkbase (size to GY_QSPGS_VKB_MAX), out_acq the acq tag and out_uk the
 * user key (each size to GY_QSPGS_MASTER_KEY_MAX), and *out_ep the epoch.
 */
int gy_qspgs_acquaintance_store(const struct gy_qspgs_store *store,
                                uint8_t suite_id, const uint8_t *uid,
                                size_t uid_len, const uint8_t *vkb,
                                const uint8_t *acq, const uint8_t *uk,
                                uint64_t ep);
int gy_qspgs_acquaintance_load(const struct gy_qspgs_store *store,
                               uint8_t suite_id, const uint8_t *uid,
                               size_t uid_len, uint8_t *out_vkb,
                               uint8_t *out_acq, uint8_t *out_uk,
                               uint64_t *out_ep);

/*
 * JOIN_LINK record (key = GID, the 16-byte suite-hash group id): store / load /
 * delete the static join-link secret jls (GY_QSPGS_JOINLINK_SECRET bytes).  It
 * is the ONE at-rest secret outside the "only muk, base pair, gk" set (D-QGS-8,
 * section 9): the join link must survive group-key rotation (App. B.8), so the
 * creator-admin keeps jls to re-seal (gk_new, fet_new) into the rotated core's
 * slot rather than mint a fresh secret.  Sealed under the custodian KEK like
 * every other record and zeroized after use.  toggle_join_link writes it, the
 * disable path removes it, and gy_qspgs_group_delete_stored removes it with gk.
 */
int gy_qspgs_joinlink_secret_store(const struct gy_qspgs_store *store,
                                   const uint8_t gid[GY_QSPGS_GID_LEN],
                                   const uint8_t *jls);
int gy_qspgs_joinlink_secret_load(const struct gy_qspgs_store *store,
                                  const uint8_t gid[GY_QSPGS_GID_LEN],
                                  uint8_t *out, size_t cap, size_t *out_len);
int gy_qspgs_joinlink_secret_delete(const struct gy_qspgs_store *store,
                                    const uint8_t gid[GY_QSPGS_GID_LEN]);

/*
 * Format-version window (mirroring gy_group_format_version_load): read the
 * format_version a record was filed under, without touching its secret payload.
 * kind selects the record and id[0..id_len) its key.  GY_ERR_NOT_FOUND if
 * absent, GY_ERR_VERIFY on a malformed header.
 */
int gy_qspgs_format_version_load(const struct gy_qspgs_store *store,
                                 enum gy_qspgs_rec_kind kind, const uint8_t *id,
                                 size_t id_len, uint16_t *out_version);

/*
 * Remove a user's at-rest records (MUK and BASE_KEY) keyed on uid.  Idempotent
 * (a missing record is GY_OK); base and muk are independent (section 2.1), so
 * either removal order is orphan-free.
 */
int gy_qspgs_user_delete_stored(const struct gy_qspgs_store *store,
                                const uint8_t *uid, size_t uid_len);

/* Remove a group's GROUP_KEY and JOIN_LINK records keyed on gid.  Idempotent. */
int gy_qspgs_group_delete_stored(const struct gy_qspgs_store *store,
                                 const uint8_t gid[GY_QSPGS_GID_LEN]);

/* ---- rederive-only open (D-GRP-7) ---------------------- */

struct gy_qspgs_member_ctx; /* qspgs_ops.h */

/*
 * Open a member context for group gid straight from the store, the QSPGS
 * analogue of gy_group_load (load the key at rest, REDERIVE everything else).
 * Loads only the two at-rest secrets a member needs - gk (the GROUP_KEY record,
 * keyed on gid) and the member's own base pair skbase || vkbase (the BASE_KEY
 * record, keyed on uid) - then rederives the whole working set (ek, rrs, rho,
 * skpsdn, and the member's own vkr) via gy_qspgs_member_ctx_open.  NOTHING
 * derived is ever read from storage (D-GRP-7); the transient gk / skbase buffers
 * are zeroized before returning.  On GY_OK the caller clears ctx with
 * gy_qspgs_member_ctx_clear.  GY_ERR_NOT_FOUND if either record is absent,
 * GY_ERR_ARG on bad input, otherwise a negative GY_ERR_* from the derivation.
 */
int gy_qspgs_member_ctx_open_stored(struct gy_qspgs_member_ctx *ctx,
                                    const struct gy_qspgs_store *store,
                                    uint8_t suite_id,
                                    const uint8_t gid[GY_QSPGS_GID_LEN],
                                    const uint8_t *uid, size_t uidlen);

#endif /* GY_QSPGS_STORE_H */
