/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_LIFECYCLE_H
#define GY_LIFECYCLE_H

#include <stddef.h>
#include <stdint.h>

#include "store.h"

/*
 * Sesame lifecycle state machine (the Sesame specification, section 3.2/4.2,
 * D-SES-2/5/7/9, D-X3DH-11).  These operations sit on top of the record model
 * (session.h) and the transactional staging engine (store.h): each one loads
 * what it needs through a gy_op, mutates records in memory, and stages the
 * results, leaving the single commit point to the caller (except gy_delete_user,
 * which spans more state than one transaction can hold and drives its own
 * commits, noted below).  Nothing here owns a clock (D-SES-7): wall time enters
 * only as an argument the application sources from its own clock callback.
 */

/* ---- session expiration (D-SES-7, section 4.2) ------------------------- */

/*
 * Expiration policy.  `enabled` is 0 until gy_expiry_cfg_init succeeds, and
 * expiration is fully OFF while disabled (D-SES-7: off until configured).
 * max_send / max_recv are the section 4.2 counter bounds; max_latency is the
 * section 3.1 stale-record window.  The library owns none of these values.
 */
struct gy_expiry_cfg {
    uint8_t enabled;
    uint32_t max_send;
    uint32_t max_recv;
    uint64_t max_latency;
};

/*
 * Configure expiration, validating the section 4.2 inequality
 * max_recv > max_send + 2 * max_latency (D-SES-7).  On violation, or a zero
 * bound, *cfg is left disabled and GY_ERR_ARG is returned; on success `enabled`
 * is set.  The 2 * max_latency term is computed in 64-bit to avoid overflow.
 */
int gy_expiry_cfg_init(struct gy_expiry_cfg *cfg, uint32_t max_send,
                       uint32_t max_recv, uint64_t max_latency);

/* Turn expiration off (the default state of a zeroed cfg). */
void gy_expiry_cfg_disable(struct gy_expiry_cfg *cfg);

/*
 * A session is expired once it has sent max_send or received max_recv messages
 * (D-SES-7).  Expiry is driven by the monotone send/recv counters, never wall
 * time, so a clock rollback cannot resurrect an expired session (acceptance
 * criterion).  Returns 1 if expired, 0 if not (or if expiration is disabled).
 */
int gy_session_expired(const struct gy_expiry_cfg *cfg,
                       const struct gy_session *s);

/*
 * A session's record is stale once `now` is more than max_latency past its
 * last receive (section 3.1); `now` comes from the application clock.  Returns
 * 1 if stale, 0 if not (or if expiration is disabled, or last_recv_at is 0).
 */
int gy_session_stale(const struct gy_expiry_cfg *cfg,
                     const struct gy_session *s, uint64_t now);

/*
 * Session-layer re-export of the identity fingerprint (D-X3DH-11): the suite
 * hash over EncodeEC(ik), written as desc->hash_len bytes to out.  Lets Layer 5
 * proto/ surface a fingerprint without reaching into kex/ itself.  Returns
 * GY_OK or a negative GY_ERR_*.
 */
int gy_identity_fingerprint(const struct gy_suite_desc *desc, uint8_t *out,
                            const struct gy_public_key *ik);

/* ---- identity-key conditional update (section 3.2, D-SES-9) ------------ */

/*
 * The old/new identity fingerprints surfaced when a conditional update would
 * replace an established identity key (D-X3DH-11).  fp_len is desc->hash_len.
 */
struct gy_key_change {
    size_t fp_len;
    uint8_t old_fp[GY_HASH_MAX];
    uint8_t new_fp[GY_HASH_MAX];
};

/*
 * Conditional update (section 3.2): create-or-update the UserRecord and
 * DeviceRecord for (user_id, device_id) from a fetched bundle's identity key.
 *
 *   - Unknown DeviceID: trust-on-first-use.  A DeviceRecord is created for ik
 *     and the DeviceID appended to the UserRecord (itself created if unknown).
 *   - Known DeviceID, same identity key: no change of identity; records are
 *     re-staged unchanged.
 *   - Known DeviceID, DIFFERENT identity key: fail closed (D-SES-9).  *chg is
 *     filled with the old and new fingerprints and GY_ERR_KEY_CHANGED is
 *     returned with ZERO state staged; the caller must run gy_accept_key_change
 *     to proceed.
 *
 * On success the (new or unchanged) records are staged; the caller commits.
 * chg may be NULL if the caller does not want the fingerprints.  A device
 * eviction from a full UserRecord (D-SES-4) is staged as part of the update.
 */
int gy_conditional_update(struct gy_op *op, uint8_t suite_id,
                          const uint8_t *user_id, size_t user_id_len,
                          const uint8_t *device_id, size_t device_id_len,
                          const struct gy_public_key *ik,
                          struct gy_key_change *chg);

/*
 * Explicitly accept a peer identity-key change (section 3.2 replacement,
 * D-SES-9): the DeviceRecord's identity key is replaced with ik and ALL of its
 * sessions are deleted (deferred), converging on the new key.  The DeviceID and
 * its place in the UserRecord are preserved.  Returns GY_ERR_STATE if the
 * DeviceRecord does not exist.  Stages the results; the caller commits.
 */
int gy_accept_key_change(struct gy_op *op, uint8_t suite_id,
                         const uint8_t *user_id, size_t user_id_len,
                         const uint8_t *device_id, size_t device_id_len,
                         const struct gy_public_key *ik);

/* ---- session insert / activate through the engine (D-SES-5) ------------ */

/*
 * Insert a new session id as the active session of a DeviceRecord (D-SES-5),
 * loading the record, applying gy_device_session_insert, and staging it.  A
 * session evicted from the inactive tail has its SessionRecord deferred for
 * deletion.  Returns GY_ERR_STATE if the DeviceRecord does not exist or the id
 * already appears in it.  Stages the results; the caller commits.
 */
int gy_device_insert_session(struct gy_op *op, const uint8_t *user_id,
                             size_t user_id_len, const uint8_t *device_id,
                             size_t device_id_len,
                             const uint8_t id[GY_SESSION_ID_LEN]);

/*
 * Activate an inactive session of a DeviceRecord (D-SES-5 activate-on-decrypt),
 * loading the record, applying gy_device_session_activate, and staging it.
 * Returns GY_ERR_STATE if the DeviceRecord does not exist or id is not one of
 * its inactive sessions.  Stages the result; the caller commits.
 */
int gy_device_activate_session(struct gy_op *op, const uint8_t *user_id,
                               size_t user_id_len, const uint8_t *device_id,
                               size_t device_id_len,
                               const uint8_t id[GY_SESSION_ID_LEN]);

/* ---- device / user deletion (compromise recovery, D-SES-2) ------------- */

/*
 * Delete a single device: defer-delete every one of its SessionRecords and its
 * DeviceRecord, and remove the DeviceID from its UserRecord (staged).  All
 * deletions zeroize (D-SES-2).  Absent records are a no-op (idempotent delete).
 * Fits in one transaction; the caller commits.
 */
int gy_delete_device(struct gy_op *op, const uint8_t *user_id,
                     size_t user_id_len, const uint8_t *device_id,
                     size_t device_id_len);

/*
 * Delete an entire user: every device (sessions + record), then the UserRecord
 * (D-SES-2).  This spans more state than one gy_op can stage, so it drives its
 * own transactions: one commit per device, then a final commit for the
 * UserRecord.  A failure aborts the in-flight transaction and returns; devices
 * already committed stay deleted (each device deletion is independently
 * consistent).  op is reused as scratch and must be caller-allocated.
 */
int gy_delete_user(const struct gy_store *store, struct gy_op *op,
                   const uint8_t *user_id, size_t user_id_len);

#endif /* GY_LIFECYCLE_H */
