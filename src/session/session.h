/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_SESSION_H
#define GY_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "ratchet.h"

/*
 * Sesame record model (the Sesame specification, sections 2.2/3.1/3.2,
 * D-SES-3/4/5/11).  This is the first Layer 4 module: the data everything
 * else in session/ operates on.  Per D-SES-11 the store has three separately
 * keyed opaque blob types rather than one nested record:
 *
 *   - SessionRecord (gy_session), keyed by SessionID.  Carries the Double
 *     Ratchet state plus session metadata.
 *   - DeviceRecord (gy_device_record), keyed by DeviceID.  Carries the peer
 *     device identity and an ORDERED list of its SessionIDs (active first,
 *     then inactive in list order), NOT the sessions themselves.
 *   - UserRecord (gy_user_record), keyed by UserID.  Carries an ordered list
 *     of its DeviceIDs.
 *
 * Keeping sessions out of the DeviceRecord is what makes close-and-resume
 * persistence practical: a ratchet step rewrites one small session blob, not
 * a multi-megabyte device blob (D-SES-11 rationale).  Everything is
 * fixed-capacity and sized by the GY_*_MAX suite maxima, so future-suite rows
 * fit without a layout change.  Records cross the store boundary only
 * as the versioned opaque blobs produced by the encode/decode pairs below;
 * the blob format is private and subject to change until v1.0 (D-GEN-1).
 */

/* SessionID: first 4 bytes of the base-key hash (D-SES-3), a local-only id. */
#define GY_SESSION_ID_LEN 4

/* Storage bounds (D-SES-4). */
#define GY_SESSION_INACTIVE_MAX 40 /* inactive sessions per DeviceRecord */
#define GY_DEVICE_MAX 32           /* devices per UserRecord */

/* Opaque application identifiers, bounded (D-SES-1); 1-byte length prefixed. */
#define GY_USER_ID_MAX 64
#define GY_DEVICE_ID_MAX 64

/*
 * DeviceRecord store-key length (D-SES-12): a DeviceRecord is keyed by the
 * (UserID, DeviceID) PAIR, not by DeviceID alone, so two peers that supply the
 * same DeviceID byte string cannot collide.  The key is a fixed 64-byte,
 * domain-separated SHA-512 of the length-prefixed pair (gy_devrec_key).  64 ==
 * GY_DEVICE_ID_MAX, so it fits every DeviceID-sized store buffer.
 */
#define GY_DEVKEY_LEN 64

/* Blob format version byte (private; D-GEN-1 principles). */
#define GY_REC_FMT_V1 0x01

/*
 * Upper bounds on the encoded blob length for each record type, so callers
 * stack-size an output buffer.  The SessionRecord bound is dominated by the
 * D-DR-8 worst-case skip store (GY_MAX_SKIP entries + epoch slots); a live
 * session serializes only its populated portion, so real blobs are far
 * smaller (D-SES-11).
 */
#define GY_SESSION_BLOB_MAX 90000
#define GY_DEVICE_BLOB_MAX 512
#define GY_USER_BLOB_MAX 2304

/*
 * A session: the Double Ratchet state plus metadata.  `base` is the full
 * suite hash over suite_id || EncodeEC(IK_A) || EncodeEC(EK_A) (base_len =
 * desc->hash_len), retained for base-key dedupe on the receive path
 * (D-SES-6.1); `id` is its first GY_SESSION_ID_LEN bytes (D-SES-3).  The
 * timestamps and counters are the D-SES-7 expiration inputs (populated by
 * later tickets; zero here).  pq_pending is the peer
 * PQ-authentication state, reserved zero.  `ad` is the fixed X3DH
 * associated data (Encode(IK_A) || Encode(IK_B), D-X3DH-6), computed once at
 * handshake and replayed as AD_session into every gy_dr_encrypt/decrypt on
 * this session; ad_len is desc-dependent (<= GY_X3DH_AD_MAX).
 */
struct gy_session {
    struct gy_dr_state dr;
    uint8_t id[GY_SESSION_ID_LEN];
    uint8_t base_len;
    uint8_t base[GY_HASH_MAX];
    uint8_t pq_pending;
    uint8_t ad_len;
    uint8_t ad[GY_X3DH_AD_MAX];
    uint64_t created_at;
    uint64_t activated_at;
    uint64_t last_recv_at;
    uint32_t nsend;
    uint32_t nrecv;
};

/*
 * A peer device record: identity plus an ordered SessionID list.  The active
 * session (if any) is `active`; `inactive[0 .. n_inactive)` are the inactive
 * sessions with index 0 the most recently active (D-SES-5 head).  stale /
 * stale_at are the D-SES-7 stale-record markers.  Sessions themselves live in
 * their own blobs keyed by these SessionIDs (D-SES-11).
 */
struct gy_device_record {
    uint8_t suite_id;
    uint8_t device_id_len;
    uint8_t device_id[GY_DEVICE_ID_MAX];
    struct gy_public_key ik;
    uint8_t fp_len;
    uint8_t fingerprint[GY_HASH_MAX];
    uint8_t has_active;
    uint8_t active[GY_SESSION_ID_LEN];
    uint32_t n_inactive;
    uint8_t inactive[GY_SESSION_INACTIVE_MAX][GY_SESSION_ID_LEN];
    uint8_t stale;
    uint64_t stale_at;
};

/*
 * A user record: an ordered DeviceID index.  Order is insertion order
 * (index 0 oldest), so device eviction picks the oldest stale device
 * (D-SES-4).  `device_stale` mirrors each DeviceRecord's stale flag so the
 * eviction decision needs no DeviceRecord load.
 */
struct gy_user_record {
    uint8_t suite_id;
    uint8_t user_id_len;
    uint8_t user_id[GY_USER_ID_MAX];
    uint32_t n_devices;
    uint8_t device_id[GY_DEVICE_MAX][GY_DEVICE_ID_MAX];
    uint8_t device_id_len[GY_DEVICE_MAX];
    uint8_t device_stale[GY_DEVICE_MAX];
    uint8_t stale;
};

/* ---- SessionID and session serialization ------------------------------- */

/*
 * Compute a session's base hash and SessionID (D-SES-3) from the creating
 * handshake's initiator keys, writing both into *s (does not touch dr).
 * ik_a/ek_a must carry the pinned suite's curve_type.  Returns GY_OK,
 * GY_ERR_STATE on a cross-suite key, or a negative GY_ERR_* from encoding or
 * hashing.
 */
int gy_session_id(struct gy_session *s, const struct gy_suite_desc *desc,
                  const struct gy_public_key *ik_a,
                  const struct gy_public_key *ek_a);

/*
 * Encode a session as a versioned blob into out (cap >= GY_SESSION_BLOB_MAX
 * is always sufficient), storing the length in *outlen.  Only the live
 * portion of the skip store is written; the epoch table is written as a
 * sparse list of live slots so the D-DR-17 (hk, n) slot indices survive the
 * round trip.  Returns GY_OK or GY_ERR_ARG on a short buffer.
 */
int gy_session_encode(uint8_t *out, size_t cap, size_t *outlen,
                      const struct gy_session *s);

/*
 * Decode a session blob (inverse of gy_session_encode).  Zeroizes *s first,
 * re-binds dr.desc from the embedded suite_id, and rejects an unknown suite,
 * a bad format/reserved byte, an out-of-range capacity, or a truncated blob.
 * Returns GY_OK or a negative GY_ERR_*.
 */
int gy_session_decode(struct gy_session *s, const uint8_t *in, size_t len);

/* Zeroize all session key material (teardown / eviction). */
void gy_session_free(struct gy_session *s);

/* ---- DeviceRecord ------------------------------------------------------- */

/*
 * Derive a DeviceRecord's store key from the (UserID, DeviceID) pair (D-SES-12):
 * out = SHA-512("geryon-devrec-key" || be32(user_id_len) || user_id ||
 * be32(device_id_len) || device_id), GY_DEVKEY_LEN (64) bytes.  Unconditional
 * SHA-512 (suite-independent): a store key needs only collision resistance, and
 * one hash keeps the key a uniform 64 bytes across suites.  The be32 length
 * prefixes disambiguate the variable-length pair.  Returns GY_OK or GY_ERR_ARG.
 */
int gy_devrec_key(const uint8_t *user_id, size_t user_id_len,
                  const uint8_t *device_id, size_t device_id_len,
                  uint8_t out[GY_DEVKEY_LEN]);

/*
 * Initialize a DeviceRecord with the peer identity and an empty SessionID
 * list.  device_id_len <= GY_DEVICE_ID_MAX and fp_len <= GY_HASH_MAX; a
 * NULL/oversize argument leaves *d zeroized and returns GY_ERR_ARG.
 */
int gy_device_record_init(struct gy_device_record *d, uint8_t suite_id,
                          const uint8_t *device_id, size_t device_id_len,
                          const struct gy_public_key *ik,
                          const uint8_t *fingerprint, size_t fp_len);

/*
 * Insert a new session id as the active session (D-SES-5): the previous
 * active (if any) is pushed to the inactive head; if that overflows
 * GY_SESSION_INACTIVE_MAX the tail id is evicted, written to evicted[] and
 * *did_evict set to 1 (else 0).  Returns GY_ERR_STATE if id already appears
 * in the record (SessionID collision, D-SES-3).
 */
int gy_device_session_insert(struct gy_device_record *d,
                             const uint8_t id[GY_SESSION_ID_LEN],
                             uint8_t evicted[GY_SESSION_ID_LEN],
                             int *did_evict);

/*
 * Move an inactive session to active (D-SES-5 activate-on-decrypt): the
 * previous active is pushed to the inactive head, id is removed from the
 * inactive list and becomes active.  Returns GY_ERR_STATE if id is not an
 * inactive session of this record.
 */
int gy_device_session_activate(struct gy_device_record *d,
                               const uint8_t id[GY_SESSION_ID_LEN]);

int gy_device_record_encode(uint8_t *out, size_t cap, size_t *outlen,
                            const struct gy_device_record *d);
int gy_device_record_decode(struct gy_device_record *d, const uint8_t *in,
                            size_t len);
void gy_device_record_free(struct gy_device_record *d);

/* ---- UserRecord --------------------------------------------------------- */

/*
 * Initialize a UserRecord with an empty device index.  user_id_len <=
 * GY_USER_ID_MAX; a NULL/oversize argument leaves *u zeroized and returns
 * GY_ERR_ARG.
 */
int gy_user_record_init(struct gy_user_record *u, uint8_t suite_id,
                        const uint8_t *user_id, size_t user_id_len);

/*
 * Append a DeviceID to the index.  At capacity, the oldest stale device is
 * evicted (its id written to out_evicted[]/ *out_evicted_len, *did_evict = 1);
 * if no device is stale the record is full and GY_ERR_STATE is returned
 * (D-SES-4).  A duplicate DeviceID returns GY_ERR_STATE.
 */
int gy_user_device_insert(struct gy_user_record *u, const uint8_t *device_id,
                          size_t device_id_len,
                          uint8_t out_evicted[GY_DEVICE_ID_MAX],
                          size_t *out_evicted_len, int *did_evict);

/*
 * Mark an indexed device stale (mirrors its DeviceRecord stale flag so
 * eviction can choose without a load).  Returns GY_ERR_STATE if the DeviceID
 * is not in the index.
 */
int gy_user_device_mark_stale(struct gy_user_record *u,
                              const uint8_t *device_id, size_t device_id_len);

/*
 * Return the index of a DeviceID in the ordered device list, or -1 if absent.
 * A cheap membership test for the lifecycle conditional update (D-SES-9).
 */
int gy_user_device_index(const struct gy_user_record *u,
                         const uint8_t *device_id, size_t device_id_len);

/*
 * Remove a DeviceID from the index (compromise recovery / device deletion,
 * D-SES-2).  Later devices shift down to keep insertion order.  Returns
 * GY_ERR_STATE if the DeviceID is not in the index.
 */
int gy_user_device_remove(struct gy_user_record *u, const uint8_t *device_id,
                          size_t device_id_len);

int gy_user_record_encode(uint8_t *out, size_t cap, size_t *outlen,
                          const struct gy_user_record *u);
int gy_user_record_decode(struct gy_user_record *u, const uint8_t *in,
                          size_t len);
void gy_user_record_free(struct gy_user_record *u);

#endif /* GY_SESSION_H */
