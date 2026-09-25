/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_GROUP_WIRE_H
#define GY_GROUP_WIRE_H

#include <stddef.h>
#include <stdint.h>

#include "group_tier.h"

/*
 * The GROUP_SPEC section 9 item 3 object header shared by every top-level
 * client-server group object: object-type byte || group-wire-version byte ||
 * compact suite_id tag.  The header is identification only; cryptographic suite
 * binding lives in the KDF and Fiat-Shamir transcript (section 2.1), never in
 * this incidental wire structure.  Nested objects (e.g. a MAC tag inside a
 * credential response) are untagged and do not use this header.
 *
 * The object-type registry is frozen at first published KATs (the section 2.2
 * label-registry rule); later versions append, never renumber.
 */

#define GY_GROUP_WIRE_VERSION 0x01
#define GY_GROUP_OBJ_HDR_LEN 3

/* Object-type registry (section 9 item 3).  The algebraic-MAC layer
 * defines the one top-level object; the credential layers append below. */
#define GY_GOBJ_SERVER_PUBLIC                                                  \
    0x01 /* ServerPublicParams iparams (section 4.2) */
#define GY_GOBJ_AUTH_RESPONSE 0x02 /* AuthCredentialResponse (section 5.1) */
#define GY_GOBJ_AUTH_PRESENTATION                                              \
    0x03 /* AuthCredentialPresentation (section 5.2.1) */
#define GY_GOBJ_PK_PRESENTATION                                                \
    0x04 /* ProfileKeyCredentialPresentation (section 5.2.2) */
/* Blind issuance (section 3.3 / 5.3, and the ProfileKeyVersion). */
#define GY_GOBJ_PK_COMMITMENT 0x05 /* ProfileKeyCommitment (section 3.3) */
#define GY_GOBJ_PK_REQUEST                                                     \
    0x06 /* ProfileKeyCredentialRequest (section 3.3 / 5.3) */
#define GY_GOBJ_PK_RESPONSE                                                    \
    0x07 /* ProfileKeyCredentialResponse (section 3.3 / 5.3) */
#define GY_GOBJ_PK_VERSION 0x08 /* ProfileKeyVersion (section 3.3, grp-pkv) */
/* The FetchGroupMembers list (section 7.7 / 9 item 2). */
#define GY_GOBJ_MEMBER_LIST                                                    \
    0x09 /* member-entry list (the ONE var-length obj) */
/* The group public key (section 3.4): exported by the founder for
 * the server to verify presentations against this group. */
#define GY_GOBJ_GROUP_PUBLIC 0x0A /* GroupPublicParams (A, B) (section 3.4) */

/*
 * Write the 3-byte object header for obj_type on tier into out (cap >=
 * GY_GROUP_OBJ_HDR_LEN).  Returns GY_OK or GY_ERR_TOOLONG.
 */
int gy_group_obj_put_header(const struct gy_group_tier *tier, uint8_t obj_type,
                            uint8_t *out, size_t cap);

/*
 * Validate that in[0..GY_GROUP_OBJ_HDR_LEN) is the header for obj_type on tier
 * (len must be at least GY_GROUP_OBJ_HDR_LEN).  Returns GY_OK on a match,
 * GY_ERR_VERIFY on any mismatch, or GY_ERR_ARG on bad input.
 */
int gy_group_obj_check_header(const struct gy_group_tier *tier,
                              uint8_t obj_type, const uint8_t *in, size_t len);

/* ------------------------------------------------------------------------- *
 * GROUP_KEY_DISTRIBUTION (GROUP_SPEC section 9 item 4, D-GRP-6): the ONE piece
 * of group data that crosses a pairwise M0-M7 session.  It is a D-GEN-1 typed
 * envelope (GY_WIRE_VERSION || suite_id || msg_type || payload), msg_type 0x03,
 * whose payload is the group format version (BE16) followed by the
 * GroupMasterKey (tier->master_key_len bytes), nothing else.  The version rides
 * here so a joining member learns the group's capability epoch from the same
 * trusted message that carries the key.  It shares the D-GEN-1 msg_type
 * byte-space with the messaging
 * envelope (0x01 INIT, 0x02 DR, session/recv.h) but is framed and validated
 * HERE in the group vertical (Path A): the messaging codec
 * (proto/envelope.c) stays group-unaware and correctly rejects 0x03 as a
 * reserved msg_type.  The application demultiplexes on the msg_type byte and
 * decides when to send / whether to accept (D-SES-1); the receiver rederives
 * GroupSecretParams / GroupPublicParams from the key (section 10).  0x03 is
 * reserved against messaging reuse by a note in session/recv.h.
 * ------------------------------------------------------------------------- */

#define GY_MSG_GROUP_KEY_DISTRIBUTION 0x03
/* D-GEN-1 envelope header: version || suite || msg_type. */
#define GY_GROUP_ENVELOPE_HDR_LEN 3
/* Payload prefix before the GroupMasterKey: the format version (BE16). */
#define GY_GROUP_ENVELOPE_FMTVER_LEN 2

/*
 * Frame master_key[0..mk_len) (mk_len MUST equal tier->master_key_len) as a
 * GROUP_KEY_DISTRIBUTION envelope into out (cap >= GY_GROUP_ENVELOPE_HDR_LEN +
 * GY_GROUP_ENVELOPE_FMTVER_LEN + tier->master_key_len).  format_version is
 * written BE16 ahead of the key.  Returns GY_OK and sets *outlen, GY_ERR_TOOLONG
 * on a short buffer, or GY_ERR_ARG on bad input.
 */
int gy_group_key_distribution_encode(const struct gy_group_tier *tier,
                                     uint16_t format_version,
                                     const uint8_t *master_key, size_t mk_len,
                                     uint8_t *out, size_t cap, size_t *outlen);

/*
 * Strictly parse a GROUP_KEY_DISTRIBUTION frame in[0..len): the header must be
 * GY_WIRE_VERSION || tier->suite_id || GY_MSG_GROUP_KEY_DISTRIBUTION and the
 * total length must be EXACTLY GY_GROUP_ENVELOPE_HDR_LEN +
 * GY_GROUP_ENVELOPE_FMTVER_LEN + tier->master_key_len (trailing bytes rejected).
 * On success writes the format version to *out_format_version and the
 * GroupMasterKey to out_master_key (mk_cap >= tier->master_key_len) and sets
 * *out_mk_len.  The codec is policy-free: it returns whatever version the frame
 * carried; the caller decides whether that version is supported.  Returns GY_OK,
 * GY_ERR_VERIFY on any header or length mismatch, or GY_ERR_ARG on bad input.
 */
int gy_group_key_distribution_decode(const struct gy_group_tier *tier,
                                     const uint8_t *in, size_t len,
                                     uint16_t *out_format_version,
                                     uint8_t *out_master_key, size_t mk_cap,
                                     size_t *out_mk_len);

#endif /* GY_GROUP_WIRE_H */
