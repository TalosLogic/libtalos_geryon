/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * IPC protocol for the geryon GROUP end-to-end example.  Reuses the messaging
 * demo's frame header (struct demo_frame_header) and length-framed IPC
 * (demo_ipc.c) verbatim; only the message-type values are group-specific, and
 * they start well above enum demo_msg_type so the two never collide even though
 * both ride the same demo_frame_header.type field.
 *
 * The coordinator plays TWO untrusted roles: the group SERVER (it holds the
 * ServerSecretParams via geryon_group_server and answers the section 8.1 RPCs)
 * and the RELAY (it forwards opaque member<->member pairwise-session bytes, the
 * GROUP_KEY_DISTRIBUTION envelopes and the fanned-out group message, without
 * parsing them).  Members address each other by logical name ("m1".."m5"); the
 * 16-byte protocol UID each member uses in the group API is separate (grp_uid).
 */

#ifndef GERYON_GROUP_DEMO_PROTO_H
#define GERYON_GROUP_DEMO_PROTO_H

#include <stddef.h>
#include <stdint.h>

#include "demo_proto.h" /* struct demo_frame_header, DEMO_NAME_MAX, payload cap */

/* Membership: a founder plus four members exercises every role transition
 * (full members, an invited-then-joined member, and a deletion). */
#define GRP_NMEMBERS 5

/*
 * Device ids.  Every member's primary device is A.  One member (see
 * GRP_MD_MEMBER) additionally runs a SECOND device, B, under the SAME 16-byte
 * member UID: group membership is per account, message delivery is per device.
 * A device id is a single byte here; the value is the contract shared by the
 * driver, the members, and the coordinator's relay.
 */
#define GRP_DEV_A 0x01
#define GRP_DEV_B 0x02

/*
 * Multi-device topology.  Member GRP_MD_MEMBER (m2, index 1) runs a SECOND
 * device on top of its primary: a separate process, a distinct device id
 * (GRP_DEV_B), the SAME 16-byte member UID, and its own relay endpoint
 * "m2b".  So there are GRP_NPROC processes: the GRP_NMEMBERS members plus the
 * one companion at process index GRP_MD_COMPANION_PROC.  The companion joins the
 * messaging mesh and receives group messages; it performs no KVAC credential or
 * roster operation, so the roster still holds one entry for m2's UID.  A real
 * app learns a peer's device set from the server (the Sesame device list); the
 * demo fixes it here so every party agrees without a discovery round trip.
 */
#define GRP_MD_MEMBER 1
#define GRP_NPROC (GRP_NMEMBERS + 1)
#define GRP_MD_COMPANION_PROC GRP_NMEMBERS
#define GRP_MD_COMPANION_NAME "m2b"

/*
 * Identity-key change (Sesame 3.2 replacement).  Member GRP_MD_REKEY_MEMBER (m3)
 * reinstalls in place near the end of the run: same account UID and same device
 * id, but a freshly generated identity key (the real trigger is an app reinstall
 * or a restore where the device slot is stable but the keystore was regenerated,
 * NOT a brand-new device, which would be a new device id).  The founder detects
 * the changed key on its next handshake (GY_ERR_KEY_CHANGED), re-verifies the
 * safety number, and re-accepts (gy_accept_identity).
 */
#define GRP_MD_REKEY_MEMBER 2

/* The 16-byte group/messaging UID for member index i (0..GRP_NMEMBERS-1):
 * a fixed, app-assigned account id (byte0 'M', byte1 the 1-based index). */
static inline void
grp_uid(int i, uint8_t out[16])
{
    size_t k;
    for (k = 0; k < 16; k++)
        out[k] = 0;
    out[0] = 'M';
    out[1] = (uint8_t)(i + 1);
}

/* Member roles in the lifecycle. */
#define GRP_ROLE_FOUNDER 0 /* m1: creates the group, is the admin */
#define GRP_ROLE_MEMBER 1  /* m2..m5 */

enum grp_msg_type {
    /* Liveness + teardown (skeleton bring-up). */
    GRP_MSG_PING = 100,
    GRP_MSG_PONG,
    GRP_MSG_GOODBYE,

    /* N-party phase barrier: every member sends it and blocks; the coordinator
     * releases all of them (reply GRP_MSG_SRV_REPLY) once all have arrived, so
     * the roster is in a known state before the next phase asserts on it. */
    GRP_MSG_BARRIER,

    /* Messaging directory (one-shot bundle publish/fetch, for the pairwise
     * session mesh). */
    GRP_MSG_PUBLISH_BUNDLE, /* member -> coord: my one-shot bundle for `to` */
    GRP_MSG_FETCH_BUNDLE,   /* member -> coord: give me `to`'s bundle */
    GRP_MSG_BUNDLE,         /* coord -> member: the requested bundle */

    /* Pairwise-session relay (opaque ciphertext bytes, coord never parses). */
    GRP_MSG_RELAY,   /* member -> coord: deliver payload to `to` */
    GRP_MSG_DELIVER, /* coord -> member: a relayed payload from `from` */
    GRP_MSG_NO_MAIL, /* coord -> member: nothing queued */
    GRP_MSG_RECV,    /* member -> coord: give me my next relayed message */

    /* Group-server RPCs (member -> coord; reply GRP_MSG_SRV_REPLY / _SRV_FAIL).
     * Payloads are the opaque group wire objects the public API emits/consumes;
     * the coordinator stores this group's public key (from GRP_MSG_SRV_REGISTER)
     * so the verify/add RPCs carry only a presentation. */
    GRP_MSG_SRV_PUBLIC,        /* -> ServerPublicParams */
    GRP_MSG_SRV_REGISTER,      /* founder: group public params (A,B) */
    GRP_MSG_SRV_ISSUE_AUTH,    /* uid(16) || date(8 BE) -> auth response */
    GRP_MSG_SRV_BLIND_ISSUE,   /* uid(16) || len16 commit || request -> resp */
    GRP_MSG_SRV_VERIFY_AUTH,   /* auth presentation -> ok */
    GRP_MSG_SRV_ADD_MEMBER,    /* pk presentation -> upsert (uid_ct, pk_ct) */
    GRP_MSG_SRV_ADD_INVITED,   /* uid_ct -> invited roster entry */
    GRP_MSG_SRV_DELETE_MEMBER, /* uid_ct -> remove roster entry */
    GRP_MSG_SRV_FETCH_MEMBERS, /* -> member-list wire */
    GRP_MSG_SRV_REPLY,         /* coord -> member: RPC result payload */
    GRP_MSG_SRV_FAIL           /* coord -> member: RPC rejected */
};

#endif /* GERYON_GROUP_DEMO_PROTO_H */
