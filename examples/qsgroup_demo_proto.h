/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * IPC protocol for the geryon QUANTUM-SAFE GROUP (QSPGS) end-to-end example.
 * Reuses the messaging demo's frame header (struct demo_frame_header) and
 * length-framed IPC (demo_ipc.c) verbatim; only the message-type values are
 * QSPGS-specific, and they start well above enum demo_msg_type and the
 * classical enum grp_msg_type so nothing collides on demo_frame_header.type.
 *
 * The coordinator plays two untrusted roles: the QSPGS SERVER (an opaque
 * object store that, once the lifecycle lands, runs the section-7.3 acceptance
 * checks of geryon_qsgroups_server.h before accepting a core / appendix write)
 * and the RELAY (it forwards opaque member<->member bytes - one-shot messaging
 * bundles for the pairwise session mesh, then the group-key delivery envelopes
 * - which it never parses).  Members address each other by logical name
 * ("m1".."mN"); the variable-length QSPGS UID each member uses in the group API
 * is separate (qsg_uid).
 */

#ifndef GERYON_QSGROUP_DEMO_PROTO_H
#define GERYON_QSGROUP_DEMO_PROTO_H

#include <stddef.h>
#include <stdint.h>
#include <string.h> /* memset, for the fixed-width qsg_uid */

/* GY_QSGROUP_UID_LEN (the fixed UID width used by qsg_uid) and the other shared
 * QSPGS wire constants.  The server header is the minimal public surface that
 * defines them (guarded), so this shared demo header is self-contained in every
 * TU that includes it (client, coordinator, and the driver), regardless of
 * which side's fuller public header the includer also pulls in. */
#include "geryon_qsgroups_server.h"

#include "demo_proto.h" /* struct demo_frame_header, DEMO_NAME_MAX, payload cap */

/* Membership: a founder plus four members, mirroring the classical group_demo's
 * five-member roster, so the worked example exercises create, invite/approve,
 * admin promotion, removal + group-key rotation, and a message fan-out. */
#define QSG_NMEMBERS 5
#define QSG_NPROC QSG_NMEMBERS

/* Member roles in the lifecycle. */
#define QSG_ROLE_FOUNDER 0 /* m1: creates the group, is the admin */
#define QSG_ROLE_MEMBER 1  /* m2..mN */

/* Mutation-phase targets (0-based member indices): the founder promotes m2 to
 * admin (SetAdmin) and removes m4 (RemoveMember + group-key rotation). */
#define QSG_PROMOTED_MEMBER 1 /* m2 */
#define QSG_REMOVED_MEMBER 3  /* m4 */

/* Group message fan-out: the founder sends this many messages ("g1".."gN") to
 * each surviving member over its pairwise session; each recipient confirms it
 * receives that many distinct, valid messages. */
#define QSG_FANOUT_MSGS 3

/* Late-phase per-member checks (0-based indices, both survivors): m3 records a
 * non-admin appendix line; m5 closes and reopens its custodian to prove the
 * sealed group state persists. */
#define QSG_APPENDIX_MEMBER 2 /* m3 */
#define QSG_REOPEN_MEMBER 4   /* m5 */

/* Core-edit operation kind carried on the SUBMIT_CORE wire (section 7.3 item 1,
 * D-QGS-13 E2): the client names its operation so the coordinator can hand the
 * right vk-lst rule to gy_qsgroups_server_core_check.  These MIRROR the library
 * GY_QSGROUP_OP_* values (geryon_qsgroups_server.h); the coordinator passes the
 * wire byte straight through, so the numeric values must match. */
#define QSG_OP_CREATE 0
#define QSG_OP_UNCHANGED 1
#define QSG_OP_APPEND_ONE 2
#define QSG_OP_REPLACE 3

/* QSPGS UIDs are a fixed width (SEC-v1.5.0 LOW-2; GY_QSGROUP_UID_LEN, from the
 * public geryon_qspgs.h / geryon_qsgroups_server.h), so the demo assigns each
 * member a GY_QSGROUP_UID_LEN-byte account id.  A real application hashes its
 * native account id to this width; the demo just tags 'Q' || (1-based index)
 * and zero-pads the rest.  Returns the length (GY_QSGROUP_UID_LEN). */
static inline size_t
qsg_uid(int i, uint8_t out[GY_QSGROUP_UID_LEN])
{
    memset(out, 0, GY_QSGROUP_UID_LEN);
    out[0] = 'Q';
    out[1] = (uint8_t)(i + 1);
    return GY_QSGROUP_UID_LEN;
}

enum qsg_msg_type {
    /* Liveness + teardown (skeleton bring-up). */
    QSG_MSG_PING = 200,
    QSG_MSG_PONG,
    QSG_MSG_GOODBYE,

    /* N-party phase barrier: every member sends it and blocks; the coordinator
     * releases all (reply QSG_MSG_SRV_REPLY) once all have arrived, so state is
     * known before the next phase asserts on it. */
    QSG_MSG_BARRIER,

    /* Messaging directory + relay (the pairwise M0-M7 session mesh that
     * delivers the group key to added members).  Opaque bytes; the coordinator
     * never parses a bundle or a ciphertext. */
    QSG_MSG_PUBLISH_BUNDLE, /* member -> coord: my one-shot bundle for `to` */
    QSG_MSG_FETCH_BUNDLE,   /* member -> coord: give me `to`'s bundle */
    QSG_MSG_BUNDLE,         /* coord -> member: the requested bundle */
    QSG_MSG_RELAY,          /* member -> coord: deliver payload to `to` */
    QSG_MSG_DELIVER,        /* coord -> member: a relayed payload from `from` */
    QSG_MSG_NO_MAIL,        /* coord -> member: nothing queued */
    QSG_MSG_RECV, /* member -> coord: give me my next relayed message */

    /* QSPGS SERVER RPCs (member -> coord; reply QSG_MSG_SRV_REPLY / _SRV_FAIL).
     * The coordinator is the untrusted server: it stores the registration
     * records and the group core, serving them back, and runs the section-7.3
     * acceptance checks (geryon_qsgroups_server.h) on a core write and a fetch.
     * All lengths below are big-endian.
     *
     *   REGISTER:     uid_len(1) || uid || acct                     -> store
     *   FETCH_ACCT:   uid_len(1) || uid                    -> acct (or empty)
     *   PUBLISH_ID:   uid_len(1) || uid || clen(2)||curve || mlen(2)||mldsa
     *   FETCH_ID:     uid_len(1) || uid  -> clen(2)||curve || mlen(2)||mldsa
     *   SUBMIT_CORE:  gid(16) || new_vmaj(4) || new_vmin(4) || ext_vmaj(4) ||
     *                 ext_vmin(4) || vkr_len(2)||vkr || 4x (len(4)||object)
     *                 [header, member-list, vk-lst, core-sig] ||
     *                 fet(GY_QSGROUP_FET_LEN)
     *                 -> coordinator runs version_check + core_check, stores the
     *                    four objects and (separately, SEC-v1.5.0 LOW-1) fet,
     *                    which it never serves back; SRV_FAIL if a check rejects.
     *   FETCH_CORE:   gid(16) || token(GY_QSGROUP_FET_LEN)
     *                 -> coordinator runs fetch_check, then serves
     *                    4x (len(4)||object); SRV_FAIL on a bad token / unknown.
     *   DEPOSIT_INV:  gid(16) || uid_len(1)||uid || entry  -> gid's invite queue
     *                 (the coordinator never opens an entry; it is sealed to the
     *                 group-wide join key).
     *   FETCH_INV:    gid(16) || uid_len(1)||uid  -> the invitee's queued entry;
     *                 SRV_FAIL if none is queued.
     *   SUBMIT_APX:   gid(16) || newcomer(1) || vkr_len(2)||vkr ||
     *                 obj_len(4)||single-line-appendix-object
     *                 -> coordinator runs apx_check (against the stored vk-lst
     *                    for an existing author, or as a newcomer for a JOIN /
     *                    UserAdd line), then appends the line to gid's stored
     *                    appendix; SRV_FAIL if the check rejects.  A SUBMIT_CORE
     *                    that advances the version clears the stored appendix
     *                    (its lines were folded into the new core).
     *   FETCH_APX:    gid(16) -> the accumulated multi-line appendix object
     *                 (an empty reply when the group has no pending lines).
     */
    QSG_MSG_SRV_REGISTER,
    QSG_MSG_SRV_FETCH_ACCT,
    QSG_MSG_SRV_PUBLISH_ID,
    QSG_MSG_SRV_FETCH_ID,
    QSG_MSG_SRV_SUBMIT_CORE,
    QSG_MSG_SRV_FETCH_CORE,
    QSG_MSG_SRV_DEPOSIT_INVITE,
    QSG_MSG_SRV_FETCH_INVITE,
    QSG_MSG_SRV_SUBMIT_APPENDIX,
    QSG_MSG_SRV_FETCH_APPENDIX,
    QSG_MSG_SRV_REPLY, /* coord -> member: result payload (may be empty) */
    QSG_MSG_SRV_FAIL   /* coord -> member: request rejected */
};

#endif /* GERYON_QSGROUP_DEMO_PROTO_H */
