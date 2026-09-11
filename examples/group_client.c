/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * One group member: a gy_custodian (messaging identity over a sealed file
 * store) plus the gy_group client.  Drives the group lifecycle end to end,
 * talking to the coordinator (group server + relay) over one pipe pair.  This
 * stage brings up the pairwise session mesh and distributes the GroupMasterKey:
 * the founder creates the group and hands each member the key inside a real
 * M0-M7 pairwise session; the credential/roster/fanout flow follows.  Public
 * headers only.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "geryon.h"
#include "geryon_group.h"

#include "demo_ipc.h"
#include "filestore.h"
#include "group_client.h"
#include "group_demo_proto.h"

#define SECS_PER_DAY 86400ull

/*
 * The clock the library reads to learn the time.  Geryon never calls a system
 * clock itself (D-SES-7: time enters ONLY through this callback), so a consumer
 * wires it to whatever wall clock the app trusts.  This is the pattern to copy:
 * the app owns a small ctx and hands the library a pointer to it.
 *
 * Here the callback returns real POSIX time(2) (seconds since the Unix epoch)
 * plus a test-only offset.  In normal use the offset is 0, so the library sees
 * the true wall clock.  The daily-credential rotation check bumps the offset by
 * a day to move the clock forward without waiting; the callback still makes a
 * genuine time(2) call underneath.  A real app leaves the offset at 0 and can
 * drop the field entirely.
 */
struct demo_clock {
    uint64_t offset_secs;
};

static uint64_t
demo_clock_now(void *ctx)
{
    const struct demo_clock *dc = ctx;
    time_t t = time(NULL);
    uint64_t now = (t == (time_t)-1) ? 0 : (uint64_t)t;

    return now + (dc != NULL ? dc->offset_secs : 0);
}

/* Day-align a Unix timestamp.  Group AuthCredentials are issued for a whole UTC
 * day (spec-true daily model), so both issuance and presentation key on the day
 * containing "now". */
static uint64_t
day_of(uint64_t now)
{
    return (now / SECS_PER_DAY) * SECS_PER_DAY;
}

/* Device A: every member's primary device, and the founder's only device.  A
 * peer this demo addresses is on device A unless it is m2's companion (device
 * B); a message received from the founder is always from device A.  This
 * process's OWN device id comes from cfg->device_id (A for a primary, B for the
 * companion). */
static const uint8_t DEVICE_ID_A[1] = {GRP_DEV_A};
/* Device B: the companion device of member GRP_MD_MEMBER (m2). */
static const uint8_t DEVICE_ID_B[1] = {GRP_DEV_B};

/* Bounded poll wait for a reply (the 1:1 demo's wait_frame mechanism).  The
 * attempt count is larger here: multi-party barriers and the concurrent
 * per-member Argon2id at custodian creation can legitimately defer a reply
 * longer than the 2-party demo, and this stays above the coordinator's own
 * poll timeout so the client is never the first to give up.  Still bounded: no
 * hang. */
#define GRP_POLL_MS 50
#define GRP_POLL_ATTEMPTS 1200 /* ~60s, then fail */

/* The founder (m1) is index 0; m5 (index 4) is invited, never self-adds.  After
 * the founder invites m5 and deletes m4, the roster is m1/m2/m3 full + m5
 * invited: 3 full, 1 invited.  The fanout targets are the surviving non-founder
 * full members m2, m3. */
static const int FANOUT_TARGETS[2] = {1, 2};

/* The founder sends each target a chain of this many messages in one ratchet
 * chain; the coordinator delivers the chain reordered, so the receiver recovers
 * them via its skip store (the group analogue of the 1:1 demo's d1..d4). */
#define GRP_FANOUT_MSGS 4

static void
member_name(int idx, char *out, size_t cap)
{
    snprintf(out, cap, "m%d", idx + 1);
}

/* The relay endpoint (logical name) for one device of a member: the companion
 * device of GRP_MD_MEMBER lives at "m2b"; every other device is the member's
 * own "m<idx+1>". */
static void
endpoint_name(int member, const uint8_t *device_id, size_t device_id_len,
              char *out, size_t cap)
{
    if (member == GRP_MD_MEMBER && device_id_len == sizeof(DEVICE_ID_B) &&
        memcmp(device_id, DEVICE_ID_B, sizeof(DEVICE_ID_B)) == 0)
        snprintf(out, cap, "%s", GRP_MD_COMPANION_NAME);
    else
        member_name(member, out, cap);
}

static void
be64_put(uint8_t *p, uint64_t v)
{
    int i;
    for (i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xff);
        v >>= 8;
    }
}

/* A distinct 32-byte ProfileKey per member. */
static void
profile_key(int idx, uint8_t out[GY_GROUP_PROFILEKEY_BYTES])
{
    int i;
    for (i = 0; i < GY_GROUP_PROFILEKEY_BYTES; i++)
        out[i] = (uint8_t)(0x40 + idx * 8 + i);
}

/* ---- framed request/reply over the coordinator pipe --------------------- */

/*
 * Wait (bounded) for one frame, then read it.  Copied from the 1:1 demo's
 * wait_frame: poll with a per-attempt timeout, retry on EINTR, give up after
 * GRP_POLL_ATTEMPTS so a wedged peer can never hang the run.  This tolerates
 * the coordinator's DEFERRED replies (a FETCH_BUNDLE parks until the peer
 * publishes; a RECV parks until a message arrives) because the total bound is
 * generous, while still never blocking forever.
 */
static int
wait_frame(int rfd, struct demo_frame_header *hdr, uint8_t *buf, size_t cap)
{
    struct pollfd p;
    int attempts;

    p.fd = rfd;
    p.events = POLLIN;
    for (attempts = 0; attempts < GRP_POLL_ATTEMPTS; attempts++) {
        int rv = poll(&p, 1, GRP_POLL_MS);

        if (rv < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (rv == 0)
            continue; /* timeout: keep waiting, bounded */
        return demo_recv_frame(rfd, hdr, buf, cap) == DEMO_IPC_OK ? 0 : -1;
    }
    return -1; /* gave up: the expected reply never arrived */
}

/*
 * Send one framed request and wait (bounded, via poll) for exactly one reply.
 * rbuf (rcap) holds the reply payload; *rtype and *rlen describe it; rfrom
 * (>= DEMO_NAME_MAX), if non-NULL, receives the reply's logical sender.
 * Returns 0 or -1 on IPC error / timeout.
 */
static int
request(int rfd, int wfd, const char *from, const char *to,
        enum grp_msg_type type, const uint8_t *payload, size_t plen,
        uint32_t *rtype, uint8_t *rbuf, size_t rcap, size_t *rlen, char *rfrom)
{
    struct demo_frame_header h, rh;

    memset(&h, 0, sizeof(h));
    h.type = type;
    h.data_len = (uint32_t)plen;
    snprintf(h.from, sizeof(h.from), "%s", from);
    if (to != NULL)
        snprintf(h.to, sizeof(h.to), "%s", to);
    if (demo_send_frame(wfd, &h, plen ? payload : NULL) != DEMO_IPC_OK)
        return -1;
    if (wait_frame(rfd, &rh, rbuf, rcap) != 0)
        return -1;
    *rtype = rh.type;
    *rlen = rh.data_len;
    if (rfrom != NULL)
        snprintf(rfrom, DEMO_NAME_MAX, "%s", rh.from);
    return 0;
}

/* A server RPC that expects GRP_MSG_SRV_REPLY: copies the reply payload into
 * out (rcap), setting *outlen.  Returns 0 on REPLY, -1 on FAIL or IPC error. */
static int
srv_call(int rfd, int wfd, const char *from, enum grp_msg_type type,
         const uint8_t *payload, size_t plen, uint8_t *out, size_t rcap,
         size_t *outlen)
{
    uint32_t rtype;
    if (request(rfd, wfd, from, "coord", type, payload, plen, &rtype, out, rcap,
                outlen, NULL) != 0)
        return -1;
    return rtype == GRP_MSG_SRV_REPLY ? 0 : -1;
}

/* ---- setup -------------------------------------------------------------- */

static int
install_server_params(gy_custodian *c, const struct grp_client_cfg *cfg,
                      int rfd, int wfd)
{
    uint8_t buf[DEMO_MAX_PAYLOAD];
    size_t len = 0;

    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_PUBLIC, NULL, 0, buf,
                 sizeof(buf), &len) != 0)
        return -1;
    return gy_custodian_group_install_server_params(c, buf, len) == GY_OK ? 0
                                                                          : -1;
}

/* Founder: register this group's public key so the server can verify members'
 * presentations (the server holds no group secret; the public key is deployer
 * state). */
static int
register_group(gy_custodian *c, const struct grp_client_cfg *cfg,
               const uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd)
{
    uint8_t gp[256], ack[64];
    size_t gplen = sizeof(gp), alen = 0;

    if (gy_custodian_group_export_group_public_params(c, gid, gp, &gplen) !=
        GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_REGISTER, gp, gplen, ack,
                    sizeof(ack), &alen);
}

/* ---- pairwise session mesh + key distribution --------------------------- */

/* A member publishes one one-shot bundle for the founder to initiate against. */
static int
publish_bundle(gy_custodian *c, const struct grp_client_cfg *cfg, int rfd,
               int wfd)
{
    uint8_t bundle[DEMO_MAX_PAYLOAD];
    size_t blen = sizeof(bundle);
    uint8_t ack[64];
    size_t alen = 0;

    if (gy_publish_bundle(c, bundle, &blen) != GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_PUBLISH_BUNDLE, bundle, blen,
                    ack, sizeof(ack), &alen);
}

/*
 * Founder: establish a pairwise session to ONE device endpoint (logical name
 * pname, addressed as (peer_uid, device_id)) and hand it the GroupMasterKey as
 * that session's first message.  Fetch is deferred by the coordinator until the
 * endpoint has published its bundle.
 */
static int
distribute_to(gy_custodian *c, const struct grp_client_cfg *cfg,
              const uint8_t gid[GY_GROUP_ID_LEN], const char *pname,
              const uint8_t *peer_uid, const uint8_t *device_id,
              size_t device_id_len, int rfd, int wfd)
{
    uint8_t bundle[DEMO_MAX_PAYLOAD], kd[512], first[DEMO_MAX_PAYLOAD];
    size_t blen = 0, kdlen = sizeof(kd), flen = sizeof(first);
    uint32_t rtype;
    gy_keychange chg;
    int erc;

    if (request(rfd, wfd, cfg->name, pname, GRP_MSG_FETCH_BUNDLE, NULL, 0,
                &rtype, bundle, sizeof(bundle), &blen, NULL) != 0 ||
        rtype != GRP_MSG_BUNDLE) {
        fprintf(stderr, "%s: fetch %s bundle failed (rtype=%u)\n", cfg->name,
                pname, rtype);
        return -1;
    }
    erc = gy_custodian_group_export_key_envelope(c, gid, kd, &kdlen);
    if (erc != GY_OK) {
        fprintf(stderr, "%s: export_key_envelope rc=%d\n", cfg->name, erc);
        return -1;
    }
    /* gy_initiate runs inside a send transaction (staged until commit). */
    if (gy_send_open(c) != GY_OK)
        return -1;
    memset(&chg, 0, sizeof(chg));
    erc = gy_initiate(c, peer_uid, GY_GROUP_UID_BYTES, device_id, device_id_len,
                      bundle, blen, kd, kdlen, &chg, first, &flen);
    if (erc != GY_OK) {
        gy_rollback(c);
        fprintf(stderr, "%s: gy_initiate to %s rc=%d\n", cfg->name, pname, erc);
        return -1;
    }
    if (gy_commit(c) != GY_OK) {
        fprintf(stderr, "%s: gy_commit (%s) failed\n", cfg->name, pname);
        return -1;
    }
    {
        uint8_t ack[64];
        size_t alen = 0;
        uint32_t art = 0;
        if (request(rfd, wfd, cfg->name, pname, GRP_MSG_RELAY, first, flen,
                    &art, ack, sizeof(ack), &alen, NULL) != 0 ||
            art != GRP_MSG_SRV_REPLY) {
            fprintf(stderr, "%s: relay to %s failed (flen=%zu, rtype=%u)\n",
                    cfg->name, pname, flen, art);
            return -1;
        }
    }
    return 0;
}

/*
 * Founder: hand every member the GroupMasterKey over a fresh pairwise session.
 * The member that runs a companion device (GRP_MD_MEMBER) gets a session PER
 * device, so both of its devices can receive group messages; the KVAC roster
 * still holds a single entry for that member's UID.
 */
static int
distribute_key(gy_custodian *c, const struct grp_client_cfg *cfg,
               const uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd, int n)
{
    uint8_t peer_uid[GY_GROUP_UID_BYTES];
    char pname[DEMO_NAME_MAX];
    int peer;

    for (peer = 0; peer < n; peer++) {
        if (peer == cfg->index)
            continue;
        member_name(peer, pname, sizeof(pname));
        grp_uid(peer, peer_uid);
        if (distribute_to(c, cfg, gid, pname, peer_uid, DEVICE_ID_A,
                          sizeof(DEVICE_ID_A), rfd, wfd) != 0)
            return -1;
    }
    /* The companion device of GRP_MD_MEMBER: same UID, device B, its own
     * session and relay endpoint. */
    grp_uid(GRP_MD_MEMBER, peer_uid);
    if (distribute_to(c, cfg, gid, GRP_MD_COMPANION_NAME, peer_uid, DEVICE_ID_B,
                      sizeof(DEVICE_ID_B), rfd, wfd) != 0)
        return -1;
    printf("%s: distributed GroupMasterKey to %d peers (+1 companion device)\n",
           cfg->name, n - 1);
    return 0;
}

/* A member receives the founder's first pairwise message and installs the key. */
static int
receive_key(gy_custodian *c, const struct grp_client_cfg *cfg,
            uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd)
{
    uint8_t msg[DEMO_MAX_PAYLOAD], kd[512];
    char from[DEMO_NAME_MAX];
    uint8_t sender_uid[GY_GROUP_UID_BYTES];
    size_t mlen = 0, kdlen = sizeof(kd);
    uint32_t rtype;
    int sidx;

    if (request(rfd, wfd, cfg->name, NULL, GRP_MSG_RECV, NULL, 0, &rtype, msg,
                sizeof(msg), &mlen, from) != 0 ||
        rtype != GRP_MSG_DELIVER)
        return -1;
    sidx = (from[0] == 'm') ? atoi(from + 1) - 1 : -1;
    if (sidx < 0)
        return -1;
    grp_uid(sidx, sender_uid);

    if (gy_receive(c, sender_uid, sizeof(sender_uid), DEVICE_ID_A,
                   sizeof(DEVICE_ID_A), msg, mlen, kd, &kdlen) != GY_OK)
        return -1;
    if (gy_custodian_group_install_key_envelope(c, kd, kdlen, gid) != GY_OK)
        return -1;
    printf("%s: joined group (key from %s)\n", cfg->name, from);
    return 0;
}

/* ---- credentials, membership, presentation ------------------------------ */

/* 7.1 GetAuthCredential: request issuance for (uid, day) and store it. */
static int
get_auth_cred(gy_custodian *c, const struct grp_client_cfg *cfg,
              const uint8_t gid[GY_GROUP_ID_LEN], const uint8_t *uid,
              uint64_t date, int rfd, int wfd)
{
    uint8_t req[16 + 8], resp[DEMO_MAX_PAYLOAD];
    size_t rlen = 0;
    int rc;

    memcpy(req, uid, 16);
    be64_put(req + 16, date);
    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_ISSUE_AUTH, req, sizeof(req),
                 resp, sizeof(resp), &rlen) != 0) {
        fprintf(stderr, "%s: SRV_ISSUE_AUTH rejected by server\n", cfg->name);
        return -1;
    }
    rc = gy_custodian_group_receive_auth_credential(c, gid, uid, date, resp,
                                                    rlen);
    if (rc != GY_OK) {
        fprintf(stderr, "%s: receive_auth_credential rc=%d\n", cfg->name, rc);
        return -1;
    }
    return 0;
}

/* 7.2/7.3 CommitToProfileKey + GetProfileKeyCredential (blind issuance). */
static int
get_pk_cred(gy_custodian *c, const struct grp_client_cfg *cfg,
            const uint8_t gid[GY_GROUP_ID_LEN], const uint8_t *uid,
            const uint8_t *pk, int rfd, int wfd)
{
    uint8_t commit[512], request_obj[DEMO_MAX_PAYLOAD];
    uint8_t payload[DEMO_MAX_PAYLOAD], resp[DEMO_MAX_PAYLOAD];
    size_t clen = sizeof(commit), reqlen = sizeof(request_obj), off, rlen = 0;

    if (gy_custodian_group_profile_key_commit(c, gid, pk, commit, &clen) !=
        GY_OK)
        return -1;
    if (gy_custodian_group_pk_credential_request(c, gid, pk, request_obj,
                                                 &reqlen) != GY_OK)
        return -1;
    /* uid(16) || len16(commit) || commit || request */
    memcpy(payload, uid, 16);
    off = 16;
    payload[off++] = (uint8_t)(clen >> 8);
    payload[off++] = (uint8_t)(clen & 0xff);
    memcpy(payload + off, commit, clen);
    off += clen;
    memcpy(payload + off, request_obj, reqlen);
    off += reqlen;
    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_BLIND_ISSUE, payload, off,
                 resp, sizeof(resp), &rlen) != 0)
        return -1;
    return gy_custodian_group_pk_credential_finish(c, gid, pk, resp, rlen) ==
                   GY_OK
               ? 0
               : -1;
}

/* 7.5 AddGroupMember (self-add): present own ProfileKeyCredential to the server. */
static int
self_add(gy_custodian *c, const struct grp_client_cfg *cfg,
         const uint8_t gid[GY_GROUP_ID_LEN], const uint8_t *uid,
         const uint8_t *pk, int rfd, int wfd)
{
    uint8_t pres[DEMO_MAX_PAYLOAD], ack[64];
    size_t plen = sizeof(pres), alen = 0;

    if (gy_custodian_group_add_member(c, gid, uid, pk, pres, &plen) != GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_ADD_MEMBER, pres, plen,
                    ack, sizeof(ack), &alen);
}

/* 7.4 AuthAsGroupMember: present an anonymous membership proof to the server. */
static int
present_member(gy_custodian *c, const struct grp_client_cfg *cfg,
               const uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd)
{
    uint8_t pres[DEMO_MAX_PAYLOAD], ack[64];
    size_t plen = sizeof(pres), alen = 0;

    if (gy_custodian_group_auth_present(c, gid, pres, &plen) != GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_VERIFY_AUTH, pres, plen,
                    ack, sizeof(ack), &alen);
}

/*
 * Negative path (mirrors the 1:1 demo's forged-SAK rejection): produce a valid
 * AuthCredentialPresentation, corrupt one byte, and confirm the server rejects
 * it.  A tampered proof must fail the server's verify as the uniform
 * GY_ERR_VERIFY (surfaced here as an SRV_FAIL), never be accepted.  Returns 0
 * when the server correctly rejected, -1 if it accepted the forgery or on IPC
 * error.
 */
static int
present_tampered(gy_custodian *c, const struct grp_client_cfg *cfg,
                 const uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd)
{
    uint8_t pres[DEMO_MAX_PAYLOAD], ack[64];
    size_t plen = sizeof(pres), alen = 0;

    if (gy_custodian_group_auth_present(c, gid, pres, &plen) != GY_OK)
        return -1;
    /* Flip a byte in the proof body (past the object header). */
    pres[plen / 2] ^= 0xff;
    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_VERIFY_AUTH, pres, plen, ack,
                 sizeof(ack), &alen) == 0) {
        fprintf(stderr, "%s: server ACCEPTED a tampered presentation\n",
                cfg->name);
        return -1;
    }
    return 0; /* rejected, as required */
}

/*
 * Store round-trip (mirrors the 1:1 demo's restart-from-sealed-store phase):
 * close the custodian and reopen it from the SAME on-disk filestore, then prove
 * the sealed group state survived by presenting membership again.  That present
 * needs the group master secret AND the stored AuthCredential, both recoverable
 * only from the sealed store (the group facade reloads its 0x40-range records
 * lazily on the first group call after reopen), so a clean re-present is an
 * end-to-end persistence check.  *c is replaced with the reopened handle;
 * returns 0 on success, -1 otherwise.
 */
static int
store_round_trip(gy_custodian **c, const struct grp_client_cfg *cfg,
                 const gy_store_callbacks *store,
                 const uint8_t gid[GY_GROUP_ID_LEN], struct demo_clock *clk,
                 int rfd, int wfd)
{
    gy_custodian *reopened = NULL;

    gy_custodian_close(*c);
    *c = NULL;
    /* Group-aware reopen: gy_custodian_open takes no clock, and the daily group
     * credential ops need one, so the group vertical supplies its own reopen
     * that reinstalls it (messaging's gy_custodian_open path is unchanged).  The
     * same clock ctx the custodian was created with is handed back in. */
    if (gy_custodian_group_open(&reopened, store, (const uint8_t *)cfg->secret,
                                strlen(cfg->secret), demo_clock_now,
                                clk) != GY_OK) {
        fprintf(stderr, "%s: custodian reopen failed\n", cfg->name);
        return -1;
    }
    *c = reopened;
    if (present_member(reopened, cfg, gid, rfd, wfd) != 0) {
        fprintf(stderr, "%s: group state lost across reopen\n", cfg->name);
        return -1;
    }
    return 0;
}

/*
 * 7.10 UpdateProfileKey: rotate to new_pk and re-present.  Cryptographically an
 * AddGroupMember over (own uid, new_pk), so it rides the same SRV_ADD_MEMBER
 * path and upserts the caller's roster entry with the new ProfileKeyCiphertext.
 */
static int
update_pk(gy_custodian *c, const struct grp_client_cfg *cfg,
          const uint8_t gid[GY_GROUP_ID_LEN],
          const uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES], int rfd, int wfd)
{
    uint8_t pres[DEMO_MAX_PAYLOAD], ack[64];
    size_t plen = sizeof(pres), alen = 0;
    int rc;

    rc = gy_custodian_group_update_profile_key(c, gid, new_pk, pres, &plen);
    if (rc != GY_OK) {
        fprintf(stderr, "%s: update_profile_key (local) rc=%d\n", cfg->name,
                rc);
        return -1;
    }
    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_ADD_MEMBER, pres, plen, ack,
                 sizeof(ack), &alen) != 0) {
        fprintf(stderr, "%s: update presentation rejected by server\n",
                cfg->name);
        return -1;
    }
    return 0;
}

/* Rendezvous: block until every member reaches this point. */
static int
barrier(const struct grp_client_cfg *cfg, int rfd, int wfd)
{
    uint8_t ack[64];
    size_t alen = 0;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_BARRIER, NULL, 0, ack,
                    sizeof(ack), &alen);
}

/* 7.9 AddInvitedGroupMember (founder): add invited_uid with no ProfileKey. */
static int
invite_member(gy_custodian *c, const struct grp_client_cfg *cfg,
              const uint8_t gid[GY_GROUP_ID_LEN], const uint8_t *invited_uid,
              int rfd, int wfd)
{
    uint8_t uid_ct[256], ack[64];
    size_t ulen = sizeof(uid_ct), alen = 0;

    if (gy_custodian_group_add_invited_member(c, gid, invited_uid, uid_ct,
                                              &ulen) != GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_ADD_INVITED, uid_ct, ulen,
                    ack, sizeof(ack), &alen);
}

/* 7.8 DeleteGroupMember (founder): remove target_uid from the roster. */
static int
remove_member(gy_custodian *c, const struct grp_client_cfg *cfg,
              const uint8_t gid[GY_GROUP_ID_LEN], const uint8_t *target_uid,
              int rfd, int wfd)
{
    uint8_t uid_ct[256], ack[64];
    size_t ulen = sizeof(uid_ct), alen = 0;

    if (gy_custodian_group_delete_member(c, gid, target_uid, uid_ct, &ulen) !=
        GY_OK)
        return -1;
    return srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_DELETE_MEMBER, uid_ct,
                    ulen, ack, sizeof(ack), &alen);
}

/* 7.7 FetchGroupMembers: fetch and decrypt the roster; check the tallies. */
static int
fetch_and_check(gy_custodian *c, const struct grp_client_cfg *cfg,
                const uint8_t gid[GY_GROUP_ID_LEN], int rfd, int wfd,
                int want_full, int want_invited, const uint8_t *self_uid,
                const uint8_t *expect_own_pk)
{
    uint8_t wire[DEMO_MAX_PAYLOAD];
    gy_group_member_view mv[GRP_NMEMBERS + 2];
    size_t wlen = 0, cnt = 0, i;
    int full = 0, invited = 0;

    if (srv_call(rfd, wfd, cfg->name, GRP_MSG_SRV_FETCH_MEMBERS, NULL, 0, wire,
                 sizeof(wire), &wlen) != 0)
        return -1;
    if (gy_custodian_group_fetch_members(c, gid, wire, wlen, mv,
                                         GRP_NMEMBERS + 2, &cnt) != GY_OK)
        return -1;
    if (cnt > GRP_NMEMBERS + 2) /* never happens: the call caps at capacity */
        cnt = GRP_NMEMBERS + 2;
    for (i = 0; i < cnt; i++) {
        if (mv[i].has_profile_key)
            full++;
        else
            invited++;
    }
    if (full != want_full || invited != want_invited) {
        fprintf(stderr,
                "%s: roster mismatch (full=%d want=%d, invited=%d "
                "want=%d)\n",
                cfg->name, full, want_full, invited, want_invited);
        return -1;
    }
    /* A surviving full member confirms its OWN entry carries its current
     * ProfileKey (decrypted from the roster), which validates UpdateProfileKey
     * for the member that rotated its key. */
    if (expect_own_pk != NULL) {
        int found = 0;
        for (i = 0; i < cnt; i++)
            if (memcmp(mv[i].uid, self_uid, GY_GROUP_UID_BYTES) == 0) {
                found = 1;
                if (!mv[i].has_profile_key ||
                    memcmp(mv[i].profile_key, expect_own_pk,
                           GY_GROUP_PROFILEKEY_BYTES) != 0) {
                    fprintf(stderr, "%s: own ProfileKey mismatch in roster\n",
                            cfg->name);
                    return -1;
                }
                break;
            }
        if (!found) {
            fprintf(stderr, "%s: own entry missing from roster\n", cfg->name);
            return -1;
        }
    }
    printf("%s: roster ok (%d full, %d invited)\n", cfg->name, full, invited);
    return 0;
}

/* ---- group message fan-out (mirrors the 1:1 demo's msg_send) ------------- */

/*
 * Send one group message to EVERY live device of one member.  gy_prepare over
 * the member's UID yields a descriptor per known device (two for the member
 * that runs a companion); each live device gets its own ciphertext in this one
 * send transaction, relayed to that device's endpoint.  This is the real Sesame
 * fan-out: membership is per account, delivery is per device.
 */
static int
fanout_to_member(gy_custodian *c, const struct grp_client_cfg *cfg, int peer,
                 int rfd, int wfd, const char *text)
{
    struct {
        uint8_t buf[DEMO_MAX_PAYLOAD];
        size_t len;
        char to[DEMO_NAME_MAX];
    } out[GRP_NMEMBERS];
    uint8_t peer_uid[GY_GROUP_UID_BYTES];
    gy_fanout_desc descs[GRP_NMEMBERS];
    gy_target tgt;
    size_t n = 0, cap, i;
    int nout = 0;

    grp_uid(peer, peer_uid);
    tgt.user_id = peer_uid;
    tgt.user_id_len = sizeof(peer_uid);

    if (gy_send_open(c) != GY_OK)
        return -1;
    if (gy_prepare(c, &tgt, 1, NULL, &n) != GY_OK || n > GRP_NMEMBERS) {
        gy_rollback(c);
        return -1;
    }
    cap = GRP_NMEMBERS;
    if (n > 0 && gy_prepare(c, &tgt, 1, descs, &cap) != GY_OK) {
        gy_rollback(c);
        return -1;
    }
    n = n > 0 ? cap : 0;
    /* Encrypt to each live device inside the one transaction; buffer the
     * ciphertexts to relay after commit. */
    for (i = 0; i < n; i++) {
        if (descs[i].status != GY_FANOUT_MESSAGE)
            continue;
        out[nout].len = sizeof(out[nout].buf);
        if (gy_encrypt(c, peer_uid, sizeof(peer_uid), descs[i].device_id,
                       descs[i].device_id_len, (const uint8_t *)text,
                       strlen(text), out[nout].buf, &out[nout].len) != GY_OK) {
            gy_rollback(c);
            return -1;
        }
        endpoint_name(peer, descs[i].device_id, descs[i].device_id_len,
                      out[nout].to, sizeof(out[nout].to));
        nout++;
    }
    if (nout == 0) {
        gy_rollback(c);
        fprintf(stderr, "%s: no live device of m%d for fan-out\n", cfg->name,
                peer + 1);
        return -1;
    }
    if (gy_commit(c) != GY_OK)
        return -1;
    for (i = 0; i < (size_t)nout; i++) {
        uint8_t ack[64];
        size_t alen = 0;
        uint32_t art = 0;
        if (request(rfd, wfd, cfg->name, out[i].to, GRP_MSG_RELAY, out[i].buf,
                    out[i].len, &art, ack, sizeof(ack), &alen, NULL) != 0 ||
            art != GRP_MSG_SRV_REPLY)
            return -1;
    }
    return 0;
}

/* Founder: fan a CHAIN of messages out to each surviving full member (and, for
 * a member with a companion, to both of its devices).  Each message is a fresh
 * ratchet step in that device's pairwise session, so a reordered chain forces
 * the receiver through its skip store. */
static int
fanout_send(gy_custodian *c, const struct grp_client_cfg *cfg, int rfd, int wfd)
{
    size_t t;
    int k;
    for (t = 0; t < sizeof(FANOUT_TARGETS) / sizeof(FANOUT_TARGETS[0]); t++)
        for (k = 0; k < GRP_FANOUT_MSGS; k++) {
            char text[3];
            text[0] = 'g';
            text[1] = (char)('1' + k);
            text[2] = '\0';
            if (fanout_to_member(c, cfg, FANOUT_TARGETS[t], rfd, wfd, text) !=
                0)
                return -1;
        }
    printf("%s: fanned out a %d-message chain to %zu members (m2 to both "
           "devices)\n",
           cfg->name, GRP_FANOUT_MSGS,
           sizeof(FANOUT_TARGETS) / sizeof(FANOUT_TARGETS[0]));
    return 0;
}

/* Recipient: receive the relayed CHAIN (delivered out of order by the
 * coordinator) and confirm every message decrypts to a distinct, valid "gN".
 * Mirrors the 1:1 demo's reordered-delivery check, generalized to N. */
static int
fanout_recv(gy_custodian *c, const struct grp_client_cfg *cfg, int rfd, int wfd)
{
    uint8_t seen[GRP_FANOUT_MSGS][2];
    int i, j;

    for (i = 0; i < GRP_FANOUT_MSGS; i++) {
        uint8_t msg[DEMO_MAX_PAYLOAD], pt[512];
        char from[DEMO_NAME_MAX];
        uint8_t sender_uid[GY_GROUP_UID_BYTES];
        size_t mlen = 0, ptlen = sizeof(pt);
        uint32_t rtype;
        int sidx;

        if (request(rfd, wfd, cfg->name, "coord", GRP_MSG_RECV, NULL, 0, &rtype,
                    msg, sizeof(msg), &mlen, from) != 0 ||
            rtype != GRP_MSG_DELIVER)
            return -1;
        sidx = (from[0] == 'm') ? atoi(from + 1) - 1 : -1;
        if (sidx < 0)
            return -1;
        grp_uid(sidx, sender_uid);
        if (gy_receive(c, sender_uid, sizeof(sender_uid), DEVICE_ID_A,
                       sizeof(DEVICE_ID_A), msg, mlen, pt, &ptlen) != GY_OK)
            return -1;
        if (ptlen != 2 || pt[0] != 'g' || pt[1] < '1' ||
            pt[1] > (uint8_t)('0' + GRP_FANOUT_MSGS)) {
            fprintf(stderr, "%s: bad group message from %s\n", cfg->name, from);
            return -1;
        }
        for (j = 0; j < i; j++)
            if (memcmp(seen[j], pt, 2) == 0) {
                fprintf(stderr, "%s: duplicate group message\n", cfg->name);
                return -1;
            }
        memcpy(seen[i], pt, 2);
        printf("%s: received group message %c%c from %s\n", cfg->name, pt[0],
               pt[1], from);
    }
    return 0;
}

/* ---- identity-key change (Sesame 3.2 replacement) ----------------------- */

/*
 * A member reinstalls IN PLACE: it keeps its account UID and its device id but
 * generates a fresh identity key (the real trigger is an app reinstall or a
 * restore of an existing device slot, not a brand-new device).  Create the fresh
 * identity on a clean store, re-register a bundle under the new key, signal the
 * founder to re-handshake, and receive the resumed session's first message.
 * *cptr is replaced with the reinstalled custodian.
 */
static int
rekey_reinstall(gy_custodian **cptr, const struct grp_client_cfg *cfg,
                struct demo_clock *clk, int rfd, int wfd)
{
    /* Process-lifetime: the reinstalled custodian references store2, so it must
     * outlive this call (one reinstall per process). */
    static struct filestore fs2;
    static gy_store_callbacks store2;
    gy_custodian *nc = NULL;
    char newdir[FILESTORE_DIR_MAX];
    uint8_t uid[GY_GROUP_UID_BYTES], founder_uid[GY_GROUP_UID_BYTES];
    uint8_t msg[DEMO_MAX_PAYLOAD], pt[256];
    char fromname[DEMO_NAME_MAX];
    size_t mlen = 0, ptlen = sizeof(pt);
    uint32_t rtype;

    grp_uid(cfg->index, uid);

    /* Reinstall = a clean app data area (what an app reinstall, or a restore
     * onto a wiped device slot, gives): close the old custodian and create a
     * fresh identity on a NEW store, keeping the SAME account UID and device id.
     * A fresh store, not gy_custodian_reset: reset clears only the identity slot
     * and leaves the old peer/prekey records, which would pollute the new
     * identity's receive path. */
    gy_custodian_close(*cptr);
    *cptr = NULL;
    if (snprintf(newdir, sizeof(newdir), "%s-reinstall", cfg->dir) >=
        (int)sizeof(newdir)) {
        fprintf(stderr, "%s: reinstall dir too long\n", cfg->name);
        return -1;
    }
    if (filestore_bind(&fs2, newdir, &store2) != 0) {
        fprintf(stderr, "%s: reinstall store bind failed\n", cfg->name);
        return -1;
    }
    if (gy_custodian_create(
            &nc, cfg->suite, &store2, (const uint8_t *)cfg->secret,
            strlen(cfg->secret), uid, sizeof(uid), cfg->device_id,
            cfg->device_id_len, demo_clock_now, clk, NULL) != GY_OK) {
        fprintf(stderr, "%s: reinstall create failed\n", cfg->name);
        return -1;
    }
    if (gy_custodian_generate_identity(nc, demo_clock_now(clk), 8) != GY_OK) {
        gy_custodian_close(nc);
        fprintf(stderr, "%s: reinstall identity regen failed\n", cfg->name);
        return -1;
    }
    *cptr = nc;

    /* Re-register the new bundle so the founder can fetch it. */
    if (publish_bundle(nc, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "%s: re-publish failed\n", cfg->name);
        return -1;
    }
    /* Signal the founder to re-handshake (a one-byte control notice via the
     * relay; not a geryon message). */
    {
        static const uint8_t marker[1] = {0x01};
        uint8_t ack[64];
        size_t alen = 0;
        uint32_t art = 0;
        if (request(rfd, wfd, cfg->name, "m1", GRP_MSG_RELAY, marker,
                    sizeof(marker), &art, ack, sizeof(ack), &alen, NULL) != 0 ||
            art != GRP_MSG_SRV_REPLY)
            return -1;
    }
    /* Receive the founder's resumed first message (its re-initiation under the
     * new identity). */
    if (request(rfd, wfd, cfg->name, NULL, GRP_MSG_RECV, NULL, 0, &rtype, msg,
                sizeof(msg), &mlen, fromname) != 0 ||
        rtype != GRP_MSG_DELIVER)
        return -1;
    grp_uid(0, founder_uid); /* the founder is m1 (index 0) */
    if (gy_receive(nc, founder_uid, sizeof(founder_uid), DEVICE_ID_A,
                   sizeof(DEVICE_ID_A), msg, mlen, pt, &ptlen) != GY_OK) {
        fprintf(stderr, "%s: resumed receive failed\n", cfg->name);
        return -1;
    }
    printf("%s: reinstalled with a new identity key; session resumed with %s\n",
           cfg->name, fromname);
    return 0;
}

/*
 * Founder: handle a member that reinstalled in place.  On being signalled, fetch
 * the member's NEW bundle and re-handshake.  The first gy_initiate fails closed
 * with GY_ERR_KEY_CHANGED and hands back both fingerprints (a safety-number
 * change a real app surfaces to the user for out-of-band re-verification); after
 * gy_accept_identity the re-initiation succeeds and resumes the conversation.
 * This mirrors the library's own key_change_then_accept contract.
 */
static int
rekey_accept(gy_custodian *c, const struct grp_client_cfg *cfg, int rfd,
             int wfd)
{
    uint8_t notice[DEMO_MAX_PAYLOAD], bundle[DEMO_MAX_PAYLOAD];
    uint8_t first[DEMO_MAX_PAYLOAD], peer_uid[GY_GROUP_UID_BYTES];
    char from[DEMO_NAME_MAX];
    size_t nlen = 0, blen = 0, flen = sizeof(first);
    uint32_t rtype;
    gy_keychange chg;
    int rc;

    /* Wait for the "I reinstalled" notice from the member. */
    if (request(rfd, wfd, cfg->name, NULL, GRP_MSG_RECV, NULL, 0, &rtype,
                notice, sizeof(notice), &nlen, from) != 0 ||
        rtype != GRP_MSG_DELIVER)
        return -1;
    grp_uid(GRP_MD_REKEY_MEMBER, peer_uid);

    /* Fetch the member's NEW bundle. */
    if (request(rfd, wfd, cfg->name, from, GRP_MSG_FETCH_BUNDLE, NULL, 0,
                &rtype, bundle, sizeof(bundle), &blen, NULL) != 0 ||
        rtype != GRP_MSG_BUNDLE) {
        fprintf(stderr, "%s: fetch %s new bundle failed\n", cfg->name, from);
        return -1;
    }

    /* First re-handshake attempt fails closed on the identity-key change. */
    if (gy_send_open(c) != GY_OK)
        return -1;
    memset(&chg, 0, sizeof(chg));
    rc = gy_initiate(c, peer_uid, sizeof(peer_uid), DEVICE_ID_A,
                     sizeof(DEVICE_ID_A), bundle, blen,
                     (const uint8_t *)"resumed", 7, &chg, first, &flen);
    gy_rollback(c);
    if (rc != GY_ERR_KEY_CHANGED) {
        fprintf(stderr, "%s: expected KEY_CHANGED from %s, got %d\n", cfg->name,
                from, rc);
        return -1;
    }
    if (chg.fp_len == 0 || memcmp(chg.old_fp, chg.new_fp, chg.fp_len) == 0) {
        fprintf(stderr, "%s: KEY_CHANGED without a fingerprint change\n",
                cfg->name);
        return -1;
    }
    printf(
        "%s: %s identity key changed (safety number differs); re-verifying\n",
        cfg->name, from);

    /* Accept the new identity, then re-initiate under it. */
    if (gy_accept_identity(c, peer_uid, sizeof(peer_uid), DEVICE_ID_A,
                           sizeof(DEVICE_ID_A), bundle, blen) != GY_OK) {
        fprintf(stderr, "%s: gy_accept_identity for %s failed\n", cfg->name,
                from);
        return -1;
    }
    flen = sizeof(first);
    if (gy_send_open(c) != GY_OK)
        return -1;
    memset(&chg, 0, sizeof(chg));
    rc = gy_initiate(c, peer_uid, sizeof(peer_uid), DEVICE_ID_A,
                     sizeof(DEVICE_ID_A), bundle, blen,
                     (const uint8_t *)"resumed", 7, &chg, first, &flen);
    if (rc != GY_OK) {
        gy_rollback(c);
        fprintf(stderr, "%s: re-initiate after accept failed (%d)\n", cfg->name,
                rc);
        return -1;
    }
    if (gy_commit(c) != GY_OK)
        return -1;
    {
        uint8_t ack[64];
        size_t alen = 0;
        uint32_t art = 0;
        if (request(rfd, wfd, cfg->name, from, GRP_MSG_RELAY, first, flen, &art,
                    ack, sizeof(ack), &alen, NULL) != 0 ||
            art != GRP_MSG_SRV_REPLY)
            return -1;
    }
    printf("%s: accepted %s's new identity; conversation resumed\n", cfg->name,
           from);
    return 0;
}

/* ---- lifecycle ---------------------------------------------------------- */

int
grp_client_run(const struct grp_client_cfg *cfg, int rfd, int wfd)
{
    struct filestore fs;
    gy_store_callbacks store;
    gy_custodian *c = NULL;
    uint8_t uid[GY_GROUP_UID_BYTES];
    uint8_t gid[GY_GROUP_ID_LEN];
    uint8_t
        own_pk[GY_GROUP_PROFILEKEY_BYTES]; /* current ProfileKey (full only) */
    /* The clock ctx the app owns: it outlives the custodian (the library holds a
     * pointer to it), so it lives for the whole member lifecycle here. */
    struct demo_clock clock_ctx = {0};
    int rc = 1;

    if (filestore_bind(&fs, cfg->dir, &store) != 0) {
        fprintf(stderr, "%s: store bind failed\n", cfg->name);
        return 1;
    }
    grp_uid(cfg->index, uid);
    if (gy_custodian_create(
            &c, cfg->suite, &store, (const uint8_t *)cfg->secret,
            strlen(cfg->secret), uid, sizeof(uid), cfg->device_id,
            cfg->device_id_len, demo_clock_now, &clock_ctx, NULL) != GY_OK) {
        fprintf(stderr, "%s: custodian create failed\n", cfg->name);
        return 1;
    }
    if (gy_custodian_generate_identity(c, demo_clock_now(&clock_ctx), 8) !=
        GY_OK) {
        fprintf(stderr, "%s: identity generation failed\n", cfg->name);
        goto out;
    }

    if (install_server_params(c, cfg, rfd, wfd) != 0) {
        fprintf(stderr, "%s: server params setup failed\n", cfg->name);
        goto out;
    }

    if (cfg->role == GRP_ROLE_FOUNDER) {
        if (gy_custodian_group_create(c, gid) != GY_OK) {
            fprintf(stderr, "%s: group create failed\n", cfg->name);
            goto out;
        }
        printf("%s: created group\n", cfg->name);
        if (register_group(c, cfg, gid, rfd, wfd) != 0) {
            fprintf(stderr, "%s: register group failed\n", cfg->name);
            goto out;
        }
        if (distribute_key(c, cfg, gid, rfd, wfd, GRP_NMEMBERS) != 0) {
            fprintf(stderr, "%s: key distribution failed\n", cfg->name);
            goto out;
        }
    } else {
        if (publish_bundle(c, cfg, rfd, wfd) != 0) {
            fprintf(stderr, "%s: bundle publish failed\n", cfg->name);
            goto out;
        }
        if (receive_key(c, cfg, gid, rfd, wfd) != 0) {
            fprintf(stderr, "%s: key receive failed\n", cfg->name);
            goto out;
        }
    }

    /* Credentials + self-add + present-as-member (every full member; m5 is
     * invited-only and skips straight to the barriers, and a companion device
     * performs no KVAC ops: its member's primary owns the one roster entry). */
    if (cfg->index != 4 && !cfg->companion) {
        profile_key(cfg->index, own_pk);
        if (get_auth_cred(c, cfg, gid, uid, day_of(demo_clock_now(&clock_ctx)),
                          rfd, wfd) != 0) {
            fprintf(stderr, "%s: get_auth_cred failed\n", cfg->name);
            goto out;
        }
        if (get_pk_cred(c, cfg, gid, uid, own_pk, rfd, wfd) != 0) {
            fprintf(stderr, "%s: get_pk_cred failed\n", cfg->name);
            goto out;
        }
        if (self_add(c, cfg, gid, uid, own_pk, rfd, wfd) != 0) {
            fprintf(stderr, "%s: self_add failed\n", cfg->name);
            goto out;
        }
        if (present_member(c, cfg, gid, rfd, wfd) != 0) {
            fprintf(stderr, "%s: present_member failed\n", cfg->name);
            goto out;
        }
        printf("%s: got credentials, joined roster, presented membership\n",
               cfg->name);
        /* m3 additionally confirms a tampered presentation is rejected (the
         * server's uniform GY_ERR_VERIFY path), the group analogue of the 1:1
         * demo's forged-request rejection. */
        if (cfg->index == 2) {
            if (present_tampered(c, cfg, gid, rfd, wfd) != 0)
                goto out;
            printf("%s: tampered presentation rejected by server\n", cfg->name);
            /* ...and that its sealed group state survives a custodian
             * close/reopen from the on-disk store. */
            if (store_round_trip(&c, cfg, &store, gid, &clock_ctx, rfd, wfd) !=
                0)
                goto out;
            printf("%s: group state recovered after store reopen\n", cfg->name);
            /* Issuance churn (the group analogue of the 1:1 demo's SPK/SAK
             * rotation): roll the clock one day forward, confirm the day-bound
             * AuthCredential is now expired (D-GRP-7 item 3), then re-issue a
             * fresh credential for the new day and present it. */
            {
                uint8_t probe[DEMO_MAX_PAYLOAD];
                size_t problen = sizeof(probe);

                clock_ctx.offset_secs += SECS_PER_DAY;
                if (gy_custodian_group_auth_present(c, gid, probe, &problen) !=
                    GY_ERR_EXPIRED) {
                    fprintf(stderr, "%s: stale credential did not expire\n",
                            cfg->name);
                    goto out;
                }
                if (get_auth_cred(c, cfg, gid, uid,
                                  day_of(demo_clock_now(&clock_ctx)), rfd,
                                  wfd) != 0 ||
                    present_member(c, cfg, gid, rfd, wfd) != 0) {
                    fprintf(stderr, "%s: credential rotation failed\n",
                            cfg->name);
                    goto out;
                }
                printf("%s: rotated AuthCredential across a day boundary\n",
                       cfg->name);
            }
        }
        /* m2 rotates its ProfileKey (7.10 UpdateProfileKey). */
        if (cfg->index == 1) {
            uint8_t new_pk[GY_GROUP_PROFILEKEY_BYTES];
            int k;
            for (k = 0; k < GY_GROUP_PROFILEKEY_BYTES; k++)
                new_pk[k] = own_pk[k] ^ 0xff;
            /* 7.10 needs a FRESH ProfileKeyCredential over the new key before
             * the update presentation (the old credential is bound to the old
             * key). */
            if (get_pk_cred(c, cfg, gid, uid, new_pk, rfd, wfd) != 0) {
                fprintf(stderr, "%s: pk-cred for new key failed\n", cfg->name);
                goto out;
            }
            if (update_pk(c, cfg, gid, new_pk, rfd, wfd) != 0) {
                fprintf(stderr, "%s: update_profile_key failed\n", cfg->name);
                goto out;
            }
            memcpy(own_pk, new_pk, sizeof(own_pk));
            printf("%s: updated ProfileKey\n", cfg->name);
        }
    }

    /* Barrier 1: every member has self-added before the founder mutates. */
    if (barrier(cfg, rfd, wfd) != 0)
        goto out;

    if (cfg->role == GRP_ROLE_FOUNDER) {
        uint8_t m5_uid[GY_GROUP_UID_BYTES], m4_uid[GY_GROUP_UID_BYTES];
        grp_uid(4, m5_uid);
        grp_uid(3, m4_uid);
        if (invite_member(c, cfg, gid, m5_uid, rfd, wfd) != 0 ||
            remove_member(c, cfg, gid, m4_uid, rfd, wfd) != 0) {
            fprintf(stderr, "%s: invite/delete failed\n", cfg->name);
            goto out;
        }
        printf("%s: invited m5, removed m4\n", cfg->name);
    }

    /* Barrier 2: the founder's roster mutations are done before anyone reads. */
    if (barrier(cfg, rfd, wfd) != 0)
        goto out;

    /* Surviving full members (m1, m2, m3) additionally confirm their own entry
     * carries their current ProfileKey; m2's is the rotated one.  The companion
     * device holds no credential state and does not read the roster. */
    if (!cfg->companion) {
        const uint8_t *check_pk = (cfg->index <= 2) ? own_pk : NULL;
        if (fetch_and_check(c, cfg, gid, rfd, wfd, 3, 1, uid, check_pk) != 0)
            goto out;
    }

    /* Fan a message chain out over the pairwise sessions. */
    if (cfg->role == GRP_ROLE_FOUNDER) {
        if (fanout_send(c, cfg, rfd, wfd) != 0) {
            fprintf(stderr, "%s: fan-out send failed\n", cfg->name);
            goto out;
        }
    }

    /* Barrier 3: the whole chain is queued at the coordinator before any
     * receiver pulls, so the coordinator actually has multiple messages to
     * reorder (otherwise a RECV that races ahead drains the mailbox FIFO). */
    if (barrier(cfg, rfd, wfd) != 0)
        goto out;

    if (cfg->role != GRP_ROLE_FOUNDER &&
        (cfg->index == FANOUT_TARGETS[0] || cfg->index == FANOUT_TARGETS[1])) {
        if (fanout_recv(c, cfg, rfd, wfd) != 0) {
            fprintf(stderr, "%s: fan-out receive failed\n", cfg->name);
            goto out;
        }
    }

    /* Identity-key change (Sesame 3.2): m3 reinstalls in place (same UID and
     * device id, new identity key); the founder detects the changed key on its
     * next handshake and re-accepts.  Only these two processes take part; the
     * rest proceed to teardown. */
    if (cfg->role == GRP_ROLE_FOUNDER) {
        if (rekey_accept(c, cfg, rfd, wfd) != 0)
            goto out;
    } else if (cfg->index == GRP_MD_REKEY_MEMBER && !cfg->companion) {
        if (rekey_reinstall(&c, cfg, &clock_ctx, rfd, wfd) != 0)
            goto out;
    }

    {
        struct demo_frame_header h;
        memset(&h, 0, sizeof(h));
        h.type = GRP_MSG_GOODBYE;
        snprintf(h.from, sizeof(h.from), "%s", cfg->name);
        (void)demo_send_frame(wfd, &h, NULL);
    }
    rc = 0;

out:
    gy_custodian_close(c);
    return rc;
}
