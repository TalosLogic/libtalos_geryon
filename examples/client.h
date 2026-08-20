/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * A demo client (Alice or Bob).  Alice and Bob share one body, differing by
 * name and, in later tickets, by role (the initiator fetches and speaks
 * first).  Each client owns a custodian and a file-backed sealed store; the
 * coordinator owns neither.  the example exercises only the coordinator
 * round-trip, so the client here just proves the pipes work.
 */

#ifndef GERYON_DEMO_CLIENT_H
#define GERYON_DEMO_CLIENT_H

#include <stdint.h>

enum client_role {
    CLIENT_INITIATOR = 0, /* fetches the peer bundle and speaks first (Alice) */
    CLIENT_RESPONDER = 1  /* waits for the initial message (Bob) */
};

struct client_cfg {
    const char *name;      /* logical name, e.g. "alice" */
    const char *peer;      /* the other client's name */
    const char *store_dir; /* per-client sealed-store directory */
    const char *cred;      /* store passphrase */
    enum client_role role;
    uint8_t suite; /* GY_SUITE_* pinned per identity; the ONLY per-suite knob a
                    * consumer sets.  The whole messaging path below is
                    * suite-agnostic (D-GEN-9): classical vs hybrid differ only
                    * in this value at create time, plus gy_pq_pending lighting
                    * up for a hybrid identity. */
};

/*
 * Run one client over its coordinator pipe pair.  Returns 0 on success, a
 * nonzero exit code on any failure (so a child fault fails the whole demo).
 */
int client_run(const struct client_cfg *cfg, int coord_rfd, int coord_wfd);

/*
 * Entry point for a re-forked client: reopen the custodian from
 * the sealed file store (no create, no re-handshake), first proving a wrong
 * passphrase fails uniformly, then resume the conversation - receive the
 * message queued during the restart and reply.  Returns 0 on success.
 */
int client_resume(const struct client_cfg *cfg, int coord_rfd, int coord_wfd);

#endif /* GERYON_DEMO_CLIENT_H */
