/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The coordinator MODELS the untrusted server.  It holds NO custodian and NO
 * private keys: it only stores opaque published bundles and relays opaque
 * ciphertext.  A design that would hand it a key is not the topology this
 * example demonstrates.
 *
 * Its state (directory, mailboxes, delivery cursors) is a persistent singleton
 * so it SURVIVES a client restart: when a client is re-forked
 * with fresh pipes, the coordinator keeps every queued message and the other
 * client's parked state, and is only re-pointed at the new pipe ends.
 */

#ifndef GERYON_DEMO_COORDINATOR_H
#define GERYON_DEMO_COORDINATOR_H

/* coordinator_run outcome. */
enum coord_status {
    COORD_DONE = 0,        /* both clients departed (GOODBYE / EOF) */
    COORD_RESTART_BOB = 1, /* bob asked to be re-forked; state preserved */
    COORD_ERROR = -1       /* an IPC error */
};

/* Initialize the singleton over the two client pipe pairs (once per run). */
void coordinator_init(int alice_rfd, int alice_wfd, int bob_rfd, int bob_wfd);

/*
 * Serve until both clients depart or a restart is requested.  Returns an
 * enum coord_status.  On COORD_RESTART_BOB the caller re-forks bob, calls
 * coordinator_rewire_bob with the fresh pipe ends, and calls this again to
 * resume; all directory/mailbox state is retained across the call.
 */
int coordinator_run(void);

/* Re-point the coordinator at a re-forked bob's fresh pipe ends. */
void coordinator_rewire_bob(int bob_rfd, int bob_wfd);

#endif /* GERYON_DEMO_COORDINATOR_H */
