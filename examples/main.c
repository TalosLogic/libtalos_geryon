/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon end-to-end example: process topology and fork/IPC plumbing.
 *
 * The parent is the coordinator (the untrusted server); it forks two clients,
 * Alice and Bob.  ALL traffic goes through the coordinator: the only pipes are
 * coordinator<->Alice and coordinator<->Bob, with no direct client<->client
 * path.  Each process closes every pipe end it does not use, because an
 * unclosed write end would leave a reader blocked forever (the classic pipe
 * deadlock).
 */

#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "client.h"
#include "coordinator.h"

/* Per-client store directory paths, filled from a per-run temp base. */
static char g_alice_dir[256];
static char g_bob_dir[256];

/* Child pids, for signal-driven cleanup.  volatile: touched from a handler. */
static volatile pid_t g_alice_pid = -1;
static volatile pid_t g_bob_pid = -1;

/*
 * On an interrupting signal, tear the children down and exit nonzero.  Only
 * async-signal-safe calls (kill, _exit) are used here.
 */
static void
on_signal(int signo)
{
    (void)signo;
    if (g_alice_pid > 0)
        kill(g_alice_pid, SIGTERM);
    if (g_bob_pid > 0)
        kill(g_bob_pid, SIGTERM);
    _exit(1);
}

/*
 * Close a pipe pair's two ends unconditionally.  Used to shed the ends a
 * process must not keep.
 */
static void
close_pair(int p[2])
{
    close(p[0]);
    close(p[1]);
}

int
main(void)
{
    struct sigaction sa;
    char base[] = "/tmp/geryon_demo_XXXXXX";
    int ca[2], ac[2], cb[2], bc[2];
    int alice_status, bob_status, rc, bob_r, bob_w;

    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Per-run sealed-store area: one directory per client under a unique
     * base, so state persists across a simulated restart within this run. */
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(g_alice_dir, sizeof(g_alice_dir), "%s/alice", base);
    snprintf(g_bob_dir, sizeof(g_bob_dir), "%s/bob", base);
    printf("demo: deterministic pass/fail, non-interactive, network-free, "
           "bounded\n");
    printf("demo: sealed stores under %s\n", base);

    if (pipe(ca) < 0 || pipe(ac) < 0 || pipe(cb) < 0 || pipe(bc) < 0) {
        perror("pipe");
        return 1;
    }

    g_alice_pid = fork();
    if (g_alice_pid < 0) {
        perror("fork alice");
        return 1;
    }
    if (g_alice_pid == 0) {
        struct client_cfg cfg = {"alice", "bob", g_alice_dir, "alice-secret",
                                 CLIENT_INITIATOR};

        /* Alice keeps ca[0] (read from coord) and ac[1] (write to coord). */
        close(ca[1]);
        close(ac[0]);
        close_pair(cb);
        close_pair(bc);
        return client_run(&cfg, ca[0], ac[1]);
    }

    g_bob_pid = fork();
    if (g_bob_pid < 0) {
        perror("fork bob");
        kill(g_alice_pid, SIGTERM);
        return 1;
    }
    if (g_bob_pid == 0) {
        struct client_cfg cfg = {"bob", "alice", g_bob_dir, "bob-secret",
                                 CLIENT_RESPONDER};

        /* Bob keeps cb[0] (read from coord) and bc[1] (write to coord). */
        close(cb[1]);
        close(bc[0]);
        close_pair(ca);
        close_pair(ac);
        return client_run(&cfg, cb[0], bc[1]);
    }

    /* Coordinator (parent) installs cleanup handlers now that children exist. */
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Coordinator keeps ca[1]/cb[1] (write) and ac[0]/bc[0] (read). */
    close(ca[0]);
    close(ac[1]);
    close(cb[0]);
    close(bc[1]);

    coordinator_init(ac[0], ca[1], bc[0], cb[1]);

    /* Current coordinator<->bob ends; these change when bob is re-forked. */
    rc = 0;
    bob_r = bc[0];
    bob_w = cb[1];

    for (;;) {
        int st = coordinator_run();

        if (st == COORD_RESTART_BOB) {
            int ncb[2], nbc[2]; /* fresh coord->bob, bob->coord pipes */

            /* The old bob is exiting; reap it and drop its stale pipes. */
            if (waitpid(g_bob_pid, &bob_status, 0) < 0)
                perror("waitpid bob (restart)");
            close(bob_r);
            close(bob_w);

            if (pipe(ncb) < 0 || pipe(nbc) < 0) {
                perror("pipe (restart)");
                rc = 1;
                break;
            }
            g_bob_pid = fork();
            if (g_bob_pid < 0) {
                perror("fork bob (restart)");
                rc = 1;
                break;
            }
            if (g_bob_pid == 0) {
                struct client_cfg cfg = {"bob", "alice", g_bob_dir,
                                         "bob-secret", CLIENT_RESPONDER};

                /* Fresh bob keeps ncb[0] (read) and nbc[1] (write); shed the
                 * coordinator's alice ends and the fresh pipes' far ends. */
                close(ncb[1]);
                close(nbc[0]);
                close(ca[1]);
                close(ac[0]);
                return client_resume(&cfg, ncb[0], nbc[1]);
            }
            /* Parent: close the child ends, rewire, and resume serving. */
            close(ncb[0]);
            close(nbc[1]);
            bob_r = nbc[0];
            bob_w = ncb[1];
            coordinator_rewire_bob(bob_r, bob_w);
            continue;
        }
        if (st == COORD_ERROR)
            rc = 1;
        break; /* COORD_DONE or COORD_ERROR */
    }

    /* Done relaying: drop our ends so the children see EOF, then reap. */
    close(ca[1]);
    close(ac[0]);
    close(bob_w);
    close(bob_r);

    if (waitpid(g_alice_pid, &alice_status, 0) < 0) {
        perror("waitpid alice");
        rc = 1;
    }
    if (waitpid(g_bob_pid, &bob_status, 0) < 0) {
        perror("waitpid bob");
        rc = 1;
    }

    if (rc != 0)
        fprintf(stderr, "demo: coordinator error\n");
    if (WIFEXITED(alice_status) && WEXITSTATUS(alice_status) != 0) {
        fprintf(stderr, "demo: alice exited %d\n", WEXITSTATUS(alice_status));
        rc = 1;
    }
    if (WIFEXITED(bob_status) && WEXITSTATUS(bob_status) != 0) {
        fprintf(stderr, "demo: bob exited %d\n", WEXITSTATUS(bob_status));
        rc = 1;
    }
    if (!WIFEXITED(alice_status) || !WIFEXITED(bob_status)) {
        fprintf(stderr, "demo: a client did not exit normally\n");
        rc = 1;
    }

    if (rc == 0)
        printf("demo: OK\n");
    return rc;
}
