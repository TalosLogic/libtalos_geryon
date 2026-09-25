/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon QUANTUM-SAFE GROUP (QSPGS) end-to-end example: process topology and
 * fork/IPC plumbing.
 *
 * The parent is the coordinator (the untrusted relay + object store); it forks
 * QSG_NMEMBERS members m1..mN.  ALL traffic goes through the coordinator: the
 * only pipes are coordinator<->member[i], with no direct member<->member path,
 * so the relay is a real untrusted intermediary and the members share no
 * memory.  Each member closes every pipe end it does not use.
 *
 * Suite-agnostic across the two HYBRID tiers: qsgroup_demo_run() takes the
 * GY_SUITE_* value from its thin main (qsgroup_demo_main.c /
 * qsgroup_demo_h448_main.c).
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "qsgroup_client.h"
#include "qsgroup_coordinator.h"
#include "qsgroup_demo_driver.h"
#include "qsgroup_demo_proto.h"

#define QSG_BASE_MAX 256
#define QSG_DIR_MAX (QSG_BASE_MAX + 16)

static volatile pid_t g_pids[QSG_NPROC];

static void
on_signal(int signo)
{
    int i;

    (void)signo;
    for (i = 0; i < QSG_NPROC; i++)
        if (g_pids[i] > 0)
            kill(g_pids[i], SIGTERM);
    _exit(1);
}

int
qsgroup_demo_run(uint8_t suite, const char *base_template)
{
    struct sigaction sa;
    char base[QSG_BASE_MAX];
    int cm[QSG_NPROC][2]; /* coordinator -> member */
    int mc[QSG_NPROC][2]; /* member -> coordinator */
    int rfd[QSG_NPROC], wfd[QSG_NPROC];
    int i, j, rc, status;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (snprintf(base, sizeof(base), "%s", base_template) >=
        (int)sizeof(base)) {
        fprintf(stderr, "qsgroup-demo: base template too long\n");
        return 1;
    }
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    printf("qsgroup-demo: deterministic pass/fail, non-interactive, "
           "network-free, bounded\n");
    printf("qsgroup-demo: %d members, sealed stores under %s\n", QSG_NMEMBERS,
           base);

    for (i = 0; i < QSG_NPROC; i++) {
        if (pipe(cm[i]) < 0 || pipe(mc[i]) < 0) {
            perror("pipe");
            return 1;
        }
        g_pids[i] = -1;
    }

    for (i = 0; i < QSG_NPROC; i++) {
        g_pids[i] = fork();
        if (g_pids[i] < 0) {
            perror("fork");
            for (j = 0; j < i; j++)
                if (g_pids[j] > 0)
                    kill(g_pids[j], SIGTERM);
            return 1;
        }
        if (g_pids[i] == 0) {
            char name[8];
            char dir[QSG_DIR_MAX];
            struct qsgroup_client_cfg cfg;

            snprintf(name, sizeof(name), "m%d", i + 1);
            snprintf(dir, sizeof(dir), "%s/m%d", base, i + 1);

            /* Keep only cm[i][0] (read) and mc[i][1] (write); shed all else. */
            for (j = 0; j < QSG_NPROC; j++) {
                close(cm[j][1]);
                close(mc[j][0]);
                if (j != i) {
                    close(cm[j][0]);
                    close(mc[j][1]);
                }
            }

            cfg.name = name;
            cfg.index = i;
            cfg.role = (i == 0) ? QSG_ROLE_FOUNDER : QSG_ROLE_MEMBER;
            cfg.dir = dir;
            cfg.secret = "qsgroup-member-secret";
            cfg.suite = suite;
            return qsgroup_client_run(&cfg, cm[i][0], mc[i][1]);
        }
    }

    /* Coordinator (parent): install cleanup handlers, shed member-side ends. */
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (i = 0; i < QSG_NPROC; i++) {
        close(cm[i][0]);
        close(mc[i][1]);
        rfd[i] = mc[i][0];
        wfd[i] = cm[i][1];
    }

    rc = qsgroup_coordinator_run(rfd, wfd, QSG_NPROC, suite, base);

    for (i = 0; i < QSG_NPROC; i++) {
        close(rfd[i]);
        close(wfd[i]);
    }
    for (i = 0; i < QSG_NPROC; i++) {
        if (waitpid(g_pids[i], &status, 0) < 0) {
            perror("waitpid");
            rc = 1;
            continue;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "qsgroup-demo: member m%d did not exit cleanly\n",
                    i + 1);
            rc = 1;
        }
    }

    if (rc == 0)
        printf("qsgroup-demo: OK\n");
    else
        fprintf(stderr, "qsgroup-demo: FAILED\n");
    return rc;
}
