/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * geryon GROUP end-to-end example: process topology and fork/IPC plumbing.
 *
 * The parent is the coordinator (the untrusted server + relay); it forks
 * GRP_NPROC processes: the GRP_NMEMBERS members m1..m5 plus m2's companion
 * device "m2b" (a second device under m2's UID).  ALL traffic goes through the
 * coordinator: the only pipes are coordinator<->process[i], with no direct
 * process<->process path, so the relay is a real untrusted intermediary and the
 * processes share no memory.  Each process closes every pipe end it does not
 * use.
 *
 * Suite-agnostic: group_demo_run() takes the GY_SUITE_* value from its thin
 * main (group_demo_main.c / group_demo_c448_main.c).
 */

#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "group_client.h"
#include "group_coordinator.h"
#include "group_demo_driver.h"
#include "group_demo_proto.h"

#define GRP_BASE_MAX 256
#define GRP_DIR_MAX (GRP_BASE_MAX + 16)

/* Device ids: every member's primary is A; m2's companion is B (see
 * group_demo_proto.h). */
static const uint8_t dev_a[1] = {GRP_DEV_A};
static const uint8_t dev_b[1] = {GRP_DEV_B};

/* GRP_NPROC processes: GRP_NMEMBERS members plus m2's companion device. */
static volatile pid_t g_pids[GRP_NPROC];

static void
on_signal(int signo)
{
    int i;
    (void)signo;
    for (i = 0; i < GRP_NPROC; i++)
        if (g_pids[i] > 0)
            kill(g_pids[i], SIGTERM);
    _exit(1);
}

int
group_demo_run(uint8_t suite, const char *base_template)
{
    struct sigaction sa;
    char base[GRP_BASE_MAX];
    int cm[GRP_NPROC][2]; /* coordinator -> process */
    int mc[GRP_NPROC][2]; /* process -> coordinator */
    int rfd[GRP_NPROC], wfd[GRP_NPROC];
    int i, j, rc, status;

    setvbuf(stdout, NULL, _IOLBF, 0);

    if (snprintf(base, sizeof(base), "%s", base_template) >=
        (int)sizeof(base)) {
        fprintf(stderr, "group-demo: base template too long\n");
        return 1;
    }
    if (mkdtemp(base) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    printf("group-demo: deterministic pass/fail, non-interactive, "
           "network-free, bounded\n");
    printf("group-demo: %d members, sealed stores under %s\n", GRP_NMEMBERS,
           base);

    for (i = 0; i < GRP_NPROC; i++) {
        if (pipe(cm[i]) < 0 || pipe(mc[i]) < 0) {
            perror("pipe");
            return 1;
        }
        g_pids[i] = -1;
    }

    for (i = 0; i < GRP_NPROC; i++) {
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
            char dir[GRP_DIR_MAX];
            struct grp_client_cfg cfg;
            int companion = (i == GRP_MD_COMPANION_PROC);

            /* Processes 0..GRP_NMEMBERS-1 are the members m1..m5; the last
             * process is m2's companion device (same UID, device B). */
            if (companion) {
                snprintf(name, sizeof(name), "%s", GRP_MD_COMPANION_NAME);
                snprintf(dir, sizeof(dir), "%s/%s", base,
                         GRP_MD_COMPANION_NAME);
            } else {
                snprintf(name, sizeof(name), "m%d", i + 1);
                snprintf(dir, sizeof(dir), "%s/m%d", base, i + 1);
            }

            /* Keep only cm[i][0] (read) and mc[i][1] (write); shed all else. */
            for (j = 0; j < GRP_NPROC; j++) {
                close(cm[j][1]);
                close(mc[j][0]);
                if (j != i) {
                    close(cm[j][0]);
                    close(mc[j][1]);
                }
            }

            cfg.name = name;
            cfg.index = companion ? GRP_MD_MEMBER : i;
            cfg.role = (i == 0) ? GRP_ROLE_FOUNDER : GRP_ROLE_MEMBER;
            cfg.dir = dir;
            cfg.secret = "group-member-secret";
            cfg.suite = suite;
            cfg.device_id = companion ? dev_b : dev_a;
            cfg.device_id_len = companion ? sizeof(dev_b) : sizeof(dev_a);
            cfg.companion = companion;
            return grp_client_run(&cfg, cm[i][0], mc[i][1]);
        }
    }

    /* Coordinator (parent): install cleanup handlers, shed member-side ends. */
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    for (i = 0; i < GRP_NPROC; i++) {
        close(cm[i][0]);
        close(mc[i][1]);
        rfd[i] = mc[i][0];
        wfd[i] = cm[i][1];
    }

    rc = grp_coordinator_run(rfd, wfd, GRP_NPROC, suite, base);

    /* Drop our ends so the processes see EOF, then reap. */
    for (i = 0; i < GRP_NPROC; i++) {
        close(rfd[i]);
        close(wfd[i]);
    }
    for (i = 0; i < GRP_NPROC; i++) {
        if (waitpid(g_pids[i], &status, 0) < 0) {
            perror("waitpid");
            rc = 1;
            continue;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            if (i == GRP_MD_COMPANION_PROC)
                fprintf(stderr, "group-demo: %s did not exit cleanly\n",
                        GRP_MD_COMPANION_NAME);
            else
                fprintf(stderr, "group-demo: member m%d did not exit cleanly\n",
                        i + 1);
            rc = 1;
        }
    }

    if (rc == 0)
        printf("group-demo: OK\n");
    else
        fprintf(stderr, "group-demo: FAILED\n");
    return rc;
}
