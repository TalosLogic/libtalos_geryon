/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_QSGROUP_CLIENT_H
#define GERYON_QSGROUP_CLIENT_H

#include <stdint.h>

/*
 * One QSPGS demo member's configuration, filled by the driver before it forks.
 * name is the logical relay endpoint ("m1".."mN"); index is the member index
 * (0-based, also the qsg_uid input); role is QSG_ROLE_*; dir is the per-member
 * sealed-store directory; secret unlocks the custodian; suite is the pinned
 * hybrid suite.
 */
struct qsgroup_client_cfg {
    const char *name;
    int index;
    int role;
    const char *dir;
    const char *secret;
    uint8_t suite;
};

/*
 * Run one QSPGS demo member over the coordinator pipe (rfd read, wfd write).
 * Returns 0 on a clean run, nonzero on any failure.
 */
int qsgroup_client_run(const struct qsgroup_client_cfg *cfg, int rfd, int wfd);

#endif /* GERYON_QSGROUP_CLIENT_H */
