/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_QSGROUP_COORDINATOR_H
#define GERYON_QSGROUP_COORDINATOR_H

#include <stdint.h>

/*
 * Run the untrusted QSPGS coordinator: the RELAY (forwards opaque
 * member<->member bytes and the phase barrier) and the SERVER (an opaque,
 * keyed object store for the group core / appendix / invite queue / account
 * records; the section-7.3 acceptance checks of geryon_qsgroups_server.h are
 * layered on in a later increment).  rfd[i]/wfd[i] are the read/write pipe ends
 * to member i, for n members.  base is the per-run store area.  Returns 0 on a
 * clean run, nonzero on error.
 */
int qsgroup_coordinator_run(const int *rfd, const int *wfd, int n,
                            uint8_t suite, const char *base);

#endif /* GERYON_QSGROUP_COORDINATOR_H */
