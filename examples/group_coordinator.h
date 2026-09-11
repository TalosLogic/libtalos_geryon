/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef GERYON_GROUP_COORDINATOR_H
#define GERYON_GROUP_COORDINATOR_H

#include <stdint.h>

/*
 * Run the untrusted coordinator: the group SERVER (holds ServerSecretParams,
 * answers the section 8.1 RPCs) and the RELAY (forwards opaque member<->member
 * bytes).  rfd[i]/wfd[i] are the read/write pipe ends to member i, for
 * n members.  base is the per-run store area (the server's sealed key lives
 * under base/server).  Returns 0 on a clean run, nonzero on error.
 */
int grp_coordinator_run(const int *rfd, const int *wfd, int n, uint8_t suite,
                        const char *base);

#endif /* GERYON_GROUP_COORDINATOR_H */
