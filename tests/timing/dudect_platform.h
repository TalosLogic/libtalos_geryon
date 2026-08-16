/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DUDECT_PLATFORM_H
#define GY_DUDECT_PLATFORM_H

#include <stdio.h>

/*
 * Pin the calling thread to a single CPU core to reduce migration noise.
 * Returns 0 on success, -1 if pinning is not supported on this platform
 * (logged at startup; the harness continues), or -2 if the call failed.
 */
int gy_dudect_pin_cpu(int cpu);

/*
 * On Linux, read the cpu0 scaling governor and print it to out, warning
 * loudly if it is not "performance" or "userspace" (frequency scaling adds
 * large timing noise).  On macOS, print an advisory.  No-op elsewhere.
 */
void gy_dudect_check_governor(FILE *out);

#endif /* GY_DUDECT_PLATFORM_H */
