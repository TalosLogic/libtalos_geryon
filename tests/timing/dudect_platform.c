/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Platform-specific affinity and governor preflight.
 */
#define _GNU_SOURCE

#include "dudect_platform.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__)

#include <sched.h>

int
gy_dudect_pin_cpu(int cpu)
{
    cpu_set_t set;

    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        return -2;
    return 0;
}

void
gy_dudect_check_governor(FILE *out)
{
    const char *path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    FILE *f = fopen(path, "r");
    char buf[64];
    size_t n;

    if (f == NULL) {
        fprintf(out, "  governor: (unavailable: %s)\n", path);
        return;
    }
    if (fgets(buf, sizeof(buf), f) == NULL) {
        fclose(f);
        fprintf(out, "  governor: (read failed)\n");
        return;
    }
    fclose(f);

    n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';

    fprintf(out, "  governor: %s\n", buf);
    if (strcmp(buf, "performance") != 0 && strcmp(buf, "userspace") != 0) {
        fprintf(out,
                "  WARNING: CPU governor is not 'performance' or 'userspace'.\n"
                "           Frequency scaling will add large timing noise.\n"
                "           Run: sudo cpupower frequency-set -g performance\n");
    }
}

#else /* non-Linux */

int
gy_dudect_pin_cpu(int cpu)
{
    (void)cpu;
    return -1;
}

void
gy_dudect_check_governor(FILE *out)
{
    fprintf(out, "  governor: (control unavailable on this platform)\n");
}

#endif
