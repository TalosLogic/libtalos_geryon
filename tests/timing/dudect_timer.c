/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * High-resolution timer abstraction.
 *
 * x86_64: __rdtscp() reads the cycle counter and waits for prior instructions
 *   to retire, but does not by itself prevent later instructions from
 *   executing before the read.  A trailing _mm_lfence() closes that window so
 *   the read brackets only the work under measurement, which markedly reduces
 *   per-trial noise on hosts with turbo / SMT / frequency scaling enabled.
 *
 * aarch64 (macOS and Linux): inline assembly reads CNTVCT_EL0 (the virtual
 *   counter) preceded by an ISB that serialises the pipeline so the read
 *   cannot be reordered before the measured work.  Apple Silicon runs the
 *   counter at 24 MHz (~41.7 ns/tick); Linux aarch64 frequency is SoC-specific
 *   (read CNTFRQ_EL0 for the exact value).
 *
 * Fallback: clock_gettime(CLOCK_MONOTONIC), nanoseconds, on any platform
 *   without a dedicated path.
 */
#define _POSIX_C_SOURCE 200809L

#include "dudect_timer.h"

#if defined(__x86_64__) || defined(_M_X64)

#include <x86intrin.h>

uint64_t
gy_dudect_now_ticks(void)
{
    unsigned int aux;
    uint64_t ticks = __rdtscp(&aux);
    _mm_lfence();
    return ticks;
}

const char *
gy_dudect_timer_name(void)
{
    return "RDTSCP+LFENCE (x86_64 cycles)";
}

#elif defined(__aarch64__)

static inline uint64_t
read_cntvct(void)
{
    uint64_t ticks;
    /*
     * ISB serialises the instruction stream: all prior instructions complete
     * before the counter is read, preventing the compiler or CPU from
     * hoisting the read above the work under measurement.  The "memory"
     * clobber prevents the compiler from reordering memory operations across
     * the barrier.
     */
    __asm__ volatile("isb\n\t"
                     "mrs %0, cntvct_el0"
                     : "=r"(ticks)::"memory");
    return ticks;
}

uint64_t
gy_dudect_now_ticks(void)
{
    return read_cntvct();
}

const char *
gy_dudect_timer_name(void)
{
#if defined(__APPLE__)
    return "CNTVCT_EL0 (aarch64 macOS, 24 MHz, ~41.7 ns/tick)";
#else
    return "CNTVCT_EL0 (aarch64; frequency from CNTFRQ_EL0)";
#endif
}

#else

#include <time.h>

uint64_t
gy_dudect_now_ticks(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

const char *
gy_dudect_timer_name(void)
{
    return "clock_gettime(CLOCK_MONOTONIC) [ns]";
}

#endif
