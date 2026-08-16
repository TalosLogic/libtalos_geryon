/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DUDECT_TIMER_H
#define GY_DUDECT_TIMER_H

#include <stdint.h>

/*
 * Return the current high-resolution timer reading in implementation-defined
 * ticks.  Differences between consecutive readings are meaningful; absolute
 * values are not.  x86_64 uses RDTSCP + LFENCE, aarch64 reads CNTVCT_EL0
 * behind an ISB, and every other platform falls back to
 * clock_gettime(CLOCK_MONOTONIC).
 */
uint64_t gy_dudect_now_ticks(void);

/*
 * Human-readable name of the active timer source, printed in the summary so a
 * captured run report identifies which clock produced the numbers.
 */
const char *gy_dudect_timer_name(void);

#endif /* GY_DUDECT_TIMER_H */
