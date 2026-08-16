/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DUDECT_TARGET_H
#define GY_DUDECT_TARGET_H

#include <stddef.h>

/*
 * Descriptor for a function under timing validation.
 *
 * setup_class(cls, state)
 *   Fills state with the inputs for class A (cls=0) or class B (cls=1).
 *   Called once per trial, OUTSIDE the timer window; all setup work (key
 *   schedule, encryption of a fixture, allocation) belongs here, not in run().
 *
 * run(state)
 *   The function under measurement.  Called reps_per_trial times in a tight
 *   loop inside the timer window.  Must perform a visible side effect on each
 *   call (write to a volatile sink) so the compiler cannot dead-code-eliminate
 *   the body.
 *
 * state_size
 *   Bytes the harness allocates and zeros before each setup_class.
 *
 * reps_per_trial
 *   Inner-loop count, sized so total trial wall time comfortably exceeds the
 *   per-trial timer granularity (target ~10 us total).
 */
struct gy_dudect_target {
    const char *name;
    void (*setup_class)(int cls, void *state);
    void (*run)(const void *state);
    size_t state_size;
    int reps_per_trial;
};

#endif /* GY_DUDECT_TARGET_H */
