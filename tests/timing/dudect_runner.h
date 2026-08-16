/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#ifndef GY_DUDECT_RUNNER_H
#define GY_DUDECT_RUNNER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Two-class sample accumulator for Welch's t-test with percentile cropping.
 * All samples (cap per class) are held in memory; the t-value is computed from
 * the cropped, sorted sample arrays at summary time.  At cap = 5e5 per class
 * this is 8 MB total, which is fine for a tool that runs outside CI.
 */
struct gy_dudect_runner {
    size_t cap;
    size_t n[2];
    uint64_t *s[2];
};

/* Returns 0 on success, -1 on allocation failure. */
int gy_dudect_runner_init(struct gy_dudect_runner *r, size_t max_per_class);

/*
 * Returns 0 if the sample was stored, -1 if the buffer for cls is full.
 * Callers treat -1 as a signal to stop sampling.
 */
int gy_dudect_runner_observe(struct gy_dudect_runner *r, int cls,
                             uint64_t ticks);

/*
 * Compute Welch's two-sample t-statistic.  crop_lo and crop_hi are
 * percentiles in [0, 100], applied symmetrically to both classes after
 * sorting; pass 0 and 100 for no cropping.  Returns 0.0 if either class has
 * fewer than 2 samples after cropping.
 */
double gy_dudect_runner_t_value(const struct gy_dudect_runner *r,
                                double crop_lo, double crop_hi);

/*
 * Print the per-class summary, the cropping window, and |t|.  The verdict is
 * decided by the caller; this only formats numbers.
 */
void gy_dudect_runner_summary(const struct gy_dudect_runner *r, FILE *out,
                              double t_value, double crop_lo, double crop_hi);

size_t gy_dudect_runner_samples(const struct gy_dudect_runner *r, int cls);

void gy_dudect_runner_free(struct gy_dudect_runner *r);

#endif /* GY_DUDECT_RUNNER_H */
