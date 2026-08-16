/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include "dudect_runner.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

int
gy_dudect_runner_init(struct gy_dudect_runner *r, size_t max_per_class)
{
    int c;

    memset(r, 0, sizeof(*r));
    r->cap = max_per_class;
    for (c = 0; c < 2; c++) {
        r->s[c] = calloc(max_per_class, sizeof(uint64_t));
        if (r->s[c] == NULL) {
            gy_dudect_runner_free(r);
            return -1;
        }
    }
    return 0;
}

int
gy_dudect_runner_observe(struct gy_dudect_runner *r, int cls, uint64_t ticks)
{
    if (cls < 0 || cls > 1)
        return -1;
    if (r->n[cls] >= r->cap)
        return -1;
    r->s[cls][r->n[cls]++] = ticks;
    return 0;
}

size_t
gy_dudect_runner_samples(const struct gy_dudect_runner *r, int cls)
{
    return (cls == 0 || cls == 1) ? r->n[cls] : 0;
}

void
gy_dudect_runner_free(struct gy_dudect_runner *r)
{
    int c;

    for (c = 0; c < 2; c++) {
        free(r->s[c]);
        r->s[c] = NULL;
    }
    r->n[0] = r->n[1] = 0;
    r->cap = 0;
}

static int
cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;

    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/*
 * Mean and sample variance for samples[lo..hi) via a numerically stable
 * two-pass computation.  *out_n receives the count used.
 */
static void
mean_var_range(const uint64_t *samples, size_t lo, size_t hi, double *out_mean,
               double *out_var, size_t *out_n)
{
    size_t i, n = (hi > lo) ? (hi - lo) : 0;
    double sum = 0.0, mean, m2 = 0.0;

    *out_n = n;
    if (n == 0) {
        *out_mean = 0.0;
        *out_var = 0.0;
        return;
    }

    for (i = lo; i < hi; i++)
        sum += (double)samples[i];
    mean = sum / (double)n;

    for (i = lo; i < hi; i++) {
        double d = (double)samples[i] - mean;
        m2 += d * d;
    }
    *out_mean = mean;
    *out_var = (n > 1) ? (m2 / (double)(n - 1)) : 0.0;
}

static size_t
pct_index(size_t n, double pct)
{
    double idx;

    if (pct <= 0.0)
        return 0;
    if (pct >= 100.0)
        return n;
    idx = (pct / 100.0) * (double)n;
    if (idx < 0.0)
        idx = 0.0;
    if (idx > (double)n)
        idx = (double)n;
    return (size_t)idx;
}

double
gy_dudect_runner_t_value(const struct gy_dudect_runner *r, double crop_lo,
                         double crop_hi)
{
    uint64_t *copy[2] = {NULL, NULL};
    double mean[2] = {0, 0};
    double var[2] = {0, 0};
    size_t n[2] = {0, 0};
    double denom;
    int c;

    /*
     * Sort copies of each class so cropping does not disturb the original
     * sample buffers.  Repeated calls (verbose progress prints) re-sort each
     * time; cheap enough for a manual tool.
     */
    for (c = 0; c < 2; c++) {
        if (r->n[c] < 2)
            return 0.0;
        copy[c] = malloc(r->n[c] * sizeof(uint64_t));
        if (copy[c] == NULL) {
            free(copy[0]);
            free(copy[1]);
            return 0.0;
        }
        memcpy(copy[c], r->s[c], r->n[c] * sizeof(uint64_t));
        qsort(copy[c], r->n[c], sizeof(uint64_t), cmp_u64);
    }

    for (c = 0; c < 2; c++) {
        size_t lo = pct_index(r->n[c], crop_lo);
        size_t hi = pct_index(r->n[c], crop_hi);
        if (hi < lo)
            hi = lo;
        mean_var_range(copy[c], lo, hi, &mean[c], &var[c], &n[c]);
    }

    free(copy[0]);
    free(copy[1]);

    if (n[0] < 2 || n[1] < 2)
        return 0.0;
    denom = sqrt(var[0] / (double)n[0] + var[1] / (double)n[1]);
    if (denom == 0.0)
        return 0.0;
    return (mean[0] - mean[1]) / denom;
}

void
gy_dudect_runner_summary(const struct gy_dudect_runner *r, FILE *out,
                         double t_value, double crop_lo, double crop_hi)
{
    int c;

    for (c = 0; c < 2; c++) {
        uint64_t *copy;
        double mean, var, sd;
        size_t lo, hi, n;

        if (r->n[c] < 2) {
            fprintf(out, "  class %c: n=%zu (insufficient)\n",
                    c == 0 ? 'A' : 'B', r->n[c]);
            continue;
        }
        copy = malloc(r->n[c] * sizeof(uint64_t));
        if (copy == NULL)
            continue;
        memcpy(copy, r->s[c], r->n[c] * sizeof(uint64_t));
        qsort(copy, r->n[c], sizeof(uint64_t), cmp_u64);

        lo = pct_index(r->n[c], crop_lo);
        hi = pct_index(r->n[c], crop_hi);
        if (hi < lo)
            hi = lo;
        mean_var_range(copy, lo, hi, &mean, &var, &n);
        sd = sqrt(var);
        fprintf(out,
                "  class %c: mu=%.2f sigma=%.2f n=%zu (raw=%zu cropped=%zu)\n",
                c == 0 ? 'A' : 'B', mean, sd, n, r->n[c], r->n[c] - n);
        free(copy);
    }
    fprintf(out, "  crop window: [%.2f%%, %.2f%%]\n", crop_lo, crop_hi);
    fprintf(out, "  |t| = %.2f\n", fabs(t_value));
}
