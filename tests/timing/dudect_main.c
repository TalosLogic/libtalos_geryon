/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * dudect-style timing-validation harness entry point.  Two-class
 * Welch t-test with percentile cropping; see tests/timing/README.md for the
 * method and how to run it locally.  This binary lives outside the merge gate
 * (built only with -DGERYON_BUILD_TIMING=ON) and is invoked manually or from
 * the nightly CI job.  The only CTest-wired path is --selftest, which runs the
 * two sentinels at a reduced sample count and confirms the harness itself
 * discriminates a leak from a clean function.
 */
#include "dudect_platform.h"
#include "dudect_runner.h"
#include "dudect_target.h"
#include "dudect_timer.h"

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Defaults: |t| < 10 over >= 1e6 measurements (5e5 per class)
 * is a pass.  Cropping the extreme percentiles removes scheduler/interrupt
 * outliers that would otherwise dominate the variance.
 */
#define DEFAULT_SAMPLES 500000
#define DEFAULT_CROP_LO 1.0
#define DEFAULT_CROP_HI 99.0
#define T_THRESHOLD 10.0
#define PASS_MIN_SAMPLES 500000

/* Reduced sample count for the bounded --selftest run. */
#define SELFTEST_SAMPLES 50000

extern const struct gy_dudect_target target_sentinel_leak;
extern const struct gy_dudect_target target_sentinel_clean;
extern const struct gy_dudect_target target_const_memcmp;
extern const struct gy_dudect_target target_x25519;
extern const struct gy_dudect_target target_xeddsa_sign;
extern const struct gy_dudect_target target_aead_tag;
extern const struct gy_dudect_target target_kdf_ctr;
extern const struct gy_dudect_target target_dr_tag;
extern const struct gy_dudect_target target_he_tag;
extern const struct gy_dudect_target target_he_recv;
extern const struct gy_dudect_target target_hybrid_x3dh;

static const struct gy_dudect_target *const target_registry[] = {
    &target_sentinel_leak, &target_sentinel_clean, &target_const_memcmp,
    &target_x25519,        &target_xeddsa_sign,    &target_aead_tag,
    &target_kdf_ctr,       &target_dr_tag,         &target_he_tag,
    &target_he_recv,       &target_hybrid_x3dh,    NULL,
};

static volatile sig_atomic_t g_stop = 0;

static void
on_sigint(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  --target NAME    run only the named target\n"
            "  --all            run every registered target (default)\n"
            "  --list           list registered targets and exit\n"
            "  --selftest       run the sentinels only and verify the harness\n"
            "                   detects a leak (bounded; used by CTest)\n"
            "  --samples N      max samples per class (default %d)\n"
            "  --reps N         override reps_per_trial for all targets\n"
            "  --crop-lo PCT    lower crop percentile (default %.1f)\n"
            "  --crop-hi PCT    upper crop percentile (default %.1f)\n"
            "  --cpu N          pin to CPU core N (default 0; Linux only)\n"
            "  --no-pin         skip CPU pinning entirely\n"
            "  --verbose        print running |t| every 10%% of progress\n"
            "  --help           this message\n"
            "\n"
            "For best results disable frequency scaling first:\n"
            "  sudo cpupower frequency-set -g performance\n",
            prog, DEFAULT_SAMPLES, DEFAULT_CROP_LO, DEFAULT_CROP_HI);
}

static const struct gy_dudect_target *
lookup(const char *name)
{
    size_t i;

    for (i = 0; target_registry[i] != NULL; i++) {
        if (strcmp(target_registry[i]->name, name) == 0)
            return target_registry[i];
    }
    return NULL;
}

/*
 * Run one target and, if out_abs_t is non-NULL, store the final |t|.  Returns
 * 0 PASS, 1 FAIL, 2 INCONCLUSIVE.  A verdict is FAIL as soon as |t| exceeds
 * the threshold; PASS additionally requires the sample floor so a short run
 * cannot certify a target as clean.
 */
static int
run_target(const struct gy_dudect_target *t, size_t samples_per_class,
           int reps_override, double crop_lo, double crop_hi, int verbose,
           double *out_abs_t)
{
    struct gy_dudect_runner r;
    void *state;
    size_t total_trials, verbose_step, trial, nmin, nA, nB;
    double tv, abs_tv;
    int reps, w, i, verdict;
    const char *verdict_str;

    reps = (reps_override > 0) ? reps_override : t->reps_per_trial;

    if (gy_dudect_runner_init(&r, samples_per_class) != 0) {
        fprintf(stderr, "  ERROR: allocation failed for %s\n", t->name);
        return 2;
    }
    state = calloc(1, t->state_size ? t->state_size : 1);
    if (state == NULL) {
        fprintf(stderr, "  ERROR: state alloc failed for %s\n", t->name);
        gy_dudect_runner_free(&r);
        return 2;
    }

    /* Warm caches and the branch predictor before recording. */
    for (w = 0; w < 1000 && !g_stop; w++) {
        int cls = w & 1;
        t->setup_class(cls, state);
        (void)gy_dudect_now_ticks();
        for (i = 0; i < reps; i++)
            t->run(state);
        (void)gy_dudect_now_ticks();
    }

    fprintf(stdout, "geryon-dudect: %s (reps=%d, target samples/class=%zu)\n",
            t->name, reps, samples_per_class);
    fflush(stdout);

    total_trials = samples_per_class * 2;
    verbose_step = (total_trials >= 10) ? (total_trials / 10) : 1;

    for (trial = 0; trial < total_trials && !g_stop; trial++) {
        int cls = (int)(trial & 1);
        uint64_t t0, t1;

        t->setup_class(cls, state);
        t0 = gy_dudect_now_ticks();
        for (i = 0; i < reps; i++)
            t->run(state);
        t1 = gy_dudect_now_ticks();

        if (gy_dudect_runner_observe(&r, cls, t1 - t0) != 0)
            break; /* One class filled up. */

        if (verbose && (trial + 1) % verbose_step == 0) {
            double v = gy_dudect_runner_t_value(&r, crop_lo, crop_hi);
            fprintf(stdout, "  [%6.1f%%] nA=%zu nB=%zu |t|=%.2f\n",
                    100.0 * (double)(trial + 1) / (double)total_trials,
                    gy_dudect_runner_samples(&r, 0),
                    gy_dudect_runner_samples(&r, 1), v < 0 ? -v : v);
            fflush(stdout);
        }
    }

    tv = gy_dudect_runner_t_value(&r, crop_lo, crop_hi);
    gy_dudect_runner_summary(&r, stdout, tv, crop_lo, crop_hi);

    nA = gy_dudect_runner_samples(&r, 0);
    nB = gy_dudect_runner_samples(&r, 1);
    nmin = (nA < nB) ? nA : nB;
    abs_tv = tv < 0 ? -tv : tv;

    if (abs_tv > T_THRESHOLD) {
        verdict = 1;
        verdict_str = "FAIL";
    } else if (nmin >= PASS_MIN_SAMPLES) {
        verdict = 0;
        verdict_str = "PASS";
    } else {
        verdict = 2;
        verdict_str = "INCONCLUSIVE";
    }
    fprintf(stdout, "  verdict: %s (threshold %.1f)\n\n", verdict_str,
            T_THRESHOLD);

    if (out_abs_t != NULL)
        *out_abs_t = abs_tv;

    free(state);
    gy_dudect_runner_free(&r);
    return verdict;
}

/*
 * Bounded harness self-check for CTest.  The leaky sentinel must exceed the
 * threshold and the clean sentinel must not; anything else means the harness
 * cannot be trusted to validate the real targets.  Returns 0 on success.
 */
static int
run_selftest(double crop_lo, double crop_hi, int verbose)
{
    double leak_t = 0.0, clean_t = 0.0;

    run_target(&target_sentinel_leak, SELFTEST_SAMPLES, 0, crop_lo, crop_hi,
               verbose, &leak_t);
    run_target(&target_sentinel_clean, SELFTEST_SAMPLES, 0, crop_lo, crop_hi,
               verbose, &clean_t);

    fprintf(stdout,
            "selftest: leak |t|=%.2f (want > %.1f), clean |t|=%.2f "
            "(want <= %.1f)\n",
            leak_t, T_THRESHOLD, clean_t, T_THRESHOLD);

    if (leak_t <= T_THRESHOLD) {
        fprintf(stderr, "selftest FAILED: leaky sentinel was not detected\n");
        return 1;
    }
    if (clean_t > T_THRESHOLD) {
        fprintf(stderr, "selftest FAILED: clean sentinel flagged as leaky\n");
        return 1;
    }
    fprintf(stdout, "selftest PASSED\n");
    return 0;
}

int
main(int argc, char **argv)
{
    const char *target_name = NULL;
    size_t samples = DEFAULT_SAMPLES;
    double crop_lo = DEFAULT_CROP_LO;
    double crop_hi = DEFAULT_CROP_HI;
    int run_all = 1, list_only = 0, selftest = 0, reps_override = 0;
    int verbose = 0, pin_cpu = 0, do_pin = 1;
    int any_fail = 0, any_inconclusive = 0, i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "--list") == 0) {
            list_only = 1;
        } else if (strcmp(a, "--selftest") == 0) {
            selftest = 1;
        } else if (strcmp(a, "--all") == 0) {
            run_all = 1;
            target_name = NULL;
        } else if (strcmp(a, "--target") == 0 && i + 1 < argc) {
            target_name = argv[++i];
            run_all = 0;
        } else if (strcmp(a, "--samples") == 0 && i + 1 < argc) {
            samples = (size_t)strtoull(argv[++i], NULL, 10);
        } else if (strcmp(a, "--reps") == 0 && i + 1 < argc) {
            reps_override = atoi(argv[++i]);
        } else if (strcmp(a, "--crop-lo") == 0 && i + 1 < argc) {
            crop_lo = strtod(argv[++i], NULL);
        } else if (strcmp(a, "--crop-hi") == 0 && i + 1 < argc) {
            crop_hi = strtod(argv[++i], NULL);
        } else if (strcmp(a, "--cpu") == 0 && i + 1 < argc) {
            pin_cpu = atoi(argv[++i]);
        } else if (strcmp(a, "--no-pin") == 0) {
            do_pin = 0;
        } else if (strcmp(a, "--verbose") == 0 || strcmp(a, "-v") == 0) {
            verbose = 1;
        } else {
            fprintf(stderr, "unknown option: %s\n\n", a);
            usage(argv[0]);
            return 2;
        }
    }

    if (list_only) {
        printf("Registered targets:\n");
        for (i = 0; target_registry[i] != NULL; i++)
            printf("  %s\n", target_registry[i]->name);
        return 0;
    }

    signal(SIGINT, on_sigint);

    printf("geryon-dudect timing-validation harness\n");
    printf("  timer:   %s\n", gy_dudect_timer_name());
    printf("  crop:    [%.2f%%, %.2f%%]\n", crop_lo, crop_hi);
    printf("  samples: %zu per class\n",
           selftest ? (size_t)SELFTEST_SAMPLES : samples);

    if (do_pin) {
        int pr = gy_dudect_pin_cpu(pin_cpu);
        if (pr == 0)
            printf("  affinity: pinned to CPU %d\n", pin_cpu);
        else if (pr == -1)
            printf("  affinity: (pinning not implemented on this platform)\n");
        else
            printf("  affinity: WARNING -- pinning to CPU %d failed\n",
                   pin_cpu);
    } else {
        printf("  affinity: (skipped via --no-pin)\n");
    }
    gy_dudect_check_governor(stdout);
    printf("\n");

    if (selftest)
        return run_selftest(crop_lo, crop_hi, verbose);

    if (target_name != NULL) {
        const struct gy_dudect_target *t = lookup(target_name);
        int v;
        if (t == NULL) {
            fprintf(stderr, "unknown target: %s (try --list)\n", target_name);
            return 2;
        }
        v = run_target(t, samples, reps_override, crop_lo, crop_hi, verbose,
                       NULL);
        if (v == 1)
            any_fail = 1;
        else if (v == 2)
            any_inconclusive = 1;
    } else if (run_all) {
        for (i = 0; target_registry[i] != NULL && !g_stop; i++) {
            int v = run_target(target_registry[i], samples, reps_override,
                               crop_lo, crop_hi, verbose, NULL);
            if (v == 1)
                any_fail = 1;
            else if (v == 2)
                any_inconclusive = 1;
        }
    }

    if (any_fail)
        return 1;
    if (any_inconclusive)
        return 2;
    return 0;
}
