/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_util.h - tiny wall-clock benchmarking helpers shared by the
 * example programs.
 *
 * Methodology note: timing noise on a loaded OS is one-sided slow
 * (preemption, cache misses, page faults, frequency dips only ever make
 * a sample slower).  So the *minimum* is the cleanest estimate of
 * intrinsic cost and the *median* is the typical run; we never trim the
 * fast tail (unlike dudect's symmetric percentile crop, which exists to
 * stabilize a two-sample leakage t-test, not to estimate runtime).
 * Callers should run a few warmup iterations first and discard them.
 *
 * Requires _POSIX_C_SOURCE >= 199309L defined before any include for
 * clock_gettime / CLOCK_MONOTONIC.
 */

#ifndef VOLEITH_EXAMPLES_BENCH_UTIL_H
#define VOLEITH_EXAMPLES_BENCH_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static inline uint64_t
bench_now_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + (uint64_t)t.tv_nsec;
}

typedef struct {
    double min;
    double median;
    double mean;
    double max;
    size_t n;
} bench_stats_t;

static int
bench_cmp_double(const void *a, const void *b)
{
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* Computes stats over `n` millisecond samples.  Sorts `samples` in place. */
static inline bench_stats_t
bench_compute(double *samples, size_t n)
{
    bench_stats_t s = {0, 0, 0, 0, n};
    if (n == 0)
        return s;

    qsort(samples, n, sizeof(double), bench_cmp_double);

    double sum = 0;
    for (size_t i = 0; i < n; i++)
        sum += samples[i];

    s.min = samples[0];
    s.max = samples[n - 1];
    s.mean = sum / (double)n;
    s.median =
        (n & 1u) ? samples[n / 2] : 0.5 * (samples[n / 2 - 1] + samples[n / 2]);
    return s;
}

static inline void
bench_print(const char *label, bench_stats_t s)
{
    printf("  %-8s min %8.4f  median %8.4f  mean %8.4f  max %8.4f ms\n", label,
           s.min, s.median, s.mean, s.max);
}

#endif /* VOLEITH_EXAMPLES_BENCH_UTIL_H */
