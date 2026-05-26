/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "dudect_runner.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

int
dudect_runner_init(dudect_runner_t *r, size_t max_samples_per_class)
{
    memset(r, 0, sizeof(*r));
    r->cap = max_samples_per_class;
    for (int c = 0; c < 2; c++) {
        r->s[c] = (uint64_t *)calloc(max_samples_per_class, sizeof(uint64_t));
        if (!r->s[c]) {
            dudect_runner_free(r);
            return -1;
        }
    }
    return 0;
}

int
dudect_runner_observe(dudect_runner_t *r, int cls, uint64_t ticks)
{
    if (cls < 0 || cls > 1)
        return -1;
    if (r->n[cls] >= r->cap)
        return -1;
    r->s[cls][r->n[cls]++] = ticks;
    return 0;
}

size_t
dudect_runner_samples(const dudect_runner_t *r, int cls)
{
    return (cls == 0 || cls == 1) ? r->n[cls] : 0;
}

void
dudect_runner_free(dudect_runner_t *r)
{
    for (int c = 0; c < 2; c++) {
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

/* Return mean/variance for samples[lo..hi) using a numerically
 * stable two-pass computation.  *out_n is the count used.
 */
static void
mean_var_range(const uint64_t *samples, size_t lo, size_t hi, double *out_mean,
               double *out_var, size_t *out_n)
{
    size_t n = (hi > lo) ? (hi - lo) : 0;
    *out_n = n;
    if (n == 0) {
        *out_mean = 0.0;
        *out_var = 0.0;
        return;
    }

    double sum = 0.0;
    for (size_t i = lo; i < hi; i++)
        sum += (double)samples[i];
    double mean = sum / (double)n;

    double m2 = 0.0;
    for (size_t i = lo; i < hi; i++) {
        double d = (double)samples[i] - mean;
        m2 += d * d;
    }
    *out_mean = mean;
    *out_var = (n > 1) ? (m2 / (double)(n - 1)) : 0.0;
}

static size_t
pct_index(size_t n, double pct)
{
    if (pct <= 0.0)
        return 0;
    if (pct >= 100.0)
        return n;
    double idx = (pct / 100.0) * (double)n;
    if (idx < 0.0)
        idx = 0.0;
    if (idx > (double)n)
        idx = (double)n;
    return (size_t)idx;
}

double
dudect_runner_t_value(const dudect_runner_t *r, double crop_lo, double crop_hi)
{
    /* Make sorted copies of each class so cropping doesn't disturb
     * the original sample buffers.  Repeated calls (e.g., during
     * verbose progress prints) re-sort each time; cheap enough.
     */
    uint64_t *copy[2] = {NULL, NULL};
    double mean[2] = {0, 0};
    double var[2] = {0, 0};
    size_t n[2] = {0, 0};

    for (int c = 0; c < 2; c++) {
        if (r->n[c] < 2)
            return 0.0;
        copy[c] = (uint64_t *)malloc(r->n[c] * sizeof(uint64_t));
        if (!copy[c]) {
            free(copy[0]);
            free(copy[1]);
            return 0.0;
        }
        memcpy(copy[c], r->s[c], r->n[c] * sizeof(uint64_t));
        qsort(copy[c], r->n[c], sizeof(uint64_t), cmp_u64);
    }

    for (int c = 0; c < 2; c++) {
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
    double denom = sqrt(var[0] / (double)n[0] + var[1] / (double)n[1]);
    if (denom == 0.0)
        return 0.0;
    return (mean[0] - mean[1]) / denom;
}

void
dudect_runner_summary(const dudect_runner_t *r, FILE *out, double t_value,
                      double crop_lo, double crop_hi)
{
    for (int c = 0; c < 2; c++) {
        if (r->n[c] < 2) {
            fprintf(out, "  class %c: n=%zu (insufficient)\n",
                    c == 0 ? 'A' : 'B', r->n[c]);
            continue;
        }
        uint64_t *copy = (uint64_t *)malloc(r->n[c] * sizeof(uint64_t));
        if (!copy)
            continue;
        memcpy(copy, r->s[c], r->n[c] * sizeof(uint64_t));
        qsort(copy, r->n[c], sizeof(uint64_t), cmp_u64);

        size_t lo = pct_index(r->n[c], crop_lo);
        size_t hi = pct_index(r->n[c], crop_hi);
        if (hi < lo)
            hi = lo;
        double mean, var;
        size_t n;
        mean_var_range(copy, lo, hi, &mean, &var, &n);
        double sd = sqrt(var);
        fprintf(out,
                "  class %c: mu=%.2f sigma=%.2f n=%zu (raw=%zu cropped=%zu)\n",
                c == 0 ? 'A' : 'B', mean, sd, n, r->n[c], r->n[c] - n);
        free(copy);
    }
    fprintf(out, "  crop window: [%.2f%%, %.2f%%]\n", crop_lo, crop_hi);
    fprintf(out, "  |t| = %.2f\n", fabs(t_value));
}
