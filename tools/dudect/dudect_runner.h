/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef DUDECT_RUNNER_H
#define DUDECT_RUNNER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Two-class sample accumulator for Welch's t-test with percentile
 * cropping.  Phase A stores all samples (cap per class) in memory;
 * the t-value is computed from the cropped sample arrays at
 * summary time.  At cap = 1e6 per class this is 16 MB total, which
 * is fine for a tool that runs outside CI.
 */
typedef struct dudect_runner {
    size_t cap;
    size_t n[2];
    uint64_t *s[2];
} dudect_runner_t;

/* Returns 0 on success, -1 on allocation failure. */
int dudect_runner_init(dudect_runner_t *r, size_t max_samples_per_class);

/* Returns 0 if the sample was stored, -1 if the buffer for `cls`
 * is full.  Callers should treat -1 as a signal to stop sampling.
 */
int dudect_runner_observe(dudect_runner_t *r, int cls, uint64_t ticks);

/* Compute Welch's two-sample t-statistic.  crop_lo and crop_hi
 * are percentiles in [0, 100], applied symmetrically to both
 * classes after sorting.  Pass crop_lo=0, crop_hi=100 for no
 * cropping.  Returns 0.0 if either class has fewer than 2 samples
 * after cropping.
 */
double dudect_runner_t_value(const dudect_runner_t *r, double crop_lo,
                             double crop_hi);

/* Print the per-class summary, the cropping range used, and the
 * t-value.  Verdict (PASS/FAIL/INCONCLUSIVE) is decided by the
 * caller; this just formats numbers.
 */
void dudect_runner_summary(const dudect_runner_t *r, FILE *out, double t_value,
                           double crop_lo, double crop_hi);

size_t dudect_runner_samples(const dudect_runner_t *r, int cls);

void dudect_runner_free(dudect_runner_t *r);

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_RUNNER_H */
