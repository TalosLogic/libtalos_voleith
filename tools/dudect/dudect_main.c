/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * dudect harness entry point.  See the dudect timing-validation design
 * for methodology and acceptance criteria.
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

#define DEFAULT_SAMPLES 200000
#define DEFAULT_CROP_LO 1.0
#define DEFAULT_CROP_HI 99.0
#define T_THRESHOLD 4.5

/* Target registry.  Each target file exports one descriptor symbol;
 * add it here to make it discoverable by name.
 */
extern const dudect_target_t target_sentinel_leak;
extern const dudect_target_t target_sentinel_clean;
extern const dudect_target_t target_voleith_gf128_mul;
extern const dudect_target_t target_voleith_gf192_mul;
extern const dudect_target_t target_voleith_gf256_mul;
extern const dudect_target_t target_voleith_byte_combine_128;
extern const dudect_target_t target_voleith_byte_combine_192;
extern const dudect_target_t target_voleith_byte_combine_256;
extern const dudect_target_t target_voleith_grostl256_gf8_build_witness_msg;
extern const dudect_target_t target_voleith_ec_matrix_invert_ct;
extern const dudect_target_t target_voleith_confrlnc_permute;
extern const dudect_target_t target_voleith_confrlnc_permute_inverse;
extern const dudect_target_t target_voleith_perm_gf16_route;
extern const dudect_target_t target_voleith_confrlnc_validate_key;
extern const dudect_target_t target_voleith_confrlnc_keygen;
extern const dudect_target_t target_voleith_rs_epoch_keygen;
extern const dudect_target_t target_voleith_rs_epoch_state_advance;
extern const dudect_target_t target_voleith_rs_epoch_derive_sk;

static const dudect_target_t *const target_registry[] = {
    &target_sentinel_leak,
    &target_sentinel_clean,
    &target_voleith_gf128_mul,
    &target_voleith_gf192_mul,
    &target_voleith_gf256_mul,
    &target_voleith_byte_combine_128,
    &target_voleith_byte_combine_192,
    &target_voleith_byte_combine_256,
    &target_voleith_grostl256_gf8_build_witness_msg,
    &target_voleith_ec_matrix_invert_ct,
    &target_voleith_confrlnc_permute,
    &target_voleith_confrlnc_permute_inverse,
    &target_voleith_perm_gf16_route,
    &target_voleith_confrlnc_validate_key,
    &target_voleith_confrlnc_keygen,
    &target_voleith_rs_epoch_keygen,
    &target_voleith_rs_epoch_state_advance,
    &target_voleith_rs_epoch_derive_sk,
    NULL,
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
            "  --target NAME      run only the named target\n"
            "  --all              run every registered target (default)\n"
            "  --list             list registered targets and exit\n"
            "  --samples N        max samples per class (default %d)\n"
            "  --reps N           override reps_per_trial for all targets\n"
            "  --crop-lo PCT      lower crop percentile (default %.1f)\n"
            "  --crop-hi PCT      upper crop percentile (default %.1f)\n"
            "  --cpu N            pin to CPU core N (default 0; Linux only)\n"
            "  --no-pin           skip CPU pinning entirely\n"
            "  --verbose          print running |t| every 10%% of progress\n"
            "  --help             this message\n"
            "\n"
            "For best results disable frequency scaling first:\n"
            "  sudo cpupower frequency-set -g performance\n",
            prog, DEFAULT_SAMPLES, DEFAULT_CROP_LO, DEFAULT_CROP_HI);
}

static const dudect_target_t *
lookup(const char *name)
{
    for (size_t i = 0; target_registry[i]; i++) {
        if (strcmp(target_registry[i]->name, name) == 0) {
            return target_registry[i];
        }
    }
    return NULL;
}

/* Returns: 0 PASS, 1 FAIL, 2 INCONCLUSIVE. */
static int
run_target(const dudect_target_t *t, size_t samples_per_class,
           int reps_override, double crop_lo, double crop_hi, int verbose)
{
    int reps;
    if (reps_override > 0) {
        reps = reps_override;
    } else {
        int scale = voleith_dudect_default_reps_scale();
        reps = t->reps_per_trial * scale;
    }

    dudect_runner_t r;
    if (dudect_runner_init(&r, samples_per_class) != 0) {
        fprintf(stderr, "  ERROR: allocation failed for %s\n", t->name);
        return 2;
    }

    void *state = calloc(1, t->state_size ? t->state_size : 1);
    if (!state) {
        fprintf(stderr, "  ERROR: state alloc failed for %s\n", t->name);
        dudect_runner_free(&r);
        return 2;
    }

    /* Warm up: 1000 throwaway trials (alternating classes) to pull
     * the harness, the timer, and the run() body into I-cache and
     * the branch predictor before recording.
     */
    for (int w = 0; w < 1000 && !g_stop; w++) {
        int cls = w & 1;
        t->setup_class(cls, state);
        (void)voleith_dudect_now_ticks();
        for (int i = 0; i < reps; i++)
            t->run(state);
        (void)voleith_dudect_now_ticks();
    }

    fprintf(stdout, "voleith-dudect: %s (reps=%d, target samples/class=%zu)\n",
            t->name, reps, samples_per_class);
    fflush(stdout);

    size_t total_trials = samples_per_class * 2;
    size_t verbose_step = (total_trials >= 10) ? (total_trials / 10) : 1;

    for (size_t trial = 0; trial < total_trials && !g_stop; trial++) {
        int cls = (int)(trial & 1);
        t->setup_class(cls, state);

        uint64_t t0 = voleith_dudect_now_ticks();
        for (int i = 0; i < reps; i++)
            t->run(state);
        uint64_t t1 = voleith_dudect_now_ticks();

        uint64_t dt = t1 - t0;
        if (dudect_runner_observe(&r, cls, dt) != 0) {
            /* One class filled up; stop. */
            break;
        }

        if (verbose && (trial + 1) % verbose_step == 0) {
            double tv = dudect_runner_t_value(&r, crop_lo, crop_hi);
            fprintf(stdout, "  [%6.1f%%] nA=%zu nB=%zu |t|=%.2f\n",
                    100.0 * (double)(trial + 1) / (double)total_trials,
                    dudect_runner_samples(&r, 0), dudect_runner_samples(&r, 1),
                    tv < 0 ? -tv : tv);
            fflush(stdout);
        }
    }

    double tv = dudect_runner_t_value(&r, crop_lo, crop_hi);
    dudect_runner_summary(&r, stdout, tv, crop_lo, crop_hi);

    size_t nA = dudect_runner_samples(&r, 0);
    size_t nB = dudect_runner_samples(&r, 1);
    size_t nmin = (nA < nB) ? nA : nB;

    int verdict;
    const char *verdict_str;
    double abs_tv = tv < 0 ? -tv : tv;
    if (abs_tv > T_THRESHOLD) {
        verdict = 1;
        verdict_str = "FAIL";
    } else if (nmin >= 100000) {
        verdict = 0;
        verdict_str = "PASS";
    } else {
        verdict = 2;
        verdict_str = "INCONCLUSIVE";
    }
    fprintf(stdout, "  verdict: %s (threshold %.1f)\n\n", verdict_str,
            T_THRESHOLD);

    free(state);
    dudect_runner_free(&r);
    return verdict;
}

int
main(int argc, char **argv)
{
    const char *target_name = NULL;
    int run_all = 1;
    int list_only = 0;
    size_t samples = DEFAULT_SAMPLES;
    int reps_override = 0;
    double crop_lo = DEFAULT_CROP_LO;
    double crop_hi = DEFAULT_CROP_HI;
    int verbose = 0;
    int pin_cpu = 0;
    int do_pin = 1;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else if (strcmp(a, "--list") == 0) {
            list_only = 1;
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
        for (size_t i = 0; target_registry[i]; i++) {
            printf("  %s\n", target_registry[i]->name);
        }
        return 0;
    }

    signal(SIGINT, on_sigint);

    printf("voleith-dudect timing-validation harness\n");
    printf("  timer:   %s\n", voleith_dudect_timer_name());
    printf("  crop:    [%.2f%%, %.2f%%]\n", crop_lo, crop_hi);
    printf("  samples: %zu per class\n", samples);

    if (do_pin) {
        int pr = voleith_dudect_pin_cpu(pin_cpu);
        if (pr == 0) {
            printf("  affinity: pinned to CPU %d\n", pin_cpu);
        } else if (pr == -1) {
            printf("  affinity: (pinning not implemented on this platform)\n");
        } else {
            printf("  affinity: WARNING -- pinning to CPU %d failed\n",
                   pin_cpu);
        }
    } else {
        printf("  affinity: (skipped via --no-pin)\n");
    }
    voleith_dudect_check_governor(stdout);
    printf("\n");

    int any_fail = 0;
    int any_inconclusive = 0;

    if (target_name) {
        const dudect_target_t *t = lookup(target_name);
        if (!t) {
            fprintf(stderr, "unknown target: %s (try --list)\n", target_name);
            return 2;
        }
        int v =
            run_target(t, samples, reps_override, crop_lo, crop_hi, verbose);
        if (v == 1)
            any_fail = 1;
        else if (v == 2)
            any_inconclusive = 1;
    } else if (run_all) {
        for (size_t i = 0; target_registry[i] && !g_stop; i++) {
            int v = run_target(target_registry[i], samples, reps_override,
                               crop_lo, crop_hi, verbose);
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
