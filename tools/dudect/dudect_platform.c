/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Platform-specific affinity, governor preflight, and reps scaling.
 * Phase B implements the Linux path; Phase C adds the macOS path.
 */
#define _GNU_SOURCE

#include "dudect_platform.h"

#include <stdio.h>
#include <string.h>

#if defined(__linux__)

#include <errno.h>
#include <sched.h>

int
voleith_dudect_pin_cpu(int cpu)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        return -2;
    }
    return 0;
}

void
voleith_dudect_check_governor(FILE *out)
{
    const char *path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor";
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(out, "  governor: (unavailable: %s)\n", path);
        return;
    }
    char buf[64];
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        fprintf(out, "  governor: (read failed)\n");
        return;
    }
    fclose(f);

    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) {
        buf[--n] = '\0';
    }

    fprintf(out, "  governor: %s\n", buf);
    if (strcmp(buf, "performance") != 0 && strcmp(buf, "userspace") != 0) {
        fprintf(out,
                "  WARNING: CPU governor is not 'performance' or 'userspace'.\n"
                "           Frequency scaling will add large timing noise.\n"
                "           Run: sudo cpupower frequency-set -g performance\n");
    }
}

#elif defined(__APPLE__) && defined(__aarch64__)

#include <mach/mach.h>
#include <mach/thread_policy.h>
#include <pthread.h>

int
voleith_dudect_pin_cpu(int cpu)
{
    (void)cpu;
    /* macOS does not expose per-core pinning from userspace.  Set an
     * affinity tag to encourage the scheduler to keep this thread on
     * the same physical cluster between trials, and request
     * USER_INTERACTIVE QoS to bias toward P-cores and away from the
     * E-core cluster (whose lower frequency and different power domain
     * adds inter-class timing noise).  Both are advisory hints only.
     */
    thread_affinity_policy_data_t policy = {.affinity_tag = 1};
    thread_policy_set(mach_thread_self(), THREAD_AFFINITY_POLICY,
                      (thread_policy_t)&policy, THREAD_AFFINITY_POLICY_COUNT);
    pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0);
    return 0;
}

void
voleith_dudect_check_governor(FILE *out)
{
    fprintf(out,
            "  governor: (macOS: no user-space frequency governor;\n"
            "             P/E-core migration adds noise - run on a quiet\n"
            "             host with no other workloads for best results)\n");
}

#else /* unknown platform */

int
voleith_dudect_pin_cpu(int cpu)
{
    (void)cpu;
    return -1;
}

void
voleith_dudect_check_governor(FILE *out)
{
    (void)out;
}

#endif

/* ---- reps scaling ---- */

/*
 * Returns a multiplier applied to each target's reps_per_trial when
 * --reps is not specified.  The intent (Phase C, C3) is to ensure
 * per-trial wall time stays well above the timer's granularity.
 *
 * On x86_64 / Linux, RDTSCP gives cycle-level resolution; reps_per_trial
 * values were tuned for that baseline and no scaling is needed.
 *
 * On Apple Silicon, CNTVCT_EL0 ticks at 24 MHz (~41.7 ns/tick).  The
 * existing reps values produce per-trial durations of:
 *   sentinel:     2000 reps × ~15 ns  = ~30 μs  → ~720 ticks
 *   aes_ct64:      200 reps × ~10 μs  = ~2 ms   >> adequate
 *   field_mul:    1000 reps × ~100 ns = ~100 μs → ~2400 ticks
 *   byte_combine: 2000 reps × ~200 ns = ~400 μs >> adequate
 * All are substantially above the 10 μs target from the design doc, so
 * scale = 1 is correct.  If a future target has much lower latency,
 * add a platform-specific case here rather than inflating reps globally.
 */
int
voleith_dudect_default_reps_scale(void)
{
    return 1;
}
