/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef DUDECT_PLATFORM_H
#define DUDECT_PLATFORM_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pin the calling thread to a single CPU core to reduce migration
 * noise.
 *
 * Returns:
 *    0 -- pinned successfully
 *   -1 -- not supported on this platform (logged at startup; harness
 *         continues)
 *   -2 -- supported but the call failed (caller may want to warn)
 */
int voleith_dudect_pin_cpu(int cpu);

/* On Linux, read /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
 * and print the current value to `out`; warn loudly if it is not
 * "performance" or "userspace" because frequency scaling adds large
 * timing noise.  On macOS, prints an advisory noting governor control
 * is unavailable.  No-op on other platforms.
 */
void voleith_dudect_check_governor(FILE *out);

/* Returns a multiplier to apply to each target's reps_per_trial so that
 * per-trial wall time stays well above the platform timer's granularity.
 * Currently 1 on all platforms (existing reps values are already adequate
 * for the 10 μs per-trial target on both x86_64 and Apple Silicon).
 */
int voleith_dudect_default_reps_scale(void);

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_PLATFORM_H */
