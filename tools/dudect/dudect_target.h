/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef DUDECT_TARGET_H
#define DUDECT_TARGET_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Descriptor for a function under timing validation.
 *
 * setup_class(cls, state)
 *   Fills `state` with the inputs for class A (cls=0) or B (cls=1).
 *   Called once per trial, outside the timer window.  Setup work
 *   (key schedule, allocation) belongs here, not in run().
 *
 * run(state)
 *   The function being measured.  Called reps_per_trial times in a
 *   tight loop inside the timer window.  Must perform a visible
 *   side effect on each call (write to a volatile sink) so the
 *   compiler cannot dead-code-eliminate the body.
 *
 * state_size
 *   Bytes the harness allocates and zeros before each setup_class.
 *
 * reps_per_trial
 *   Inner-loop count.  Sized so total trial wall time exceeds the
 *   per-trial timer granularity by a comfortable margin (target
 *   ~10 us total).
 */
typedef struct dudect_target {
    const char *name;
    void (*setup_class)(int cls, void *state);
    void (*run)(const void *state);
    size_t state_size;
    int reps_per_trial;
} dudect_target_t;

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_TARGET_H */
