/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 */
#ifndef DUDECT_TIMER_H
#define DUDECT_TIMER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Return the current high-resolution timer reading in implementation-
 * defined ticks.  Differences between consecutive readings are
 * meaningful; absolute values are not.  Phase A uses clock_gettime
 * (1 ns ticks).  Phases B and C replace this with RDTSCP / CNTVCT_EL0
 * respectively.
 */
uint64_t voleith_dudect_now_ticks(void);

/* Human-readable name of the active timer source.  Printed in the
 * harness summary so a captured run report identifies which clock
 * produced the numbers.
 */
const char *voleith_dudect_timer_name(void);

#ifdef __cplusplus
}
#endif

#endif /* DUDECT_TIMER_H */
