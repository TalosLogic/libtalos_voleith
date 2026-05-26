/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Phase A sentinel targets.  These exist to validate the harness
 * itself, not to validate any library code.
 *
 *   sentinel_leak  -- a deliberately variable-time function; must
 *                     produce a FAIL verdict (|t| large).
 *   sentinel_clean -- a deliberately constant-time function; must
 *                     produce a PASS verdict (|t| <= 4.5).
 *
 * If either sentinel produces the wrong verdict on the dev box,
 * the harness has a bug and the real targets cannot be trusted.
 */
#include "dudect_target.h"

#include <stdint.h>
#include <string.h>

#define SENTINEL_SECRET_BYTES 32

typedef struct {
    uint8_t secret[SENTINEL_SECRET_BYTES];
} sentinel_state_t;

/* Volatile sink so the compiler cannot eliminate the work being
 * measured.  All sentinel runs xor their accumulator into this.
 */
static volatile uint8_t sentinel_sink;

/* ----- sentinel_leak -------------------------------------------------- */

/* Class A: secret starts with a non-zero byte, so the early-exit
 *          loop runs to the end (slow path).
 * Class B: secret is all zeros, so the loop exits on byte 0 (fast path).
 *
 * The function body branches on the secret value.  That is the leak
 * the harness must detect.
 */
static void
sentinel_leak_setup(int cls, void *state)
{
    sentinel_state_t *s = (sentinel_state_t *)state;
    if (cls == 0) {
        for (int i = 0; i < SENTINEL_SECRET_BYTES; i++) {
            s->secret[i] = (uint8_t)(i + 1);
        }
    } else {
        memset(s->secret, 0, sizeof(s->secret));
    }
}

static void
sentinel_leak_run(const void *state)
{
    const sentinel_state_t *s = (const sentinel_state_t *)state;
    uint8_t acc = 0;
    for (int i = 0; i < SENTINEL_SECRET_BYTES; i++) {
        if (s->secret[i] == 0)
            break;
        acc ^= s->secret[i];
    }
    sentinel_sink ^= acc;
}

const dudect_target_t target_sentinel_leak = {
    .name = "sentinel_leak",
    .setup_class = sentinel_leak_setup,
    .run = sentinel_leak_run,
    .state_size = sizeof(sentinel_state_t),
    .reps_per_trial = 2000,
};

/* ----- sentinel_clean ------------------------------------------------- */

/* Class A: secret = all zeros.
 * Class B: secret = all 0xFF.
 *
 * The function does a fixed-iteration XOR fold.  No branch on the
 * secret; the loop bound is a compile-time constant.  The harness
 * must NOT flag this as a leak.
 */
static void
sentinel_clean_setup(int cls, void *state)
{
    sentinel_state_t *s = (sentinel_state_t *)state;
    uint8_t fill = (cls == 0) ? 0x00 : 0xFF;
    memset(s->secret, fill, sizeof(s->secret));
}

static void
sentinel_clean_run(const void *state)
{
    const sentinel_state_t *s = (const sentinel_state_t *)state;
    uint8_t acc = 0;
    for (int i = 0; i < SENTINEL_SECRET_BYTES; i++) {
        acc ^= s->secret[i];
    }
    sentinel_sink ^= acc;
}

const dudect_target_t target_sentinel_clean = {
    .name = "sentinel_clean",
    .setup_class = sentinel_clean_setup,
    .run = sentinel_clean_run,
    .state_size = sizeof(sentinel_state_t),
    .reps_per_trial = 2000,
};
