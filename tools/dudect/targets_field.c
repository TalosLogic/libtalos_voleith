/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Constant-time software field-multiplication targets.  Validates
 * that voleith_gf{128,192,256}_mul -- when compiled WITHOUT CLMUL /
 * PMULL hardware acceleration -- exhibits no secret-dependent
 * runtime variation.
 *
 * Class A: a = fixed non-zero value, b = all-zero word.
 * Class B: a = same as A,            b = all-ones word.
 *
 * Multiplying by zero exercises no bit-XOR steps in the
 * constant-time loop body; multiplying by all-ones exercises every
 * step.  If the bitmask-conditional XOR replacement leaked at all
 * the harness would catch it here.
 *
 * gf8_mul and gf64_mul are subsumed by the larger fields (they
 * are called transitively and have less surface area), so they
 * are not separately measured.
 */
#include "dudect_target.h"

#include "field.h"

#include <stdint.h>
#include <string.h>

static volatile uint64_t field_target_sink;

/* ----- GF(2^128) ----------------------------------------------------- */

typedef struct {
    voleith_gf128_t a, b;
} gf128_state_t;

static void
gf128_mul_setup(int cls, void *state)
{
    gf128_state_t *s = (gf128_state_t *)state;
    s->a.v[0] = 0x0123456789abcdefULL;
    s->a.v[1] = 0xfedcba9876543210ULL;
    if (cls == 0) {
        s->b.v[0] = 0;
        s->b.v[1] = 0;
    } else {
        s->b.v[0] = ~(uint64_t)0;
        s->b.v[1] = ~(uint64_t)0;
    }
}

static void
gf128_mul_run(const void *state)
{
    const gf128_state_t *s = (const gf128_state_t *)state;
    voleith_gf128_t c;
    voleith_gf128_mul(&c, &s->a, &s->b);
    field_target_sink ^= c.v[0] ^ c.v[1];
}

const dudect_target_t target_voleith_gf128_mul = {
    .name = "voleith_gf128_mul",
    .setup_class = gf128_mul_setup,
    .run = gf128_mul_run,
    .state_size = sizeof(gf128_state_t),
    .reps_per_trial = 1000,
};

/* ----- GF(2^192) ----------------------------------------------------- */

typedef struct {
    voleith_gf192_t a, b;
} gf192_state_t;

static void
gf192_mul_setup(int cls, void *state)
{
    gf192_state_t *s = (gf192_state_t *)state;
    s->a.v[0] = 0x0123456789abcdefULL;
    s->a.v[1] = 0xfedcba9876543210ULL;
    s->a.v[2] = 0x55aa55aa55aa55aaULL;
    if (cls == 0) {
        s->b.v[0] = 0;
        s->b.v[1] = 0;
        s->b.v[2] = 0;
    } else {
        s->b.v[0] = ~(uint64_t)0;
        s->b.v[1] = ~(uint64_t)0;
        s->b.v[2] = ~(uint64_t)0;
    }
}

static void
gf192_mul_run(const void *state)
{
    const gf192_state_t *s = (const gf192_state_t *)state;
    voleith_gf192_t c;
    voleith_gf192_mul(&c, &s->a, &s->b);
    field_target_sink ^= c.v[0] ^ c.v[1] ^ c.v[2];
}

const dudect_target_t target_voleith_gf192_mul = {
    .name = "voleith_gf192_mul",
    .setup_class = gf192_mul_setup,
    .run = gf192_mul_run,
    .state_size = sizeof(gf192_state_t),
    .reps_per_trial = 1000,
};

/* ----- GF(2^256) ----------------------------------------------------- */

typedef struct {
    voleith_gf256_t a, b;
} gf256_state_t;

static void
gf256_mul_setup(int cls, void *state)
{
    gf256_state_t *s = (gf256_state_t *)state;
    s->a.v[0] = 0x0123456789abcdefULL;
    s->a.v[1] = 0xfedcba9876543210ULL;
    s->a.v[2] = 0x55aa55aa55aa55aaULL;
    s->a.v[3] = 0xaa55aa55aa55aa55ULL;
    if (cls == 0) {
        memset(&s->b, 0, sizeof(s->b));
    } else {
        s->b.v[0] = ~(uint64_t)0;
        s->b.v[1] = ~(uint64_t)0;
        s->b.v[2] = ~(uint64_t)0;
        s->b.v[3] = ~(uint64_t)0;
    }
}

static void
gf256_mul_run(const void *state)
{
    const gf256_state_t *s = (const gf256_state_t *)state;
    voleith_gf256_t c;
    voleith_gf256_mul(&c, &s->a, &s->b);
    field_target_sink ^= c.v[0] ^ c.v[1] ^ c.v[2] ^ c.v[3];
}

const dudect_target_t target_voleith_gf256_mul = {
    .name = "voleith_gf256_mul",
    .setup_class = gf256_mul_setup,
    .run = gf256_mul_run,
    .state_size = sizeof(gf256_state_t),
    .reps_per_trial = 1000,
};
