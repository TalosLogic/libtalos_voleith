/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * voleith_byte_combine constant-time validation.  The function
 * combines 8 secret bytes into a single GF(2^lambda) element using
 * powers of the alpha_8 generator.  The constant-time rewrite (C-3
 * from the security review) replaced the original
 * secret-conditional XOR with a bitmask-conditional XOR plus an
 * optimiser barrier; dudect verifies no measurable side channel
 * was reintroduced by the compiler.
 *
 * Class A: x = {0x00, 0x00, ..., 0x00}
 * Class B: x = {0xFF, 0xFF, ..., 0xFF}
 *
 * Every bit position contributes (or doesn't) a corresponding
 * alpha power; if any bitmask conditional survived as a branch
 * the harness would surface it.
 */
#include "dudect_target.h"

#include "field.h"

#include <stdint.h>
#include <string.h>

static volatile uint8_t bc_target_sink;

typedef struct {
    uint8_t x[8];
} bc_state_t;

static void
bc_setup(int cls, void *state)
{
    bc_state_t *s = (bc_state_t *)state;
    memset(s->x, cls ? 0xFF : 0x00, sizeof(s->x));
}

/* Lambda is encoded in the run callback; one descriptor per lambda. */

static void
bc128_run(const void *state)
{
    const bc_state_t *s = (const bc_state_t *)state;
    uint8_t out[16];
    voleith_byte_combine(out, s->x, 128);
    bc_target_sink ^= out[0] ^ out[15];
}

static void
bc192_run(const void *state)
{
    const bc_state_t *s = (const bc_state_t *)state;
    uint8_t out[24];
    voleith_byte_combine(out, s->x, 192);
    bc_target_sink ^= out[0] ^ out[23];
}

static void
bc256_run(const void *state)
{
    const bc_state_t *s = (const bc_state_t *)state;
    uint8_t out[32];
    voleith_byte_combine(out, s->x, 256);
    bc_target_sink ^= out[0] ^ out[31];
}

const dudect_target_t target_voleith_byte_combine_128 = {
    .name = "voleith_byte_combine_128",
    .setup_class = bc_setup,
    .run = bc128_run,
    .state_size = sizeof(bc_state_t),
    .reps_per_trial = 2000,
};

const dudect_target_t target_voleith_byte_combine_192 = {
    .name = "voleith_byte_combine_192",
    .setup_class = bc_setup,
    .run = bc192_run,
    .state_size = sizeof(bc_state_t),
    .reps_per_trial = 2000,
};

const dudect_target_t target_voleith_byte_combine_256 = {
    .name = "voleith_byte_combine_256",
    .setup_class = bc_setup,
    .run = bc256_run,
    .state_size = sizeof(bc_state_t),
    .reps_per_trial = 2000,
};
