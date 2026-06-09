/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_soft.c - Software Groestl permutations via the bitsliced AES S-box.
 *
 * Always compiled; provides the universal constant-time fallback when neither
 * AES-NI nor ARMv8 Crypto Extension is available.  SubBytes is handled by
 * aes_ct64_sbox_inplace_4blocks, which runs the Canright tower-field S-box
 * in bitsliced form over 64 input bytes at a time.
 */

#include "grostl_dispatch.h"
#include "aes_ct64.h"

/* ================================================================
 * ShiftBytes vectors (spec SS3.4.4 + Round3Mods SS2.1.1 / SS2.2.1).
 * ================================================================ */

static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* ================================================================
 * SubBytes: AES S-box applied byte-wise to the full state.
 *
 * The bitsliced engine processes 64 bytes per call.  For the 128-byte
 * Groestl-512 state, two calls cover the first and second halves.
 * ================================================================ */

static inline void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    aes_ct64_sbox_inplace_4blocks(state);
}

static void
sub_bytes_512(uint8_t state[GROSTL_STATE_BYTES_256])
{
    grostl_sbox_inplace_64bytes(state);
}

static void
sub_bytes_1024(uint8_t state[GROSTL_STATE_BYTES_512])
{
    grostl_sbox_inplace_64bytes(state);
    grostl_sbox_inplace_64bytes(state + GROSTL_STATE_BYTES_256);
}

/* ================================================================
 * Permutations: R = MixBytes o ShiftBytes o SubBytes o AddRoundConstant.
 * ================================================================ */

static void
grostl_soft_p512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_p(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_P512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_soft_q512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_q(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_Q512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_soft_p1024(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_p(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_P1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

static void
grostl_soft_q1024(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_q(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_Q1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

/* ================================================================
 * Ops table.
 * ================================================================ */

const voleith_grostl_ops_t voleith_grostl_ops_soft = {
    .p512 = grostl_soft_p512,
    .q512 = grostl_soft_q512,
    .p1024 = grostl_soft_p1024,
    .q1024 = grostl_soft_q1024,
    .name = "soft",
};
