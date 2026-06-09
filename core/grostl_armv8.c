/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_armv8.c - ARMv8 Crypto Extension Groestl permutations.
 *
 * Compiled only when VOLEITH_HAVE_ARMV8_AES is defined; the entire file is
 * guarded so a build without ARMv8 Crypto Extension compiles this TU to an
 * empty object.
 *
 * SubBytes uses vaeseq_u8 with a zero key to apply the AES S-box, then
 * vqtbl1q_u8 with the forward ShiftRows permutation to undo the ShiftRows
 * that the instruction additionally performs.  See the comment in the
 * original grostl.c for the derivation.
 */

#ifdef VOLEITH_HAVE_ARMV8_AES

#include <arm_neon.h>

#include "grostl_dispatch.h"

/* ================================================================
 * ShiftBytes vectors.
 * ================================================================ */

static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* ================================================================
 * SubBytes: ARMv8 path.
 *
 * Forward AES ShiftRows sigma, used as a vqtbl1q mask to undo the
 * ShiftRows that vaeseq_u8 inserts:
 *   out[j] = result[SHIFT_ROWS_MASK[j]] recovers S(input[j]).
 * ================================================================ */

static const uint8_t SHIFT_ROWS_MASK[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};

static inline uint8x16_t
grostl_sbox_block_armv8(uint8x16_t x, uint8x16_t shift_rows_mask)
{
    uint8x16_t sub_then_shift = vaeseq_u8(x, vdupq_n_u8(0));
    return vqtbl1q_u8(sub_then_shift, shift_rows_mask);
}

static void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    uint8x16_t mask = vld1q_u8(SHIFT_ROWS_MASK);
    uint8x16_t b0 = vld1q_u8(state + 0);
    uint8x16_t b1 = vld1q_u8(state + 16);
    uint8x16_t b2 = vld1q_u8(state + 32);
    uint8x16_t b3 = vld1q_u8(state + 48);
    b0 = grostl_sbox_block_armv8(b0, mask);
    b1 = grostl_sbox_block_armv8(b1, mask);
    b2 = grostl_sbox_block_armv8(b2, mask);
    b3 = grostl_sbox_block_armv8(b3, mask);
    vst1q_u8(state + 0, b0);
    vst1q_u8(state + 16, b1);
    vst1q_u8(state + 32, b2);
    vst1q_u8(state + 48, b3);
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
 * Permutations.
 * ================================================================ */

static void
grostl_armv8_p512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_p(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_P512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_armv8_q512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_q(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_Q512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_armv8_p1024(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_p(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_P1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

static void
grostl_armv8_q1024(uint8_t *state)
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

const voleith_grostl_ops_t voleith_grostl_ops_armv8 = {
    .p512 = grostl_armv8_p512,
    .q512 = grostl_armv8_q512,
    .p1024 = grostl_armv8_p1024,
    .q1024 = grostl_armv8_q1024,
    .name = "armv8",
};

#endif /* VOLEITH_HAVE_ARMV8_AES */
