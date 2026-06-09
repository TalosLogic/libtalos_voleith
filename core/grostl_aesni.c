/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_aesni.c - x86 AES-NI Groestl permutations.
 *
 * Compiled only when VOLEITH_HAVE_AES_NI is defined; the entire file is
 * guarded so a build without AES-NI compiles this TU to an empty object.
 *
 * SubBytes uses _mm_aesenclast_si128 with a zero round key to apply the
 * AES S-box, then _mm_shuffle_epi8 with the forward ShiftRows permutation
 * to undo the ShiftRows that the instruction additionally performs.  See
 * the comment in the original grostl.c for the derivation.
 */

#ifdef VOLEITH_HAVE_AES_NI

#include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 (pshufb) */
#include <wmmintrin.h> /* AES-NI _mm_aesenclast_si128 */

#include "grostl_dispatch.h"

/* ================================================================
 * ShiftBytes vectors.
 * ================================================================ */

static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* ================================================================
 * SubBytes: AES-NI path.
 *
 * Forward AES ShiftRows sigma, used as a pshufb mask to undo the
 * ShiftRows that _mm_aesenclast_si128 inserts:
 *   out[j] = result[SHIFT_ROWS_MASK[j]] recovers S(input[j]).
 * ================================================================ */

static const uint8_t SHIFT_ROWS_MASK[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};

static inline __m128i
grostl_sbox_block_aesni(__m128i x, __m128i shift_rows_mask)
{
    __m128i sub_then_shift = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return _mm_shuffle_epi8(sub_then_shift, shift_rows_mask);
}

static void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    __m128i mask = _mm_loadu_si128((const __m128i *)SHIFT_ROWS_MASK);
    __m128i b0 = _mm_loadu_si128((const __m128i *)(state + 0));
    __m128i b1 = _mm_loadu_si128((const __m128i *)(state + 16));
    __m128i b2 = _mm_loadu_si128((const __m128i *)(state + 32));
    __m128i b3 = _mm_loadu_si128((const __m128i *)(state + 48));
    b0 = grostl_sbox_block_aesni(b0, mask);
    b1 = grostl_sbox_block_aesni(b1, mask);
    b2 = grostl_sbox_block_aesni(b2, mask);
    b3 = grostl_sbox_block_aesni(b3, mask);
    _mm_storeu_si128((__m128i *)(state + 0), b0);
    _mm_storeu_si128((__m128i *)(state + 16), b1);
    _mm_storeu_si128((__m128i *)(state + 32), b2);
    _mm_storeu_si128((__m128i *)(state + 48), b3);
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
grostl_aesni_p512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_p(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_P512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_aesni_q512(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_q(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_Q512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
grostl_aesni_p1024(uint8_t *state)
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_p(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_P1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

static void
grostl_aesni_q1024(uint8_t *state)
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

const voleith_grostl_ops_t voleith_grostl_ops_aesni = {
    .p512 = grostl_aesni_p512,
    .q512 = grostl_aesni_q512,
    .p1024 = grostl_aesni_p1024,
    .q1024 = grostl_aesni_q1024,
    .name = "aesni",
};

#endif /* VOLEITH_HAVE_AES_NI */
