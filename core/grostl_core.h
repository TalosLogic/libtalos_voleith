/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_core.h - Shared Groestl constants and pure-software round-function
 * helpers.
 *
 * Included by grostl_aesni.c, grostl_armv8.c, grostl_soft.c, and grostl.c.
 * Not intended for consumers outside core/.
 *
 * All round-function helpers are static inline so that including this header
 * in a TU that does not call them produces no code and no unused-function
 * warnings.
 */

#ifndef VOLEITH_GROSTL_CORE_H
#define VOLEITH_GROSTL_CORE_H

#include <stdint.h>

/* ================================================================
 * State dimensions and round counts.
 * ================================================================ */

#define GROSTL_ROWS 8
#define GROSTL_COLS_256 8
#define GROSTL_COLS_512 16
#define GROSTL_STATE_BYTES_256 (GROSTL_ROWS * GROSTL_COLS_256) /* 64  */
#define GROSTL_STATE_BYTES_512 (GROSTL_ROWS * GROSTL_COLS_512) /* 128 */
#define GROSTL_ROUNDS_256 10
#define GROSTL_ROUNDS_512 14

/* ================================================================
 * Constant-time GF(2^8) multiplication by small constants.
 *
 * Field: x^8 + x^4 + x^3 + x + 1 (0x11b), same as AES/Rijndael.
 *
 * xtime(b) = b * x:
 *   carry = high bit of b, broadcast to all 8 bits as 0xff or 0x00.
 *   result = (b << 1) ^ (carry & 0x1b).
 *
 * Branchless: 0u - (b >> 7) is 0xff..ff if bit 7 is set, else 0.
 * ================================================================ */

static inline uint8_t
gf_xtime(uint8_t b)
{
    uint8_t carry_mask = (uint8_t)(0u - (uint32_t)(b >> 7));
    return (uint8_t)((b << 1) ^ (carry_mask & 0x1b));
}

static inline uint8_t
gf_mul2(uint8_t b)
{
    return gf_xtime(b);
}

static inline uint8_t
gf_mul3(uint8_t b)
{
    return (uint8_t)(gf_xtime(b) ^ b);
}

static inline uint8_t
gf_mul4(uint8_t b)
{
    return gf_xtime(gf_xtime(b));
}

static inline uint8_t
gf_mul5(uint8_t b)
{
    return (uint8_t)(gf_mul4(b) ^ b);
}

static inline uint8_t
gf_mul7(uint8_t b)
{
    return (uint8_t)(gf_mul4(b) ^ gf_xtime(b) ^ b);
}

/* ================================================================
 * AddRoundConstant.
 *
 * P: only row 0 is altered; column c contributes (c<<4) ^ round.
 * Q: rows 0..6 are XORed with 0xff; row 7 column c is XORed with
 *    (0xff ^ (c<<4) ^ round).
 * ================================================================ */

static inline void
add_round_constant_p(uint8_t *state, int columns, uint8_t round)
{
    for (int c = 0; c < columns; c++)
        state[0 + GROSTL_ROWS * c] ^= (uint8_t)((c << 4) ^ round);
}

static inline void
add_round_constant_q(uint8_t *state, int columns, uint8_t round)
{
    for (int c = 0; c < columns; c++) {
        for (int r = 0; r < GROSTL_ROWS - 1; r++)
            state[r + GROSTL_ROWS * c] ^= 0xff;
        state[(GROSTL_ROWS - 1) + GROSTL_ROWS * c] ^=
            (uint8_t)(0xff ^ (c << 4) ^ round);
    }
}

/* ================================================================
 * ShiftBytes: cyclically rotate row r left by shift[r] over v cols.
 * ================================================================ */

static inline void
shift_bytes(uint8_t *state, int columns, const uint8_t shift[GROSTL_ROWS])
{
    uint8_t row[GROSTL_COLS_512];

    for (int r = 0; r < GROSTL_ROWS; r++) {
        uint8_t s = shift[r];
        for (int c = 0; c < columns; c++)
            row[c] = state[r + GROSTL_ROWS * ((c + s) % columns)];
        for (int c = 0; c < columns; c++)
            state[r + GROSTL_ROWS * c] = row[c];
    }
}

/* ================================================================
 * MixBytes: left-multiply each column by the Groestl circulant matrix
 * B = circ(02, 02, 03, 04, 05, 03, 05, 07).
 * ================================================================ */

static inline void
mix_bytes_column(const uint8_t in[GROSTL_ROWS], uint8_t out[GROSTL_ROWS])
{
    uint8_t a = in[0];
    uint8_t b = in[1];
    uint8_t c = in[2];
    uint8_t d = in[3];
    uint8_t e = in[4];
    uint8_t f = in[5];
    uint8_t g = in[6];
    uint8_t h = in[7];

    out[0] = (uint8_t)(gf_mul2(a) ^ gf_mul2(b) ^ gf_mul3(c) ^ gf_mul4(d) ^
                       gf_mul5(e) ^ gf_mul3(f) ^ gf_mul5(g) ^ gf_mul7(h));
    out[1] = (uint8_t)(gf_mul7(a) ^ gf_mul2(b) ^ gf_mul2(c) ^ gf_mul3(d) ^
                       gf_mul4(e) ^ gf_mul5(f) ^ gf_mul3(g) ^ gf_mul5(h));
    out[2] = (uint8_t)(gf_mul5(a) ^ gf_mul7(b) ^ gf_mul2(c) ^ gf_mul2(d) ^
                       gf_mul3(e) ^ gf_mul4(f) ^ gf_mul5(g) ^ gf_mul3(h));
    out[3] = (uint8_t)(gf_mul3(a) ^ gf_mul5(b) ^ gf_mul7(c) ^ gf_mul2(d) ^
                       gf_mul2(e) ^ gf_mul3(f) ^ gf_mul4(g) ^ gf_mul5(h));
    out[4] = (uint8_t)(gf_mul5(a) ^ gf_mul3(b) ^ gf_mul5(c) ^ gf_mul7(d) ^
                       gf_mul2(e) ^ gf_mul2(f) ^ gf_mul3(g) ^ gf_mul4(h));
    out[5] = (uint8_t)(gf_mul4(a) ^ gf_mul5(b) ^ gf_mul3(c) ^ gf_mul5(d) ^
                       gf_mul7(e) ^ gf_mul2(f) ^ gf_mul2(g) ^ gf_mul3(h));
    out[6] = (uint8_t)(gf_mul3(a) ^ gf_mul4(b) ^ gf_mul5(c) ^ gf_mul3(d) ^
                       gf_mul5(e) ^ gf_mul7(f) ^ gf_mul2(g) ^ gf_mul2(h));
    out[7] = (uint8_t)(gf_mul2(a) ^ gf_mul3(b) ^ gf_mul4(c) ^ gf_mul5(d) ^
                       gf_mul3(e) ^ gf_mul5(f) ^ gf_mul7(g) ^ gf_mul2(h));
}

static inline void
mix_bytes(uint8_t *state, int columns)
{
    uint8_t col_in[GROSTL_ROWS];
    uint8_t col_out[GROSTL_ROWS];

    for (int c = 0; c < columns; c++) {
        for (int r = 0; r < GROSTL_ROWS; r++)
            col_in[r] = state[r + GROSTL_ROWS * c];
        mix_bytes_column(col_in, col_out);
        for (int r = 0; r < GROSTL_ROWS; r++)
            state[r + GROSTL_ROWS * c] = col_out[r];
    }
}

#endif /* VOLEITH_GROSTL_CORE_H */
