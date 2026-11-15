/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_grostl_norm_const.h - shared constants for the Grostl norm S-box
 * round-pair gadget (FAEST paired-round norm; prover and verifier must agree).
 *
 * Grostl's S-box IS the AES S-box, so the inversion/affine field constants
 * (Frobenius GF8_NORM_SQ, the linearized affine GF8_NORM_AFFINE_C, and the
 * inverse affine GF8_NORM_INV_AFFINE) are reused verbatim from gf8_norm_const.h
 * and are NOT redeclared here.  What differs is Grostl's linear layer and its
 * public round constants:
 *
 *   - ShiftBytes: a per-row cyclic shift of columns, given by shift[ROWS].  The
 *     Grostl-256 permutation (bits 512) has 8 columns; Grostl-512 (bits 1024)
 *     has 16.  grostl_norm_build_shift derives the flat byte permutation and
 *     its inverse (for the odd-round s recovery) exactly as the frozen
 *     shift_bytes_wires in circuits/grostl_gf8_circuit.c.
 *   - MixBytes: multiply each 8-byte column by the circulant
 *     B = circ(2, 2, 3, 4, 5, 3, 5, 7); row i is row 0 right-rotated by i.
 *     The gadget works in the embedded conjugate domain, so it needs the scalar
 *     GF(2^8) multipliers (GROSTL_NORM_MIX) rather than the frozen path's GF(2)
 *     bit matrices.  The b=1 (squared) domain uses c^2 of each multiplier
 *     (SQ(2)=0x04, SQ(3)=0x05, SQ(4)=0x10, SQ(5)=0x11, SQ(7)=0x15),
 *     computed at runtime.
 *   - AddRoundConstant: public, applied before SubBytes.  grostl_norm_round_const
 *     reproduces add_round_constant_{p,q}_wires per byte.
 *
 * All layouts were derived and verified (circulant matches the frozen explicit
 * MixBytes rows and is GF(2^8)-consistent; every shift variant is a genuine
 * permutation whose inverse round-trips and matches the byte-level reference).
 * This header is the single source of truth so the prover and verifier cannot
 * drift.
 */

#ifndef VOLEITH_GF8_GROSTL_NORM_CONST_H
#define VOLEITH_GF8_GROSTL_NORM_CONST_H

#include "gf8_norm_const.h"
#include <stdint.h>

/* Grostl state is 8 rows; byte (r + ROWS*c) is row r, column c. */
#define GROSTL_NORM_ROWS 8u

/* Largest column count (Grostl-512 permutation P1024/Q1024). */
#define GROSTL_NORM_MAX_COLS 16u
#define GROSTL_NORM_MAX_STATE                                                  \
    (GROSTL_NORM_ROWS * GROSTL_NORM_MAX_COLS) /* 128 */

/*
 * The ShiftBytes row shifts themselves (P/Q x {8-col Grostl-256, 16-col
 * Grostl-512}) live with the circuit builder that selects a permutation, not
 * here: the gadget receives shift[ROWS] per entry and derives the flat
 * permutation with grostl_norm_build_shift below.  For reference they are
 * P8 = {0,1,2,3,4,5,6,7}, Q8 = {1,3,5,7,0,2,4,6},
 * P16 = {0,1,2,3,4,5,6,11}, Q16 = {1,3,5,11,0,2,4,6}, re-verified against
 * circuits/grostl_gf8_circuit.c.
 */

/* MixBytes circulant B = circ(2,2,3,4,5,3,5,7); row i = row 0 right-rotated by
 * i.  Entry [i][j] is the GF(2^8) multiplier applied to input byte j in output
 * row i. */
static const uint8_t GROSTL_NORM_MIX[GROSTL_NORM_ROWS][GROSTL_NORM_ROWS] = {
    {2, 2, 3, 4, 5, 3, 5, 7}, {7, 2, 2, 3, 4, 5, 3, 5},
    {5, 7, 2, 2, 3, 4, 5, 3}, {3, 5, 7, 2, 2, 3, 4, 5},
    {5, 3, 5, 7, 2, 2, 3, 4}, {4, 5, 3, 5, 7, 2, 2, 3},
    {3, 4, 5, 3, 5, 7, 2, 2}, {2, 3, 4, 5, 3, 5, 7, 2},
};

/*
 * grostl_norm_build_shift - fill fwd/inv with the flat ShiftBytes byte
 * permutation for a `cols`-column state and row shifts `shift`.
 *
 * ShiftBytes is new[r][c] = old[r][(c + shift[r]) mod cols], so out[dst] =
 * in[fwd[dst]] and the odd-round recovery undoes it with inv.  Both arrays must
 * hold ROWS*cols entries (<= GROSTL_NORM_MAX_STATE).
 */
static inline void
grostl_norm_build_shift(unsigned int cols,
                        const uint8_t shift[GROSTL_NORM_ROWS], uint8_t *fwd,
                        uint8_t *inv)
{
    for (unsigned int r = 0; r < GROSTL_NORM_ROWS; r++) {
        unsigned int s = shift[r];
        for (unsigned int c = 0; c < cols; c++) {
            unsigned int dst = r + GROSTL_NORM_ROWS * c;
            unsigned int src = r + GROSTL_NORM_ROWS * ((c + s) % cols);
            fwd[dst] = (uint8_t)src;
        }
    }
    for (unsigned int i = 0; i < GROSTL_NORM_ROWS * cols; i++)
        inv[fwd[i]] = (uint8_t)i;
}

/*
 * grostl_norm_round_const - fill rc[0..ROWS*cols-1] with the public
 * AddRoundConstant byte added before SubBytes in round `round`.  is_q selects
 * the Q permutation's constant; otherwise P's.  Mirrors
 * add_round_constant_{p,q}_wires exactly.
 */
static inline void
grostl_norm_round_const(int is_q, unsigned int cols, uint8_t round, uint8_t *rc)
{
    for (unsigned int i = 0; i < GROSTL_NORM_ROWS * cols; i++)
        rc[i] = 0;
    for (unsigned int col = 0; col < cols; col++) {
        if (!is_q) {
            /* P: only row 0 of each column. */
            rc[0 + GROSTL_NORM_ROWS * col] = (uint8_t)((col << 4) ^ round);
        } else {
            /* Q: rows 0..6 inverted; row 7 carries the counter. */
            for (unsigned int r = 0; r < GROSTL_NORM_ROWS - 1; r++)
                rc[r + GROSTL_NORM_ROWS * col] = 0xff;
            rc[(GROSTL_NORM_ROWS - 1) + GROSTL_NORM_ROWS * col] =
                (uint8_t)(0xff ^ (col << 4) ^ round);
        }
    }
}

#endif /* VOLEITH_GF8_GROSTL_NORM_CONST_H */
