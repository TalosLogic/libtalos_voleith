/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_norm_const.h - shared field constants for the AES norm S-box round-pair
 * gadget (FAEST paired-round norm; prover and verifier must agree).
 *
 * All constants are in voleith's AES GF(2^8) field (reduce poly
 * x^8+x^4+x^3+x+1, 0x1B), derived independently from the AES affine matrix and
 * verified (span closed under Frobenius^4; affine linearized polynomial
 * reproduces M*z; inverse_affine(affine(z)) == z for all z).  They are pinned
 * value-exact against faest-ref (bfSSS_c / beta tables / c_squares) by the norm
 * compat gate; this header is the single source of truth so the prover and
 * verifier cannot drift.
 */

#ifndef VOLEITH_GF8_NORM_CONST_H
#define VOLEITH_GF8_NORM_CONST_H

#include <stdint.h>

/* Frobenius x -> x^2 as an 8x8 GF(2) bit matrix (same matrix the circuit's
 * SQUARE wire uses).  Row-major: out bit i = XOR_j M[i][j] in[j]. */
static const uint8_t GF8_NORM_SQ[8] = {0x51, 0xD0, 0x22, 0xF0,
                                       0x94, 0x60, 0x28, 0xC0};

/* AES affine linearized-polynomial coefficients: affine(z) = C[8] XOR
 * sum_{k=0}^{7} C[k] * z^(2^k).  C[8] = 0x63 is the additive constant.  The
 * dosq (b=1) variant squares C[0..8] in-field. */
static const uint8_t GF8_NORM_AFFINE_C[9] = {0x05, 0x09, 0xf9, 0x25, 0xf4,
                                             0x01, 0xb5, 0x8f, 0x63};

/* Inverse of the AES affine linear part M (for recovering the odd-round S-box
 * input s from the committed reset state): inverse_affine(y) = M^-1 * (y XOR
 * 0x63). */
static const uint8_t GF8_NORM_INV_AFFINE[8] = {0xa4, 0x49, 0x92, 0x25,
                                               0x4a, 0x94, 0x29, 0x52};

/* ShiftRows byte permutation (new[k] = old[PERM[k]], column-major state) and
 * its inverse (used in the s recovery). */
static const unsigned int GF8_NORM_SHIFTROWS[16] = {
    0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
static const unsigned int GF8_NORM_INV_SHIFTROWS[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3};

#endif /* VOLEITH_GF8_NORM_CONST_H */
