/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_gf16_circuit.c - GF(2^16) RLNC generation-membership circuit (T5.6).
 *
 * See rlnc_gf16_circuit.h for the relation and cost model.
 */

#include "rlnc_gf16_circuit.h"

#include <stdlib.h>
#include <string.h>

/*
 * Build the 16x16 GF(2) matrix of the map x -> c * x in GF(2^16) for a fixed
 * field element c.  Column b is c * x^b = gf16_mul(c, 1<<b); row i collects,
 * for each b, bit i of that column.  Multiplication by a constant is
 * GF(2)-linear, so this realizes c*x as a free LINEAR_MAP gate.
 */
static void
mulconst_matrix(uint16_t M[16], voleith_gf16_t c)
{
    memset(M, 0, 16 * sizeof(uint16_t));
    for (int b = 0; b < 16; b++) {
        uint16_t col = voleith_gf16_mul(c, (uint16_t)(1u << b));
        for (int i = 0; i < 16; i++)
            if ((col >> i) & 1u)
                M[i] |= (uint16_t)(1u << b);
    }
}

void
voleith_rlnc_gf16_membership_circuit(voleith_gf16_circuit_t *c,
                                     const gf16_wire_id *src_wires,
                                     const voleith_gf16_t *coeffs,
                                     const gf16_wire_id *y_wires, size_t k,
                                     size_t elems)
{
    if (!c || !src_wires || !coeffs || !y_wires)
        return;

    for (size_t e = 0; e < elems; e++) {
        gf16_wire_id acc = GF16_WIRE_ID_INVALID;

        for (size_t j = 0; j < k; j++) {
            voleith_gf16_t cj = coeffs[j];
            gf16_wire_id term;

            if (cj == 0) {
                /* Zero coefficient contributes nothing. */
                continue;
            } else if (cj == 1) {
                /* Identity: the source wire itself, no map needed. */
                term = src_wires[j * elems + e];
            } else {
                uint16_t M[16];
                mulconst_matrix(M, cj);
                term =
                    voleith_gf16_add_linear_map(c, src_wires[j * elems + e], M);
            }

            acc = (acc == GF16_WIRE_ID_INVALID)
                      ? term
                      : voleith_gf16_add_xor(c, acc, term);
        }

        /* All-zero coefficient vector: the combination is the zero element. */
        if (acc == GF16_WIRE_ID_INVALID)
            acc = voleith_gf16_add_const(c, 0);

        voleith_gf16_assert_equal(c, acc, y_wires[e]);
    }
}

void
voleith_rlnc_gf16_coded_vector_circuit(voleith_gf16_circuit_t *c,
                                       const gf16_wire_id *coeff_wires,
                                       const voleith_gf16_t *sources,
                                       const gf16_wire_id *y_wires, size_t k,
                                       size_t elems)
{
    if (!c || !coeff_wires || !sources || !y_wires)
        return;

    for (size_t e = 0; e < elems; e++) {
        gf16_wire_id acc = GF16_WIRE_ID_INVALID;

        for (size_t j = 0; j < k; j++) {
            /* Public source element is the constant; secret coeff is the wire. */
            voleith_gf16_t s = sources[j * elems + e];
            gf16_wire_id term;

            if (s == 0) {
                continue;
            } else if (s == 1) {
                term = coeff_wires[j];
            } else {
                uint16_t M[16];
                mulconst_matrix(M, s);
                term = voleith_gf16_add_linear_map(c, coeff_wires[j], M);
            }

            acc = (acc == GF16_WIRE_ID_INVALID)
                      ? term
                      : voleith_gf16_add_xor(c, acc, term);
        }

        if (acc == GF16_WIRE_ID_INVALID)
            acc = voleith_gf16_add_const(c, 0);

        voleith_gf16_assert_equal(c, acc, y_wires[e]);
    }
}

void
voleith_rlnc_gf16_membership_secret_circuit(voleith_gf16_circuit_t *c,
                                            const gf16_wire_id *src_wires,
                                            const gf16_wire_id *coeff_wires,
                                            const gf16_wire_id *y_wires,
                                            size_t k, size_t elems)
{
    if (!c || !src_wires || !coeff_wires || !y_wires)
        return;

    for (size_t e = 0; e < elems; e++) {
        gf16_wire_id acc = GF16_WIRE_ID_INVALID;

        for (size_t j = 0; j < k; j++) {
            /* Both factors are secret wires, so each term costs one MUL. */
            gf16_wire_id term = voleith_gf16_add_mul(c, coeff_wires[j],
                                                     src_wires[j * elems + e]);

            acc = (acc == GF16_WIRE_ID_INVALID)
                      ? term
                      : voleith_gf16_add_xor(c, acc, term);
        }

        /* k == 0 is rejected by the witness-count contract; defend anyway. */
        if (acc == GF16_WIRE_ID_INVALID)
            acc = voleith_gf16_add_const(c, 0);

        voleith_gf16_assert_equal(c, acc, y_wires[e]);
    }
}

int
voleith_rlnc_gf16_membership_secret_build_witness(const uint8_t *sources,
                                                  size_t k, size_t symbol_bytes,
                                                  const voleith_gf16_t *coeffs,
                                                  voleith_gf16_t *out)
{
    if (!sources || !coeffs || !out || k == 0 || symbol_bytes == 0 ||
        (symbol_bytes & 1u) != 0)
        return -1;

    size_t elems = symbol_bytes / 2;

    /* X prefix (k*elems, row-major), then the coding vector c (k). */
    if (voleith_rlnc_gf16_build_witness(sources, k, symbol_bytes, out) != 0)
        return -1;
    for (size_t j = 0; j < k; j++)
        out[k * elems + j] = coeffs[j];
    return 0;
}

int
voleith_rlnc_gf16_build_witness(const uint8_t *sources, size_t k,
                                size_t symbol_bytes, voleith_gf16_t *out)
{
    if (!sources || !out || k == 0 || symbol_bytes == 0 ||
        (symbol_bytes & 1u) != 0)
        return -1;

    size_t elems = symbol_bytes / 2;
    for (size_t j = 0; j < k; j++) {
        const uint8_t *sym = sources + j * symbol_bytes;
        for (size_t e = 0; e < elems; e++)
            out[j * elems + e] = voleith_gf16_from_bytes(sym + 2 * e);
    }
    return 0;
}

int
voleith_rlnc_gf16_coeffs_full_rank(const voleith_gf16_t *coeff_rows,
                                   size_t n_rows, size_t k)
{
    if (!coeff_rows || k == 0 || n_rows < k)
        return 0;

    /*
     * Gaussian elimination over GF(2^16) on a working copy of the rows.
     * Counts pivots; rank == k means the coefficient vectors span the full
     * k-dimensional space, i.e. the generation can be rebuilt.  Public data,
     * not constant-time.
     */
    voleith_gf16_t *m = calloc(n_rows * k, sizeof(voleith_gf16_t));
    if (!m)
        return 0;
    memcpy(m, coeff_rows, n_rows * k * sizeof(voleith_gf16_t));

    size_t rank = 0;
    for (size_t col = 0; col < k && rank < n_rows; col++) {
        /* Find a pivot row at or below `rank` with a nonzero entry in col. */
        size_t piv = rank;
        while (piv < n_rows && m[piv * k + col] == 0)
            piv++;
        if (piv == n_rows)
            continue; /* No pivot in this column. */

        /* Swap pivot row into position `rank`. */
        if (piv != rank) {
            for (size_t j = 0; j < k; j++) {
                voleith_gf16_t tmp = m[rank * k + j];
                m[rank * k + j] = m[piv * k + j];
                m[piv * k + j] = tmp;
            }
        }

        /* Normalize the pivot row so the pivot is 1. */
        voleith_gf16_t inv = voleith_gf16_inv(m[rank * k + col]);
        for (size_t j = 0; j < k; j++)
            m[rank * k + j] = voleith_gf16_mul(m[rank * k + j], inv);

        /* Eliminate this column from every other row. */
        for (size_t r = 0; r < n_rows; r++) {
            if (r == rank)
                continue;
            voleith_gf16_t f = m[r * k + col];
            if (f == 0)
                continue;
            for (size_t j = 0; j < k; j++)
                m[r * k + j] = voleith_gf16_add(
                    m[r * k + j], voleith_gf16_mul(f, m[rank * k + j]));
        }
        rank++;
    }

    free(m);
    return rank == k ? 1 : 0;
}
