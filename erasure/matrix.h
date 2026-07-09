/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * matrix.h - Generator matrices and field-generic linear algebra for the
 * erasure-coding module.
 *
 * A generator matrix G is an n-by-k matrix over GF(2^8) or GF(2^16): the
 * code maps a length-k message vector M to a length-n codeword C = G . M.
 * Both Vandermonde and Cauchy constructions are provided.  A Cauchy
 * construction is systematic ([I_k; coding rows]) and MDS (every k-by-k
 * submatrix invertible); a Vandermonde construction is the classic
 * non-systematic n-by-k matrix, also MDS for distinct evaluation points.
 *
 * Elements of either field are carried in a uint16_t (GF(2^8) uses the low
 * byte).  Field arithmetic dispatches on the matrix's field selector.
 *
 * This is a plaintext data layer over public coding data; it is not on the
 * constant-time proving path.  See docs/ERASURE_CODES_DESIGN.md.
 */

#ifndef VOLEITH_ERASURE_MATRIX_H
#define VOLEITH_ERASURE_MATRIX_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "field.h"
#include "field16.h"

/* ========================================================================
 * Field-generic element arithmetic (dispatch on a public selector)
 * ======================================================================== */

/* Returns a + b (field-independent: XOR). */
static inline uint16_t
voleith_ec_field_add(uint16_t a, uint16_t b)
{
    return a ^ b;
}

/* Returns a * b in the selected field. */
static inline uint16_t
voleith_ec_field_mul(voleith_ec_field_t field, uint16_t a, uint16_t b)
{
    if (field == VOLEITH_EC_FIELD_GF8)
        return voleith_gf8_mul((voleith_gf8_t)a, (voleith_gf8_t)b);
    return voleith_gf16_mul((voleith_gf16_t)a, (voleith_gf16_t)b);
}

/* Returns a^{-1} in the selected field (0 for a == 0). */
static inline uint16_t
voleith_ec_field_inv(voleith_ec_field_t field, uint16_t a)
{
    if (field == VOLEITH_EC_FIELD_GF8)
        return voleith_gf8_inv((voleith_gf8_t)a);
    return voleith_gf16_inv((voleith_gf16_t)a);
}

/* Number of distinct nonzero field elements available as code points. */
static inline size_t
voleith_ec_field_order(voleith_ec_field_t field)
{
    return (field == VOLEITH_EC_FIELD_GF8) ? 256u : 65536u;
}

/* ========================================================================
 * Matrix type
 * ======================================================================== */

typedef struct {
    uint16_t *e; /* rows * cols elements, row-major (not owned by value). */
    size_t rows;
    size_t cols;
    voleith_ec_field_t field;
} voleith_ec_matrix_t;

typedef enum {
    VOLEITH_EC_MATRIX_VANDERMONDE,
    VOLEITH_EC_MATRIX_CAUCHY
} voleith_ec_matrix_kind_t;

/* Element accessors (row-major, no bounds check). */
static inline uint16_t
voleith_ec_matrix_get(const voleith_ec_matrix_t *m, size_t r, size_t c)
{
    return m->e[r * m->cols + c];
}

static inline void
voleith_ec_matrix_set(voleith_ec_matrix_t *m, size_t r, size_t c, uint16_t v)
{
    m->e[r * m->cols + c] = v;
}

/* ========================================================================
 * Lifecycle
 * ======================================================================== */

/*
 * Allocates an (rows x cols) matrix over the given field, zero-initialized.
 * Returns 0 on success, a negative VOLEITH_EC_ERR_* code on failure.
 */
int voleith_ec_matrix_alloc(voleith_ec_matrix_t *m, voleith_ec_field_t field,
                            size_t rows, size_t cols);

/* Frees the element storage and clears the descriptor.  Safe on a zeroed
 * descriptor. */
void voleith_ec_matrix_free(voleith_ec_matrix_t *m);

/*
 * Like voleith_ec_matrix_free, but zeroes the element storage first (using
 * voleith_secure_zero, which the compiler cannot elide).  Use for matrices
 * carrying secret material: the confidential codec's key L, its inverse
 * L^{-1}, and any row-reduced working copy of them.  Safe on a zeroed
 * descriptor.
 */
void voleith_ec_matrix_free_secure(voleith_ec_matrix_t *m);

/* ========================================================================
 * Construction
 * ======================================================================== */

/*
 * Builds an n-by-k generator matrix of the given kind over the given field
 * (allocating it into out, which must be an unused/zeroed descriptor).
 *
 * VANDERMONDE: out[i][j] = point(i)^j, point(i) = i + 1 (distinct nonzero),
 *   non-systematic, MDS.
 * CAUCHY: systematic [I_k ; coding], coding[i][j] = 1 / (x_i + y_j) with
 *   disjoint point sets y_j = j and x_i = k + i, MDS.
 *
 * Requires 0 < k <= n and enough distinct field points (n < field order for
 * Vandermonde, n <= field order for Cauchy).  Returns 0 on success, a
 * negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_ec_matrix_generator(voleith_ec_matrix_t *out,
                                voleith_ec_field_t field,
                                voleith_ec_matrix_kind_t kind, size_t n,
                                size_t k);

/*
 * Selects nrows rows of g (by the indices in row_idx) into a freshly
 * allocated out (nrows x g->cols).  Used by decode to assemble the k-by-k
 * system from the indices of received chunks.  Returns 0 on success, a
 * negative VOLEITH_EC_ERR_* on failure (e.g. a row index out of range).
 */
int voleith_ec_matrix_select_rows(const voleith_ec_matrix_t *g,
                                  const size_t *row_idx, size_t nrows,
                                  voleith_ec_matrix_t *out);

/* ========================================================================
 * Linear solve (decode)
 *
 * voleith_ec_matrix_invert is NOT constant-time (data-dependent pivot search
 * and branches).  That is acceptable for the RS data layer, which handles
 * public payloads.  Code that inverts a SECRET matrix (the confidential-RLNC
 * codec's L) must use voleith_ec_matrix_invert_ct instead (M-2).
 * ======================================================================== */

/*
 * Inverts a square (k x k) matrix via Gauss-Jordan elimination, allocating
 * the result into inv (an unused/zeroed descriptor).  Returns 0 on success,
 * VOLEITH_EC_ERR_SINGULAR if the matrix is not invertible, or another
 * negative VOLEITH_EC_ERR_* on bad arguments / allocation failure.  a is not
 * modified.
 */
int voleith_ec_matrix_invert(const voleith_ec_matrix_t *a,
                             voleith_ec_matrix_t *inv);

/*
 * Constant-time inverse of a square (k x k) matrix, for the confidential-RLNC
 * codec's SECRET matrix L (keygen / decode).  Same result as
 * voleith_ec_matrix_invert, but with a fixed memory-access and control-flow
 * pattern (oblivious masked pivoting, unconditional elimination) so L does not
 * leak through timing or cache (security review M-2).  The only secret-
 * dependent observable is the singular / non-singular return code.  Prefer the
 * variable-time voleith_ec_matrix_invert for public RS data (it is cheaper).
 * Returns 0, VOLEITH_EC_ERR_SINGULAR, or another negative VOLEITH_EC_ERR_*.
 */
int voleith_ec_matrix_invert_ct(const voleith_ec_matrix_t *a,
                                voleith_ec_matrix_t *inv);

/*
 * Matrix product over the field: out = a . b, with a (m x p), b (p x q),
 * out allocated (m x q) into an unused/zeroed descriptor.  Both inputs must
 * share the same field.  Decode recovers the message by multiplying the
 * inverted k-by-k submatrix by the received-chunk matrix (k x w symbols).
 * Returns 0 on success, a negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_ec_matrix_mul(const voleith_ec_matrix_t *a,
                          const voleith_ec_matrix_t *b,
                          voleith_ec_matrix_t *out);

/* ========================================================================
 * Debug
 * ======================================================================== */

/* Prints the matrix as hex rows to stdout, prefixed with label. */
void voleith_ec_matrix_print(const voleith_ec_matrix_t *m, const char *label);

#endif /* VOLEITH_ERASURE_MATRIX_H */
