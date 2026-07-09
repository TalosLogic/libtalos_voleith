/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * matrix.c - Generator matrices for the erasure-coding module.
 *
 * Plaintext linear algebra over GF(2^8) / GF(2^16) for Reed-Solomon and RLNC.
 * voleith_ec_matrix_invert is variable-time (data-dependent pivot / branches),
 * which is fine for the public RS coding data.  The confidential codec, whose
 * matrix L is secret, uses voleith_ec_matrix_invert_ct instead (M-2).
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "matrix.h"

#include <stdio.h>
#include <stdlib.h>

#include "util.h"

int
voleith_ec_matrix_alloc(voleith_ec_matrix_t *m, voleith_ec_field_t field,
                        size_t rows, size_t cols)
{
    uint16_t *e;

    if (m == NULL || rows == 0 || cols == 0)
        return VOLEITH_EC_ERR_PARAM;
    if (field != VOLEITH_EC_FIELD_GF8 && field != VOLEITH_EC_FIELD_GF16)
        return VOLEITH_EC_ERR_FIELD;

    e = calloc(rows * cols, sizeof(*e));
    if (e == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    m->e = e;
    m->rows = rows;
    m->cols = cols;
    m->field = field;
    return VOLEITH_EC_OK;
}

void
voleith_ec_matrix_free(voleith_ec_matrix_t *m)
{
    if (m == NULL)
        return;
    free(m->e);
    m->e = NULL;
    m->rows = 0;
    m->cols = 0;
}

void
voleith_ec_matrix_free_secure(voleith_ec_matrix_t *m)
{
    if (m == NULL)
        return;
    if (m->e != NULL)
        voleith_secure_zero(m->e, m->rows * m->cols * sizeof(*m->e));
    free(m->e);
    m->e = NULL;
    m->rows = 0;
    m->cols = 0;
}

/*
 * Returns base^exp in the matrix's field.  exp is small (a column index),
 * so a straight square-and-multiply is fine; this is public data.
 */
static uint16_t
field_pow(voleith_ec_field_t field, uint16_t base, size_t exp)
{
    uint16_t r = 1;

    while (exp > 0) {
        if (exp & 1u)
            r = voleith_ec_field_mul(field, r, base);
        base = voleith_ec_field_mul(field, base, base);
        exp >>= 1;
    }
    return r;
}

static int
build_vandermonde(voleith_ec_matrix_t *out, voleith_ec_field_t field, size_t n,
                  size_t k)
{
    size_t i, j;
    int rc;

    /* Points 1..n must be distinct nonzero field elements. */
    if (n >= voleith_ec_field_order(field))
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_ec_matrix_alloc(out, field, n, k);
    if (rc != VOLEITH_EC_OK)
        return rc;

    for (i = 0; i < n; i++) {
        uint16_t point = (uint16_t)(i + 1);
        for (j = 0; j < k; j++)
            voleith_ec_matrix_set(out, i, j, field_pow(field, point, j));
    }
    return VOLEITH_EC_OK;
}

static int
build_cauchy(voleith_ec_matrix_t *out, voleith_ec_field_t field, size_t n,
             size_t k)
{
    size_t i, j;
    int rc;

    /*
     * Systematic [I_k ; coding].  The coding rows use disjoint point sets
     * y_j = j (columns) and x_i = k + i (parity rows); all of 0..n-1 must
     * be distinct field elements, so n must not exceed the field order.
     */
    if (n > voleith_ec_field_order(field))
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_ec_matrix_alloc(out, field, n, k);
    if (rc != VOLEITH_EC_OK)
        return rc;

    /* Top k rows: identity (data passthrough). */
    for (i = 0; i < k; i++)
        voleith_ec_matrix_set(out, i, i, 1);

    /* Bottom n-k rows: Cauchy coding, coding[i][j] = 1 / (x_i + y_j). */
    for (i = 0; i < n - k; i++) {
        uint16_t x = (uint16_t)(k + i);
        for (j = 0; j < k; j++) {
            uint16_t y = (uint16_t)j;
            uint16_t denom = voleith_ec_field_add(x, y);
            voleith_ec_matrix_set(out, k + i, j,
                                  voleith_ec_field_inv(field, denom));
        }
    }
    return VOLEITH_EC_OK;
}

int
voleith_ec_matrix_generator(voleith_ec_matrix_t *out, voleith_ec_field_t field,
                            voleith_ec_matrix_kind_t kind, size_t n, size_t k)
{
    if (out == NULL || k == 0 || k > n)
        return VOLEITH_EC_ERR_PARAM;
    if (field != VOLEITH_EC_FIELD_GF8 && field != VOLEITH_EC_FIELD_GF16)
        return VOLEITH_EC_ERR_FIELD;

    switch (kind) {
    case VOLEITH_EC_MATRIX_VANDERMONDE:
        return build_vandermonde(out, field, n, k);
    case VOLEITH_EC_MATRIX_CAUCHY:
        return build_cauchy(out, field, n, k);
    default:
        return VOLEITH_EC_ERR_PARAM;
    }
}

int
voleith_ec_matrix_select_rows(const voleith_ec_matrix_t *g,
                              const size_t *row_idx, size_t nrows,
                              voleith_ec_matrix_t *out)
{
    size_t i, j;
    int rc;

    if (g == NULL || row_idx == NULL || out == NULL || nrows == 0)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_ec_matrix_alloc(out, g->field, nrows, g->cols);
    if (rc != VOLEITH_EC_OK)
        return rc;

    for (i = 0; i < nrows; i++) {
        if (row_idx[i] >= g->rows) {
            voleith_ec_matrix_free(out);
            return VOLEITH_EC_ERR_PARAM;
        }
        for (j = 0; j < g->cols; j++)
            voleith_ec_matrix_set(out, i, j,
                                  voleith_ec_matrix_get(g, row_idx[i], j));
    }
    return VOLEITH_EC_OK;
}

/*
 * Adds factor * (row src) into row dst, over m->cols columns, in the
 * field: row_dst[j] ^= factor * row_src[j].
 */
static void
row_axpy(voleith_ec_matrix_t *m, size_t dst, size_t src, uint16_t factor)
{
    size_t j;

    for (j = 0; j < m->cols; j++) {
        uint16_t prod = voleith_ec_field_mul(m->field, factor,
                                             voleith_ec_matrix_get(m, src, j));
        voleith_ec_matrix_set(
            m, dst, j,
            voleith_ec_field_add(voleith_ec_matrix_get(m, dst, j), prod));
    }
}

/* Scales row r by scalar s, over m->cols columns. */
static void
row_scale(voleith_ec_matrix_t *m, size_t r, uint16_t s)
{
    size_t j;

    for (j = 0; j < m->cols; j++)
        voleith_ec_matrix_set(
            m, r, j,
            voleith_ec_field_mul(m->field, s, voleith_ec_matrix_get(m, r, j)));
}

/* Swaps rows ra and rb of m. */
static void
row_swap(voleith_ec_matrix_t *m, size_t ra, size_t rb)
{
    size_t j;

    if (ra == rb)
        return;
    for (j = 0; j < m->cols; j++) {
        uint16_t t = voleith_ec_matrix_get(m, ra, j);
        voleith_ec_matrix_set(m, ra, j, voleith_ec_matrix_get(m, rb, j));
        voleith_ec_matrix_set(m, rb, j, t);
    }
}

int
voleith_ec_matrix_invert(const voleith_ec_matrix_t *a, voleith_ec_matrix_t *inv)
{
    voleith_ec_matrix_t work = {0};
    size_t i, j, col, k;
    int rc;

    if (a == NULL || inv == NULL || a->rows == 0 || a->rows != a->cols)
        return VOLEITH_EC_ERR_PARAM;
    k = a->rows;

    /* work = copy of a; inv = identity.  Gauss-Jordan reduces work to I,
     * applying the same operations to inv, which becomes a^{-1}. */
    rc = voleith_ec_matrix_alloc(&work, a->field, k, k);
    if (rc != VOLEITH_EC_OK)
        return rc;
    rc = voleith_ec_matrix_alloc(inv, a->field, k, k);
    if (rc != VOLEITH_EC_OK) {
        voleith_ec_matrix_free(&work);
        return rc;
    }
    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++)
            voleith_ec_matrix_set(&work, i, j, voleith_ec_matrix_get(a, i, j));
        voleith_ec_matrix_set(inv, i, i, 1);
    }

    for (col = 0; col < k; col++) {
        uint16_t pivot, pinv;
        size_t prow = col;

        /* Partial pivot: find any row at/below col with a nonzero entry. */
        while (prow < k && voleith_ec_matrix_get(&work, prow, col) == 0)
            prow++;
        if (prow == k) {
            voleith_ec_matrix_free_secure(&work);
            voleith_ec_matrix_free_secure(inv);
            return VOLEITH_EC_ERR_SINGULAR;
        }
        row_swap(&work, col, prow);
        row_swap(inv, col, prow);

        /* Normalize the pivot row so work[col][col] == 1. */
        pivot = voleith_ec_matrix_get(&work, col, col);
        pinv = voleith_ec_field_inv(a->field, pivot);
        row_scale(&work, col, pinv);
        row_scale(inv, col, pinv);

        /* Eliminate the pivot column from every other row. */
        for (i = 0; i < k; i++) {
            uint16_t factor;
            if (i == col)
                continue;
            factor = voleith_ec_matrix_get(&work, i, col);
            if (factor == 0)
                continue;
            row_axpy(&work, i, col, factor);
            row_axpy(inv, i, col, factor);
        }
    }

    /* work holds a row-reduced image of the (possibly secret) input a. */
    voleith_ec_matrix_free_secure(&work);
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Constant-time inverse (for the confidential codec's SECRET matrix L)
 *
 * voleith_ec_matrix_invert above is variable-time and fine for public RS
 * data.  The confidential-RLNC codec inverts the secret coefficient matrix L
 * (keygen / decode), where a data-dependent pivot search or branch would leak
 * L through timing / cache (security review M-2).  This variant fixes the
 * memory-access and control-flow pattern: it visits every candidate pivot,
 * swaps via a {0, ~0} mask, and eliminates every row unconditionally (a zero
 * factor still does the full axpy).  The underlying GF(2^w) mul / inv are
 * already constant-time.  The ONLY secret-dependent observable is the final
 * singular / non-singular return code (one bit, unavoidable at the API and
 * already revealed by keygen's rejection acceptance).
 * ======================================================================== */

/* Optimizer barrier: keep a {0, ~0} mask opaque so the compiler cannot
 * re-derive a branch from it.  Compiles to zero instructions. */
static inline uint16_t
ct_barrier_u16(uint16_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("" : "+r"(x));
    return x;
#else
    volatile uint16_t v = x;
    return v;
#endif
}

/* Returns ~0 if x != 0, else 0 (16-bit field element). */
static inline uint16_t
ct_mask_nonzero(uint16_t x)
{
    uint32_t v = x;
    /* high bit of (v | -v) is set iff v != 0 */
    return ct_barrier_u16((uint16_t)(0u - ((v | (0u - v)) >> 31)));
}

/* Constant-time swap of rows ra and rb when mask == ~0 (no-op when 0). */
static void
ct_cond_swap_rows(voleith_ec_matrix_t *m, size_t ra, size_t rb, uint16_t mask)
{
    size_t j;

    for (j = 0; j < m->cols; j++) {
        uint16_t a = voleith_ec_matrix_get(m, ra, j);
        uint16_t b = voleith_ec_matrix_get(m, rb, j);
        uint16_t d = (uint16_t)((a ^ b) & mask);
        voleith_ec_matrix_set(m, ra, j, (uint16_t)(a ^ d));
        voleith_ec_matrix_set(m, rb, j, (uint16_t)(b ^ d));
    }
}

int
voleith_ec_matrix_invert_ct(const voleith_ec_matrix_t *a,
                            voleith_ec_matrix_t *inv)
{
    voleith_ec_matrix_t work = {0};
    size_t i, j, col, k;
    uint16_t singular = 0;
    int rc;

    if (a == NULL || inv == NULL || a->rows == 0 || a->rows != a->cols)
        return VOLEITH_EC_ERR_PARAM;
    k = a->rows;

    rc = voleith_ec_matrix_alloc(&work, a->field, k, k);
    if (rc != VOLEITH_EC_OK)
        return rc;
    rc = voleith_ec_matrix_alloc(inv, a->field, k, k);
    if (rc != VOLEITH_EC_OK) {
        voleith_ec_matrix_free_secure(&work);
        return rc;
    }
    for (i = 0; i < k; i++) {
        for (j = 0; j < k; j++)
            voleith_ec_matrix_set(&work, i, j, voleith_ec_matrix_get(a, i, j));
        voleith_ec_matrix_set(inv, i, i, 1);
    }

    for (col = 0; col < k; col++) {
        uint16_t found = 0; /* ~0 once a pivot row is settled into col */
        uint16_t pivot, pinv;

        /* Oblivious pivot: consider every row at/below col, swapping the
         * first nonzero one into place through a mask (fixed access pattern,
         * no data-dependent early exit). */
        for (i = col; i < k; i++) {
            uint16_t cand =
                ct_mask_nonzero(voleith_ec_matrix_get(&work, i, col));
            uint16_t do_swap = (uint16_t)(cand & ~found);
            ct_cond_swap_rows(&work, col, i, do_swap);
            ct_cond_swap_rows(inv, col, i, do_swap);
            found = (uint16_t)(found | cand);
        }
        /* A column with no nonzero entry means a is singular. */
        singular = (uint16_t)(singular | (uint16_t)~found);

        /* Normalize the pivot row (pinv of 0 is 0; masked out by singular). */
        pivot = voleith_ec_matrix_get(&work, col, col);
        pinv = (uint16_t)voleith_ec_field_inv(a->field, pivot);
        row_scale(&work, col, pinv);
        row_scale(inv, col, pinv);

        /* Eliminate the pivot column from every OTHER row.  The r == col test
         * is on public loop indices; the factor is secret but the axpy always
         * runs (a zero factor is a full-cost no-op). */
        for (i = 0; i < k; i++) {
            uint16_t factor;
            if (i == col)
                continue;
            factor = voleith_ec_matrix_get(&work, i, col);
            row_axpy(&work, i, col, factor);
            row_axpy(inv, i, col, factor);
        }
    }

    voleith_ec_matrix_free_secure(&work);
    if (singular != 0) {
        voleith_ec_matrix_free_secure(inv);
        return VOLEITH_EC_ERR_SINGULAR;
    }
    return VOLEITH_EC_OK;
}

int
voleith_ec_matrix_mul(const voleith_ec_matrix_t *a,
                      const voleith_ec_matrix_t *b, voleith_ec_matrix_t *out)
{
    size_t i, j, t;
    int rc;

    if (a == NULL || b == NULL || out == NULL || a->cols != b->rows)
        return VOLEITH_EC_ERR_PARAM;
    if (a->field != b->field)
        return VOLEITH_EC_ERR_FIELD;

    rc = voleith_ec_matrix_alloc(out, a->field, a->rows, b->cols);
    if (rc != VOLEITH_EC_OK)
        return rc;

    for (i = 0; i < a->rows; i++) {
        for (j = 0; j < b->cols; j++) {
            uint16_t acc = 0;
            for (t = 0; t < a->cols; t++) {
                uint16_t prod = voleith_ec_field_mul(
                    a->field, voleith_ec_matrix_get(a, i, t),
                    voleith_ec_matrix_get(b, t, j));
                acc = voleith_ec_field_add(acc, prod);
            }
            voleith_ec_matrix_set(out, i, j, acc);
        }
    }
    return VOLEITH_EC_OK;
}

void
voleith_ec_matrix_print(const voleith_ec_matrix_t *m, const char *label)
{
    size_t i, j;
    int width;

    if (m == NULL) {
        printf("%s: (null)\n", label != NULL ? label : "matrix");
        return;
    }

    width = (m->field == VOLEITH_EC_FIELD_GF8) ? 2 : 4;
    printf("%s: %zux%zu over GF(2^%d)\n", label != NULL ? label : "matrix",
           m->rows, m->cols, (int)m->field);
    for (i = 0; i < m->rows; i++) {
        printf("  [");
        for (j = 0; j < m->cols; j++)
            printf(" %0*X", width,
                   (unsigned int)voleith_ec_matrix_get(m, i, j));
        printf(" ]\n");
    }
}
