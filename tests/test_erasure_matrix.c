/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_matrix.c - Tests for the erasure-coding generator matrices
 * and Gaussian-elimination decode (erasure/matrix.c).
 *
 * The core property is MDS recovery: with an (n, k) generator G and a
 * length-k message M (carried as a k x w symbol block), the codeword
 * C = G . M lets any k of the n rows recover M.  The test verifies this
 * for every k-subset of small (n, k), over both fields (GF(2^8), GF(2^16))
 * and both constructions (Vandermonde, Cauchy).  It also checks that a
 * singular submatrix is reported, not crashed on.
 */

#include "matrix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-58s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

/* Simple LCG so messages are deterministic across runs. */
static uint32_t rng_state = 0x12345678u;

static uint16_t
next_elem(voleith_ec_field_t field)
{
    rng_state = rng_state * 1103515245u + 12345u;
    if (field == VOLEITH_EC_FIELD_GF8)
        return (uint16_t)((rng_state >> 16) & 0xFFu);
    return (uint16_t)((rng_state >> 8) & 0xFFFFu);
}

/* Advances idx (length k, strictly increasing in [0, n)) to the next
 * combination.  Returns 1 if a next combination was produced, 0 if the
 * enumeration is exhausted. */
static int
comb_next(size_t *idx, size_t k, size_t n)
{
    size_t pos = k;

    while (pos-- > 0) {
        if (idx[pos] < n - k + pos) {
            size_t j;
            idx[pos]++;
            for (j = pos + 1; j < k; j++)
                idx[j] = idx[j - 1] + 1;
            return 1;
        }
    }
    return 0;
}

static int
matrix_equal(const voleith_ec_matrix_t *a, const voleith_ec_matrix_t *b)
{
    size_t i, j;

    if (a->rows != b->rows || a->cols != b->cols)
        return 0;
    for (i = 0; i < a->rows; i++)
        for (j = 0; j < a->cols; j++)
            if (voleith_ec_matrix_get(a, i, j) !=
                voleith_ec_matrix_get(b, i, j))
                return 0;
    return 1;
}

/*
 * Runs the every-k-subset recovery test for one (field, kind, n, k, w).
 * Returns 1 on full success, 0 on the first failure (printing a reason).
 */
static int
run_roundtrip(voleith_ec_field_t field, voleith_ec_matrix_kind_t kind, size_t n,
              size_t k, size_t w)
{
    voleith_ec_matrix_t g = {0}, msg = {0}, code = {0};
    size_t *idx;
    size_t i, j;
    int ok = 1;

    if (voleith_ec_matrix_generator(&g, field, kind, n, k) != VOLEITH_EC_OK) {
        FAIL("generator build failed");
        return 0;
    }

    /* Random message M (k x w) and codeword C = G . M (n x w). */
    if (voleith_ec_matrix_alloc(&msg, field, k, w) != VOLEITH_EC_OK) {
        voleith_ec_matrix_free(&g);
        FAIL("message alloc failed");
        return 0;
    }
    for (i = 0; i < k; i++)
        for (j = 0; j < w; j++)
            voleith_ec_matrix_set(&msg, i, j, next_elem(field));

    if (voleith_ec_matrix_mul(&g, &msg, &code) != VOLEITH_EC_OK) {
        voleith_ec_matrix_free(&g);
        voleith_ec_matrix_free(&msg);
        FAIL("encode (G . M) failed");
        return 0;
    }

    idx = calloc(k, sizeof(*idx));
    if (idx == NULL) {
        voleith_ec_matrix_free(&g);
        voleith_ec_matrix_free(&msg);
        voleith_ec_matrix_free(&code);
        FAIL("idx alloc failed");
        return 0;
    }
    for (i = 0; i < k; i++)
        idx[i] = i;

    do {
        voleith_ec_matrix_t sub = {0}, inv = {0}, recv = {0}, rec = {0};

        /* Submatrix G_S and received chunks C_S for this k-subset. */
        if (voleith_ec_matrix_select_rows(&g, idx, k, &sub) != VOLEITH_EC_OK ||
            voleith_ec_matrix_select_rows(&code, idx, k, &recv) !=
                VOLEITH_EC_OK) {
            ok = 0;
            FAIL("select_rows failed");
            voleith_ec_matrix_free(&sub);
            voleith_ec_matrix_free(&recv);
            break;
        }

        if (voleith_ec_matrix_invert(&sub, &inv) != VOLEITH_EC_OK) {
            /* MDS: every k-subset must be invertible. */
            ok = 0;
            FAIL("submatrix not invertible (not MDS)");
            voleith_ec_matrix_free(&sub);
            voleith_ec_matrix_free(&recv);
            break;
        }

        if (voleith_ec_matrix_mul(&inv, &recv, &rec) != VOLEITH_EC_OK) {
            ok = 0;
            FAIL("decode (inv . C_S) failed");
            voleith_ec_matrix_free(&sub);
            voleith_ec_matrix_free(&inv);
            voleith_ec_matrix_free(&recv);
            break;
        }

        if (!matrix_equal(&rec, &msg)) {
            ok = 0;
            FAIL("recovered message != original");
        }

        voleith_ec_matrix_free(&sub);
        voleith_ec_matrix_free(&inv);
        voleith_ec_matrix_free(&recv);
        voleith_ec_matrix_free(&rec);
    } while (ok && comb_next(idx, k, n));

    free(idx);
    voleith_ec_matrix_free(&g);
    voleith_ec_matrix_free(&msg);
    voleith_ec_matrix_free(&code);
    return ok;
}

static void
test_roundtrip_gf8_vandermonde(void)
{
    TEST("gf8 Vandermonde: every 3-of-6 subset recovers");
    if (run_roundtrip(VOLEITH_EC_FIELD_GF8, VOLEITH_EC_MATRIX_VANDERMONDE, 6, 3,
                      4))
        PASS();
}

static void
test_roundtrip_gf8_cauchy(void)
{
    TEST("gf8 Cauchy (systematic): every 3-of-6 subset recovers");
    if (run_roundtrip(VOLEITH_EC_FIELD_GF8, VOLEITH_EC_MATRIX_CAUCHY, 6, 3, 4))
        PASS();
}

static void
test_roundtrip_gf16_vandermonde(void)
{
    TEST("gf16 Vandermonde: every 3-of-6 subset recovers");
    if (run_roundtrip(VOLEITH_EC_FIELD_GF16, VOLEITH_EC_MATRIX_VANDERMONDE, 6,
                      3, 4))
        PASS();
}

static void
test_roundtrip_gf16_cauchy(void)
{
    TEST("gf16 Cauchy (systematic): every 3-of-6 subset recovers");
    if (run_roundtrip(VOLEITH_EC_FIELD_GF16, VOLEITH_EC_MATRIX_CAUCHY, 6, 3, 4))
        PASS();
}

static void
test_roundtrip_gf8_wider(void)
{
    /* A second shape exercises k=2 and a larger n. */
    TEST("gf8 Cauchy: every 2-of-5 subset recovers");
    if (run_roundtrip(VOLEITH_EC_FIELD_GF8, VOLEITH_EC_MATRIX_CAUCHY, 5, 2, 3))
        PASS();
}

static void
test_singular_reported(void)
{
    voleith_ec_matrix_t m = {0}, inv = {0};
    int rc;

    TEST("singular submatrix returns VOLEITH_EC_ERR_SINGULAR");
    if (voleith_ec_matrix_alloc(&m, VOLEITH_EC_FIELD_GF8, 3, 3) !=
        VOLEITH_EC_OK) {
        FAIL("alloc failed");
        return;
    }
    /* Rows 0 and 1 identical -> rank deficient -> singular. */
    voleith_ec_matrix_set(&m, 0, 0, 1);
    voleith_ec_matrix_set(&m, 0, 1, 2);
    voleith_ec_matrix_set(&m, 0, 2, 3);
    voleith_ec_matrix_set(&m, 1, 0, 1);
    voleith_ec_matrix_set(&m, 1, 1, 2);
    voleith_ec_matrix_set(&m, 1, 2, 3);
    voleith_ec_matrix_set(&m, 2, 0, 4);
    voleith_ec_matrix_set(&m, 2, 1, 5);
    voleith_ec_matrix_set(&m, 2, 2, 6);

    rc = voleith_ec_matrix_invert(&m, &inv);
    voleith_ec_matrix_free(&m);
    voleith_ec_matrix_free(&inv);
    if (rc != VOLEITH_EC_ERR_SINGULAR) {
        FAIL("expected VOLEITH_EC_ERR_SINGULAR");
        return;
    }
    PASS();
}

static void
test_invert_identity(void)
{
    voleith_ec_matrix_t id = {0}, inv = {0};
    int ok;

    TEST("inverse of identity is identity (gf16)");
    if (voleith_ec_matrix_alloc(&id, VOLEITH_EC_FIELD_GF16, 4, 4) !=
        VOLEITH_EC_OK) {
        FAIL("alloc failed");
        return;
    }
    voleith_ec_matrix_set(&id, 0, 0, 1);
    voleith_ec_matrix_set(&id, 1, 1, 1);
    voleith_ec_matrix_set(&id, 2, 2, 1);
    voleith_ec_matrix_set(&id, 3, 3, 1);

    if (voleith_ec_matrix_invert(&id, &inv) != VOLEITH_EC_OK) {
        voleith_ec_matrix_free(&id);
        FAIL("invert failed");
        return;
    }
    ok = matrix_equal(&id, &inv);
    voleith_ec_matrix_free(&id);
    voleith_ec_matrix_free(&inv);
    if (!ok) {
        FAIL("inv(I) != I");
        return;
    }
    PASS();
}

int
main(void)
{
    printf("=== Erasure generator-matrix / decode tests ===\n");
    test_roundtrip_gf8_vandermonde();
    test_roundtrip_gf8_cauchy();
    test_roundtrip_gf16_vandermonde();
    test_roundtrip_gf16_cauchy();
    test_roundtrip_gf8_wider();
    test_singular_reported();
    test_invert_identity();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
