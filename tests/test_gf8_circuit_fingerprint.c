/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf8_circuit_fingerprint.c - Tests for voleith_gf8_circuit_fingerprint().
 *
 * Mirrors test_circuit_fingerprint.c for the GF(2^8) element-level circuit
 * type.
 *
 * Tests:
 *   1: Determinism - same builder sequence twice produces the same 16 bytes.
 *   2: Reordering constraints changes the fingerprint.
 *   3: Reordering wires changes the fingerprint.
 *   4: Swapping XOR operands changes the fingerprint.
 *   5: Changing a const wire's value changes the fingerprint.
 *   6: Constraint-kind change (assert_zero vs assert_equal vs assert_product).
 *   7: Linear-map matrix bytes are bound.
 *   8: NULL args rejected.
 */

#include "gf8_circuit.h"
#include "gf8_circuit_fingerprint.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/*
 * Reference circuit: covers every wire kind that has interesting state
 * in the canonical encoding (witness, instance, const, xor, xor_const,
 * linear_map, square, mul) plus all three constraint kinds.
 */
static voleith_gf8_circuit_t *
build_reference(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (c == NULL)
        return NULL;

    gf8_wire_id w0 = voleith_gf8_add_witness(c);
    gf8_wire_id w1 = voleith_gf8_add_witness(c);
    gf8_wire_id inst = voleith_gf8_add_instance(c);
    gf8_wire_id k = voleith_gf8_add_const(c, 0x53);
    gf8_wire_id x = voleith_gf8_add_xor(c, w0, w1);
    gf8_wire_id xc = voleith_gf8_add_xor_const(c, x, 0xa5);
    uint8_t M[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    gf8_wire_id lm = voleith_gf8_add_linear_map(c, w0, M);
    gf8_wire_id sq = voleith_gf8_add_square(c, w1);
    gf8_wire_id m = voleith_gf8_add_mul(c, sq, lm);

    voleith_gf8_assert_zero(c, xc);
    voleith_gf8_assert_equal(c, m, inst);
    voleith_gf8_assert_product(c, w0, w1, k);

    return c;
}

/* ================================================================
 * Test 1: Determinism.
 * ================================================================ */
static void
test_determinism(void)
{
    voleith_gf8_circuit_t *c1 = build_reference();
    voleith_gf8_circuit_t *c2 = build_reference();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp3[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    check("determinism: build_reference returns non-NULL",
          c1 != NULL && c2 != NULL);
    if (c1 == NULL || c2 == NULL) {
        voleith_gf8_circuit_free(c1);
        voleith_gf8_circuit_free(c2);
        return;
    }

    check("determinism: fingerprint of c1 succeeds",
          voleith_gf8_circuit_fingerprint(c1, fp1) == 0);
    check("determinism: fingerprint of c2 succeeds",
          voleith_gf8_circuit_fingerprint(c2, fp2) == 0);
    check("determinism: re-fingerprint of c1 succeeds",
          voleith_gf8_circuit_fingerprint(c1, fp3) == 0);

    check("determinism: identical builds produce identical fingerprints",
          memcmp(fp1, fp2, sizeof(fp1)) == 0);
    check("determinism: repeated calls are idempotent",
          memcmp(fp1, fp3, sizeof(fp1)) == 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 2: Reordering constraints changes the fingerprint.
 * ================================================================ */
static void
test_constraint_reorder(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    gf8_wire_id w0 = voleith_gf8_add_witness(c1);
    gf8_wire_id w1 = voleith_gf8_add_witness(c1);
    voleith_gf8_assert_zero(c1, w0);
    voleith_gf8_assert_zero(c1, w1);

    w0 = voleith_gf8_add_witness(c2);
    w1 = voleith_gf8_add_witness(c2);
    voleith_gf8_assert_zero(c2, w1); /* reversed order */
    voleith_gf8_assert_zero(c2, w0);

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    check("reorder constraints: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 3: Reordering wires changes the fingerprint.
 * ================================================================ */
static void
test_wire_reorder(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    gf8_wire_id w0 = voleith_gf8_add_witness(c1);
    gf8_wire_id w1 = voleith_gf8_add_witness(c1);
    (void)voleith_gf8_add_instance(c1);
    voleith_gf8_assert_zero(c1, w0);
    voleith_gf8_assert_zero(c1, w1);

    (void)voleith_gf8_add_instance(c2); /* instance first */
    w0 = voleith_gf8_add_witness(c2);
    w1 = voleith_gf8_add_witness(c2);
    voleith_gf8_assert_zero(c2, w0);
    voleith_gf8_assert_zero(c2, w1);

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    check("reorder wires: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 4: Swapping XOR operands changes the fingerprint.
 * ================================================================ */
static void
test_operand_swap(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    gf8_wire_id w0 = voleith_gf8_add_witness(c1);
    gf8_wire_id w1 = voleith_gf8_add_witness(c1);
    (void)voleith_gf8_add_xor(c1, w0, w1);

    w0 = voleith_gf8_add_witness(c2);
    w1 = voleith_gf8_add_witness(c2);
    (void)voleith_gf8_add_xor(c2, w1, w0); /* swapped */

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    check("swap XOR operands: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 5: Changing a const wire's value changes the fingerprint.
 * ================================================================ */
static void
test_const_val_change(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    (void)voleith_gf8_add_const(c1, 0x53);
    (void)voleith_gf8_add_const(c2, 0x54);

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    check("change const_val: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 6: Constraint-kind change differs.
 * ================================================================ */
static void
test_constraint_kind_change(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c3 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp3[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    gf8_wire_id w0 = voleith_gf8_add_witness(c1);
    (void)voleith_gf8_add_witness(c1);
    voleith_gf8_assert_zero(c1, w0);

    w0 = voleith_gf8_add_witness(c2);
    gf8_wire_id w1 = voleith_gf8_add_witness(c2);
    voleith_gf8_assert_equal(c2, w0, w1);

    w0 = voleith_gf8_add_witness(c3);
    w1 = voleith_gf8_add_witness(c3);
    gf8_wire_id w2 = voleith_gf8_add_witness(c3);
    voleith_gf8_assert_product(c3, w0, w1, w2);

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    (void)voleith_gf8_circuit_fingerprint(c3, fp3);
    check("constraint kind: zero != equal", memcmp(fp1, fp2, sizeof(fp1)) != 0);
    check("constraint kind: equal != product",
          memcmp(fp2, fp3, sizeof(fp1)) != 0);
    check("constraint kind: zero != product",
          memcmp(fp1, fp3, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
    voleith_gf8_circuit_free(c3);
}

/* ================================================================
 * Test 7: LINEAR_MAP matrix bytes are bound.
 * ================================================================ */
static void
test_linear_map_matrix_bound(void)
{
    voleith_gf8_circuit_t *c1 = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *c2 = voleith_gf8_circuit_new();
    uint8_t fp1[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t M_a[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};
    uint8_t M_b[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x81};

    gf8_wire_id w0 = voleith_gf8_add_witness(c1);
    (void)voleith_gf8_add_linear_map(c1, w0, M_a);

    w0 = voleith_gf8_add_witness(c2);
    (void)voleith_gf8_add_linear_map(c2, w0, M_b);

    (void)voleith_gf8_circuit_fingerprint(c1, fp1);
    (void)voleith_gf8_circuit_fingerprint(c2, fp2);
    check("linear_map: matrix byte change differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_gf8_circuit_free(c1);
    voleith_gf8_circuit_free(c2);
}

/* ================================================================
 * Test 8: NULL args rejected.
 * ================================================================ */
static void
test_null_args(void)
{
    voleith_gf8_circuit_t *c = build_reference();
    uint8_t fp[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    check("null: circuit == NULL rejected",
          voleith_gf8_circuit_fingerprint(NULL, fp) != 0);
    check("null: out == NULL rejected",
          voleith_gf8_circuit_fingerprint(c, NULL) != 0);
    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    printf("test_gf8_circuit_fingerprint: starting\n");
    test_determinism();
    test_constraint_reorder();
    test_wire_reorder();
    test_operand_swap();
    test_const_val_change();
    test_constraint_kind_change();
    test_linear_map_matrix_bound();
    test_null_args();
    printf("test_gf8_circuit_fingerprint: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
