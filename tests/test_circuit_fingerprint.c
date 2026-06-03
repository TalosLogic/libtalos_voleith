/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_circuit_fingerprint.c - Tests for voleith_circuit_fingerprint().
 *
 * Exercises the canonical circuit serialization indirectly: by
 * constructing pairs of circuits that the spec says should fingerprint
 * the same (deterministic build) or differently (reordered
 * wires/constraints, swapped operands, modified constants), and
 * confirming the fingerprint behaves accordingly.
 *
 * Tests:
 *   1: Determinism - same builder sequence twice produces the same 16 bytes.
 *   2: Reordering constraints changes the fingerprint.
 *   3: Reordering wires changes the fingerprint.
 *   4: Swapping XOR operands changes the fingerprint (a XOR b vs b XOR a).
 *   5: Changing a const-wire bit changes the fingerprint.
 *   6: Constraint-kind change (assert_zero vs assert_equal) changes output.
 *   7: NULL args rejected.
 */

#include "circuit.h"
#include "circuit_fingerprint.h"

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
 * Build a small reference circuit:
 *   w0 = witness, w1 = witness, w2 = instance, w3 = const(1)
 *   a  = w0 AND w1
 *   x  = a XOR w2
 *   n  = NOT x
 *   constraint: assert n == w3
 *
 * Mixes every wire kind plus one constraint so the fingerprint
 * exercises every branch of the canonical serializer.
 */
static voleith_circuit_t *
build_reference(void)
{
    voleith_circuit_t *c;
    wire_id w0, w1, w2, w3, a, x, n;

    c = voleith_circuit_new();
    if (c == NULL)
        return NULL;

    w0 = voleith_circuit_add_witness(c);
    w1 = voleith_circuit_add_witness(c);
    w2 = voleith_circuit_add_instance(c);
    w3 = voleith_circuit_add_const(c, 1);
    a = voleith_circuit_add_and(c, w0, w1);
    x = voleith_circuit_add_xor(c, a, w2);
    n = voleith_circuit_add_not(c, x);
    voleith_circuit_assert_equal(c, n, w3);

    return c;
}

/* ================================================================
 * Test 1: Determinism.
 * ================================================================ */
static void
test_determinism(void)
{
    voleith_circuit_t *c1, *c2;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp3[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    c1 = build_reference();
    c2 = build_reference();

    check("determinism: build_reference returns non-NULL",
          c1 != NULL && c2 != NULL);

    if (c1 == NULL || c2 == NULL) {
        voleith_circuit_free(c1);
        voleith_circuit_free(c2);
        return;
    }

    check("determinism: fingerprint of c1 succeeds",
          voleith_circuit_fingerprint(c1, fp1) == 0);
    check("determinism: fingerprint of c2 succeeds",
          voleith_circuit_fingerprint(c2, fp2) == 0);
    /* Recompute over c1 to confirm the call has no hidden state. */
    check("determinism: re-fingerprint of c1 succeeds",
          voleith_circuit_fingerprint(c1, fp3) == 0);

    check("determinism: identical builds produce identical fingerprints",
          memcmp(fp1, fp2, sizeof(fp1)) == 0);
    check("determinism: repeated calls are idempotent",
          memcmp(fp1, fp3, sizeof(fp1)) == 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 2: Reordering constraints changes the fingerprint.
 * ================================================================ */
static void
test_constraint_reorder(void)
{
    voleith_circuit_t *c1, *c2;
    wire_id w0, w1, x, y;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    /* c1: assert(x == 0); assert(y == 0) */
    c1 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c1);
    w1 = voleith_circuit_add_witness(c1);
    x = voleith_circuit_add_and(c1, w0, w1);
    y = voleith_circuit_add_xor(c1, w0, w1);
    voleith_circuit_assert_zero(c1, x);
    voleith_circuit_assert_zero(c1, y);

    /* c2: identical wires, but constraints in reverse order. */
    c2 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c2);
    w1 = voleith_circuit_add_witness(c2);
    x = voleith_circuit_add_and(c2, w0, w1);
    y = voleith_circuit_add_xor(c2, w0, w1);
    voleith_circuit_assert_zero(c2, y);
    voleith_circuit_assert_zero(c2, x);

    (void)voleith_circuit_fingerprint(c1, fp1);
    (void)voleith_circuit_fingerprint(c2, fp2);

    check("reorder constraints: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 3: Reordering wires changes the fingerprint.
 *
 * The two circuits compute the same function but in a different order
 * of declaration.  Canonical serialization is wire-order-sensitive, so
 * they MUST produce different fingerprints - identity binding depends
 * on it.
 * ================================================================ */
static void
test_wire_reorder(void)
{
    voleith_circuit_t *c1, *c2;
    wire_id w0, w1, w2;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    /* c1: witness, witness, instance. */
    c1 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c1);
    w1 = voleith_circuit_add_witness(c1);
    w2 = voleith_circuit_add_instance(c1);
    (void)voleith_circuit_add_xor(c1, w0, w1);
    voleith_circuit_assert_zero(c1, w2);

    /* c2: instance, witness, witness - flipped order. */
    c2 = voleith_circuit_new();
    w2 = voleith_circuit_add_instance(c2);
    w0 = voleith_circuit_add_witness(c2);
    w1 = voleith_circuit_add_witness(c2);
    (void)voleith_circuit_add_xor(c2, w0, w1);
    voleith_circuit_assert_zero(c2, w2);

    (void)voleith_circuit_fingerprint(c1, fp1);
    (void)voleith_circuit_fingerprint(c2, fp2);

    check("reorder wires: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 4: Swapping XOR operands changes the fingerprint.
 *
 * (a XOR b) and (b XOR a) compute the same value but the canonical
 * encoding records the operand order verbatim, so they fingerprint
 * differently.  This is desirable: identity binding must reflect the
 * exact circuit structure, not its semantic equivalence class.
 * ================================================================ */
static void
test_operand_swap(void)
{
    voleith_circuit_t *c1, *c2;
    wire_id w0, w1;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    c1 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c1);
    w1 = voleith_circuit_add_witness(c1);
    (void)voleith_circuit_add_xor(c1, w0, w1);

    c2 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c2);
    w1 = voleith_circuit_add_witness(c2);
    (void)voleith_circuit_add_xor(c2, w1, w0); /* operands swapped */

    (void)voleith_circuit_fingerprint(c1, fp1);
    (void)voleith_circuit_fingerprint(c2, fp2);

    check("swap XOR operands: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 5: Changing a const-wire's bit value changes the fingerprint.
 * ================================================================ */
static void
test_const_bit_change(void)
{
    voleith_circuit_t *c1, *c2;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    c1 = voleith_circuit_new();
    (void)voleith_circuit_add_const(c1, 0);

    c2 = voleith_circuit_new();
    (void)voleith_circuit_add_const(c2, 1);

    (void)voleith_circuit_fingerprint(c1, fp1);
    (void)voleith_circuit_fingerprint(c2, fp2);

    check("change const bit: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 6: Constraint kind change (assert_zero vs assert_equal) differs.
 * ================================================================ */
static void
test_constraint_kind_change(void)
{
    voleith_circuit_t *c1, *c2;
    wire_id w0, w1;
    uint8_t fp1[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp2[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    c1 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c1);
    (void)voleith_circuit_add_witness(c1);
    voleith_circuit_assert_zero(c1, w0);

    c2 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c2);
    w1 = voleith_circuit_add_witness(c2);
    voleith_circuit_assert_equal(c2, w0, w1);

    (void)voleith_circuit_fingerprint(c1, fp1);
    (void)voleith_circuit_fingerprint(c2, fp2);

    check("constraint kind change: fingerprint differs",
          memcmp(fp1, fp2, sizeof(fp1)) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 7: NULL args rejected.
 * ================================================================ */
static void
test_null_args(void)
{
    voleith_circuit_t *c;
    uint8_t fp[VOLEITH_CIRCUIT_FINGERPRINT_BYTES];

    c = build_reference();
    check("null: circuit == NULL rejected",
          voleith_circuit_fingerprint(NULL, fp) != 0);
    check("null: out == NULL rejected",
          voleith_circuit_fingerprint(c, NULL) != 0);
    voleith_circuit_free(c);
}

int
main(void)
{
    printf("test_circuit_fingerprint: starting\n");
    test_determinism();
    test_constraint_reorder();
    test_wire_reorder();
    test_operand_swap();
    test_const_bit_change();
    test_constraint_kind_change();
    test_null_args();
    printf("test_circuit_fingerprint: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
