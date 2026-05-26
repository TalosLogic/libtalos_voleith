/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_circuit.c - Tests for the Boolean circuit definition API
 *
 * Tests:
 *   1: Wire ID assignment (witness, instance, const)
 *   2: Gate counts and wire counts
 *   3: Topological order guarantee (inputs always before gate outputs)
 *   4: Circuit evaluation - correct gate semantics
 *   5: Constraint checking - assert_zero and assert_equal
 *   6: Constraint failures detected on incorrect witnesses
 *   7: Larger circuit (x AND y XOR z) end-to-end
 */

#include "circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

/* Helper: get the value of wire w from a wire_vals buffer */
static uint8_t
wire_val(const uint8_t *wire_vals, wire_id w)
{
    return (wire_vals[w / 8] >> (w % 8)) & 1;
}

/* Helper: pack a single bit into a byte array at position idx */
static void
set_bit(uint8_t *arr, size_t idx, uint8_t val)
{
    if (val & 1)
        arr[idx / 8] |= (uint8_t)(1u << (idx % 8));
    else
        arr[idx / 8] &= (uint8_t) ~(1u << (idx % 8));
}

/*
 * Test 1: Wire ID assignment
 * Witness, instance, and const wires are assigned sequential IDs.
 */
static void
test_wire_id_assignment(void)
{
    voleith_circuit_t *c = voleith_circuit_new();
    check("circuit_new returns non-NULL", c != NULL);

    wire_id w0 = voleith_circuit_add_witness(c);
    wire_id w1 = voleith_circuit_add_witness(c);
    wire_id i0 = voleith_circuit_add_instance(c);
    wire_id k0 = voleith_circuit_add_const(c, 0);
    wire_id k1 = voleith_circuit_add_const(c, 1);

    check("wire IDs are sequential",
          w0 == 0 && w1 == 1 && i0 == 2 && k0 == 3 && k1 == 4);
    check("witness count = 2", voleith_circuit_witness_count(c) == 2);
    check("instance count = 1", voleith_circuit_instance_count(c) == 1);
    check("wire count = 5", voleith_circuit_wire_count(c) == 5);
    check("and gate count = 0", voleith_circuit_and_gate_count(c) == 0);

    voleith_circuit_free(c);
}

/*
 * Test 2: Gate counts
 */
static void
test_gate_counts(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_witness(c);

    wire_id x = voleith_circuit_add_xor(c, a, b);
    wire_id y = voleith_circuit_add_and(c, a, b);
    wire_id z = voleith_circuit_add_not(c, a);
    wire_id w = voleith_circuit_add_and(c, x, y);
    (void)z;
    (void)w;

    check("and gate count = 2", voleith_circuit_and_gate_count(c) == 2);
    check("wire count = 6 (2 witness + 4 gate)",
          voleith_circuit_wire_count(c) == 6);

    voleith_circuit_free(c);
}

/*
 * Test 3: Topological order - gate inputs always have smaller IDs than outputs.
 */
static void
test_topological_order(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_witness(c);
    wire_id x = voleith_circuit_add_xor(c, a, b);
    wire_id y = voleith_circuit_add_and(c, a, x);
    wire_id z = voleith_circuit_add_not(c, y);
    (void)z;

    const wire_entry_t *wires = voleith_circuit_wires(c);
    size_t n = voleith_circuit_wire_count(c);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (wires[i].a != WIRE_ID_INVALID && wires[i].a >= (wire_id)i) {
            ok = 0;
            break;
        }
        if (wires[i].b != WIRE_ID_INVALID && wires[i].b >= (wire_id)i) {
            ok = 0;
            break;
        }
    }
    check("all gate inputs have smaller IDs than their output", ok);

    voleith_circuit_free(c);
}

/*
 * Test 4: Circuit evaluation - gate semantics
 */
static void
test_eval_gate_semantics(void)
{
    /* Build: a=witness, b=witness, k1=const(1)
     *   xor_ab = a XOR b
     *   and_ab = a AND b
     *   not_a  = NOT a
     *   xor_k  = a XOR 1  (= NOT a via XOR with const 1)
     */
    voleith_circuit_t *c = voleith_circuit_new();
    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_witness(c);
    wire_id k1 = voleith_circuit_add_const(c, 1);
    wire_id xor_ab = voleith_circuit_add_xor(c, a, b);
    wire_id and_ab = voleith_circuit_add_and(c, a, b);
    wire_id not_a = voleith_circuit_add_not(c, a);
    wire_id xor_k = voleith_circuit_add_xor(c, a, k1);
    (void)k1;

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);

    /* Test all 4 combinations of (a, b) */
    static const uint8_t bits[4][2] = {{0, 0}, {0, 1}, {1, 0}, {1, 1}};
    int ok_xor = 1, ok_and = 1, ok_not = 1, ok_xork = 1;

    for (int t = 0; t < 4; t++) {
        uint8_t wa = bits[t][0], wb = bits[t][1];
        uint8_t witness[1] = {0};
        set_bit(witness, 0, wa);
        set_bit(witness, 1, wb);

        memset(vals, 0, (n_wires + 7) / 8);
        voleith_circuit_eval(c, witness, NULL, vals);

        if (wire_val(vals, xor_ab) != (wa ^ wb))
            ok_xor = 0;
        if (wire_val(vals, and_ab) != (wa & wb))
            ok_and = 0;
        if (wire_val(vals, not_a) != (wa ^ 1))
            ok_not = 0;
        if (wire_val(vals, xor_k) != (wa ^ 1))
            ok_xork = 0;
    }

    check("XOR gate semantics correct for all inputs", ok_xor);
    check("AND gate semantics correct for all inputs", ok_and);
    check("NOT gate semantics correct for all inputs", ok_not);
    check("XOR-with-const-1 equals NOT", ok_xork);

    free(vals);
    voleith_circuit_free(c);
}

/*
 * Test 5: Constraints - assert_zero and assert_equal
 */
static void
test_constraints(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_witness(c);
    wire_id xab = voleith_circuit_add_xor(c, a, b);

    /* assert a XOR b == 0 (i.e., a == b) */
    voleith_circuit_assert_zero(c, xab);

    check("constraint count = 1", voleith_circuit_constraint_count(c) == 1);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);

    /* a=0, b=0: a XOR b = 0, constraint passes */
    uint8_t witness[1] = {0};
    set_bit(witness, 0, 0);
    set_bit(witness, 1, 0);
    int r = voleith_circuit_eval(c, witness, NULL, vals);
    check("assert_zero: 0 XOR 0 = 0 passes", r == 1);

    /* a=1, b=1: a XOR b = 0, constraint passes */
    memset(vals, 0, (n_wires + 7) / 8);
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 1);
    r = voleith_circuit_eval(c, witness, NULL, vals);
    check("assert_zero: 1 XOR 1 = 0 passes", r == 1);

    /* a=0, b=1: a XOR b = 1, constraint fails */
    memset(vals, 0, (n_wires + 7) / 8);
    set_bit(witness, 0, 0);
    set_bit(witness, 1, 1);
    r = voleith_circuit_eval(c, witness, NULL, vals);
    check("assert_zero: 0 XOR 1 = 1 fails", r == 0);

    free(vals);
    voleith_circuit_free(c);
}

/*
 * Test 6: assert_equal
 */
static void
test_assert_equal(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id a = voleith_circuit_add_witness(c);
    wire_id b = voleith_circuit_add_instance(c);
    voleith_circuit_assert_equal(c, a, b);

    check("assert_equal adds one constraint",
          voleith_circuit_constraint_count(c) == 1);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);

    uint8_t witness[1] = {0}, instance[1] = {0};

    /* a=1, b=1: equal, passes */
    set_bit(witness, 0, 1);
    set_bit(instance, 0, 1);
    int r = voleith_circuit_eval(c, witness, instance, vals);
    check("assert_equal: 1 == 1 passes", r == 1);

    /* a=0, b=1: not equal, fails */
    memset(vals, 0, (n_wires + 7) / 8);
    set_bit(witness, 0, 0);
    set_bit(instance, 0, 1);
    r = voleith_circuit_eval(c, witness, instance, vals);
    check("assert_equal: 0 != 1 fails", r == 0);

    free(vals);
    voleith_circuit_free(c);
}

/*
 * Test 7: Larger circuit - (a AND b) XOR c = target (public)
 *
 * Circuit: given witness (a, b, c) and instance (target),
 * asserts (a AND b) XOR c == target.
 */
static void
test_larger_circuit(void)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id wa = voleith_circuit_add_witness(c);
    wire_id wb = voleith_circuit_add_witness(c);
    wire_id wc = voleith_circuit_add_witness(c);
    wire_id target = voleith_circuit_add_instance(c);

    wire_id ab = voleith_circuit_add_and(c, wa, wb);
    wire_id ab_xc = voleith_circuit_add_xor(c, ab, wc);
    wire_id diff = voleith_circuit_add_xor(c, ab_xc, target);
    voleith_circuit_assert_zero(c, diff);

    check("larger circuit: 1 AND gate", voleith_circuit_and_gate_count(c) == 1);
    check("larger circuit: 3 witness, 1 instance",
          voleith_circuit_witness_count(c) == 3 &&
              voleith_circuit_instance_count(c) == 1);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *vals = calloc((n_wires + 7) / 8, 1);
    uint8_t witness[1] = {0}, instance[1] = {0};

    /* a=1, b=1, c=0: (1 AND 1) XOR 0 = 1; target=1 → passes */
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 1);
    set_bit(witness, 2, 0);
    set_bit(instance, 0, 1);
    int r = voleith_circuit_eval(c, witness, instance, vals);
    check("larger circuit: (1&1)^0 = 1, target=1 passes", r == 1);

    /* same but target=0 → fails */
    memset(vals, 0, (n_wires + 7) / 8);
    set_bit(instance, 0, 0);
    r = voleith_circuit_eval(c, witness, instance, vals);
    check("larger circuit: (1&1)^0 = 1, target=0 fails", r == 0);

    /* a=1, b=0, c=1: (1 AND 0) XOR 1 = 1; target=1 → passes */
    memset(vals, 0, (n_wires + 7) / 8);
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 0);
    set_bit(witness, 2, 1);
    set_bit(instance, 0, 1);
    r = voleith_circuit_eval(c, witness, instance, vals);
    check("larger circuit: (1&0)^1 = 1, target=1 passes", r == 1);

    free(vals);
    voleith_circuit_free(c);
}

int
main(void)
{
    printf("test_circuit: Boolean circuit definition API\n");

    test_wire_id_assignment();
    test_gate_counts();
    test_topological_order();
    test_eval_gate_semantics();
    test_constraints();
    test_assert_equal();
    test_larger_circuit();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
