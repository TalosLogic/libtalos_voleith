/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf8_circuit.c - Tests for the GF(2⁸) element-level circuit API
 *
 * Tests:
 *   1:  Wire ID assignment (witness, instance, const)
 *   2:  Counter tracking (witness, instance, mul, assert_product counts)
 *   3:  ell formula: ell = n_witness + n_mul
 *   4:  Topological order guarantee
 *   5:  Evaluation - XOR gate semantics
 *   6:  Evaluation - XOR_CONST gate semantics
 *   7:  Evaluation - MUL gate semantics (spot checks)
 *   8:  Evaluation - SQUARE gate correctness for all 256 inputs
 *   9:  Evaluation - LINEAR_MAP gate (identity matrix)
 *  10:  Evaluation - LINEAR_MAP gate (swap-bits matrix)
 *  11:  MUX gate: sel=0 selects a, sel=1 selects b
 *  12:  MUX gate costs exactly one VOLE slot (one MUL)
 *  13:  Inverse circuit (Proposition 6.4): assert_product x²·x⁻¹ = x and
 *       x·(x⁻¹)² = x⁻¹, using zero MUL gates (VOLE slot count = 2)
 *  14:  Inverse circuit evaluates correctly for valid witness
 *  15:  Inverse circuit fails for wrong inverse witness
 *  16:  assert_zero: passes when wire = 0x00, fails otherwise
 *  17:  assert_equal: passes when wires match, fails otherwise
 *  18:  assert_product: passes for correct product, fails for wrong
 *  19:  Instance wires evaluated from instance array
 */

#include "../proof/gf8_circuit.h"
#include "../core/field.h"
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

/* ================================================================
 * Test helpers
 * ================================================================ */

/* ================================================================
 * Test 1: Wire ID assignment
 * ================================================================ */
static void
test_wire_id_assignment(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    check("circuit_new returns non-NULL", c != NULL);

    gf8_wire_id w0 = voleith_gf8_add_witness(c);
    gf8_wire_id w1 = voleith_gf8_add_witness(c);
    gf8_wire_id i0 = voleith_gf8_add_instance(c);
    gf8_wire_id k0 = voleith_gf8_add_const(c, 0x00);
    gf8_wire_id k1 = voleith_gf8_add_const(c, 0xFF);
    gf8_wire_id m0 = voleith_gf8_add_mul(c, w0, w1);

    check("wire IDs are sequential",
          w0 == 0 && w1 == 1 && i0 == 2 && k0 == 3 && k1 == 4 && m0 == 5);
    check("wire_count = 6", voleith_gf8_circuit_wire_count(c) == 6);
    check("ok flag is set", voleith_gf8_circuit_ok(c) == 1);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 2: Counter tracking
 * ================================================================ */
static void
test_counter_tracking(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id p = voleith_gf8_add_instance(c);

    gf8_wire_id xab = voleith_gf8_add_xor(c, a, b);
    gf8_wire_id m1 = voleith_gf8_add_mul(c, a, b);
    gf8_wire_id m2 = voleith_gf8_add_mul(c, m1, p);
    (void)xab;

    /* assert_product does not create a wire, just a constraint */
    voleith_gf8_assert_product(c, a, b, m1);
    voleith_gf8_assert_product(c, m1, p, m2);

    check("witness count = 2", voleith_gf8_circuit_witness_count(c) == 2);
    check("instance count = 1", voleith_gf8_circuit_instance_count(c) == 1);
    check("mul count = 2", voleith_gf8_circuit_mul_count(c) == 2);
    check("assert_product count = 2",
          voleith_gf8_circuit_assert_product_count(c) == 2);
    check("constraint count = 2", voleith_gf8_circuit_constraint_count(c) == 2);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 3: ell formula
 * ================================================================ */
static void
test_ell_formula(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    /* ell = 0 initially */
    check("ell = 0 for empty circuit", voleith_gf8_qs_ell(c) == 0);

    gf8_wire_id w0 = voleith_gf8_add_witness(c);
    gf8_wire_id w1 = voleith_gf8_add_witness(c);
    gf8_wire_id w2 = voleith_gf8_add_witness(c);
    check("ell = 3 after 3 witnesses", voleith_gf8_qs_ell(c) == 3);

    /* Free operations do not increase ell */
    gf8_wire_id s = voleith_gf8_add_square(c, w0);
    (void)s;
    check("ell = 3 after square (free)", voleith_gf8_qs_ell(c) == 3);

    /* Each add_mul adds 1 to ell */
    gf8_wire_id m = voleith_gf8_add_mul(c, w0, w1);
    check("ell = 4 after one mul", voleith_gf8_qs_ell(c) == 4);

    /* assert_product does not increase ell */
    voleith_gf8_assert_product(c, w0, w1, m);
    check("ell = 4 after assert_product (free)", voleith_gf8_qs_ell(c) == 4);

    /* add_mux adds 1 mul internally */
    gf8_wire_id sel = w2;
    gf8_wire_id mx = voleith_gf8_add_mux(c, w0, w1, sel);
    (void)mx;
    check("ell = 5 after mux (1 internal mul)", voleith_gf8_qs_ell(c) == 5);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 4: Topological order
 * Every gate input must have a smaller wire ID than its output.
 * ================================================================ */
static void
test_topological_order(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id x = voleith_gf8_add_xor(c, a, b);
    gf8_wire_id y = voleith_gf8_add_mul(c, a, x);
    gf8_wire_id z = voleith_gf8_add_square(c, y);
    (void)z;

    const gf8_wire_entry_t *wires = voleith_gf8_circuit_wires(c);
    size_t n = voleith_gf8_circuit_wire_count(c);

    int ok = 1;
    for (size_t i = 0; i < n; i++) {
        if (wires[i].a != GF8_WIRE_ID_INVALID && wires[i].a >= (gf8_wire_id)i) {
            ok = 0;
            break;
        }
        if (wires[i].b != GF8_WIRE_ID_INVALID && wires[i].b >= (gf8_wire_id)i) {
            ok = 0;
            break;
        }
    }
    check("all gate inputs have smaller IDs than their output", ok);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 5: XOR gate evaluation
 * ================================================================ */
static void
test_xor_eval(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id x = voleith_gf8_add_xor(c, a, b);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* Test (0x53 XOR 0xCA) = 0x99 */
    uint8_t witness[2] = {0x53, 0xCA};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("XOR: 0x53 XOR 0xCA = 0x99", vals[x] == (0x53 ^ 0xCA));

    /* Test (0xFF XOR 0xFF) = 0x00 */
    witness[0] = 0xFF;
    witness[1] = 0xFF;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("XOR: 0xFF XOR 0xFF = 0x00", vals[x] == 0x00);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 6: XOR_CONST gate evaluation
 * ================================================================ */
static void
test_xor_const_eval(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id x = voleith_gf8_add_xor_const(c, a, 0xAB);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t witness[1] = {0x53};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("XOR_CONST: 0x53 XOR 0xAB = 0xF8", vals[x] == (0x53 ^ 0xAB));

    witness[0] = 0x00;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("XOR_CONST: 0x00 XOR 0xAB = 0xAB", vals[x] == 0xAB);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 7: MUL gate evaluation
 * ================================================================ */
static void
test_mul_eval(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id m = voleith_gf8_add_mul(c, a, b);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* 0x02 * 0x02 = 0x04 (shift left 1, no reduction needed) */
    uint8_t witness[2] = {0x02, 0x02};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUL: 0x02 * 0x02 = 0x04",
          vals[m] == voleith_gf8_mul(0x02, 0x02) && vals[m] == 0x04);

    /* 0x53 * 0x01 = 0x53 (identity) */
    witness[0] = 0x53;
    witness[1] = 0x01;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUL: 0x53 * 0x01 = 0x53", vals[m] == 0x53);

    /* 0x00 * anything = 0x00 */
    witness[0] = 0x00;
    witness[1] = 0xFF;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUL: 0x00 * 0xFF = 0x00", vals[m] == 0x00);

    /* Spot-check against field.c for a nontrivial product */
    witness[0] = 0xA5;
    witness[1] = 0x3C;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUL: 0xA5 * 0x3C matches voleith_gf8_mul",
          vals[m] == voleith_gf8_mul(0xA5, 0x3C));

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 8: SQUARE gate - all 256 inputs
 * Frobenius squaring: a² in GF(2⁸) must equal gf8_mul(a, a).
 * ================================================================ */
static void
test_square_all_inputs(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id s = voleith_gf8_add_square(c, a);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    int all_ok = 1;
    for (int x = 0; x < 256; x++) {
        uint8_t witness[1] = {(uint8_t)x};
        memset(vals, 0, n);
        voleith_gf8_circuit_eval(c, witness, NULL, vals);
        uint8_t expected = voleith_gf8_mul((uint8_t)x, (uint8_t)x);
        if (vals[s] != expected) {
            printf("  FAIL: SQUARE(0x%02X) = 0x%02X, expected 0x%02X\n", x,
                   vals[s], expected);
            all_ok = 0;
            break;
        }
    }
    check("SQUARE gate correct for all 256 inputs", all_ok);
    check("SQUARE does not increase mul count",
          voleith_gf8_circuit_mul_count(c) == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 9: LINEAR_MAP - identity matrix
 * ================================================================ */
static void
test_linear_map_identity(void)
{
    /* Identity matrix: row i = (1 << i) */
    static const uint8_t I8[8] = {0x01, 0x02, 0x04, 0x08,
                                  0x10, 0x20, 0x40, 0x80};

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id o = voleith_gf8_add_linear_map(c, a, I8);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t witness[1] = {0xA7};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("LINEAR_MAP identity: output = input", vals[o] == 0xA7);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 10: LINEAR_MAP - bit-reversal permutation matrix
 * Reverses the 8 bits: row i maps input bit (7-i) to output bit i.
 * Matrix row i = (1 << (7-i)).
 * ================================================================ */
static void
test_linear_map_bit_reverse(void)
{
    /* Bit-reversal matrix: row i = (1 << (7-i)) */
    static const uint8_t R8[8] = {0x80, 0x40, 0x20, 0x10,
                                  0x08, 0x04, 0x02, 0x01};

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id o = voleith_gf8_add_linear_map(c, a, R8);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* Reverse of 0b10110001 (0xB1) = 0b10001101 (0x8D) */
    uint8_t witness[1] = {0xB1};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("LINEAR_MAP bit-reverse: 0xB1 reversed = 0x8D", vals[o] == 0x8D);

    /* Reverse of 0xFF = 0xFF */
    witness[0] = 0xFF;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("LINEAR_MAP bit-reverse: 0xFF reversed = 0xFF", vals[o] == 0xFF);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 11: MUX evaluation
 * ================================================================ */
static void
test_mux_eval(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id sel = voleith_gf8_add_witness(c);
    gf8_wire_id out = voleith_gf8_add_mux(c, a, b, sel);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* sel=0x00: output should be a */
    uint8_t witness[3] = {0x53, 0xCA, 0x00};
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUX sel=0: output = a (0x53)", vals[out] == 0x53);

    /* sel=0x01: output should be b */
    witness[2] = 0x01;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUX sel=1: output = b (0xCA)", vals[out] == 0xCA);

    /* a = b: output is always a regardless of sel */
    witness[0] = 0x42;
    witness[1] = 0x42;
    witness[2] = 0x00;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUX a=b, sel=0: output = a = b", vals[out] == 0x42);

    witness[2] = 0x01;
    memset(vals, 0, n);
    voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("MUX a=b, sel=1: output = a = b", vals[out] == 0x42);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 12: MUX VOLE slot count
 * add_mux must add exactly 1 to mul_count (one internal MUL gate).
 * ================================================================ */
static void
test_mux_slot_count(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id sel = voleith_gf8_add_witness(c);

    check("mul_count = 0 before mux", voleith_gf8_circuit_mul_count(c) == 0);
    gf8_wire_id mx = voleith_gf8_add_mux(c, a, b, sel);
    (void)mx;
    check("mul_count = 1 after one mux", voleith_gf8_circuit_mul_count(c) == 1);
    check("ell = 4 (3 witnesses + 1 mux mul)", voleith_gf8_qs_ell(c) == 4);

    /* mux internally creates 3 wires: XOR, MUL, XOR */
    /* wire_count = 3 witnesses + 3 internal = 6 */
    check("wire_count = 6 after mux", voleith_gf8_circuit_wire_count(c) == 6);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 13: Inverse circuit (Proposition 6.4)
 *
 * To prove y = x⁻¹ (or x = y = 0) without an add_mul gate:
 *   1. Declare witnesses x and y (= x⁻¹).
 *   2. Compute x² = square(x)  and  y² = square(y)  (both free).
 *   3. assert_product(x², y, x)   - checks x² · y = x
 *   4. assert_product(x, y², y)   - checks x · y² = y
 *
 * By Proposition 6.4, these two constraints together prove y = x⁻¹
 * (or x = y = 0).
 *
 * Expected: 2 witnesses, 0 mul gates, ell = 2, 2 assert_product constraints.
 * ================================================================ */
static void
test_inverse_circuit_structure(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id x = voleith_gf8_add_witness(c);    /* slot 0 */
    gf8_wire_id y = voleith_gf8_add_witness(c);    /* slot 1 (= x⁻¹) */
    gf8_wire_id x2 = voleith_gf8_add_square(c, x); /* free */
    gf8_wire_id y2 = voleith_gf8_add_square(c, y); /* free */

    voleith_gf8_assert_product(c, x2, y, x); /* x²·y = x */
    voleith_gf8_assert_product(c, x, y2, y); /* x·y² = y */

    check("inv circuit: witness count = 2",
          voleith_gf8_circuit_witness_count(c) == 2);
    check("inv circuit: mul count = 0 (no add_mul)",
          voleith_gf8_circuit_mul_count(c) == 0);
    check("inv circuit: ell = 2 (only 2 witness slots)",
          voleith_gf8_qs_ell(c) == 2);
    check("inv circuit: assert_product count = 2",
          voleith_gf8_circuit_assert_product_count(c) == 2);

    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 14: Inverse circuit evaluates correctly for valid witnesses
 * ================================================================ */
static void
test_inverse_circuit_valid(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id x = voleith_gf8_add_witness(c);
    gf8_wire_id y = voleith_gf8_add_witness(c);
    gf8_wire_id x2 = voleith_gf8_add_square(c, x);
    gf8_wire_id y2 = voleith_gf8_add_square(c, y);
    voleith_gf8_assert_product(c, x2, y, x);
    voleith_gf8_assert_product(c, x, y2, y);
    (void)x2;
    (void)y2;

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* x=1, y=1 (trivial: 1⁻¹ = 1) */
    uint8_t witness[2] = {0x01, 0x01};
    int r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("inv circuit: x=1, y=1 passes", r == 1);

    /* x=0, y=0 (degenerate: 0·0 = 0) */
    witness[0] = 0x00;
    witness[1] = 0x00;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("inv circuit: x=0, y=0 passes", r == 1);

    /* x=0x02, y=inv(0x02).
     * inv(0x02) in GF(2⁸): 0x02 * y = 1 → y = 0x8D.
     * Verify: gf8_mul(0x02, 0x8D) should = 0x01. */
    uint8_t y_val = 0x8D; /* inv(0x02) in AES field */
    if (voleith_gf8_mul(0x02, y_val) != 0x01) {
        /* Recompute: find y such that 0x02 * y = 1 */
        for (int i = 1; i < 256; i++) {
            if (voleith_gf8_mul(0x02, (uint8_t)i) == 0x01) {
                y_val = (uint8_t)i;
                break;
            }
        }
    }
    witness[0] = 0x02;
    witness[1] = y_val;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("inv circuit: x=0x02, y=inv(0x02) passes", r == 1);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 15: Inverse circuit fails for wrong inverse witness
 * ================================================================ */
static void
test_inverse_circuit_invalid(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id x = voleith_gf8_add_witness(c);
    gf8_wire_id y = voleith_gf8_add_witness(c);
    gf8_wire_id x2 = voleith_gf8_add_square(c, x);
    gf8_wire_id y2 = voleith_gf8_add_square(c, y);
    voleith_gf8_assert_product(c, x2, y, x);
    voleith_gf8_assert_product(c, x, y2, y);
    (void)x2;
    (void)y2;

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    /* x=0x02, y=0x02 (wrong: y should be inv(0x02), not 0x02 itself) */
    uint8_t witness[2] = {0x02, 0x02};
    int r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("inv circuit: x=0x02, y=0x02 (wrong) fails", r == 0);

    /* x=0x53, y=0x00 (wrong) */
    witness[0] = 0x53;
    witness[1] = 0x00;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("inv circuit: x=0x53, y=0x00 (wrong) fails", r == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 16: assert_zero
 * ================================================================ */
static void
test_assert_zero(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id d = voleith_gf8_add_xor(c, a, b);
    voleith_gf8_assert_zero(c, d); /* assert a XOR b = 0, i.e., a = b */

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t witness[2];

    /* a = b → a XOR b = 0 → passes */
    witness[0] = 0x53;
    witness[1] = 0x53;
    int r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("assert_zero: a XOR a = 0 passes", r == 1);

    /* a ≠ b → a XOR b ≠ 0 → fails */
    witness[0] = 0x53;
    witness[1] = 0x54;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("assert_zero: 0x53 XOR 0x54 ≠ 0 fails", r == 0);

    /* zero wire directly */
    voleith_gf8_circuit_free(c);
    c = voleith_gf8_circuit_new();
    gf8_wire_id z = voleith_gf8_add_const(c, 0x00);
    voleith_gf8_assert_zero(c, z);
    n = voleith_gf8_circuit_wire_count(c);
    vals = realloc(vals, n);
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, NULL, NULL, vals);
    check("assert_zero: const 0x00 passes", r == 1);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 17: assert_equal
 * ================================================================ */
static void
test_assert_equal(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, a, b);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t witness[1], instance[1];

    witness[0] = 0xAB;
    instance[0] = 0xAB;
    int r = voleith_gf8_circuit_eval(c, witness, instance, vals);
    check("assert_equal: 0xAB == 0xAB passes", r == 1);

    witness[0] = 0xAB;
    instance[0] = 0xAC;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, instance, vals);
    check("assert_equal: 0xAB != 0xAC fails", r == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 18: assert_product
 * ================================================================ */
static void
test_assert_product(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_witness(c);
    gf8_wire_id p = voleith_gf8_add_witness(c);
    /* assert a * b == p */
    voleith_gf8_assert_product(c, a, b, p);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t wa = 0x53, wb = 0xCA;
    uint8_t correct_p = voleith_gf8_mul(wa, wb);

    uint8_t witness[3] = {wa, wb, correct_p};
    int r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("assert_product: correct product passes", r == 1);

    /* wrong product: correct_p XOR 1 */
    witness[2] = correct_p ^ 0x01;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("assert_product: wrong product fails", r == 0);

    /* a=0, b=anything, p=0 */
    witness[0] = 0x00;
    witness[1] = 0xFF;
    witness[2] = 0x00;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("assert_product: 0 * 0xFF = 0 passes", r == 1);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 19: Instance wires
 * ================================================================ */
static void
test_instance_wires(void)
{
    /* Circuit: witness a, instance b → assert a + b = 0, i.e., a = b */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c);
    gf8_wire_id b = voleith_gf8_add_instance(c);
    gf8_wire_id d = voleith_gf8_add_xor(c, a, b);
    voleith_gf8_assert_zero(c, d);

    check("witness count = 1, instance count = 1",
          voleith_gf8_circuit_witness_count(c) == 1 &&
              voleith_gf8_circuit_instance_count(c) == 1);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);

    uint8_t witness[1] = {0x7F};
    uint8_t instance[1] = {0x7F};
    int r = voleith_gf8_circuit_eval(c, witness, instance, vals);
    check("instance: a == b passes", r == 1);

    instance[0] = 0x80;
    memset(vals, 0, n);
    r = voleith_gf8_circuit_eval(c, witness, instance, vals);
    check("instance: a != b fails", r == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * main
 * ================================================================ */
int
main(void)
{
    printf("test_gf8_circuit: GF(2^8) element-level circuit API\n");

    test_wire_id_assignment();
    test_counter_tracking();
    test_ell_formula();
    test_topological_order();
    test_xor_eval();
    test_xor_const_eval();
    test_mul_eval();
    test_square_all_inputs();
    test_linear_map_identity();
    test_linear_map_bit_reverse();
    test_mux_eval();
    test_mux_slot_count();
    test_inverse_circuit_structure();
    test_inverse_circuit_valid();
    test_inverse_circuit_invalid();
    test_assert_zero();
    test_assert_equal();
    test_assert_product();
    test_instance_wires();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
