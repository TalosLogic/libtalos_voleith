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
 *   9: PRODUCT3 kind distinctness and fourth-operand binding.
 *  10: Frozen-constraint fingerprint byte-identity golden (ZERO/EQUAL/PRODUCT).
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

/* ================================================================
 * Test 9: PRODUCT3 kind distinctness and fourth-operand binding.
 *
 * The fourth operand d is serialized ONLY for PRODUCT3 (appended after c),
 * so ZERO/EQUAL/PRODUCT fingerprints are byte-identical to pre-PRODUCT3
 * circuits - that frozen byte-identity is pinned by the aes128_gf8_circuit
 * golden in test_aes_gf8_circuit.c (test 18).  Here we verify the new kind
 * is distinct from PRODUCT and that its d operand is bound.
 * ================================================================ */
static void
test_product3_operand_binding(void)
{
    uint8_t fp_p[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp_p3[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fp_p3b[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    gf8_wire_id a, b, cw, dw;

    /* PRODUCT a·b==c; a fourth wire is added so the wire tables match c3. */
    voleith_gf8_circuit_t *cp = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(cp);
    b = voleith_gf8_add_witness(cp);
    cw = voleith_gf8_add_witness(cp);
    (void)voleith_gf8_add_witness(cp);
    voleith_gf8_assert_product(cp, a, b, cw);

    /* PRODUCT3 a·b·c==d, target d = wire 3. */
    voleith_gf8_circuit_t *c3 = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c3);
    b = voleith_gf8_add_witness(c3);
    cw = voleith_gf8_add_witness(c3);
    dw = voleith_gf8_add_witness(c3);
    voleith_gf8_assert_product3(c3, a, b, cw, dw);

    /* PRODUCT3 identical except target d = wire 2 (different 4th operand). */
    voleith_gf8_circuit_t *c3b = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c3b);
    b = voleith_gf8_add_witness(c3b);
    cw = voleith_gf8_add_witness(c3b);
    (void)voleith_gf8_add_witness(c3b);
    voleith_gf8_assert_product3(c3b, a, b, cw, cw);

    (void)voleith_gf8_circuit_fingerprint(cp, fp_p);
    (void)voleith_gf8_circuit_fingerprint(c3, fp_p3);
    (void)voleith_gf8_circuit_fingerprint(c3b, fp_p3b);

    check("product3: PRODUCT3 differs from PRODUCT",
          memcmp(fp_p, fp_p3, sizeof(fp_p)) != 0);
    check("product3: fourth operand d is bound",
          memcmp(fp_p3, fp_p3b, sizeof(fp_p3)) != 0);

    voleith_gf8_circuit_free(cp);
    voleith_gf8_circuit_free(c3);
    voleith_gf8_circuit_free(c3b);
}

/* ================================================================
 * Test 10: frozen-constraint fingerprint byte-identity regression pin.
 *
 * Adding GF8_CONSTRAINT_PRODUCT3 appended a value to the constraint-kind
 * enum (keeping ZERO=0/EQUAL=1/PRODUCT=2) and a fourth operand `d` to
 * gf8_constraint_entry_t, absorbed into the fingerprint ONLY for PRODUCT3.
 * The frozen kinds (ZERO/EQUAL/PRODUCT) and every frozen wire kind must
 * therefore fingerprint byte-identically to the pre-PRODUCT3 serialization.
 *
 * build_reference() exercises all three frozen constraint kinds plus every
 * wire kind, so this golden locks their canonical bytes.  The AES-128 golden
 * (test_aes_gf8_circuit.c test 18) separately pins PRODUCT at scale; this pins
 * ZERO and EQUAL, which the AES circuit does not use.  A mismatch means the
 * frozen serialization drifted (e.g. `d` leaking into a non-PRODUCT3
 * constraint, a reordered field, or a shifted enum value): if intentional,
 * re-pin; otherwise it is a regression.
 *
 * GOLDEN captured once from a build of this commit over build_reference()
 * (byte-identical to the pre-PRODUCT3 value, since d is not absorbed for these
 * kinds).  Until pinned, the all-zero placeholder fails by design.
 * ================================================================ */
#ifndef FROZEN_FP_GOLDEN_BYTES
#define FROZEN_FP_GOLDEN_BYTES                                                 \
    0x0c, 0xed, 0x67, 0xb9, 0x67, 0x87, 0x6c, 0x33, 0x28, 0xc7, 0x04, 0xfb,    \
        0x1f, 0x0a, 0x1a, 0x74
#endif

static void
test_frozen_constraint_fingerprint_golden(void)
{
    static const uint8_t golden[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES] = {
        FROZEN_FP_GOLDEN_BYTES};
    uint8_t fp[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t zero[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES] = {0};

    voleith_gf8_circuit_t *c = build_reference();
    check("frozen golden: build_reference returns non-NULL", c != NULL);
    if (c == NULL)
        return;

    check("frozen golden: fingerprint computed",
          voleith_gf8_circuit_fingerprint(c, fp) == 0);

    printf("  frozen-constraint circuit fingerprint:");
    for (int i = 0; i < VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES; i++)
        printf(" %02x", fp[i]);
    printf("\n");

    if (memcmp(golden, zero, sizeof(golden)) == 0)
        printf("  NOTE: FROZEN_FP_GOLDEN_BYTES is unset; pin the bytes "
               "printed above.\n");

    check("frozen golden: fingerprint matches pin (ZERO/EQUAL/PRODUCT "
          "byte-identity)",
          memcmp(fp, golden, sizeof(fp)) == 0);

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
    test_product3_operand_binding();
    test_frozen_constraint_fingerprint_golden();
    printf("test_gf8_circuit_fingerprint: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
