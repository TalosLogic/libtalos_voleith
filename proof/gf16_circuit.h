/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_circuit.h - GF(2^16) element-level circuit definition API
 *
 * The GF(2^16) counterpart to gf8_circuit.h.  Each wire carries a single
 * GF(2^16) element (a voleith_gf16_t) rather than a byte, and one VOLE slot
 * is consumed per GF(2^16) multiplication (add_mul); all GF(2)-linear
 * operations (XOR, squaring, linear maps) are free.
 *
 * This is the native proving field for standalone RLNC membership (the
 * coefficient field is GF(2^16); see docs/ERASURE_CODES_DESIGN.md), avoiding
 * the 3x mul-gate cost a GF(2^8)^2 tower would impose on a verify path that
 * is linear in circuit size.
 *
 * VOLE slot layout (identical structure to gf8, element width doubled):
 *   Slots  0 .. n_witness-1       witness elements, in declaration order
 *   Slots  n_witness .. ell-1     add_mul gate outputs, in gate order
 *   (ell = n_witness + n_mul)
 *
 * Wire IDs are sequential non-negative integers assigned in creation order,
 * so the wire table is always in topological order.
 */

#ifndef VOLEITH_GF16_CIRCUIT_H
#define VOLEITH_GF16_CIRCUIT_H

#include <stdint.h>
#include <stddef.h>

#include "../core/field16.h"

/* Wire identifier - index into the circuit's wire table */
typedef uint32_t gf16_wire_id;

/* Sentinel for "no wire" / invalid wire */
#define GF16_WIRE_ID_INVALID UINT32_MAX

/*
 * Wire kinds - determines how the wire's GF(2^16) value is computed.
 * Operations marked "free" cost zero VOLE slots because they are
 * GF(2)-linear: their VOLE tags are derived from input tags.  MUL wires
 * cost one VOLE slot each (the QuickSilver multiplication check).
 */
typedef enum {
    GF16_WIRE_WITNESS,    /* private input: GF(2^16) element from witness */
    GF16_WIRE_INSTANCE,   /* public input:  GF(2^16) element from instance */
    GF16_WIRE_CONST,      /* constant element; value in const_val */
    GF16_WIRE_XOR,        /* output = a XOR b          (free: GF(2)-linear) */
    GF16_WIRE_XOR_CONST,  /* output = a XOR const_val  (free: GF(2)-linear) */
    GF16_WIRE_LINEAR_MAP, /* output = M.a for 16x16 GF(2) matrix M (free) */
    GF16_WIRE_SQUARE,     /* output = a^2 = Frobenius(a) (free: GF(2)-linear) */
    GF16_WIRE_MUL, /* output = a . b in GF(2^16)  (costs one VOLE slot) */
} gf16_wire_kind_t;

/*
 * A single wire entry.
 *
 * For primary inputs (WITNESS/INSTANCE/CONST) the input wire fields are
 * unused (GF16_WIRE_ID_INVALID).  For unary gates (LINEAR_MAP, SQUARE,
 * XOR_CONST) a holds the input, b is GF16_WIRE_ID_INVALID.  For binary gates
 * (XOR, MUL) both a and b hold input wire IDs.
 *
 * const_val: for CONST and XOR_CONST, the embedded constant element.
 * matrix:    for LINEAR_MAP, the 16x16 GF(2) matrix stored row-major.  Row i
 *            is matrix[i] (a uint16_t); bit j of matrix[i] is the (i,j) entry.
 *            Output bit i = parity(matrix[i] & a_bits).
 */
typedef struct {
    gf16_wire_kind_t kind;
    gf16_wire_id a;      /* first input wire, or GF16_WIRE_ID_INVALID */
    gf16_wire_id b;      /* second input wire, or GF16_WIRE_ID_INVALID */
    uint16_t const_val;  /* for CONST and XOR_CONST */
    uint16_t matrix[16]; /* for LINEAR_MAP: row i of the 16x16 GF(2) matrix */
} gf16_wire_entry_t;

/*
 * Constraint types - assertions the verifier checks.
 *   ZERO:    wire a must equal 0x0000.
 *   EQUAL:   wire a must equal wire b.
 *   PRODUCT: wire a . wire b must equal wire c (QuickSilver assert_product).
 */
typedef enum {
    GF16_CONSTRAINT_ZERO,
    GF16_CONSTRAINT_EQUAL,
    GF16_CONSTRAINT_PRODUCT,
} gf16_constraint_kind_t;

typedef struct {
    gf16_constraint_kind_t kind;
    gf16_wire_id a;
    gf16_wire_id b;
    gf16_wire_id c;
} gf16_constraint_entry_t;

/* The GF(2^16) circuit - opaque type, built via the API below. */
typedef struct voleith_gf16_circuit voleith_gf16_circuit_t;

/* ================================================================
 * Lifecycle
 * ================================================================ */

voleith_gf16_circuit_t *voleith_gf16_circuit_new(void);
void voleith_gf16_circuit_free(voleith_gf16_circuit_t *c);

/*
 * Set incremental resource ceilings: at most max_wires total wires and
 * max_gates gate (non-input) wires.  0 means unlimited (the default).  When
 * a ceiling would be crossed an add_* call fails (returns
 * GF16_WIRE_ID_INVALID and clears voleith_gf16_circuit_ok()).
 */
void voleith_gf16_circuit_set_limits(voleith_gf16_circuit_t *c,
                                     size_t max_wires, size_t max_gates);

/* ================================================================
 * Builder API
 *
 * Functions returning gf16_wire_id return GF16_WIRE_ID_INVALID on allocation
 * failure.  Void functions discard errors (check voleith_gf16_circuit_ok()).
 * ================================================================ */

gf16_wire_id voleith_gf16_add_witness(voleith_gf16_circuit_t *c);
gf16_wire_id voleith_gf16_add_instance(voleith_gf16_circuit_t *c);
gf16_wire_id voleith_gf16_add_const(voleith_gf16_circuit_t *c, uint16_t val);
gf16_wire_id voleith_gf16_add_xor(voleith_gf16_circuit_t *c, gf16_wire_id a,
                                  gf16_wire_id b);
gf16_wire_id voleith_gf16_add_xor_const(voleith_gf16_circuit_t *c,
                                        gf16_wire_id a, uint16_t k);

/*
 * Add a GF(2)-linear map gate: output = M . a for the 16x16 GF(2) matrix M.
 * M is row-major: M[i] is row i; output bit i = parity(M[i] & a_bits).  Free.
 */
gf16_wire_id voleith_gf16_add_linear_map(voleith_gf16_circuit_t *c,
                                         gf16_wire_id a, const uint16_t M[16]);

/* Add a Frobenius squaring gate: output = a^2 in GF(2^16).  Free. */
gf16_wire_id voleith_gf16_add_square(voleith_gf16_circuit_t *c, gf16_wire_id a);

/*
 * Add a multiplication gate: output = a . b in GF(2^16).  Costs one VOLE
 * slot.  VOLE slot index = n_witness + (mul gate count before this call).
 */
gf16_wire_id voleith_gf16_add_mul(voleith_gf16_circuit_t *c, gf16_wire_id a,
                                  gf16_wire_id b);

/*
 * Add a 2-to-1 MUX gate: output = (sel == 0x0000) ? a : b, expanded as
 * diff = b XOR a (free), prod = sel . diff (one MUL), out = a XOR prod (free).
 * Costs one VOLE slot.
 *
 * SOUNDNESS PRECONDITION: sel must be 0x0000 or 0x0001.  This is NOT enforced
 * here.  When sel is a witness (prover-controlled), the caller MUST constrain
 * it to {0,1} with voleith_gf16_assert_product(c, sel, sel, sel); omitting the
 * constraint is a soundness break -- a malicious prover can set sel to any
 * field element and make the "MUX" select an arbitrary affine combination
 * a + sel.(b - a) rather than a or b.  The constraint is deliberately left to
 * the caller so a single selector driving several muxes (e.g. one direction
 * bit over every byte of a node) pays the booleanity constraint once rather
 * than per mux.  See emit_switch in circuits/permutation_gf16_circuit.c for
 * the canonical assert-once-then-mux pattern.
 */
gf16_wire_id voleith_gf16_add_mux(voleith_gf16_circuit_t *c, gf16_wire_id a,
                                  gf16_wire_id b, gf16_wire_id sel);

/* ================================================================
 * Constraints
 * ================================================================ */

void voleith_gf16_assert_zero(voleith_gf16_circuit_t *c, gf16_wire_id w);
void voleith_gf16_assert_equal(voleith_gf16_circuit_t *c, gf16_wire_id a,
                               gf16_wire_id b);
/*
 * Assert that a . b == c_expected in GF(2^16).  Free: it checks the
 * polynomial relation on existing committed wire values, no VOLE slot.
 */
void voleith_gf16_assert_product(voleith_gf16_circuit_t *c, gf16_wire_id a,
                                 gf16_wire_id b, gf16_wire_id c_expected);

/* ================================================================
 * Introspection
 * ================================================================ */

size_t voleith_gf16_circuit_wire_count(const voleith_gf16_circuit_t *c);
size_t voleith_gf16_circuit_witness_count(const voleith_gf16_circuit_t *c);
size_t voleith_gf16_circuit_instance_count(const voleith_gf16_circuit_t *c);
size_t voleith_gf16_circuit_gate_count(const voleith_gf16_circuit_t *c);
size_t voleith_gf16_circuit_mul_count(const voleith_gf16_circuit_t *c);
size_t
voleith_gf16_circuit_assert_product_count(const voleith_gf16_circuit_t *c);
size_t voleith_gf16_circuit_constraint_count(const voleith_gf16_circuit_t *c);

/* Number of VOLE slots: ell = n_witness + n_mul (in GF(2^16) elements). */
size_t voleith_gf16_qs_ell(const voleith_gf16_circuit_t *c);

int voleith_gf16_circuit_ok(const voleith_gf16_circuit_t *c);

/*
 * Validate that every wire-id reference is in range (gate inputs strictly
 * below the gate index, constraint wires below n_wires).  Returns 0 on
 * success, -1 on an out-of-range reference or NULL circuit.  Called by the
 * prove / verify entry points to fail fast on a malformed circuit.
 */
int voleith_gf16_circuit_validate(const voleith_gf16_circuit_t *c);

const gf16_wire_entry_t *
voleith_gf16_circuit_wires(const voleith_gf16_circuit_t *c);
const gf16_constraint_entry_t *
voleith_gf16_circuit_constraints(const voleith_gf16_circuit_t *c);

/*
 * Fill M with the 16x16 GF(2) Frobenius squaring matrix for GF(2^16) under
 * m16 = x^16 + x^12 + x^3 + x + 1: column j is (x^j)^2 reduced mod m16, so
 * (M . a_bits) equals the bit vector of a^2.  Row-major (M[i] = row i).  The
 * QuickSilver prover and verifier use this to push VOLE tags through a
 * SQUARE gate as a GF(2)-linear map.
 */
void voleith_gf16_square_matrix(uint16_t M[16]);

/* ================================================================
 * Circuit evaluation (for testing and witness checking)
 *
 * Inputs and outputs are GF(2^16) element arrays (one voleith_gf16_t per
 * wire), not packed bytes.
 * ================================================================ */

/*
 * Evaluate the circuit.  witness: witness_count elements; instance:
 * instance_count elements; wire_vals: output, wire_count elements (caller
 * allocates).  Returns 1 if all constraints hold, 0 if any is violated, -1
 * on error (NULL circuit or output buffer).
 */
int voleith_gf16_circuit_eval(const voleith_gf16_circuit_t *c,
                              const voleith_gf16_t *witness,
                              const voleith_gf16_t *instance,
                              voleith_gf16_t *wire_vals);

/*
 * Check whether all constraints hold for a wire_vals buffer from
 * voleith_gf16_circuit_eval().  Returns 1 if all pass, 0 if any fail.
 */
int voleith_gf16_circuit_check_constraints(const voleith_gf16_circuit_t *c,
                                           const voleith_gf16_t *wire_vals);

#endif /* VOLEITH_GF16_CIRCUIT_H */
