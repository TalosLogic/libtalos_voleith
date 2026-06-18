/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_circuit.h - GF(2⁸) element-level circuit definition API
 *
 * This is the element-level counterpart to circuit.h. Each wire carries a
 * single GF(2⁸) element (one byte) rather than a single bit. Operating at
 * element granularity reduces VOLE slot count dramatically:
 *
 *   Bit-level:   one VOLE slot per AND gate
 *   GF(2⁸)-level: one VOLE slot per GF(2⁸) multiplication (add_mul)
 *                  zero slots for all GF(2)-linear operations (XOR, squaring,
 *                  linear maps)
 *
 * In the AES S-box: 36 AND gates → 1 add_mul gate (via Proposition 6.4
 * from the FAEST spec: asserting x²·y = x and x·y² = y proves y = x⁻¹ or
 * x = y = 0, using two free assert_product checks and one inv_in witness).
 *
 * VOLE slot layout:
 *   Slots  0 .. n_witness-1       witness elements, in declaration order
 *   Slots  n_witness .. ell-1     add_mul gate outputs, in gate order
 *   (ell = n_witness + n_mul)
 *
 * Wire IDs are sequential non-negative integers assigned in order of
 * creation, so the wire table is always in topological order.
 *
 * Usage pattern:
 *   voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
 *   gf8_wire_id k  = voleith_gf8_add_witness(c);     // key byte
 *   gf8_wire_id k2 = voleith_gf8_add_square(c, k);   // k² (free)
 *   gf8_wire_id ki = voleith_gf8_add_witness(c);      // k⁻¹ (inv witness)
 *   // assert k² · ki == k  and  k · ki² == ki  (Proposition 6.4)
 *   voleith_gf8_assert_product(c, k2, ki, k);
 *   gf8_wire_id ki2 = voleith_gf8_add_square(c, ki);
 *   voleith_gf8_assert_product(c, k, ki2, ki);
 *   voleith_gf8_circuit_free(c);
 */

#ifndef VOLEITH_GF8_CIRCUIT_H
#define VOLEITH_GF8_CIRCUIT_H

#include <stdint.h>
#include <stddef.h>

/* Wire identifier - index into the circuit's wire table */
typedef uint32_t gf8_wire_id;

/* Sentinel for "no wire" / invalid wire */
#define GF8_WIRE_ID_INVALID UINT32_MAX

/*
 * Wire kinds - determines how the wire's GF(2⁸) value is computed.
 *
 * WITNESS and INSTANCE wires are primary inputs.
 * CONST wires carry a fixed element embedded in the circuit.
 * All operations below marked "free" cost zero VOLE slots because they
 * are GF(2)-linear: their VOLE tags are derived from input tags.
 * MUL wires cost one VOLE slot each (the QuickSilver multiplication check).
 */
typedef enum {
    GF8_WIRE_WITNESS,    /* private input: GF(2⁸) element from witness */
    GF8_WIRE_INSTANCE,   /* public input:  GF(2⁸) element from instance */
    GF8_WIRE_CONST,      /* constant element; value in const_val */
    GF8_WIRE_XOR,        /* output = a XOR b          (free: GF(2)-linear) */
    GF8_WIRE_XOR_CONST,  /* output = a XOR const_val  (free: GF(2)-linear) */
    GF8_WIRE_LINEAR_MAP, /* output = M·a for 8×8 GF(2) matrix M (free) */
    GF8_WIRE_SQUARE,     /* output = a² = Frobenius(a) (free: GF(2)-linear) */
    GF8_WIRE_MUL, /* output = a · b in GF(2⁸)  (costs one VOLE slot) */
} gf8_wire_kind_t;

/*
 * A single wire entry.
 *
 * For primary inputs (WITNESS/INSTANCE/CONST), the input wire fields are
 * unused (GF8_WIRE_ID_INVALID).
 *
 * For unary gates (LINEAR_MAP, SQUARE, XOR_CONST): a holds the input, b is
 * GF8_WIRE_ID_INVALID.
 *
 * For binary gates (XOR, MUL): both a and b hold input wire IDs.
 *
 * const_val: for CONST and XOR_CONST, the embedded constant byte.
 *
 * matrix: for LINEAR_MAP, the 8×8 GF(2) matrix stored row-major.
 *         Row i is matrix[i]; bit j of matrix[i] is the (i,j) entry.
 *         Output bit i = inner product of matrix row i with input bits.
 *         (Column-vector convention: out = M · a_col, where a_col[j] = bit j
 *          of the input element.)
 */
typedef struct {
    gf8_wire_kind_t kind;
    gf8_wire_id a;     /* first input wire, or GF8_WIRE_ID_INVALID */
    gf8_wire_id b;     /* second input wire, or GF8_WIRE_ID_INVALID */
    uint8_t const_val; /* for CONST and XOR_CONST */
    uint8_t matrix[8]; /* for LINEAR_MAP: row i of the 8×8 GF(2) matrix */
} gf8_wire_entry_t;

/*
 * Constraint types - assertions that the verifier checks.
 *
 * ZERO:    wire a must equal 0x00.
 * EQUAL:   wire a must equal wire b.
 * PRODUCT: wire a · wire b must equal wire c  (QuickSilver assert_product).
 *          PRODUCT costs zero VOLE slots - it checks existing committed values.
 */
typedef enum {
    GF8_CONSTRAINT_ZERO,    /* assert wire a == 0x00 */
    GF8_CONSTRAINT_EQUAL,   /* assert wire a == wire b */
    GF8_CONSTRAINT_PRODUCT, /* assert wire a · wire b == wire c */
} gf8_constraint_kind_t;

/*
 * A single constraint entry.
 * For ZERO:    a is the checked wire; b and c are GF8_WIRE_ID_INVALID.
 * For EQUAL:   a and b are the checked wires; c is GF8_WIRE_ID_INVALID.
 * For PRODUCT: a, b, c are all used (a · b == c).
 */
typedef struct {
    gf8_constraint_kind_t kind;
    gf8_wire_id a;
    gf8_wire_id b;
    gf8_wire_id c;
} gf8_constraint_entry_t;

/*
 * The GF(2⁸) circuit - opaque type, constructed via the builder API below.
 */
typedef struct voleith_gf8_circuit voleith_gf8_circuit_t;

/* ================================================================
 * Lifecycle
 * ================================================================ */

/*
 * Allocate an empty circuit. Returns NULL on allocation failure.
 * Must be freed with voleith_gf8_circuit_free().
 */
voleith_gf8_circuit_t *voleith_gf8_circuit_new(void);

/*
 * Free a circuit and all its allocated memory.
 */
void voleith_gf8_circuit_free(voleith_gf8_circuit_t *c);

/*
 * Set incremental resource ceilings on a circuit: at most `max_wires` total
 * wires and `max_gates` gate (non-input) wires.  A value of 0 means unlimited,
 * which is the default for a newly created circuit, so circuits built without
 * calling this behave exactly as before (identical wire/constraint tables and
 * fingerprint).  When a ceiling is set, the builder's add_* calls fail
 * (returning GF8_WIRE_ID_INVALID and clearing voleith_gf8_circuit_ok()) the
 * moment an append would cross it, bounding a bulk emitter's allocation rather
 * than detecting the overflow only after the fact.
 */
void voleith_gf8_circuit_set_limits(voleith_gf8_circuit_t *c, size_t max_wires,
                                    size_t max_gates);

/* ================================================================
 * Builder API - add wires and gates
 *
 * All functions returning gf8_wire_id return GF8_WIRE_ID_INVALID on
 * allocation failure. Void functions silently discard errors (callers
 * may check voleith_gf8_circuit_ok() after construction).
 * ================================================================ */

/*
 * Declare a witness (private input) wire.
 * Assigned VOLE slot index = (current witness count before this call).
 */
gf8_wire_id voleith_gf8_add_witness(voleith_gf8_circuit_t *c);

/*
 * Declare an instance (public input) wire.
 * Not assigned a VOLE slot - both prover and verifier know its value.
 */
gf8_wire_id voleith_gf8_add_instance(voleith_gf8_circuit_t *c);

/*
 * Add a constant wire carrying the fixed GF(2⁸) element `val`.
 */
gf8_wire_id voleith_gf8_add_const(voleith_gf8_circuit_t *c, uint8_t val);

/*
 * Add an XOR gate: output = a XOR b. Free in QuickSilver.
 */
gf8_wire_id voleith_gf8_add_xor(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b);

/*
 * Add an XOR-with-constant gate: output = a XOR k. Free in QuickSilver.
 */
gf8_wire_id voleith_gf8_add_xor_const(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                      uint8_t k);

/*
 * Add a GF(2)-linear map gate: output = M · a for 8×8 GF(2) matrix M.
 * M is stored row-major: M[i] is row i (a byte); output bit i =
 * popcount(M[i] & a) mod 2.  Free in QuickSilver.
 *
 * Typical use: basis change (AES ↔ tower field) and Frobenius squaring as
 * an explicit matrix.
 */
gf8_wire_id voleith_gf8_add_linear_map(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                       const uint8_t M[8]);

/*
 * Add a Frobenius squaring gate: output = a² in GF(2⁸). Free in QuickSilver.
 * Equivalent to add_linear_map with the squaring matrix for the AES field,
 * but provided as a dedicated primitive for clarity.
 */
gf8_wire_id voleith_gf8_add_square(voleith_gf8_circuit_t *c, gf8_wire_id a);

/*
 * Add a multiplication gate: output = a · b in GF(2⁸).
 * Costs one VOLE slot - the QuickSilver prover commits to the output.
 * VOLE slot index = n_witness + (mul gate count before this call).
 */
gf8_wire_id voleith_gf8_add_mul(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b);

/*
 * Add a 2-to-1 MUX gate: output = (sel == 0x00) ? a : b.
 * Implemented as a XOR (b XOR a), one MUL (sel · diff), and a XOR (a XOR prod).
 * Costs one VOLE slot (the internal multiplication).
 * sel is a wire expected to carry 0x00 or 0x01 - the circuit does not
 * enforce this; the caller must constrain sel to be a bit if required.
 */
gf8_wire_id voleith_gf8_add_mux(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b, gf8_wire_id sel);

/* ================================================================
 * Constraints - assertions on wire values
 * ================================================================ */

/*
 * Assert that wire w evaluates to 0x00.
 */
void voleith_gf8_assert_zero(voleith_gf8_circuit_t *c, gf8_wire_id w);

/*
 * Assert that wire a equals wire b.
 */
void voleith_gf8_assert_equal(voleith_gf8_circuit_t *c, gf8_wire_id a,
                              gf8_wire_id b);

/*
 * Assert that a · b == c_expected in GF(2⁸).
 * This is the "free" multiplication check: it costs zero VOLE slots because
 * the QuickSilver verifier checks the polynomial relation on existing
 * committed wire values.
 *
 * Primary use: Proposition 6.4 inverse check for the AES S-box.
 *   assert_product(x², x⁻¹, x)   →  x² · x⁻¹ == x
 *   assert_product(x, (x⁻¹)², x⁻¹) → x · (x⁻¹)² == x⁻¹
 */
void voleith_gf8_assert_product(voleith_gf8_circuit_t *c, gf8_wire_id a,
                                gf8_wire_id b, gf8_wire_id c_expected);

/* ================================================================
 * Introspection
 * ================================================================ */

/* Total number of wires (all kinds) */
size_t voleith_gf8_circuit_wire_count(const voleith_gf8_circuit_t *c);

/* Number of witness (private input) wires */
size_t voleith_gf8_circuit_witness_count(const voleith_gf8_circuit_t *c);

/* Number of instance (public input) wires */
size_t voleith_gf8_circuit_instance_count(const voleith_gf8_circuit_t *c);

/* Number of gate (produced, non-input) wires: wire_count minus the WITNESS,
 * INSTANCE, and CONST input wires. */
size_t voleith_gf8_circuit_gate_count(const voleith_gf8_circuit_t *c);

/* Number of MUL gates (add_mul calls; determines VOLE slot count) */
size_t voleith_gf8_circuit_mul_count(const voleith_gf8_circuit_t *c);

/* Number of assert_product constraints */
size_t voleith_gf8_circuit_assert_product_count(const voleith_gf8_circuit_t *c);

/* Number of constraints (all kinds) */
size_t voleith_gf8_circuit_constraint_count(const voleith_gf8_circuit_t *c);

/*
 * Number of VOLE slots: ell = n_witness + n_mul.
 * This is the ℓ in the FAEST spec (Table 5.1), measured in GF(2⁸) elements.
 */
size_t voleith_gf8_qs_ell(const voleith_gf8_circuit_t *c);

/*
 * Returns 1 if all builder operations succeeded (no allocation failure),
 * 0 if any operation failed silently.
 */
int voleith_gf8_circuit_ok(const voleith_gf8_circuit_t *c);

/*
 * Validate that every wire-id reference in the circuit is in range.
 *
 * For each gate wire at index i, requires that input wire ids (a, b
 * where applicable) are strictly less than i - the topological-order
 * property the evaluator relies on.  For each constraint, requires
 * referenced wire ids to be less than n_wires.  Primary input wires
 * (WITNESS, INSTANCE, CONST) carry no wire references and are
 * skipped.
 *
 * Returns 0 on success, -1 if any reference is out of range or c is
 * NULL.  Called automatically by the GF(2⁸) prove / verify entry
 * points to fail fast on a malformed circuit (covering L-N2 from the
 * 1.2.0 security review).  Available as a public function so callers
 * that accept circuits from less-trusted sources can validate
 * up-front.
 */
int voleith_gf8_circuit_validate(const voleith_gf8_circuit_t *c);

/*
 * Read-only access to the wire table (for QuickSilver and evaluation).
 * Returns pointer to the internal array of wire_count entries.
 * Valid until the next modification of the circuit.
 */
const gf8_wire_entry_t *
voleith_gf8_circuit_wires(const voleith_gf8_circuit_t *c);

/*
 * Read-only access to the constraint table.
 */
const gf8_constraint_entry_t *
voleith_gf8_circuit_constraints(const voleith_gf8_circuit_t *c);

/* ================================================================
 * Circuit evaluation (for testing and witness checking)
 *
 * Inputs and outputs are byte arrays: one byte per wire element.
 * ================================================================ */

/*
 * Evaluate the circuit on the given witness and instance byte vectors.
 *
 * witness:    byte array, witness_count bytes (one byte per witness wire,
 *             in declaration order).
 * instance:   byte array, instance_count bytes (one byte per instance wire,
 *             in declaration order).
 * wire_vals:  output array, wire_count bytes (caller allocates).
 *             wire_vals[i] is the GF(2⁸) value of wire i.
 *
 * Returns 1 if all constraints are satisfied, 0 otherwise.
 * Returns -1 on error (NULL circuit or NULL output buffer).
 */
int voleith_gf8_circuit_eval(const voleith_gf8_circuit_t *c,
                             const uint8_t *witness, const uint8_t *instance,
                             uint8_t *wire_vals);

/*
 * Check whether all constraints are satisfied given a wire_vals buffer
 * produced by voleith_gf8_circuit_eval().
 *
 * Returns 1 if all constraints pass, 0 if any fail.
 */
int voleith_gf8_circuit_check_constraints(const voleith_gf8_circuit_t *c,
                                          const uint8_t *wire_vals);

#endif /* VOLEITH_GF8_CIRCUIT_H */
