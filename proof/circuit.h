/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * circuit.h - Boolean circuit definition API
 *
 * A circuit is a directed acyclic graph of gates over GF(2) (bits).
 * Wires carry single-bit values. Gates compute XOR, AND, or NOT of their
 * input wires and produce an output wire.
 *
 * In the QuickSilver proof system:
 *   - XOR and NOT gates are "free" - they cost no proof elements because
 *     VOLE correlations are linearly homomorphic.
 *   - AND gates each require one multiplication check. AND gate count
 *     determines proof size and prover work.
 *
 * Wire IDs are sequential non-negative integers assigned in order of
 * creation. Because inputs must be declared before the gates that use
 * them, the wires array is always in topological order - iterating
 * wires[0..n_wires) visits every wire in a valid evaluation order.
 *
 * Usage pattern:
 *   voleith_circuit_t *c = voleith_circuit_new();
 *   wire_id k = voleith_circuit_add_witness(c);   // key bit
 *   wire_id p = voleith_circuit_add_instance(c);  // plaintext bit
 *   wire_id a = voleith_circuit_add_and(c, k, p);
 *   wire_id x = voleith_circuit_add_xor(c, a, k);
 *   voleith_circuit_assert_zero(c, x);             // constrain output
 *   // ... prove/verify with this circuit ...
 *   voleith_circuit_free(c);
 */

#ifndef VOLEITH_CIRCUIT_H
#define VOLEITH_CIRCUIT_H

#include <stdint.h>
#include <stddef.h>

/* Wire identifier - index into the circuit's wire table */
typedef uint32_t wire_id;

/* Sentinel for "no wire" / invalid wire */
#define WIRE_ID_INVALID UINT32_MAX

/*
 * Maximum stack allocation for circuit-related buffers (VLAs and stack/heap
 * hybrids).  One place to change if the threshold ever needs adjusting.
 * Expressed in bytes; wire-count limits derive from this via sizeof(wire_id).
 */
#define VOLEITH_STACK_BUF_MAX 4096u

/*
 * Wire kinds - determines how the wire's value is computed.
 *
 * WITNESS and INSTANCE wires are primary inputs (no gate computes them).
 * CONST wires carry a fixed bit value embedded in the circuit.
 * XOR, AND, NOT wires are gate outputs computed from input wires.
 */
typedef enum {
    WIRE_KIND_WITNESS,  /* private input: bit from the witness vector */
    WIRE_KIND_INSTANCE, /* public input: bit from the instance vector */
    WIRE_KIND_CONST,    /* constant bit (0 or 1) */
    WIRE_KIND_XOR,      /* output = a XOR b  (free in QuickSilver) */
    WIRE_KIND_AND,      /* output = a AND b  (costs one mult check) */
    WIRE_KIND_NOT,      /* output = NOT a    (= a XOR 1, free) */
} wire_kind_t;

/*
 * A single wire entry. For primary inputs (WITNESS/INSTANCE/CONST), the
 * input fields are unused. For gates, `a` and `b` hold the input wire IDs
 * (b is WIRE_ID_INVALID for unary gates like NOT).
 */
typedef struct {
    wire_kind_t kind;
    wire_id a;         /* first input wire, or WIRE_ID_INVALID */
    wire_id b;         /* second input wire, or WIRE_ID_INVALID */
    uint8_t const_bit; /* for WIRE_KIND_CONST: the fixed value (0 or 1) */
} wire_entry_t;

/*
 * Constraint types - assertions that the verifier checks.
 */
typedef enum {
    CONSTRAINT_ZERO,  /* assert wire a == 0 */
    CONSTRAINT_EQUAL, /* assert wire a == wire b */
} constraint_kind_t;

/*
 * A single constraint entry.
 * For CONSTRAINT_ZERO, only `a` is used (b = WIRE_ID_INVALID).
 * For CONSTRAINT_EQUAL, both `a` and `b` are used.
 */
typedef struct {
    constraint_kind_t kind;
    wire_id a;
    wire_id b;
} constraint_entry_t;

/*
 * The circuit - opaque type, constructed via the builder API below.
 */
typedef struct voleith_circuit voleith_circuit_t;

/* ================================================================
 * Lifecycle
 * ================================================================ */

/*
 * Allocate an empty circuit. Returns NULL on allocation failure.
 * Must be freed with voleith_circuit_free().
 */
voleith_circuit_t *voleith_circuit_new(void);

/*
 * Free a circuit and all its allocated memory.
 */
void voleith_circuit_free(voleith_circuit_t *c);

/* ================================================================
 * Builder API - add wires and gates
 *
 * All functions return WIRE_ID_INVALID on allocation failure.
 * Allocation failures are also recorded in an internal flag readable
 * via voleith_circuit_ok(); callers may defer error handling until
 * the circuit is complete rather than checking every call.
 * ================================================================ */

/*
 * Declare a witness (private input) wire.
 * Witness wires are assigned bit indices 0, 1, 2, ... in order of
 * declaration. The prover supplies their values; the verifier does not.
 */
wire_id voleith_circuit_add_witness(voleith_circuit_t *c);

/*
 * Declare an instance (public input) wire.
 * Instance wires are assigned bit indices 0, 1, 2, ... in order of
 * declaration. Both prover and verifier know these values.
 */
wire_id voleith_circuit_add_instance(voleith_circuit_t *c);

/*
 * Add a constant wire carrying the fixed bit value `bit` (0 or 1).
 */
wire_id voleith_circuit_add_const(voleith_circuit_t *c, uint8_t bit);

/*
 * Add an XOR gate: output = a XOR b. Free in QuickSilver.
 */
wire_id voleith_circuit_add_xor(voleith_circuit_t *c, wire_id a, wire_id b);

/*
 * Add an AND gate: output = a AND b. Costs one QuickSilver mult check.
 */
wire_id voleith_circuit_add_and(voleith_circuit_t *c, wire_id a, wire_id b);

/*
 * Add a NOT gate: output = NOT a (= a XOR 1). Free in QuickSilver.
 */
wire_id voleith_circuit_add_not(voleith_circuit_t *c, wire_id a);

/* ================================================================
 * Constraints - assertions on output wires
 * ================================================================ */

/*
 * Assert that wire w evaluates to 0. Used to express that a computed
 * output equals a known constant (e.g., computed XOR of ciphertext bits
 * with expected ciphertext must be zero).
 *
 * On allocation failure the constraint is dropped and the circuit's
 * internal alloc_ok flag is cleared. Callers must check
 * voleith_circuit_ok() before passing the circuit to prove / verify.
 */
void voleith_circuit_assert_zero(voleith_circuit_t *c, wire_id w);

/*
 * Assert that wire a equals wire b.
 * Implemented as assert_zero(a XOR b). See assert_zero for the
 * OOM contract.
 */
void voleith_circuit_assert_equal(voleith_circuit_t *c, wire_id a, wire_id b);

/* ================================================================
 * Introspection
 * ================================================================ */

/* Total number of wires (all kinds) */
size_t voleith_circuit_wire_count(const voleith_circuit_t *c);

/* Number of witness (private input) wires */
size_t voleith_circuit_witness_count(const voleith_circuit_t *c);

/* Number of instance (public input) wires */
size_t voleith_circuit_instance_count(const voleith_circuit_t *c);

/* Number of AND gates (determines proof size) */
size_t voleith_circuit_and_gate_count(const voleith_circuit_t *c);

/*
 * Maximum QuickSilver constraint degree d in force for this circuit.  The
 * proof opens d+1 coefficients (a_0..a_d) and the QS mask region is d*lambda.
 * All circuits built today are degree-2 (AND gate / assert baseline); the
 * accessor exists so the serialization, transcript, and QS layers are
 * parameterized by d rather than hardcoding 2.  d is derived per-circuit and
 * is NOT transmitted on the wire.
 */
unsigned int voleith_circuit_qs_degree(const voleith_circuit_t *c);

/* Number of constraints */
size_t voleith_circuit_constraint_count(const voleith_circuit_t *c);

/*
 * Returns 1 if all builder operations succeeded (no allocation failure),
 * 0 if any operation failed silently. Builder functions like add_xor /
 * add_and / assert_zero / assert_equal cannot signal OOM through their
 * return values; on realloc failure they set an internal flag instead.
 * Callers must check this before passing a circuit to prove / verify.
 */
int voleith_circuit_ok(const voleith_circuit_t *c);

/*
 * Validate that every wire-id reference in the circuit is in range.
 *
 * For each gate wire at index i, requires that input wire ids (a, b)
 * are strictly less than i - the topological-order property the
 * evaluator relies on.  For each constraint, requires referenced wire
 * ids to be less than n_wires.  Primary input wires (WITNESS,
 * INSTANCE, CONST) have unused a/b fields (WIRE_ID_INVALID) and are
 * skipped.
 *
 * Returns 0 on success, -1 if any reference is out of range or c is
 * NULL.  Called automatically by the prove / verify entry points to
 * fail fast on a malformed circuit (covering L-N2 from the 1.2.0
 * security review).  Available as a public function so callers that
 * accept circuits from less-trusted sources (e.g. a future
 * deserialize path) can validate up-front.
 */
int voleith_circuit_validate(const voleith_circuit_t *c);

/*
 * Read-only access to the wire table (for QuickSilver and evaluation).
 * Returns pointer to the internal array of n_wires entries.
 * Valid until the next modification of the circuit.
 */
const wire_entry_t *voleith_circuit_wires(const voleith_circuit_t *c);

/*
 * Read-only access to the constraint table.
 * Returns pointer to the internal array of n_constraints entries.
 */
const constraint_entry_t *
voleith_circuit_constraints(const voleith_circuit_t *c);

/* ================================================================
 * Circuit evaluation (for testing and witness checking)
 * ================================================================ */

/*
 * Evaluate the circuit on the given witness and instance bit vectors.
 *
 * witness:    bit-packed array, witness_count bits, little-endian within
 *             each byte (bit i is byte i/8, bit i%8).
 * instance:   bit-packed array, instance_count bits, same packing.
 * wire_vals:  output array of wire_count bits (caller allocates,
 *             ceil(wire_count / 8) bytes). wire_vals[i] gives bit i.
 *
 * Returns 1 if all constraints are satisfied, 0 otherwise.
 * Returns -1 on error (NULL circuit or NULL output buffer).
 */
int voleith_circuit_eval(const voleith_circuit_t *c, const uint8_t *witness,
                         const uint8_t *instance, uint8_t *wire_vals);

/*
 * Check whether all constraints are satisfied given a wire_vals buffer
 * produced by voleith_circuit_eval().
 *
 * Returns 1 if all constraints pass, 0 if any fail.
 */
int voleith_circuit_check_constraints(const voleith_circuit_t *c,
                                      const uint8_t *wire_vals);

#endif /* VOLEITH_CIRCUIT_H */
