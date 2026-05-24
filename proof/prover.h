/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * prover.h - QuickSilver prover (FAEST spec Section 6)
 *
 * Implements the bit-level QuickSilver prover for any Boolean circuit.
 * Takes a circuit, witness, and VOLE correlation (u, V) and produces
 * the QuickSilver proof elements (d, a0_tilde, a1_tilde, a2_tilde).
 *
 * VOLE slot layout:
 *   Slots 0..witness_count-1:         witness wire i → slot i
 *   Slots witness_count..ell-1:        AND gate j → slot witness_count+j
 *   where ell = witness_count + and_gate_count
 *
 * The d vector is the VOLE correction: d[w] = bit[w] XOR bit(u, slot[w])
 * for each wire w with a VOLE slot. This is the only thing the prover
 * sends that reveals information about the witness - the Fiat-Shamir
 * challenge delta must be derived AFTER committing d to the transcript.
 *
 * The (a0_tilde, a1_tilde, a2_tilde) triple encodes the degree-0, degree-1,
 * and degree-2 coefficients of the QuickSilver multiplication check,
 * accumulated across all AND gates and assert_zero constraints.
 *
 * Verification check (verifier reconstructs a0_tilde from Q, d, delta):
 *   a0_tilde_verifier = q_tilde + delta*a1_tilde + delta^2*a2_tilde
 * If this matches the prover's a0_tilde, the circuit is satisfied.
 *
 * chall_2 format (4*lambda/8 + 8 bytes):
 *   [0..lambda/8-1]:         r0 (GF(2^lambda) hash key)
 *   [lambda/8..2*lambda/8-1]: r1 (GF(2^lambda) hash key)
 *   [2*lambda/8..3*lambda/8-1]: s (GF(2^lambda) Horner key for h0)
 *   [3*lambda/8..3*lambda/8+7]: t (GF(2^64) Horner key for h1)
 */

#ifndef VOLEITH_PROVER_H
#define VOLEITH_PROVER_H

#include <stdint.h>
#include <stddef.h>
#include "circuit.h"

/*
 * Compute ell = witness_count + and_gate_count for a circuit.
 *
 * This is the number of VOLE slots needed by the QuickSilver prover.
 */
size_t voleith_qs_ell(const voleith_circuit_t *circuit);

/*
 * Compute ellhat = ell + 3*lambda + UNIVERSAL_HASH_B_BITS (= 16).
 *
 * ellhat is the total VOLE output length required by the protocol.
 */
size_t voleith_qs_ellhat(const voleith_circuit_t *circuit, unsigned int lambda);

/*
 * QuickSilver prover.
 *
 * Proves knowledge of a witness satisfying the circuit using the provided
 * VOLE correlation (u, V). Computes d (the VOLE correction) and the
 * three zk_hash outputs (a0_tilde, a1_tilde, a2_tilde).
 *
 * circuit:   the Boolean circuit to prove
 * witness:   bit-packed witness (witness_count bits, LE bit order)
 * instance:  bit-packed instance (instance_count bits, LE bit order)
 * lambda:    security parameter (128, 192, or 256)
 * u:         VOLE u vector, ellhat_bytes = ceil(ellhat/8) bytes
 * V:         array of lambda pointers, each pointing to ellhat_bytes of
 *            the VOLE V matrix row
 * chall_2:   zk_hash parameters, 3*lambda/8+8 bytes (see format above)
 * d_out:     output: VOLE correction bits, ell_bytes = ceil(ell/8) bytes
 *            Only bits 0..ell-1 are meaningful; remaining bits are 0.
 * a0_tilde:  output: degree-0 hash, lambda/8 bytes
 * a1_tilde:  output: degree-1 hash, lambda/8 bytes
 * a2_tilde:  output: degree-2 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_qs_prove(const voleith_circuit_t *circuit, const uint8_t *witness,
                     const uint8_t *instance, unsigned int lambda,
                     const uint8_t *u, const uint8_t **V,
                     const uint8_t *chall_2, uint8_t *d_out, uint8_t *a0_tilde,
                     uint8_t *a1_tilde, uint8_t *a2_tilde);

/*
 * Compute only the VOLE correction d, without the full QuickSilver hash.
 *
 * d[slot] = bit[wire] XOR bit(u, slot) for each wire with a VOLE slot
 * (witness wires and AND gate outputs, in slot order).
 *
 * Used to pre-compute d before chall_2 is available, since chall_2 is
 * derived from d and voleith_qs_prove needs chall_2 as input.
 *
 * circuit:  the Boolean circuit
 * witness:  bit-packed witness (witness_count bits, LE bit order)
 * instance: bit-packed instance (instance_count bits, LE bit order)
 * u:        VOLE u vector, ceil(ellhat/8) bytes
 * d_out:    output: VOLE correction bits, ceil(ell/8) bytes; caller zeros first
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_qs_compute_d(const voleith_circuit_t *circuit,
                         const uint8_t *witness, const uint8_t *instance,
                         const uint8_t *u, uint8_t *d_out);

#endif /* VOLEITH_PROVER_H */
