/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_prover.h - Element-level (GF(2⁸)) QuickSilver prover
 *
 * Implements the element-level QuickSilver prover for GF(2⁸) circuits.
 * Each VOLE slot carries one GF(2⁸) element (one byte).
 *
 * VOLE slot layout:
 *   Slots 0..witness_count-1:         witness byte i → slot i
 *   Slots witness_count..ell-1:        MUL gate j → slot witness_count+j
 *   where ell = witness_count + mul_gate_count  (in GF(2⁸) elements)
 *
 * The d vector is ell bytes: d[s] = wire_element[s] XOR u[s]
 * (one byte per slot, not one bit as in bit-level QuickSilver).
 *
 * The chall_2 format and (a0_tilde, a1_tilde, a2_tilde) output format
 * are identical to the bit-level prover - the ZKHash layer is unchanged.
 *
 * ellhat_bits  = ell*8 + 3*lambda + 16    (FAEST spec Table 5.1, k=8)
 * ellhat_bytes = ell + ceil((3*lambda+16)/8)
 */

#ifndef VOLEITH_GF8_PROVER_H
#define VOLEITH_GF8_PROVER_H

#include <stdint.h>
#include <stddef.h>
#include "gf8_circuit.h"

/*
 * Compute ellhat_bytes = ell + ceil((3*lambda + 16) / 8).
 *
 * This is the total VOLE output length in bytes required by the protocol.
 * (ell = voleith_gf8_qs_ell(circuit) is already declared in gf8_circuit.h)
 */
size_t voleith_gf8_qs_ellhat(const voleith_gf8_circuit_t *circuit,
                             unsigned int lambda);

/*
 * Element-level QuickSilver prover.
 *
 * Proves knowledge of a witness satisfying the GF(2⁸) circuit using
 * the provided VOLE correlation (u, V). Computes d (the VOLE correction)
 * and the three ZKHash outputs (a0_tilde, a1_tilde, a2_tilde).
 *
 * circuit:   the GF(2⁸) circuit to prove
 * witness:   witness bytes, one per witness wire (witness_count bytes)
 * instance:  instance bytes, one per instance wire (instance_count bytes)
 * lambda:    security parameter (128, 192, or 256)
 * u:         VOLE u vector, ellhat_bytes long
 * V:         array of lambda pointers, each pointing to ellhat_bytes of V matrix row
 * chall_2:   ZKHash parameters, 3*lambda/8+8 bytes
 * d_out:     output: VOLE correction bytes, ell bytes (one byte per element slot)
 * a0_tilde:  output: degree-0 hash, lambda/8 bytes
 * a1_tilde:  output: degree-1 hash, lambda/8 bytes
 * a2_tilde:  output: degree-2 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_gf8_qs_prove(const voleith_gf8_circuit_t *circuit,
                         const uint8_t *witness, const uint8_t *instance,
                         unsigned int lambda, const uint8_t *u,
                         const uint8_t **V, const uint8_t *chall_2,
                         uint8_t *d_out, uint8_t *a0_tilde, uint8_t *a1_tilde,
                         uint8_t *a2_tilde);

/*
 * Compute only the VOLE correction d, without the full QuickSilver hash.
 *
 * d[s] = wire_element[s] XOR u[s]  for each element slot s = 0..ell-1.
 *
 * Used to pre-compute d before chall_2 is available (chicken-and-egg
 * same as the bit-level voleith_qs_compute_d).
 *
 * circuit:  the GF(2⁸) circuit
 * witness:  witness bytes (witness_count bytes)
 * instance: instance bytes (instance_count bytes)
 * u:        VOLE u vector, ellhat_bytes long
 * d_out:    output: ell bytes (caller zeros first)
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_gf8_qs_compute_d(const voleith_gf8_circuit_t *circuit,
                             const uint8_t *witness, const uint8_t *instance,
                             const uint8_t *u, uint8_t *d_out);

#endif /* VOLEITH_GF8_PROVER_H */
