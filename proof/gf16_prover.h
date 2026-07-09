/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_prover.h - Element-level (GF(2^16)) QuickSilver prover
 *
 * The GF(2^16) counterpart to gf8_prover.h.  Each VOLE slot carries one
 * GF(2^16) element (16 bits / 2 bytes).
 *
 * VOLE slot layout:
 *   Slots 0..witness_count-1:      witness element i -> slot i
 *   Slots witness_count..ell-1:    MUL gate j -> slot witness_count+j
 *   ell = witness_count + mul_gate_count  (in GF(2^16) elements)
 *
 * The d vector is 2*ell bytes: d[s] = wire_element[s] XOR u[s], stored as a
 * little-endian 16-bit value per slot (two bytes), the GF(2^16) analogue of
 * the gf8 prover's one-byte-per-slot d.
 *
 * The chall_2 format and (a0_tilde, a1_tilde, a2_tilde) output format are
 * identical to the gf8 / bit-level prover: the GF(2^lambda) ZKHash layer is
 * unchanged.
 *
 *   ellhat_bits  = ell*16 + 3*lambda + 16   (FAEST spec Table 5.1, k=16)
 *   ellhat_bytes = 2*ell + ceil((3*lambda+16)/8)
 */

#ifndef VOLEITH_GF16_PROVER_H
#define VOLEITH_GF16_PROVER_H

#include <stdint.h>
#include <stddef.h>
#include "gf16_circuit.h"

/* Compute ellhat_bytes = 2*ell + ceil((3*lambda + 16) / 8). */
size_t voleith_gf16_qs_ellhat(const voleith_gf16_circuit_t *circuit,
                              unsigned int lambda);

/*
 * Element-level QuickSilver prover.
 *
 * circuit:   the GF(2^16) circuit to prove
 * witness:   witness elements, one per witness wire (witness_count elements)
 * instance:  instance elements, one per instance wire (instance_count)
 * lambda:    security parameter (128, 192, or 256)
 * u:         VOLE u vector, ellhat_bytes long
 * V:         array of lambda pointers, each ellhat_bytes of a V matrix row
 * chall_2:   ZKHash parameters, 3*lambda/8+8 bytes
 * d_out:     output: VOLE correction, 2*ell bytes (16-bit LE per slot)
 * a0_tilde:  output: degree-0 hash, lambda/8 bytes
 * a1_tilde:  output: degree-1 hash, lambda/8 bytes
 * a2_tilde:  output: degree-2 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_gf16_qs_prove(const voleith_gf16_circuit_t *circuit,
                          const voleith_gf16_t *witness,
                          const voleith_gf16_t *instance, unsigned int lambda,
                          const uint8_t *u, const uint8_t **V,
                          const uint8_t *chall_2, uint8_t *d_out,
                          uint8_t *a0_tilde, uint8_t *a1_tilde,
                          uint8_t *a2_tilde);

/*
 * Compute only the VOLE correction d, without the full QuickSilver hash.
 * d[s] = wire_element[s] XOR u[s] (16-bit LE per slot) for s = 0..ell-1.
 *
 * u:     VOLE u vector, ellhat_bytes long
 * d_out: output: 2*ell bytes
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_gf16_qs_compute_d(const voleith_gf16_circuit_t *circuit,
                              const voleith_gf16_t *witness,
                              const voleith_gf16_t *instance, const uint8_t *u,
                              uint8_t *d_out);

#endif /* VOLEITH_GF16_PROVER_H */
