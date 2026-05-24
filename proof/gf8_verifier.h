/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_verifier.h - Element-level (GF(2⁸)) QuickSilver verifier
 *
 * Reconstructs a0_tilde from the verifier's VOLE Q matrix, the VOLE
 * correction d, the challenge delta, and the prover's a1_tilde, a2_tilde.
 *
 * Verifier key for element slot s:
 *   key[w] = ByteCombine(Q columns s*8..s*8+7) + Δ * embed(d[s])
 *
 * For GF(2)-linear gates:
 *   XOR:       key[out] = key[a] XOR key[b]
 *   XOR_CONST: key[out] = key[a] + Δ * embed(const_val)
 *   LINEAR_MAP/SQUARE: propagated via the 8 bit-level key components
 *   INSTANCE/CONST:    key[w] = Δ * embed(public_val)
 *
 * Final check:
 *   a0_tilde_out = q_tilde + Δ * a1_tilde + Δ² * a2_tilde
 */

#ifndef VOLEITH_GF8_VERIFIER_H
#define VOLEITH_GF8_VERIFIER_H

#include <stdint.h>
#include <stddef.h>
#include "gf8_circuit.h"

/*
 * Element-level QuickSilver verifier.
 *
 * Reconstructs a0_tilde from the circuit, the verifier's VOLE Q matrix,
 * the correction d, the VOLE challenge delta, and the prover's a1_tilde,
 * a2_tilde. The caller compares a0_tilde_out against the prover's a0_tilde.
 *
 * circuit:      the GF(2⁸) circuit being verified
 * instance:     instance bytes (instance_count bytes)
 * lambda:       security parameter (128, 192, or 256)
 * Q:            array of lambda pointers, each pointing to ellhat_bytes of Q matrix row
 * d:            VOLE correction bytes from prover, ell bytes
 * delta:        VOLE challenge, lambda/8 bytes
 * chall_2:      ZKHash parameters, 3*lambda/8+8 bytes
 * a1_tilde:     prover's degree-1 hash, lambda/8 bytes
 * a2_tilde:     prover's degree-2 hash, lambda/8 bytes
 * a0_tilde_out: output: reconstructed degree-0 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_gf8_qs_verify(const voleith_gf8_circuit_t *circuit,
                          const uint8_t *instance, unsigned int lambda,
                          const uint8_t **Q, const uint8_t *d,
                          const uint8_t *delta, const uint8_t *chall_2,
                          const uint8_t *a1_tilde, const uint8_t *a2_tilde,
                          uint8_t *a0_tilde_out);

#endif /* VOLEITH_GF8_VERIFIER_H */
