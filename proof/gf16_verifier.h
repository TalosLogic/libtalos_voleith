/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_verifier.h - Element-level (GF(2^16)) QuickSilver verifier
 *
 * The GF(2^16) counterpart to gf8_verifier.h.  Reconstructs a0_tilde from the
 * verifier's VOLE Q matrix, the VOLE correction d, the challenge delta, and
 * the prover's transmitted coefficients a_1..a_d.
 *
 * Verifier key for element slot s:
 *   key[w] = WordCombine(Q columns s*16..s*16+15) + Delta * embed(d[s])
 * with GF(2)-linear gates propagated through the 16 bit-level key components.
 *
 * Final check: a0_tilde_out = q_tilde + sum_{i=1..d} Delta^i * a_i.
 */

#ifndef VOLEITH_GF16_VERIFIER_H
#define VOLEITH_GF16_VERIFIER_H

#include <stdint.h>
#include <stddef.h>
#include "gf16_circuit.h"

/*
 * Element-level QuickSilver verifier.
 *
 * circuit:      the GF(2^16) circuit being verified
 * instance:     instance elements (instance_count elements)
 * lambda:       security parameter (128, 192, or 256)
 * Q:            array of lambda pointers, each ellhat_bytes of a Q matrix row
 * d:            VOLE correction from prover, 2*ell bytes (16-bit LE per slot)
 * delta:        VOLE challenge, lambda/8 bytes
 * chall_2:      ZKHash parameters, 3*lambda/8+8 bytes
 * a_in:         prover's transmitted coefficients; a_in[i] = a_i for i = 1..d
 *               (a_in[0] is unused), each lambda/8 bytes.  d is the opening
 *               count for this circuit (voleith_gf16_circuit_qs_degree, 2 today).
 * a0_tilde_out: output: reconstructed degree-0 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_gf16_qs_verify(const voleith_gf16_circuit_t *circuit,
                           const voleith_gf16_t *instance, unsigned int lambda,
                           const uint8_t **Q, const uint8_t *d,
                           const uint8_t *delta, const uint8_t *chall_2,
                           const uint8_t *const *a_in, uint8_t *a0_tilde_out);

#endif /* VOLEITH_GF16_VERIFIER_H */
