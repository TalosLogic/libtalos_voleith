/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * verifier.h - QuickSilver verifier (FAEST spec Section 6)
 *
 * Reconstructs a0_tilde from the verifier's VOLE keys (Q), the VOLE
 * correction d from the prover, the challenge delta, and the prover's
 * a1_tilde and a2_tilde.
 *
 * Verification check:
 *   a0_tilde_out = q_tilde + delta*a1_tilde + delta^2*a2_tilde
 *
 * The caller then checks a0_tilde_out == a0_tilde (from the prover's proof).
 * In Fiat-Shamir mode (Phase 8), both values feed into the transcript hash
 * and the check is implicit.
 *
 * For each AND gate (a AND b = c), the verifier contributes:
 *   key[a]*key[b] + key[c]
 * to the zk_hash accumulator, where:
 *   key[w] = GF(2^lambda) from Q column s[w] + delta * d[s[w]]
 *
 * For each assert_zero constraint on wire w:
 *   key[w]
 * is added to the accumulator.
 *
 * Key propagation through gates:
 *   XOR(a,b): key[out] = key[a] + key[b]
 *   NOT(a):   key[out] = key[a] + delta   (adding key of const-1 = delta)
 *   CONST 0:  key[w] = 0
 *   CONST 1:  key[w] = delta
 *   INSTANCE: key[w] = delta * v   (v is the public instance bit)
 */

#ifndef VOLEITH_VERIFIER_H
#define VOLEITH_VERIFIER_H

#include <stdint.h>
#include <stddef.h>
#include "circuit.h"

/*
 * QuickSilver verifier.
 *
 * Reconstructs a0_tilde from the verifier's perspective and returns it.
 * The caller must compare a0_tilde_out against the prover's a0_tilde
 * to determine if the proof is valid.
 *
 * circuit:     the Boolean circuit
 * instance:    bit-packed instance (instance_count bits, LE bit order)
 * lambda:      security parameter (128, 192, or 256)
 * Q:           array of lambda pointers, each ellhat_bytes wide (VOLE Q matrix)
 * d:           VOLE correction from prover, ell_bytes = ceil(ell/8) bytes
 * delta:       GF(2^lambda) challenge, lambda/8 bytes
 * chall_2:     zk_hash parameters, 3*lambda/8+8 bytes (same format as prover)
 * a1_tilde:    degree-1 hash from prover, lambda/8 bytes
 * a2_tilde:    degree-2 hash from prover, lambda/8 bytes
 * a0_tilde_out: output: reconstructed degree-0 hash, lambda/8 bytes
 *
 * Returns 0 on success, -1 on allocation failure or invalid parameters.
 */
int voleith_qs_verify(const voleith_circuit_t *circuit, const uint8_t *instance,
                      unsigned int lambda, const uint8_t **Q, const uint8_t *d,
                      const uint8_t *delta, const uint8_t *chall_2,
                      const uint8_t *a1_tilde, const uint8_t *a2_tilde,
                      uint8_t *a0_tilde_out);

#endif /* VOLEITH_VERIFIER_H */
