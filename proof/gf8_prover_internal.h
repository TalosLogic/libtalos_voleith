/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_prover_internal.h - Test-only seam into the GF(2^8) prover.
 *
 * The functions declared here are identical to their public
 * voleith_gf8_qs_* counterparts EXCEPT that they do not reject a witness
 * that violates a circuit constraint: voleith_gf8_circuit_eval returning
 * 0 (a satisfiable-structure circuit whose constraints are not met) is
 * allowed to proceed, while structural errors (eval < 0) are still
 * rejected.
 *
 * This exists solely so soundness tests can drive the verifier with a
 * FORGED, inconsistent witness (e.g. a PRODUCT constraint a*b = c with
 * c != a*b) and confirm the verifier rejects it.  The honest public API
 * gates such witnesses at the prover, which is correct for production
 * but hides the verifier-side soundness check from black-box tests.
 *
 * NOT part of the public API.  No production code path calls these.
 */

#ifndef VOLEITH_GF8_PROVER_INTERNAL_H
#define VOLEITH_GF8_PROVER_INTERNAL_H

#include "gf8_circuit.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Like voleith_gf8_qs_compute_d, but does not reject a constraint-violating
 * witness (eval == 0 proceeds; eval < 0 still fails). */
int voleith_gf8_qs_compute_d_unchecked(const voleith_gf8_circuit_t *circuit,
                                       const uint8_t *witness,
                                       const uint8_t *instance,
                                       const uint8_t *u, uint8_t *d_out);

/* Like voleith_gf8_qs_prove, but does not reject a constraint-violating
 * witness (eval == 0 proceeds; eval < 0 still fails). */
int voleith_gf8_qs_prove_unchecked(const voleith_gf8_circuit_t *circuit,
                                   const uint8_t *witness,
                                   const uint8_t *instance, unsigned int lambda,
                                   const uint8_t *u, const uint8_t **V,
                                   const uint8_t *chall_2, uint8_t *d_out,
                                   uint8_t *a0_tilde, uint8_t *a1_tilde,
                                   uint8_t *a2_tilde);

#ifdef __cplusplus
}
#endif

#endif /* VOLEITH_GF8_PROVER_INTERNAL_H */
