/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_prover_internal.h - Test-only seam into the GF(2^16) prover.
 *
 * Identical to the public voleith_gf16_qs_* counterparts EXCEPT that they do
 * not reject a witness that violates a circuit constraint:
 * voleith_gf16_circuit_eval returning 0 (a satisfiable-structure circuit
 * whose constraints are not met) proceeds, while structural errors (eval < 0)
 * are still rejected.
 *
 * This exists solely so soundness tests can drive the verifier with a FORGED,
 * inconsistent witness (e.g. a PRODUCT constraint a*b = c with c != a*b) and
 * confirm the verifier rejects it.  NOT part of the public API.
 */

#ifndef VOLEITH_GF16_PROVER_INTERNAL_H
#define VOLEITH_GF16_PROVER_INTERNAL_H

#include "gf16_circuit.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Like voleith_gf16_qs_compute_d, but does not reject a constraint-violating
 * witness (eval == 0 proceeds; eval < 0 still fails). */
int voleith_gf16_qs_compute_d_unchecked(const voleith_gf16_circuit_t *circuit,
                                        const voleith_gf16_t *witness,
                                        const voleith_gf16_t *instance,
                                        const uint8_t *u, uint8_t *d_out);

/* Like voleith_gf16_qs_prove, but does not reject a constraint-violating
 * witness (eval == 0 proceeds; eval < 0 still fails). */
int voleith_gf16_qs_prove_unchecked(const voleith_gf16_circuit_t *circuit,
                                    const voleith_gf16_t *witness,
                                    const voleith_gf16_t *instance,
                                    unsigned int lambda, const uint8_t *u,
                                    const uint8_t **V, const uint8_t *chall_2,
                                    uint8_t *d_out, uint8_t *const *a_out);

/*
 * Test-only syndrome accumulator selector (shared by the gf16 prover and
 * verifier).  0 = collapsed; nonzero = reference (pre-collapse).  Never set in
 * production.
 */
extern int voleith_gf16_syndrome_ref_mode;

#ifdef __cplusplus
}
#endif

#endif /* VOLEITH_GF16_PROVER_INTERNAL_H */
