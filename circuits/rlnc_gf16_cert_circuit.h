/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_gf16_cert_circuit.h - GF(2^16) RLNC decodability / sufficiency
 * certificate circuit (P7 T7.1).
 *
 * Proves knowledge of the inverse of a secret m-by-m GF(2^16) coefficient
 * matrix C:
 *
 *     C . Cinv = I_m,
 *
 * with BOTH C and Cinv carried as secret witnesses.  A matrix over a field
 * has an inverse iff it is full rank, so a satisfying witness certifies "the
 * m held coded packets are linearly independent, hence enough to rebuild the
 * generation" WITHOUT revealing the packets' coding vectors (C) or letting the
 * verifier rebuild (neither C nor Cinv leaves the witness).  This is the
 * in-circuit, zero-knowledge counterpart of the plaintext rank check
 * voleith_rlnc_gf16_coeffs_full_rank(): that check operates on PUBLIC coding
 * vectors and convinces the holder itself; this certificate convinces a THIRD
 * PARTY while keeping the coding vectors secret (the heavier statement noted
 * in docs/ERASURE_CODES_DESIGN.md section 6.8 "proving to a third party").
 *
 * It is self-contained: it does not depend on the confidential codec or the
 * permutation gadget of the rest of P7, and is independently useful for
 * keyless verifiable relay (a relay proving the packets it forwards are a
 * decodable set).
 *
 * Cost: the only nonlinear work is the matrix product C . Cinv, m^3 GF(2^16)
 * multiplications (one add_mul per scalar product term); the accumulation is
 * free XOR and the identity comparison is a free assert_equal per entry.
 *   n_witness = 2 * m * m   (C row-major, then Cinv row-major)
 *   n_mul     = m^3
 *   ell       = 2*m*m + m^3
 *
 * Generation binding (a SEPARATE, ADDITIVE capability, delivered as Phase P8;
 * this cert ships standalone with NO instance wires and that does not change):
 * the core relation certifies decodability but does not by itself pin WHICH
 * generation C belongs to, nor that C is the coding matrix of the packets a
 * holder actually received.  Binding closes that via a Fiat-Shamir-derived linear
 * projection w = r^T C with r drawn from a POST-COMMIT transcript point (so a
 * cheating prover cannot adapt C to r; Freivalds-style, ~1/2^16 per check).
 *
 * Crucially the binding is a PROOF-LAYER opening, NOT in-circuit: the gf16 proof
 * freezes the circuit at prove_commit and r only exists after chall_1, so the
 * projection cannot be circuit gates or instance wires (an in-circuit build-time r
 * would be insecure).  It is emitted in prove_respond over the committed witness,
 * riding the gf16_proof two-phase split, and so is ADDITIVE: it does NOT change
 * this circuit's fingerprint.  P8 also adds a data-blind membership circuit
 * (Y = c . X, both secret) as the anchor linking a hidden c to a real packet.
 * See docs/ERASURE_CODES_DESIGN.md sections 6.11 and 9.2.
 */

#ifndef VOLEITH_RLNC_GF16_CERT_CIRCUIT_H
#define VOLEITH_RLNC_GF16_CERT_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "../proof/gf16_circuit.h"
#include "../core/field16.h"

/*
 * Number of witness elements for an m-by-m certificate: 2*m*m (the matrix C
 * followed by its inverse Cinv, both row-major).
 */
static inline size_t
voleith_rlnc_gf16_cert_n_witness(size_t m)
{
    return 2u * m * m;
}

/*
 * Number of multiplication gates (VOLE slots beyond the witnesses): m^3.
 */
static inline size_t
voleith_rlnc_gf16_cert_n_mul(size_t m)
{
    return m * m * m;
}

/*
 * Append the certificate relation to circuit c.
 *
 *   c_wires:    m*m witness wire ids for C, row-major (c_wires[i*m + l] is
 *               entry (i, l) of C).
 *   cinv_wires: m*m witness wire ids for Cinv, row-major (cinv_wires[l*m + j]
 *               is entry (l, j) of Cinv).
 *   m:          matrix dimension (> 0).
 *
 * For each (i, j) asserts (C . Cinv)[i][j] == [i == j], i.e. 1 on the diagonal
 * and 0 off it.  Adds m^3 MUL gates.  Errors (allocation / limits) surface via
 * voleith_gf16_circuit_ok().
 */
void voleith_rlnc_gf16_cert_circuit(voleith_gf16_circuit_t *c,
                                    const gf16_wire_id *c_wires,
                                    const gf16_wire_id *cinv_wires, size_t m);

/*
 * Build the witness array [C | Cinv] (2*m*m elements, row-major each) for a
 * given coefficient matrix C.  The inverse is computed by the plaintext
 * erasure/matrix.c Gauss-Jordan invert (the same routine the codec uses), so
 * the in-circuit Cinv witness is cross-checked against the validated plaintext
 * layer.
 *
 *   c_mat: m*m GF(2^16) elements, row-major (the coefficient matrix C).
 *   m:     matrix dimension (> 0).
 *   out:   2*m*m GF(2^16) elements (caller allocates): C then Cinv.
 *
 * Returns 0 on success, VOLEITH_EC_ERR_SINGULAR if C is not invertible (no
 * satisfying witness exists, so the holder does not yet have a decodable
 * set), or another negative VOLEITH_EC_ERR_* on bad arguments / allocation
 * failure.
 */
int voleith_rlnc_gf16_cert_build_witness(const voleith_gf16_t *c_mat, size_t m,
                                         voleith_gf16_t *out);

#endif /* VOLEITH_RLNC_GF16_CERT_CIRCUIT_H */
