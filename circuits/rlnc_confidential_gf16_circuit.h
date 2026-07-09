/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_confidential_gf16_circuit.h - GF(2^16) confidential-RLNC proof wrapper
 * (P7 T7.6).
 *
 * Proves that a public coded packet `data` is the correct confidential-RLNC
 * encoding (paper 2 scheme 1, the shipped GF(2^16) / t=2 instantiation) of a
 * public source generation `P` under a SECRET coefficient matrix L and a SECRET
 * partial permutation:
 *
 *     data = T^{-1}( permute( T( L . P ) ) )
 *
 * over the m-by-l generation, where T splits each GF(2^16) element into two
 * byte sub-symbols and the permutation acts on the whole m*l*2 grid.  The proof
 * keeps L and the permutation hidden while convincing a verifier the packet is a
 * well-formed encoding; with the optional decodability certificate it also
 * proves L is full rank (the packet is decodable).
 *
 * Orientation (matches T5.6 voleith_rlnc_gf16_coded_vector_circuit): the source
 * generation P is PUBLIC (baked in as constants, so each coefficient-times-data
 * product is a free GF(2)-linear map), the output `data` is a PUBLIC instance,
 * and the secrets are L and the permutation.  This is the coding-key / linkage
 * hiding orientation; it reveals the generation.  A both-secret data-hiding
 * variant (P also witnessed, paying m*l*m mul gates for L.P) is future work, the
 * same split noted in rlnc_gf16_circuit.h.
 *
 * Cost: the encode L.P and the T / T^{-1} maps are FREE (linear maps + XOR).
 * The only multiplications are the permutation network's S(m*l*2) switches
 * (voleith_perm_gf16_n_switches) plus, if the certificate is requested, the
 * m^3 products of L . Linv.
 *
 * Wire layout the caller MUST follow (witness add-order):
 *   1. coeff_wires    : m*m   secret L, row-major
 *   2. coeff_inv_wires : m*m  secret Linv, row-major   (ONLY if with_cert)
 *   3. ctrl_wires     : S(m*l*2) secret permutation control bits
 * Instance wires: data_wires (m*l, the public coded packet).  Source P is a
 * compile-time constant array, not a wire.
 */

#ifndef VOLEITH_RLNC_CONFIDENTIAL_GF16_CIRCUIT_H
#define VOLEITH_RLNC_CONFIDENTIAL_GF16_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "../proof/gf16_circuit.h"
#include "../core/field16.h"

/* Sub-symbols per element: the shipped GF(2^16) instantiation splits into two
 * byte sub-symbols (t = 2, w2 = 8). */
#define VOLEITH_RLNC_CONFIDENTIAL_GF16_T 2u

/* Number of permutation control-bit witnesses: S(m*l*t). */
size_t voleith_rlnc_confidential_gf16_n_ctrl(size_t m, size_t l);

/* Number of permutation mul gates (= n_ctrl); the certificate adds m^3 more. */
static inline size_t
voleith_rlnc_confidential_gf16_n_mul(size_t m, size_t l, int with_cert)
{
    size_t s = voleith_rlnc_confidential_gf16_n_ctrl(m, l);
    return with_cert ? s + m * m * m : s;
}

/* Number of witness elements: L (m*m) + Linv (m*m, if cert) + ctrl (S(m*l*t)). */
static inline size_t
voleith_rlnc_confidential_gf16_n_witness(size_t m, size_t l, int with_cert)
{
    size_t s = voleith_rlnc_confidential_gf16_n_ctrl(m, l);
    return (with_cert ? 2u * m * m : m * m) + s;
}

/*
 * Append the confidential-encoding relation to circuit c.
 *
 *   source:          m*l PUBLIC source elements (P, row-major source[r*l + e]).
 *   coeff_wires:     m*m secret L wire ids, row-major.
 *   coeff_inv_wires: m*m secret Linv wire ids (row-major), or NULL to omit the
 *                    decodability certificate.
 *   ctrl_wires:      S(m*l*t) secret permutation control-bit wire ids.
 *   data_wires:      m*l instance wire ids, the public coded packet.
 *   m, l:            generation dimensions (> 0).
 *
 * Asserts data == T^{-1}(permute(T(L.P))) element-by-element; enforces
 * permutation control-bit booleanity; and, if coeff_inv_wires != NULL, asserts
 * L . Linv = I_m.  Errors (allocation / limits) surface via
 * voleith_gf16_circuit_ok().
 */
void voleith_rlnc_confidential_gf16_circuit(voleith_gf16_circuit_t *c,
                                            const voleith_gf16_t *source,
                                            const gf16_wire_id *coeff_wires,
                                            const gf16_wire_id *coeff_inv_wires,
                                            const gf16_wire_id *ctrl_wires,
                                            const gf16_wire_id *data_wires,
                                            size_t m, size_t l);

/*
 * Build the witness element array in the layout above:
 *   [ L (m*m) | Linv (m*m, only if with_cert) | ctrl bits (S(m*l*t)) ].
 *
 *   L:        m*m plaintext coefficient matrix (row-major).
 *   m, l:     dimensions (> 0).
 *   perm:     m*l*t entries, the plaintext permutation (out[i] = in[perm[i]]).
 *   with_cert: nonzero to include Linv (requires L invertible).
 *   out:      voleith_rlnc_confidential_gf16_n_witness(m, l, with_cert) elements
 *             (caller allocates).
 *
 * Returns 0 on success, VOLEITH_EC_ERR_SINGULAR if with_cert and L is not
 * invertible, or a negative error on bad arguments / routing failure.
 */
int voleith_rlnc_confidential_gf16_build_witness(const voleith_gf16_t *L,
                                                 size_t m, size_t l,
                                                 const size_t *perm,
                                                 int with_cert,
                                                 voleith_gf16_t *out);

#endif /* VOLEITH_RLNC_CONFIDENTIAL_GF16_CIRCUIT_H */
