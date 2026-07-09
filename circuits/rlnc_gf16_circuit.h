/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rlnc_gf16_circuit.h - GF(2^16) RLNC generation-membership circuit (T5.6).
 *
 * Proves that a public coded symbol y belongs to a committed (witnessed)
 * generation X of k source symbols:
 *
 *     y[e] = sum_{j=0}^{k-1} c_j * X[j][e]     for each element index e,
 *
 * where the coefficient vector c (k GF(2^16) elements) is PUBLIC (it travels
 * in the RLNC packet header) and the source symbols X are SECRET witnesses
 * (the committed generation).  This is the in-circuit form of RLNC capability
 * 2 / capability 3 over the native gf16 prover (proof/gf16_proof.c): it lets a
 * node prove a recoded symbol is a genuine combination of a generation it
 * holds without revealing the generation, hiding the source content while the
 * coefficient vector stays public.
 *
 * Cost: ZERO multiplication gates.  Each c_j is a public constant, so
 * x -> c_j * x is a GF(2)-linear map (a free LINEAR_MAP gate); the whole
 * relation is a free linear combination plus one assert_equal per element.
 * ell = k * elems witness slots.
 *
 * Sufficiency ("enough symbols to rebuild") is a PLAINTEXT property of the
 * public coefficient vectors, not an in-circuit assertion: a set of received
 * symbols can rebuild the generation iff their coefficient matrix has rank k.
 * voleith_rlnc_gf16_coeffs_full_rank() is the plaintext check the retriever
 * runs over the (public) coefficient vectors; see docs/ERASURE_CODES_DESIGN.md
 * section 6.8.
 */

#ifndef VOLEITH_RLNC_GF16_CIRCUIT_H
#define VOLEITH_RLNC_GF16_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "../proof/gf16_circuit.h"
#include "../core/field16.h"

/*
 * Number of witness elements for a k-source generation of elems-element
 * symbols: k * elems (the source matrix X, row-major X[j][e]).
 */
static inline size_t
voleith_rlnc_gf16_n_witness(size_t k, size_t elems)
{
    return k * elems;
}

/*
 * Append the membership relation to circuit c.
 *
 *   src_wires: k*elems witness wire ids, row-major (src_wires[j*elems + e] is
 *              the e-th GF(2^16) element of source symbol j).
 *   coeffs:    k PUBLIC coefficients (the coded symbol's coefficient vector).
 *   y_wires:   elems instance wire ids carrying the public coded symbol y.
 *   k:         number of source symbols (> 0).
 *   elems:     GF(2^16) elements per symbol (> 0).
 *
 * For each e in [0, elems) asserts y[e] == sum_j coeffs[j] * src[j][e].  Adds
 * no MUL gates.  Errors (allocation) surface via voleith_gf16_circuit_ok().
 */
void voleith_rlnc_gf16_membership_circuit(voleith_gf16_circuit_t *c,
                                          const gf16_wire_id *src_wires,
                                          const voleith_gf16_t *coeffs,
                                          const gf16_wire_id *y_wires, size_t k,
                                          size_t elems);

/*
 * Number of witness elements for the secret-coefficient (coded-vector)
 * orientation: just k (the hidden coding vector), independent of elems.
 */
static inline size_t
voleith_rlnc_gf16_coded_vector_n_witness(size_t k)
{
    return k;
}

/*
 * Append the DUAL relation to circuit c: the coding vector is SECRET and the
 * source data is PUBLIC ("reveal the data, hide the combination").  This is
 * the routing-privacy / traffic-analysis-resistance overlay: a relay proves a
 * coded packet y is a genuine combination of publicly-known data blocks X
 * without revealing WHICH combination c it used.
 *
 *   coeff_wires: k witness wire ids, the secret coding vector (coeff_wires[j]
 *                is c_j; one coefficient per source, shared across all element
 *                positions).
 *   sources:     k*elems PUBLIC source elements, row-major (sources[j*elems+e]
 *                is the e-th GF(2^16) element of public source symbol j).
 *   y_wires:     elems instance wire ids carrying the public coded symbol y.
 *   k:           number of source symbols (> 0).
 *   elems:       GF(2^16) elements per symbol (> 0).
 *
 * For each e asserts y[e] == sum_j sources[j][e] * coeff_wires[j].  Each
 * source element is a public constant, so sources[j][e] * c_j is a free
 * LINEAR_MAP of the secret c_j: ZERO MUL gates, ell = k witnesses (the proof
 * is independent of the symbol length elems).
 *
 * NOTE: this hides the coding vector, NOT the data (X is public).  It is a
 * combination-privacy overlay, not a data cipher; encrypting the data as well
 * requires the both-secret path (see docs/private/LINEAR_CODING_CIRCUITS.md
 * section B.8).  Errors surface via voleith_gf16_circuit_ok().
 */
void voleith_rlnc_gf16_coded_vector_circuit(voleith_gf16_circuit_t *c,
                                            const gf16_wire_id *coeff_wires,
                                            const voleith_gf16_t *sources,
                                            const gf16_wire_id *y_wires,
                                            size_t k, size_t elems);

/*
 * Number of witness elements for the BOTH-SECRET (data-blind) orientation:
 * k*elems (the source matrix X, row-major) followed by k (the coding vector
 * c).  X is laid out as a contiguous PREFIX so a generation's packet proofs
 * can share one committed X by reusing the same X wire ids across proofs (the
 * Phase P8 T8.3 shared-anchor wiring); per-packet proofs that do not share
 * simply declare a fresh X prefix each.
 */
static inline size_t
voleith_rlnc_gf16_membership_secret_n_witness(size_t k, size_t elems)
{
    return k * elems + k;
}

/*
 * Number of multiplication gates for the both-secret orientation: k*elems
 * (one MUL per term c_j * X[j][e]; both factors are secret wires).
 */
static inline size_t
voleith_rlnc_gf16_membership_secret_n_mul(size_t k, size_t elems)
{
    return k * elems;
}

/*
 * Append the DATA-BLIND membership relation to circuit c: BOTH the coding
 * vector c and the source generation X are SECRET witnesses (P8 T8.1).  This
 * is the anchor that ties a hidden coding vector to a real coded packet
 * without revealing the data, the building block the decodability binding
 * (sections 6.11 / 9.2) projects over.
 *
 *   src_wires:   k*elems witness wire ids for X, row-major (src_wires[j*elems+e]
 *                is the e-th GF(2^16) element of source symbol j).
 *   coeff_wires: k witness wire ids, the secret coding vector (coeff_wires[j]
 *                is c_j, one coefficient per source).
 *   y_wires:     elems instance wire ids carrying the public coded packet y
 *                (the packet transmitted on the wire; the verifier sees y but
 *                neither X nor c).
 *   k:           number of source symbols (> 0).
 *   elems:       GF(2^16) elements per symbol (> 0).
 *
 * For each e asserts y[e] == sum_j coeff_wires[j] * src_wires[j][e].  Both
 * factors are secret, so each term is a MUL: k*elems MUL gates total.  Unlike
 * the public-coeff and public-source variants above, this is NOT free; that is
 * the price of hiding the data as well as the combination.
 *
 * The X and c wires are CALLER-DECLARED (this function only adds gates and
 * constraints, it commits nothing internally).  That keeps T8.1 agnostic to
 * the (a) self-contained / (b) shared-X choice: a caller wanting per-packet
 * independence (lowest emit latency via parallelism) declares a fresh X per
 * proof; a caller amortizing X across a generation declares X once and reuses
 * the wire ids (T8.3).  Recommended witness layout is the X-prefix-then-c order
 * of voleith_rlnc_gf16_membership_secret_n_witness().  Errors surface via
 * voleith_gf16_circuit_ok().
 */
void voleith_rlnc_gf16_membership_secret_circuit(
    voleith_gf16_circuit_t *c, const gf16_wire_id *src_wires,
    const gf16_wire_id *coeff_wires, const gf16_wire_id *y_wires, size_t k,
    size_t elems);

/*
 * Build the both-secret witness array [X | c] for the membership_secret
 * circuit: k*elems GF(2^16) source elements (from the plaintext erasure-layout
 * sources buffer, same convention as voleith_rlnc_gf16_build_witness) followed
 * by the k coding-vector coefficients.
 *
 *   sources:      k * symbol_bytes bytes (source j at sources + j*symbol_bytes).
 *   k:            number of sources (> 0).
 *   symbol_bytes: bytes per symbol (> 0, even).
 *   coeffs:       k GF(2^16) coding-vector elements.
 *   out:          k*(symbol_bytes/2) + k GF(2^16) elements (caller allocates).
 *
 * Returns 0 on success, -1 on bad arguments.
 */
int voleith_rlnc_gf16_membership_secret_build_witness(
    const uint8_t *sources, size_t k, size_t symbol_bytes,
    const voleith_gf16_t *coeffs, voleith_gf16_t *out);

/*
 * Convert a plaintext RLNC sources buffer (erasure layout: k*symbol_bytes
 * bytes, source j at sources + j*symbol_bytes, each symbol elems = symbol_bytes/2
 * GF(2^16) elements little-endian) into the row-major witness element array
 * expected by the circuit (out[j*elems + e]).
 *
 *   sources:      k * symbol_bytes bytes.
 *   k:            number of sources (> 0).
 *   symbol_bytes: bytes per symbol (> 0, even).
 *   out:          k * (symbol_bytes/2) GF(2^16) elements (caller allocates).
 *
 * Returns 0 on success, -1 on bad arguments.
 */
int voleith_rlnc_gf16_build_witness(const uint8_t *sources, size_t k,
                                    size_t symbol_bytes, voleith_gf16_t *out);

/*
 * Plaintext sufficiency check over PUBLIC coefficient vectors: returns 1 if
 * the n_rows coefficient vectors (each k GF(2^16) elements, row-major
 * coeff_rows[r*k + j]) span a rank-k space (so the generation can be
 * rebuilt), 0 otherwise.  Not constant-time; operates only on public data.
 */
int voleith_rlnc_gf16_coeffs_full_rank(const voleith_gf16_t *coeff_rows,
                                       size_t n_rows, size_t k);

#endif /* VOLEITH_RLNC_GF16_CIRCUIT_H */
