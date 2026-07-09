/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * permutation_gf16_circuit.h - GF(2^16) secret-permutation routing gadget
 * (P7 T7.5).
 *
 * The one new costly primitive of the confidential-RLNC proof (paper 2 lever
 * 2): a circuit proving that a SECRET partial permutation was applied to a
 * vector of GF(2^16) wires, i.e. that the output vector is a genuine
 * rearrangement of the input vector under a witnessed permutation.  It is built
 * as an ARBITRARY-SIZE WAKSMAN (AS-Waksman) routing network: a recursive
 * arrangement of 2x2 switches, each gated by one secret control bit.
 *
 * Why a routing network and not a multiset / grand-product argument: a genuine
 * Waksman network is, for ANY assignment of control bits, automatically a
 * permutation of its inputs (every switch conserves its two values).  So
 * permutation-validity is STRUCTURAL: there is no separate sortedness or
 * grand-product check, and a cheating prover cannot make the output anything
 * but a rearrangement of the input.  The witness is only the O(n log n) control
 * bits realizing the desired table, derived by the standard routing algorithm
 * (voleith_perm_gf16_route).  The network size is fixed at circuit-build time
 * (the grid dimension n is public), so there is no secret-dependent sizing.
 *
 * Gate shape per switch (the GF(2^16) form of the shipped secret-dir Merkle
 * MUX): given inputs a, b and a secret control bit s constrained to {0, 1} by
 * assert_product(s, s, s) (booleanity), the straight/cross outputs are
 *     out0 = MUX(a, b, s)  = (s == 0) ? a : b        (one mul gate)
 *     out1 = a XOR b XOR out0                          (free; the swap conserves
 *                                                       a XOR b)
 * so each switch costs exactly ONE multiplication.  Total mul gates and total
 * control-bit witnesses both equal the switch count S(n)
 * (voleith_perm_gf16_n_switches).
 *
 * Network convention (a faithful AS-Waksman): a block of size n has floor(n/2)
 * input switches (on input pairs (0,1), (2,3), ...), a top subnetwork of size
 * ceil(n/2), a bottom subnetwork of size floor(n/2), and an output stage.  For
 * EVEN n the first output switch is omitted (outputs 0, 1 are wired straight
 * from the two subnetworks), which is the one-switch-per-even-block saving that
 * makes the count ~ n*log2(n) - n + 1.  For ODD n the unpaired input and output
 * wires pass straight into / out of the top subnetwork.  The router and the
 * circuit builder share this exact recursion so control-bit indices line up.
 *
 * Permutation convention matches the plaintext codec
 * (voleith_confrlnc_permute): out[i] = in[perm[i]], i.e. perm[i] is the input
 * position feeding output position i.
 */

#ifndef VOLEITH_PERMUTATION_GF16_CIRCUIT_H
#define VOLEITH_PERMUTATION_GF16_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "../proof/gf16_circuit.h"

/*
 * Number of 2x2 switches (= mul gates = control-bit witnesses) in the network
 * for n inputs.  S(0) = S(1) = 0, S(2) = 1, and
 *   S(n) = floor(n/2)            (input switches)
 *        + n_out(n)              (output switches; even n: n/2 - 1, odd: n/2)
 *        + S(ceil(n/2)) + S(floor(n/2)).
 */
size_t voleith_perm_gf16_n_switches(size_t n);

/*
 * Append the routing network to circuit c.
 *
 *   in_wires:   n input wire ids (caller chooses witness / instance / derived).
 *   ctrl_wires: S(n) control-bit wire ids (the permutation witness); each is
 *               constrained to {0, 1} by an added assert_product booleanity
 *               check, so the caller need not pre-constrain them.
 *   out_wires:  n output wire ids (filled by this call) carrying the permuted
 *               vector, for the caller to consume / assert against.
 *   n:          vector length (> 0).
 *
 * Adds S(n) MUX (mul) gates and S(n) free booleanity asserts.  For n == 1 the
 * single wire passes through (out_wires[0] = in_wires[0]); no gates.  Errors
 * (allocation / limits) surface via voleith_gf16_circuit_ok().
 */
void voleith_perm_gf16_circuit(voleith_gf16_circuit_t *c,
                               const gf16_wire_id *in_wires,
                               const gf16_wire_id *ctrl_wires,
                               gf16_wire_id *out_wires, size_t n);

/*
 * Derive the S(n) control bits realizing the permutation perm (out[i] =
 * in[perm[i]]) and write them, in the exact order voleith_perm_gf16_circuit
 * consumes ctrl_wires, to bits_out (one GF(2^16) element per switch, value 0 or
 * 1).  This is the prover-side witness derivation (the standard AS-Waksman
 * 2-coloring routing).
 *
 * CONSTANT-TIME: perm is secret key material, so the memory-access pattern and
 * control flow depend only on n (public), never on the permutation values
 * (security review M-3).  The coloring uses Euler-tour list-ranking with
 * masked O(n) scans in place of every secret-indexed access, giving
 * O(n^2 log n) work.
 *
 *   perm:     n entries, a permutation of [0, n) (perm[i] feeds output i).
 *   n:        vector length (> 0).
 *   bits_out: S(n) elements (caller allocates); each set to 0 or 1.
 *
 * Returns 0 on success, -1 on a bad argument, a non-permutation table, or an
 * allocation failure.
 */
int voleith_perm_gf16_route(const size_t *perm, size_t n, uint16_t *bits_out);

/*
 * Variable-time REFERENCE router, IDENTICAL contract to
 * voleith_perm_gf16_route but using a data-dependent BFS coloring.  It is a
 * TEST ORACLE ONLY (its timing leaks the permutation); never call it on a
 * secret permutation.  Exposed so tests can cross-check the constant-time
 * router against an independent implementation.
 */
int voleith_perm_gf16_route_reference(const size_t *perm, size_t n,
                                      uint16_t *bits_out);

#endif /* VOLEITH_PERMUTATION_GF16_CIRCUIT_H */
