/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_gf8.h - Hirose double-block-length compression as a
 * GF(2^8) element-level circuit.
 *
 * This header exposes one Hirose iteration (the compression `f`)
 * only.  The leaf-hash, inode-hash, padding rules, and domain-
 * separation constants (HIROSE_IV_LEAF, HIROSE_C_LEAF_*,
 * HIROSE_C_INODE) plus the voleith_node_hash_vt instances live in
 * the implementation file once step 9.4 of
 * docs/HIROSE_MERKLE_DESIGN.md lands; the iteration primitive is
 * factored out here so it can be shared by both the fixed-32 and
 * variable-leaf vts and by the inode hash.
 *
 * Cost (one iteration):
 *
 *   VOLE slots:      500 inv_in witness bytes
 *                    (52 KS + 224 encrypt + 224 encrypt)
 *   assert_product:  1000  (2 per S-box, Prop. 6.4)
 *   Linear glue:     16 add_xor_const (G ^ c)
 *                  + 16 add_xor       (Gn  = E(K,G)   ^ G)
 *                  + 16 add_xor       (Hn  = E(K,Gxc) ^ Gxc)
 *                  - all free
 *
 * Soundness-relevant property: the key-schedule sharing across the two
 * encryptions is structural - one aes256_gf8_expand_key emit, two
 * aes256_gf8_encrypt_rk emits feeding off the same `rk` wire array.
 * The Hirose construction's collision-resistance reduction (FSE 2006)
 * requires both encryptions to use the same key K = H || M; sharing
 * the schedule in-circuit is what saves 52 S-boxes (104 assert_products)
 * per iteration vs. two independent aes256_gf8_circuit calls.
 *
 * The matching software primitive in core/hirose.h deliberately does
 * NOT share the schedule - it calls voleith_aes_encrypt twice through
 * a single voleith_aes_key_expand context, which is functionally
 * equivalent in output but does not mirror the circuit's internal
 * structure.  That makes the software primitive an independent oracle
 * for the circuit: any output divergence is a circuit bug, never a
 * shared-misreading bug.
 *
 * See docs/HIROSE_MERKLE_DESIGN.md for the construction and the gate-
 * accounting derivation; docs/HASH_AGNOSTIC_MERKLE_DESIGN.md §3.2 for
 * the role of this primitive in the 1.2.0 hash-agnostic Merkle vt
 * framework.
 */

#ifndef VOLEITH_NODE_HASH_HIROSE_GF8_H
#define VOLEITH_NODE_HASH_HIROSE_GF8_H

#include "../proof/gf8_circuit.h"
#include <stdint.h>
#include <stddef.h>

/*
 * Constant number of inv_in witness bytes consumed by one
 * hirose_gf8_iteration_circuit call.  Equal to
 *   AES256_GF8_KS_INVIN_BYTES (52)
 *     + 2 * AES256_GF8_ENC_INVIN_BYTES (224)
 *   = 500.
 *
 * Exposed both as a #define (for stack-allocated buffers in callers
 * that need a compile-time constant) and via the
 * hirose_gf8_iteration_witness_bytes() accessor (for ABI symmetry
 * with the rest of the circuits/<...>_witness_bytes API).
 */
#define HIROSE_GF8_ITERATION_WITNESS_BYTES 500

size_t hirose_gf8_iteration_witness_bytes(void);

/*
 * hirose_gf8_iteration_circuit - emit one Hirose iteration `f`.
 *
 * Given a 256-bit chaining value (G || H), a 128-bit message block M,
 * and a 128-bit nonzero constant c (compile-time public, not a wire),
 * emits the gates that compute:
 *
 *     K        = H || M                   (256-bit AES-256 key)
 *     G_out    = AES_K(G)        XOR G
 *     H_out    = AES_K(G XOR c)  XOR G XOR c
 *
 * Implementation detail: both encryptions share one key schedule (one
 * aes256_gf8_expand_key emit + two aes256_gf8_encrypt_rk emits).
 *
 * c_const MUST be nonzero - a zero constant collapses the two
 * encryptions to the same call and breaks the construction's
 * collision-resistance bound.  This is enforced by convention at the
 * caller, not by the circuit (a zero c would still build a valid
 * circuit that simply implements a different and weaker function).
 *
 * G, H, M:        16 GF(2^8) wires each.
 * c_const:        16 plain bytes, treated as a circuit constant via
 *                 add_xor_const (zero VOLE slots).
 * G_out, H_out:   16 GF(2^8) wires each, receive the output.  May
 *                 alias any of G / H / M, so callers can chain
 *                 iterations in-place via
 *                   hirose_gf8_iteration_circuit(c, G, H, M, k, G, H);
 *                 (Internally the function snapshots G's wire IDs
 *                 before any output write; H and M are each read
 *                 exactly once at the start, so aliasing is safe
 *                 in every combination.)
 *
 * Witness cost:   adds HIROSE_GF8_ITERATION_WITNESS_BYTES (500)
 *                 inv_in witnesses to the circuit, in the order the
 *                 matching builder produces them.
 */
void hirose_gf8_iteration_circuit(voleith_gf8_circuit_t *c,
                                  const gf8_wire_id G[16],
                                  const gf8_wire_id H[16],
                                  const gf8_wire_id M[16],
                                  const uint8_t c_const[16],
                                  gf8_wire_id G_out[16], gf8_wire_id H_out[16]);

/*
 * hirose_gf8_iteration_build_witness - compute the inv_in witnesses
 * for one hirose_gf8_iteration_circuit call.
 *
 * Layout (matches circuit emission order):
 *
 *   inv_out[ 0 ..  51]  = aes256_gf8_expand_key_witness over (H||M)
 *   inv_out[52 .. 275]  = aes256_gf8_encrypt_rk_witness for AES_K(G)
 *   inv_out[276..499]   = aes256_gf8_encrypt_rk_witness for AES_K(G^c)
 *
 * Optionally returns the chaining output (G_out, H_out) so callers
 * can chain iterations without re-deriving the values from
 * core/hirose.h.  Pass NULL for either output pointer to skip it.
 *
 * G, H, M, c_const: 16 bytes each, c_const must be nonzero.
 * inv_out[500]:     receives the 500 inv_in bytes.
 * G_out, H_out:     optional 16-byte outputs; may be NULL.
 *
 * All caller-supplied; internal scratch (round-key table, key
 * material) is securely zeroed before return.
 */
void hirose_gf8_iteration_build_witness(
    const uint8_t G[16], const uint8_t H[16], const uint8_t M[16],
    const uint8_t c_const[16],
    uint8_t inv_out[HIROSE_GF8_ITERATION_WITNESS_BYTES], uint8_t G_out[16],
    uint8_t H_out[16]);

/* ================================================================
 * Leaf and inode wrappers (step 9.4)
 *
 * Three constructions over the iteration primitive:
 *
 *   - fixed-32 leaf:   2 iterations over a constant IV_LEAF, 32-byte
 *                      data absorbed as two M blocks; no padding.
 *                      Used by voleith_node_hash_hirose_fixed32.
 *   - variable leaf:   n iterations over the same IV_LEAF with 10*
 *                      padding (append 0x80, zero-pad to next 16B
 *                      boundary; aligned input always gets an extra
 *                      block).  Used by voleith_node_hash_hirose.
 *   - inode:           2 iterations with the left child L as IV, the
 *                      right child R absorbed as two M blocks.
 *                      Shared by both vts.
 *
 * Domain separation across the three (and across the two leaf vts)
 * is realized by distinct c constants (see implementation).  Cost
 * accounting:
 *
 *   fixed-32 leaf:  inv_in = 2 * 500 = 1000 bytes
 *   variable leaf:  inv_in = n_iter(len) * 500, where
 *                   n_iter(len) = (len + 16) / 16
 *                   (n_iter for len=0/1/15/16/17/32 = 1/1/1/2/2/3)
 *   inode:          inv_in = 2 * 500 = 1000 bytes
 *
 * The function signatures intentionally match the
 * voleith_node_hash_vt function-pointer slots so the vt instances
 * can be initialized by-pointer with no thunks.  See
 * circuits/node_hash_vt.h.
 * ================================================================ */

/* inv_in byte counts. */
size_t merkle_hirose_gf8_fixed32_leaf_invin_bytes(size_t leaf_data_bytes);
size_t merkle_hirose_gf8_fixed96_leaf_invin_bytes(size_t leaf_data_bytes);
size_t merkle_hirose_gf8_variable_leaf_invin_bytes(size_t leaf_data_bytes);
size_t merkle_hirose_gf8_inode_invin_bytes(void);

/* In-circuit emission. */
void merkle_hirose_gf8_fixed32_leaf_circuit(voleith_gf8_circuit_t *c,
                                            const gf8_wire_id *leaf_data,
                                            size_t leaf_data_bytes,
                                            gf8_wire_id *out_node);

void merkle_hirose_gf8_fixed96_leaf_circuit(voleith_gf8_circuit_t *c,
                                            const gf8_wire_id *leaf_data,
                                            size_t leaf_data_bytes,
                                            gf8_wire_id *out_node);

void merkle_hirose_gf8_variable_leaf_circuit(voleith_gf8_circuit_t *c,
                                             const gf8_wire_id *leaf_data,
                                             size_t leaf_data_bytes,
                                             gf8_wire_id *out_node);

void merkle_hirose_gf8_inode_circuit(voleith_gf8_circuit_t *c,
                                     const gf8_wire_id *left,
                                     const gf8_wire_id *right,
                                     gf8_wire_id *out_node);

/* Witness builders.  Return 0 on success, -1 on internal allocation
 * failure.  Hirose impls are stack-only and always return 0; the int
 * signature matches the voleith_node_hash_vt contract for uniformity. */
int merkle_hirose_gf8_fixed32_leaf_build_witness(const uint8_t *leaf_data,
                                                 size_t leaf_data_bytes,
                                                 uint8_t *inv_out);

int merkle_hirose_gf8_fixed96_leaf_build_witness(const uint8_t *leaf_data,
                                                 size_t leaf_data_bytes,
                                                 uint8_t *inv_out);

int merkle_hirose_gf8_variable_leaf_build_witness(const uint8_t *leaf_data,
                                                  size_t leaf_data_bytes,
                                                  uint8_t *inv_out);

int merkle_hirose_gf8_inode_build_witness(const uint8_t *left,
                                          const uint8_t *right,
                                          uint8_t *inv_out);

/* Software helpers (independent oracles via core/hirose.c).  Return 0
 * on success, -1 on internal allocation failure.  Hirose impls are
 * stack-only and always return 0. */
int merkle_hirose_fixed32_leaf_hash(const uint8_t *leaf_data,
                                    size_t leaf_data_bytes, uint8_t *out);

int merkle_hirose_fixed96_leaf_hash(const uint8_t *leaf_data,
                                    size_t leaf_data_bytes, uint8_t *out);

int merkle_hirose_variable_leaf_hash(const uint8_t *leaf_data,
                                     size_t leaf_data_bytes, uint8_t *out);

int merkle_hirose_inode_hash(const uint8_t *left, const uint8_t *right,
                             uint8_t *out);

#endif /* VOLEITH_NODE_HASH_HIROSE_GF8_H */
