/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_vt_gf8_circuit.h - generic vt-driven Merkle path circuit.
 *
 * Branch B of the merkle tree circuits hash-agnostic refactor
 * (docs/MERKLE_TREE_CIRCUITS_DESIGN.md "Implementation plan:
 * hash-agnostic refactor").  Hash-family-agnostic Merkle path
 * verification parameterised by a voleith_node_hash_vt - one body
 * usable across AES-DM, AES-128-CMAC, all four Grøstl variants, and
 * both Hirose vts (and any future hash that ships a vt).
 *
 * The vt is consumed at circuit-build time only; the proof-time gate
 * stream is identical to what a hand-written hash-specific
 * implementation produces.  Each existing fixed-hash entry point in
 * circuits/merkle_gf8_circuit.h and circuits/merkle_grostl_gf8_circuit.h
 * has an equivalent invocation here:
 *
 *   merkle_gf8_leaf_hash_circuit + merkle_gf8_path_circuit(... DM)
 *     == merkle_vt_gf8_path_circuit(... &voleith_node_hash_aes_dm ...)
 *
 *   merkle_grostl_gf8_leaf_hash_circuit(...256_T27)
 *     + merkle_grostl_gf8_path_circuit(...256_T27)
 *     == merkle_vt_gf8_path_circuit(... &voleith_node_hash_grostl256_t27 ...)
 *
 * and so on for every wrapped vt.  Bit-exact equivalence
 * (witness_count, mul_count, assert_product_count, and circuit output
 * on identical inputs) is asserted by tests/test_merkle_vt_gf8_equivalence.c
 * for every existing-entry / equivalent-vt pairing.
 *
 * The existing fixed-hash entry points stay in place unchanged - this
 * branch is purely additive.  Whether the existing entry points
 * eventually become thin wrappers around this generic body is a
 * deferred Branch E concern.
 *
 * Booleanity (secret-dir): the direction wire at every level is
 * constrained to {0, 1} inside this circuit via assert_product(dir,
 * dir, dir).  This is a structural property of the generic body,
 * NEVER a caller obligation - an unconstrained mux selector is a
 * silent soundness break (a malicious prover can erase the carried-up
 * chain value and forge a path).  See docs/MERKLE_TREE_CIRCUITS_DESIGN.md
 * "Booleanity - enforce in-circuit".
 *
 * Direction convention (matches every other Merkle path circuit in
 * this library):
 *   path_dirs[0]        = leaf level (bottom of tree)
 *   path_dirs[depth-1]  = level immediately below the root
 *   path_dirs[k] = 0  -> accumulated hash is the LEFT  child of its
 *                        parent, sibling on the RIGHT
 *                        inode(current, sibling)
 *   path_dirs[k] = 1  -> accumulated hash is the RIGHT child of its
 *                        parent, sibling on the LEFT
 *                        inode(sibling, current)
 *   For leaf index j: path_dirs[k] = bit k of j (LSB first).
 */

#ifndef VOLEITH_MERKLE_VT_GF8_CIRCUIT_H
#define VOLEITH_MERKLE_VT_GF8_CIRCUIT_H

#include "node_hash_vt.h"

/*
 * merkle_vt_gf8_path_circuit - verify a Merkle authentication path
 * with a public (instance) leaf index.
 *
 * Emits the leaf hash gates via h->leaf_circuit, then walks `depth`
 * levels of inode compressions via h->inode_circuit.  Direction is
 * resolved at circuit-build time (path_dirs are plain uint8_t 0/1
 * values), so there is zero mul-gate cost for the direction swap.
 *
 * c               - circuit to append to
 * h               - node-hash vt (e.g. &voleith_node_hash_aes_dm)
 * leaf_data       - leaf_data_bytes wire IDs of raw leaf data; may be
 *                   NULL when leaf_data_bytes == 0
 * leaf_data_bytes - byte length of leaf data
 * path_nodes      - depth * h->node_bytes wire IDs of sibling hashes,
 *                   leaf-level first
 * path_dirs       - depth bytes of plain 0/1 values
 * depth           - number of levels from leaf hash to root
 * root            - output: h->node_bytes wire IDs for the root
 *
 * Returns 0 on success, -1 if h->node_bytes exceeds
 * MERKLE_VT_MAX_NODE_BYTES (every in-tree vt is checked at compile
 * time; this rejects third-party vts at runtime).
 */
int merkle_vt_gf8_path_circuit(voleith_gf8_circuit_t *c,
                               const voleith_node_hash_vt *h,
                               const gf8_wire_id *leaf_data,
                               size_t leaf_data_bytes,
                               const gf8_wire_id *path_nodes,
                               const uint8_t *path_dirs, size_t depth,
                               gf8_wire_id *root);

/*
 * merkle_vt_gf8_path_circuit_secret_dir - verify a Merkle path with a
 * private (witness) leaf index.
 *
 * Same as merkle_vt_gf8_path_circuit, but path_dirs is an array of
 * gf8_wire_id witness wires (each 0x00 or 0x01).  Each level pays
 * h->node_bytes mul gates for a per-byte mux selecting the
 * (left, right) pair from (current, sibling) under dir.
 *
 * Booleanity: every dir wire is constrained to {0, 1} by an
 * in-circuit assert_product(dir, dir, dir) at the matching level.
 * This is the structural soundness rule of the generic body, not a
 * caller obligation.
 *
 * c               - circuit to append to
 * h               - node-hash vt
 * leaf_data       - leaf_data_bytes wire IDs of raw leaf data
 * leaf_data_bytes - byte length of leaf data
 * path_nodes      - depth * h->node_bytes wire IDs of sibling hashes
 * path_dirs       - depth witness wires, each 0x00 or 0x01
 * depth           - number of levels from leaf hash to root
 * root            - output: h->node_bytes wire IDs for the root
 *
 * Returns 0 on success, -1 if h->node_bytes exceeds
 * MERKLE_VT_MAX_NODE_BYTES.
 */
int merkle_vt_gf8_path_circuit_secret_dir(voleith_gf8_circuit_t *c,
                                          const voleith_node_hash_vt *h,
                                          const gf8_wire_id *leaf_data,
                                          size_t leaf_data_bytes,
                                          const gf8_wire_id *path_nodes,
                                          const gf8_wire_id *path_dirs,
                                          size_t depth, gf8_wire_id *root);

#endif /* VOLEITH_MERKLE_VT_GF8_CIRCUIT_H */
