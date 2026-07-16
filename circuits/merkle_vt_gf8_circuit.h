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

/*
 * merkle_vt_gf8_path_from_leaf_node_secret_dir - verify a Merkle path
 * with a private (witness) leaf index, starting from a pre-computed
 * leaf node.
 *
 * Same as merkle_vt_gf8_path_circuit_secret_dir, but skips the
 * leaf-hash gates: the caller supplies h->node_bytes wires that
 * already hold the leaf node value (e.g. the output wires of an OWF
 * leaf_circuit shared with the membership tree).  Enables RSv1 and any
 * future consumer to feed an already-hashed leaf into the inode walk
 * without paying a second leaf-hash gate stream.
 *
 * Equivalence: when called on `vt->leaf_hash(leaf_data)`, the gate
 * stream of the inode walk is byte-exact identical to
 * merkle_vt_gf8_path_circuit_secret_dir called on `leaf_data`.  The
 * caller is responsible for declaring or building the leaf_node wires
 * however they wish; this entry owns only the inode walk and the
 * per-level booleanity check on path_dirs.
 *
 * Booleanity: every dir wire is constrained to {0, 1} by an
 * in-circuit assert_product(dir, dir, dir) at the matching level.
 * Same structural soundness rule as the existing secret-dir entry.
 *
 * c          - circuit to append to
 * h          - node-hash vt
 * leaf_node  - h->node_bytes wire IDs holding the leaf node value
 * path_nodes - depth * h->node_bytes wire IDs of sibling hashes,
 *              leaf-level first
 * path_dirs  - depth witness wires, each 0x00 or 0x01
 * depth      - number of levels from leaf node to root
 * root       - output: h->node_bytes wire IDs for the root
 *
 * Returns 0 on success, -1 if h->node_bytes exceeds
 * MERKLE_VT_MAX_NODE_BYTES.
 */
int merkle_vt_gf8_path_from_leaf_node_secret_dir(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *leaf_node, const gf8_wire_id *path_nodes,
    const gf8_wire_id *path_dirs, size_t depth, gf8_wire_id *root);

/*
 * merkle_vt_gf8_path_from_leaf_node_public_dir - verify a Merkle path
 * with per-proof PUBLIC directions supplied as instance wires, starting
 * from a pre-computed leaf node.
 *
 * Unlike merkle_vt_gf8_path_circuit (whose path_dirs are plain uint8_t
 * constants resolved at circuit-build time, so the tree shape is baked
 * into the fingerprint), this entry carries the direction at each level
 * on a runtime INSTANCE wire.  The gate stream is therefore identical
 * for every direction pattern at a fixed depth (t-independence): the
 * concrete directions enter only as instance values at prove/verify
 * time.  This is what lets a caller pin one circuit fingerprint per
 * config while proving membership at an arbitrary public position, e.g.
 * the RSv6 epoch tree at public epoch t.
 *
 * Like the secret-dir form, each level selects the (left, right) pair
 * from (current, sibling) under dir.  Here the selection uses the
 * slot-free voleith_gf8_add_mux_instance, so a level costs only the
 * inode gate stream: zero extra VOLE slots for the swap.
 *
 * Booleanity: NONE is enforced, and none is required.  Each dir is a
 * PUBLIC instance wire fixed by the verifier (library-derived from the
 * public index), not a prover-chosen witness, so the malicious-selector
 * attack that forces the secret-dir booleanity rule does not apply.  A
 * non-boolean public dir would merely yield the algebraic mux result
 * (same contract as voleith_gf8_add_mux_instance); callers derive the
 * dir bytes from the public position and never expose that knob.
 *
 * c          - circuit to append to
 * h          - node-hash vt
 * leaf_node  - h->node_bytes wire IDs holding the leaf node value
 * path_nodes - depth * h->node_bytes wire IDs of sibling hashes,
 *              leaf-level first
 * path_dirs  - depth INSTANCE wires, each carrying 0x00 or 0x01
 * depth      - number of levels from leaf node to root
 * root       - output: h->node_bytes wire IDs for the root
 *
 * Returns 0 on success, -1 if h->node_bytes exceeds
 * MERKLE_VT_MAX_NODE_BYTES.  A dir wire that is not an INSTANCE wire is
 * rejected by the mux builder (the circuit's ok flag is cleared).
 */
int merkle_vt_gf8_path_from_leaf_node_public_dir(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *leaf_node, const gf8_wire_id *path_nodes,
    const gf8_wire_id *path_dirs, size_t depth, gf8_wire_id *root);

#endif /* VOLEITH_MERKLE_VT_GF8_CIRCUIT_H */
