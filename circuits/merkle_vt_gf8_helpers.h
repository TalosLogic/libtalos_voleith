/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_vt_gf8_helpers.h - software helpers for hash-agnostic Merkle
 * trees driven by voleith_node_hash_vt.
 *
 * These run entirely out of circuit: the level-by-level walk uses the
 * vt's inode_hash software callback to build a root or extract a
 * sibling path.  Packages the pattern currently inlined in test
 * fixtures (and in the KVAC example) into a library-level API so
 * RSv1's voleith_rsv1_ring_build (T5c) and any future ring builder
 * can call one function instead of carrying a local tree walker.
 *
 * Leaf input is the array of pre-hashed leaf nodes (each vt->node_bytes
 * wide).  Computing those leaf nodes from secret material is the
 * caller's job (one vt->leaf_hash call per leaf); RSv1's ring builder
 * does that step before invoking voleith_merkle_vt_build.
 *
 * Caller-visible failures (return -1) are limited to argument
 * validation (NULL, n_leaves zero or not a power of two, leaf_index
 * out of range) and propagated vt->inode_hash errors.  Memory
 * allocation failure is also surfaced as -1.
 *
 * See docs/RSV1_DESIGN.md §10 step 5 and docs/RSV1_IMPLEMENTATION_PLAN.md
 * T5a for the use case driving this module.
 */

#ifndef VOLEITH_MERKLE_VT_GF8_HELPERS_H
#define VOLEITH_MERKLE_VT_GF8_HELPERS_H

#include "node_hash_vt.h"

#include <stddef.h>
#include <stdint.h>

/*
 * voleith_merkle_vt_build - compute the Merkle root from an array of
 * pre-hashed leaf nodes.
 *
 * Walks vt->inode_hash level by level over a balanced binary tree.
 *
 * vt         - node-hash vt providing inode_hash and node_bytes.
 * leaf_nodes - n_leaves * vt->node_bytes bytes, leaf 0 first.
 * n_leaves   - count of leaves.  MUST be a non-zero power of two;
 *              otherwise -1.
 * root_out   - vt->node_bytes bytes, written iff the call returns 0.
 *
 * Returns 0 on success, -1 on NULL argument, malformed n_leaves,
 * vt->inode_hash failure, or allocation failure.  On failure root_out
 * is left untouched.
 */
int voleith_merkle_vt_build(const voleith_node_hash_vt *vt,
                            const uint8_t *leaf_nodes, size_t n_leaves,
                            uint8_t *root_out);

/*
 * voleith_merkle_vt_compute_path - extract the sibling path for one
 * leaf in a balanced Merkle tree.
 *
 * Walks the same level-by-level pattern as voleith_merkle_vt_build,
 * but instead of just emitting the root, emits the sibling node at
 * each level along the path from leaf_index to the root.
 *
 * Sibling ordering matches the secret-dir Merkle path circuit
 * convention (merkle_vt_gf8_circuit.h): siblings_out[k]
 * is the sibling at level k counted from the leaf upward, with k = 0
 * at leaf level and k = depth - 1 at the level just below the root.
 * For leaf_index i, the sibling at level k sits at position
 * (i >> k) ^ 1 within that level's node array.
 *
 * Caller derives path_dirs separately from leaf_index (the
 * voleith_rs_membership_pack_witness implementation does this); the
 * paths produced here drop straight into that packer.
 *
 * vt           - node-hash vt providing inode_hash and node_bytes.
 * leaf_nodes   - n_leaves * vt->node_bytes bytes, leaf 0 first.
 * n_leaves     - count of leaves.  Same constraint as build.
 * leaf_index   - which leaf's path to emit.  MUST satisfy
 *                leaf_index < n_leaves; otherwise -1.
 * siblings_out - log2(n_leaves) * vt->node_bytes bytes, written iff
 *                the call returns 0.
 *
 * Returns 0 on success, -1 on NULL argument, malformed n_leaves,
 * leaf_index out of range, vt->inode_hash failure, or allocation
 * failure.  On failure siblings_out is left untouched.
 */
int voleith_merkle_vt_compute_path(const voleith_node_hash_vt *vt,
                                   const uint8_t *leaf_nodes, size_t n_leaves,
                                   size_t leaf_index, uint8_t *siblings_out);

#endif /* VOLEITH_MERKLE_VT_GF8_HELPERS_H */
