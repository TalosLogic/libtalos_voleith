/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_vt_gf8_circuit.c - generic vt-driven Merkle path circuit.
 *
 * Single body parameterised by voleith_node_hash_vt; supports both
 * public-dir (zero mul-gate static swap) and secret-dir (per-byte
 * mux with structural booleanity).  All hash-specific gates live in
 * h->leaf_circuit and h->inode_circuit; this body owns only the path
 * traversal, the direction handling, and the booleanity rule.
 *
 * Bit-exact gate-stream equivalence with the existing fixed-hash entry
 * points (merkle_gf8_path_circuit, merkle_grostl_gf8_path_circuit, and
 * their secret-dir forms) is asserted by
 * tests/test_merkle_vt_gf8_equivalence.c.
 */

#include "merkle_vt_gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/* MERKLE_VT_MAX_NODE_BYTES lives in node_hash_vt.h so vt definitions
 * can _Static_assert against it. */

/*
 * walk_inodes_public_dir - inode-chain walk for the public-dir entry
 * points.  Direction is resolved statically at circuit-build time, so
 * the left/right swap is a pointer choice with zero mul-gate cost.
 *
 * On entry `current` holds the W = h->node_bytes leaf-level wire IDs
 * (already populated by the caller, from either leaf_circuit or a
 * pre-computed leaf node).  On exit `current` holds the root-level
 * wire IDs.
 */
static void
walk_inodes_public_dir(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
                       gf8_wire_id *current, const gf8_wire_id *path_nodes,
                       const uint8_t *path_dirs, size_t depth)
{
    size_t W = h->node_bytes;

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * W;
        const gf8_wire_id *left = path_dirs[level] ? sibling : current;
        const gf8_wire_id *right = path_dirs[level] ? current : sibling;

        gf8_wire_id next[MERKLE_VT_MAX_NODE_BYTES];
        h->inode_circuit(c, left, right, next);
        for (size_t i = 0; i < W; i++)
            current[i] = next[i];
    }
}

/*
 * walk_inodes_secret_dir - inode-chain walk for the secret-dir entry
 * points.  Each level pays W mul gates for a per-byte mux selecting
 * the (left, right) pair from (current, sibling) under dir, plus one
 * free assert_product(dir, dir, dir) booleanity check.
 *
 * Booleanity is enforced HERE so every secret-dir caller inherits the
 * structural soundness rule.  Never leave the {0, 1} constraint to the
 * caller - an unconstrained mux selector is a silent soundness break.
 *
 * On entry `current` holds the W = h->node_bytes leaf-level wire IDs.
 * On exit `current` holds the root-level wire IDs.
 */
static void
walk_inodes_secret_dir(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
                       gf8_wire_id *current, const gf8_wire_id *path_nodes,
                       const gf8_wire_id *path_dirs, size_t depth)
{
    size_t W = h->node_bytes;

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * W;
        gf8_wire_id dir = path_dirs[level];

        /*
         * Structural soundness: every direction wire must be a bit.
         * dir == dir * dir holds only for dir in {0, 1} in GF(2^8).
         * Free check (no mul-slot, no witness); folded into the
         * QuickSilver batch.  An unconstrained mux selector is a
         * silent soundness break - a malicious prover can blend the
         * (current, sibling) ordering and forge a path.
         */
        voleith_gf8_assert_product(c, dir, dir, dir);

        gf8_wire_id left[MERKLE_VT_MAX_NODE_BYTES];
        gf8_wire_id right[MERKLE_VT_MAX_NODE_BYTES];
        for (size_t i = 0; i < W; i++) {
            left[i] = voleith_gf8_add_mux(c, current[i], sibling[i], dir);
            gf8_wire_id cs = voleith_gf8_add_xor(c, current[i], sibling[i]);
            right[i] = voleith_gf8_add_xor(c, left[i], cs);
        }

        gf8_wire_id next[MERKLE_VT_MAX_NODE_BYTES];
        h->inode_circuit(c, left, right, next);
        for (size_t i = 0; i < W; i++)
            current[i] = next[i];
    }
}

int
merkle_vt_gf8_path_circuit(voleith_gf8_circuit_t *c,
                           const voleith_node_hash_vt *h,
                           const gf8_wire_id *leaf_data, size_t leaf_data_bytes,
                           const gf8_wire_id *path_nodes,
                           const uint8_t *path_dirs, size_t depth,
                           gf8_wire_id *root)
{
    if (h->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    size_t W = h->node_bytes;

    gf8_wire_id current[MERKLE_VT_MAX_NODE_BYTES];
    h->leaf_circuit(c, leaf_data, leaf_data_bytes, current);

    walk_inodes_public_dir(c, h, current, path_nodes, path_dirs, depth);

    for (size_t i = 0; i < W; i++)
        root[i] = current[i];
    return 0;
}

int
merkle_vt_gf8_path_circuit_secret_dir(voleith_gf8_circuit_t *c,
                                      const voleith_node_hash_vt *h,
                                      const gf8_wire_id *leaf_data,
                                      size_t leaf_data_bytes,
                                      const gf8_wire_id *path_nodes,
                                      const gf8_wire_id *path_dirs,
                                      size_t depth, gf8_wire_id *root)
{
    if (h->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    size_t W = h->node_bytes;

    gf8_wire_id current[MERKLE_VT_MAX_NODE_BYTES];
    h->leaf_circuit(c, leaf_data, leaf_data_bytes, current);

    walk_inodes_secret_dir(c, h, current, path_nodes, path_dirs, depth);

    for (size_t i = 0; i < W; i++)
        root[i] = current[i];
    return 0;
}

int
merkle_vt_gf8_path_from_leaf_node_secret_dir(voleith_gf8_circuit_t *c,
                                             const voleith_node_hash_vt *h,
                                             const gf8_wire_id *leaf_node,
                                             const gf8_wire_id *path_nodes,
                                             const gf8_wire_id *path_dirs,
                                             size_t depth, gf8_wire_id *root)
{
    if (h->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    size_t W = h->node_bytes;

    gf8_wire_id current[MERKLE_VT_MAX_NODE_BYTES];
    for (size_t i = 0; i < W; i++)
        current[i] = leaf_node[i];

    walk_inodes_secret_dir(c, h, current, path_nodes, path_dirs, depth);

    for (size_t i = 0; i < W; i++)
        root[i] = current[i];
    return 0;
}
