/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_vt_gf8_helpers.c - software helpers for hash-agnostic Merkle
 * trees driven by voleith_node_hash_vt.
 *
 * Packages the level-by-level inode walk previously inlined in test
 * fixtures and the KVAC example.  See merkle_vt_gf8_helpers.h for the
 * public contract and the RS-V1 implementation plan T5a for the use
 * case driving this module.
 */

#include "merkle_vt_gf8_helpers.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int
is_power_of_two(size_t n)
{
    return n > 0 && (n & (n - 1)) == 0;
}

/*
 * Level-by-level walker shared by build / compute_path.  Maintains a
 * ping-pong (cur, next) pair of node-buffers and applies vt->inode_hash
 * across consecutive pairs at each level.  If siblings_out is non-NULL,
 * emits the sibling node along the path from leaf_index (LSB first)
 * before each compression step.
 */
static int
walk_tree(const voleith_node_hash_vt *vt, const uint8_t *leaf_nodes,
          size_t n_leaves, size_t leaf_index, uint8_t *root_out,
          uint8_t *siblings_out)
{
    size_t W = vt->node_bytes;

    if (n_leaves == 1) {
        memcpy(root_out, leaf_nodes, W);
        return 0;
    }

    uint8_t *cur = calloc(n_leaves, W);
    uint8_t *next = calloc(n_leaves / 2u, W);
    if (cur == NULL || next == NULL) {
        free(cur);
        free(next);
        return -1;
    }

    memcpy(cur, leaf_nodes, n_leaves * W);
    size_t cur_n = n_leaves;
    size_t cur_idx = leaf_index;
    size_t level = 0;

    while (cur_n > 1) {
        if (siblings_out != NULL) {
            size_t sib_idx = cur_idx ^ 1u;
            memcpy(siblings_out + level * W, cur + sib_idx * W, W);
        }

        size_t next_n = cur_n >> 1;
        for (size_t j = 0; j < next_n; j++) {
            if (vt->inode_hash(cur + (2u * j) * W, cur + (2u * j + 1u) * W,
                               next + j * W) != 0) {
                free(cur);
                free(next);
                return -1;
            }
        }

        memcpy(cur, next, next_n * W);
        cur_n = next_n;
        cur_idx >>= 1;
        level++;
    }

    memcpy(root_out, cur, W);
    free(cur);
    free(next);
    return 0;
}

int
voleith_merkle_vt_build(const voleith_node_hash_vt *vt,
                        const uint8_t *leaf_nodes, size_t n_leaves,
                        uint8_t *root_out)
{
    if (vt == NULL || leaf_nodes == NULL || root_out == NULL)
        return -1;
    if (!is_power_of_two(n_leaves))
        return -1;
    if (vt->node_bytes == 0 || vt->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    if (vt->inode_hash == NULL)
        return -1;

    return walk_tree(vt, leaf_nodes, n_leaves, 0, root_out, NULL);
}

int
voleith_merkle_vt_compute_path(const voleith_node_hash_vt *vt,
                               const uint8_t *leaf_nodes, size_t n_leaves,
                               size_t leaf_index, uint8_t *siblings_out)
{
    if (vt == NULL || leaf_nodes == NULL)
        return -1;
    if (!is_power_of_two(n_leaves))
        return -1;
    if (leaf_index >= n_leaves)
        return -1;
    if (vt->node_bytes == 0 || vt->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    if (vt->inode_hash == NULL)
        return -1;
    if (n_leaves > 1 && siblings_out == NULL)
        return -1;

    /*
     * The walker writes a root we don't expose.  Sized to the vt's
     * compile-time maximum so the stack scratch fits any in-tree vt.
     */
    uint8_t root_scratch[MERKLE_VT_MAX_NODE_BYTES];
    return walk_tree(vt, leaf_nodes, n_leaves, leaf_index, root_scratch,
                     siblings_out);
}
