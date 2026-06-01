/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_vt_gf8_circuit.c - generic vt-driven indexed-Merkle
 * non-membership circuit (Branch C).
 *
 * Build leaf_data = low_value || low_next || next_index (as a wire
 * array), run merkle_vt_gf8_path_circuit{,_secret_dir} on it, then
 * assert low_value < target  and  target < low_next via the shared
 * indexed_merkle_gf8_assert_lt comparison.
 *
 * Identical body shape to the existing
 * indexed_merkle_gf8_nonmember_circuit and
 * indexed_merkle_grostl_gf8_nonmember_circuit; the only differences
 * are that the leaf-hash + path emission go through h-> rather than
 * through the family-specific entry points, and the leaf_data wire
 * array bound matches the existing fixed-hash entries'
 * (LEAF_DATA_MAX_BYTES = VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id)).
 *
 * Bit-exact gate-stream equivalence with the existing fixed-hash entry
 * points is asserted by tests/test_indexed_merkle_vt_gf8_equivalence.c.
 */

#include "indexed_merkle_vt_gf8_circuit.h"
#include "indexed_merkle_gf8_circuit.h" /* shared indexed_merkle_gf8_assert_lt */
#include "../proof/circuit.h"           /* VOLEITH_STACK_BUF_MAX */
#include <stddef.h>
#include <stdint.h>

/* Stack-VLA bound for the leaf_data wire array - matches the existing
 * indexed_merkle_gf8_circuit / indexed_merkle_grostl_gf8_circuit
 * fixed-hash entries' LEAF_DATA_MAX_BYTES exactly. */
#define MERKLE_VT_LEAF_DATA_MAX_BYTES                                          \
    (VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id))

int
merkle_vt_gf8_indexed_nonmember_circuit(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    gf8_wire_id *root)
{
    if (h->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    size_t leaf_data_bytes = 2 * target_bytes + index_bytes;
    if (leaf_data_bytes > MERKLE_VT_LEAF_DATA_MAX_BYTES)
        return -1;

    gf8_wire_id leaf_data[leaf_data_bytes]; /* VLA, size-bounded above */

    size_t off = 0;
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_value[i];
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_next[i];
    for (size_t i = 0; i < index_bytes; i++)
        leaf_data[off++] = next_index[i];

    if (merkle_vt_gf8_path_circuit(c, h, leaf_data, leaf_data_bytes, path_nodes,
                                   path_dirs, depth, root) != 0)
        return -1;

    indexed_merkle_gf8_assert_lt(c, low_value, target, target_bytes);
    indexed_merkle_gf8_assert_lt(c, target, low_next, target_bytes);
    return 0;
}

int
merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    gf8_wire_id *root)
{
    if (h->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    size_t leaf_data_bytes = 2 * target_bytes + index_bytes;
    if (leaf_data_bytes > MERKLE_VT_LEAF_DATA_MAX_BYTES)
        return -1;

    gf8_wire_id leaf_data[leaf_data_bytes];

    size_t off = 0;
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_value[i];
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_next[i];
    for (size_t i = 0; i < index_bytes; i++)
        leaf_data[off++] = next_index[i];

    /*
     * Direction-wire booleanity is enforced inside
     * merkle_vt_gf8_path_circuit_secret_dir; not repeated here.
     */
    if (merkle_vt_gf8_path_circuit_secret_dir(c, h, leaf_data, leaf_data_bytes,
                                              path_nodes, path_dirs, depth,
                                              root) != 0)
        return -1;

    indexed_merkle_gf8_assert_lt(c, low_value, target, target_bytes);
    indexed_merkle_gf8_assert_lt(c, target, low_next, target_bytes);
    return 0;
}
