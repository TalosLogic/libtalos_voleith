/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_grostl_gf8_circuit.c - Indexed Merkle non-membership
 * proof over wide Grøstl nodes.
 *
 * See indexed_merkle_grostl_gf8_circuit.h for the protocol and the trust
 * assumption.  This is the wide-node analogue of
 * indexed_merkle_gf8_circuit.c: the leaf-record hash and the
 * authentication path use the Grøstl circuits from
 * merkle_grostl_gf8_circuit.c, while the ordering comparison reuses the
 * shared indexed_merkle_gf8_assert_lt (node-size independent).
 */

#include "indexed_merkle_grostl_gf8_circuit.h"
#include "circuit.h"                    /* for VOLEITH_STACK_BUF_MAX */
#include "indexed_merkle_gf8_circuit.h" /* shared indexed_merkle_gf8_assert_lt */
#include "merkle_grostl_gf8_circuit.h"
#include <stddef.h>

/*
 * Maximum leaf-data byte-wire count to allocate on the stack.
 * leaf_data_bytes = 2*target_bytes + index_bytes; each gf8_wire_id is 4 bytes.
 */
#define LEAF_DATA_MAX_BYTES (VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id))

/* node_bytes for the widest variant; sizes the leaf-hash output buffer. */
#define MAX_NODE_BYTES 64

int
indexed_merkle_grostl_gf8_nonmember_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root)
{
    /* Build leaf data wire array: low_value || low_next || next_index */
    size_t leaf_data_bytes = 2 * target_bytes + index_bytes;
    /* CIR-2: signal stack-VLA bound violation to the caller. */
    if (leaf_data_bytes > LEAF_DATA_MAX_BYTES)
        return -1;

    gf8_wire_id leaf_data
        [leaf_data_bytes]; /* VLA; size bounded by LEAF_DATA_MAX_BYTES */

    size_t off = 0;
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_value[i];
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_next[i];
    for (size_t i = 0; i < index_bytes; i++)
        leaf_data[off++] = next_index[i];

    /* Step 1: hash the adjacent leaf record */
    gf8_wire_id leaf_hash[MAX_NODE_BYTES];
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_data, leaf_data_bytes, variant,
                                        leaf_hash);

    /* Step 2: verify the Merkle authentication path */
    merkle_grostl_gf8_path_circuit(c, leaf_hash, path_nodes, path_dirs, depth,
                                   variant, root);

    /* Step 3: assert ordering constraints (violations fail at verify time) */
    indexed_merkle_gf8_assert_lt(c, low_value, target,
                                 target_bytes); /* low_value < target  */
    indexed_merkle_gf8_assert_lt(c, target, low_next,
                                 target_bytes); /* target   < low_next */
    return 0;
}

int
indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root)
{
    /* Build leaf data wire array: low_value || low_next || next_index */
    size_t leaf_data_bytes = 2 * target_bytes + index_bytes;
    /* CIR-2: same stack-VLA bound check as the public-dir variant. */
    if (leaf_data_bytes > LEAF_DATA_MAX_BYTES)
        return -1;

    gf8_wire_id leaf_data[leaf_data_bytes];

    size_t off = 0;
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_value[i];
    for (size_t i = 0; i < target_bytes; i++)
        leaf_data[off++] = low_next[i];
    for (size_t i = 0; i < index_bytes; i++)
        leaf_data[off++] = next_index[i];

    /* Step 1: hash the adjacent leaf record */
    gf8_wire_id leaf_hash[MAX_NODE_BYTES];
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_data, leaf_data_bytes, variant,
                                        leaf_hash);

    /*
     * Step 2: verify the Merkle authentication path.  path_dirs are private
     * wires; their booleanity (dir in {0, 1}) is enforced inside
     * merkle_grostl_gf8_path_circuit_secret_dir, so it need not be repeated
     * here.
     */
    merkle_grostl_gf8_path_circuit_secret_dir(c, leaf_hash, path_nodes,
                                              path_dirs, depth, variant, root);

    /* Step 3: assert ordering constraints */
    indexed_merkle_gf8_assert_lt(c, low_value, target, target_bytes);
    indexed_merkle_gf8_assert_lt(c, target, low_next, target_bytes);
    return 0;
}
