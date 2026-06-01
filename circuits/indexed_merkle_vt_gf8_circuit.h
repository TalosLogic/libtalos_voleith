/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_vt_gf8_circuit.h - generic vt-driven indexed-Merkle
 * non-membership circuit.
 *
 * Branch C of the merkle tree circuits hash-agnostic refactor
 * (docs/MERKLE_TREE_CIRCUITS_DESIGN.md "Implementation plan:
 * hash-agnostic refactor").  Hash-family-agnostic indexed Merkle
 * non-membership parameterised by a voleith_node_hash_vt - one body
 * usable across every wrapped vt.
 *
 * Composed on top of circuits/merkle_vt_gf8_circuit.{h,c} (Branch B):
 * this circuit builds the adjacent-leaf record (low_value || low_next
 * || next_index) as a wire array, calls the generic Merkle path
 * circuit on it, then asserts the two ordering constraints via the
 * shared indexed_merkle_gf8_assert_lt comparison.  Mirrors the
 * existing per-family layout (merkle_gf8_circuit.c is paired with
 * indexed_merkle_gf8_circuit.c; merkle_grostl_gf8_circuit.c with
 * indexed_merkle_grostl_gf8_circuit.c).
 *
 * Each existing fixed-hash entry point in
 * circuits/indexed_merkle_gf8_circuit.h and
 * circuits/indexed_merkle_grostl_gf8_circuit.h has an equivalent
 * invocation here.  Bit-exact equivalence is asserted by
 * tests/test_indexed_merkle_vt_gf8_equivalence.c for every
 * existing-entry / equivalent-vt pairing.
 *
 * The existing fixed-hash entry points stay in place unchanged -
 * Branch C is purely additive.
 */

#ifndef VOLEITH_INDEXED_MERKLE_VT_GF8_CIRCUIT_H
#define VOLEITH_INDEXED_MERKLE_VT_GF8_CIRCUIT_H

#include "merkle_vt_gf8_circuit.h"

/*
 * merkle_vt_gf8_indexed_nonmember_circuit - prove T is not a member
 * of an indexed Merkle tree, with a public (instance) leaf index.
 *
 * Indexed-Merkle non-membership: find an adjacent leaf L such that
 *   L.value < T < L.next_value
 * and prove (a) L is in the tree (Merkle path verification with the
 * leaf record low_value || low_next || next_index), (b) the two
 * ordering constraints hold.  The leaf hash, inode hash, and path
 * traversal come from h; the comparisons come from the shared
 * indexed_merkle_gf8_assert_lt (the comparison is over the value
 * field and is independent of node size).
 *
 * Generic counterpart to the family-specific
 *   indexed_merkle_gf8_nonmember_circuit(... voleith_merkle_hash_t)
 *   indexed_merkle_grostl_gf8_nonmember_circuit(... grostl_variant_t)
 * fixed-hash entry points.  Bit-exact equivalence is asserted by the
 * Branch C equivalence harness.
 *
 * c            - circuit to append to
 * h            - node-hash vt; selects the leaf / inode / path family
 * target       - target_bytes wire IDs for T (byte 0 = LSB byte)
 * target_bytes - byte width of target, low_value, low_next; > 0
 * low_value    - target_bytes wire IDs for the adjacent leaf value (< T)
 * low_next     - target_bytes wire IDs for the adjacent leaf next_value (> T)
 * next_index   - index_bytes wire IDs for the adjacent leaf next_index
 *                field; included verbatim in the leaf hash
 * index_bytes  - byte width of next_index; > 0
 * path_nodes   - depth * h->node_bytes wire IDs for sibling hashes,
 *                leaf-level first
 * path_dirs    - depth bytes of plain 0/1 values (public leaf index)
 * depth        - number of levels from leaf hash to root (>= 1)
 * root         - output: h->node_bytes wire IDs for the computed root
 *
 * Returns 0 on success; -1 if (2*target_bytes + index_bytes) exceeds
 * the internal stack-VLA bound (in which case the circuit is left
 * unchanged and root is not written - caller must check the return
 * value before consuming root).
 */
int merkle_vt_gf8_indexed_nonmember_circuit(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    gf8_wire_id *root);

/*
 * merkle_vt_gf8_indexed_nonmember_circuit_secret_dir - non-membership
 * with a private (witness) leaf index.
 *
 * Identical to merkle_vt_gf8_indexed_nonmember_circuit except path_dirs
 * is an array of gf8_wire_id witness wires (each 0x00 or 0x01).
 * Direction-wire booleanity is enforced inside
 * merkle_vt_gf8_path_circuit_secret_dir; not repeated here.
 *
 * Returns 0 on success; -1 on the same stack-VLA bound violation as
 * the public-dir variant.
 */
int merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
    const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    gf8_wire_id *root);

#endif /* VOLEITH_INDEXED_MERKLE_VT_GF8_CIRCUIT_H */
