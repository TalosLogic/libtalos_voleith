/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_grostl_gf8_circuit.h - Indexed Merkle non-membership
 * proof over wide Grøstl nodes, as a GF(2⁸) element-level circuit.
 *
 * Wide-node companion to indexed_merkle_gf8_circuit.h.  That circuit
 * hashes the adjacent leaf record and its authentication path with
 * 16-byte AES-DM / AES-CMAC nodes (2⁶⁴ collision resistance).  This one
 * uses the wider Grøstl nodes of merkle_grostl_gf8_circuit.h, giving the
 * full collision resistance of the digest (2¹²⁸ / 2¹⁰⁸ / 2²⁵⁶ for the
 * GROSTL_256 / GROSTL_256_T27 / GROSTL_512 variants).  Use this when an
 * adversary can choose leaf values - the indexed tree's non-membership
 * soundness then rests on the node hash's collision resistance, and
 * 2⁶⁴ is below the security level.
 *
 * The structure is identical to the DM/CMAC indexed circuit:
 *   1. Hash the adjacent leaf record
 *      (leaf_data = low_value || low_next || next_index) with Grøstl.
 *   2. Verify its Merkle path (computes the root from leaf hash +
 *      siblings) with the Grøstl inode hash.
 *   3. Assert low_value < target  and  target < low_next.
 *
 * Steps 1-2 are the merkle_grostl_gf8 circuits; step 3 is the shared
 * indexed_merkle_gf8_assert_lt comparison (3 GF(2⁸) mul gates per bit),
 * which is over the value field and so is independent of node size.
 *
 * Trust assumption: as with every indexed-Merkle non-membership proof,
 * soundness additionally requires that the tree builder honestly
 * maintains the linked-list adjacency invariant (each leaf's next_value
 * / next_index identifies the next-larger leaf actually present).  The
 * circuit cannot verify this; see indexed_merkle_gf8_circuit.h and the
 * project design notes.
 *
 * Direction convention (same as merkle_grostl_gf8_circuit.h): the
 * public-dir circuit takes path_dirs as a plain const uint8_t * of 0/1
 * values resolved at circuit-build time (public leaf index, zero
 * mul-gate cost).  The secret-dir circuit
 * (indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir) takes
 * path_dirs as committed gf8_wire_id witness wires and muxes each node
 * byte, hiding the leaf index - required for the anonymous-credential
 * revocation use case, where the index would deanonymize the member.
 */

#ifndef VOLEITH_INDEXED_MERKLE_GROSTL_GF8_CIRCUIT_H
#define VOLEITH_INDEXED_MERKLE_GROSTL_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/*
 * indexed_merkle_grostl_gf8_nonmember_circuit - prove T is not in an
 * indexed Merkle tree whose nodes are Grøstl hashes.
 *
 * Appends gates that hash the adjacent leaf record, verify its Merkle
 * path, and internally assert the two ordering constraints
 * low_value < target and target < low_next.
 *
 * c            - circuit to append to
 * target       - target_bytes wire IDs for T (byte 0 = LSB byte)
 * target_bytes - byte width of target, low_value, and low_next; > 0
 * low_value    - target_bytes wire IDs for the adjacent leaf value (< target)
 * low_next     - target_bytes wire IDs for the adjacent leaf next_value (> target)
 * next_index   - index_bytes wire IDs for the adjacent leaf next_index field;
 *                included verbatim in the leaf hash
 * index_bytes  - byte width of next_index; > 0
 * path_nodes   - depth × node_bytes wire IDs for sibling hashes, leaf-level first
 * path_dirs    - depth plain 0/1 values (public leaf index, resolved at build time)
 * depth        - number of levels from leaf hash to root (>= 1)
 * variant      - Grøstl node variant; must match the tree being verified
 * root         - output: merkle_grostl_node_bytes(variant) wire IDs for the
 *                computed tree root
 *
 * Returns 0 on success; -1 if (2*target_bytes + index_bytes) exceeds the
 * internal stack-VLA bound (in which case the circuit is left unchanged
 * and root is not written - check the return value before consuming root).
 */
int indexed_merkle_grostl_gf8_nonmember_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root);

/*
 * indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir - prove
 * non-membership with private path direction bits (hidden leaf index).
 *
 * Identical to indexed_merkle_grostl_gf8_nonmember_circuit except
 * path_dirs is an array of gf8_wire_id (private witnesses, one per
 * level), each carrying 0x00 or 0x01.  Use when the leaf index must
 * remain hidden - e.g. anonymous-credential revocation, where the
 * adjacent leaf's position would deanonymize the prover.
 *
 * Additional cost vs. the public-dir variant: node_bytes mul gates per
 * level for the muxes.  Booleanity of each direction wire
 * (dir in {0, 1}) is enforced inside
 * merkle_grostl_gf8_path_circuit_secret_dir, so it is not repeated here.
 *
 * Parameters: same as indexed_merkle_grostl_gf8_nonmember_circuit except
 *   path_dirs - depth gf8_wire_id, each 0x00 or 0x01 (private witness wires)
 *
 * Returns 0 on success; -1 on the same stack-VLA bound violation as the
 * public-dir variant.
 */
int indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root);

#endif /* VOLEITH_INDEXED_MERKLE_GROSTL_GF8_CIRCUIT_H */
