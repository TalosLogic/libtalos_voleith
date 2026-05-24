/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_circuit.h - Indexed Merkle non-membership proof as Boolean circuit
 *
 * An indexed Merkle tree is a sorted Merkle tree where each leaf stores a
 * (value, next_value, next_index) triple with the invariant:
 *
 *   value[i] < next_value[i]  for all i
 *   next_value[i] == value[next_index[i]]
 *
 * To prove that target T is NOT a member of the set:
 *   1. Find the adjacent leaf L such that L.value < T < L.next_value.
 *   2. Prove L is in the tree (Merkle path verification).
 *   3. Assert L.value < T  and  T < L.next_value.
 *
 * This circuit performs all three steps:
 *   - Hashes the adjacent leaf record: leaf_data = low_value || low_next || next_index
 *   - Verifies the Merkle path (computes root from leaf hash + siblings)
 *   - Asserts low_value < target  and  target < low_next  (internal constraints)
 *
 * The root output is returned for the caller to assert equal to the known
 * public root instance wires.
 *
 * AND gate cost:
 *   leaf hash: 7,200 (DM) or 14,400 (CMAC) for leaf_data fitting one 128-bit block
 *              (additional 7,200 or 7,200/14,400 AND gates per extra block if
 *               2*target_bits + index_bits > 128)
 *   path:      depth × 7,328 (DM) or depth × 21,728 (CMAC)
 *   ordering:  6 × target_bits AND gates (2 comparisons × 3 AND gates/bit)
 *
 * Comparison circuit (assert a < b, n = target_bits):
 *   Processes bit positions from MSB (n-1) down to LSB (0).  At each bit i:
 *     hi_i      = NOT(a[i]) AND b[i]        1 AND: a[i]=0,b[i]=1 at this bit
 *     update_lt = eq_mask AND hi_i           1 AND: only if higher bits matched
 *     lt       ^= update_lt                  XOR: free
 *     eq_mask  &= NOT(a[i] XOR b[i])         1 AND: clear mask when bits diverge
 *   Constraint: assert_zero(NOT(lt))  - fails proof if a >= b.
 *
 * Bit/byte convention: same as aes_circuit.h.
 *   Each byte: 8 consecutive wire IDs, bit 0 = LSB, bit 7 = MSB.
 *   For an N-bit integer: wire[0] = LSB, wire[N-1] = MSB.
 *
 * Wire type convention (Signal KVAC typical use):
 *   target:     add_instance() - public value to prove non-membership of.
 *   low_value, low_next, next_index, path_nodes, path_dirs:
 *               add_witness() - private; reveals which leaf and path were used.
 *   root[]:     caller asserts_equal to add_instance() root wires after calling
 *               this function.  The circuit computes root; it does not assert it.
 *
 * Constraints added internally (checked at proof verification, not at eval):
 *   assert_zero(NOT(lt_low_target)):   low_value < target
 *   assert_zero(NOT(lt_target_next)):  target < low_next
 */

#ifndef VOLEITH_INDEXED_MERKLE_CIRCUIT_H
#define VOLEITH_INDEXED_MERKLE_CIRCUIT_H

#include "circuit.h"
#include "merkle_circuit.h"
#include <stddef.h>

/*
 * indexed_merkle_nonmember_circuit - prove T is not in an indexed Merkle tree.
 *
 * Appends gates that hash the adjacent leaf record, verify its Merkle path,
 * and internally assert the two ordering constraints low_value < target and
 * target < low_next.
 *
 * Parameters:
 *   c           - circuit to append gates to
 *   target      - target_bits wire IDs for the value T (bit 0 = LSB)
 *   target_bits - bit width of target, low_value, and low_next; must be > 0.
 *                 Requires 2*target_bits + index_bits to be a multiple of 8.
 *   low_value   - target_bits wire IDs for the adjacent leaf value (< target)
 *   low_next    - target_bits wire IDs for the adjacent leaf next_value (> target)
 *   next_index  - index_bits wire IDs for the adjacent leaf next_index field;
 *                 included verbatim in the leaf hash for full leaf binding
 *   index_bits  - bit width of next_index; must be > 0
 *   path_nodes  - depth × 128 wire IDs for sibling hashes, leaf-level first
 *   path_dirs   - depth wire IDs for direction bits (0=left, 1=right), leaf-level first
 *   depth       - number of levels from leaf hash to root (>= 1)
 *   hash        - hash function (DM or CMAC); must match the tree being verified
 *   root        - output: 128 wire IDs for the computed tree root
 */
void indexed_merkle_nonmember_circuit(
    voleith_circuit_t *c, const wire_id *target, size_t target_bits,
    const wire_id *low_value, const wire_id *low_next,
    const wire_id *next_index, size_t index_bits, const wire_id *path_nodes,
    const wire_id *path_dirs, size_t depth, voleith_merkle_hash_t hash,
    wire_id root[128]);

#endif /* VOLEITH_INDEXED_MERKLE_CIRCUIT_H */
