/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_gf8_circuit.h - Indexed Merkle non-membership proof as GF(2⁸) circuit
 *
 * GF(2⁸) counterpart to indexed_merkle_circuit.h. Each wire carries one byte.
 *
 * An indexed Merkle tree is a sorted Merkle tree where each leaf stores a
 * (value, next_value, next_index) triple.  To prove T is NOT a member:
 *   1. Find the adjacent leaf L such that L.value < T < L.next_value.
 *   2. Prove L is in the tree (Merkle path verification).
 *   3. Assert L.value < T  and  T < L.next_value.
 *
 * This circuit performs all three steps:
 *   - Hashes the adjacent leaf record: leaf_data = low_value || low_next || next_index
 *   - Verifies the Merkle path (computes root from leaf hash + siblings)
 *   - Asserts low_value < target  and  target < low_next  (internal constraints)
 *
 * Comparison circuit - assert a < b (target_bytes-wide unsigned integers):
 *   Processes bits from the MSB of the MSB-byte down to the LSB of the LSB-byte.
 *   Each bit is extracted from its byte wire via a free GF(2)-linear map.
 *   Uses 3 GF(2⁸) multiplication gates per bit:
 *     hi_i      = (1 XOR a_bit) MUL b_bit    a_bit=0, b_bit=1 at this bit
 *     update_lt = eq_mask MUL hi_i            only if higher bits matched
 *     lt       ^= update_lt                   XOR: free
 *     eq_mask   = eq_mask MUL (1 XOR (a_bit XOR b_bit))   clear mask on divergence
 *   Constraint: assert_zero(lt XOR 0x01) - fails proof if a >= b.
 *
 * VOLE slot cost (witness + mul gates):
 *   leaf hash:   aes_cmac_gf8_n_aes_calls(2*target_bytes+index_bytes) × inv_per_call
 *                (200 for AES-128 hash, 276 for AES-256 hash)
 *   path:        depth × (16 + compress_witnesses)
 *   ordering:    2 × 3 × 8 × target_bytes  mul gates (3 per bit, 2 comparisons)
 *
 * Direction convention (same as merkle_gf8_circuit.h):
 *   indexed_merkle_gf8_nonmember_circuit:
 *     path_dirs is a plain const uint8_t * (public leaf index - zero mul-gate cost).
 *   indexed_merkle_gf8_nonmember_circuit_secret_dir:
 *     path_dirs is a const gf8_wire_id * (private witness, 16 mul gates per level).
 *     Use when the leaf index reveals member identity and must remain hidden.
 *
 * Wire type convention (public-dir variant):
 *   target:                                add_instance() - public value.
 *   low_value, low_next, next_index,
 *   path_nodes:                            add_witness() - private.
 *   path_dirs:                             plain uint8_t (public, resolved at build time).
 *   root[]:                                computed by the circuit; caller should
 *                                          assert_equal to known public root wires.
 */

#ifndef VOLEITH_INDEXED_MERKLE_GF8_CIRCUIT_H
#define VOLEITH_INDEXED_MERKLE_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "merkle_gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/*
 * indexed_merkle_gf8_nonmember_circuit - prove T is not in an indexed Merkle tree.
 *
 * Appends gates that hash the adjacent leaf record, verify its Merkle path,
 * and internally assert the two ordering constraints low_value < target and
 * target < low_next.
 *
 * Parameters:
 *   c            - circuit to append to
 *   target       - target_bytes gf8_wire_id for T (byte 0 = LSB byte)
 *   target_bytes - byte width of target, low_value, and low_next; must be > 0
 *   low_value    - target_bytes gf8_wire_id for the adjacent leaf value (< target)
 *   low_next     - target_bytes gf8_wire_id for the adjacent leaf next_value (> target)
 *   next_index   - index_bytes gf8_wire_id for the adjacent leaf next_index field;
 *                  included verbatim in the leaf hash
 *   index_bytes  - byte width of next_index; must be > 0
 *   path_nodes   - depth × 16 gf8_wire_id for sibling hashes, leaf-level first
 *   path_dirs    - depth plain 0/1 values (public leaf index, resolved at build time)
 *   depth        - number of levels from leaf hash to root (>= 1)
 *   hash         - hash function; must match the tree being verified
 *   root         - output: 16 gf8_wire_id for the computed tree root
 *
 * Returns 0 on success; -1 if (2*target_bytes + index_bytes) exceeds
 * the internal stack-VLA bound LEAF_DATA_MAX_BYTES (in which case
 * the circuit is left unchanged and `root` is not written - the
 * caller must check the return value before consuming `root`).
 */
int indexed_merkle_gf8_nonmember_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    voleith_merkle_hash_t hash, gf8_wire_id root[16]);

/*
 * indexed_merkle_gf8_nonmember_circuit_secret_dir - prove non-membership with
 * private path direction bits.
 *
 * Identical to indexed_merkle_gf8_nonmember_circuit except path_dirs is an
 * array of gf8_wire_id (private witnesses, one per level), each carrying 0x00
 * or 0x01.  Use when the leaf index must remain hidden (e.g., Signal KVAC where
 * the index reveals which member holds the credential).
 *
 * Additional cost vs. public-dir variant: 16 mul gates × depth.
 *
 * Parameters: same as indexed_merkle_gf8_nonmember_circuit except:
 *   path_dirs - depth gf8_wire_id, each 0x00 or 0x01 (private witness wires)
 *
 * Returns 0 on success; -1 on the same LEAF_DATA_MAX_BYTES bound
 * violation as indexed_merkle_gf8_nonmember_circuit.
 */
int indexed_merkle_gf8_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_hash_t hash, gf8_wire_id root[16]);

#endif /* VOLEITH_INDEXED_MERKLE_GF8_CIRCUIT_H */
