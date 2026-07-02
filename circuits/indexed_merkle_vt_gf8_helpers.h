/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_vt_gf8_helpers.h - software helpers for hash-agnostic
 * indexed Merkle trees driven by voleith_node_hash_vt.
 *
 * These run entirely out of circuit: they hash each (value, next_value,
 * next_index) record into a leaf node via vt->leaf_hash and then drive
 * the same level-by-level inode walk as voleith_merkle_vt_build (see
 * circuits/merkle_vt_gf8_helpers.h).
 *
 * The IMT layout matches the circuit-side convention enforced by
 * circuits/indexed_merkle_vt_gf8_circuit.{h,c}: each leaf is the hash
 * of the concatenation low_value || low_next || next_index, and the
 * multi-byte fields are encoded byte 0 = LSB through byte n-1 = MSB
 * (the same little-endian convention used by indexed_merkle_gf8_assert_lt).
 *
 * Records are sort-ordered by `value` ascending; the linked-list
 * `next_index` field is consistent with sort order (records[i].next_index
 * points to the array slot holding records[i].next_value).  The library
 * neither enforces sort order nor inspects `next_index` - callers are
 * responsible for keeping the array well-formed.  This matches T8's
 * revocation-branch use case where the builder maintains the sort order
 * and just hands a snapshot here.
 *
 * Caller-visible failures (return -1) are limited to argument
 * validation (NULL, n_records not a power of two, vt mis-sized) and
 * propagated vt callback errors.  Lookups also return -1 when `target`
 * is found among the records' values (member, not non-member) or when
 * no record straddles `target`.
 *
 * See the RS-V1 implementation plan T5b for the use case driving
 * this module.
 */

#ifndef VOLEITH_INDEXED_MERKLE_VT_GF8_HELPERS_H
#define VOLEITH_INDEXED_MERKLE_VT_GF8_HELPERS_H

#include "node_hash_vt.h"

#include <stddef.h>
#include <stdint.h>

/*
 * A single indexed-Merkle leaf record.  Field byte widths are passed
 * to the helper functions as `value_bytes` / `index_bytes` arguments
 * since they are tree-wide constants (not per-record).
 *
 *   value      - the leaf's own value (value_bytes, byte 0 = LSB)
 *   next_value - the value of the record next in sort order
 *                (value_bytes, byte 0 = LSB)
 *   next_index - the array index of the record next in sort order,
 *                included verbatim in the leaf hash (index_bytes)
 *
 * Pointers are borrowed: the helper functions read but never copy the
 * three buffers, and never free them.
 */
typedef struct {
    const uint8_t *value;
    const uint8_t *next_value;
    const uint8_t *next_index;
} voleith_imt_record_t;

/*
 * voleith_imt_vt_build - compute the IMT root from a sort-ordered
 * array of records.
 *
 * Hashes each record's leaf payload (value || next_value || next_index)
 * with vt->leaf_hash into a leaf node, then drives the same
 * level-by-level walk as voleith_merkle_vt_build.
 *
 * vt          - node-hash vt providing leaf_hash, inode_hash, node_bytes.
 * records     - n_records entries.
 * n_records   - MUST be a non-zero power of two; otherwise -1.
 * value_bytes - byte width of value / next_value.  MUST be > 0.
 * index_bytes - byte width of next_index.  MUST be > 0.
 * root_out    - vt->node_bytes bytes, written iff the call returns 0.
 *
 * Returns 0 on success, -1 on NULL argument, malformed n_records,
 * zero-width fields, propagated vt callback failure, or allocation
 * failure.  On failure root_out is left untouched.
 */
int voleith_imt_vt_build(const voleith_node_hash_vt *vt,
                         const voleith_imt_record_t *records, size_t n_records,
                         size_t value_bytes, size_t index_bytes,
                         uint8_t *root_out);

/*
 * voleith_imt_vt_lookup_nonmember - locate the adjacent leaf that
 * straddles `target` and emit its sibling path.
 *
 * Iterates the records: if any record's `value` equals `target`, the
 * lookup fails (target is a member, not a non-member, so the caller
 * cannot prove non-membership for it).  Otherwise, finds the record
 * whose [value, next_value) interval contains target and emits its
 * leaf index plus the sibling path produced by
 * voleith_merkle_vt_compute_path.
 *
 * Comparison is over the value field, little-endian (byte 0 = LSB),
 * matching the circuit-side indexed_merkle_gf8_assert_lt convention.
 *
 * vt                 - node-hash vt providing leaf_hash, inode_hash.
 * records            - n_records entries (sort-ordered).
 * n_records          - MUST be a non-zero power of two.
 * value_bytes        - byte width of value / next_value / target.
 * index_bytes        - byte width of next_index.
 * target             - value_bytes bytes for the candidate non-member.
 * adj_leaf_index_out - index into records[] of the straddling record;
 *                      written iff the call returns 0.  Callers derive
 *                      path_dirs as bit k of this index for level k.
 * path_out           - log2(n_records) * vt->node_bytes bytes of
 *                      sibling nodes (leaf-level first); written iff
 *                      the call returns 0.  When n_records == 1 the
 *                      path is empty; path_out may be NULL.
 *
 * Returns 0 on success, -1 on NULL argument (other than path_out when
 * n_records == 1), malformed n_records, zero-width fields, target
 * matches an existing record's value (member), no record straddles
 * target, propagated vt callback failure, or allocation failure.
 * On failure both adj_leaf_index_out and path_out are left untouched.
 */
int voleith_imt_vt_lookup_nonmember(const voleith_node_hash_vt *vt,
                                    const voleith_imt_record_t *records,
                                    size_t n_records, size_t value_bytes,
                                    size_t index_bytes, const uint8_t *target,
                                    size_t *adj_leaf_index_out,
                                    uint8_t *path_out);

/*
 * voleith_imt_vt_validate_records - reject malformed record arrays
 * before they can drive a build or lookup.
 *
 * The non-membership circuit asserts low_value < target < low_next on
 * a single record whose hash sits in the IMT.  Soundness against an
 * adversarial prover (one who picks any record's tuple as their
 * witness, not just the one a friendly lookup would return) reduces
 * to three invariants on the record array:
 *
 *   1. Sort order.  records[i].value <= records[i+1].value, treated
 *      lsb-first per the indexed_merkle_gf8_assert_lt convention.
 *      Equality is permitted so trailing "max" sentinels with
 *      value == next_value == MAX can be repeated to pad n_records
 *      to a power of two.
 *
 *   2. Well-formed intervals.  records[i].value <= records[i].next_value.
 *      Rules out wrap-around intervals (next_value < value) which
 *      would otherwise let an adversarial prover assert_lt on a
 *      target outside the IMT's value range.
 *
 *   3. No overlap.  For every non-degenerate record (records[i].value
 *      < records[i].next_value), if i < n_records - 1 then
 *      records[i].next_value <= records[i+1].value.  This is the
 *      soundness-critical check: an overlap (next_value[i] >
 *      value[i+1]) lets an adversary use records[i] to assert_lt on
 *      target = records[i+1].value, forging a non-membership proof
 *      for an actual member.  Degenerate records (value ==
 *      next_value) have empty intervals; assert_lt(value, target,
 *      value) can never be satisfied (strict comparison), so they
 *      cannot drive an attack and are exempt from this check.
 *
 * Completeness (every legitimate non-member has some adjacent record
 * whose interval covers it) is NOT checked: it requires the
 * application's chosen sentinel pattern at the extremes of the value
 * range, which is policy, not soundness.  An IMT that passes
 * validation may still fail to admit non-membership proofs for some
 * targets (lookup_nonmember will return -1 for those targets); it
 * will not, however, produce a verifying-but-false non-membership
 * proof for a member.
 *
 * Cost: one O(n_records) pass with byte-wise lsb-first comparisons.
 * Not on the proof hot path; called once per build / lookup.
 *
 * Returns 0 if every invariant holds, -1 otherwise (or on NULL
 * argument / zero-width fields).
 */
int voleith_imt_vt_validate_records(const voleith_imt_record_t *records,
                                    size_t n_records, size_t value_bytes);

#endif /* VOLEITH_INDEXED_MERKLE_VT_GF8_HELPERS_H */
