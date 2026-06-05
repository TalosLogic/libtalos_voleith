/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_vt_gf8_helpers.c - software helpers for hash-agnostic
 * indexed Merkle trees driven by voleith_node_hash_vt.
 *
 * See indexed_merkle_vt_gf8_helpers.h for the public contract and
 * docs/RSV1_IMPLEMENTATION_PLAN.md T5b for the use case driving this
 * module.
 */

#include "indexed_merkle_vt_gf8_helpers.h"
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
 * Compare two little-endian multi-byte unsigned integers (byte 0 = LSB).
 * Returns -1, 0, or +1 with the usual memcmp semantics.  Matches the
 * byte ordering enforced by indexed_merkle_gf8_assert_lt.
 */
static int
lsb_uint_cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    for (size_t i = n; i > 0; i--) {
        uint8_t av = a[i - 1];
        uint8_t bv = b[i - 1];
        if (av < bv)
            return -1;
        if (av > bv)
            return 1;
    }
    return 0;
}

/*
 * Hash one record's leaf payload (value || next_value || next_index)
 * into a node-bytes-wide leaf node.  Allocates a scratch buffer of
 * leaf_data_bytes (the maximum is small enough that calloc is fine here -
 * record builds are not on the proof hot path).
 */
static int
hash_record(const voleith_node_hash_vt *vt, const voleith_imt_record_t *record,
            size_t value_bytes, size_t index_bytes, uint8_t *out)
{
    size_t leaf_data_bytes = 2u * value_bytes + index_bytes;
    uint8_t *buf = calloc(leaf_data_bytes, 1);
    if (buf == NULL)
        return -1;

    size_t off = 0;
    memcpy(buf + off, record->value, value_bytes);
    off += value_bytes;
    memcpy(buf + off, record->next_value, value_bytes);
    off += value_bytes;
    memcpy(buf + off, record->next_index, index_bytes);

    int rc = vt->leaf_hash(buf, leaf_data_bytes, out);
    free(buf);
    return rc;
}

/*
 * Hash all records into a contiguous (n_records * vt->node_bytes) buffer
 * suitable for feeding to voleith_merkle_vt_build / _compute_path.
 * Caller owns and frees the returned buffer; NULL on failure.
 */
static uint8_t *
hash_all_records(const voleith_node_hash_vt *vt,
                 const voleith_imt_record_t *records, size_t n_records,
                 size_t value_bytes, size_t index_bytes)
{
    size_t W = vt->node_bytes;
    uint8_t *leaf_nodes = calloc(n_records, W);
    if (leaf_nodes == NULL)
        return NULL;

    for (size_t i = 0; i < n_records; i++) {
        if (hash_record(vt, &records[i], value_bytes, index_bytes,
                        leaf_nodes + i * W) != 0) {
            free(leaf_nodes);
            return NULL;
        }
    }
    return leaf_nodes;
}

static int
validate_common(const voleith_node_hash_vt *vt,
                const voleith_imt_record_t *records, size_t n_records,
                size_t value_bytes, size_t index_bytes)
{
    if (vt == NULL || records == NULL)
        return -1;
    if (vt->node_bytes == 0 || vt->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    if (vt->leaf_hash == NULL || vt->inode_hash == NULL)
        return -1;
    if (!is_power_of_two(n_records))
        return -1;
    if (value_bytes == 0 || index_bytes == 0)
        return -1;
    for (size_t i = 0; i < n_records; i++) {
        if (records[i].value == NULL || records[i].next_value == NULL ||
            records[i].next_index == NULL)
            return -1;
    }
    if (voleith_imt_vt_validate_records(records, n_records, value_bytes) != 0)
        return -1;
    return 0;
}

int
voleith_imt_vt_validate_records(const voleith_imt_record_t *records,
                                size_t n_records, size_t value_bytes)
{
    if (records == NULL)
        return -1;
    if (n_records == 0 || value_bytes == 0)
        return -1;

    for (size_t i = 0; i < n_records; i++) {
        if (records[i].value == NULL || records[i].next_value == NULL)
            return -1;

        /* Invariant 2: well-formed interval (value <= next_value). */
        if (lsb_uint_cmp(records[i].value, records[i].next_value, value_bytes) >
            0)
            return -1;

        if (i + 1 < n_records) {
            if (records[i + 1].value == NULL)
                return -1;

            /* Invariant 1: sort order (value[i] <= value[i+1]). */
            if (lsb_uint_cmp(records[i].value, records[i + 1].value,
                             value_bytes) > 0)
                return -1;

            /*
             * Invariant 3: non-overlap.  Only applies to non-degenerate
             * records (value[i] < next_value[i]); degenerate sentinels
             * (value == next_value) have empty intervals and cannot
             * drive an assert_lt attack.
             */
            if (lsb_uint_cmp(records[i].value, records[i].next_value,
                             value_bytes) < 0) {
                if (lsb_uint_cmp(records[i].next_value, records[i + 1].value,
                                 value_bytes) > 0)
                    return -1;
            }
        }
    }
    return 0;
}

int
voleith_imt_vt_build(const voleith_node_hash_vt *vt,
                     const voleith_imt_record_t *records, size_t n_records,
                     size_t value_bytes, size_t index_bytes, uint8_t *root_out)
{
    if (root_out == NULL)
        return -1;
    if (validate_common(vt, records, n_records, value_bytes, index_bytes) != 0)
        return -1;

    uint8_t *leaf_nodes =
        hash_all_records(vt, records, n_records, value_bytes, index_bytes);
    if (leaf_nodes == NULL)
        return -1;

    int rc = voleith_merkle_vt_build(vt, leaf_nodes, n_records, root_out);
    free(leaf_nodes);
    return rc;
}

int
voleith_imt_vt_lookup_nonmember(const voleith_node_hash_vt *vt,
                                const voleith_imt_record_t *records,
                                size_t n_records, size_t value_bytes,
                                size_t index_bytes, const uint8_t *target,
                                size_t *adj_leaf_index_out, uint8_t *path_out)
{
    if (target == NULL || adj_leaf_index_out == NULL)
        return -1;
    if (validate_common(vt, records, n_records, value_bytes, index_bytes) != 0)
        return -1;
    if (n_records > 1 && path_out == NULL)
        return -1;

    /*
     * Membership check first: if target equals any record's value the
     * caller cannot prove non-membership for it, regardless of which
     * (if any) record's interval covers it.
     */
    for (size_t i = 0; i < n_records; i++) {
        if (lsb_uint_cmp(records[i].value, target, value_bytes) == 0)
            return -1;
    }

    /*
     * Locate the straddling record: value < target < next_value.  Sort
     * order is the caller's contract, so a single forward scan suffices
     * and there is at most one match in a well-formed tree.
     */
    size_t adj = n_records; /* sentinel: "not found" */
    for (size_t i = 0; i < n_records; i++) {
        if (lsb_uint_cmp(records[i].value, target, value_bytes) < 0 &&
            lsb_uint_cmp(target, records[i].next_value, value_bytes) < 0) {
            adj = i;
            break;
        }
    }
    if (adj == n_records)
        return -1;

    uint8_t *leaf_nodes =
        hash_all_records(vt, records, n_records, value_bytes, index_bytes);
    if (leaf_nodes == NULL)
        return -1;

    int rc = voleith_merkle_vt_compute_path(vt, leaf_nodes, n_records, adj,
                                            path_out);
    free(leaf_nodes);
    if (rc != 0)
        return -1;

    *adj_leaf_index_out = adj;
    return 0;
}
