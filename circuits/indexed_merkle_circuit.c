/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_circuit.c - Indexed Merkle non-membership proof as Boolean circuit
 *
 * See indexed_merkle_circuit.h for protocol and AND gate cost documentation.
 */

#include "indexed_merkle_circuit.h"
#include "merkle_circuit.h"
#include <stddef.h>

/*
 * Maximum VLA stack allocation for the leaf data wire buffer.
 * leaf_data_bits = 2*target_bits + index_bits; each wire_id is 4 bytes.
 * VOLEITH_STACK_BUF_MAX bytes / 4 = wire IDs → e.g. 256-bit target + 64-bit index uses 576.
 * Callers with larger domain sizes must not use this function.
 */
#define LEAF_DATA_MAX_BITS (VOLEITH_STACK_BUF_MAX / sizeof(wire_id))

/* ================================================================
 * Comparison circuit - assert a < b (unsigned, n_bits-wide integers)
 *
 * Processes bits from MSB (n_bits-1) down to LSB (0).
 * Uses 3 AND gates per bit.  Adds one assert_zero constraint.
 * ================================================================ */

static void
assert_lt(voleith_circuit_t *c, const wire_id *a, const wire_id *b,
          size_t n_bits)
{
    /* lt      - running "a < b" result; starts false (0) */
    /* eq_mask - all bits seen so far are equal; starts true (1) */
    wire_id lt = voleith_circuit_add_const(c, 0);
    wire_id eq_mask = voleith_circuit_add_const(c, 1);

    /* Process MSB first so earlier bits have priority. */
    for (size_t i = n_bits; i-- > 0;) {
        /* hi_i = NOT(a[i]) AND b[i]: true iff a[i]=0, b[i]=1 at this bit */
        wire_id not_a_i = voleith_circuit_add_not(c, a[i]);
        wire_id hi_i = voleith_circuit_add_and(c, not_a_i, b[i]);

        /* update_lt = eq_mask AND hi_i: only contribute if higher bits matched */
        wire_id update_lt = voleith_circuit_add_and(c, eq_mask, hi_i);

        /* lt ^= update_lt: once set, XOR with 0 keeps it; masked to 0 otherwise */
        lt = voleith_circuit_add_xor(c, lt, update_lt);

        /* eq_mask &= NOT(a[i] XOR b[i]): clear mask when bits diverge */
        wire_id diff_i = voleith_circuit_add_xor(c, a[i], b[i]);
        wire_id eq_i = voleith_circuit_add_not(c, diff_i);
        eq_mask = voleith_circuit_add_and(c, eq_mask, eq_i);
    }

    /* Assert lt == 1: assert_zero(NOT(lt)) fails the proof if a >= b. */
    wire_id not_lt = voleith_circuit_add_not(c, lt);
    voleith_circuit_assert_zero(c, not_lt);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
indexed_merkle_nonmember_circuit(voleith_circuit_t *c, const wire_id *target,
                                 size_t target_bits, const wire_id *low_value,
                                 const wire_id *low_next,
                                 const wire_id *next_index, size_t index_bits,
                                 const wire_id *path_nodes,
                                 const wire_id *path_dirs, size_t depth,
                                 voleith_merkle_hash_t hash, wire_id root[128])
{
    /* Build leaf data wire array: low_value || low_next || next_index */
    size_t leaf_data_bits = 2 * target_bits + index_bits;
    if (leaf_data_bits > LEAF_DATA_MAX_BITS)
        return; /* guard against stack overflow */

    wire_id
        leaf_data[leaf_data_bits]; /* VLA; size bounded by LEAF_DATA_MAX_BITS */

    size_t off = 0;
    for (size_t i = 0; i < target_bits; i++)
        leaf_data[off++] = low_value[i];
    for (size_t i = 0; i < target_bits; i++)
        leaf_data[off++] = low_next[i];
    for (size_t i = 0; i < index_bits; i++)
        leaf_data[off++] = next_index[i];

    /* Step 1: hash the adjacent leaf record */
    wire_id leaf_hash[128];
    merkle_leaf_hash_circuit(c, leaf_data, leaf_data_bits, hash, leaf_hash);

    /* Step 2: verify the Merkle authentication path */
    merkle_path_circuit(c, leaf_hash, path_nodes, path_dirs, depth, hash, root);

    /* Step 3: assert ordering constraints (internal; violations fail the proof) */
    assert_lt(c, low_value, target, target_bits); /* low_value < target   */
    assert_lt(c, target, low_next, target_bits);  /* target   < low_next  */
}
