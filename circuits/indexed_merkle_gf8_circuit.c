/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * indexed_merkle_gf8_circuit.c - Indexed Merkle non-membership proof as GF(2⁸) circuit
 *
 * See indexed_merkle_gf8_circuit.h for protocol and VOLE slot cost documentation.
 */

#include "indexed_merkle_gf8_circuit.h"
#include "merkle_gf8_circuit.h"
#include "circuit.h" /* for VOLEITH_STACK_BUF_MAX */
#include <stddef.h>

/*
 * Maximum leaf data byte-wire count to allocate on the stack.
 * leaf_data_bytes = 2*target_bytes + index_bytes; each gf8_wire_id is 4 bytes.
 */
#define LEAF_DATA_MAX_BYTES (VOLEITH_STACK_BUF_MAX / sizeof(gf8_wire_id))

/* ================================================================
 * Comparison circuit - assert a < b (unsigned, n_bytes-wide integers)
 *
 * Byte 0 is the LSB byte; byte n_bytes-1 is the MSB byte.
 * Processes bytes MSB-first, then bits within each byte MSB-first.
 * Uses 3 GF(2⁸) mul gates per bit, which acts as AND on {0x00, 0x01} values.
 * Adds one assert_zero constraint.
 *
 * Non-static: shared with indexed_merkle_grostl_gf8_circuit.c (the
 * comparison is over the value field, independent of Merkle node size).
 * ================================================================ */

void
indexed_merkle_gf8_assert_lt(voleith_gf8_circuit_t *c, const gf8_wire_id *a,
                             const gf8_wire_id *b, size_t n_bytes)
{
    /* lt      - running "a < b" result; starts false (0x00) */
    /* eq_mask - all bits seen so far are equal; starts true (0x01) */
    gf8_wire_id lt = voleith_gf8_add_const(c, 0x00);
    gf8_wire_id eq_mask = voleith_gf8_add_const(c, 0x01);

    /* Process bytes from MSB (n_bytes-1) down to LSB (0). */
    for (size_t byte_idx = n_bytes; byte_idx-- > 0;) {
        /* Process bits within this byte from MSB (bit 7) down to LSB (bit 0). */
        for (int bit = 7; bit >= 0; bit--) {
            /*
             * Extract bit `bit` from byte wire a[byte_idx] and b[byte_idx].
             * Linear map: row 0 of M has only bit `bit` set → output bit 0
             * gets input bit `bit`; all other output bits are 0.
             * Result is 0x00 or 0x01.
             */
            uint8_t M[8] = {0};
            M[0] = (uint8_t)(1u << bit);
            gf8_wire_id a_bit = voleith_gf8_add_linear_map(c, a[byte_idx], M);
            gf8_wire_id b_bit = voleith_gf8_add_linear_map(c, b[byte_idx], M);

            /* hi_i = NOT(a_bit) MUL b_bit: true iff a_bit=0, b_bit=1 */
            gf8_wire_id not_a = voleith_gf8_add_xor_const(c, a_bit, 0x01);
            gf8_wire_id hi_i = voleith_gf8_add_mul(c, not_a, b_bit);

            /* update_lt = eq_mask MUL hi_i: only contributes when higher bits matched */
            gf8_wire_id update_lt = voleith_gf8_add_mul(c, eq_mask, hi_i);

            /* lt ^= update_lt: once set, stays set */
            lt = voleith_gf8_add_xor(c, lt, update_lt);

            /* eq_mask = eq_mask MUL NOT(a_bit XOR b_bit): clear when bits diverge */
            gf8_wire_id diff = voleith_gf8_add_xor(c, a_bit, b_bit);
            gf8_wire_id eq_bit = voleith_gf8_add_xor_const(c, diff, 0x01);
            eq_mask = voleith_gf8_add_mul(c, eq_mask, eq_bit);
        }
    }

    /* Assert lt == 0x01: assert_zero(lt XOR 0x01) fails the proof if a >= b. */
    gf8_wire_id not_lt = voleith_gf8_add_xor_const(c, lt, 0x01);
    voleith_gf8_assert_zero(c, not_lt);
}

/* ================================================================
 * Public API
 * ================================================================ */

int
indexed_merkle_gf8_nonmember_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const uint8_t *path_dirs, size_t depth,
    voleith_merkle_hash_t hash, gf8_wire_id root[16])
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
    gf8_wire_id leaf_hash[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_data, leaf_data_bytes, hash,
                                 leaf_hash);

    /* Step 2: verify the Merkle authentication path */
    merkle_gf8_path_circuit(c, leaf_hash, path_nodes, path_dirs, depth, hash,
                            root);

    /* Step 3: assert ordering constraints (violations fail the proof at verify time) */
    indexed_merkle_gf8_assert_lt(c, low_value, target,
                                 target_bytes); /* low_value < target  */
    indexed_merkle_gf8_assert_lt(c, target, low_next,
                                 target_bytes); /* target   < low_next */
    return 0;
}

int
indexed_merkle_gf8_nonmember_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *target, size_t target_bytes,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, size_t index_bytes,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_hash_t hash, gf8_wire_id root[16])
{
    /* Build leaf data wire array: low_value || low_next || next_index */
    size_t leaf_data_bytes = 2 * target_bytes + index_bytes;
    /* CIR-2: same stack-VLA bound check / signaling as the public-dir
     * variant above. */
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
    gf8_wire_id leaf_hash[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_data, leaf_data_bytes, hash,
                                 leaf_hash);

    /*
     * Step 2: verify the Merkle authentication path.  path_dirs are private
     * wires; their booleanity (dir in {0, 1}) is enforced inside
     * merkle_gf8_path_circuit_secret_dir, so it need not be repeated here.
     */
    merkle_gf8_path_circuit_secret_dir(c, leaf_hash, path_nodes, path_dirs,
                                       depth, hash, root);

    /* Step 3: assert ordering constraints */
    indexed_merkle_gf8_assert_lt(c, low_value, target, target_bytes);
    indexed_merkle_gf8_assert_lt(c, target, low_next, target_bytes);
    return 0;
}
