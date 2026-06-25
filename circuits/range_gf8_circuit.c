/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * range_gf8_circuit.c - bounded-range / interval assertion as a GF(2^8)
 * element circuit.
 *
 * See range_gf8_circuit.h for the contract and cost.  The strict
 * less-than core mirrors indexed_merkle_gf8_assert_lt (same little-endian
 * convention, same 3-mul-gates-per-bit cost), but is reproduced here as a
 * helper that RETURNS the comparison-result wire instead of asserting, so
 * assert_in_range_gf8 can compose two bounds without touching the frozen
 * indexed-Merkle path.
 */

#include "range_gf8_circuit.h"
#include <stdint.h>

/*
 * Return a wire holding 0x01 if a < b, else 0x00, for two n_bytes-wide
 * unsigned little-endian byte-vector wire arrays (byte 0 = LSB).
 *
 * Processes bytes MSB-first and bits MSB-first, tracking a running "less
 * than" result and an "all higher bits equal so far" mask.  Costs 3
 * GF(2^8) mul gates per bit (the muls act as AND on {0x00, 0x01}); adds
 * no witness slots and no constraints (the caller asserts on the result).
 */
static gf8_wire_id
compute_lt(voleith_gf8_circuit_t *c, const gf8_wire_id *a, const gf8_wire_id *b,
           size_t n_bytes)
{
    /* lt      - running "a < b" result; starts false (0x00). */
    /* eq_mask - all bits seen so far are equal; starts true (0x01). */
    gf8_wire_id lt = voleith_gf8_add_const(c, 0x00);
    gf8_wire_id eq_mask = voleith_gf8_add_const(c, 0x01);

    /* Process bytes from MSB (n_bytes-1) down to LSB (0). */
    for (size_t byte_idx = n_bytes; byte_idx-- > 0;) {
        /* Bits within this byte from MSB (bit 7) down to LSB (bit 0). */
        for (int bit = 7; bit >= 0; bit--) {
            /*
             * Extract bit `bit` from a[byte_idx] / b[byte_idx] into bit 0.
             * Linear map row 0 has only bit `bit` set; result is 0x00/0x01.
             */
            uint8_t M[8] = {0};
            M[0] = (uint8_t)(1u << bit);
            gf8_wire_id a_bit = voleith_gf8_add_linear_map(c, a[byte_idx], M);
            gf8_wire_id b_bit = voleith_gf8_add_linear_map(c, b[byte_idx], M);

            /* hi_i = NOT(a_bit) MUL b_bit: true iff a_bit=0, b_bit=1. */
            gf8_wire_id not_a = voleith_gf8_add_xor_const(c, a_bit, 0x01);
            gf8_wire_id hi_i = voleith_gf8_add_mul(c, not_a, b_bit);

            /* update_lt = eq_mask MUL hi_i: only when higher bits matched. */
            gf8_wire_id update_lt = voleith_gf8_add_mul(c, eq_mask, hi_i);

            /* lt ^= update_lt: once set, stays set. */
            lt = voleith_gf8_add_xor(c, lt, update_lt);

            /* eq_mask MUL NOT(a_bit XOR b_bit): clear when bits diverge. */
            gf8_wire_id diff = voleith_gf8_add_xor(c, a_bit, b_bit);
            gf8_wire_id eq_bit = voleith_gf8_add_xor_const(c, diff, 0x01);
            eq_mask = voleith_gf8_add_mul(c, eq_mask, eq_bit);
        }
    }

    return lt;
}

void
assert_in_range_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *value,
                    const gf8_wire_id *low, const gf8_wire_id *high,
                    size_t n_bytes)
{
    /* value >= low  <=>  NOT(value < low):  assert (value < low) == 0. */
    gf8_wire_id below = compute_lt(c, value, low, n_bytes);
    voleith_gf8_assert_zero(c, below);

    /* value <= high <=>  NOT(high < value): assert (high < value) == 0. */
    gf8_wire_id above = compute_lt(c, high, value, n_bytes);
    voleith_gf8_assert_zero(c, above);
}
