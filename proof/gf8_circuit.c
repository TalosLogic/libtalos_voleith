/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_circuit.c - GF(2⁸) element-level circuit definition, builder, and evaluation
 */

#include "gf8_circuit.h"
#include "../core/field.h"
#include <stdlib.h>
#include <string.h>

/* Initial capacity for dynamic arrays */
#define INITIAL_WIRE_CAP 64
#define INITIAL_CONSTRAINT_CAP 16

struct voleith_gf8_circuit {
    gf8_wire_entry_t *wires;
    size_t n_wires;
    size_t cap_wires;

    gf8_constraint_entry_t *constraints;
    size_t n_constraints;
    size_t cap_constraints;

    /* Less-than constraints (Option 3: separate table, so the fixed-degree
     * constraint path above stays byte-identical). lt_bits is the shared pool
     * of bit-wire ids each lt_entry indexes into (2*width ids per entry). */
    gf8_lt_entry_t *lt_constraints;
    size_t n_lt;
    size_t cap_lt;
    gf8_wire_id *lt_bits;
    size_t n_lt_bits;
    size_t cap_lt_bits;
    unsigned int max_lt_degree; /* max (width+1) over LT entries; 0 if none */

    /* Syndrome constraints (Option 3: separate table, fixed-degree path stays
     * byte-identical).  syndrome_bits is the shared pool of bit-wire ids each
     * entry indexes into (t*idx_bits index bits then p s bits per entry). */
    gf8_syndrome_entry_t *syndrome_constraints;
    size_t n_syndrome;
    size_t cap_syndrome;
    gf8_wire_id *syndrome_bits;
    size_t n_syndrome_bits;
    size_t cap_syndrome_bits;
    unsigned int max_syndrome_degree; /* max idx_bits over entries; 0 if none */

    size_t n_witness;
    size_t n_instance;
    size_t n_const;          /* CONST input-wire count */
    size_t n_mul;            /* add_mul gate count */
    size_t n_assert_product; /* assert_product constraint count */
    int alloc_ok;            /* 0 if any append failed */

    /*
     * Incremental resource ceilings (0 == unlimited; the default).  When set
     * via voleith_gf8_circuit_set_limits(), append_wire refuses to grow the
     * circuit past wire_cap total wires or gate_cap gate (non-input) wires,
     * clearing alloc_ok the moment a ceiling would be crossed.  This bounds a
     * bulk emitter (a Tier 2a registry body) as it runs instead of only after
     * the whole body has been materialized.
     */
    size_t wire_cap;
    size_t gate_cap;
};

/* ================================================================
 * Helpers
 * ================================================================ */

/* Append a wire entry; returns the new gf8_wire_id or GF8_WIRE_ID_INVALID */
static gf8_wire_id
append_wire(voleith_gf8_circuit_t *c, gf8_wire_entry_t entry)
{
    /*
     * Incremental resource caps (0 == unlimited).  Checked at the sole
     * wire-append choke point so a bulk emitter is stopped the moment a
     * ceiling is crossed, never after the whole body has materialized.  A
     * refused append clears alloc_ok, exactly like an allocation failure, so
     * every existing voleith_gf8_circuit_ok() caller already catches it.
     */
    if (c->wire_cap != 0 && c->n_wires >= c->wire_cap) {
        c->alloc_ok = 0;
        return GF8_WIRE_ID_INVALID;
    }
    if (c->gate_cap != 0 && entry.kind != GF8_WIRE_WITNESS &&
        entry.kind != GF8_WIRE_INSTANCE && entry.kind != GF8_WIRE_CONST &&
        c->n_wires - c->n_witness - c->n_instance - c->n_const >= c->gate_cap) {
        c->alloc_ok = 0;
        return GF8_WIRE_ID_INVALID;
    }

    if (c->n_wires == c->cap_wires) {
        size_t new_cap = c->cap_wires * 2;
        gf8_wire_entry_t *p =
            realloc(c->wires, new_cap * sizeof(gf8_wire_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return GF8_WIRE_ID_INVALID;
        }
        c->wires = p;
        c->cap_wires = new_cap;
    }
    gf8_wire_id id = (gf8_wire_id)c->n_wires;
    c->wires[c->n_wires++] = entry;
    return id;
}

/* Append a constraint; marks alloc_ok=0 on failure */
static void
append_constraint(voleith_gf8_circuit_t *c, gf8_constraint_entry_t entry)
{
    if (c->n_constraints == c->cap_constraints) {
        size_t new_cap = c->cap_constraints * 2;
        gf8_constraint_entry_t *p =
            realloc(c->constraints, new_cap * sizeof(gf8_constraint_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return;
        }
        c->constraints = p;
        c->cap_constraints = new_cap;
    }
    c->constraints[c->n_constraints++] = entry;
}

/*
 * Apply an 8×8 GF(2) matrix to a GF(2⁸) element.
 * matrix[i] is row i; output bit i = popcount(matrix[i] & a) mod 2.
 */
static uint8_t
apply_linear_map(const uint8_t M[8], uint8_t a)
{
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t masked = M[i] & a;
        /* Compute parity of masked byte */
        masked ^= masked >> 4;
        masked ^= masked >> 2;
        masked ^= masked >> 1;
        result |= (uint8_t)((masked & 1u) << i);
    }
    return result;
}

/*
 * Frobenius squaring matrix for GF(2⁸) with polynomial x^8+x^4+x^3+x+1.
 *
 * a² is GF(2)-linear: if a = Σ aᵢ·αⁱ, then a² = Σ aᵢ·α^(2i).
 * We precompute the 8 columns of the squaring matrix (α^0, α^2, α^4, ...,
 * α^14 each reduced mod P_8), then transpose to get rows.
 *
 * α² = 0x04
 * α⁴ = 0x10
 * α⁶ = 0x40
 * α⁸  = α⁴+α³+α+1 = 0x1B  (from P_8: α⁸ = α⁴+α³+α+1)
 * α^10 = α²·α⁸ = 0x04·0x1B = gf8_mul(4,0x1B) = 0x6C (need to compute)
 * α^12 = α²·α^10 = ...
 * α^14 = α²·α^12 = ...
 *
 * Hardcoded values: row i of M_sq satisfies (M_sq · a)[i] = bit i of a².
 * Computed from: the column j of M_sq is the bit representation of α^(2j).
 */
static const uint8_t GF8_SQUARE_MATRIX[8] = {
    /* Row 0: which input bits contribute to output bit 0 of a²? */
    /* a² = a0·1 + a1·α² + a2·α⁴ + a3·α⁶ + a4·α⁸ + a5·α^10 + a6·α^12 + a7·α^14 */
    /* α^0  = 0x01, bit 0 of: 0x01=1, 0x04=0, 0x10=0, 0x40=0,
                              0x1B=1, ?, ?, ?                               */
    /* Pre-computed values (verified by direct computation below):
     * alpha^0  = 0x01
     * alpha^2  = 0x04
     * alpha^4  = 0x10
     * alpha^6  = 0x40
     * alpha^8  = 0x1B  (= alpha^4 + alpha^3 + alpha + 1)
     * alpha^10 = 0x6C  (= alpha^2 * 0x1B; carry-less: 0x04*0x1B = 0x4+0x8+0x10+0x40 = 0x6C? let me verify)
     *   0x04 * 0x1B: shift 0x1B left by 2 bits = 0x6C. No reduction needed since degree <= 7.
     * alpha^12 = alpha^2 * alpha^10 = 0x04 * 0x6C
     *   shift 0x6C left by 2 = 0x1B0 -> reduce: 0x1B0 XOR (0x11B << 0) = 0x1B0 XOR 0x11B = 0x0AB? No.
     *   Actually alpha^12 = alpha^4 * alpha^8 = 0x10 * 0x1B = shift 0x1B by 4 = 0x1B0
     *   0x1B0 = 0b110110000. Bits 8 set. Reduce: XOR 0x11B (= x^8+x^4+x^3+x+1) -> 0x1B0 XOR 0x11B = 0x0AB?
     *   0x1B0 = 0001 1011 0000
     *   0x11B = 0001 0001 1011
     *   XOR  = 0000 1010 1011 = 0xAB. Wait that's 9 bits? Let me redo:
     *   0x1B0 = 256+128+32+16 = 432. In binary: 1 1011 0000 (9 bits).
     *   0x11B = 283 = 1 0001 1011 (9 bits).
     *   XOR = 0 1010 1011 = 0xAB. Yes, alpha^12 = 0xAB.
     * alpha^14 = alpha^2 * alpha^12 = 0x04 * 0xAB:
     *   shift 0xAB left by 2: 0x2AC = 10 1010 1100.
     *   Bit 9 set: XOR 0x11B: 0x2AC XOR 0x11B = 0x197? Wait:
     *   0x2AC = 0010 1010 1100
     *   0x11B = 0001 0001 1011
     *   XOR   = 0011 1011 0111 = 0x3B7? That can't be right (>8 bits).
     *   Let me redo. 0xAB * 0x04 = shift left 2:
     *   0xAB = 1010 1011
     *   << 2  = 10 1010 1100 = 0x2AC (10 bits)
     *   Reduce bit 9: XOR (0x11B << 1) = 0x236
     *     0x2AC XOR 0x236 = 0x09A
     *   Reduce bit 8: 0x09A has bit 8? 0x09A = 154. Bit 8 = 0. Done.
     *   alpha^14 = 0x9A? Let me double-check with alpha^14 = alpha^8 * alpha^6:
     *   0x1B * 0x40: shift 0x1B left by 6 = 0x6C0.
     *   0x6C0 = 0110 1100 0000 (11 bits).
     *   Reduce bit 10: XOR (0x11B << 2) = 0x46C
     *     0x6C0 XOR 0x46C = 0x2AC
     *   Reduce bit 9: XOR (0x11B << 1) = 0x236
     *     0x2AC XOR 0x236 = 0x09A
     *   Reduce bit 8: bit 8 of 0x09A = 0. Done.
     *   alpha^14 = 0x9A. Confirmed.
     *
     * Summary:
     *   a0 -> col 0: alpha^0  = 0x01
     *   a1 -> col 1: alpha^2  = 0x04
     *   a2 -> col 2: alpha^4  = 0x10
     *   a3 -> col 3: alpha^6  = 0x40
     *   a4 -> col 4: alpha^8  = 0x1B
     *   a5 -> col 5: alpha^10 = 0x6C
     *   a6 -> col 6: alpha^12 = 0xAB
     *   a7 -> col 7: alpha^14 = 0x9A
     *
     * The matrix M_sq has column j = alpha^(2j) as a bit vector.
     * Row i of M_sq = the set of j such that bit i of alpha^(2j) is 1.
     *
     * Columns (bit vectors, LSB = row 0):
     *   col 0 (0x01): row 0
     *   col 1 (0x04): row 2
     *   col 2 (0x10): row 4
     *   col 3 (0x40): row 6
     *   col 4 (0x1B = 0001 1011): rows 0,1,3,4
     *   col 5 (0x6C = 0110 1100): rows 2,3,5,6
     *   col 6 (0xAB = 1010 1011): rows 0,1,3,5,7
     *   col 7 (0x9A = 1001 1010): rows 1,3,4,7
     *
     * Row i = sum (as byte) of 2^j for each j where bit i of col_j is 1:
     *   row 0: cols {0,4,6}     = 0x01+0x10+0x40     = bit0,bit4,bit6 -> 0b01010001 = 0x51
     *   row 1: cols {4,6,7}                           = bit4,bit6,bit7 -> 0b11010000 = 0xD0
     *   row 2: cols {1,5}                             = bit1,bit5      -> 0b00100010 = 0x22
     *   row 3: cols {4,5,6,7}                         = bit4,bit5,bit6,bit7 -> 0b11110000 = 0xF0?
     *          Wait. Col 4 has row 3: yes (0x1B bit3=1). Col 5 has row 3: 0x6C=0110 1100 bit3=1.
     *          Col 6 has row 3: 0xAB=1010 1011 bit3=1. Col 7 has row 3: 0x9A=1001 1010 bit3=1.
     *          row 3: bits {4,5,6,7} -> 0b11110000 = 0xF0
     *   row 4: cols {2,4,7}     col2: bit4=1(0x10=0001 0000 bit4=1), col4: 0x1B bit4=1, col7: 0x9A=1001 1010 bit4=1
     *          row 4: bits {2,4,7} -> 0b10010100 = 0x94
     *   row 5: cols {5,6}       col5: 0x6C=0110 1100 bit5=1, col6: 0xAB=1010 1011 bit5=1
     *          row 5: bits {5,6} -> 0b01100000 = 0x60
     *   row 6: cols {3,5}       col3: 0x40 bit6=1, col5: 0x6C bit6=1
     *          row 6: bits {3,6} -> 0b01001000 = 0x48? Wait bit 3 of col3: j=3, so bit position in row byte is 2^3=8?
     *          No, I'm confusing myself. Let me redo clearly.
     *
     *          Row i of M_sq is a byte where bit j is 1 iff bit i of alpha^(2j) is 1.
     *          row 6: bit j = 1 iff bit 6 of alpha^(2j) is 1.
     *            j=0: bit6 of 0x01 = 0
     *            j=1: bit6 of 0x04 = 0
     *            j=2: bit6 of 0x10 = 0
     *            j=3: bit6 of 0x40 = 1  -> j=3
     *            j=4: bit6 of 0x1B = 0
     *            j=5: bit6 of 0x6C = 1  -> j=5 (0x6C = 0110 1100, bit6=1)
     *            j=6: bit6 of 0xAB = 0  (0xAB = 1010 1011, bit6=0)
     *            j=7: bit6 of 0x9A = 0  (0x9A = 1001 1010, bit6=0)
     *          row 6 = (1<<3)|(1<<5) = 0x08|0x20 = 0x28
     *   row 7: bit j = 1 iff bit 7 of alpha^(2j) is 1.
     *            j=0: 0
     *            j=1: 0
     *            j=2: 0
     *            j=3: 0
     *            j=4: 0
     *            j=5: 0x6C=0110 1100, bit7=0
     *            j=6: 0xAB=1010 1011, bit7=1  -> j=6
     *            j=7: 0x9A=1001 1010, bit7=1  -> j=7
     *          row 7 = (1<<6)|(1<<7) = 0x40|0x80 = 0xC0
     *
     * Let me redo rows 0-5 more carefully:
     * row 0: bit j = 1 iff bit 0 of alpha^(2j) is 1.
     *   j=0: 0x01 bit0=1 -> j=0
     *   j=1: 0x04 bit0=0
     *   j=2: 0x10 bit0=0
     *   j=3: 0x40 bit0=0
     *   j=4: 0x1B=0001 1011 bit0=1 -> j=4
     *   j=5: 0x6C=0110 1100 bit0=0
     *   j=6: 0xAB=1010 1011 bit0=1 -> j=6
     *   j=7: 0x9A=1001 1010 bit0=0
     *   row 0 = (1<<0)|(1<<4)|(1<<6) = 0x01|0x10|0x40 = 0x51 ✓
     *
     * row 1: bit j = 1 iff bit 1 of alpha^(2j) is 1.
     *   j=0: 0x01 bit1=0
     *   j=1: 0x04 bit1=0
     *   j=2: 0x10 bit1=0
     *   j=3: 0x40 bit1=0
     *   j=4: 0x1B=0001 1011 bit1=1 -> j=4
     *   j=5: 0x6C=0110 1100 bit1=0
     *   j=6: 0xAB=1010 1011 bit1=1 -> j=6
     *   j=7: 0x9A=1001 1010 bit1=1 -> j=7
     *   row 1 = (1<<4)|(1<<6)|(1<<7) = 0x10|0x40|0x80 = 0xD0 ✓
     *
     * row 2: bit j = 1 iff bit 2 of alpha^(2j) is 1.
     *   j=0: 0
     *   j=1: 0x04 bit2=1 -> j=1
     *   j=2: 0
     *   j=3: 0
     *   j=4: 0x1B=0001 1011 bit2=0
     *   j=5: 0x6C=0110 1100 bit2=1 -> j=5
     *   j=6: 0xAB=1010 1011 bit2=0
     *   j=7: 0x9A=1001 1010 bit2=0
     *   row 2 = (1<<1)|(1<<5) = 0x02|0x20 = 0x22 ✓
     *
     * row 3: bit j = 1 iff bit 3 of alpha^(2j) is 1.
     *   j=0: 0
     *   j=1: 0
     *   j=2: 0
     *   j=3: 0
     *   j=4: 0x1B=0001 1011 bit3=1 -> j=4
     *   j=5: 0x6C=0110 1100 bit3=1 -> j=5
     *   j=6: 0xAB=1010 1011 bit3=1 -> j=6
     *   j=7: 0x9A=1001 1010 bit3=1 -> j=7
     *   row 3 = (1<<4)|(1<<5)|(1<<6)|(1<<7) = 0x10|0x20|0x40|0x80 = 0xF0 ✓
     *
     * row 4: bit j = 1 iff bit 4 of alpha^(2j) is 1.
     *   j=0: 0
     *   j=1: 0
     *   j=2: 0x10 bit4=1 -> j=2
     *   j=3: 0
     *   j=4: 0x1B=0001 1011 bit4=1 -> j=4
     *   j=5: 0x6C=0110 1100 bit4=0
     *   j=6: 0xAB=1010 1011 bit4=0
     *   j=7: 0x9A=1001 1010 bit4=1 -> j=7
     *   row 4 = (1<<2)|(1<<4)|(1<<7) = 0x04|0x10|0x80 = 0x94 ✓
     *
     * row 5: bit j = 1 iff bit 5 of alpha^(2j) is 1.
     *   j=0: 0
     *   j=1: 0
     *   j=2: 0
     *   j=3: 0
     *   j=4: 0x1B=0001 1011 bit5=0
     *   j=5: 0x6C=0110 1100 bit5=1 -> j=5
     *   j=6: 0xAB=1010 1011 bit5=1 -> j=6
     *   j=7: 0x9A=1001 1010 bit5=0
     *   row 5 = (1<<5)|(1<<6) = 0x20|0x40 = 0x60 ✓
     *
     * Final matrix rows: {0x51, 0xD0, 0x22, 0xF0, 0x94, 0x60, 0x28, 0xC0}
     */
    0x51, 0xD0, 0x22, 0xF0, 0x94, 0x60, 0x28, 0xC0};

/* ================================================================
 * Lifecycle
 * ================================================================ */

voleith_gf8_circuit_t *
voleith_gf8_circuit_new(void)
{
    voleith_gf8_circuit_t *c = calloc(1, sizeof(voleith_gf8_circuit_t));
    if (!c)
        return NULL;

    c->wires = calloc(INITIAL_WIRE_CAP, sizeof(gf8_wire_entry_t));
    if (!c->wires) {
        free(c);
        return NULL;
    }
    c->cap_wires = INITIAL_WIRE_CAP;

    c->constraints =
        calloc(INITIAL_CONSTRAINT_CAP, sizeof(gf8_constraint_entry_t));
    if (!c->constraints) {
        free(c->wires);
        free(c);
        return NULL;
    }
    c->cap_constraints = INITIAL_CONSTRAINT_CAP;
    c->alloc_ok = 1;

    return c;
}

void
voleith_gf8_circuit_free(voleith_gf8_circuit_t *c)
{
    if (!c)
        return;
    free(c->wires);
    free(c->constraints);
    free(c->lt_constraints);
    free(c->lt_bits);
    for (size_t i = 0; i < c->n_syndrome; i++)
        free((void *)c->syndrome_constraints[i].M);
    free(c->syndrome_constraints);
    free(c->syndrome_bits);
    free(c);
}

void
voleith_gf8_circuit_set_limits(voleith_gf8_circuit_t *c, size_t max_wires,
                               size_t max_gates)
{
    if (!c)
        return;
    c->wire_cap = max_wires;
    c->gate_cap = max_gates;
}

/* ================================================================
 * Builder API
 * ================================================================ */

gf8_wire_id
voleith_gf8_add_witness(voleith_gf8_circuit_t *c)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_WITNESS,
        .a = GF8_WIRE_ID_INVALID,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    gf8_wire_id id = append_wire(c, e);
    if (id != GF8_WIRE_ID_INVALID)
        c->n_witness++;
    return id;
}

gf8_wire_id
voleith_gf8_add_instance(voleith_gf8_circuit_t *c)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_INSTANCE,
        .a = GF8_WIRE_ID_INVALID,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    gf8_wire_id id = append_wire(c, e);
    if (id != GF8_WIRE_ID_INVALID)
        c->n_instance++;
    return id;
}

gf8_wire_id
voleith_gf8_add_const(voleith_gf8_circuit_t *c, uint8_t val)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_CONST,
        .a = GF8_WIRE_ID_INVALID,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = val,
        .matrix = {0},
    };
    gf8_wire_id id = append_wire(c, e);
    if (id != GF8_WIRE_ID_INVALID)
        c->n_const++;
    return id;
}

gf8_wire_id
voleith_gf8_add_xor(voleith_gf8_circuit_t *c, gf8_wire_id a, gf8_wire_id b)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_XOR,
        .a = a,
        .b = b,
        .const_val = 0,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf8_wire_id
voleith_gf8_add_xor_const(voleith_gf8_circuit_t *c, gf8_wire_id a, uint8_t k)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_XOR_CONST,
        .a = a,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = k,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf8_wire_id
voleith_gf8_add_linear_map(voleith_gf8_circuit_t *c, gf8_wire_id a,
                           const uint8_t M[8])
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_LINEAR_MAP,
        .a = a,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = 0,
    };
    memcpy(e.matrix, M, 8);
    return append_wire(c, e);
}

gf8_wire_id
voleith_gf8_add_square(voleith_gf8_circuit_t *c, gf8_wire_id a)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_SQUARE,
        .a = a,
        .b = GF8_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf8_wire_id
voleith_gf8_add_mul(voleith_gf8_circuit_t *c, gf8_wire_id a, gf8_wire_id b)
{
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_MUL,
        .a = a,
        .b = b,
        .const_val = 0,
        .matrix = {0},
    };
    gf8_wire_id id = append_wire(c, e);
    if (id != GF8_WIRE_ID_INVALID)
        c->n_mul++;
    return id;
}

gf8_wire_id
voleith_gf8_add_mux(voleith_gf8_circuit_t *c, gf8_wire_id a, gf8_wire_id b,
                    gf8_wire_id sel)
{
    /*
     * MUX(a, b, sel) = a XOR (sel · (b XOR a))
     *
     * Expansion:
     *   diff = b XOR a        (free XOR gate)
     *   prod = sel · diff     (one MUL gate - costs one VOLE slot)
     *   out  = a XOR prod     (free XOR gate)
     */
    gf8_wire_id diff = voleith_gf8_add_xor(c, b, a);
    if (diff == GF8_WIRE_ID_INVALID)
        return GF8_WIRE_ID_INVALID;

    gf8_wire_id prod = voleith_gf8_add_mul(c, sel, diff);
    if (prod == GF8_WIRE_ID_INVALID)
        return GF8_WIRE_ID_INVALID;

    return voleith_gf8_add_xor(c, a, prod);
}

gf8_wire_id
voleith_gf8_add_scale_instance(voleith_gf8_circuit_t *c, gf8_wire_id a,
                               gf8_wire_id b)
{
    /*
     * b must reference an already-declared INSTANCE wire.  Rejecting a
     * witness/gate operand here (and again in circuit_validate) is what keeps
     * the free path public-only: a secret operand would need a VOLE slot.
     */
    if (b >= c->n_wires || c->wires[b].kind != GF8_WIRE_INSTANCE) {
        c->alloc_ok = 0;
        return GF8_WIRE_ID_INVALID;
    }
    gf8_wire_entry_t e = {
        .kind = GF8_WIRE_SCALE_INSTANCE,
        .a = a,
        .b = b,
        .const_val = 0,
        .matrix = {0},
    };
    /* Not counted as a MUL: consumes no VOLE slot. */
    return append_wire(c, e);
}

gf8_wire_id
voleith_gf8_add_mux_instance(voleith_gf8_circuit_t *c, gf8_wire_id a,
                             gf8_wire_id b, gf8_wire_id sel)
{
    /*
     * MUX(a, b, sel) = a XOR (sel · (b XOR a)), with sel an instance wire so
     * the scale gate is free.
     *
     *   diff = b XOR a                    (free XOR gate)
     *   prod = scale_instance(diff, sel)  (free: sel is public)
     *   out  = a XOR prod                 (free XOR gate)
     */
    gf8_wire_id diff = voleith_gf8_add_xor(c, b, a);
    if (diff == GF8_WIRE_ID_INVALID)
        return GF8_WIRE_ID_INVALID;

    gf8_wire_id prod = voleith_gf8_add_scale_instance(c, diff, sel);
    if (prod == GF8_WIRE_ID_INVALID)
        return GF8_WIRE_ID_INVALID;

    return voleith_gf8_add_xor(c, a, prod);
}

void
voleith_gf8_mul_matrix(uint8_t out[8], uint8_t c)
{
    /*
     * Column j of the map x -> c·x is c·αʲ (αʲ = the element with only bit j
     * set).  Scatter each column bit into the row-major matrix that
     * apply_linear_map consumes: out[i] bit j = bit i of c·αʲ.
     */
    for (int i = 0; i < 8; i++)
        out[i] = 0;
    for (int j = 0; j < 8; j++) {
        uint8_t col = voleith_gf8_mul(c, (uint8_t)(1u << j));
        for (int i = 0; i < 8; i++) {
            if (col & (uint8_t)(1u << i))
                out[i] |= (uint8_t)(1u << j);
        }
    }
}

void
voleith_gf8_assert_zero(voleith_gf8_circuit_t *c, gf8_wire_id w)
{
    gf8_constraint_entry_t e = {
        .kind = GF8_CONSTRAINT_ZERO,
        .a = w,
        .b = GF8_WIRE_ID_INVALID,
        .c = GF8_WIRE_ID_INVALID,
    };
    append_constraint(c, e);
}

void
voleith_gf8_assert_equal(voleith_gf8_circuit_t *c, gf8_wire_id a, gf8_wire_id b)
{
    gf8_constraint_entry_t e = {
        .kind = GF8_CONSTRAINT_EQUAL,
        .a = a,
        .b = b,
        .c = GF8_WIRE_ID_INVALID,
    };
    append_constraint(c, e);
}

void
voleith_gf8_assert_product(voleith_gf8_circuit_t *c, gf8_wire_id a,
                           gf8_wire_id b, gf8_wire_id c_expected)
{
    gf8_constraint_entry_t e = {
        .kind = GF8_CONSTRAINT_PRODUCT,
        .a = a,
        .b = b,
        .c = c_expected,
    };
    append_constraint(c, e);
    if (c->alloc_ok)
        c->n_assert_product++;
}

void
voleith_gf8_assert_lt(voleith_gf8_circuit_t *c, const gf8_wire_id *a_bits,
                      const gf8_wire_id *b_bits, unsigned int width)
{
    if (!c || !a_bits || !b_bits || width == 0) {
        if (c)
            c->alloc_ok = 0;
        return;
    }

    /* Grow the bit pool by 2*width ids. */
    size_t need = c->n_lt_bits + (size_t)2 * width;
    if (need > c->cap_lt_bits) {
        size_t new_cap = c->cap_lt_bits ? c->cap_lt_bits : 32;
        while (new_cap < need)
            new_cap *= 2;
        gf8_wire_id *p = realloc(c->lt_bits, new_cap * sizeof(gf8_wire_id));
        if (!p) {
            c->alloc_ok = 0;
            return;
        }
        c->lt_bits = p;
        c->cap_lt_bits = new_cap;
    }

    /* Grow the LT entry table. */
    if (c->n_lt == c->cap_lt) {
        size_t new_cap = c->cap_lt ? c->cap_lt * 2 : 8;
        gf8_lt_entry_t *p =
            realloc(c->lt_constraints, new_cap * sizeof(gf8_lt_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return;
        }
        c->lt_constraints = p;
        c->cap_lt = new_cap;
    }

    size_t off = c->n_lt_bits;
    for (unsigned int i = 0; i < width; i++)
        c->lt_bits[off + i] = a_bits[i];
    for (unsigned int i = 0; i < width; i++)
        c->lt_bits[off + width + i] = b_bits[i];
    c->n_lt_bits += (size_t)2 * width;

    c->lt_constraints[c->n_lt].bits_off = off;
    c->lt_constraints[c->n_lt].width = width;
    c->n_lt++;

    if (width + 1u > c->max_lt_degree)
        c->max_lt_degree = width + 1u;
}

size_t
voleith_gf8_circuit_lt_count(const voleith_gf8_circuit_t *c)
{
    return c->n_lt;
}

const gf8_lt_entry_t *
voleith_gf8_circuit_lt_constraints(const voleith_gf8_circuit_t *c)
{
    return c->lt_constraints;
}

const gf8_wire_id *
voleith_gf8_circuit_lt_bits(const voleith_gf8_circuit_t *c)
{
    return c->lt_bits;
}

void
voleith_gf8_assert_syndrome(voleith_gf8_circuit_t *c,
                            const gf8_wire_id *idx_bit_wires,
                            const gf8_wire_id *s_bit_wires, uint32_t t,
                            uint32_t idx_bits, uint32_t p, uint32_t n0,
                            const uint8_t *M)
{
    if (!c || !idx_bit_wires || !s_bit_wires || t == 0 || idx_bits == 0 ||
        p == 0 || n0 == 0 || (n0 > 1u && !M)) {
        if (c)
            c->alloc_ok = 0;
        return;
    }

    size_t block_bytes = ((size_t)p + 7u) / 8u;
    size_t m_bytes = (size_t)(n0 - 1u) * block_bytes;
    size_t n_index_bits = (size_t)t * idx_bits;
    size_t need = c->n_syndrome_bits + n_index_bits + (size_t)p;

    /* Grow the shared syndrome bit pool. */
    if (need > c->cap_syndrome_bits) {
        size_t new_cap = c->cap_syndrome_bits ? c->cap_syndrome_bits : 64;
        while (new_cap < need)
            new_cap *= 2;
        gf8_wire_id *np =
            realloc(c->syndrome_bits, new_cap * sizeof(gf8_wire_id));
        if (!np) {
            c->alloc_ok = 0;
            return;
        }
        c->syndrome_bits = np;
        c->cap_syndrome_bits = new_cap;
    }

    /* Grow the syndrome entry table. */
    if (c->n_syndrome == c->cap_syndrome) {
        size_t new_cap = c->cap_syndrome ? c->cap_syndrome * 2 : 4;
        gf8_syndrome_entry_t *np = realloc(
            c->syndrome_constraints, new_cap * sizeof(gf8_syndrome_entry_t));
        if (!np) {
            c->alloc_ok = 0;
            return;
        }
        c->syndrome_constraints = np;
        c->cap_syndrome = new_cap;
    }

    /* Own a copy of the public matrix (bound later by the cfg-fingerprint). */
    uint8_t *m_copy = NULL;
    if (m_bytes > 0) {
        m_copy = calloc(m_bytes, 1);
        if (!m_copy) {
            c->alloc_ok = 0;
            return;
        }
        memcpy(m_copy, M, m_bytes);
    }

    size_t idx_off = c->n_syndrome_bits;
    for (size_t i = 0; i < n_index_bits; i++)
        c->syndrome_bits[idx_off + i] = idx_bit_wires[i];
    size_t s_off = idx_off + n_index_bits;
    for (uint32_t j = 0; j < p; j++)
        c->syndrome_bits[s_off + j] = s_bit_wires[j];
    c->n_syndrome_bits = need;

    gf8_syndrome_entry_t *e = &c->syndrome_constraints[c->n_syndrome];
    e->idx_off = idx_off;
    e->s_off = s_off;
    e->t = t;
    e->idx_bits = idx_bits;
    e->p = p;
    e->n0 = n0;
    e->M = m_copy;
    e->m_bytes = m_bytes;
    c->n_syndrome++;

    if (idx_bits > c->max_syndrome_degree)
        c->max_syndrome_degree = idx_bits;
}

size_t
voleith_gf8_circuit_syndrome_count(const voleith_gf8_circuit_t *c)
{
    return c->n_syndrome;
}

const gf8_syndrome_entry_t *
voleith_gf8_circuit_syndrome_constraints(const voleith_gf8_circuit_t *c)
{
    return c->syndrome_constraints;
}

const gf8_wire_id *
voleith_gf8_circuit_syndrome_bits(const voleith_gf8_circuit_t *c)
{
    return c->syndrome_bits;
}

/* ================================================================
 * Introspection
 * ================================================================ */

size_t
voleith_gf8_circuit_wire_count(const voleith_gf8_circuit_t *c)
{
    return c->n_wires;
}

size_t
voleith_gf8_circuit_witness_count(const voleith_gf8_circuit_t *c)
{
    return c->n_witness;
}

size_t
voleith_gf8_circuit_instance_count(const voleith_gf8_circuit_t *c)
{
    return c->n_instance;
}

size_t
voleith_gf8_circuit_gate_count(const voleith_gf8_circuit_t *c)
{
    /* Gates are the produced (non-input) wires: every XOR, XOR_CONST,
     * LINEAR_MAP, SQUARE, and MUL wire.  The inputs are WITNESS, INSTANCE,
     * and CONST wires. */
    return c->n_wires - c->n_witness - c->n_instance - c->n_const;
}

size_t
voleith_gf8_circuit_mul_count(const voleith_gf8_circuit_t *c)
{
    return c->n_mul;
}

unsigned int
voleith_gf8_circuit_qs_degree(const voleith_gf8_circuit_t *c)
{
    /* Baseline degree-2 (MUL gate / assert_product).  A less-than constraint
     * of width w raises the opening degree to w+1 (tracked as max_lt_degree); a
     * syndrome constraint raises it to idx_bits (tracked as max_syndrome_degree).
     * d is derived, not transmitted; degree-2-only circuits stay at 2
     * (byte-identical). */
    unsigned int d = 2u;
    if (c->max_lt_degree > d)
        d = c->max_lt_degree;
    if (c->max_syndrome_degree > d)
        d = c->max_syndrome_degree;
    return d;
}

size_t
voleith_gf8_circuit_assert_product_count(const voleith_gf8_circuit_t *c)
{
    return c->n_assert_product;
}

size_t
voleith_gf8_circuit_constraint_count(const voleith_gf8_circuit_t *c)
{
    return c->n_constraints;
}

size_t
voleith_gf8_qs_ell(const voleith_gf8_circuit_t *c)
{
    return c->n_witness + c->n_mul;
}

int
voleith_gf8_circuit_ok(const voleith_gf8_circuit_t *c)
{
    return c->alloc_ok;
}

int
voleith_gf8_circuit_validate(const voleith_gf8_circuit_t *c)
{
    if (!c)
        return -1;
    size_t n = c->n_wires;
    for (size_t i = 0; i < n; i++) {
        const gf8_wire_entry_t *w = &c->wires[i];
        switch (w->kind) {
        case GF8_WIRE_WITNESS:
        case GF8_WIRE_INSTANCE:
        case GF8_WIRE_CONST:
            break;
        case GF8_WIRE_XOR:
        case GF8_WIRE_MUL:
            if (w->a >= i || w->b >= i)
                return -1;
            break;
        case GF8_WIRE_SCALE_INSTANCE:
            /* Re-check operand kind: b must be an instance wire, so a forged
             * blob cannot smuggle a witness operand through the free path. */
            if (w->a >= i || w->b >= i ||
                c->wires[w->b].kind != GF8_WIRE_INSTANCE)
                return -1;
            break;
        case GF8_WIRE_XOR_CONST:
        case GF8_WIRE_LINEAR_MAP:
        case GF8_WIRE_SQUARE:
            if (w->a >= i)
                return -1;
            break;
        }
    }
    for (size_t i = 0; i < c->n_constraints; i++) {
        const gf8_constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case GF8_CONSTRAINT_ZERO:
            if (con->a >= n)
                return -1;
            break;
        case GF8_CONSTRAINT_EQUAL:
            if (con->a >= n || con->b >= n)
                return -1;
            break;
        case GF8_CONSTRAINT_PRODUCT:
            if (con->a >= n || con->b >= n || con->c >= n)
                return -1;
            break;
        }
    }
    for (size_t i = 0; i < c->n_lt; i++) {
        const gf8_lt_entry_t *lt = &c->lt_constraints[i];
        size_t cnt = (size_t)2 * lt->width;
        if (lt->width == 0 || lt->bits_off + cnt > c->n_lt_bits)
            return -1;
        for (size_t j = 0; j < cnt; j++)
            if (c->lt_bits[lt->bits_off + j] >= n)
                return -1;
    }
    for (size_t i = 0; i < c->n_syndrome; i++) {
        const gf8_syndrome_entry_t *sy = &c->syndrome_constraints[i];
        size_t block_bytes = ((size_t)sy->p + 7u) / 8u;
        size_t cnt = (size_t)sy->t * sy->idx_bits + (size_t)sy->p;
        if (sy->t == 0 || sy->idx_bits == 0 || sy->p == 0 || sy->n0 == 0)
            return -1;
        if (sy->m_bytes != (size_t)(sy->n0 - 1u) * block_bytes)
            return -1;
        if (sy->idx_off + cnt > c->n_syndrome_bits ||
            sy->s_off != sy->idx_off + (size_t)sy->t * sy->idx_bits)
            return -1;
        for (size_t j = 0; j < cnt; j++)
            if (c->syndrome_bits[sy->idx_off + j] >= n)
                return -1;
    }
    return 0;
}

const gf8_wire_entry_t *
voleith_gf8_circuit_wires(const voleith_gf8_circuit_t *c)
{
    return c->wires;
}

const gf8_constraint_entry_t *
voleith_gf8_circuit_constraints(const voleith_gf8_circuit_t *c)
{
    return c->constraints;
}

/* ================================================================
 * Evaluation
 * ================================================================ */

int
voleith_gf8_circuit_eval(const voleith_gf8_circuit_t *c, const uint8_t *witness,
                         const uint8_t *instance, uint8_t *wire_vals)
{
    if (!c || !wire_vals)
        return -1;

    size_t witness_idx = 0;
    size_t instance_idx = 0;

    for (size_t i = 0; i < c->n_wires; i++) {
        const gf8_wire_entry_t *w = &c->wires[i];
        uint8_t val = 0;

        switch (w->kind) {
        case GF8_WIRE_WITNESS:
            val = witness ? witness[witness_idx++] : 0;
            break;
        case GF8_WIRE_INSTANCE:
            val = instance ? instance[instance_idx++] : 0;
            break;
        case GF8_WIRE_CONST:
            val = w->const_val;
            break;
        case GF8_WIRE_XOR:
            val = wire_vals[w->a] ^ wire_vals[w->b];
            break;
        case GF8_WIRE_XOR_CONST:
            val = wire_vals[w->a] ^ w->const_val;
            break;
        case GF8_WIRE_LINEAR_MAP:
            val = apply_linear_map(w->matrix, wire_vals[w->a]);
            break;
        case GF8_WIRE_SQUARE:
            val = apply_linear_map(GF8_SQUARE_MATRIX, wire_vals[w->a]);
            break;
        case GF8_WIRE_MUL:
        case GF8_WIRE_SCALE_INSTANCE:
            val = voleith_gf8_mul(wire_vals[w->a], wire_vals[w->b]);
            break;
        }

        wire_vals[i] = val;
    }

    /* Returns 1 if all constraints satisfied, 0 if any violated, -1 on error. */
    return voleith_gf8_circuit_check_constraints(c, wire_vals);
}

/*
 * Returns 1 if every constraint holds for wire_vals, 0 if any is violated.
 * Never returns -1: a NULL check must be done by the caller before calling
 * this function (voleith_gf8_circuit_eval handles that guard).
 */
int
voleith_gf8_circuit_check_constraints(const voleith_gf8_circuit_t *c,
                                      const uint8_t *wire_vals)
{
    for (size_t i = 0; i < c->n_constraints; i++) {
        const gf8_constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case GF8_CONSTRAINT_ZERO:
            if (wire_vals[con->a] != 0x00)
                return 0;
            break;
        case GF8_CONSTRAINT_EQUAL:
            if (wire_vals[con->a] != wire_vals[con->b])
                return 0;
            break;
        case GF8_CONSTRAINT_PRODUCT: {
            uint8_t prod =
                voleith_gf8_mul(wire_vals[con->a], wire_vals[con->b]);
            if (prod != wire_vals[con->c])
                return 0;
            break;
        }
        }
    }
    /* Less-than: value(A) < value(B), MSB-first bit wires (each 0x00/0x01). */
    for (size_t i = 0; i < c->n_lt; i++) {
        const gf8_lt_entry_t *lt = &c->lt_constraints[i];
        const gf8_wire_id *bits = c->lt_bits + lt->bits_off;
        int lt_holds = 0; /* A < B ? */
        for (unsigned int j = 0; j < lt->width; j++) {
            uint8_t aj = wire_vals[bits[j]] & 1u;
            uint8_t bj = wire_vals[bits[lt->width + j]] & 1u;
            if (aj != bj) {
                lt_holds = (aj == 0); /* first differing bit: A<B iff a=0,b=1 */
                break;
            }
        }
        if (!lt_holds)
            return 0;
    }
    /*
     * Syndrome: s_j = XOR_k M[j, g_k], global-bit form (clear-domain oracle;
     * the degree-d prover/verifier accumulators are validated against this).
     * g_k is reconstructed from its MSB-first index bits; block b_k = g_k / p,
     * local_k = g_k mod p.  A non-identity block b contributes the circulant
     * coefficient m_b[(j - local_k) mod p] to s_j (matching ichor_gf2x_mul in
     * voleith_rs_opener_argus_syndrome); the identity last block contributes
     * [local_k == j].
     */
    for (size_t i = 0; i < c->n_syndrome; i++) {
        const gf8_syndrome_entry_t *sy = &c->syndrome_constraints[i];
        const gf8_wire_id *idx = c->syndrome_bits + sy->idx_off;
        const gf8_wire_id *s_wires = c->syndrome_bits + sy->s_off;
        size_t block_bytes = ((size_t)sy->p + 7u) / 8u;
        uint32_t p = sy->p;

        for (uint32_t j = 0; j < p; j++) {
            uint8_t acc = 0;
            for (uint32_t k = 0; k < sy->t; k++) {
                const gf8_wire_id *kb = idx + (size_t)k * sy->idx_bits;
                uint32_t g = 0;
                for (uint32_t b = 0; b < sy->idx_bits; b++)
                    g = (g << 1) | (wire_vals[kb[b]] & 1u); /* MSB-first */
                uint32_t blk = g / p;
                uint32_t local = g % p;
                if (blk == sy->n0 - 1u) {
                    acc ^= (uint8_t)(local == j);
                } else {
                    uint32_t a = (j + p - local) % p; /* (j - local) mod p */
                    const uint8_t *mb = sy->M + (size_t)blk * block_bytes;
                    acc ^= (uint8_t)((mb[a >> 3] >> (a & 7u)) & 1u);
                }
            }
            if ((wire_vals[s_wires[j]] & 1u) != acc)
                return 0;
        }
    }
    return 1;
}
