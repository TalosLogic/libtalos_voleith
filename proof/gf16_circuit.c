/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_circuit.c - GF(2^16) element-level circuit definition, builder, and
 * evaluation.  The GF(2^16) counterpart to gf8_circuit.c.
 */

#include "gf16_circuit.h"
#include "../core/field16.h"

#include <stdlib.h>
#include <string.h>

#define INITIAL_WIRE_CAP 64
#define INITIAL_CONSTRAINT_CAP 16

struct voleith_gf16_circuit {
    gf16_wire_entry_t *wires;
    size_t n_wires;
    size_t cap_wires;

    gf16_constraint_entry_t *constraints;
    size_t n_constraints;
    size_t cap_constraints;

    /* Less-than constraints (Option 3: separate table). lt_bits is the shared
     * pool of bit-wire ids each entry indexes (2*width ids per entry). */
    gf16_lt_entry_t *lt_constraints;
    size_t n_lt;
    size_t cap_lt;
    gf16_wire_id *lt_bits;
    size_t n_lt_bits;
    size_t cap_lt_bits;
    unsigned int max_lt_degree; /* max (width+1) over LT entries; 0 if none */

    /* Syndrome constraints (Option 3: separate table).  syndrome_bits is the
     * shared pool (t*idx_bits index bits then p s bits per entry). */
    gf16_syndrome_entry_t *syndrome_constraints;
    size_t n_syndrome;
    size_t cap_syndrome;
    gf16_wire_id *syndrome_bits;
    size_t n_syndrome_bits;
    size_t cap_syndrome_bits;
    unsigned int max_syndrome_degree; /* max idx_bits over entries; 0 if none */

    size_t n_witness;
    size_t n_instance;
    size_t n_const;
    size_t n_mul;
    size_t n_assert_product;
    int alloc_ok;

    size_t wire_cap;
    size_t gate_cap;
};

/* ================================================================
 * Helpers
 * ================================================================ */

static gf16_wire_id
append_wire(voleith_gf16_circuit_t *c, gf16_wire_entry_t entry)
{
    if (c->wire_cap != 0 && c->n_wires >= c->wire_cap) {
        c->alloc_ok = 0;
        return GF16_WIRE_ID_INVALID;
    }
    if (c->gate_cap != 0 && entry.kind != GF16_WIRE_WITNESS &&
        entry.kind != GF16_WIRE_INSTANCE && entry.kind != GF16_WIRE_CONST &&
        c->n_wires - c->n_witness - c->n_instance - c->n_const >= c->gate_cap) {
        c->alloc_ok = 0;
        return GF16_WIRE_ID_INVALID;
    }

    if (c->n_wires == c->cap_wires) {
        size_t new_cap = c->cap_wires * 2;
        gf16_wire_entry_t *p =
            realloc(c->wires, new_cap * sizeof(gf16_wire_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return GF16_WIRE_ID_INVALID;
        }
        c->wires = p;
        c->cap_wires = new_cap;
    }
    gf16_wire_id id = (gf16_wire_id)c->n_wires;
    c->wires[c->n_wires++] = entry;
    return id;
}

static void
append_constraint(voleith_gf16_circuit_t *c, gf16_constraint_entry_t entry)
{
    if (c->n_constraints == c->cap_constraints) {
        size_t new_cap = c->cap_constraints * 2;
        gf16_constraint_entry_t *p =
            realloc(c->constraints, new_cap * sizeof(gf16_constraint_entry_t));
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
 * Apply a 16x16 GF(2) matrix to a GF(2^16) element.
 * M[i] is row i; output bit i = parity(M[i] & a).
 */
static uint16_t
apply_linear_map(const uint16_t M[16], uint16_t a)
{
    uint16_t result = 0;
    for (int i = 0; i < 16; i++) {
        uint16_t masked = M[i] & a;
        masked ^= masked >> 8;
        masked ^= masked >> 4;
        masked ^= masked >> 2;
        masked ^= masked >> 1;
        result |= (uint16_t)((masked & 1u) << i);
    }
    return result;
}

void
voleith_gf16_square_matrix(uint16_t M[16])
{
    /*
     * Column j of the squaring map is (x^j)^2 = square(1<<j) reduced mod
     * m16; row i collects, for each j, bit i of that column.  square is a
     * GF(2)-linear map, so this reconstructs a^2 = M . a_bits.
     */
    memset(M, 0, 16 * sizeof(uint16_t));
    for (int j = 0; j < 16; j++) {
        uint16_t ej = (uint16_t)(1u << j);
        uint16_t sq = voleith_gf16_mul(ej, ej);
        for (int i = 0; i < 16; i++)
            if ((sq >> i) & 1u)
                M[i] |= (uint16_t)(1u << j);
    }
}

/* ================================================================
 * Lifecycle
 * ================================================================ */

voleith_gf16_circuit_t *
voleith_gf16_circuit_new(void)
{
    voleith_gf16_circuit_t *c = calloc(1, sizeof(voleith_gf16_circuit_t));
    if (!c)
        return NULL;

    c->wires = calloc(INITIAL_WIRE_CAP, sizeof(gf16_wire_entry_t));
    if (!c->wires) {
        free(c);
        return NULL;
    }
    c->cap_wires = INITIAL_WIRE_CAP;

    c->constraints =
        calloc(INITIAL_CONSTRAINT_CAP, sizeof(gf16_constraint_entry_t));
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
voleith_gf16_circuit_free(voleith_gf16_circuit_t *c)
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
voleith_gf16_circuit_set_limits(voleith_gf16_circuit_t *c, size_t max_wires,
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

gf16_wire_id
voleith_gf16_add_witness(voleith_gf16_circuit_t *c)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_WITNESS,
        .a = GF16_WIRE_ID_INVALID,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    gf16_wire_id id = append_wire(c, e);
    if (id != GF16_WIRE_ID_INVALID)
        c->n_witness++;
    return id;
}

gf16_wire_id
voleith_gf16_add_instance(voleith_gf16_circuit_t *c)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_INSTANCE,
        .a = GF16_WIRE_ID_INVALID,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    gf16_wire_id id = append_wire(c, e);
    if (id != GF16_WIRE_ID_INVALID)
        c->n_instance++;
    return id;
}

gf16_wire_id
voleith_gf16_add_const(voleith_gf16_circuit_t *c, uint16_t val)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_CONST,
        .a = GF16_WIRE_ID_INVALID,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = val,
        .matrix = {0},
    };
    gf16_wire_id id = append_wire(c, e);
    if (id != GF16_WIRE_ID_INVALID)
        c->n_const++;
    return id;
}

gf16_wire_id
voleith_gf16_add_xor(voleith_gf16_circuit_t *c, gf16_wire_id a, gf16_wire_id b)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_XOR,
        .a = a,
        .b = b,
        .const_val = 0,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf16_wire_id
voleith_gf16_add_xor_const(voleith_gf16_circuit_t *c, gf16_wire_id a,
                           uint16_t k)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_XOR_CONST,
        .a = a,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = k,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf16_wire_id
voleith_gf16_add_linear_map(voleith_gf16_circuit_t *c, gf16_wire_id a,
                            const uint16_t M[16])
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_LINEAR_MAP,
        .a = a,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = 0,
    };
    memcpy(e.matrix, M, 16 * sizeof(uint16_t));
    return append_wire(c, e);
}

gf16_wire_id
voleith_gf16_add_square(voleith_gf16_circuit_t *c, gf16_wire_id a)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_SQUARE,
        .a = a,
        .b = GF16_WIRE_ID_INVALID,
        .const_val = 0,
        .matrix = {0},
    };
    return append_wire(c, e);
}

gf16_wire_id
voleith_gf16_add_mul(voleith_gf16_circuit_t *c, gf16_wire_id a, gf16_wire_id b)
{
    gf16_wire_entry_t e = {
        .kind = GF16_WIRE_MUL,
        .a = a,
        .b = b,
        .const_val = 0,
        .matrix = {0},
    };
    gf16_wire_id id = append_wire(c, e);
    if (id != GF16_WIRE_ID_INVALID)
        c->n_mul++;
    return id;
}

gf16_wire_id
voleith_gf16_add_mux(voleith_gf16_circuit_t *c, gf16_wire_id a, gf16_wire_id b,
                     gf16_wire_id sel)
{
    gf16_wire_id diff = voleith_gf16_add_xor(c, b, a);
    if (diff == GF16_WIRE_ID_INVALID)
        return GF16_WIRE_ID_INVALID;

    gf16_wire_id prod = voleith_gf16_add_mul(c, sel, diff);
    if (prod == GF16_WIRE_ID_INVALID)
        return GF16_WIRE_ID_INVALID;

    return voleith_gf16_add_xor(c, a, prod);
}

void
voleith_gf16_assert_zero(voleith_gf16_circuit_t *c, gf16_wire_id w)
{
    gf16_constraint_entry_t e = {
        .kind = GF16_CONSTRAINT_ZERO,
        .a = w,
        .b = GF16_WIRE_ID_INVALID,
        .c = GF16_WIRE_ID_INVALID,
    };
    append_constraint(c, e);
}

void
voleith_gf16_assert_equal(voleith_gf16_circuit_t *c, gf16_wire_id a,
                          gf16_wire_id b)
{
    gf16_constraint_entry_t e = {
        .kind = GF16_CONSTRAINT_EQUAL,
        .a = a,
        .b = b,
        .c = GF16_WIRE_ID_INVALID,
    };
    append_constraint(c, e);
}

void
voleith_gf16_assert_product(voleith_gf16_circuit_t *c, gf16_wire_id a,
                            gf16_wire_id b, gf16_wire_id c_expected)
{
    gf16_constraint_entry_t e = {
        .kind = GF16_CONSTRAINT_PRODUCT,
        .a = a,
        .b = b,
        .c = c_expected,
    };
    append_constraint(c, e);
    if (c->alloc_ok)
        c->n_assert_product++;
}

void
voleith_gf16_assert_lt(voleith_gf16_circuit_t *c, const gf16_wire_id *a_bits,
                       const gf16_wire_id *b_bits, unsigned int width)
{
    if (!c || !a_bits || !b_bits || width == 0) {
        if (c)
            c->alloc_ok = 0;
        return;
    }

    size_t need = c->n_lt_bits + (size_t)2 * width;
    if (need > c->cap_lt_bits) {
        size_t new_cap = c->cap_lt_bits ? c->cap_lt_bits : 32;
        while (new_cap < need)
            new_cap *= 2;
        gf16_wire_id *p = realloc(c->lt_bits, new_cap * sizeof(gf16_wire_id));
        if (!p) {
            c->alloc_ok = 0;
            return;
        }
        c->lt_bits = p;
        c->cap_lt_bits = new_cap;
    }

    if (c->n_lt == c->cap_lt) {
        size_t new_cap = c->cap_lt ? c->cap_lt * 2 : 8;
        gf16_lt_entry_t *p =
            realloc(c->lt_constraints, new_cap * sizeof(gf16_lt_entry_t));
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
voleith_gf16_circuit_lt_count(const voleith_gf16_circuit_t *c)
{
    return c->n_lt;
}

const gf16_lt_entry_t *
voleith_gf16_circuit_lt_constraints(const voleith_gf16_circuit_t *c)
{
    return c->lt_constraints;
}

const gf16_wire_id *
voleith_gf16_circuit_lt_bits(const voleith_gf16_circuit_t *c)
{
    return c->lt_bits;
}

void
voleith_gf16_assert_syndrome(voleith_gf16_circuit_t *c,
                             const gf16_wire_id *idx_bit_wires,
                             const gf16_wire_id *s_bit_wires, uint32_t t,
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

    if (need > c->cap_syndrome_bits) {
        size_t new_cap = c->cap_syndrome_bits ? c->cap_syndrome_bits : 64;
        while (new_cap < need)
            new_cap *= 2;
        gf16_wire_id *np =
            realloc(c->syndrome_bits, new_cap * sizeof(gf16_wire_id));
        if (!np) {
            c->alloc_ok = 0;
            return;
        }
        c->syndrome_bits = np;
        c->cap_syndrome_bits = new_cap;
    }

    if (c->n_syndrome == c->cap_syndrome) {
        size_t new_cap = c->cap_syndrome ? c->cap_syndrome * 2 : 4;
        gf16_syndrome_entry_t *np = realloc(
            c->syndrome_constraints, new_cap * sizeof(gf16_syndrome_entry_t));
        if (!np) {
            c->alloc_ok = 0;
            return;
        }
        c->syndrome_constraints = np;
        c->cap_syndrome = new_cap;
    }

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

    gf16_syndrome_entry_t *e = &c->syndrome_constraints[c->n_syndrome];
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
voleith_gf16_circuit_syndrome_count(const voleith_gf16_circuit_t *c)
{
    return c->n_syndrome;
}

const gf16_syndrome_entry_t *
voleith_gf16_circuit_syndrome_constraints(const voleith_gf16_circuit_t *c)
{
    return c->syndrome_constraints;
}

const gf16_wire_id *
voleith_gf16_circuit_syndrome_bits(const voleith_gf16_circuit_t *c)
{
    return c->syndrome_bits;
}

/* ================================================================
 * Introspection
 * ================================================================ */

size_t
voleith_gf16_circuit_wire_count(const voleith_gf16_circuit_t *c)
{
    return c->n_wires;
}

size_t
voleith_gf16_circuit_witness_count(const voleith_gf16_circuit_t *c)
{
    return c->n_witness;
}

size_t
voleith_gf16_circuit_instance_count(const voleith_gf16_circuit_t *c)
{
    return c->n_instance;
}

size_t
voleith_gf16_circuit_gate_count(const voleith_gf16_circuit_t *c)
{
    return c->n_wires - c->n_witness - c->n_instance - c->n_const;
}

size_t
voleith_gf16_circuit_mul_count(const voleith_gf16_circuit_t *c)
{
    return c->n_mul;
}

unsigned int
voleith_gf16_circuit_qs_degree(const voleith_gf16_circuit_t *c)
{
    /* Baseline degree-2 (MUL gate / assert_product); a width-w less-than
     * constraint raises the opening degree to w+1, a syndrome constraint to
     * idx_bits.  d is derived, not transmitted; degree-2-only circuits stay at
     * 2 (byte-identical). */
    unsigned int d = 2u;
    if (c->max_lt_degree > d)
        d = c->max_lt_degree;
    if (c->max_syndrome_degree > d)
        d = c->max_syndrome_degree;
    return d;
}

size_t
voleith_gf16_circuit_assert_product_count(const voleith_gf16_circuit_t *c)
{
    return c->n_assert_product;
}

size_t
voleith_gf16_circuit_constraint_count(const voleith_gf16_circuit_t *c)
{
    return c->n_constraints;
}

size_t
voleith_gf16_qs_ell(const voleith_gf16_circuit_t *c)
{
    return c->n_witness + c->n_mul;
}

int
voleith_gf16_circuit_ok(const voleith_gf16_circuit_t *c)
{
    return c->alloc_ok;
}

int
voleith_gf16_circuit_validate(const voleith_gf16_circuit_t *c)
{
    if (!c)
        return -1;
    size_t n = c->n_wires;
    for (size_t i = 0; i < n; i++) {
        const gf16_wire_entry_t *w = &c->wires[i];
        switch (w->kind) {
        case GF16_WIRE_WITNESS:
        case GF16_WIRE_INSTANCE:
        case GF16_WIRE_CONST:
            break;
        case GF16_WIRE_XOR:
        case GF16_WIRE_MUL:
            if (w->a >= i || w->b >= i)
                return -1;
            break;
        case GF16_WIRE_XOR_CONST:
        case GF16_WIRE_LINEAR_MAP:
        case GF16_WIRE_SQUARE:
            if (w->a >= i)
                return -1;
            break;
        }
    }
    for (size_t i = 0; i < c->n_constraints; i++) {
        const gf16_constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case GF16_CONSTRAINT_ZERO:
            if (con->a >= n)
                return -1;
            break;
        case GF16_CONSTRAINT_EQUAL:
            if (con->a >= n || con->b >= n)
                return -1;
            break;
        case GF16_CONSTRAINT_PRODUCT:
            if (con->a >= n || con->b >= n || con->c >= n)
                return -1;
            break;
        }
    }
    for (size_t i = 0; i < c->n_lt; i++) {
        const gf16_lt_entry_t *lt = &c->lt_constraints[i];
        size_t cnt = (size_t)2 * lt->width;
        if (lt->width == 0 || lt->bits_off + cnt > c->n_lt_bits)
            return -1;
        for (size_t j = 0; j < cnt; j++)
            if (c->lt_bits[lt->bits_off + j] >= n)
                return -1;
    }
    for (size_t i = 0; i < c->n_syndrome; i++) {
        const gf16_syndrome_entry_t *sy = &c->syndrome_constraints[i];
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

const gf16_wire_entry_t *
voleith_gf16_circuit_wires(const voleith_gf16_circuit_t *c)
{
    return c->wires;
}

const gf16_constraint_entry_t *
voleith_gf16_circuit_constraints(const voleith_gf16_circuit_t *c)
{
    return c->constraints;
}

/* ================================================================
 * Evaluation
 * ================================================================ */

int
voleith_gf16_circuit_eval(const voleith_gf16_circuit_t *c,
                          const voleith_gf16_t *witness,
                          const voleith_gf16_t *instance,
                          voleith_gf16_t *wire_vals)
{
    if (!c || !wire_vals)
        return -1;

    size_t witness_idx = 0;
    size_t instance_idx = 0;

    for (size_t i = 0; i < c->n_wires; i++) {
        const gf16_wire_entry_t *w = &c->wires[i];
        uint16_t val = 0;

        switch (w->kind) {
        case GF16_WIRE_WITNESS:
            val = witness ? witness[witness_idx++] : 0;
            break;
        case GF16_WIRE_INSTANCE:
            val = instance ? instance[instance_idx++] : 0;
            break;
        case GF16_WIRE_CONST:
            val = w->const_val;
            break;
        case GF16_WIRE_XOR:
            val = wire_vals[w->a] ^ wire_vals[w->b];
            break;
        case GF16_WIRE_XOR_CONST:
            val = wire_vals[w->a] ^ w->const_val;
            break;
        case GF16_WIRE_LINEAR_MAP:
            val = apply_linear_map(w->matrix, wire_vals[w->a]);
            break;
        case GF16_WIRE_SQUARE:
            val = voleith_gf16_mul(wire_vals[w->a], wire_vals[w->a]);
            break;
        case GF16_WIRE_MUL:
            val = voleith_gf16_mul(wire_vals[w->a], wire_vals[w->b]);
            break;
        }

        wire_vals[i] = val;
    }

    return voleith_gf16_circuit_check_constraints(c, wire_vals);
}

int
voleith_gf16_circuit_check_constraints(const voleith_gf16_circuit_t *c,
                                       const voleith_gf16_t *wire_vals)
{
    for (size_t i = 0; i < c->n_constraints; i++) {
        const gf16_constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case GF16_CONSTRAINT_ZERO:
            if (wire_vals[con->a] != 0x0000)
                return 0;
            break;
        case GF16_CONSTRAINT_EQUAL:
            if (wire_vals[con->a] != wire_vals[con->b])
                return 0;
            break;
        case GF16_CONSTRAINT_PRODUCT: {
            uint16_t prod =
                voleith_gf16_mul(wire_vals[con->a], wire_vals[con->b]);
            if (prod != wire_vals[con->c])
                return 0;
            break;
        }
        }
    }
    /* Less-than: value(A) < value(B), MSB-first bit wires (each 0/1). */
    for (size_t i = 0; i < c->n_lt; i++) {
        const gf16_lt_entry_t *lt = &c->lt_constraints[i];
        const gf16_wire_id *bits = c->lt_bits + lt->bits_off;
        int lt_holds = 0;
        for (unsigned int j = 0; j < lt->width; j++) {
            uint16_t aj = wire_vals[bits[j]] & 1u;
            uint16_t bj = wire_vals[bits[lt->width + j]] & 1u;
            if (aj != bj) {
                lt_holds = (aj == 0);
                break;
            }
        }
        if (!lt_holds)
            return 0;
    }
    /* Syndrome: s_j = XOR_k M[j, g_k] (clear-domain oracle; the degree-d
     * accumulators are validated against this).  Same circulant column->row map
     * as voleith_rs_opener_argus_syndrome (block g_k/p, local g_k%p; non-id
     * block -> m_b[(j-local) mod p], id last block -> [local==j]). */
    for (size_t i = 0; i < c->n_syndrome; i++) {
        const gf16_syndrome_entry_t *sy = &c->syndrome_constraints[i];
        const gf16_wire_id *idx = c->syndrome_bits + sy->idx_off;
        const gf16_wire_id *s_wires = c->syndrome_bits + sy->s_off;
        size_t block_bytes = ((size_t)sy->p + 7u) / 8u;
        uint32_t p = sy->p;

        for (uint32_t j = 0; j < p; j++) {
            uint16_t acc = 0;
            for (uint32_t k = 0; k < sy->t; k++) {
                const gf16_wire_id *kb = idx + (size_t)k * sy->idx_bits;
                uint32_t g = 0;
                for (uint32_t b = 0; b < sy->idx_bits; b++)
                    g = (g << 1) | (wire_vals[kb[b]] & 1u); /* MSB-first */
                uint32_t blk = g / p;
                uint32_t local = g % p;
                if (blk == sy->n0 - 1u) {
                    acc ^= (uint16_t)(local == j);
                } else {
                    uint32_t a = (j + p - local) % p; /* (j - local) mod p */
                    const uint8_t *mb = sy->M + (size_t)blk * block_bytes;
                    acc ^= (uint16_t)((mb[a >> 3] >> (a & 7u)) & 1u);
                }
            }
            if ((wire_vals[s_wires[j]] & 1u) != acc)
                return 0;
        }
    }
    return 1;
}
