/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * circuit.c - Boolean circuit definition, builder, and evaluation
 */

#include "circuit.h"
#include <stdlib.h>
#include <string.h>

/* Initial capacity for dynamic arrays */
#define INITIAL_WIRE_CAP 64
#define INITIAL_CONSTRAINT_CAP 16

struct voleith_circuit {
    wire_entry_t *wires;
    size_t n_wires;
    size_t cap_wires;

    constraint_entry_t *constraints;
    size_t n_constraints;
    size_t cap_constraints;

    size_t n_witness;
    size_t n_instance;
    size_t n_and;
    int alloc_ok; /* 0 if any append failed */
};

/* ================================================================
 * Helpers
 * ================================================================ */

/* Append a wire entry; returns the new wire_id or WIRE_ID_INVALID */
static wire_id
append_wire(voleith_circuit_t *c, wire_entry_t entry)
{
    if (c->n_wires == c->cap_wires) {
        size_t new_cap = c->cap_wires * 2;
        wire_entry_t *p = realloc(c->wires, new_cap * sizeof(wire_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return WIRE_ID_INVALID;
        }
        c->wires = p;
        c->cap_wires = new_cap;
    }
    wire_id id = (wire_id)c->n_wires;
    c->wires[c->n_wires++] = entry;
    return id;
}

/* Append a constraint; returns 0 on success, -1 on allocation failure */
static int
append_constraint(voleith_circuit_t *c, constraint_entry_t entry)
{
    if (c->n_constraints == c->cap_constraints) {
        size_t new_cap = c->cap_constraints * 2;
        constraint_entry_t *p =
            realloc(c->constraints, new_cap * sizeof(constraint_entry_t));
        if (!p) {
            c->alloc_ok = 0;
            return -1;
        }
        c->constraints = p;
        c->cap_constraints = new_cap;
    }
    c->constraints[c->n_constraints++] = entry;
    return 0;
}

/* Read a packed bit from a byte array */
static inline uint8_t
read_bit(const uint8_t *arr, size_t idx)
{
    return (arr[idx / 8] >> (idx % 8)) & 1;
}

/* Write a bit into a packed byte array */
static inline void
write_bit(uint8_t *arr, size_t idx, uint8_t val)
{
    if (val & 1)
        arr[idx / 8] |= (uint8_t)(1u << (idx % 8));
    else
        arr[idx / 8] &= (uint8_t) ~(1u << (idx % 8));
}

/* ================================================================
 * Lifecycle
 * ================================================================ */

voleith_circuit_t *
voleith_circuit_new(void)
{
    voleith_circuit_t *c = calloc(1, sizeof(voleith_circuit_t));
    if (!c)
        return NULL;

    c->wires = calloc(INITIAL_WIRE_CAP, sizeof(wire_entry_t));
    if (!c->wires) {
        free(c);
        return NULL;
    }
    c->cap_wires = INITIAL_WIRE_CAP;

    c->constraints = calloc(INITIAL_CONSTRAINT_CAP, sizeof(constraint_entry_t));
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
voleith_circuit_free(voleith_circuit_t *c)
{
    if (!c)
        return;
    free(c->wires);
    free(c->constraints);
    free(c);
}

/* ================================================================
 * Builder API
 * ================================================================ */

wire_id
voleith_circuit_add_witness(voleith_circuit_t *c)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_WITNESS,
        .a = WIRE_ID_INVALID,
        .b = WIRE_ID_INVALID,
        .const_bit = 0,
    };
    wire_id id = append_wire(c, e);
    if (id != WIRE_ID_INVALID)
        c->n_witness++;
    return id;
}

wire_id
voleith_circuit_add_instance(voleith_circuit_t *c)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_INSTANCE,
        .a = WIRE_ID_INVALID,
        .b = WIRE_ID_INVALID,
        .const_bit = 0,
    };
    wire_id id = append_wire(c, e);
    if (id != WIRE_ID_INVALID)
        c->n_instance++;
    return id;
}

wire_id
voleith_circuit_add_const(voleith_circuit_t *c, uint8_t bit)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_CONST,
        .a = WIRE_ID_INVALID,
        .b = WIRE_ID_INVALID,
        .const_bit = bit & 1,
    };
    return append_wire(c, e);
}

wire_id
voleith_circuit_add_xor(voleith_circuit_t *c, wire_id a, wire_id b)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_XOR,
        .a = a,
        .b = b,
        .const_bit = 0,
    };
    return append_wire(c, e);
}

wire_id
voleith_circuit_add_and(voleith_circuit_t *c, wire_id a, wire_id b)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_AND,
        .a = a,
        .b = b,
        .const_bit = 0,
    };
    wire_id id = append_wire(c, e);
    if (id != WIRE_ID_INVALID)
        c->n_and++;
    return id;
}

wire_id
voleith_circuit_add_not(voleith_circuit_t *c, wire_id a)
{
    wire_entry_t e = {
        .kind = WIRE_KIND_NOT,
        .a = a,
        .b = WIRE_ID_INVALID,
        .const_bit = 0,
    };
    return append_wire(c, e);
}

void
voleith_circuit_assert_zero(voleith_circuit_t *c, wire_id w)
{
    constraint_entry_t e = {
        .kind = CONSTRAINT_ZERO,
        .a = w,
        .b = WIRE_ID_INVALID,
    };
    append_constraint(c, e);
}

void
voleith_circuit_assert_equal(voleith_circuit_t *c, wire_id a, wire_id b)
{
    /* Expand to assert_zero(a XOR b) so the prover/verifier see only
     * CONSTRAINT_ZERO entries - the QuickSilver layer only handles ZERO. */
    wire_id xw = voleith_circuit_add_xor(c, a, b);
    voleith_circuit_assert_zero(c, xw);
}

/* ================================================================
 * Introspection
 * ================================================================ */

size_t
voleith_circuit_wire_count(const voleith_circuit_t *c)
{
    return c->n_wires;
}

size_t
voleith_circuit_witness_count(const voleith_circuit_t *c)
{
    return c->n_witness;
}

size_t
voleith_circuit_instance_count(const voleith_circuit_t *c)
{
    return c->n_instance;
}

size_t
voleith_circuit_and_gate_count(const voleith_circuit_t *c)
{
    return c->n_and;
}

unsigned int
voleith_circuit_qs_degree(const voleith_circuit_t *c)
{
    (void)c;
    /* Baseline degree-2 (AND gate / assert).  When higher-degree constraint
     * sinks are added this derives the max over the constraint table. */
    return 2u;
}

size_t
voleith_circuit_constraint_count(const voleith_circuit_t *c)
{
    return c->n_constraints;
}

int
voleith_circuit_ok(const voleith_circuit_t *c)
{
    return c->alloc_ok;
}

int
voleith_circuit_validate(const voleith_circuit_t *c)
{
    if (!c)
        return -1;
    size_t n = c->n_wires;
    for (size_t i = 0; i < n; i++) {
        const wire_entry_t *w = &c->wires[i];
        switch (w->kind) {
        case WIRE_KIND_WITNESS:
        case WIRE_KIND_INSTANCE:
        case WIRE_KIND_CONST:
            break;
        case WIRE_KIND_XOR:
        case WIRE_KIND_AND:
            if (w->a >= i || w->b >= i)
                return -1;
            break;
        case WIRE_KIND_NOT:
            if (w->a >= i)
                return -1;
            break;
        }
    }
    for (size_t i = 0; i < c->n_constraints; i++) {
        const constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case CONSTRAINT_ZERO:
            if (con->a >= n)
                return -1;
            break;
        case CONSTRAINT_EQUAL:
            if (con->a >= n || con->b >= n)
                return -1;
            break;
        }
    }
    return 0;
}

const wire_entry_t *
voleith_circuit_wires(const voleith_circuit_t *c)
{
    return c->wires;
}

const constraint_entry_t *
voleith_circuit_constraints(const voleith_circuit_t *c)
{
    return c->constraints;
}

/* ================================================================
 * Evaluation
 * ================================================================ */

int
voleith_circuit_eval(const voleith_circuit_t *c, const uint8_t *witness,
                     const uint8_t *instance, uint8_t *wire_vals)
{
    if (!c || !wire_vals)
        return -1;

    /* Track per-kind bit indices for primary inputs */
    size_t witness_idx = 0;
    size_t instance_idx = 0;

    /* Zero output buffer */
    size_t val_bytes = (c->n_wires + 7) / 8;
    memset(wire_vals, 0, val_bytes);

    for (size_t i = 0; i < c->n_wires; i++) {
        const wire_entry_t *w = &c->wires[i];
        uint8_t val = 0;

        switch (w->kind) {
        case WIRE_KIND_WITNESS:
            val = witness ? read_bit(witness, witness_idx++) : 0;
            break;
        case WIRE_KIND_INSTANCE:
            val = instance ? read_bit(instance, instance_idx++) : 0;
            break;
        case WIRE_KIND_CONST:
            val = w->const_bit & 1;
            break;
        case WIRE_KIND_XOR:
            val = read_bit(wire_vals, w->a) ^ read_bit(wire_vals, w->b);
            break;
        case WIRE_KIND_AND:
            val = read_bit(wire_vals, w->a) & read_bit(wire_vals, w->b);
            break;
        case WIRE_KIND_NOT:
            val = read_bit(wire_vals, w->a) ^ 1;
            break;
        }

        write_bit(wire_vals, i, val);
    }

    return voleith_circuit_check_constraints(c, wire_vals);
}

int
voleith_circuit_check_constraints(const voleith_circuit_t *c,
                                  const uint8_t *wire_vals)
{
    for (size_t i = 0; i < c->n_constraints; i++) {
        const constraint_entry_t *con = &c->constraints[i];
        switch (con->kind) {
        case CONSTRAINT_ZERO:
            if (read_bit(wire_vals, con->a) != 0)
                return 0;
            break;
        case CONSTRAINT_EQUAL:
            if (read_bit(wire_vals, con->a) != read_bit(wire_vals, con->b))
                return 0;
            break;
        }
    }
    return 1;
}
