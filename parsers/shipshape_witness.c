/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witness.c - generic Tier 1 witness generator (W6.2).
 *
 * Single forward pass over the lowered GF(2^8) wire table (wire ids are
 * canonical emission order, so every operand precedes its consumer).  See
 * the witness-generation design; the per-wire rules are 3.2, the
 * external/internal partition and INV fill are 4.
 */

#include "shipshape_witness.h"

#include <stdlib.h>
#include <string.h>

#include "field.h"
#include "gf8_circuit.h"
#include "shipshape_witgen_dispatch.h"
#include "util.h"

/* GF(2)-linear 8x8 map: output bit i is the parity of (matrix[i] & x). */
static voleith_gf8_t
apply_linear_map(const uint8_t matrix[8], voleith_gf8_t x)
{
    voleith_gf8_t y = 0;

    for (int i = 0; i < 8; i++) {
        unsigned bits = (unsigned)(matrix[i] & x);
        bits ^= bits >> 4;
        bits ^= bits >> 2;
        bits ^= bits >> 1;
        y |= (voleith_gf8_t)((bits & 1u) << i);
    }
    return y;
}

size_t
voleith_shipshape_external_witness_len(const voleith_shipshape_parsed_t *parsed)
{
    size_t total = 0;

    if (parsed == NULL)
        return 0;
    for (size_t i = 0; i < parsed->n_decls; i++)
        if (parsed->decls[i].kind == VOLEITH_SHIPSHAPE_DECL_WITNESS)
            total += parsed->decls[i].length;
    return total;
}

/*
 * Evaluate every constraint against `value`; return 0 if all hold, or
 * VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT on the first violation.
 */
static int
self_check(const voleith_gf8_circuit_t *circuit, const voleith_gf8_t *value)
{
    const gf8_constraint_entry_t *cs = voleith_gf8_circuit_constraints(circuit);
    size_t n = voleith_gf8_circuit_constraint_count(circuit);

    for (size_t i = 0; i < n; i++) {
        switch (cs[i].kind) {
        case GF8_CONSTRAINT_ZERO:
            if (value[cs[i].a] != 0)
                return VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT;
            break;
        case GF8_CONSTRAINT_EQUAL:
            if (value[cs[i].a] != value[cs[i].b])
                return VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT;
            break;
        case GF8_CONSTRAINT_PRODUCT:
            if (voleith_gf8_mul(value[cs[i].a], value[cs[i].b]) !=
                value[cs[i].c])
                return VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT;
            break;
        }
    }
    return 0;
}

int
voleith_shipshape_witness_gen(const voleith_shipshape_parsed_t *parsed,
                              const uint8_t *ext_witness,
                              size_t ext_witness_len, const uint8_t *instance,
                              size_t instance_len, unsigned flags,
                              uint8_t **out, size_t *out_len)
{
    const voleith_gf8_circuit_t *circuit;
    const gf8_wire_entry_t *wires;
    const gf8_constraint_entry_t *cs;
    voleith_gf8_t *value = NULL;
    uint8_t *is_external = NULL;
    gf8_wire_id *inv_src = NULL;
    uint8_t *full = NULL;
    uint8_t *skip_inv = NULL;
    voleith_shipshape_witgen_backend_fn *disp_fn = NULL;
    voleith_shipshape_witgen_backend_fn *fn_cache = NULL;
    const voleith_shipshape_region_t **disp_region = NULL;
    size_t n_wires, n_witness, n_instance, n_constraints, ext_count;
    size_t ext_pos = 0, inst_pos = 0, wit_pos = 0;
    int r;

    if (out == NULL)
        return VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG;
    *out = NULL;
    if (out_len != NULL)
        *out_len = 0;
    if (parsed == NULL || parsed->circuit == NULL)
        return VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG;

    circuit = parsed->circuit;
    n_wires = voleith_gf8_circuit_wire_count(circuit);
    n_witness = voleith_gf8_circuit_witness_count(circuit);
    n_instance = voleith_gf8_circuit_instance_count(circuit);
    n_constraints = voleith_gf8_circuit_constraint_count(circuit);
    ext_count = voleith_shipshape_external_witness_len(parsed);

    /* Argument validation (length gates before any work, ISA 5.1 style). */
    if ((ext_count > 0 && ext_witness == NULL) ||
        (n_instance > 0 && instance == NULL))
        return VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG;
    if (ext_witness_len != ext_count)
        return VOLEITH_SHIPSHAPE_WITGEN_EXT_LEN;
    if (instance_len != n_instance)
        return VOLEITH_SHIPSHAPE_WITGEN_INSTANCE_LEN;

    wires = voleith_gf8_circuit_wires(circuit);
    cs = voleith_gf8_circuit_constraints(circuit);

    value = calloc(n_wires ? n_wires : 1, sizeof(*value));
    is_external = calloc(n_wires ? n_wires : 1, sizeof(*is_external));
    inv_src = calloc(n_wires ? n_wires : 1, sizeof(*inv_src));
    full = calloc(n_witness ? n_witness : 1, sizeof(*full));
    skip_inv = calloc(n_witness ? n_witness : 1, sizeof(*skip_inv));
    disp_fn = calloc(n_witness ? n_witness : 1, sizeof(*disp_fn));
    disp_region = calloc(n_witness ? n_witness : 1, sizeof(*disp_region));
    fn_cache =
        calloc(parsed->n_regions ? parsed->n_regions : 1, sizeof(*fn_cache));
    if (value == NULL || is_external == NULL || inv_src == NULL ||
        full == NULL || skip_inv == NULL || disp_fn == NULL ||
        disp_region == NULL || fn_cache == NULL) {
        r = VOLEITH_SHIPSHAPE_WITGEN_ALLOC;
        goto fail;
    }

    /* External witnesses: the wire ranges of the WITNESS declarations (4). */
    for (size_t i = 0; i < parsed->n_decls; i++) {
        const voleith_shipshape_decl_t *d = &parsed->decls[i];

        if (d->kind != VOLEITH_SHIPSHAPE_DECL_WITNESS || d->length == 0)
            continue;
        for (size_t k = 0; k < d->length; k++)
            is_external[d->first_wire + k] = 1;
    }

    /*
     * INV fill sources: for each PRODUCT constraint, the second operand b is
     * the inverted witness and the third operand c is its source a, with
     * value == inv(value[a]) (4).  First writer wins (the gadget's defining
     * constraint precedes the second PRODUCT, which has the witness as its
     * third operand, never its second).
     */
    for (size_t i = 0; i < n_wires; i++)
        inv_src[i] = GF8_WIRE_ID_INVALID;
    for (size_t i = 0; i < n_constraints; i++)
        if (cs[i].kind == GF8_CONSTRAINT_PRODUCT &&
            inv_src[cs[i].b] == GF8_WIRE_ID_INVALID)
            inv_src[cs[i].b] = cs[i].c;

    /*
     * Tier 2a interleaved-skip pre-pass (W8.4).  Select the OUTERMOST
     * dispatched regions and, for each, mark its witness span so the forward
     * pass reads the backend-filled value rather than recomputing the
     * brute-force inverse.  A region's witness span is internal inv wires only;
     * outer regions enclose the spans of nested ones (shipshape.h), so an
     * inner dispatched region nested inside an outer dispatched region must
     * NOT fire a second backend over the same slots.
     *
     * A dispatched region R is a dispatch point iff no OTHER dispatched region
     * S strictly encloses it.  S strictly encloses R when S's span starts at or
     * before R's, ends at or after R's, and is strictly larger (S.n_witness >
     * R.n_witness).  The strict-size test keeps a region from "enclosing
     * itself" and breaks ties between equal spans (only one of which can be the
     * true outer).  Array order is NOT relied on; spans are compared directly.
     *
     * With nothing registered, voleith_shipshape_witgen_lookup returns NULL for
     * every region, so skip_inv / disp_fn / disp_region stay all-zero and the
     * forward pass is byte-for-byte the generic behaviour.
     */
    /*
     * I3: resolve each region's backend once (O(n_regions) registry string
     * lookups) so the enclosure scan below reads cached pointers instead of
     * repeating voleith_shipshape_witgen_lookup (a registry string scan) in
     * its inner loop.  Cost drops from O(n_regions^2 * table) string work to
     * O(n_regions^2) integer comparisons.
     */
    for (size_t ri = 0; ri < parsed->n_regions; ri++)
        fn_cache[ri] = voleith_shipshape_witgen_lookup(&parsed->regions[ri]);

    for (size_t ri = 0; ri < parsed->n_regions; ri++) {
        const voleith_shipshape_region_t *R = &parsed->regions[ri];
        voleith_shipshape_witgen_backend_fn fn = fn_cache[ri];
        size_t r_lo, r_hi;
        int enclosed = 0;

        if (fn == NULL)
            continue;

        r_lo = R->first_witness;
        r_hi = R->first_witness + R->n_witness;

        for (size_t si = 0; si < parsed->n_regions; si++) {
            const voleith_shipshape_region_t *S = &parsed->regions[si];

            if (si == ri)
                continue;
            if (fn_cache[si] == NULL)
                continue;
            if (S->n_witness <= R->n_witness)
                continue; /* not strictly larger; cannot enclose R */
            if (S->first_witness <= r_lo &&
                S->first_witness + S->n_witness >= r_hi) {
                enclosed = 1;
                break;
            }
        }
        if (enclosed)
            continue;

        /* R is an outermost dispatch point.  Mark its span and entry point. */
        disp_fn[R->first_witness] = fn;
        disp_region[R->first_witness] = R;
        for (size_t w = r_lo; w < r_hi; w++)
            skip_inv[w] = 1;
    }

    /* Forward pass: evaluate every wire, collect the full witness array. */
    for (size_t i = 0; i < n_wires; i++) {
        const gf8_wire_entry_t *w = &wires[i];

        switch (w->kind) {
        case GF8_WIRE_WITNESS:
            if (is_external[i]) {
                /* External witness: copied straight from the caller's input. */
                value[i] = ext_witness[ext_pos++];
                full[wit_pos] = value[i];
            } else {
                /*
                 * Internal inv witness.  If wit_pos is the first slot of an
                 * outermost dispatched region, run the backend now: all of the
                 * region's input wires already carry values (operands precede
                 * consumers), so it can fill full[first_witness .. end) in line.
                 */
                if (disp_fn[wit_pos] != NULL) {
                    int drc = voleith_shipshape_witgen_invoke_region(
                        disp_region[wit_pos], disp_fn[wit_pos], value, n_wires,
                        full, n_witness);
                    if (drc != 0) {
                        r = VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT;
                        goto fail;
                    }
                }
                if (skip_inv[wit_pos]) {
                    /* Backend already wrote this slot; skip the inverse. */
                    value[i] = full[wit_pos];
                } else {
                    if (inv_src[i] == GF8_WIRE_ID_INVALID) {
                        r = VOLEITH_SHIPSHAPE_WITGEN_UNRESOLVED;
                        goto fail;
                    }
                    value[i] = voleith_gf8_inv(value[inv_src[i]]);
                    full[wit_pos] = value[i];
                }
            }
            wit_pos++;
            break;
        case GF8_WIRE_INSTANCE:
            value[i] = instance[inst_pos++];
            break;
        case GF8_WIRE_CONST:
            value[i] = w->const_val;
            break;
        case GF8_WIRE_XOR:
            value[i] = value[w->a] ^ value[w->b];
            break;
        case GF8_WIRE_XOR_CONST:
            value[i] = value[w->a] ^ w->const_val;
            break;
        case GF8_WIRE_LINEAR_MAP:
            value[i] = apply_linear_map(w->matrix, value[w->a]);
            break;
        case GF8_WIRE_SQUARE:
            value[i] = voleith_gf8_mul(value[w->a], value[w->a]);
            break;
        case GF8_WIRE_MUL:
            value[i] = voleith_gf8_mul(value[w->a], value[w->b]);
            break;
        }
    }

    /*
     * Self-check (W8.4): now that backends fill their spans in line, this
     * validates value[] including backend-supplied inverses, so a wrong
     * backend is caught here when SELF_CHECK is set (fail-closed at gen time).
     */
    if ((flags & VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK) != 0) {
        r = self_check(circuit, value);
        if (r != 0)
            goto fail;
    }

    /* Success: hand the secret witness buffer to the caller. */
    voleith_secure_zero(value, (n_wires ? n_wires : 1) * sizeof(*value));
    free(value);
    free(is_external);
    free(inv_src);
    free(skip_inv);
    free(disp_fn);
    free(disp_region);
    free(fn_cache);
    *out = full;
    if (out_len != NULL)
        *out_len = n_witness;
    return 0;

fail:
    if (value != NULL)
        voleith_secure_zero(value, (n_wires ? n_wires : 1) * sizeof(*value));
    if (full != NULL)
        voleith_secure_zero(full, (n_witness ? n_witness : 1) * sizeof(*full));
    free(value);
    free(is_external);
    free(inv_src);
    free(full);
    free(skip_inv);
    free(disp_fn);
    free(disp_region);
    free(fn_cache);
    return r;
}
