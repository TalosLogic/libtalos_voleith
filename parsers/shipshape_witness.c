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

#include "aes_norm_gf8_circuit.h"
#include "field.h"
#include "gf8_circuit.h"
#include "grostl_norm_gf8_circuit.h"
#include "shipshape_witgen_dispatch.h"
#include "util.h"

/* Max norm state bytes: ROWS * MAX_COLS = 8 * 16 (Grostl-512). */
#define NORM_SOLVE_MAX_NST 128u

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
        case GF8_CONSTRAINT_PRODUCT3:
            if (voleith_gf8_mul(voleith_gf8_mul(value[cs[i].a], value[cs[i].b]),
                                value[cs[i].c]) != value[cs[i].d])
                return VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT;
            break;
        }
    }
    return 0;
}

/* ================================================================
 * Norm-gadget witness solving (crypto-v3).
 *
 * The frozen inverse-fill path (inv_src, above) resolves only inverse
 * witnesses committed through a PRODUCT constraint.  A norm circuit instead
 * commits packed subfield-norm bytes and s_tilde reset states through the
 * paired-round norm gadget (proof/gf8_circuit.h), which the inv_src path
 * cannot derive.  These are deterministic functions of the round-pair's
 * input state (state_in) and odd-round key (k0), computed by the circuit
 * layer's aes_norm_gf8_solve_pair / grostl_norm_gf8_solve_pair.
 *
 * This map records, per internal witness wire, which norm entry / role
 * (packed or s_tilde) / index it fills.  The packed wires are not stored in
 * the gadget pool, so they are recovered by walking cw[i] (the embedded norm
 * wire, pool slot 1) back through its two LINEAR_MAP producers
 * (add_norm_embed then add_nibble) to the committed packed witness.  Each
 * entry is solved once, lazily, when the forward pass first reaches one of
 * its witnesses (state_in / k0 are already evaluated by then).
 * ================================================================ */

typedef struct {
    int kind;                    /* 0 = AES, 1 = Grostl */
    unsigned int nst;            /* state bytes (16 AES; 64/128 Grostl) */
    const gf8_wire_id *state_in; /* nst pool ids */
    const gf8_wire_id *k0;       /* 16 pool ids (AES only) */
    const gf8_wire_id *s_tilde;  /* nst pool ids */
    unsigned int cols;           /* Grostl */
    const uint8_t *shift;        /* Grostl (8 entries) */
    int is_q;                    /* Grostl */
    unsigned int odd_round;      /* Grostl */
    int solved;
    uint8_t packed_val[NORM_SOLVE_MAX_NST / 2];
    uint8_t stilde_val[NORM_SOLVE_MAX_NST];
} norm_solve_entry_t;

typedef struct {
    size_t n; /* number of norm entries */
    norm_solve_entry_t *ents;
    uint8_t *role;    /* n_wires: 0 none, 1 packed, 2 s_tilde */
    int *ent_of;      /* n_wires: entry index, or -1 */
    uint16_t *idx_of; /* n_wires: index within packed[]/s_tilde[] */
} norm_map_t;

static void
free_norm_map(norm_map_t *m)
{
    if (m == NULL)
        return;
    if (m->ents != NULL && m->n > 0)
        voleith_secure_zero(m->ents, m->n * sizeof(*m->ents));
    free(m->ents);
    free(m->role);
    free(m->ent_of);
    free(m->idx_of);
    memset(m, 0, sizeof(*m));
}

/*
 * Mark one norm entry's committed witnesses in the map.  pool is the entry's
 * wire pool (stride nst), stride_groups is 4 (AES: state/norm/s_tilde/k0) or
 * 3 (Grostl: state/norm/s_tilde).  Returns 0 on success.
 */
static void
map_norm_entry(norm_map_t *m, const gf8_wire_entry_t *wires, size_t ent_index,
               const gf8_wire_id *pool, size_t off, unsigned int nst)
{
    unsigned int i;

    for (i = 0; i < nst; i++) {
        gf8_wire_id cw = pool[off + 1u * nst + i];
        gf8_wire_id nib = wires[cw].a; /* add_norm_embed input */
        gf8_wire_id pk = wires[nib].a; /* add_nibble input = packed wire */
        gf8_wire_id st = pool[off + 2u * nst + i];

        if (i % 2u == 0u) {
            m->role[pk] = 1;
            m->ent_of[pk] = (int)ent_index;
            m->idx_of[pk] = (uint16_t)(i / 2u);
        }
        m->role[st] = 2;
        m->ent_of[st] = (int)ent_index;
        m->idx_of[st] = (uint16_t)i;
    }
}

static int
build_norm_map(const voleith_gf8_circuit_t *circuit,
               const gf8_wire_entry_t *wires, size_t n_wires, norm_map_t *m)
{
    size_t n_aes = voleith_gf8_circuit_norm_count(circuit);
    size_t n_gro = voleith_gf8_circuit_grostl_norm_count(circuit);
    const gf8_norm_entry_t *ae = voleith_gf8_circuit_norm_constraints(circuit);
    const gf8_wire_id *ap = voleith_gf8_circuit_norm_wires(circuit);
    const gf8_grostl_norm_entry_t *ge =
        voleith_gf8_circuit_grostl_norm_constraints(circuit);
    const gf8_wire_id *gp = voleith_gf8_circuit_grostl_norm_wires(circuit);
    size_t total = n_aes + n_gro;
    size_t e, i;

    memset(m, 0, sizeof(*m));
    if (total == 0)
        return 0; /* no norm gadgets: map stays empty, forward pass unchanged */

    m->n = total;
    m->ents = calloc(total, sizeof(*m->ents));
    m->role = calloc(n_wires ? n_wires : 1, sizeof(*m->role));
    m->ent_of = calloc(n_wires ? n_wires : 1, sizeof(*m->ent_of));
    m->idx_of = calloc(n_wires ? n_wires : 1, sizeof(*m->idx_of));
    if (m->ents == NULL || m->role == NULL || m->ent_of == NULL ||
        m->idx_of == NULL) {
        free_norm_map(m);
        return -1;
    }
    for (i = 0; i < n_wires; i++)
        m->ent_of[i] = -1;

    for (e = 0; e < n_aes; e++) {
        norm_solve_entry_t *s = &m->ents[e];
        size_t off = ae[e].wires_off;
        unsigned int nst = ae[e].nst;

        if (nst > NORM_SOLVE_MAX_NST) {
            free_norm_map(m);
            return -1;
        }
        s->kind = 0;
        s->nst = nst;
        s->state_in = &ap[off + 0u * nst];
        s->s_tilde = &ap[off + 2u * nst];
        s->k0 = &ap[off + 3u * nst];
        map_norm_entry(m, wires, e, ap, off, nst);
    }
    for (e = 0; e < n_gro; e++) {
        norm_solve_entry_t *s = &m->ents[n_aes + e];
        size_t off = ge[e].wires_off;
        unsigned int nst = ge[e].nst;

        if (nst > NORM_SOLVE_MAX_NST) {
            free_norm_map(m);
            return -1;
        }
        s->kind = 1;
        s->nst = nst;
        s->cols = ge[e].cols;
        s->shift = ge[e].shift;
        s->is_q = ge[e].is_q;
        s->odd_round = ge[e].odd_round;
        s->state_in = &gp[off + 0u * nst];
        s->s_tilde = &gp[off + 2u * nst];
        map_norm_entry(m, wires, n_aes + e, gp, off, nst);
    }
    return 0;
}

/*
 * Fill one norm witness wire `wid` (with wit_pos `wp`) from its solved entry,
 * solving the entry lazily from already-evaluated input wire values.
 */
static void
norm_fill_wire(norm_map_t *m, gf8_wire_id wid, size_t wp,
               const voleith_gf8_t *value, voleith_gf8_t *out_value,
               uint8_t *full)
{
    norm_solve_entry_t *s = &m->ents[m->ent_of[wid]];

    if (!s->solved) {
        uint8_t st_in[NORM_SOLVE_MAX_NST];
        uint8_t k0[16];
        unsigned int q;

        for (q = 0; q < s->nst; q++)
            st_in[q] = value[s->state_in[q]];
        if (s->kind == 0) {
            for (q = 0; q < 16; q++)
                k0[q] = value[s->k0[q]];
            aes_norm_gf8_solve_pair(st_in, k0, s->packed_val, s->stilde_val);
        } else {
            grostl_norm_gf8_solve_pair(st_in, s->nst, s->cols, s->shift,
                                       s->is_q, s->odd_round, s->packed_val,
                                       s->stilde_val);
        }
        s->solved = 1;
    }

    *out_value = (m->role[wid] == 1) ? s->packed_val[m->idx_of[wid]]
                                     : s->stilde_val[m->idx_of[wid]];
    full[wp] = *out_value;
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
    norm_map_t norm;
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
    memset(&norm, 0, sizeof(norm));

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

    /*
     * Norm-gadget map (crypto-v3): record which internal witnesses are norm
     * packed / s_tilde commitments so the forward pass can solve them (the
     * inv_src path cannot).  Empty when the circuit has no norm gadgets, in
     * which case the forward pass is byte-for-byte the frozen behaviour.
     */
    if (build_norm_map(circuit, wires, n_wires, &norm) != 0) {
        r = VOLEITH_SHIPSHAPE_WITGEN_ALLOC;
        goto fail;
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
                } else if (norm.role != NULL && norm.role[i] != 0) {
                    /* Norm packed / s_tilde commitment: solve from the
                     * round-pair's already-evaluated inputs (crypto-v3). */
                    norm_fill_wire(&norm, (gf8_wire_id)i, wit_pos, value,
                                   &value[i], full);
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
        case GF8_WIRE_SCALE_INSTANCE:
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
    free_norm_map(&norm);
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
    free_norm_map(&norm);
    return r;
}
