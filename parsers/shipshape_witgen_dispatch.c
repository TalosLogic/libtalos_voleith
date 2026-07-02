/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_dispatch.c - Tier 2a hash-pinned witness-backend
 * registration and dispatch (W8.2 + W8.3a).
 *
 * Design: the witness-generation design §7.  Scope:
 *   - A fixed-size static registration table (no dynamic allocation).
 *   - Dispatch over FIXED Tier 2a registry entries by (name, frozen hash).
 *   - Dispatch over PARAMETRIC entries by structural name keying (W8.3c):
 *     one backend serves every message length, authenticated implicitly by
 *     the compiled-in frozen registry.  The per-length body hash is advisory.
 *   - REG_HASH_PARAM (crypto-v2 hash-parametric) CONSTRUCTION entries dispatch
 *     by structural bracketed-name keying (W8.5a): a region whose name is the
 *     bracketed "fqn[type]" form and whose cv2_valid flag is set matches a
 *     construction table entry registered under the exact bracketed name.  This
 *     file registers no construction backend, so by default these still fall
 *     through to the generic path.
 *   - W8.4: backends fill their witness span IN LINE during the single forward
 *     pass.  This file exposes the per-region resolution
 *     (voleith_shipshape_witgen_lookup) and per-region invocation
 *     (voleith_shipshape_witgen_invoke_region) the forward pass drives; it no
 *     longer runs a post-pass overlay.
 *   - Per-region ext assembly (W8.3a): the invoke helper reads the forward-pass
 *     value array and assembles ext[k] = value[region->inputs[k]] for the
 *     matched region before calling the backend.
 *
 * This file registers NO real backends.  Real backends are opt-in performance
 * layers registered by the caller before witness generation.
 */

#include "shipshape_witgen_dispatch.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "gf8_circuit.h"
#include "shipshape_node_hash_types.h"
#include "shipshape_registry.h"
#include "util.h"

/* Maximum number of simultaneously registered backends. */
#define WITGEN_DISPATCH_CAPACITY 32

/*
 * One registration table entry.
 * `fqn` is a borrowed pointer (caller must ensure static lifetime).
 * `by_name` is the match-kind discriminator: 0 = HASH/FIXED (match on name
 *   AND exact body_hash), 1 = NAME/PARAMETRIC (match on name only, body_hash
 *   ignored), 2 = CONSTRUCTION (crypto-v2; match on the exact bracketed
 *   "fqn[type]" name only, body_hash ignored).
 * `body_hash` is a copied 16-byte fingerprint (HASH entries only; zeroed and
 *   ignored for NAME and CONSTRUCTION entries).
 * `fn` is the backend function pointer.
 */
typedef struct {
    const char *fqn;
    int by_name;
    uint8_t body_hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES];
    voleith_shipshape_witgen_backend_fn fn;
} witgen_entry_t;

static witgen_entry_t s_table[WITGEN_DISPATCH_CAPACITY];
static size_t s_count = 0;

int
voleith_shipshape_witgen_register(
    const char *fqn,
    const uint8_t body_hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES],
    voleith_shipshape_witgen_backend_fn fn)
{
    if (fqn == NULL || body_hash == NULL || fn == NULL)
        return -1;
    if (s_count >= WITGEN_DISPATCH_CAPACITY)
        return -1;
    s_table[s_count].fqn = fqn;
    s_table[s_count].by_name = 0;
    memcpy(s_table[s_count].body_hash, body_hash,
           VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES);
    s_table[s_count].fn = fn;
    s_count++;
    return 0;
}

/*
 * Resolve fqn to its registry entry kind.  Returns 0 and writes *kind on a
 * name match; returns -1 if the name is absent from the frozen crypto-v1
 * registry.
 */
static int
registry_kind_of(const char *fqn, voleith_shipshape_reg_kind_t *kind)
{
    size_t n = voleith_shipshape_registry_count;
    size_t i;

    for (i = 0; i < n; i++) {
        if (strcmp(voleith_shipshape_registry[i].fqn, fqn) == 0) {
            *kind = voleith_shipshape_registry[i].kind;
            return 0;
        }
    }
    return -1;
}

int
voleith_shipshape_witgen_register_parametric(
    const char *fqn, voleith_shipshape_witgen_backend_fn fn)
{
    voleith_shipshape_reg_kind_t kind;

    if (fqn == NULL || fn == NULL)
        return -1;
    if (s_count >= WITGEN_DISPATCH_CAPACITY)
        return -1;

    /*
     * Structural keying requires the name to be a PARAMETRIC entry in the
     * frozen registry: a FIXED or hash-parametric name can never be
     * registered through this path.
     */
    if (registry_kind_of(fqn, &kind) != 0)
        return -1;
    if (kind != VOLEITH_SHIPSHAPE_REG_PARAMETRIC)
        return -1;

    s_table[s_count].fqn = fqn;
    s_table[s_count].by_name = 1;
    memset(s_table[s_count].body_hash, 0,
           VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES);
    s_table[s_count].fn = fn;
    s_count++;
    return 0;
}

/*
 * Validate that `fqn` is a well-formed known crypto-v2 bracketed construction
 * name "<entry>[<type>]": <entry> equals some voleith_shipshape_reg_hash[].fqn,
 * <type> resolves via voleith_shipshape_node_hash_type_by_name() to a known
 * node-hash type, and the name ends with ']'.  Returns 0 if valid, -1 if not.
 */
static int
construction_name_valid(const char *fqn)
{
    const char *lb;
    const char *type_start;
    size_t entry_len, type_len, fqn_len, n, i;

    lb = strchr(fqn, '[');
    if (lb == NULL)
        return -1;
    entry_len = (size_t)(lb - fqn);

    fqn_len = strlen(fqn);
    /* The name must end with ']'. */
    if (fqn_len == 0 || fqn[fqn_len - 1] != ']')
        return -1;
    /* Type substring lies between '[' and the trailing ']'. */
    type_start = lb + 1;
    if (type_start > fqn + fqn_len - 1)
        return -1;
    type_len = (size_t)((fqn + fqn_len - 1) - type_start);
    if (type_len == 0)
        return -1;

    /* The entry prefix must equal some frozen reg_hash fqn exactly. */
    n = voleith_shipshape_reg_hash_count;
    for (i = 0; i < n; i++) {
        const char *e_fqn = voleith_shipshape_reg_hash[i].fqn;

        if (strlen(e_fqn) == entry_len && strncmp(e_fqn, fqn, entry_len) == 0)
            break;
    }
    if (i == n)
        return -1;

    /* The type substring must resolve to a known node-hash type. */
    if (voleith_shipshape_node_hash_type_by_name(type_start, type_len) == NULL)
        return -1;

    return 0;
}

int
voleith_shipshape_witgen_register_construction(
    const char *fqn, voleith_shipshape_witgen_backend_fn fn)
{
    if (fqn == NULL || fn == NULL)
        return -1;
    if (s_count >= WITGEN_DISPATCH_CAPACITY)
        return -1;

    /*
     * Structural keying requires the name to be a well-formed known crypto-v2
     * bracketed construction name.  A malformed or unknown name is rejected so
     * a typo cannot silently register a backend that never fires.
     */
    if (construction_name_valid(fqn) != 0)
        return -1;

    s_table[s_count].fqn = fqn;
    s_table[s_count].by_name = 2;
    memset(s_table[s_count].body_hash, 0,
           VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES);
    s_table[s_count].fn = fn;
    s_count++;
    return 0;
}

void
voleith_shipshape_witgen_reset(void)
{
    s_count = 0;
}

/*
 * Entry-kind-aware resolver: given a region, look it up in the frozen crypto-v1
 * registry and, if the entry is FIXED, return a pointer to its single frozen
 * body hash.
 *
 * Returns a pointer to the body_hash bytes on a FIXED match, or NULL if the
 * region name is not in the registry or the entry is not FIXED.
 *
 * Guardrail (W8.2 scope):
 *   - FIXED entries: resolved here, dispatch is by (name, exact hash).
 *   - PARAMETRIC entries: not dispatchable in W8.2.  Parametric backends will
 *     authenticate structurally (name + registry version), not by an exact
 *     per-instantiation hash, because each parameter value yields a distinct
 *     body hash.
 *   - REG_HASH_PARAM (crypto-v2 hash-parametric) entries: not handled here.
 *     Construction dispatch keys off the bracketed region name and cv2_valid
 *     in voleith_shipshape_witgen_lookup (W8.5a), not the frozen body hash.
 */
static const uint8_t *
resolve_fixed_body_hash(const voleith_shipshape_region_t *region)
{
    size_t n = voleith_shipshape_registry_count;
    size_t i;

    for (i = 0; i < n; i++) {
        if (strcmp(voleith_shipshape_registry[i].fqn, region->name) != 0)
            continue;
        /* Name matched.  Only FIXED entries are dispatchable in W8.2. */
        if (voleith_shipshape_registry[i].kind != VOLEITH_SHIPSHAPE_REG_FIXED)
            return NULL;
        /* FIXED entries have exactly one body (param == 0, ignored). */
        return voleith_shipshape_registry[i].bodies[0].hash;
    }
    return NULL;
}

voleith_shipshape_witgen_backend_fn
voleith_shipshape_witgen_lookup(const voleith_shipshape_region_t *region)
{
    voleith_shipshape_reg_kind_t kind;
    size_t ti;

    /* Early-out: nothing registered means no region dispatches. */
    if (s_count == 0)
        return NULL;

    /*
     * Resolve the region's registry kind.  A name absent from the crypto-v1
     * registry is either a crypto-v2 construction call (bracketed "fqn[type]",
     * region->cv2_valid set) or an unrelated name.  For a construction region,
     * match a by_name == 2 table entry on the exact bracketed name (W8.5a);
     * anything else never dispatches and the generic pass suffices.
     */
    if (registry_kind_of(region->name, &kind) != 0) {
        if (region->cv2_valid) {
            for (ti = 0; ti < s_count; ti++) {
                if (s_table[ti].by_name != 2)
                    continue;
                if (strcmp(s_table[ti].fqn, region->name) != 0)
                    continue;
                return s_table[ti].fn;
            }
        }
        return NULL;
    }

    if (kind == VOLEITH_SHIPSHAPE_REG_FIXED) {
        const uint8_t *frozen_hash = resolve_fixed_body_hash(region);

        if (frozen_hash == NULL)
            return NULL;

        /* Search the table for a (name, exact hash) match. */
        for (ti = 0; ti < s_count; ti++) {
            if (s_table[ti].by_name != 0)
                continue;
            if (strcmp(s_table[ti].fqn, region->name) != 0)
                continue;
            /*
             * Name matched.  Verify the hash with a constant-time compare.
             * A mismatch means a different version's backend is registered:
             * fall through to the generic evaluator, no cross-version
             * substitution (parser Goal 2 rule (ii)).
             */
            if (voleith_const_memcmp(
                    s_table[ti].body_hash, frozen_hash,
                    VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES) != 0)
                continue;
            return s_table[ti].fn;
        }
        return NULL;
    }

    if (kind == VOLEITH_SHIPSHAPE_REG_PARAMETRIC) {
        /*
         * Structural name keying (W8.3c): one backend serves every message
         * length, authenticated implicitly by the compiled-in frozen registry.
         * The per-length body hash is advisory, not a gate.  Match on name
         * alone.
         */
        for (ti = 0; ti < s_count; ti++) {
            if (s_table[ti].by_name != 1)
                continue;
            if (strcmp(s_table[ti].fqn, region->name) != 0)
                continue;
            return s_table[ti].fn;
        }
        return NULL;
    }

    /*
     * REG_HASH_PARAM crypto-v2 entries are dispatched, when applicable, via the
     * construction branch above (region->cv2_valid + bracketed name).  Reaching
     * here means a crypto-v1 registry name of some other kind: no dispatch.
     */
    return NULL;
}

int
voleith_shipshape_witgen_invoke_region(const voleith_shipshape_region_t *region,
                                       voleith_shipshape_witgen_backend_fn fn,
                                       const voleith_gf8_t *value,
                                       size_t n_wires, uint8_t *full,
                                       size_t n_witness_total)
{
    size_t n_in = region->n_inputs;
    uint8_t *ext_scratch = NULL;
    size_t k;
    int rc;

    /*
     * I1: defense-in-depth.  The backend writes
     * full[region->first_witness .. first_witness + region->n_witness); that
     * span must lie within the n_witness_total-byte witness buffer.  Every
     * parser-produced circuit satisfies this (a region span is a sub-range of
     * the witness array), but a hand-built parsed_t might not.  Reject an
     * out-of-range span here rather than letting the backend write past `full`.
     * The subtraction is overflow-safe: first_witness <= n_witness_total is
     * checked before n_witness_total - first_witness is formed.
     */
    if (region->first_witness > n_witness_total ||
        region->n_witness > n_witness_total - region->first_witness)
        return -1;

    if (n_in > 0) {
        ext_scratch = calloc(n_in, sizeof(*ext_scratch));
        if (ext_scratch == NULL)
            return -1;
        for (k = 0; k < n_in; k++) {
            gf8_wire_id wid = region->inputs[k];

            /* Guard: wire id must be in range. */
            if ((size_t)wid >= n_wires) {
                /* ext_scratch holds secret witness bytes; zero before free. */
                voleith_secure_zero(ext_scratch, n_in);
                free(ext_scratch);
                return -1;
            }
            ext_scratch[k] = (uint8_t)value[wid];
        }
    }
    rc = fn(region, ext_scratch, n_in, full);
    /*
     * ext_scratch carries the region's secret inputs copied from value[]
     * (for ring_sig/v1 this includes the signer's secret key); zero it before
     * release so no secret material is left on the freed heap (N8-1).
     */
    if (ext_scratch != NULL)
        voleith_secure_zero(ext_scratch, n_in);
    free(ext_scratch);
    return rc;
}
