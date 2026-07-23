/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_dispatch.h - Tier 2a hash-pinned witness-backend
 * registration and dispatch (W8.2).
 *
 * The generic Tier 1 evaluator (parsers/shipshape_witness.c) closes the gap
 * between the external witness input and the full witness array for any parsed
 * circuit.  For circuits that are mostly large registry calls (AES-CMAC over
 * a long message, a Grostl hash), a crypto-specific backend computes the same
 * internal witnesses far faster by running the primitive natively rather than
 * one byte-multiply at a time.
 *
 * This component is purely a speed layer.  It is prover-side only and
 * fail-closed (the witness-generation design §7.1): a wrong backend yields an
 * invalid proof, never a verifier accept.  The generic evaluator is always
 * the correct fallback.
 *
 * W8.4: backends fill their witness span IN LINE during the single forward
 * pass, not as a post-pass overlay.  The forward pass runs a pre-pass over the
 * regions (voleith_shipshape_witgen_lookup) to find which slots a backend
 * fills, then invokes the backend (voleith_shipshape_witgen_invoke_region) the
 * moment the write cursor reaches the region's first internal witness slot, and
 * reads the backend value for those slots instead of computing the expensive
 * brute-force inverse.  Outermost dispatched regions cover any nested ones.
 *
 * FIXED entries dispatch by (fully-qualified name, frozen body hash) per
 * §7.2.  A name match with a hash mismatch falls through to the generic
 * path; no cross-version substitution.  The hash is the single frozen body
 * hash from the registry table.
 *
 * PARAMETRIC entries (cmac/<...>, grostl/<...>) dispatch by STRUCTURAL name keying
 * (W8.3c): one backend serves every message length, so a per-length body
 * hash cannot pin it.  Authentication is implicit in the binary: the backend
 * table and the frozen registry are compiled together, so a name match
 * against a PARAMETRIC registry entry is sufficient.  The per-length body
 * hash is advisory, not a gate.
 *
 * REG_HASH_PARAM (crypto-v2 hash-parametric) construction entries dispatch by
 * STRUCTURAL bracketed-name keying (W8.5a): the region carries the bracketed
 * name "fqn[type]" plus the resolved construction parameters (cv2_valid set),
 * and a construction backend registered under the exact bracketed name serves
 * it.  Authentication is implicit in the binary, the same model as PARAMETRIC.
 * With no construction backend registered (the production default), these fall
 * through to the generic path exactly as before.
 *
 * Design doc: the witness-generation design §7.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_WITGEN_DISPATCH_H
#define VOLEITH_PARSERS_SHIPSHAPE_WITGEN_DISPATCH_H

#include <stddef.h>
#include <stdint.h>

#include "field.h"
#include "gf8_circuit.h"
#include "shipshape.h"
#include "shipshape_registry.h"

/*
 * Backend function type.  Fill the internal witness bytes for one Tier 2a
 * region.
 *
 * `region` gives the witness span (first_witness, n_witness) in the full
 * array; the backend writes its computed witness bytes into
 * full[region->first_witness .. first_witness+n_witness-1].
 *
 * `ext` / `ext_len`: the region's signature-order input bytes assembled from
 * the forward pass.  `ext[k]` is the value of the wire at
 * `region->inputs[k]` for k in 0..ext_len-1.  This is the per-region
 * external-input slice the backend needs to run the primitive natively.
 *
 * Returns 0 on success.  A nonzero return aborts witness generation: a
 * registered backend that cannot run is a build error, not a silent
 * fallthrough (the witness-generation design §7.3).
 */
typedef int (*voleith_shipshape_witgen_backend_fn)(
    const voleith_shipshape_region_t *region, const uint8_t *ext,
    size_t ext_len, uint8_t *full);

/*
 * Register a Tier 2a witness backend for the FIXED entry identified by
 * (fqn, body_hash).
 *
 * `fqn` must have static lifetime; the registry stores the pointer, not a
 * copy.  `body_hash` is copied into the table.  `fn` is the backend.
 *
 * Returns 0 on success.  Returns a negative value if any argument is NULL,
 * if fn is NULL, or if the registry is full.
 *
 * NOTE: the spec doc (the witness-generation design §7.3) uses the constant name
 * VOLEITH_SHIPSHAPE_BODY_HASH_BYTES; the real symbol in the codebase is
 * VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES (shipshape_registry.h:43).
 * This implementation uses the real symbol.
 */
int voleith_shipshape_witgen_register(
    const char *fqn,
    const uint8_t body_hash[VOLEITH_SHIPSHAPE_REGISTRY_BODY_HASH_BYTES],
    voleith_shipshape_witgen_backend_fn fn);

/*
 * Register a Tier 2a witness backend for the PARAMETRIC entry named `fqn`
 * (W8.3c).
 *
 * PARAMETRIC entries (cmac/<...>, grostl/<...>) take a variable message length, so
 * each length yields a distinct body hash and no single exact hash can pin
 * the backend.  Dispatch is therefore by name only, authenticated implicitly
 * by the compiled-in frozen registry (the backend and the registry table
 * link together).  The one registered backend serves every message length;
 * it derives the length from ext_len.
 *
 * `fqn` must have static lifetime; the registry stores the pointer, not a
 * copy.  `fn` is the backend.
 *
 * Returns 0 on success.  Returns a negative value if any argument is NULL,
 * if the registry is full, or if `fqn` does not name a PARAMETRIC entry in
 * the frozen crypto-v1 registry (absent, or a different kind).  The
 * PARAMETRIC-kind requirement is checked against
 * voleith_shipshape_registry[].kind so a FIXED or hash-parametric name can
 * never be registered through this structural-keying path.
 */
int voleith_shipshape_witgen_register_parametric(
    const char *fqn, voleith_shipshape_witgen_backend_fn fn);

/*
 * Register a Tier 2a witness backend for a crypto-v2 hash-parametric
 * CONSTRUCTION entry named by its bracketed form `fqn` (W8.5a), for example
 * "stdlib/crypto/ring_sig/v1[aes_dm]".
 *
 * Construction entries (merkle/path_secret, indexed_merkle/nonmember_secret,
 * ring_sig/v1) take the node-hash TYPE as a bracketed parameter and a variable
 * tree depth, so no single exact body hash can pin a backend.  Dispatch is
 * therefore by the exact bracketed name only, authenticated implicitly by the
 * compiled-in frozen registry (the backend and the registry table link
 * together).  The matched region carries the resolved construction parameters
 * (cv2_valid, cv2_type_id, cv2_params) the backend uses to drive the walk.
 *
 * `fqn` must have static lifetime; the registry stores the pointer, not a copy.
 * `fn` is the backend.
 *
 * The bracketed name is VALIDATED structurally: it must be of the form
 * "<entry>[<type>]", where <entry> equals some voleith_shipshape_reg_hash[].fqn
 * and <type> resolves via voleith_shipshape_node_hash_type_by_name() to a known
 * node-hash type, and the name must end with ']'.  A malformed or unknown name
 * is rejected.
 *
 * Returns 0 on success.  Returns a negative value if any argument is NULL, if
 * the registry is full, or if `fqn` is not a well-formed known bracketed
 * crypto-v2 construction name.
 */
int voleith_shipshape_witgen_register_construction(
    const char *fqn, voleith_shipshape_witgen_backend_fn fn);

/*
 * Clear the dispatch registry.  Intended for use in tests that need a clean
 * slate between cases; not for production code.
 */
void voleith_shipshape_witgen_reset(void);

/*
 * Look up the registered backend for one region (W8.4 interleaved skip).
 *
 * Resolution mirrors the dispatch decision: the region name is resolved in the
 * frozen crypto-v1 registry.  A FIXED entry matches a by-hash table entry whose
 * name and frozen body hash both agree (constant-time hash compare); a
 * PARAMETRIC entry matches a by-name table entry on name alone.  A crypto-v2
 * construction region (region->cv2_valid set, a bracketed "fqn[type]" name not
 * in the crypto-v1 registry) matches a by-name construction table entry whose
 * fqn equals the bracketed name.  An unrecognised non-construction name never
 * matches.
 *
 * Returns the matched backend function pointer, or NULL if no backend is
 * registered for the region (the generic evaluator handles it).
 *
 * The forward pass calls this once per region in a pre-pass to decide which
 * witness slots a backend will fill, so it can skip the brute-force inverse for
 * those slots and read the backend value instead.
 */
voleith_shipshape_witgen_backend_fn
voleith_shipshape_witgen_lookup(const voleith_shipshape_region_t *region);

/*
 * Invoke one backend for one region (W8.4 interleaved skip).
 *
 * Assembles the per-region ext slice from the forward-pass value array
 * (ext[k] = value[region->inputs[k]] for k in 0..region->n_inputs-1, with an
 * in-range guard on each wire id), calls `fn`, and frees the scratch buffer.
 * `fn` must be the pointer returned by voleith_shipshape_witgen_lookup for the
 * same region.
 *
 * The forward pass calls this the moment its write cursor reaches the region's
 * first internal witness slot, at which point all of the region's input wires
 * already carry values, so the backend can fill
 * full[region->first_witness .. first_witness + n_witness - 1] in line.
 *
 * `n_witness_total` is the length of the `full` witness buffer.  The region's
 * write span [first_witness, first_witness + region->n_witness) is checked to
 * lie within it before the backend runs, so an inconsistent region (only
 * reachable from a hand-built parsed_t, never from the parser) yields a clean
 * error instead of an out-of-bounds write.
 *
 * Returns 0 on success.  Returns a negative value on an out-of-range input wire
 * id, a region span that overflows the witness buffer, an allocation failure,
 * or a nonzero backend return: a registered backend that cannot run is a build
 * error, not a silent fallthrough (the witness-generation design SECTION 7).
 */
int voleith_shipshape_witgen_invoke_region(
    const voleith_shipshape_region_t *region,
    voleith_shipshape_witgen_backend_fn fn, const voleith_gf8_t *value,
    size_t n_wires, uint8_t *full, size_t n_witness_total);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_WITGEN_DISPATCH_H */
