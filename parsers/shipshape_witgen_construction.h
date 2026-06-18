/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_construction.h - Tier 2a native witness backends for
 * the crypto-v2 hash-parametric CONSTRUCTION registry entries (W8.5b).
 *
 * Three constructions take the node-hash TYPE as a bracketed parameter and a
 * variable tree depth: merkle/path_secret, ring_sig/v1, and
 * indexed_merkle/nonmember_secret.  Each one's INTERNAL inv-witness span is
 * exactly [leaf invs] followed by depth copies of [inode invs], emitted in that
 * order by the generic Tier 1 evaluator (parsers/shipshape_witness.c) as it
 * walks the leaf_circuit then the per-level inode_circuit of the corresponding
 * vt-driven circuit body.  A construction backend reproduces that span natively
 * by composing the node-hash vt's leaf_build_witness with a per-level
 * inode_build_witness walk (the same composition as
 * voleith_rs_membership_pack_witness sections 4 and 5), yielding byte-identical
 * output far faster than the per-byte brute-force inverse.
 *
 * The composition is vt-generic, so every backend is registered under every
 * node-hash type in the frozen node-hash type table: the handler runs only on a
 * region the parser actually built, which it only does for legal widths.
 *
 * This is purely a speed layer.  It is prover-side only and fail-closed
 * (docs/CIRC_WITNESS_GEN.md SECTION 7): a wrong backend yields an invalid
 * proof, never a verifier accept.  The generic evaluator is always the correct
 * fallback, and nothing is registered until the caller invokes the register
 * entry point below before witness generation.
 *
 * Backends are opt-in.  Nothing is registered until the caller invokes the
 * register entry point.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CONSTRUCTION_H
#define VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CONSTRUCTION_H

/*
 * Register the crypto-v2 construction witness backends with the Tier 2a
 * dispatch registry.  For each confirmed construction (merkle/path_secret,
 * ring_sig/v1, indexed_merkle/nonmember_secret) the matching handler is
 * registered under the bracketed name "stdlib/crypto/<entry>[<type>]" for every
 * node-hash type in the frozen node-hash type table.
 *
 * Returns 0 on success.  Returns a negative value if any registration fails
 * (e.g. the dispatch table is full).  On a partial failure the table may hold
 * some of the backends already registered; the caller should reset for a clean
 * slate.
 */
int voleith_shipshape_witgen_register_constructions(void);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CONSTRUCTION_H */
