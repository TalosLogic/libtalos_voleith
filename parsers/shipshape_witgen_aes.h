/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_aes.h - Tier 2a native witness backends for the
 * FIXED aes/<...> registry entries (W8.3b).
 *
 * Registers fast, hash-pinned witness backends for the seven FIXED aes/<...>
 * crypto-v1 registry entries (sbox, keyschedule_128, encrypt_rounds_128,
 * encrypt_128, keyschedule_256, encrypt_rounds_256, encrypt_256).  Each
 * backend wraps the matching builder in circuits/aes_gf8_circuit.h, which
 * emits inv_in bytes in the exact circuit-evaluation order the generic Tier 1
 * evaluator fills.  The output is therefore byte-identical to the generic
 * path: this is purely a speed layer (the witness-generation design SECTION 7).
 *
 * Backends are opt-in.  Nothing is registered until the caller invokes
 * voleith_shipshape_witgen_register_aes() before witness generation.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_WITGEN_AES_H
#define VOLEITH_PARSERS_SHIPSHAPE_WITGEN_AES_H

/*
 * Register the seven FIXED aes/<...> witness backends with the Tier 2a dispatch
 * registry (parsers/shipshape_witgen_dispatch.h).
 *
 * Each entry is resolved by scanning the frozen crypto-v1 registry for its
 * fully-qualified name, fetching the single frozen body hash via
 * voleith_shipshape_registry_body_hash(idx, 0, ...), and registering the
 * (fqn, hash, backend) triple.  The fqn strings are static literals borrowed
 * by the registry.
 *
 * Returns 0 on success.  Returns a negative value if any name is missing from
 * the registry, any body-hash lookup fails, or any registration fails (e.g.
 * the dispatch table is full).  On a partial failure the table may hold some
 * of the backends already registered; the caller should reset if it needs a
 * clean slate.
 */
int voleith_shipshape_witgen_register_aes(void);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_WITGEN_AES_H */
