/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witgen_cmac_grostl.h - Tier 2a native witness backends for
 * the PARAMETRIC cmac/<...> and grostl/<...> registry entries (W8.3c).
 *
 * Registers structural-name-keyed witness backends for the six PARAMETRIC
 * crypto-v1 entries (cmac/aes_128, cmac/aes_256, grostl/hash_256,
 * grostl/hash_256_t27, grostl/hash_512, grostl/hash_512_t59).  Each backend
 * wraps the matching builder in circuits/aes_cmac_gf8_circuit.h or
 * circuits/grostl_gf8_circuit.h, which emits inv_in bytes in the exact
 * circuit-evaluation order the generic Tier 1 evaluator fills.  The output is
 * therefore byte-identical to the generic path: this is purely a speed layer
 * (the witness-generation design SECTION 7).
 *
 * PARAMETRIC entries take a variable message length, so a single exact body
 * hash cannot pin a backend.  These register through the structural-keying
 * path (voleith_shipshape_witgen_register_parametric): one backend per name
 * serves every message length, deriving the length from ext_len.
 *
 * The grostl t27 / t59 truncations affect only OUTPUT wires, not the internal
 * inv_in trace, so hash_256 and hash_256_t27 share one handler (registered
 * under both names), as do hash_512 and hash_512_t59.  Four handlers, six
 * registrations.
 *
 * Backends are opt-in.  Nothing is registered until the caller invokes the
 * register entry points below before witness generation.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CMAC_GROSTL_H
#define VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CMAC_GROSTL_H

/*
 * Register the two PARAMETRIC cmac/<...> witness backends (cmac/aes_128,
 * cmac/aes_256) with the Tier 2a dispatch registry through the
 * structural-name-keying path.
 *
 * Returns 0 on success.  Returns a negative value if any name is not a
 * PARAMETRIC entry in the frozen registry or any registration fails (e.g. the
 * dispatch table is full).  On a partial failure the table may hold some of
 * the backends already registered; the caller should reset for a clean slate.
 */
int voleith_shipshape_witgen_register_cmac(void);

/*
 * Register the four PARAMETRIC grostl/<...> witness backends (hash_256,
 * hash_256_t27, hash_512, hash_512_t59) with the Tier 2a dispatch registry.
 * Two handlers serve the four names: the t27 / t59 variants differ only in
 * output byte count, not in the inv_in witness trace.
 *
 * Returns 0 on success, a negative value on any failure (see
 * voleith_shipshape_witgen_register_cmac for the failure modes).
 */
int voleith_shipshape_witgen_register_grostl(void);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_WITGEN_CMAC_GROSTL_H */
