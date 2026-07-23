/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_witness.h - generic Tier 1 witness generator for parsed
 * Shipshape (.ship) circuits.
 *
 * Completes the full witness array (one byte per WITNESS wire, canonical
 * order; ISA 2.11) that voleith_gf8_prove consumes, from the external
 * witness input (only the file-declared WITNESS wires) and the instance
 * input.  The gap is the gadget-internal witnesses introduced by lowering:
 * in Tier 1, the INV output, which the evaluator computes as the GF(2^8)
 * inverse of its source wire, resolved from the defining ASSERT_PRODUCT
 * constraint.  See the witness-generation design (W6.1) for the full design,
 * including the deferred Tier 2a hash-pinned dispatch interface.
 *
 * This is the generic evaluator (W6.2); it is the trusted reference and the
 * always-available path.  It reproduces, byte for byte, the output of the
 * hand-written circuits/<...>_build_witness helpers for the registry circuits.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_WITNESS_H
#define VOLEITH_PARSERS_SHIPSHAPE_WITNESS_H

#include <stddef.h>
#include <stdint.h>

#include "shipshape.h"

/* ================================================================
 * Error codes (negative; mirror voleith_shipshape_error_t conventions)
 * ================================================================ */

typedef enum {
    VOLEITH_SHIPSHAPE_WITGEN_NULL_ARG = -1, /* required pointer argument NULL */
    VOLEITH_SHIPSHAPE_WITGEN_ALLOC = -2,    /* allocation failure */
    VOLEITH_SHIPSHAPE_WITGEN_EXT_LEN = -3,  /* external input length mismatch */
    VOLEITH_SHIPSHAPE_WITGEN_INSTANCE_LEN = -4, /* instance length mismatch */
    VOLEITH_SHIPSHAPE_WITGEN_UNRESOLVED = -5,   /* internal witness, no INV
                                                   defining constraint (4) */
    VOLEITH_SHIPSHAPE_WITGEN_CONSTRAINT = -6,   /* self-check: a constraint is
                                                   violated by the input */
} voleith_shipshape_witgen_error_t;

/* flags for voleith_shipshape_witness_gen */
#define VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK 0x1u /* evaluate constraints (5) */

/*
 * Number of external witness bytes the circuit expects: the sum of the
 * lengths of its top-level WITNESS declarations (distinct from the full
 * witness_count, which also counts gadget-internal INV outputs).  Returns 0
 * if parsed is NULL.
 */
size_t voleith_shipshape_external_witness_len(
    const voleith_shipshape_parsed_t *parsed);

/*
 * Generate the full witness array for a parsed circuit.
 *
 * ext_witness / ext_witness_len: one byte per external WITNESS wire, in
 *   declaration order.  ext_witness_len MUST equal
 *   voleith_shipshape_external_witness_len(parsed).
 * instance / instance_len: one byte per INSTANCE wire, in declaration order.
 *   instance_len MUST equal voleith_gf8_circuit_instance_count(circuit); may
 *   be NULL only when that count is 0.
 * flags: 0, or VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK to evaluate the circuit's
 *   constraints against the completed witness and fail on a violation.
 *
 * On success returns 0, sets *out to a freshly allocated buffer of
 * voleith_gf8_circuit_witness_count(circuit) bytes (the caller frees it with
 * free(), and SHOULD voleith_secure_zero it after proving), and sets
 * *out_len to that count.  On failure returns a negative
 * voleith_shipshape_witgen_error_t, with *out set to NULL and *out_len to 0.
 */
int voleith_shipshape_witness_gen(const voleith_shipshape_parsed_t *parsed,
                                  const uint8_t *ext_witness,
                                  size_t ext_witness_len,
                                  const uint8_t *instance, size_t instance_len,
                                  unsigned flags, uint8_t **out,
                                  size_t *out_len);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_WITNESS_H */
