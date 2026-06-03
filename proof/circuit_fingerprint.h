/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * circuit_fingerprint.h - 16-byte SHAKE-128 fingerprint over a circuit.
 *
 * Used by the proof metadata header (proof_header.h) to bind a proof to
 * a specific circuit identity.  Verifiers re-compute the fingerprint
 * over their caller-supplied circuit and compare it to the value
 * carried in the header; mismatch is rejected before any crypto runs.
 *
 * Canonical serialization (input to SHAKE-128):
 *
 *   domain_tag   = "voleith-circuit-cf-v1" || 0x00   (22 bytes)
 *   u32_le n_wires
 *   u32_le n_witness
 *   u32_le n_instance
 *   u32_le n_and
 *   u32_le n_constraints
 *   for each wire in declaration order:
 *       u8     kind         (matches wire_kind_t: WITNESS=0, INSTANCE=1,
 *                            CONST=2, XOR=3, AND=4, NOT=5)
 *       u32_le a            (0 if the kind has no first input)
 *       u32_le b            (0 if the kind has no second input)
 *       u8     const_bit    (0 unless kind == CONST)
 *   for each constraint in declaration order:
 *       u8     kind         (CONSTRAINT_ZERO=0, CONSTRAINT_EQUAL=1)
 *       u32_le a
 *       u32_le b            (0 if the kind has no second operand)
 *
 * WIRE_ID_INVALID (= UINT32_MAX) in unused operand positions is
 * normalized to 0 on the wire so the fingerprint is stable regardless
 * of which sentinel a producer uses internally.
 *
 * The "-v1" suffix in the domain tag pins this layout.  Any future
 * change to the canonical encoding MUST come with a new tag (e.g.
 * "-v2") so cross-version proofs fail loudly rather than silently
 * binding to the wrong bytes.
 */

#ifndef VOLEITH_CIRCUIT_FINGERPRINT_H
#define VOLEITH_CIRCUIT_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#include "circuit.h"

#define VOLEITH_CIRCUIT_FINGERPRINT_BYTES 16
#define VOLEITH_CIRCUIT_FINGERPRINT_DOMAIN_TAG "voleith-circuit-cf-v1"

/*
 * Compute SHAKE-128 of the canonical serialization of *circuit, truncated
 * to VOLEITH_CIRCUIT_FINGERPRINT_BYTES bytes, and write the result to out.
 *
 * Deterministic: given two circuits with identical wire-by-wire and
 * constraint-by-constraint encodings, the function returns the same 16
 * bytes.  Reordering wires or constraints, changing any operand, or
 * changing the domain tag changes the output.
 *
 * Returns 0 on success, -1 if circuit or out is NULL.  Does not modify
 * out on failure.
 */
int voleith_circuit_fingerprint(const voleith_circuit_t *circuit,
                                uint8_t out[VOLEITH_CIRCUIT_FINGERPRINT_BYTES]);

#endif /* VOLEITH_CIRCUIT_FINGERPRINT_H */
