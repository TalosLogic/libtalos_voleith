/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_circuit_fingerprint.h - 16-byte SHAKE-128 fingerprint over a GF(2^16)
 *                              element-level circuit.
 *
 * Parallel to gf8_circuit_fingerprint.h for the GF(2^16) circuit type.  Used
 * by the proof metadata header (proof_header.h) to bind a GF(2^16) proof to a
 * specific circuit identity.
 *
 * Canonical serialization (input to SHAKE-128):
 *
 *   domain_tag   = "voleith-gf16-circuit-cf-v1" || 0x00   (27 bytes)
 *   u32_le n_wires
 *   u32_le n_witness
 *   u32_le n_instance
 *   u32_le n_mul
 *   u32_le n_constraints
 *   for each wire in declaration order:
 *       u8      kind         (matches gf16_wire_kind_t: WITNESS=0, INSTANCE=1,
 *                             CONST=2, XOR=3, XOR_CONST=4, LINEAR_MAP=5,
 *                             SQUARE=6, MUL=7)
 *       u32_le  a            (0 if the kind has no first input)
 *       u32_le  b            (0 if the kind has no second input)
 *       u32_le  const_val    (0 unless kind == CONST or XOR_CONST)
 *       u32_le  matrix[16]   (zero-filled unless kind == LINEAR_MAP; each row
 *                             absorbed little-endian for cross-platform
 *                             determinism)
 *   for each constraint in declaration order:
 *       u8      kind         (GF16_CONSTRAINT_ZERO=0, EQUAL=1, PRODUCT=2)
 *       u32_le  a
 *       u32_le  b            (0 if the kind has no second operand)
 *       u32_le  c            (0 unless kind == PRODUCT)
 *
 * GF16_WIRE_ID_INVALID (= UINT32_MAX) in unused operand positions is
 * normalized to 0 on the wire so the fingerprint is stable regardless of
 * which sentinel a producer uses internally.  The "-v1" suffix pins the
 * layout; any future encoding change MUST come with a new tag.
 */

#ifndef VOLEITH_GF16_CIRCUIT_FINGERPRINT_H
#define VOLEITH_GF16_CIRCUIT_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#include "gf16_circuit.h"

#define VOLEITH_GF16_CIRCUIT_FINGERPRINT_BYTES 16
#define VOLEITH_GF16_CIRCUIT_FINGERPRINT_DOMAIN_TAG "voleith-gf16-circuit-cf-v1"

/*
 * Compute SHAKE-128 of the canonical serialization of *circuit, truncated to
 * VOLEITH_GF16_CIRCUIT_FINGERPRINT_BYTES bytes, written to out.
 *
 * Returns 0 on success, -1 if circuit or out is NULL.
 */
int voleith_gf16_circuit_fingerprint(
    const voleith_gf16_circuit_t *circuit,
    uint8_t out[VOLEITH_GF16_CIRCUIT_FINGERPRINT_BYTES]);

#endif /* VOLEITH_GF16_CIRCUIT_FINGERPRINT_H */
