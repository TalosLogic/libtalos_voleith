/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_circuit_fingerprint.h - 16-byte SHAKE-128 fingerprint over a GF(2^8)
 *                             element-level circuit.
 *
 * Parallel to circuit_fingerprint.h for the GF(2^8) circuit type.  Used by
 * the proof metadata header (proof_header.h) to bind a GF(2^8) proof to a
 * specific circuit identity.
 *
 * Canonical serialization (input to SHAKE-128):
 *
 *   domain_tag   = "voleith-gf8-circuit-cf-v1" || 0x00   (26 bytes)
 *   u32_le n_wires
 *   u32_le n_witness
 *   u32_le n_instance
 *   u32_le n_mul
 *   u32_le n_constraints
 *   for each wire in declaration order:
 *       u8     kind         (matches gf8_wire_kind_t: WITNESS=0, INSTANCE=1,
 *                            CONST=2, XOR=3, XOR_CONST=4, LINEAR_MAP=5,
 *                            SQUARE=6, MUL=7)
 *       u32_le a            (0 if the kind has no first input)
 *       u32_le b            (0 if the kind has no second input)
 *       u8     const_val    (0 unless kind == CONST or XOR_CONST)
 *       u8[8]  matrix       (zero-filled unless kind == LINEAR_MAP)
 *   for each constraint in declaration order:
 *       u8     kind         (GF8_CONSTRAINT_ZERO=0, EQUAL=1, PRODUCT=2,
 *                            PRODUCT3=3)
 *       u32_le a
 *       u32_le b            (0 if the kind has no second operand)
 *       u32_le c            (0 unless kind == PRODUCT or PRODUCT3)
 *       u32_le d            (ONLY when kind == PRODUCT3; absent otherwise)
 *   AES norm round-pair appendix (ONLY when the circuit has >= 1 norm entry;
 *   entirely absent otherwise, so norm-free circuits are byte-identical):
 *       u32_le n_norm
 *       for each norm entry in declaration order:
 *           u32_le nst
 *           u8     last_pair       (0 or 1)
 *           u32_le wire[4*nst]     (state_in, norm, s_tilde, k0 wire ids)
 *   Grostl norm round-pair appendix (ONLY when the circuit has >= 1 Grostl
 *   norm entry; entirely absent otherwise, so circuits without them are
 *   byte-identical, exactly like the AES norm appendix):
 *       u32_le n_grostl_norm
 *       for each Grostl norm entry in declaration order:
 *           u32_le nst
 *           u32_le cols
 *           u8     is_q            (0 or 1)
 *           u8     odd_round
 *           u8     shift[8]        (ShiftBytes row shifts)
 *           u32_le wire[3*nst]     (state_in, norm, s_tilde wire ids)
 *
 * GF8_WIRE_ID_INVALID (= UINT32_MAX) in unused operand positions is
 * normalized to 0 on the wire so the fingerprint is stable regardless of
 * which sentinel a producer uses internally.
 *
 * The "-v1" suffix in the domain tag pins this layout.  The PRODUCT3 fourth
 * operand and the AES/Grostl norm appendices are appended only for features
 * absent from the original v1 circuits, so no v1 fingerprint changes and the
 * tag still identifies the layout.  Any change that alters an existing encoding
 * MUST come with a new tag.
 */

#ifndef VOLEITH_GF8_CIRCUIT_FINGERPRINT_H
#define VOLEITH_GF8_CIRCUIT_FINGERPRINT_H

#include <stddef.h>
#include <stdint.h>

#include "gf8_circuit.h"

#define VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES 16
#define VOLEITH_GF8_CIRCUIT_FINGERPRINT_DOMAIN_TAG "voleith-gf8-circuit-cf-v1"

/*
 * Compute SHAKE-128 of the canonical serialization of *circuit, truncated
 * to VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES bytes, and write the result to
 * out.
 *
 * Returns 0 on success, -1 if circuit or out is NULL.  Does not modify
 * out on failure.
 */
int voleith_gf8_circuit_fingerprint(
    const voleith_gf8_circuit_t *circuit,
    uint8_t out[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES]);

#endif /* VOLEITH_GF8_CIRCUIT_FINGERPRINT_H */
