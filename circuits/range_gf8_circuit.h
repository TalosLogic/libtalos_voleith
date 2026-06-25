/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * range_gf8_circuit.h - bounded-range / interval assertion as a GF(2^8)
 * element circuit.
 *
 * assert_in_range_gf8 constrains low <= value <= high (inclusive) for
 * n_bytes-wide unsigned little-endian byte-vector wires (byte 0 = LSB),
 * failing the proof otherwise.  It packages the common "value in
 * [low, high]" pattern (timestamp validity windows, version-number
 * floors, numeric attribute thresholds) so callers do not hand-wire two
 * comparators and reason about inclusivity each time.
 *
 * This is a Layer 4 C circuit builder composed of existing Tier 1 gates
 * (bit-extract linear maps + assert_product + assert_zero); it is NOT a
 * Shipshape opcode (the Tier 1 opcode set is closed) and has no .ship
 * surface of its own, mirroring the existing assert_lt comparator.
 *
 * Cost: two strict comparisons, each 3 GF(2^8) mul gates per bit
 * (3 * 8 * n_bytes), so 6 * 8 * n_bytes mul gates total, plus two
 * assert_zero constraints.  Adds no witness slots.
 */

#ifndef VOLEITH_RANGE_GF8_CIRCUIT_H
#define VOLEITH_RANGE_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stddef.h>

/*
 * Assert low <= value <= high (inclusive) for three n_bytes-wide
 * unsigned little-endian byte-vector wire arrays (byte 0 = LSB byte).
 *
 * Soundness-critical: a value outside [low, high] makes the circuit
 * unsatisfiable, so the prover cannot produce a verifying proof.  The
 * bounds may be witness, instance, or constant wires; a caller wanting
 * compile-time bounds passes them as voleith_gf8_add_const wires.
 *
 * Implemented as value >= low  (i.e. NOT(value < low)) AND
 *                  value <= high (i.e. NOT(high < value)), which avoids
 * any +/-1 boundary overflow.
 */
void assert_in_range_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *value,
                         const gf8_wire_id *low, const gf8_wire_id *high,
                         size_t n_bytes);

#endif /* VOLEITH_RANGE_GF8_CIRCUIT_H */
