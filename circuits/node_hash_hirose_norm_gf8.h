/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_norm_gf8.h - Hirose double-block node hash, FAEST
 * paired-round norm S-box data path.
 *
 * Drop-in siblings of voleith_node_hash_hirose / _hirose_fixed32 /
 * _hirose_fixed96: same node output (same Hirose construction, same IV
 * and c constants, same 128-bit collision resistance, same 14 AES-256
 * rounds), but the two inner AES-256 encryptions per iteration commit
 * packed 4-bit subfield norms, so the per-iteration witness is 388
 * bytes instead of 500 (the AES-256 KEY SCHEDULE STAYS FROZEN 8-bit, so
 * only the two encryptions' S-boxes shrink: 52 KS + 2*168 enc vs 52 +
 * 2*224).  Round count and the dense c constants are unchanged, so the
 * dense-c / full-round quantum-collision posture is preserved.
 *
 * The construction bodies are shared verbatim with the frozen vts
 * through node_hash_hirose_gf8_internal.h.  The vt instances are
 * declared in node_hash_vt.h (the umbrella vt header).
 */

#ifndef VOLEITH_NODE_HASH_HIROSE_NORM_GF8_H
#define VOLEITH_NODE_HASH_HIROSE_NORM_GF8_H

#include "../proof/gf8_circuit.h"
#include "node_hash_vt.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Per-iteration inv_in witness bytes for the norm data path:
 *   AES256_GF8_KS_INVIN_BYTES (52, frozen)
 *     + 2 * AES256_NORM_GF8_ENC_INVIN_BYTES (168)
 *   = 388.
 * Exposed as a #define for stack buffers and via the
 * hirose_norm_gf8_iteration_witness_bytes() accessor (ABI symmetry with
 * the frozen primitive).
 */
#define HIROSE_NORM_GF8_ITERATION_WITNESS_BYTES 388

size_t hirose_norm_gf8_iteration_witness_bytes(void);

/*
 * hirose_norm_gf8_iteration_circuit / _build_witness - one Hirose
 * iteration with the norm encryptions.  Arguments and semantics match
 * hirose_gf8_iteration_circuit / _build_witness (same G/H/M/c_const and
 * optional G_out/H_out outputs); the only differences are the norm
 * encryptions and the 388-byte inv_in size.  Exposed so the iteration
 * primitive can be tested directly, mirroring the frozen API.
 */
void hirose_norm_gf8_iteration_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id G[16], const gf8_wire_id H[16],
    const gf8_wire_id M[16], const uint8_t c_const[16], gf8_wire_id G_out[16],
    gf8_wire_id H_out[16]);

void hirose_norm_gf8_iteration_build_witness(
    const uint8_t G[16], const uint8_t H[16], const uint8_t M[16],
    const uint8_t c_const[16],
    uint8_t inv_out[HIROSE_NORM_GF8_ITERATION_WITNESS_BYTES], uint8_t G_out[16],
    uint8_t H_out[16]);

#endif /* VOLEITH_NODE_HASH_HIROSE_NORM_GF8_H */
