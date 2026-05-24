/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_gf8_circuit.h - AES-CMAC as a GF(2⁸) element circuit (RFC 4493)
 *
 * Element-level counterpart to aes_cmac_circuit.h. Each wire carries one
 * GF(2⁸) element (one byte) instead of one bit.
 *
 * Witness slot cost (AES-128, 200 witness slots per AES call):
 *   Subkey generation:  1 AES call  →  200 slots
 *   CBC-MAC:            n_cbc AES calls  →  n_cbc × 200 slots
 *   Total:              (n_cbc + 1) × 200  where n_cbc = max(1, ceil(msg_bytes/16))
 *
 * For AES-256, replace 200 with 276 per AES call.
 *
 * All GF(2)-linear operations (shift_xor_rb, XOR) are free: zero VOLE slots.
 * The shift_xor_rb operation on 16-byte blocks is implemented via per-byte
 * GF(2) linear maps (see implementation) - no mul gates required.
 */

#ifndef VOLEITH_AES_CMAC_GF8_CIRCUIT_H
#define VOLEITH_AES_CMAC_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/*
 * aes_cmac_gf8_circuit - AES-CMAC as a GF(2⁸) element circuit.
 *
 * key:          GF(2⁸) wire IDs for the AES key (key_bytes wires).
 * key_bytes:    16 (AES-128) or 32 (AES-256).
 * message:      GF(2⁸) wire IDs for the message (message_bytes wires).
 *               May be NULL when message_bytes == 0.
 * message_bytes: message length in bytes (any non-negative value).
 * tag:          receives 16 wire IDs for the 128-bit CMAC tag (one per byte).
 */
void aes_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                          size_t key_bytes, const gf8_wire_id *message,
                          size_t message_bytes, gf8_wire_id tag[16]);

/*
 * Total number of AES calls inside aes_cmac_gf8_circuit:
 *   1 (subkey AES) + n_cbc,  where n_cbc = max(1, ceil(message_bytes / 16)).
 */
static inline size_t
aes_cmac_gf8_n_aes_calls(size_t message_bytes)
{
    size_t n_full = message_bytes / 16;
    int needs_padding = (message_bytes == 0) || (message_bytes % 16 != 0);
    return (needs_padding ? n_full + 1 : n_full) + 1;
}

/*
 * Required witness buffer size (in bytes) for aes_cmac_gf8_build_witness:
 *   key_bytes + aes_cmac_gf8_n_aes_calls(message_bytes) × inv_per_call
 * where inv_per_call = 200 for AES-128, 276 for AES-256.
 */
static inline size_t
aes_cmac_gf8_witness_bytes(size_t key_bytes, size_t message_bytes)
{
    size_t inv_per_call = (key_bytes == 16) ? 200u : 276u;
    return key_bytes + aes_cmac_gf8_n_aes_calls(message_bytes) * inv_per_call;
}

/*
 * aes_cmac_gf8_build_witness - build the full witness vector for aes_cmac_gf8_circuit.
 *
 * Produces a witness array laid out as:
 *   [key_bytes bytes: AES key]
 *   [inv_per_call bytes: inv_in for subkey AES call (L = AES(key, 0^16))]
 *   [inv_per_call bytes: inv_in for 1st CBC block]
 *   ...
 *   [inv_per_call bytes: inv_in for last CBC block]
 *
 * key:           AES key bytes.
 * key_bytes:     16 (AES-128) or 32 (AES-256).
 * message:       message bytes (may be NULL when message_bytes == 0).
 * message_bytes: message length in bytes.
 * witness_out:   caller-allocated buffer of aes_cmac_gf8_witness_bytes bytes.
 * tag_out:       if non-NULL, receives the computed 16-byte CMAC tag.
 */
void aes_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                const uint8_t *message, size_t message_bytes,
                                uint8_t *witness_out, uint8_t tag_out[16]);

#endif /* VOLEITH_AES_CMAC_GF8_CIRCUIT_H */
