/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_gf8_circuit.c - AES-CMAC as a GF(2⁸) element circuit (RFC 4493)
 *
 * Element-level port of aes_cmac_circuit.c. Each wire carries one GF(2⁸)
 * element (one byte) instead of one bit. The shift_xor_rb operation is
 * implemented via per-byte GF(2) linear maps - no mul gates required.
 * All VOLE cost comes from the AES calls inside (200 or 276 witness slots each).
 *
 * The CMAC mode logic (subkey generation, CBC-MAC chaining, last-block
 * padding, witness layout) lives in aes_cmac_gf8_internal.h, shared with the
 * norm-S-box variant (aes_cmac_norm_gf8_circuit.c).  This file is the frozen
 * 8-bit-inverse instantiation: it drives the shared skeletons with norm = 0,
 * so the emitted circuit, its fingerprint and the RFC 4493 KATs are exactly
 * what they were before the skeleton was extracted.
 */

#include "aes_cmac_gf8_circuit.h"
#include "aes_cmac_gf8_internal.h"

void
aes_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                     size_t key_bytes, const gf8_wire_id *message,
                     size_t message_bytes, gf8_wire_id tag[16])
{
    cmac_circuit_skeleton(c, key, key_bytes, message, message_bytes, tag, 0);
}

void
aes_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                           const uint8_t *message, size_t message_bytes,
                           uint8_t *witness_out, uint8_t tag_out[16])
{
    cmac_witness_skeleton(key, key_bytes, message, message_bytes, witness_out,
                          tag_out, 0);
}
