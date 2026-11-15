/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_norm_gf8_circuit.c - AES-CMAC as a GF(2^8) element circuit (RFC
 * 4493) with the FAEST paired-round norm S-box.  See
 * aes_cmac_norm_gf8_circuit.h.
 *
 * The CMAC mode logic is shared with the frozen circuit through
 * aes_cmac_gf8_internal.h; this file is the norm instantiation, driving the
 * shared skeletons with norm = 1.  Same tag as the frozen MAC (RFC 4493), 75%
 * of the witness.
 */

#include "aes_cmac_norm_gf8_circuit.h"
#include "aes_cmac_gf8_internal.h"

void
aes_cmac_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                          size_t key_bytes, const gf8_wire_id *message,
                          size_t message_bytes, gf8_wire_id tag[16])
{
    cmac_circuit_skeleton(c, key, key_bytes, message, message_bytes, tag, 1);
}

void
aes_cmac_norm_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                const uint8_t *message, size_t message_bytes,
                                uint8_t *witness_out, uint8_t tag_out[16])
{
    cmac_witness_skeleton(key, key_bytes, message, message_bytes, witness_out,
                          tag_out, 1);
}
