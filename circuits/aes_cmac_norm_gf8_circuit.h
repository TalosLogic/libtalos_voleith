/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_norm_gf8_circuit.h - AES-CMAC as a GF(2^8) element circuit (RFC
 * 4493) with the FAEST paired-round norm S-box.
 *
 * Drop-in sibling of aes_cmac_gf8_circuit.h: same MAC (same tag, RFC 4493), but
 * each inner AES call commits packed 4-bit subfield norms instead of one
 * inverse byte per S-box, so the witness is 75% of the frozen circuit's (160
 * inv_in bytes per AES-128 call, 220 per AES-256 call).  The CMAC mode logic is
 * shared verbatim with the frozen circuit through aes_cmac_gf8_internal.h.
 */

#ifndef VOLEITH_AES_CMAC_NORM_GF8_CIRCUIT_H
#define VOLEITH_AES_CMAC_NORM_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "aes_norm_gf8_circuit.h" /* AES{128,256}_NORM_GF8_WITNESS_BYTES */
#include <stddef.h>
#include <stdint.h>

/*
 * aes_cmac_norm_gf8_circuit - AES-CMAC, norm S-box data path.  Arguments match
 * aes_cmac_gf8_circuit: key (key_bytes = 16 or 32), message (message_bytes,
 * may be NULL when 0), tag receives the 16-byte CMAC tag.
 */
void aes_cmac_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                               size_t key_bytes, const gf8_wire_id *message,
                               size_t message_bytes, gf8_wire_id tag[16]);

/*
 * Total number of AES calls: 1 (subkey) + n_cbc, where
 * n_cbc = max(1, ceil(message_bytes / 16)).  Same as the frozen circuit.
 */
static inline size_t
aes_cmac_norm_gf8_n_aes_calls(size_t message_bytes)
{
    size_t n_full = message_bytes / 16;
    int needs_padding = (message_bytes == 0) || (message_bytes % 16 != 0);
    return (needs_padding ? n_full + 1 : n_full) + 1;
}

/*
 * Required witness buffer size for aes_cmac_norm_gf8_build_witness:
 *   key_bytes + n_aes_calls * inv_per_call
 * where inv_per_call = AES128_NORM_GF8_WITNESS_BYTES - 16 (AES-128) or
 * AES256_NORM_GF8_WITNESS_BYTES - 32 (AES-256).
 */
static inline size_t
aes_cmac_norm_gf8_witness_bytes(size_t key_bytes, size_t message_bytes)
{
    size_t inv_per_call = (key_bytes == 16)
                              ? (AES128_NORM_GF8_WITNESS_BYTES - 16u)
                              : (AES256_NORM_GF8_WITNESS_BYTES - 32u);
    return key_bytes +
           aes_cmac_norm_gf8_n_aes_calls(message_bytes) * inv_per_call;
}

/*
 * aes_cmac_norm_gf8_build_witness - build the full witness vector.  Layout:
 *   [key_bytes key]
 *   [inv_per_call per AES call, in order: subkey AES, then each CBC block]
 * witness_out must hold aes_cmac_norm_gf8_witness_bytes bytes; tag_out, if
 * non-NULL, receives the 16-byte CMAC tag.
 */
void aes_cmac_norm_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                     const uint8_t *message,
                                     size_t message_bytes, uint8_t *witness_out,
                                     uint8_t tag_out[16]);

#endif /* VOLEITH_AES_CMAC_NORM_GF8_CIRCUIT_H */
