/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_gf8_circuit.h - KDF in Counter Mode using GF(2⁸) AES-CMAC as PRF
 *
 * Element-level counterpart to kdf_ctr_cmac_circuit.h. Each wire carries one
 * GF(2⁸) element (one byte) instead of one bit.
 *
 * Implements NIST SP 800-108r1-upd1 Section 4.1 (KDF in Counter Mode)
 * with AES-CMAC as the pseudorandom function:
 *   K(i) = CMAC(K_IN, [i]_32 || fixed_input),  i = 1, 2, ..., n
 *   K_OUT = leftmost output_bytes of K(1) || K(2) || ... || K(n)
 *
 * where [i]_32 is the 32-bit big-endian encoding of counter i, represented
 * as four constant byte-wires (free in QuickSilver).
 *
 * Witness slot cost:
 *   key_bytes + n × aes_cmac_gf8_n_aes_calls(4 + fixed_input_bytes) × inv_per_call
 * where:
 *   n             = ceil(output_bytes / 16)
 *   inv_per_call  = 200 (AES-128) or 276 (AES-256)
 *
 * All non-S-box operations (counter construction, XOR, shift_xor_rb, CBC chaining)
 * are GF(2)-linear - zero VOLE slots.
 */

#ifndef VOLEITH_KDF_CTR_CMAC_GF8_CIRCUIT_H
#define VOLEITH_KDF_CTR_CMAC_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/*
 * kdf_ctr_cmac_gf8_circuit - KDF in Counter Mode using GF(2⁸) AES-CMAC.
 *
 * c                - circuit to append gates to
 * key              - key_bytes GF(2⁸) wire IDs for the KDK
 * key_bytes        - 16 (AES-128) or 32 (AES-256)
 * fixed_input      - fixed_input_bytes GF(2⁸) wire IDs for FixedInputData;
 *                    may be NULL when fixed_input_bytes == 0
 * fixed_input_bytes - byte length of fixed_input (must be byte-aligned)
 * output           - caller-allocated array of output_bytes wire IDs;
 *                    receives wire IDs for the derived keying material K_OUT
 * output_bytes     - requested output length in bytes (> 0, multiple of 16
 *                    or truncated at the last block)
 *
 * Returns 0 on success; -1 if (4 + fixed_input_bytes) exceeds the
 * internal stack-VLA bound KDF_GF8_MSG_MAX_BYTES (in which case the
 * circuit is left unchanged and the contents of `output` are
 * unspecified - the caller must check the return value before
 * consuming `output`).
 */
int kdf_ctr_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                             size_t key_bytes, const gf8_wire_id *fixed_input,
                             size_t fixed_input_bytes, gf8_wire_id *output,
                             size_t output_bytes);

/*
 * Total number of AES calls inside one invocation:
 *   n = ceil(output_bytes / 16) CMAC iterations, each contributing
 *   aes_cmac_gf8_n_aes_calls(4 + fixed_input_bytes) AES calls.
 */
static inline size_t
kdf_ctr_cmac_gf8_n_aes_calls(size_t output_bytes, size_t fixed_input_bytes)
{
    size_t n = (output_bytes + 15) / 16;
    return n * aes_cmac_gf8_n_aes_calls(4 + fixed_input_bytes);
}

/*
 * Required witness buffer size in bytes:
 *   key_bytes + kdf_ctr_cmac_gf8_n_aes_calls(...) × inv_per_call
 */
static inline size_t
kdf_ctr_cmac_gf8_witness_bytes(size_t key_bytes, size_t output_bytes,
                               size_t fixed_input_bytes)
{
    size_t inv_per_call = (key_bytes == 16) ? 200u : 276u;
    return key_bytes +
           kdf_ctr_cmac_gf8_n_aes_calls(output_bytes, fixed_input_bytes) *
               inv_per_call;
}

/*
 * kdf_ctr_cmac_gf8_build_witness - build the full witness vector.
 *
 * Witness layout:
 *   [key_bytes bytes: KDK]
 *   [inv_per_call bytes: inv_in for each AES call in iteration 1, in order]
 *   [inv_per_call bytes: inv_in for each AES call in iteration 2, in order]
 *   ...
 *
 * key              - KDK bytes
 * key_bytes        - 16 or 32
 * fixed_input      - FixedInputData bytes (may be NULL when 0)
 * fixed_input_bytes - byte length of fixed_input
 * output_bytes     - same value passed to kdf_ctr_cmac_gf8_circuit
 * witness_out      - caller-allocated, kdf_ctr_cmac_gf8_witness_bytes() bytes
 * output_out       - if non-NULL, receives the output_bytes derived key bytes
 *
 * Returns 0 on success; -1 on internal allocation failure (in which
 * case `witness_out` and `output_out` are left in an unspecified
 * state and must not be consumed).
 */
int kdf_ctr_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                   const uint8_t *fixed_input,
                                   size_t fixed_input_bytes,
                                   size_t output_bytes, uint8_t *witness_out,
                                   uint8_t *output_out);

#endif /* VOLEITH_KDF_CTR_CMAC_GF8_CIRCUIT_H */
