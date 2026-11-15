/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_gf8_circuit.c - KDF in Counter Mode using GF(2⁸) AES-CMAC as PRF
 *
 * NIST SP 800-108r1-upd1, Section 4.1.
 *
 * Per-iteration message (counter before fixed input, r = 32):
 *   K(i) = CMAC(K_IN, [i]_32 || fixed_input),  i = 1..n
 *   K_OUT = leftmost output_bytes of K(1) || ... || K(n)
 *
 * The 4-byte counter [i]_32be is represented as four constant byte-wires,
 * costing zero VOLE slots. All VOLE cost is inside the AES-CMAC calls.
 *
 * The KDF-CTR mode logic lives in kdf_ctr_cmac_gf8_internal.h, shared with the
 * norm-S-box variant (kdf_ctr_cmac_norm_gf8_circuit.c).  This file is the
 * frozen 8-bit-inverse instantiation: it drives the shared skeletons with
 * norm = 0, so the emitted circuit, its fingerprint and the KATs are exactly
 * what they were before the skeleton was extracted.
 */

#include "kdf_ctr_cmac_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_internal.h"

int
kdf_ctr_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                         size_t key_bytes, const gf8_wire_id *fixed_input,
                         size_t fixed_input_bytes, gf8_wire_id *output,
                         size_t output_bytes)
{
    return kdf_circuit_skeleton(c, key, key_bytes, fixed_input,
                                fixed_input_bytes, output, output_bytes, 0);
}

int
kdf_ctr_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                               const uint8_t *fixed_input,
                               size_t fixed_input_bytes, size_t output_bytes,
                               uint8_t *witness_out, uint8_t *output_out)
{
    return kdf_witness_skeleton(key, key_bytes, fixed_input, fixed_input_bytes,
                                output_bytes, witness_out, output_out, 0);
}
