/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_norm_gf8_circuit.c - KDF in Counter Mode (NIST SP
 * 800-108r1-upd1 Section 4.1) using GF(2^8) AES-CMAC with the FAEST
 * paired-round norm S-box.  See kdf_ctr_cmac_norm_gf8_circuit.h.
 *
 * The KDF-CTR mode logic is shared with the frozen circuit through
 * kdf_ctr_cmac_gf8_internal.h; this file is the norm instantiation, driving the
 * shared skeletons with norm = 1.  Same derived key material as the frozen
 * KDF, smaller witness.
 */

#include "kdf_ctr_cmac_norm_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_internal.h"

int
kdf_ctr_cmac_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                              size_t key_bytes, const gf8_wire_id *fixed_input,
                              size_t fixed_input_bytes, gf8_wire_id *output,
                              size_t output_bytes)
{
    return kdf_circuit_skeleton(c, key, key_bytes, fixed_input,
                                fixed_input_bytes, output, output_bytes, 1);
}

int
kdf_ctr_cmac_norm_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                    const uint8_t *fixed_input,
                                    size_t fixed_input_bytes,
                                    size_t output_bytes, uint8_t *witness_out,
                                    uint8_t *output_out)
{
    return kdf_witness_skeleton(key, key_bytes, fixed_input, fixed_input_bytes,
                                output_bytes, witness_out, output_out, 1);
}
