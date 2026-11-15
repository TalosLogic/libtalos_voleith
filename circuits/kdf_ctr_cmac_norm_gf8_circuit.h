/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * kdf_ctr_cmac_norm_gf8_circuit.h - KDF in Counter Mode (NIST SP
 * 800-108r1-upd1 Section 4.1) using GF(2^8) AES-CMAC with the FAEST
 * paired-round norm S-box.
 *
 * Drop-in sibling of kdf_ctr_cmac_gf8_circuit.h: same derived key material
 * (same NIST KDF, same AES-CMAC PRF), but each inner AES call commits packed
 * 4-bit subfield norms, so the witness is smaller (per-call inv 160/220 vs the
 * frozen 200/276; the AES key schedule stays frozen 8-bit, so only the
 * encryption S-boxes shrink).  The KDF-CTR mode logic is shared verbatim with
 * the frozen circuit through kdf_ctr_cmac_gf8_internal.h.
 */

#ifndef VOLEITH_KDF_CTR_CMAC_NORM_GF8_CIRCUIT_H
#define VOLEITH_KDF_CTR_CMAC_NORM_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "aes_cmac_norm_gf8_circuit.h" /* aes_cmac_norm_gf8_* helpers */
#include <stddef.h>
#include <stdint.h>

/*
 * kdf_ctr_cmac_norm_gf8_circuit - KDF-CTR(AES-CMAC), norm S-box data path.
 * Arguments and return value match kdf_ctr_cmac_gf8_circuit: returns 0, or -1
 * if (4 + fixed_input_bytes) exceeds the internal stack-VLA bound (circuit
 * left unchanged, `output` unspecified).
 */
int kdf_ctr_cmac_norm_gf8_circuit(voleith_gf8_circuit_t *c,
                                  const gf8_wire_id *key, size_t key_bytes,
                                  const gf8_wire_id *fixed_input,
                                  size_t fixed_input_bytes, gf8_wire_id *output,
                                  size_t output_bytes);

/* Total AES calls: n * aes_cmac_norm_gf8_n_aes_calls(4 + fixed_input_bytes),
 * where n = ceil(output_bytes / 16).  Same as the frozen circuit. */
static inline size_t
kdf_ctr_cmac_norm_gf8_n_aes_calls(size_t output_bytes, size_t fixed_input_bytes)
{
    size_t n = (output_bytes + 15) / 16;
    return n * aes_cmac_norm_gf8_n_aes_calls(4 + fixed_input_bytes);
}

/* Required witness buffer size:
 *   key_bytes + kdf_ctr_cmac_norm_gf8_n_aes_calls(...) * inv_per_call
 * where inv_per_call = AES128_NORM_GF8_WITNESS_BYTES - 16 (AES-128) or
 * AES256_NORM_GF8_WITNESS_BYTES - 32 (AES-256). */
static inline size_t
kdf_ctr_cmac_norm_gf8_witness_bytes(size_t key_bytes, size_t output_bytes,
                                    size_t fixed_input_bytes)
{
    size_t inv_per_call = (key_bytes == 16)
                              ? (AES128_NORM_GF8_WITNESS_BYTES - 16u)
                              : (AES256_NORM_GF8_WITNESS_BYTES - 32u);
    return key_bytes +
           kdf_ctr_cmac_norm_gf8_n_aes_calls(output_bytes, fixed_input_bytes) *
               inv_per_call;
}

/*
 * kdf_ctr_cmac_norm_gf8_build_witness - build the full witness vector.  Layout
 * matches kdf_ctr_cmac_gf8_build_witness ([key][per-AES-call inv_in, in
 * order]), with the norm per-call inv size.  Returns 0, or -1 on internal
 * allocation failure.
 */
int kdf_ctr_cmac_norm_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                                        const uint8_t *fixed_input,
                                        size_t fixed_input_bytes,
                                        size_t output_bytes,
                                        uint8_t *witness_out,
                                        uint8_t *output_out);

#endif /* VOLEITH_KDF_CTR_CMAC_NORM_GF8_CIRCUIT_H */
