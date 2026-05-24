/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_gf8_circuit.h - AES S-box and AES-128/256 as GF(2⁸) element-level circuits
 *
 * Element-level counterpart to aes_circuit.h. Each wire carries one GF(2⁸)
 * element (one byte) instead of one bit.
 *
 * VOLE slot costs (witness_count increase per call, assuming key wires are
 * already declared by the caller):
 *   aes_gf8_sbox:      1 witness slot (inv_in) + 2 assert_product checks (free)
 *   aes128_gf8_circuit: 200 witness slots (200 S-boxes × 1)
 *   aes256_gf8_circuit: 276 witness slots (276 S-boxes × 1)
 *
 * All linear operations (ShiftRows, MixColumns, AddRoundKey, affine transform,
 * Frobenius squaring) cost zero VOLE slots - they produce wires whose VOLE
 * tags are derived linearly from existing slots.
 *
 * AES byte/state ordering:
 *   - Each AES block/key is represented as 16 (or 32) consecutive gf8_wire_ids.
 *   - Element k of a block array corresponds to byte k of the block.
 *   - AES state is column-major: byte k = state[row=k%4][col=k/4].
 *   - For key and plaintext: element 0 is the first byte (highest-order NIST byte).
 *
 * Witness ordering (for the prover's witness vector):
 *   - Key bytes come first (declared by the caller before calling aes128_gf8_circuit).
 *   - inv_in witnesses for each S-box follow in circuit-evaluation order:
 *       key schedule S-boxes (rounds 1..10, 4 S-boxes each = 40 total)
 *       data path S-boxes (rounds 1..10, 16 S-boxes each = 160 total)
 *   - Use aes128_gf8_build_witness / aes256_gf8_build_witness to construct the
 *     correct witness array for a given key and plaintext.
 *
 * assert_product constraint count:
 *   - Each aes_gf8_sbox call adds 2 assert_product constraints (free checks).
 *   - aes128_gf8_circuit: 400 assert_product constraints total.
 *   - aes256_gf8_circuit: 552 assert_product constraints total.
 */

#ifndef VOLEITH_AES_GF8_CIRCUIT_H
#define VOLEITH_AES_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stdint.h>
#include <stddef.h>

/*
 * AES affine transform matrix (8×8 GF(2), row-major).
 *
 * Applied to the GF(2⁸) inverse element as part of the AES S-box.
 * Row i gives which input bits contribute to output bit i:
 *   out_i = b_i ⊕ b_{i+4 mod 8} ⊕ b_{i+5 mod 8} ⊕ b_{i+6 mod 8} ⊕ b_{i+7 mod 8}
 * (FIPS 197 Section 4.2.1)
 *
 * Exposed here so that sub-circuits (AES-CMAC, KDF) can apply the same
 * affine transform without duplicating the constant.
 */
extern const uint8_t AES_GF8_AFFINE_MATRIX[8];

/*
 * aes_gf8_sbox - AES S-box at element level.
 *
 * Takes one wire `in` (the S-box input byte, in AES GF(2⁸) polynomial basis).
 * Internally adds one witness wire `inv_in` (prover supplies in^{-1}, or 0 if
 * in = 0) and two assert_product constraints:
 *   assert_product(in², inv_in, in)    checks: in² · inv_in = in
 *   assert_product(in, inv_in², inv_in) checks: in · inv_in² = inv_in
 * These two constraints together prove inv_in = in^{-1} (Proposition 6.4 from
 * the FAEST spec Section 6.2), with trivial satisfaction at x = y = 0.
 * The affine transform and XOR 0x63 are free (GF(2)-linear gates).
 *
 * Returns the wire holding the S-box output byte.
 * VOLE slot cost: 1 (the inv_in witness wire only; assert_product is free).
 * assert_product count: +2.
 */
gf8_wire_id aes_gf8_sbox(voleith_gf8_circuit_t *c, gf8_wire_id in);

/*
 * aes128_gf8_circuit - AES-128 encryption as a GF(2⁸) element circuit.
 *
 * key[0..15]:       16 GF(2⁸) wires for key bytes 0..15
 * plaintext[0..15]: 16 GF(2⁸) wires for plaintext bytes 0..15
 * output[0..15]:    receives 16 GF(2⁸) wire IDs for ciphertext bytes 0..15
 *
 * Adds 200 witness wires (inv_in per S-box) and 400 assert_product constraints.
 * ell contribution: 200 (from 200 aes_gf8_sbox calls).
 *
 * Typical usage:
 *   gf8_wire_id key[16], pt[16], ct[16];
 *   for (int i = 0; i < 16; i++) key[i] = voleith_gf8_add_witness(c);
 *   for (int i = 0; i < 16; i++) pt[i]  = voleith_gf8_add_instance(c);
 *   aes128_gf8_circuit(c, key, pt, ct);
 *   // witness_count = 16 (key) + 200 (inv_in) = 216
 *   // ell = 216, assert_product_count = 400
 */
void aes128_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[16],
                        const gf8_wire_id plaintext[16],
                        gf8_wire_id output[16]);

/*
 * aes256_gf8_circuit - AES-256 encryption as a GF(2⁸) element circuit.
 *
 * key[0..31]:       32 GF(2⁸) wires for key bytes 0..31
 * plaintext[0..15]: 16 GF(2⁸) wires for plaintext bytes 0..15
 * output[0..15]:    receives 16 GF(2⁸) wire IDs for ciphertext bytes 0..15
 *
 * Adds 276 witness wires (inv_in per S-box) and 552 assert_product constraints.
 */
void aes256_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[32],
                        const gf8_wire_id plaintext[16],
                        gf8_wire_id output[16]);

/*
 * aes128_gf8_build_witness - construct the full witness vector for AES-128.
 *
 * Computes the 216-byte witness array for aes128_gf8_circuit:
 *   witness[0..15]:   key bytes
 *   witness[16..55]:  inv_in for 10 key schedule SubWord calls (4 S-boxes each)
 *   witness[56..215]: inv_in for 10 data path SubBytes rounds (16 S-boxes each)
 *
 * key[16]:         AES-128 key bytes
 * plaintext[16]:   plaintext bytes (needed to trace data path S-box inputs)
 * witness[216]:    output witness array (caller allocates, 216 bytes)
 * ciphertext[16]:  if non-NULL, receives the AES-128(key, plaintext) result
 */
void aes128_gf8_build_witness(const uint8_t key[16],
                              const uint8_t plaintext[16], uint8_t witness[216],
                              uint8_t ciphertext[16]);

/*
 * aes256_gf8_build_witness - construct the full witness vector for AES-256.
 *
 * Computes the 308-byte witness array for aes256_gf8_circuit:
 *   witness[0..31]:   key bytes
 *   witness[32..83]:  inv_in for key schedule SubWord calls (52 S-boxes)
 *   witness[84..307]: inv_in for 14 data path SubBytes rounds (224 S-boxes)
 *
 * key[32]:         AES-256 key bytes
 * plaintext[16]:   plaintext bytes
 * witness[308]:    output witness array (caller allocates, 308 bytes)
 * ciphertext[16]:  if non-NULL, receives the AES-256(key, plaintext) result
 */
void aes256_gf8_build_witness(const uint8_t key[32],
                              const uint8_t plaintext[16], uint8_t witness[308],
                              uint8_t ciphertext[16]);

#endif /* VOLEITH_AES_GF8_CIRCUIT_H */
