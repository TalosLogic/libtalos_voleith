/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_circuit.h - AES S-box and full AES-128/AES-256 as Boolean circuits
 *
 * These functions add gates to an existing voleith_circuit_t to compute
 * AES operations.  All gate inputs and outputs are wire IDs.  Input wires
 * must have been added by the caller before calling these functions.
 *
 * Bit convention throughout:
 *   - Each AES byte is represented as 8 consecutive wire IDs.
 *   - Bit 0 of a byte is the coefficient of x^0 in AES GF(2^8) (LSB of the byte value).
 *   - Bit 7 is the coefficient of x^7 (MSB).
 *   - For a 128-bit key/plaintext/ciphertext block, bits 8*i .. 8*i+7 are byte i.
 *
 * AES byte/state ordering:
 *   - AES state is a 4×4 matrix of bytes.
 *   - Byte k maps to state[k % 4][k / 4] (column-major as in FIPS 197).
 *   - The 128-element wire_id arrays follow byte index 0..15.
 *
 * AND gate cost:
 *   - aes_sbox_circuit:  36 AND gates per S-box invocation
 *   - aes128_circuit:   200 S-box calls × 36 = 7 200 AND gates total
 *   - aes256_circuit:   276 S-box calls × 36 = 9 936 AND gates total
 *
 * (Smaller AND-gate counts are possible with Boyar-Peralta style optimization;
 * this implementation favors clarity over gate minimization.)
 */

#ifndef VOLEITH_AES_CIRCUIT_H
#define VOLEITH_AES_CIRCUIT_H

#include "circuit.h"

/*
 * aes_sbox_circuit - AES S-box as a Boolean circuit (36 AND gates).
 *
 * Appends gates to circuit `c` that compute the AES S-box on the 8 input
 * wire IDs in[0..7] (bit 0 = LSB).  Writes 8 output wire IDs to out[0..7].
 *
 * The S-box is computed as GF(2^8) inversion (via Canright tower field
 * decomposition over GF(2^4)/GF(2^2)) followed by the AES affine transform.
 */
void aes_sbox_circuit(voleith_circuit_t *c, const wire_id in[8],
                      wire_id out[8]);

/*
 * aes128_circuit - AES-128 encryption as a Boolean circuit.
 *
 * Appends gates for a complete AES-128 encryption, including the key
 * schedule.  key[0..127] and plaintext[0..127] are wire IDs for the 128-bit
 * key and 128-bit plaintext respectively; output[0..127] receives wire IDs
 * for the 128-bit ciphertext.
 *
 * Typical usage:
 *   - key wires:       add_witness (private: prover knows the key)
 *   - plaintext wires: add_instance (public: known to both parties)
 *   - ciphertext:      add_instance bits, then assert_equal to output bits
 */
void aes128_circuit(voleith_circuit_t *c, const wire_id key[128],
                    const wire_id plaintext[128], wire_id output[128]);

/*
 * aes256_circuit - AES-256 encryption as a Boolean circuit.
 *
 * key[0..255]: wire IDs for 256-bit key.
 * plaintext[0..127]: wire IDs for 128-bit plaintext.
 * output[0..127]: receives wire IDs for 128-bit ciphertext.
 */
void aes256_circuit(voleith_circuit_t *c, const wire_id key[256],
                    const wire_id plaintext[128], wire_id output[128]);

#endif /* VOLEITH_AES_CIRCUIT_H */
