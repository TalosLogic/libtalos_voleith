/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_norm_gf8_circuit.h - AES-128/256 as GF(2^8) element circuits using the
 * FAEST paired-round norm S-box.
 *
 * Additive twin of aes_gf8_circuit.h.  The cipher output byte is identical to
 * the frozen circuit (same NIST AES vectors); the difference is purely in the
 * witness encoding: half the data-path S-boxes commit a 4-bit subfield norm
 * instead of an 8-bit inverse, averaging 6 bits per S-box (a 25% VOLE-slot
 * reduction on the data path) via voleith_gf8_assert_aes_norm_roundpair.  The
 * key schedule stays frozen (8-bit inverse S-boxes, reused from
 * aes_gf8_circuit); only the encryption data path is re-expressed.
 *
 * The output wires are degree-1 committed state (the odd-round reset), so these
 * circuits compose into CMAC/KDF/Merkle exactly like the frozen twin.
 *
 * Witness ordering (for the prover's witness vector):
 *   - key bytes (16), declared by the caller before the circuit call.
 *   - key-schedule inv_in bytes (40 for AES-128), frozen key schedule.
 *   - per round-pair, in evaluation order: 8 packed norm bytes (two 4-bit
 *     norms each, 16 S-boxes) then 16 intermediate-state bytes (s_tilde).
 *   Use aes128_norm_gf8_build_witness / aes256_norm_gf8_build_witness.
 *
 * Plaintext is an instance (public) input, as in aes_gf8_circuit.
 */

#ifndef VOLEITH_AES_NORM_GF8_CIRCUIT_H
#define VOLEITH_AES_NORM_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stdint.h>
#include <stddef.h>

/* Full witness sizes (bytes): key + frozen key schedule + norm data path. */
#define AES128_NORM_GF8_WITNESS_BYTES 176 /* 16 + 40 + 5*(8+16)           */
#define AES256_NORM_GF8_WITNESS_BYTES 252 /* 32 + 52 + 7*(8+16)           */

/*
 * Norm data-path inv_in size for the split encrypt_rk form (below).  The
 * key-schedule inv_in is the FROZEN AES256_GF8_KS_INVIN_BYTES (the norm
 * data path reuses the 8-bit key schedule verbatim); only the encryption
 * S-boxes shrink, so this is 7 round-pairs * (8 packed norms + 16
 * s_tilde) = 168, versus the frozen AES256_GF8_ENC_INVIN_BYTES of 224.
 */
#define AES256_NORM_GF8_ENC_INVIN_BYTES 168 /* 7*(8+16) */

/* AES-128 counterpart: 5 round-pairs * (8 packed norms + 16 s_tilde) = 120,
 * versus the frozen AES128_GF8_ENC_INVIN_BYTES of 160. */
#define AES128_NORM_GF8_ENC_INVIN_BYTES 120 /* 5*(8+16) */

/*
 * aes128_norm_gf8_circuit - AES-128 encryption, norm S-box data path.
 *
 * key[0..15]:       16 GF(2^8) key-byte wires (witness).
 * plaintext[0..15]: 16 GF(2^8) plaintext-byte wires (instance).
 * output[0..15]:    receives 16 ciphertext-byte wires (degree-1 committed).
 */
void aes128_norm_gf8_circuit(voleith_gf8_circuit_t *c,
                             const gf8_wire_id key[16],
                             const gf8_wire_id plaintext[16],
                             gf8_wire_id output[16]);

/*
 * aes128_norm_gf8_build_witness - construct the full 176-byte witness for
 * aes128_norm_gf8_circuit.
 *
 * key[16]:        AES-128 key bytes.
 * plaintext[16]:  plaintext bytes (public instance; needed to trace the data
 *                 path).
 * witness[176]:   output witness array (caller allocates).
 * ciphertext[16]: if non-NULL, receives AES-128(key, plaintext).
 */
void aes128_norm_gf8_build_witness(
    const uint8_t key[16], const uint8_t plaintext[16],
    uint8_t witness[AES128_NORM_GF8_WITNESS_BYTES], uint8_t ciphertext[16]);

/*
 * aes256_norm_gf8_circuit - AES-256 encryption, norm S-box data path.
 *
 * key[0..31]:       32 GF(2^8) key-byte wires (witness).
 * plaintext[0..15]: 16 GF(2^8) plaintext-byte wires (instance).
 * output[0..15]:    receives 16 ciphertext-byte wires.
 */
void aes256_norm_gf8_circuit(voleith_gf8_circuit_t *c,
                             const gf8_wire_id key[32],
                             const gf8_wire_id plaintext[16],
                             gf8_wire_id output[16]);

/*
 * aes256_norm_gf8_build_witness - construct the full 252-byte witness for
 * aes256_norm_gf8_circuit.
 */
void aes256_norm_gf8_build_witness(
    const uint8_t key[32], const uint8_t plaintext[16],
    uint8_t witness[AES256_NORM_GF8_WITNESS_BYTES], uint8_t ciphertext[16]);

/*
 * Split AES-256 norm encryption: norm data path over a precomputed key
 * schedule.  The schedule is built by the FROZEN aes256_gf8_expand_key /
 * aes256_gf8_expand_key_witness (the norm twin does not re-express the
 * key schedule), so a caller sharing one schedule across several
 * encryptions (e.g. a Hirose iteration's two same-key encryptions)
 * expands once with the frozen routine, then calls these.  The emitted
 * gate stream and the inv_in bytes are byte-identical to the data-path
 * portion of aes256_norm_gf8_circuit.
 *
 * rk[15][16]:       round keys from aes256_gf8_expand_key(_witness).
 * plaintext[0..15]: 16 plaintext-byte wires / bytes.
 * output[0..15]:    receives 16 ciphertext-byte wires (degree-1 committed).
 * inv_out[168]:     receives AES256_NORM_GF8_ENC_INVIN_BYTES inv_in bytes.
 * ciphertext[16]:   if non-NULL, receives the resulting ciphertext bytes.
 */
void aes256_norm_gf8_encrypt_rk(voleith_gf8_circuit_t *c,
                                const gf8_wire_id rk[15][16],
                                const gf8_wire_id plaintext[16],
                                gf8_wire_id output[16]);

void aes256_norm_gf8_encrypt_rk_witness(
    const uint8_t rk[15][16], const uint8_t plaintext[16],
    uint8_t inv_out[AES256_NORM_GF8_ENC_INVIN_BYTES], uint8_t ciphertext[16]);

/*
 * Split AES-128 norm encryption over a precomputed frozen key schedule
 * (rk from aes128_gf8_expand_key(_witness)).  Byte-identical gate stream
 * and inv_in to the data-path portion of aes128_norm_gf8_circuit.
 *
 * rk[11][16]:       round keys from aes128_gf8_expand_key(_witness).
 * plaintext[0..15]: 16 plaintext-byte wires / bytes.
 * output[0..15]:    receives 16 ciphertext-byte wires (degree-1 committed).
 * inv_out[120]:     receives AES128_NORM_GF8_ENC_INVIN_BYTES inv_in bytes.
 * ciphertext[16]:   if non-NULL, receives the resulting ciphertext bytes.
 */
void aes128_norm_gf8_encrypt_rk(voleith_gf8_circuit_t *c,
                                const gf8_wire_id rk[11][16],
                                const gf8_wire_id plaintext[16],
                                gf8_wire_id output[16]);

void aes128_norm_gf8_encrypt_rk_witness(
    const uint8_t rk[11][16], const uint8_t plaintext[16],
    uint8_t inv_out[AES128_NORM_GF8_ENC_INVIN_BYTES], uint8_t ciphertext[16]);

/*
 * Solve one AES norm round-pair's committed witnesses from its inputs.
 * Given the even-round input state (state_in[16], the gadget's state_in
 * pool wires) and the odd-round round key (k0[16], the gadget's k0 pool
 * wires), writes the 8 packed-norm bytes and the 16-byte s_tilde reset
 * state.  Used by a generic witness generator to fill norm witnesses from
 * the already-evaluated input wire values (the same bytes the circuit
 * builder commits).  Independent of key size (AES-128 and AES-256 share
 * the round-pair structure).
 */
void aes_norm_gf8_solve_pair(const uint8_t state_in[16], const uint8_t k0[16],
                             uint8_t packed_out[8], uint8_t s_tilde_out[16]);

#endif /* VOLEITH_AES_NORM_GF8_CIRCUIT_H */
