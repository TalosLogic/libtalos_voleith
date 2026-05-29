/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_gf8_circuit.h - Grøstl-256 and Grøstl-512 as GF(2⁸) element circuits.
 *
 * Builds the Grøstl hash as a VOLEitH GF(2⁸) circuit, reusing the
 * existing aes_gf8_sbox gadget (Proposition 6.4 from FAEST §6.2) for
 * SubBytes - the Grøstl S-box IS the AES S-box.  All other Grøstl
 * round operations (AddRoundConstant, ShiftBytes, MixBytes) and the
 * compression-function XORs are GF(2)-linear: zero VOLE slots, zero
 * mul gates.
 *
 * Mul-gate cost (= one VOLE slot per S-box):
 *
 *   per Grøstl-256 compression : 1,280  (P + Q each = 10 rounds * 64 boxes)
 *   per Grøstl-256 output Ω    :   640  (P only)
 *   per Grøstl-512 compression : 3,584  (14 rounds * 128 boxes * 2)
 *   per Grøstl-512 output Ω    : 1,792
 *
 * Internal padding constants (0x80 marker, zero pad, 64-bit block
 * count) are added as voleith_gf8_add_const wires - they're public
 * structural data, not witness or instance.
 *
 * Witness layout (returned by grostl{256,512}_gf8_build_witness):
 *
 *   bytes [0 .. msg_bytes-1]            caller's message bytes
 *   bytes [msg_bytes ..]                inv_in for every S-box in
 *                                       circuit-evaluation order
 *
 * Total witness length = grostl{256,512}_gf8_witness_bytes(msg_bytes).
 * The caller declares its msg wires (via voleith_gf8_add_witness)
 * BEFORE calling grostl{256,512}_gf8_circuit; the circuit then adds
 * the inv_in witness wires internally.
 *
 * Block count computation (used by both the circuit and the witness
 * builder; must match Grøstl spec §3.6):
 *
 *   pad to next multiple of block_size after appending 0x80, 8-byte
 *   big-endian length field at the end of the last block.
 *
 *   n_blocks_256(N) = ceil((N + 9) / 64)
 *   n_blocks_512(N) = ceil((N + 9) / 128)
 *
 * Cross-validated against core/grostl.c (which is itself
 * NIST-KAT-validated) on every test run.
 */

#ifndef VOLEITH_GROSTL_GF8_CIRCUIT_H
#define VOLEITH_GROSTL_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

/*
 * Grøstl-256 over GF(2⁸) byte-wires.
 *
 * c          : circuit to append to
 * msg        : msg_bytes wire IDs for the message; may be NULL when
 *              msg_bytes == 0
 * msg_bytes  : input message length in bytes
 * out        : receives the 32 wire IDs for the 256-bit digest, in
 *              the spec's byte order (out[0] = first digest byte)
 *
 * Mul-gate cost = 1,280 * n_compressions + 640  where
 *   n_compressions = ceil((msg_bytes + 9) / 64).
 */
void grostl256_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                           size_t msg_bytes, gf8_wire_id out[32]);

/*
 * Grøstl-512 over GF(2⁸) byte-wires.
 *
 * Mul-gate cost = 3,584 * n_compressions + 1,792  where
 *   n_compressions = ceil((msg_bytes + 9) / 128).
 */
void grostl512_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                           size_t msg_bytes, gf8_wire_id out[64]);

/*
 * Witness-array size (in bytes) required by grostl{256,512}_gf8_build_witness.
 * Includes both the msg_bytes message bytes and the internal inv_in
 * slots, in that order.
 */
size_t grostl256_gf8_witness_bytes(size_t msg_bytes);
size_t grostl512_gf8_witness_bytes(size_t msg_bytes);

/*
 * Construct the full witness array for grostl{256,512}_gf8_circuit.
 *
 * msg        : message bytes (NULL allowed when msg_bytes == 0)
 * msg_bytes  : input message length in bytes
 * witness    : output buffer; caller allocates exactly
 *              grostl{256,512}_gf8_witness_bytes(msg_bytes) bytes
 *
 * Layout: witness[0..msg_bytes-1] = msg, then inv_in values in the
 * same order the circuit adds them (P then Q per compression block,
 * then a final P for the output transform).
 *
 * Constant-time: no data-dependent branches on the message; the
 * brute-force GF(2⁸) inverse used inside aes_gf8_sbox witness
 * production scans a fixed 0..255 range for every S-box input, so
 * the total work is identical regardless of message content.  See
 * dudect target voleith_grostl256_gf8_build_witness_msg.
 */
void grostl256_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                 uint8_t *witness);
void grostl512_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                 uint8_t *witness);

#endif /* VOLEITH_GROSTL_GF8_CIRCUIT_H */
