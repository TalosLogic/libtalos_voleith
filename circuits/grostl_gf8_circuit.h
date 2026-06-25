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

/*
 * Fixed-input single-compression node circuit: H = Omega(f(iv, block)).
 *
 * One Grøstl compression of a single full-width block under the
 * caller-supplied public chaining value iv, then the output transform
 * Omega, truncated to the node width (the last out_bytes of the state,
 * matching voleith_grostl_finalize and core/grostl.c
 * voleith_grostl{256,512}_compress_node, the matching software oracle).
 *
 * No Merkle-Damgård padding: the input is exactly one block of fixed
 * width, so no 0x80 marker, no zero pad, and no length block.  Domain
 * separation between leaf and internal-node hashing is carried entirely
 * by iv (the caller passes distinct iv values), NOT by a 1-byte
 * in-message prefix; that is what keeps L || R to exactly one block and
 * the cost to a single compression.
 *
 * This is a SIBLING of grostl{256,512}_gf8_circuit: it reuses the same
 * internal P / Q / Omega builders but skips padding and IV setup.  The
 * full-hash entry points are unchanged (they feed the frozen Shipshape
 * witgen fingerprint).
 *
 *   c     : circuit to append to
 *   iv    : 64 (256) / 128 (512) byte fixed public chaining value
 *   block : 64 (256) / 128 (512) caller-declared input wire IDs
 *   out   : receives 32 (256) / 64 (512) node-digest wire IDs
 *
 * Mul-gate cost = 1,920 (256) / 5,376 (512): one compression (P + Q)
 * plus the output transform's P, no padding block.
 */
void grostl256_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                                const gf8_wire_id block[64],
                                gf8_wire_id out[32]);
void grostl512_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[128],
                                const gf8_wire_id block[128],
                                gf8_wire_id out[64]);

/*
 * inv_in witness size (in bytes) for one node circuit.  Excludes the
 * block input bytes, which the caller declares as its own witness
 * wires before invoking grostl{256,512}_gf8_node_circuit (see
 * feedback_gf8_witness_layout).  Returns 1,920 (256) / 5,376 (512).
 */
size_t grostl256_gf8_node_invin_bytes(void);
size_t grostl512_gf8_node_invin_bytes(void);

/*
 * Fill inv_out with the grostl{256,512}_gf8_node_invin_bytes() inv_in
 * values for one node hash of block under iv, in circuit-evaluation
 * order (P then Q for the compression, then the output transform's P).
 * Matches the S-box order grostl{256,512}_gf8_node_circuit emits.
 */
void grostl256_gf8_node_build_witness(const uint8_t iv[64],
                                      const uint8_t block[64],
                                      uint8_t *inv_out);
void grostl512_gf8_node_build_witness(const uint8_t iv[128],
                                      const uint8_t block[128],
                                      uint8_t *inv_out);

#endif /* VOLEITH_GROSTL_GF8_CIRCUIT_H */
