/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_gf8_circuit.h - V5 designated-opener in-circuit relation.
 *
 * OP.CIRC.2: the syndrome half of the opener relation.  Given the committed
 * bit-packed support of the QC-MDPC error e and the public syndrome s, emit
 * the degree-d QuickSilver constraints that bind s = M * e^T to the committed
 * support and enforce UNIFORM weight-t well-formedness (distinct + ascending +
 * canonical + in-range).  The KDF gadget (K = argus_kdf(support)) and the DEM
 * clause (tag_ct == K XOR id) arrive in OP.CIRC.3.
 */

#ifndef VOLEITH_RS_OPENER_GF8_CIRCUIT_H
#define VOLEITH_RS_OPENER_GF8_CIRCUIT_H

#include "gf8_circuit.h"

#include <stdint.h>

/*
 * voleith_rs_opener_syndrome_gf8 - emit s = M * e^T + well-formedness over a
 * committed bit-packed support.
 *
 *   support_wires  msg_bytes = ceil(t*idx_bits/8) GF(2^8) byte wires holding
 *                  the support bit-packed LSB-first at idx_bits per index
 *                  (ichor_bitpack_le32 / contract A3).  Secret (witness); the
 *                  same bytes the KDF gadget will consume in OP.CIRC.3.
 *   s_bit_wires    p syndrome bit wires (public / instance), s_j at [j].
 *   t, idx_bits, p, n0, M   the Argus (M, s) parameters; M is the (n0-1)
 *                  circulant first-row blocks of ceil(p/8) bytes, baked into
 *                  the syndrome constraints.  M is NULL only if n0 == 1.
 *
 * Extracts the t*idx_bits MSB-first index bit wires from the packed support via
 * free linear maps (each selects one packed bit into byte bit 0), then emits
 * voleith_gf8_assert_syndrome plus the strict-ascending less-than chain
 * (distinct + ascending + canonical) and the range check idx[t-1] < n against a
 * baked constant n = n0*p.  Zero VOLE slots; raises the circuit's QS opening
 * degree to idx_bits + 1 (the less-than gadget).
 *
 * Returns 0 on success, -1 on a NULL required argument, a zero dimension, or
 * allocation failure.
 */
int voleith_rs_opener_syndrome_gf8(voleith_gf8_circuit_t *c,
                                   const gf8_wire_id *support_wires,
                                   const gf8_wire_id *s_bit_wires, uint32_t t,
                                   uint32_t idx_bits, uint32_t p, uint32_t n0,
                                   const uint8_t *M);

/*
 * voleith_rs_opener_dem_aesdm_gf8 - the lambda=128 KDF + XOR-OTP DEM clause
 * (OP.CIRC.3a).  Emits K = AES-DM(ds_iv, support) over the committed packed
 * support, then asserts tag_ct == K XOR id byte-for-byte.
 *
 * The KDF is standard message-keyed Davies-Meyer, byte-exact to ichor_aesdm_*
 * (init_iv / absorb / finalize_fixed): h = ds_iv; per 16-byte support block M,
 * h = AES_M(h) XOR h; the final partial block is zero-padded and run through one
 * more iteration (an exact block multiple adds none); K = the final h.  NOT the
 * chaining-value-keyed MMO of node_hash_aes_gf8's leaf/inode compressions.
 *
 *   support_wires  msg_bytes packed support byte wires (the OP.CIRC.2 witness).
 *   ds_iv          the 16-byte (lambda, prim, n0) domain-separation IV
 *                  (params->ds_iv).
 *   id_wires       key_bytes id wires (the leaf-preimage handle, OP.CIRC.1).
 *   tag_ct_wires   key_bytes tag_ct instance wires.
 *   key_bytes      = lambda/8; MUST be 16 (this is the AES-DM / lambda=128
 *                   primitive; Grostl-256 / lambda=256 is OP.CIRC.3b).
 *
 * Adds one AES-128 gadget per absorbed block (200 inv_in witnesses each); the
 * DEM XOR + equality is free.  Returns 0 on success, -1 on a NULL argument,
 * key_bytes != 16, or allocation failure.
 */
int voleith_rs_opener_dem_aesdm_gf8(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *support_wires,
                                    size_t msg_bytes, const uint8_t ds_iv[16],
                                    const gf8_wire_id *id_wires,
                                    const gf8_wire_id *tag_ct_wires,
                                    size_t key_bytes);

/*
 * inv_in witness byte count the AES-DM KDF emits for an msg_bytes-long packed
 * support: (msg_bytes/16 + (msg_bytes % 16 != 0)) * 200.  Zero for msg_bytes 0.
 */
size_t voleith_rs_opener_kdf_aesdm_invin_bytes(size_t msg_bytes);

/*
 * voleith_rs_opener_kdf_aesdm_build_witness - fill the AES-DM KDF inv_in witness
 * (voleith_rs_opener_kdf_aesdm_invin_bytes(msg_bytes) bytes) for the given
 * ds_iv and packed support msg, in the S-box order the gadget emits.  Software
 * mirror of the in-circuit chain (each block's 200 inv_in via
 * aes128_gf8_build_witness, chained by the Davies-Meyer feed-forward).
 */
void voleith_rs_opener_kdf_aesdm_build_witness(const uint8_t ds_iv[16],
                                               const uint8_t *msg,
                                               size_t msg_bytes,
                                               uint8_t *out_invin);

/*
 * voleith_rs_opener_dem_grostl256_gf8 - the lambda=256 KDF + XOR-OTP DEM clause
 * (OP.CIRC.3b), twin of the AES-DM variant.  Emits K = Grostl-256(ds_iv,
 * support) then asserts tag_ct == K XOR id byte-for-byte.
 *
 * The KDF is byte-exact to ichor_grostl256_init_iv / absorb / finalize_fixed:
 * the 64-byte IV is ds_iv zero-padded to 64; the support is the message,
 * compressed 64 bytes per block; the final partial block is zero-filled to 64
 * and compressed (an exact block multiple adds none; an empty message
 * compresses a single zero block); K = Omega(final state), truncated to 32.
 *
 *   support_wires  msg_bytes packed support byte wires (the OP.CIRC.2 witness).
 *   ds_iv          the 16-byte domain-separation IV (params->ds_iv).
 *   id_wires       key_bytes id wires.
 *   tag_ct_wires   key_bytes tag_ct instance wires.
 *   key_bytes      = lambda/8; MUST be 32 (Grostl-256 / lambda=256).
 *
 * Returns 0 on success, -1 on a NULL argument, key_bytes != 32, or allocation
 * failure.
 */
int voleith_rs_opener_dem_grostl256_gf8(
    voleith_gf8_circuit_t *c, const gf8_wire_id *support_wires,
    size_t msg_bytes, const uint8_t ds_iv[16], const gf8_wire_id *id_wires,
    const gf8_wire_id *tag_ct_wires, size_t key_bytes);

/*
 * inv_in witness byte count the Grostl-256 KDF emits for an msg_bytes-long
 * packed support, and the software mirror of the chain's inv_in (in the S-box
 * order the gadget emits).  Same block accounting as ichor_grostl_finalize_fixed.
 */
size_t voleith_rs_opener_kdf_grostl256_invin_bytes(size_t msg_bytes);
void voleith_rs_opener_kdf_grostl256_build_witness(const uint8_t ds_iv[16],
                                                   const uint8_t *msg,
                                                   size_t msg_bytes,
                                                   uint8_t *out_invin);

#endif /* VOLEITH_RS_OPENER_GF8_CIRCUIT_H */
