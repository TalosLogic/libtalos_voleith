/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_norm_gf8_circuit.h - Grostl-256 and Grostl-512 as GF(2^8) element
 * circuits with the FAEST paired-round norm S-box.
 *
 * Drop-in sibling of grostl_gf8_circuit.h: same hash function, same public
 * output (verified against the frozen circuit and the NIST KATs), but each
 * pair of permutation rounds commits packed 4-bit subfield norms for the even
 * round and the full reset state for the odd round, instead of one inverse
 * byte per S-box.  This averages 6 committed bits per S-box rather than 8, so
 * every witness array below is 75% of its frozen counterpart.  Grostl has no
 * secret key schedule, so the saving is clean.
 *
 * The linear layer (ShiftBytes / MixBytes / padding / IV injection) is shared
 * verbatim with the frozen circuit through grostl_gf8_internal.h; the norm
 * round-pair relation is asserted by voleith_gf8_assert_grostl_norm_roundpair
 * (proof/gf8_circuit.h).  See grostl_norm_gf8_circuit.c for the data path.
 */

#ifndef VOLEITH_GROSTL_NORM_GF8_CIRCUIT_H
#define VOLEITH_GROSTL_NORM_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================
 * Full-hash circuit builders.  msg is a caller-declared run of witness
 * wires; the circuit appends its own packed-norm and reset-state witnesses.
 * ================================================================ */

/* Grostl-256 over GF(2^8) byte-wires, norm S-box.  out is the 32-byte digest. */
void grostl256_norm_gf8_circuit(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *msg, size_t msg_bytes,
                                gf8_wire_id out[32]);

/* Grostl-512 over GF(2^8) byte-wires, norm S-box.  out is the 64-byte digest. */
void grostl512_norm_gf8_circuit(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *msg, size_t msg_bytes,
                                gf8_wire_id out[64]);

/* Witness-array size (in bytes) required by grostl{256,512}_norm_gf8_build
 * _witness: msg_bytes followed by the per-pair norm witnesses. */
size_t grostl256_norm_gf8_witness_bytes(size_t msg_bytes);
size_t grostl512_norm_gf8_witness_bytes(size_t msg_bytes);

/* Construct the full witness array for grostl{256,512}_norm_gf8_circuit.
 * witness must hold grostl{256,512}_norm_gf8_witness_bytes(msg_bytes). */
void grostl256_norm_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                      uint8_t *witness);
void grostl512_norm_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                      uint8_t *witness);

/* ================================================================
 * Fixed-input single-compression node circuits: H = Omega(f(iv, block)).
 * iv is injected as public constant wires; block is caller-declared.
 * ================================================================ */

void grostl256_norm_gf8_node_circuit(voleith_gf8_circuit_t *c,
                                     const uint8_t iv[64],
                                     const gf8_wire_id block[64],
                                     gf8_wire_id out[32]);
void grostl512_norm_gf8_node_circuit(voleith_gf8_circuit_t *c,
                                     const uint8_t iv[128],
                                     const gf8_wire_id block[128],
                                     gf8_wire_id out[64]);

/* ================================================================
 * Fixed-input multi-block node circuits:
 * H = Omega(f(... f(f(iv, block0), block1) ..., block_{k-1})).  No MD padding.
 * ================================================================ */

void grostl256_norm_gf8_node2_circuit(voleith_gf8_circuit_t *c,
                                      const uint8_t iv[64],
                                      const gf8_wire_id block[128],
                                      gf8_wire_id out[32]);
void grostl512_norm_gf8_node2_circuit(voleith_gf8_circuit_t *c,
                                      const uint8_t iv[128],
                                      const gf8_wire_id block[256],
                                      gf8_wire_id out[64]);

void grostl256_norm_gf8_nodeN_circuit(voleith_gf8_circuit_t *c,
                                      const uint8_t iv[64],
                                      const gf8_wire_id *blocks,
                                      size_t n_blocks, gf8_wire_id out[32]);

/* ================================================================
 * Node-circuit witness (inv_in) sizes and builders.  Each fills inv_out with
 * the per-pair norm witnesses in circuit-evaluation order, excluding the
 * caller-declared block bytes.
 * ================================================================ */

size_t grostl256_norm_gf8_node_invin_bytes(void);
size_t grostl512_norm_gf8_node_invin_bytes(void);
size_t grostl256_norm_gf8_node2_invin_bytes(void);
size_t grostl512_norm_gf8_node2_invin_bytes(void);
size_t grostl256_norm_gf8_nodeN_invin_bytes(size_t n_blocks);

void grostl256_norm_gf8_node_build_witness(const uint8_t iv[64],
                                           const uint8_t block[64],
                                           uint8_t *inv_out);
void grostl512_norm_gf8_node_build_witness(const uint8_t iv[128],
                                           const uint8_t block[128],
                                           uint8_t *inv_out);
void grostl256_norm_gf8_node2_build_witness(const uint8_t iv[64],
                                            const uint8_t block[128],
                                            uint8_t *inv_out);
void grostl512_norm_gf8_node2_build_witness(const uint8_t iv[128],
                                            const uint8_t block[256],
                                            uint8_t *inv_out);
void grostl256_norm_gf8_nodeN_build_witness(const uint8_t iv[64],
                                            const uint8_t *blocks,
                                            size_t n_blocks, uint8_t *inv_out);

/*
 * Solve one Grostl norm round-pair's committed witnesses from its inputs.
 * state_in[nst] is the even-round SubBytes input (the gadget's state_in pool
 * wires, i.e. state XOR the public even AddRoundConstant); (cols, shift, is_q,
 * odd_round) are the gadget entry's parameters.  Writes nst/2 packed-norm
 * bytes and the nst-byte s_tilde reset state.  Used by a generic witness
 * generator to fill norm witnesses from already-evaluated input wire values.
 * shift has 8 entries (ROWS).
 */
void grostl_norm_gf8_solve_pair(const uint8_t *state_in, unsigned int nst,
                                unsigned int cols, const uint8_t shift[8],
                                int is_q, unsigned int odd_round,
                                uint8_t *packed_out, uint8_t *s_tilde_out);

#ifdef __cplusplus
}
#endif

#endif /* VOLEITH_GROSTL_NORM_GF8_CIRCUIT_H */
