/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_gf8_circuit.h - Merkle path verification as a GF(2⁸) element-level circuit
 *
 * GF(2⁸) counterpart to merkle_circuit.h. Each wire carries one GF(2⁸)
 * element (one byte) instead of one bit, reducing VOLE slot count from
 * AND-gate count to witness count (one slot per S-box inversion).
 *
 * Key difference from the bit-level circuit:
 *   Direction bits (path_dirs) are plain uint8_t values (0 or 1) resolved at
 *   circuit-build time - zero mul-gate cost per level. This is the correct
 *   design when the leaf index is a public instance value.
 *
 *   For the Signal KVAC use case (leaf index is private - reveals member identity),
 *   use merkle_gf8_path_circuit_secret_dir: path_dirs are gf8_wire_id wires
 *   (witness, one per level), costing 16 mul gates per level via voleith_gf8_add_mux.
 *
 * Witness slot cost (depth d):
 *   DM leaf hash (data_bytes-byte leaf):
 *     data_bytes + n_aes_dm × 200
 *     where n_aes_dm = max(1, ceil(data_bytes/16))  (one AES per Damgård block)
 *
 *   CMAC128 leaf hash:
 *     data_bytes + aes_cmac_gf8_n_aes_calls(data_bytes) × 200
 *
 *   CMAC256 leaf hash:
 *     data_bytes + aes_cmac_gf8_n_aes_calls(data_bytes) × 276
 *
 *   DM path (per level):
 *     16 (sibling node witness) + 200 (one AES-128 for DM compress)
 *
 *   CMAC128 path (per level):
 *     16 (sibling node witness) + aes_cmac_gf8_n_aes_calls(32) × 200  = 16 + 600
 *
 *   CMAC256 path (per level):
 *     16 (sibling node witness) + aes_cmac_gf8_n_aes_calls(32) × 276  = 16 + 828
 *
 * Domain constants (same as merkle_circuit.c):
 *   "VOLEitH-Leaf\0\0\0\0" (16 bytes, AES-128 key)
 *   "VOLEitH-Node\0\0\0\0" (16 bytes, AES-128 key)
 *   "VOLEitH-Leaf-256\0...\0" (32 bytes, AES-256 key)
 *   "VOLEitH-Node-256\0...\0" (32 bytes, AES-256 key)
 *
 * Direction convention (same as merkle_circuit.h):
 *   path_dirs[i] = 0: accumulated hash is the LEFT  child → H(current, sibling)
 *   path_dirs[i] = 1: accumulated hash is the RIGHT child → H(sibling, current)
 *   path_dirs[0]        = leaf level (bottom of tree)
 *   path_dirs[depth-1]  = level immediately below the root
 *   For leaf index j: path_dirs[k] = bit k of j (LSB first).
 *
 * Wire type convention (Signal KVAC):
 *   leaf_data, path_nodes: add_witness() - kept private.
 *   path_dirs:             plain uint8_t (public, resolved at build time).
 *   root[]:                assert_equal to add_instance() root wires.
 */

#ifndef VOLEITH_MERKLE_GF8_CIRCUIT_H
#define VOLEITH_MERKLE_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include "merkle_circuit.h" /* for voleith_merkle_hash_t */
#include <stddef.h>
#include <stdint.h>

/*
 * merkle_gf8_leaf_hash_circuit - hash raw leaf data to a 128-bit (16-byte) leaf hash.
 *
 * c                - circuit to append to
 * leaf_data        - leaf_data_bytes gf8_wire_id for raw leaf bytes;
 *                    may be NULL when leaf_data_bytes == 0
 * leaf_data_bytes  - byte length of leaf data (must be byte-aligned)
 * hash             - hash function selection (DM, CMAC128, or CMAC256)
 * leaf_hash        - output: 16 gf8_wire_id for the 128-bit leaf hash
 */
void merkle_gf8_leaf_hash_circuit(voleith_gf8_circuit_t *c,
                                  const gf8_wire_id *leaf_data,
                                  size_t leaf_data_bytes,
                                  voleith_merkle_hash_t hash,
                                  gf8_wire_id leaf_hash[16]);

/*
 * merkle_gf8_path_circuit - verify a Merkle authentication path.
 *
 * Appends gates that compute the Merkle tree root from a pre-hashed leaf
 * and the sibling hashes along the path. The caller should assert the 16
 * root wire IDs equal to the known public root instance wires.
 *
 * c           - circuit to append to
 * leaf_hash   - 16 gf8_wire_id for the pre-hashed leaf (from merkle_gf8_leaf_hash_circuit)
 * path_nodes  - depth × 16 gf8_wire_id for sibling hashes, leaf-level first
 * path_dirs   - depth plain 0/1 values (not wire IDs); resolved at circuit-build
 *               time with zero mul-gate cost (public leaf index)
 * depth       - number of levels from leaf hash to root
 * hash        - hash function; must match what was used for leaf_hash
 * root        - output: 16 gf8_wire_id for the computed root hash
 */
void merkle_gf8_path_circuit(voleith_gf8_circuit_t *c,
                             const gf8_wire_id leaf_hash[16],
                             const gf8_wire_id *path_nodes,
                             const uint8_t *path_dirs, size_t depth,
                             voleith_merkle_hash_t hash, gf8_wire_id root[16]);

/*
 * merkle_gf8_path_circuit_secret_dir - verify a Merkle path with private direction bits.
 *
 * Same as merkle_gf8_path_circuit but path_dirs is an array of gf8_wire_id (one
 * per level), each carrying 0x00 (left child) or 0x01 (right child) as a private
 * witness. Used when the leaf index must remain hidden (e.g., Signal KVAC where
 * the index reveals member identity).
 *
 * Costs 16 mul gates per level (one voleith_gf8_add_mux per output byte).
 *
 * c           - circuit to append to
 * leaf_hash   - 16 gf8_wire_id for the pre-hashed leaf
 * path_nodes  - depth × 16 gf8_wire_id for sibling hashes, leaf-level first
 * path_dirs   - depth gf8_wire_id, each 0x00 or 0x01 (private leaf index bits)
 * depth       - number of levels from leaf hash to root
 * hash        - hash function; must match what was used for leaf_hash
 * root        - output: 16 gf8_wire_id for the computed root hash
 */
void merkle_gf8_path_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id leaf_hash[16],
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_hash_t hash, gf8_wire_id root[16]);

#endif /* VOLEITH_MERKLE_GF8_CIRCUIT_H */
