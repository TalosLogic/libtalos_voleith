/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_circuit.h - Merkle path verification as a Boolean circuit
 *
 * Provides two functions:
 *
 *   merkle_leaf_hash_circuit() - hash raw leaf data to a 128-bit leaf hash,
 *       using a hard-coded leaf domain constant for separation from internal
 *       node hashes.  Callers MUST use this function (not aes_cmac_circuit
 *       directly) to ensure correct domain separation.
 *
 *   merkle_path_circuit() - verify a Merkle authentication path, computing
 *       the tree root from a pre-hashed leaf and the sibling hashes along
 *       the path.  The caller asserts the root output equal to the known
 *       public root.
 *
 * Hash function choice (voleith_merkle_hash_t):
 *
 *   VOLEITH_MERKLE_HASH_AES_DM - Davies-Meyer: 7,200 AND gates per inode.
 *       Leaf hash uses Merkle-Damgård DM chaining with IV = MERKLE_LEAF_DOMAIN.
 *       Inode: H(L,R) = AES_L(R ⊕ C_inode) ⊕ (R ⊕ C_inode).
 *       Security in the ideal cipher model.
 *
 *   VOLEITH_MERKLE_HASH_AES_CMAC - Fixed-key AES-128-CMAC: 21,728 AND gates per inode.
 *       Leaf hash: CMAC(K_leaf, data).  Inode: CMAC(K_inode, L‖R).
 *       K_leaf ≠ K_inode; security reduces to AES-PRF with a fixed key.
 *       Preferred when a non-ideal-cipher security argument is required.
 *
 *   VOLEITH_MERKLE_HASH_AES256_CMAC - Fixed-key AES-256-CMAC: 29,936 AND gates per inode.
 *       Same construction as AES_CMAC but using AES-256 with 32-byte domain keys.
 *       Use with Level 5 (256-bit security) parameter sets.
 *       Note: AES-256-DM is not offered - DM requires the chaining state (128 bits)
 *       to serve as the AES key, but AES-256 requires a 256-bit key; the sizes are
 *       incompatible without additional design choices.
 *
 * Domain separation (hard-coded, not caller-configurable):
 *   Leaf hashing and inode hashing always use distinct domain constants,
 *   preventing the Merkle second-preimage attack (internal node substitution).
 *   Callers cannot override the domain constants.  Callers MUST use
 *   merkle_leaf_hash_circuit() - not aes_cmac_circuit() directly - to obtain
 *   correct domain separation.
 *
 * AND gate cost (128-bit leaves, tree depth d):
 *   DM:       merkle_leaf_hash_circuit =  7,200; merkle_path_circuit = d × 7,328
 *   CMAC128:  merkle_leaf_hash_circuit = 14,400; merkle_path_circuit = d × 21,728
 *   CMAC256:  merkle_leaf_hash_circuit = 19,872; merkle_path_circuit = d × 29,936
 *   (128 AND gates per level for the direction multiplexer)
 *
 * Bit/byte convention: same as aes_circuit.h.
 *   Each byte: 8 consecutive wire IDs, bit 0 = LSB, bit 7 = MSB.
 *   128-bit block: wire[8k .. 8k+7] = byte k.
 *
 * Direction convention:
 *   path_dirs[i] = 0: accumulated hash is the LEFT  child → H(current, sibling)
 *   path_dirs[i] = 1: accumulated hash is the RIGHT child → H(sibling, current)
 *   path_dirs[0]        = leaf level (bottom of tree)
 *   path_dirs[depth-1]  = level immediately below the root
 *   For leaf index j: path_dirs[k] = bit k of j (LSB first).
 *
 * Leaf representation:
 *   merkle_path_circuit() expects pre-hashed 128-bit wire IDs from
 *   merkle_leaf_hash_circuit().  Callers must not pass raw leaf data
 *   directly to merkle_path_circuit().
 *
 * Wire type convention for privacy-preserving proofs (e.g. Signal KVAC):
 *   leaf_data, path_nodes, path_dirs: add_witness() - kept private.
 *   root[]:                           assert_equal to add_instance() root wires.
 */

#ifndef VOLEITH_MERKLE_CIRCUIT_H
#define VOLEITH_MERKLE_CIRCUIT_H

#include "circuit.h"
#include <stddef.h>

/*
 * Hash function selection.  The same choice applies to both leaf hashing
 * and internal node hashing; mixing types across the two functions is not
 * supported.
 */
typedef enum {
    VOLEITH_MERKLE_HASH_AES_DM, /* Davies-Meyer AES-128: fast, ideal-cipher security    */
    VOLEITH_MERKLE_HASH_AES_CMAC, /* Fixed-key AES-128-CMAC: more conservative security   */
    VOLEITH_MERKLE_HASH_AES256_CMAC, /* Fixed-key AES-256-CMAC: 256-bit security (Level 5)   */
} voleith_merkle_hash_t;

/*
 * merkle_leaf_hash_circuit - hash raw leaf data to a 128-bit leaf hash.
 *
 * Parameters:
 *   c              - circuit to append gates to
 *   leaf_data      - wire IDs for raw leaf data; may be NULL if leaf_data_bits == 0
 *   leaf_data_bits - bit length of leaf_data; must be a multiple of 8
 *   hash           - hash function selection (DM or CMAC)
 *   leaf_hash      - output: 128 wire IDs for the 128-bit leaf hash
 */
void merkle_leaf_hash_circuit(voleith_circuit_t *c, const wire_id *leaf_data,
                              size_t leaf_data_bits, voleith_merkle_hash_t hash,
                              wire_id leaf_hash[128]);

/*
 * merkle_path_circuit - verify a Merkle authentication path.
 *
 * Appends gates that compute the Merkle tree root from a pre-hashed leaf
 * and the sibling hashes along the path.  The caller should assert the
 * 128 root wire IDs equal to the known public root instance wires.
 *
 * Parameters:
 *   c           - circuit to append gates to
 *   leaf_hash   - 128 wire IDs for the pre-hashed leaf (from merkle_leaf_hash_circuit)
 *   path_nodes  - depth × 128 wire IDs for sibling hashes, leaf-level first
 *   path_dirs   - depth wire IDs for direction bits (0=left, 1=right), leaf-level first
 *   depth       - number of levels from leaf hash to root
 *   hash        - hash function; must match what was used for leaf_hash
 *   root        - output: 128 wire IDs for the computed root hash
 */
void merkle_path_circuit(voleith_circuit_t *c, const wire_id leaf_hash[128],
                         const wire_id *path_nodes, const wire_id *path_dirs,
                         size_t depth, voleith_merkle_hash_t hash,
                         wire_id root[128]);

#endif /* VOLEITH_MERKLE_CIRCUIT_H */
