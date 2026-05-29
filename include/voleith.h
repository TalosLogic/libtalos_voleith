/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * voleith.h - VOLEitH zero-knowledge proof library (umbrella header)
 *
 * Include this single header to access the full public API.
 *
 * ================================================================
 * Proof system
 * ================================================================
 *
 * 1. Build a circuit describing your computation using circuit.h:
 *
 *      voleith_circuit_t *c = voleith_circuit_new();
 *
 *      // Declare inputs
 *      wire_id key = voleith_circuit_add_witness(c);   // private
 *      wire_id pub = voleith_circuit_add_instance(c);  // public
 *
 *      // Add gates (XOR/NOT are free; AND gates determine proof cost)
 *      wire_id a = voleith_circuit_add_and(c, key, pub);
 *      wire_id x = voleith_circuit_add_xor(c, a, key);
 *
 *      // Constrain outputs
 *      voleith_circuit_assert_zero(c, x);
 *
 * 2. Prove knowledge of a witness satisfying the circuit:
 *
 *      voleith_proof_t proof;
 *      int rc = voleith_prove(&proof, &voleith_params_em_128f,
 *                             c, witness_bytes, instance_bytes,
 *                             fs_seed, fs_seed_len);
 *
 * 3. Verify:
 *
 *      rc = voleith_verify(&proof, &voleith_params_em_128f,
 *                          c, instance_bytes, fs_seed, fs_seed_len);
 *      voleith_proof_free(&proof);
 *      voleith_circuit_free(c);
 *
 * ================================================================
 * Circuit building blocks
 * ================================================================
 *
 * Pre-built sub-circuits for common operations.  Each appends gates
 * to an existing circuit and returns wire IDs for composition:
 *
 *   aes128_circuit / aes256_circuit     - AES encrypt
 *   aes_cmac_circuit                    - AES-CMAC MAC
 *   kdf_ctr_cmac_circuit                - NIST SP 800-108 KDF-CTR
 *   merkle_leaf_hash_circuit            - Merkle leaf hash
 *   merkle_path_circuit                 - Merkle path verification
 *   indexed_merkle_nonmember_circuit    - Indexed Merkle non-membership
 *
 * ================================================================
 * AND gate costs (proof size and prover work)
 * ================================================================
 *
 *   AES-128 encrypt:              7,200 AND gates
 *   AES-256 encrypt:              9,936 AND gates
 *   AES-128-CMAC (128-bit key): 14,400 AND gates (2 AES-128 calls)
 *   AES-256-CMAC (256-bit key): 19,872 AND gates (2 AES-256 calls)
 *   KDF-CTR (n outputs, 128):   n × 14,400 AND gates
 *   KDF-CTR (n outputs, 256):   n × 19,872 AND gates
 *   Merkle DM      (depth d):    7,200 leaf + d × 7,328 path
 *   Merkle CMAC128 (depth d):   14,400 leaf + d × 21,728 path
 *   Merkle CMAC256 (depth d):   19,872 leaf + d × 29,936 path
 *   Indexed Merkle DM:           above + 6 × target_bits ordering gates
 *
 * ================================================================
 * Parameter sets (security levels)
 * ================================================================
 *
 *   voleith_params_em_128s / _128f  - 128-bit security (slow/fast)
 *   voleith_params_em_192s / _192f  - 192-bit security
 *   voleith_params_em_256s / _256f  - 256-bit security
 *
 * ================================================================
 * Wire encoding conventions
 * ================================================================
 *
 *   Witness/instance bytes are bit-packed in little-endian bit order:
 *   byte[0] bit 0 = wire 0 (first declared witness/instance wire).
 *
 *   For multi-byte values (AES keys, hash outputs, etc.):
 *   byte k, bit b → wire 8k+b, where bit 0 = LSB, bit 7 = MSB.
 */

#ifndef VOLEITH_H
#define VOLEITH_H

/* Library version */
#define VOLEITH_VERSION_MAJOR 1
#define VOLEITH_VERSION_MINOR 1
#define VOLEITH_VERSION_PATCH 0
#define VOLEITH_VERSION_STRING "1.1.0"

/* Proof system: circuit builder and prove/verify API */
#include "circuit.h"
#include "proof.h"

/* Circuit building blocks */
#include "aes_circuit.h"
#include "aes_cmac_circuit.h"
#include "kdf_ctr_cmac_circuit.h"
#include "merkle_circuit.h"
#include "indexed_merkle_circuit.h"

#endif /* VOLEITH_H */
