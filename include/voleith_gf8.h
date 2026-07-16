/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * voleith_gf8.h - VOLEitH GF(2⁸) element-level proof library (umbrella header)
 *
 * Include this single header to access the full GF(2⁸) element-level API.
 *
 * ================================================================
 * GF(2⁸) proof system
 * ================================================================
 *
 * The GF(2⁸) element-level variant carries one field element (byte) per
 * wire and per VOLE slot.  This is more efficient than the bit-level
 * variant when the circuit's natural data type is bytes: witness and
 * mul-gate counts are 8× smaller, and the AES S-box inverse (200 slots)
 * replaces 200 individual AND gates with 200 witness slots.
 *
 * 1. Build a circuit using gf8_circuit.h:
 *
 *      voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
 *
 *      // Declare inputs (one wire = one byte)
 *      gf8_wire_id key_byte = voleith_gf8_add_witness(c);   // private
 *      gf8_wire_id pub_byte = voleith_gf8_add_instance(c);  // public
 *
 *      // Free gates: XOR, linear maps, squaring
 *      gf8_wire_id xored = voleith_gf8_add_xor(c, key_byte, pub_byte);
 *
 *      // Mul gate costs one VOLE slot (cf. AND gate in bit-level variant)
 *      gf8_wire_id prod = voleith_gf8_add_mul(c, key_byte, pub_byte);
 *
 *      // Constrain outputs
 *      voleith_gf8_assert_zero(c, xored);
 *
 * 2. Prove:
 *
 *      voleith_proof_t proof;
 *      int rc = voleith_gf8_prove(&proof, &voleith_params_em_128f,
 *                                 c, witness_bytes, instance_bytes,
 *                                 fs_seed, fs_seed_len);
 *
 * 3. Verify:
 *
 *      rc = voleith_gf8_verify(&proof, &voleith_params_em_128f,
 *                              c, instance_bytes, fs_seed, fs_seed_len);
 *      voleith_proof_free(&proof);
 *      voleith_gf8_circuit_free(c);
 *
 * ================================================================
 * Circuit building blocks
 * ================================================================
 *
 * Pre-built sub-circuits for common byte-oriented operations.
 * Each appends gates to an existing circuit and returns gf8_wire_id
 * arrays for composition:
 *
 *   aes128_gf8_circuit / aes256_gf8_circuit     - AES encrypt
 *   aes_cmac_gf8_circuit                        - AES-CMAC MAC
 *   kdf_ctr_cmac_gf8_circuit                    - NIST SP 800-108 KDF-CTR
 *   merkle_gf8_leaf_hash_circuit                - Merkle leaf hash
 *   merkle_gf8_path_circuit                     - Merkle path verification
 *   indexed_merkle_gf8_nonmember_circuit        - Indexed Merkle non-membership
 *   grostl256_gf8_circuit / grostl512_gf8_circuit - Grøstl hash
 *   merkle_grostl_gf8_path_circuit              - Wide-node Grøstl Merkle path
 *   indexed_merkle_grostl_gf8_nonmember_circuit - Wide-node Grøstl indexed non-membership
 *   merkle_vt_gf8_path_circuit                  - Hash-agnostic Merkle path (vt-driven)
 *   merkle_vt_gf8_indexed_nonmember_circuit     - Hash-agnostic indexed Merkle non-membership
 *
 * ================================================================
 * Node-hash vt registry
 * ================================================================
 *
 * The vt-driven (hash-agnostic) Merkle / IMT circuits and the RSv1 ring
 * signature layer accept any wrapped voleith_node_hash_vt:
 *
 *   voleith_node_hash_aes_dm        - AES-128 Davies-Meyer    (16B, 2⁶⁴  CR)
 *   voleith_node_hash_aes_cmac128   - AES-128-CMAC            (16B, 2⁶⁴  CR)
 *   voleith_node_hash_aes_cmac256   - AES-256-CMAC            (16B, 2⁶⁴  CR)
 *   voleith_node_hash_grostl256     - Grøstl-256              (32B, 2¹²⁸ CR) [deprecated]
 *   voleith_node_hash_grostl256_t27 - Grøstl-256 truncated 27 (27B, 2¹⁰⁸ CR) [deprecated]
 *   voleith_node_hash_grostl512     - Grøstl-512              (64B, 2²⁵⁶ CR) [deprecated]
 *   voleith_node_hash_grostl512_t59 - Grøstl-512 truncated 59 (59B, 2²³⁶ CR) [deprecated]
 *   voleith_node_hash_grostl256_fixed - Grøstl-256 fixed-input (32B, 2¹²⁸ CR)
 *   voleith_node_hash_grostl512_fixed - Grøstl-512 fixed-input (64B, 2²⁵⁶ CR)
 *   voleith_node_hash_hirose        - Hirose-AES-256 variable (32B, 2¹²⁸ CR)
 *   voleith_node_hash_hirose_fixed32- Hirose-AES-256 fixed-32 (32B, 2¹²⁸ CR)
 *
 * See circuits/node_hash_vt.h for the vt struct and the rationale per
 * variant.
 *
 * ================================================================
 * RSv1 ring signatures
 * ================================================================
 *
 * voleith_rsv1_* wraps the vt-driven Merkle / IMT circuits into a
 * non-interactive ring signature with optional revocation.  Statement:
 * "I know sk such that OWF(sk) is in the membership tree at root R
 * (and, optionally, NOT in the revocation IMT at root V); m is bound
 * via Fiat-Shamir."
 *
 *   voleith_rsv1_ring_build(cfg, sks, n, root_out, paths_out, ...)
 *   voleith_rsv1_sign(sig, cfg, params, sk, R, membership, V, revocation, m)
 *   voleith_rsv1_verify(sig, cfg, params, R, V, m)
 *   voleith_ring_sig_pack / _unpack    - on-the-wire envelope ("VRS1")
 *
 * See proof/ring_sig_v1_gf8.h and docs/RSV1_DESIGN.md for the full API
 * and protocol spec.
 *
 * ================================================================
 * VOLE slot costs (ell = n_witness + n_mul)
 * ================================================================
 *
 *   AES-128 encrypt:              200 slots  (inv_in per S-box call)
 *   AES-256 encrypt:              276 slots
 *   AES-128-CMAC:                 n_aes_calls(msg_bytes) × 200 slots
 *   AES-256-CMAC:                 n_aes_calls(msg_bytes) × 276 slots
 *   KDF-CTR (n iters, AES-128):   n × n_aes_per_cmac(fixed_input) × 200 slots
 *   Merkle DM      (depth d):     dm_n_aes(data) × 200  leaf + d × (16 + 200) path
 *   Merkle CMAC128 (depth d):     n_aes(data) × 200      leaf + d × (16 + 600) path
 *   Indexed Merkle:               above + 2 × 3 × 8 × target_bytes mul gates
 *
 * All caller-supplied wires (key bytes, path nodes, etc.) also cost
 * one witness slot each.
 *
 * ================================================================
 * Two-phase API (Signal KVAC / shared transcript)
 * ================================================================
 *
 * For hybrid protocols that share a Fiat-Shamir transcript with a
 * classical credential scheme, use the two-phase API:
 *
 *   voleith_gf8_prove_commit()    - Phase 1: commit (produces blob)
 *   voleith_gf8_prove_respond()   - Phase 2: complete proof from external chall_1
 *
 *   voleith_gf8_verify_reconstruct() - Phase 1: BAVC reconstruct (produces blob)
 *   voleith_gf8_verify_respond()     - Phase 2: verify from external chall_1
 *
 * See gf8_proof.h for full documentation and the usage pattern.
 *
 * ================================================================
 * Parameter sets
 * ================================================================
 *
 * Reused from proof.h (same parameter sets as the bit-level variant):
 *
 *   voleith_params_em_128s / _128f  - 128-bit security (slow/fast)
 *   voleith_params_em_192s / _192f  - 192-bit security
 *   voleith_params_em_256s / _256f  - 256-bit security
 *
 * ================================================================
 * Wire encoding conventions
 * ================================================================
 *
 *   Witness and instance arrays are byte arrays: one byte per wire.
 *   byte[i] corresponds to the i-th voleith_gf8_add_witness() /
 *   voleith_gf8_add_instance() call.
 *
 *   For multi-byte values (AES keys, hash outputs, etc.):
 *   byte k → the k-th wire, where byte 0 = least-significant byte.
 */

#ifndef VOLEITH_GF8_H
#define VOLEITH_GF8_H

/* Library version */
#ifndef VOLEITH_VERSION_MAJOR
#define VOLEITH_VERSION_MAJOR 1
#define VOLEITH_VERSION_MINOR 10
#define VOLEITH_VERSION_PATCH 0
#define VOLEITH_VERSION_STRING "1.10.0"
#endif

/* GF(2⁸) proof system: circuit builder and prove/verify API */
#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "proof_header.h"

/* Circuit building blocks */
#include "aes_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "merkle_gf8_circuit.h"
#include "indexed_merkle_gf8_circuit.h"
#include "range_gf8_circuit.h"
#include "grostl_gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
#include "indexed_merkle_grostl_gf8_circuit.h"

/* Hash-agnostic (vt-driven) Merkle / IMT stack */
#include "node_hash_vt.h"
#include "merkle_vt_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "merkle_vt_gf8_helpers.h"
#include "indexed_merkle_vt_gf8_helpers.h"

/* Ring signatures: membership core + composable config + RSv1 wrappers */
#include "rs_membership_gf8.h"
#include "rs_membership_gf8_circuit.h"
#include "rs_gf8.h"
#include "ring_sig_v1_gf8.h"

#endif /* VOLEITH_GF8_H */
