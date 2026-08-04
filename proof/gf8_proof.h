/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf8_proof.h - Full VOLEitH non-interactive proof system (element-level)
 *
 * Fiat-Shamir wrapper for the GF(2⁸) element-level QuickSilver proof system.
 * Protocol structure, grinding loop, BAVC open/reconstruct, and proof layout
 * are identical to proof.h/proof.c.  The only differences from the bit-level
 * variant are:
 *
 *   - circuit type: voleith_gf8_circuit_t instead of voleith_circuit_t
 *   - d vector is ell bytes (one byte per GF(2⁸) slot), not ceil(ell/8) bytes
 *   - ellhat_bytes = ell + ceil((3λ+16)/8), computed directly in bytes
 *   - witness and instance arrays are byte-arrays (one byte per wire)
 *
 * The voleith_params_t, voleith_proof_t, parameter set constants, and
 * voleith_chall1_bytes() are reused unchanged from proof.h.
 *
 * Proof layout (same structure as bit-level, d size differs):
 *   [c_0 | ... | c_{τ-2}]          (τ-1) × ellhat_bytes
 *   [u_tilde]                        λ/8 + 2 bytes
 *   [d]                              ell bytes   (GF(2⁸): one byte per slot)
 *   [a1_tilde]                       λ/8 bytes
 *   [a2_tilde]                       λ/8 bytes
 *   [decom_i]                        n_leafcom×τ×(λ/8) + T_open×(λ/8) bytes
 *   [chall_3]                        λ/8 bytes
 *   [iv]                             16 bytes
 *   [ctr]                            4 bytes (uint32_t little-endian)
 */

#ifndef VOLEITH_GF8_PROOF_H
#define VOLEITH_GF8_PROOF_H

#include <stdint.h>
#include <stddef.h>
#include "proof.h"       /* voleith_params_t, voleith_proof_t, parameter sets */
#include "gf8_circuit.h" /* voleith_gf8_circuit_t */

/* ================================================================
 * Proof size
 * ================================================================ */

/*
 * Compute the proof size in bytes for the given params and GF(2⁸) circuit ell.
 *
 * ell = voleith_gf8_qs_ell(circuit)  (count of GF(2⁸) element slots).
 *
 * NOTE: this overload has no circuit, so it cannot know the QuickSilver opening
 * degree and assumes the degree-2 baseline.  It is correct for every circuit
 * that uses only MUL / assert_product (degree 2).  For a circuit carrying a
 * higher-degree constraint (e.g. a less-than / opener circuit) the proof is
 * larger; use voleith_gf8_proof_byte_size_circuit() instead, which derives both
 * ell and the opening degree from the circuit.
 */
size_t voleith_gf8_proof_byte_size(const voleith_params_t *params, size_t ell);

/*
 * Degree-aware proof size: derives both ell and the QuickSilver opening degree
 * (voleith_gf8_circuit_qs_degree) from the circuit, so it is correct for
 * degree-d (d > 2) circuits as well.  Returns 0 on NULL input.
 */
size_t
voleith_gf8_proof_byte_size_circuit(const voleith_params_t *params,
                                    const voleith_gf8_circuit_t *circuit);

/* ================================================================
 * Prove and verify
 * ================================================================ */

/*
 * Generate a non-interactive proof for a GF(2⁸) element-level circuit.
 *
 * params:      parameter set (security level, grinding, etc.)
 * circuit:     the GF(2⁸) element circuit
 * witness:     private input - one byte per witness wire (witness_count bytes);
 *              byte i corresponds to the i-th voleith_gf8_add_witness() call
 * instance:    public input - one byte per instance wire (instance_count bytes);
 *              may be NULL if instance_count == 0
 * fs_seed:     Fiat-Shamir seed; should incorporate all public data and be
 *              unique per proof (include fresh randomness).
 *
 *              SECURITY (M-N2): the Fiat-Shamir transcript hashes
 *              only fs_seed, instance, and the BAVC commitment.  It
 *              does NOT bind the circuit identity, parameter set, or
 *              library version.  The caller MUST hash into fs_seed:
 *                - a circuit/protocol identifier,
 *                - a packed encoding of `params` (lambda, tau,
 *                  w_grind, n_leafcom, T_open),
 *                - a library/transcript version tag.
 *              Auto-binding is planned for 1.3.0 alongside the proof
 *              metadata header; until then this is a caller
 *              obligation.
 * fs_seed_len: length of fs_seed in bytes
 * proof:       output - proof->data is malloc'd; caller calls voleith_proof_free()
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_gf8_prove(voleith_proof_t *proof, const voleith_params_t *params,
                      const voleith_gf8_circuit_t *circuit,
                      const uint8_t *witness, const uint8_t *instance,
                      const uint8_t *fs_seed, size_t fs_seed_len);

/*
 * Expected byte length of the witness / instance buffer for the
 * GF(2⁸) prove/verify API.  GF(2⁸) circuits use one byte per
 * witness/instance wire, so the buffer size is the wire count
 * directly (no bit-packing).
 *
 * Use these to feed the _v2 entry points without duplicating the
 * encoding convention at every call site:
 *
 *     voleith_gf8_prove_v2(&p, params, c, witness,
 *                          voleith_gf8_circuit_witness_byte_len(c),
 *                          instance,
 *                          voleith_gf8_circuit_instance_byte_len(c),
 *                          fs_seed, fs_seed_len);
 *
 * Returns 0 if circuit is NULL (no read of the witness/instance
 * buffer is safe in that case anyway; voleith_gf8_prove_v2 will
 * reject).
 */
size_t
voleith_gf8_circuit_witness_byte_len(const voleith_gf8_circuit_t *circuit);
size_t
voleith_gf8_circuit_instance_byte_len(const voleith_gf8_circuit_t *circuit);

/*
 * Length-validated GF(2⁸) prove (M-N3, 1.3.0).
 *
 * Use voleith_gf8_circuit_witness_byte_len() and
 * voleith_gf8_circuit_instance_byte_len() to compute the expected
 * lengths from the circuit:
 *   witness_len  == voleith_gf8_circuit_witness_byte_len(circuit)
 *   instance_len == voleith_gf8_circuit_instance_byte_len(circuit)
 *
 * voleith_gf8_prove is preserved for source-compatibility and will be
 * removed in 2.0.0; new code should use voleith_gf8_prove_v2.
 *
 * Returns 0 on success, -1 on length mismatch or any condition that
 * would cause voleith_gf8_prove to fail.
 */
int voleith_gf8_prove_v2(voleith_proof_t *proof, const voleith_params_t *params,
                         const voleith_gf8_circuit_t *circuit,
                         const uint8_t *witness, size_t witness_len,
                         const uint8_t *instance, size_t instance_len,
                         const uint8_t *fs_seed, size_t fs_seed_len);

/*
 * Verify a non-interactive proof for a GF(2⁸) element-level circuit.
 *
 * See voleith_gf8_prove() above for the M-N2 caller-binding
 * requirement on fs_seed.
 *
 * Returns 0 if the proof is valid, -1 if invalid or malformed.
 */
int voleith_gf8_verify(const voleith_proof_t *proof,
                       const voleith_params_t *params,
                       const voleith_gf8_circuit_t *circuit,
                       const uint8_t *instance, const uint8_t *fs_seed,
                       size_t fs_seed_len);

/*
 * Length-validated GF(2⁸) verify (M-N3, 1.3.0).  See
 * voleith_gf8_prove_v2 for the rationale and the deprecation timeline
 * of voleith_gf8_verify.
 *
 * Required:
 *   instance_len == voleith_gf8_circuit_instance_byte_len(circuit)
 */
int voleith_gf8_verify_v2(const voleith_proof_t *proof,
                          const voleith_params_t *params,
                          const voleith_gf8_circuit_t *circuit,
                          const uint8_t *instance, size_t instance_len,
                          const uint8_t *fs_seed, size_t fs_seed_len);

/* ================================================================
 * Two-phase prove/verify API (for hybrid proof systems)
 *
 * Mirrors the bit-level two-phase API in proof.h.  See proof.h for
 * the Signal KVAC shared-transcript usage pattern; replace all
 * voleith_* calls with voleith_gf8_* and voleith_circuit_t with
 * voleith_gf8_circuit_t.
 * ================================================================ */

typedef struct voleith_gf8_prover_commit_t voleith_gf8_prover_commit_t;
typedef struct voleith_gf8_verifier_reconstruct_t
    voleith_gf8_verifier_reconstruct_t;

/*
 * Size of the commitment blob in bytes: 2*(λ/8) + (τ-1)*ellhat_bytes + 16.
 */
size_t voleith_gf8_commit_blob_size(const voleith_params_t *params,
                                    const voleith_gf8_circuit_t *circuit);

/*
 * Phase 1 (Prove): VOLEitH commit.
 *
 * Writes hcom || c || iv into commitment_out (voleith_gf8_commit_blob_size bytes).
 * On success, *ctx_out is heap-allocated; free with voleith_gf8_prover_commit_free().
 * Returns 0 on success, -1 on error.
 */
int voleith_gf8_prove_commit(voleith_gf8_prover_commit_t **ctx_out,
                             const voleith_params_t *params,
                             const voleith_gf8_circuit_t *circuit,
                             const uint8_t *witness, const uint8_t *instance,
                             const uint8_t *fs_seed, size_t fs_seed_len,
                             uint8_t *commitment_out);

/*
 * Phase 2 (Prove): Complete the proof given the external Fiat-Shamir challenge.
 *
 * chall_1 must be voleith_chall1_bytes(params->lambda) bytes; this function
 * reads exactly that many bytes and does not check the length, so a shorter
 * buffer is an out-of-bounds read (caller's responsibility).
 * witness and instance must be the same as passed to voleith_gf8_prove_commit().
 * On success, proof_out->data is malloc'd; caller must voleith_proof_free() it.
 * Returns 0 on success, -1 on error.
 */
int voleith_gf8_prove_respond(voleith_proof_t *proof_out,
                              voleith_gf8_prover_commit_t *ctx,
                              const voleith_gf8_circuit_t *circuit,
                              const uint8_t *witness, const uint8_t *instance,
                              const uint8_t *chall_1);

/* Free context from voleith_gf8_prove_commit().  Safe to call with NULL. */
void voleith_gf8_prover_commit_free(voleith_gf8_prover_commit_t *ctx);

/*
 * Phase 1 (Verify): BAVC reconstruct and extract commitment blob.
 *
 * Writes hcom_rec || c || iv into commitment_out (voleith_gf8_commit_blob_size bytes).
 * On success, *ctx_out is heap-allocated; free with voleith_gf8_verifier_reconstruct_free().
 * Returns 0 on success, -1 if the proof is malformed or grinding check fails.
 */
int voleith_gf8_verify_reconstruct(voleith_gf8_verifier_reconstruct_t **ctx_out,
                                   const voleith_proof_t *proof,
                                   const voleith_params_t *params,
                                   const voleith_gf8_circuit_t *circuit,
                                   uint8_t *commitment_out);

/*
 * Phase 2 (Verify): Complete verification given the external Fiat-Shamir challenge.
 *
 * chall_1 must be voleith_chall1_bytes(params->lambda) bytes; this function
 * reads exactly that many bytes and does not check the length, so a shorter
 * buffer is an out-of-bounds read (caller's responsibility).
 * Returns 0 if the proof is valid, -1 if invalid.
 */
int voleith_gf8_verify_respond(voleith_gf8_verifier_reconstruct_t *ctx,
                               const voleith_gf8_circuit_t *circuit,
                               const uint8_t *instance, const uint8_t *chall_1);

/* Free context from voleith_gf8_verify_reconstruct().  Safe to call with NULL. */
void
voleith_gf8_verifier_reconstruct_free(voleith_gf8_verifier_reconstruct_t *ctx);

#endif /* VOLEITH_GF8_PROOF_H */
