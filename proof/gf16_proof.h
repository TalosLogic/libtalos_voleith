/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * gf16_proof.h - Full VOLEitH non-interactive proof system (GF(2^16))
 *
 * Fiat-Shamir wrapper for the GF(2^16) element-level QuickSilver proof
 * system.  Protocol structure, grinding loop, BAVC open/reconstruct, proof
 * layout, and two-phase split are identical to gf8_proof.h.  Differences from
 * the GF(2^8) variant:
 *
 *   - circuit type: voleith_gf16_circuit_t
 *   - d vector is 2*ell bytes (one 16-bit LE element per slot)
 *   - ellhat_bytes = 2*ell + ceil((3*lambda+16)/8)
 *   - witness and instance arrays are GF(2^16) element arrays
 *     (voleith_gf16_t, one element per wire), not byte arrays
 *
 * The voleith_params_t, voleith_proof_t, parameter set constants, and
 * voleith_chall1_bytes() are reused unchanged from proof.h.
 *
 * Proof layout (same structure as gf8, d size differs):
 *   [c_0 | ... | c_{tau-2}]        (tau-1) x ellhat_bytes
 *   [u_tilde]                        lambda/8 + 2 bytes
 *   [d]                              2*ell bytes  (GF(2^16): 16-bit LE / slot)
 *   [a1_tilde]                       lambda/8 bytes
 *   [a2_tilde]                       lambda/8 bytes
 *   [decom_i]                        n_leafcom x tau x (lambda/8) + ...
 *   [chall_3]                        lambda/8 bytes
 *   [iv]                             16 bytes
 *   [ctr]                            4 bytes (uint32_t little-endian)
 */

#ifndef VOLEITH_GF16_PROOF_H
#define VOLEITH_GF16_PROOF_H

#include <stdint.h>
#include <stddef.h>
#include "proof.h"        /* voleith_params_t, voleith_proof_t, param sets */
#include "gf16_circuit.h" /* voleith_gf16_circuit_t, voleith_gf16_t */

/* ================================================================
 * Proof size
 * ================================================================ */

/*
 * Proof size in bytes for the given params and GF(2^16) circuit ell.
 * ell = voleith_gf16_qs_ell(circuit) (count of GF(2^16) element slots).
 */
size_t voleith_gf16_proof_byte_size(const voleith_params_t *params, size_t ell);

/* ================================================================
 * Prove and verify
 * ================================================================ */

/*
 * Generate a non-interactive proof for a GF(2^16) element-level circuit.
 *
 * witness:  private input, one GF(2^16) element per witness wire
 * instance: public input, one GF(2^16) element per instance wire; may be NULL
 *           if instance_count == 0
 * fs_seed:  Fiat-Shamir seed.  SECURITY (M-N2, same as gf8): the transcript
 *           binds the circuit / params identity through the v1 metadata
 *           header that rides inside the commitment blob, but the caller
 *           must still incorporate fresh per-proof randomness into fs_seed.
 *
 * Returns 0 on success, -1 on error.
 */
int voleith_gf16_prove(voleith_proof_t *proof, const voleith_params_t *params,
                       const voleith_gf16_circuit_t *circuit,
                       const voleith_gf16_t *witness,
                       const voleith_gf16_t *instance, const uint8_t *fs_seed,
                       size_t fs_seed_len);

/*
 * Expected length (in GF(2^16) elements) of the witness / instance buffer for
 * the GF(2^16) prove/verify API.  GF(2^16) circuits use one element per wire,
 * so the buffer length is the wire count directly.  Returns 0 if circuit is
 * NULL.
 */
size_t voleith_gf16_circuit_witness_len(const voleith_gf16_circuit_t *circuit);
size_t voleith_gf16_circuit_instance_len(const voleith_gf16_circuit_t *circuit);

/*
 * Length-validated GF(2^16) prove.  witness_len and instance_len are in
 * GF(2^16) elements and must equal voleith_gf16_circuit_witness_len() /
 * voleith_gf16_circuit_instance_len() respectively.
 *
 * Returns 0 on success, -1 on length mismatch or any prove failure.
 */
int voleith_gf16_prove_v2(voleith_proof_t *proof,
                          const voleith_params_t *params,
                          const voleith_gf16_circuit_t *circuit,
                          const voleith_gf16_t *witness, size_t witness_len,
                          const voleith_gf16_t *instance, size_t instance_len,
                          const uint8_t *fs_seed, size_t fs_seed_len);

/*
 * Verify a non-interactive proof for a GF(2^16) element-level circuit.
 * Returns 0 if valid, -1 if invalid or malformed.
 */
int voleith_gf16_verify(const voleith_proof_t *proof,
                        const voleith_params_t *params,
                        const voleith_gf16_circuit_t *circuit,
                        const voleith_gf16_t *instance, const uint8_t *fs_seed,
                        size_t fs_seed_len);

/*
 * Length-validated GF(2^16) verify.  instance_len is in GF(2^16) elements and
 * must equal voleith_gf16_circuit_instance_len(circuit).
 */
int voleith_gf16_verify_v2(const voleith_proof_t *proof,
                           const voleith_params_t *params,
                           const voleith_gf16_circuit_t *circuit,
                           const voleith_gf16_t *instance, size_t instance_len,
                           const uint8_t *fs_seed, size_t fs_seed_len);

/* ================================================================
 * Two-phase prove/verify API (for hybrid proof systems)
 *
 * Mirrors the gf8 two-phase API.  The split point is chall_1: phase 1
 * produces the commitment blob, the caller derives chall_1 over a shared
 * transcript, phase 2 completes the proof / verification.
 * ================================================================ */

typedef struct voleith_gf16_prover_commit_t voleith_gf16_prover_commit_t;
typedef struct voleith_gf16_verifier_reconstruct_t
    voleith_gf16_verifier_reconstruct_t;

/* Commitment blob size: header + 2*(lambda/8) + (tau-1)*ellhat_bytes + 16. */
size_t voleith_gf16_commit_blob_size(const voleith_params_t *params,
                                     const voleith_gf16_circuit_t *circuit);

/*
 * Phase 1 (Prove): VOLEitH commit.  Writes header || hcom || c || iv into
 * commitment_out (voleith_gf16_commit_blob_size bytes).  On success *ctx_out
 * is heap-allocated; free with voleith_gf16_prover_commit_free().
 */
int voleith_gf16_prove_commit(voleith_gf16_prover_commit_t **ctx_out,
                              const voleith_params_t *params,
                              const voleith_gf16_circuit_t *circuit,
                              const voleith_gf16_t *witness,
                              const voleith_gf16_t *instance,
                              const uint8_t *fs_seed, size_t fs_seed_len,
                              uint8_t *commitment_out);

/*
 * Phase 2 (Prove): complete the proof given the external chall_1
 * (voleith_chall1_bytes(params->lambda) bytes; read without a length check).
 * witness and instance must match voleith_gf16_prove_commit().  On success
 * proof_out->data is malloc'd; free with voleith_proof_free().
 */
int voleith_gf16_prove_respond(voleith_proof_t *proof_out,
                               voleith_gf16_prover_commit_t *ctx,
                               const voleith_gf16_circuit_t *circuit,
                               const voleith_gf16_t *witness,
                               const voleith_gf16_t *instance,
                               const uint8_t *chall_1);

void voleith_gf16_prover_commit_free(voleith_gf16_prover_commit_t *ctx);

/*
 * Phase 1 (Verify): BAVC reconstruct and extract the commitment blob.  Writes
 * header || hcom_rec || c || iv into commitment_out.  On success *ctx_out is
 * heap-allocated; free with voleith_gf16_verifier_reconstruct_free().
 */
int voleith_gf16_verify_reconstruct(
    voleith_gf16_verifier_reconstruct_t **ctx_out, const voleith_proof_t *proof,
    const voleith_params_t *params, const voleith_gf16_circuit_t *circuit,
    uint8_t *commitment_out);

/*
 * Phase 2 (Verify): complete verification given the external chall_1.
 * Returns 0 if valid, -1 if invalid.
 */
int voleith_gf16_verify_respond(voleith_gf16_verifier_reconstruct_t *ctx,
                                const voleith_gf16_circuit_t *circuit,
                                const voleith_gf16_t *instance,
                                const uint8_t *chall_1);

void voleith_gf16_verifier_reconstruct_free(
    voleith_gf16_verifier_reconstruct_t *ctx);

#endif /* VOLEITH_GF16_PROOF_H */
