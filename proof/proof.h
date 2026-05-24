/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * proof.h - Full VOLEitH non-interactive proof system
 *
 * Top-level prove/verify API integrating:
 *   - VOLEitH commitment (GGM tree + ConvertToVOLE)
 *   - Fiat-Shamir transcript (challenge derivation via SHAKE)
 *   - QuickSilver prover/verifier
 *   - VOLEHash (universal hash for VOLE compression)
 *
 * Protocol flow (Prove):
 *   1. Derive root_seed || iv  via H_3(fs_seed)
 *   2. VOLEitH commit            → hcom, u, c[0..τ-2], V
 *   3. chall_1 = H_2^1(fs_seed || instance || hcom || c || iv)   [5λ/8+8 bytes]
 *   4. u_tilde = VOLEHash(chall_1, u, ell)                        [λ/8+2 bytes]
 *   5. For each row i: V_tilde[i] = VOLEHash(chall_1, V[i], ell)  [λ/8+2 bytes]
 *   6. d = compute_d(circuit, witness, instance, u)               [⌈ell/8⌉ bytes]
 *   7. chall_2 = H_2^2(chall_1 || u_tilde || V_tilde[0..λ-1] || d)  [3λ/8+8 bytes]
 *   8. QS prove → (d, a0_tilde, a1_tilde, a2_tilde)
 *   9. chall_3 = H_2^3(chall_2 || a0_tilde || a1_tilde || a2_tilde || ctr_LE32)
 *      grinding: retry with ctr++ until top w_grind bits of chall_3 are 0
 *  10. i_delta = decode_challenge(chall_3)
 *  11. BAVC open at i_delta → decom_i
 *  12. σ = (c, u_tilde, d, a1_tilde, a2_tilde, decom_i, chall_3, iv, ctr)
 *
 * Protocol flow (Verify):
 *   1. Check top w_grind bits of chall_3 are 0
 *   2. Decode i_delta from chall_3
 *   3. VOLEitH reconstruct: hcom, Q from (decom_i, c, chall_3, iv)
 *   4. chall_1 = H_2^1(fs_seed || instance || hcom || c || iv)
 *   5. For each row i: D[i] = VOLEHash(chall_1, Q[i], ell)
 *      If bit i of chall_3 is set: D[i] XOR= u_tilde
 *   6. chall_2 = H_2^2(chall_1 || u_tilde || D[0..λ-1] || d)
 *   7. QS verify(Q, d, chall_3_as_delta, chall_2, a1_tilde, a2_tilde) → a0_tilde_out
 *   8. chall_3' = H_2^3(chall_2 || a0_tilde_out || a1_tilde || a2_tilde || ctr)
 *   9. Accept iff chall_3 == chall_3'
 */

#ifndef VOLEITH_PROOF_H
#define VOLEITH_PROOF_H

#include <stdint.h>
#include <stddef.h>
#include "circuit.h"

/* ================================================================
 * Parameter sets
 * ================================================================ */

/*
 * VOLEitH parameter set.
 *
 * All fields are derived from the FAEST v2.0 spec (meson.build).
 */
typedef struct {
    unsigned int lambda; /* security parameter: 128, 192, or 256 */
    unsigned int tau;    /* number of VOLE instances */
    unsigned int
        w_grind; /* grinding parameter (top bits of chall_3 must be 0) */
    unsigned int T_open; /* max revealed seeds in BAVC opening */
    unsigned int
        n_leafcom; /* lambda-bit blocks per leaf commitment (2=EM, 3=FAEST) */
} voleith_params_t;

/* FAEST-EM-128s: λ=128, τ=11, w_grind=7, T_open=103, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_128s;

/* FAEST-EM-128f: λ=128, τ=16, w_grind=8, T_open=112, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_128f;

/* FAEST-EM-192s: λ=192, τ=16, w_grind=8, T_open=162, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_192s;

/* FAEST-EM-192f: λ=192, τ=24, w_grind=8, T_open=176, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_192f;

/* FAEST-EM-256s: λ=256, τ=22, w_grind=6, T_open=218, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_256s;

/* FAEST-EM-256f: λ=256, τ=32, w_grind=8, T_open=234, n_leafcom=2 */
extern const voleith_params_t voleith_params_em_256f;

/*
 * Validate a voleith_params_t at the public API boundary.
 *
 * Returns 0 if every field falls within the supported ranges:
 *   lambda    ∈ {128, 192, 256}
 *   tau       ∈ [1, 32]            (upper bound = stack i_delta[32])
 *   w_grind   < lambda             (otherwise lambda - w_grind underflows)
 *   n_leafcom ∈ {2, 3}             (2 = FAEST-EM, 3 = FAEST)
 *   T_open    > 0
 *
 * Returns -1 otherwise.  Called at the top of every public prove /
 * verify entry point so caller-constructed parameters get a clean
 * rejection at the API boundary rather than tripping deeper checks
 * via implementation-defined unsigned-to-signed conversions.
 */
int voleith_params_validate(const voleith_params_t *params);

/* ================================================================
 * Proof object
 * ================================================================ */

/*
 * A serialized non-interactive proof.
 *
 * data: flat proof buffer (all components serialized back-to-back)
 * len:  proof length in bytes
 *
 * Proof layout (offsets depend on params and circuit ell):
 *   [c_0 | ... | c_{τ-2}]          (τ-1) × ellhat_bytes
 *   [u_tilde]                        λ/8 + 2 bytes
 *   [d]                              ⌈ell/8⌉ bytes
 *   [a1_tilde]                       λ/8 bytes
 *   [a2_tilde]                       λ/8 bytes
 *   [decom_i]                        n_leafcom×τ×(λ/8) + T_open×(λ/8) bytes
 *   [chall_3]                        λ/8 bytes
 *   [iv]                             16 bytes
 *   [ctr]                            4 bytes (uint32_t little-endian)
 */
typedef struct {
    uint8_t *data;
    size_t len;
} voleith_proof_t;

/* ================================================================
 * Proof size
 * ================================================================ */

/*
 * Compute the proof size in bytes for the given params and circuit ell.
 *
 * ell = witness_count + and_gate_count (use voleith_qs_ell(circuit)).
 */
size_t voleith_proof_byte_size(const voleith_params_t *params, size_t ell);

/* ================================================================
 * Prove and verify
 * ================================================================ */

/*
 * Generate a non-interactive proof.
 *
 * params:      parameter set (security level, grinding, etc.)
 * circuit:     the Boolean circuit
 * witness:     bit-packed private input (witness_count bits, LE bit order)
 * instance:    bit-packed public input (instance_count bits, LE bit order);
 *              may be NULL if instance_count == 0
 * fs_seed:     Fiat-Shamir seed (randomness + public data commitment).
 *              Should include all public data (message, public key, etc.)
 *              and be unique per proof (e.g. include fresh randomness).
 * fs_seed_len: length of fs_seed in bytes
 * proof:       output - proof->data is malloc'd by this function
 *
 * Returns 0 on success, -1 on error.
 * Caller must call voleith_proof_free(proof) after use.
 */
int voleith_prove(voleith_proof_t *proof, const voleith_params_t *params,
                  const voleith_circuit_t *circuit, const uint8_t *witness,
                  const uint8_t *instance, const uint8_t *fs_seed,
                  size_t fs_seed_len);

/*
 * Verify a non-interactive proof.
 *
 * params:      parameter set (must match the one used to prove)
 * circuit:     the Boolean circuit (must match the one used to prove)
 * instance:    bit-packed public input (same as used to prove)
 * fs_seed:     Fiat-Shamir seed (same as used to prove)
 * fs_seed_len: length of fs_seed in bytes
 * proof:       the proof to verify
 *
 * Returns 0 if the proof is valid, -1 if it is invalid or malformed.
 */
int voleith_verify(const voleith_proof_t *proof, const voleith_params_t *params,
                   const voleith_circuit_t *circuit, const uint8_t *instance,
                   const uint8_t *fs_seed, size_t fs_seed_len);

/*
 * Free all heap memory in a proof.
 */
void voleith_proof_free(voleith_proof_t *proof);

/* ================================================================
 * Two-phase prove/verify API (for hybrid proof systems)
 *
 * These functions split voleith_prove() and voleith_verify() at the
 * first Fiat-Shamir challenge (chall_1), so that chall_1 can be derived
 * from an external shared transcript rather than computed internally.
 *
 * Signal KVAC usage pattern (prove side):
 *
 *   size_t blob_len = voleith_commit_blob_size(params, circuit);
 *   uint8_t *blob = malloc(blob_len);                // hcom || c || iv
 *
 *   voleith_prover_commit_t *ctx;
 *   voleith_prove_commit(&ctx, params, circuit, witness, instance,
 *                        fs_seed, fs_seed_len, blob);
 *
 *   // Mix blob into shared transcript; also absorb classical commitment;
 *   // squeeze chall_1 (exactly voleith_chall1_bytes(lambda) bytes).
 *   uint8_t chall_1[...];
 *   shared_transcript_squeeze(chall_1, voleith_chall1_bytes(params->lambda));
 *
 *   voleith_proof_t proof;
 *   voleith_prove_respond(&proof, ctx, circuit, witness, instance, chall_1);
 *   voleith_prover_commit_free(ctx);
 *   free(blob);
 *
 * Signal KVAC usage pattern (verify side):
 *
 *   size_t blob_len = voleith_commit_blob_size(params, circuit);
 *   uint8_t *blob = malloc(blob_len);
 *
 *   voleith_verifier_reconstruct_t *ctx;
 *   voleith_verify_reconstruct(&ctx, proof, params, circuit, blob);
 *
 *   // Mix blob into shared transcript alongside classical verification data;
 *   // squeeze chall_1.
 *   uint8_t chall_1[...];
 *   shared_transcript_squeeze(chall_1, voleith_chall1_bytes(params->lambda));
 *
 *   int ok = voleith_verify_respond(ctx, circuit, instance, chall_1);
 *   voleith_verifier_reconstruct_free(ctx);
 *   free(blob);
 * ================================================================ */

/*
 * Opaque prover context between commit and respond phases.
 * Allocated by voleith_prove_commit(), freed by voleith_prover_commit_free().
 */
typedef struct voleith_prover_commit_t voleith_prover_commit_t;

/*
 * Opaque verifier context between reconstruct and respond phases.
 * Allocated by voleith_verify_reconstruct(), freed by voleith_verifier_reconstruct_free().
 */
typedef struct voleith_verifier_reconstruct_t voleith_verifier_reconstruct_t;

/*
 * Size of the commitment blob: 2*(lambda/8) + (tau-1)*ellhat_bytes + 16 bytes.
 * Allocate this many bytes for the commitment_out buffer.
 */
size_t voleith_commit_blob_size(const voleith_params_t *params,
                                const voleith_circuit_t *circuit);

/*
 * Size of chall_1 in bytes: 5*(lambda/8) + 8.
 */
static inline size_t
voleith_chall1_bytes(unsigned int lambda)
{
    return 5u * (lambda / 8u) + 8u;
}

/*
 * Phase 1 (Prove): VOLEitH commit.
 *
 * Performs steps 1-2 of the prove protocol (H_3 seed derivation + GGM commit).
 * Writes hcom || c || iv into commitment_out (voleith_commit_blob_size bytes).
 * This blob should be absorbed into the shared Fiat-Shamir transcript.
 *
 * On success, *ctx_out is heap-allocated; free with voleith_prover_commit_free().
 * Returns 0 on success, -1 on error.
 */
int voleith_prove_commit(voleith_prover_commit_t **ctx_out,
                         const voleith_params_t *params,
                         const voleith_circuit_t *circuit,
                         const uint8_t *witness, const uint8_t *instance,
                         const uint8_t *fs_seed, size_t fs_seed_len,
                         uint8_t *commitment_out);

/*
 * Phase 2 (Prove): Complete the proof given the external Fiat-Shamir challenge.
 *
 * chall_1 must be voleith_chall1_bytes(params->lambda) bytes, derived from
 * the shared transcript (which must include the commitment blob).
 * witness and instance must be the same as passed to voleith_prove_commit().
 *
 * On success, proof_out->data is malloc'd; caller must voleith_proof_free() it.
 * Call voleith_prover_commit_free(ctx) after this returns regardless of result.
 * Returns 0 on success, -1 on error.
 */
int voleith_prove_respond(voleith_proof_t *proof_out,
                          voleith_prover_commit_t *ctx,
                          const voleith_circuit_t *circuit,
                          const uint8_t *witness, const uint8_t *instance,
                          const uint8_t *chall_1);

/*
 * Free context from voleith_prove_commit().  Safe to call with NULL.
 */
void voleith_prover_commit_free(voleith_prover_commit_t *ctx);

/*
 * Phase 1 (Verify): BAVC reconstruct and extract commitment blob.
 *
 * Performs steps 1-3 of the verify protocol (grinding check, i_delta decode,
 * BAVC reconstruct → hcom_rec).  Writes hcom_rec || c || iv into commitment_out
 * (voleith_commit_blob_size bytes); absorb this blob into the shared transcript
 * to reproduce the prover's chall_1.
 *
 * On success, *ctx_out is heap-allocated; free with voleith_verifier_reconstruct_free().
 * Returns 0 on success, -1 if the proof is malformed or grinding check fails.
 */
int voleith_verify_reconstruct(voleith_verifier_reconstruct_t **ctx_out,
                               const voleith_proof_t *proof,
                               const voleith_params_t *params,
                               const voleith_circuit_t *circuit,
                               uint8_t *commitment_out);

/*
 * Phase 2 (Verify): Complete verification given the external Fiat-Shamir challenge.
 *
 * chall_1 must be voleith_chall1_bytes(params->lambda) bytes.
 * instance must be the same as used to prove.
 *
 * Call voleith_verifier_reconstruct_free(ctx) after this returns.
 * Returns 0 if the proof is valid, -1 if it is invalid.
 */
int voleith_verify_respond(voleith_verifier_reconstruct_t *ctx,
                           const voleith_circuit_t *circuit,
                           const uint8_t *instance, const uint8_t *chall_1);

/*
 * Free context from voleith_verify_reconstruct().  Safe to call with NULL.
 */
void voleith_verifier_reconstruct_free(voleith_verifier_reconstruct_t *ctx);

#endif /* VOLEITH_PROOF_H */
