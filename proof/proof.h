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
 * Variant identifiers
 *
 * These enums describe the public variant choices that may be
 * persisted in a proof's metadata header.  They live in proof.h so
 * the params struct below can carry them directly without dragging
 * the proof_header.h dependency back through every translation unit.
 * The proof_header.h symbols of the same names are re-exported from
 * here.
 * ================================================================ */

typedef enum {
    VOLEITH_FS_SHAKE = 0, /* default; FAEST v2.0 spec-conformant */
    VOLEITH_FS_GROSTL =
        1, /* Grostl-256 / Grostl-512 (FS_TRANSFORM_SWITCHING_DESIGN.md) */
} voleith_fs_kind_t;

typedef enum {
    VOLEITH_BAVC_STANDARD = 0, /* default; FAEST v2.0 GGM tree */
    VOLEITH_BAVC_HALF_TREE =
        1, /* correlated GGM (the half-tree implementation plan) */
} voleith_bavc_kind_t;

typedef enum {
    VOLEITH_PARAM_EM_128F = 0,
    VOLEITH_PARAM_EM_128S = 1,
    VOLEITH_PARAM_EM_192F = 2,
    VOLEITH_PARAM_EM_192S = 3,
    VOLEITH_PARAM_EM_256F = 4,
    VOLEITH_PARAM_EM_256S = 5,
} voleith_param_set_id_t;

/* ================================================================
 * Parameter sets
 * ================================================================ */

/*
 * VOLEitH parameter set.
 *
 * Numeric fields are derived from the FAEST v2.0 spec (meson.build);
 * fs_kind and bavc_kind select the Fiat-Shamir backend and BAVC
 * construction respectively.  The two new fields default to
 * VOLEITH_FS_SHAKE / VOLEITH_BAVC_STANDARD (both value 0), so any
 * pre-existing positional initializer that omits them remains
 * spec-conformant - though new code should set them explicitly.
 */
typedef struct {
    unsigned int lambda; /* security parameter: 128, 192, or 256 */
    unsigned int tau;    /* number of VOLE instances */
    unsigned int
        w_grind; /* grinding parameter (top bits of chall_3 must be 0) */
    unsigned int T_open; /* max revealed seeds in BAVC opening */
    unsigned int
        n_leafcom; /* lambda-bit blocks per leaf commitment (2=EM, 3=FAEST) */
    voleith_fs_kind_t fs_kind;     /* Fiat-Shamir backend */
    voleith_bavc_kind_t bavc_kind; /* BAVC construction */
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
 * Construct a voleith_params_t from variant choices.
 *
 * set:  named parameter set (see voleith_param_set_id_t).
 * fs:   Fiat-Shamir backend selection.
 * bavc: BAVC construction selection.
 *
 * Returns a fully-populated params struct by value.  The returned
 * struct has fs_kind and bavc_kind set to the caller's choices and
 * lambda/tau/w_grind/T_open/n_leafcom drawn from the named set.
 *
 * On an out-of-range `set`, the returned struct is zero-initialized
 * (lambda == 0) and should be rejected by voleith_params_validate.
 * Cross-field validity (e.g. lambda=192 with fs=GROSTL, currently
 * deferred) is not enforced here; downstream code that does not
 * support a combination is responsible for rejecting it.
 */
voleith_params_t voleith_params_build(voleith_param_set_id_t set,
                                      voleith_fs_kind_t fs,
                                      voleith_bavc_kind_t bavc);

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
 *
 *              SECURITY (M-N2): the Fiat-Shamir transcript hashes
 *              only fs_seed, instance, and the BAVC commitment.  It
 *              does NOT bind the circuit identity, parameter set, or
 *              library version.  The caller MUST include all of:
 *                - a circuit/protocol identifier (so a proof for one
 *                  circuit cannot be replayed against a different
 *                  one whose witness/instance layout coincides),
 *                - a packed encoding of `params` (lambda, tau,
 *                  w_grind, n_leafcom, T_open),
 *                - a library/transcript version tag.
 *              Auto-binding is planned for 1.3.0 alongside the proof
 *              metadata header; until then this is a caller
 *              obligation.
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
 * Expected byte length of the witness / instance buffer for the
 * bit-level prove/verify API.  Witness and instance bits are
 * bit-packed LSB-first per byte, so the buffer size is
 * ceil(wire_count / 8).
 *
 * Use these to feed the _v2 entry points without duplicating the
 * encoding math at every call site:
 *
 *     voleith_prove_v2(&p, params, c, witness,
 *                      voleith_circuit_witness_byte_len(c),
 *                      instance,
 *                      voleith_circuit_instance_byte_len(c),
 *                      fs_seed, fs_seed_len);
 *
 * Returns 0 if circuit is NULL (no read of the witness/instance
 * buffer is safe in that case anyway; voleith_prove_v2 will reject).
 */
size_t voleith_circuit_witness_byte_len(const voleith_circuit_t *circuit);
size_t voleith_circuit_instance_byte_len(const voleith_circuit_t *circuit);

/*
 * Length-validated prove (M-N3, 1.3.0).
 *
 * Same protocol as voleith_prove, but accepts explicit byte lengths for
 * witness and instance.  Rejects mismatches at the public API boundary
 * before any reads, eliminating the OOB-read concern on caller miscount.
 *
 * Use voleith_circuit_witness_byte_len() and
 * voleith_circuit_instance_byte_len() to compute the expected lengths
 * from the circuit:
 *   witness_len  == voleith_circuit_witness_byte_len(circuit)
 *   instance_len == voleith_circuit_instance_byte_len(circuit)
 *
 * `voleith_prove` is preserved for source-compatibility and will be
 * removed in 2.0.0; new code should use voleith_prove_v2.
 *
 * Returns 0 on success, -1 on length mismatch or any condition that
 * would cause voleith_prove to fail.
 */
int voleith_prove_v2(voleith_proof_t *proof, const voleith_params_t *params,
                     const voleith_circuit_t *circuit, const uint8_t *witness,
                     size_t witness_len, const uint8_t *instance,
                     size_t instance_len, const uint8_t *fs_seed,
                     size_t fs_seed_len);

/*
 * Verify a non-interactive proof.
 *
 * params:      parameter set (must match the one used to prove)
 * circuit:     the Boolean circuit (must match the one used to prove)
 * instance:    bit-packed public input (same as used to prove)
 * fs_seed:     Fiat-Shamir seed (same as used to prove).  See
 *              voleith_prove() above for the M-N2 caller-binding
 *              requirement (circuit id + packed params + version tag
 *              must be hashed into fs_seed by the caller until
 *              auto-binding lands in 1.3.0).
 * fs_seed_len: length of fs_seed in bytes
 * proof:       the proof to verify
 *
 * Returns 0 if the proof is valid, -1 if it is invalid or malformed.
 */
int voleith_verify(const voleith_proof_t *proof, const voleith_params_t *params,
                   const voleith_circuit_t *circuit, const uint8_t *instance,
                   const uint8_t *fs_seed, size_t fs_seed_len);

/*
 * Length-validated verify (M-N3, 1.3.0).  See voleith_prove_v2 above
 * for the rationale and the deprecation timeline of voleith_verify.
 *
 * Required:
 *   instance_len == voleith_circuit_instance_byte_len(circuit)
 *
 * Returns 0 if the proof is valid, -1 on length mismatch or any
 * condition that would cause voleith_verify to reject.
 */
int voleith_verify_v2(const voleith_proof_t *proof,
                      const voleith_params_t *params,
                      const voleith_circuit_t *circuit, const uint8_t *instance,
                      size_t instance_len, const uint8_t *fs_seed,
                      size_t fs_seed_len);

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
 * SECURITY (M-N2): in the two-phase mode, chall_1 is produced by
 * the caller's shared transcript, so it is the caller's
 * responsibility to absorb a circuit identifier, packed `params`,
 * and a library/transcript version tag into that transcript
 * alongside the commitment blob and any classical-component
 * commitments.  See voleith_prove() for the same caller-binding
 * requirement on the one-shot API.
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
 *
 * Single source of truth for the chall_1 length.  The two-phase respond
 * functions read EXACTLY this many bytes from the caller-supplied chall_1
 * pointer and cannot validate its length (a raw pointer carries none), so
 * the caller MUST size the buffer with this helper; a shorter buffer is an
 * out-of-bounds read.
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
 * the shared transcript (which must include the commitment blob).  This
 * function reads exactly that many bytes and does not check the length;
 * a shorter buffer is an out-of-bounds read (caller's responsibility).
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
 * chall_1 must be voleith_chall1_bytes(params->lambda) bytes; this function
 * reads exactly that many bytes and does not check the length, so a shorter
 * buffer is an out-of-bounds read (caller's responsibility).
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
