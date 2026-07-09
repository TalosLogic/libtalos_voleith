/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_chunk_cert_proof.h - non-interactive RS chunk membership certificate
 * (Fiat-Shamir wrapper over the certificate circuit), plan T6.5.
 *
 * A certificate is a gf8_proof over the chunk membership circuit
 * (circuits/rs_chunk_cert_circuit.h): the prover (FWK holder / dataset owner)
 * attests that an FWK-blinded leaf for `chunk_digest` sits at the chunk's
 * position on the path to `merkle_root`, in zero knowledge (FWK never
 * revealed).  Two index modes:
 *
 *   PUBLIC-index: the chunk index is public (bound into the circuit and the
 *     Fiat-Shamir seed); the verifier passes it in.
 *   SECRET-index: the index is hidden in the witness with the in-circuit
 *     indexed-consistency constraint; the verifier never sees it.
 *
 * Dataset binding (design section 6.7, the T6.0 two-layer check).  The
 * certificate is bound to the dataset root R = H(merkle_root || H(metadata)),
 * not just to the bare merkle_root: the prover binds R into the Fiat-Shamir
 * seed, and the verifier first recomputes R from (merkle_root, metadata) and
 * checks it against the authoritative R it trusts (ledger-published / signed)
 * before verifying the proof against merkle_root.  So a certificate cannot be
 * replayed under a different parameter set, profile, index, or dataset.
 *
 * The Fiat-Shamir seed binds (M-N2 caller obligation): a domain tag and
 * format version, the parameter-set fingerprint, the CR profile, the chunk
 * count, the index mode (and, public mode only, the index), the dataset root
 * R, and the chunk_digest.
 *
 * See docs/ERASURE_CODES_DESIGN.md sections 6.1 / 6.6 / 6.7.
 */

#ifndef VOLEITH_RS_CHUNK_CERT_PROOF_H
#define VOLEITH_RS_CHUNK_CERT_PROOF_H

#include <stddef.h>
#include <stdint.h>

#include "proof.h"      /* voleith_params_t, voleith_proof_t */
#include "rs_dataset.h" /* voleith_rs_cr_profile_t, voleith_rs_metadata_t */

/* Fiat-Shamir seed width for the certificate (matches the RSv1 seed width). */
#define VOLEITH_RS_CHUNK_CERT_FS_SEED_BYTES 16

/*
 * voleith_rs_chunk_cert_prove - produce a PUBLIC-index certificate for the
 * chunk at `index` of an n_chunks-chunk dataset.
 *
 * The proof is emitted into proof_out (proof_out->data is malloc'd; free with
 * voleith_proof_free).  The dataset root R is derived internally as
 * compute_R(merkle_root, metadata) and bound into the Fiat-Shamir seed.
 *
 *   cr           - CR profile; MUST equal metadata->cr_profile.
 *   fwk          - secret FWK, voleith_rs_fwk_bytes(cr) bytes.
 *   chunk_digest - public, voleith_rs_cr_digest_bytes(cr) bytes.
 *   merkle_root  - public, node_bytes (= digest width) bytes.
 *   siblings     - witness sibling path, depth * node_bytes bytes (NULL iff
 *                  depth == 0), e.g. voleith_rs_tree_sibling_path output.
 *   metadata     - the dataset metadata bound to R.
 *
 * Because the underlying prove runs circuit_eval first, a wrong FWK / sibling
 * / index (one that does not walk to merkle_root) fails here with -1: only an
 * FWK holder can produce a valid certificate.  Returns 0 on success, -1 on a
 * NULL / out-of-range argument or proof-system failure.
 */
int voleith_rs_chunk_cert_prove(
    voleith_proof_t *proof_out, const voleith_params_t *params,
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *merkle_root,
    const uint8_t *siblings, const voleith_rs_metadata_t *metadata);

/*
 * voleith_rs_chunk_cert_verify - verify a PUBLIC-index certificate.
 *
 * First performs the two-layer dataset check: recomputes R from
 * (merkle_root, metadata) and rejects unless it equals the authoritative
 * R / R_len the caller trusts.  Then rebuilds the circuit for (cr, n_chunks,
 * index), fills the instance (merkle_root || chunk_digest), recomputes the
 * Fiat-Shamir seed, and verifies the proof.
 *
 * Returns 0 if the certificate is valid for this dataset, -1 otherwise (bad
 * argument, R mismatch, or invalid proof).
 */
int voleith_rs_chunk_cert_verify(const voleith_proof_t *proof,
                                 const voleith_params_t *params,
                                 voleith_rs_cr_profile_t cr, size_t n_chunks,
                                 size_t index, const uint8_t *chunk_digest,
                                 const uint8_t *merkle_root,
                                 const voleith_rs_metadata_t *metadata,
                                 const uint8_t *R, size_t R_len);

/*
 * voleith_rs_chunk_cert_prove_secret_dir - produce a SECRET-index certificate.
 *
 * Same as voleith_rs_chunk_cert_prove, but the index is hidden: it is carried
 * in the witness (with the in-circuit indexed-consistency constraint) and is
 * NOT bound into the Fiat-Shamir seed.  The prover still supplies `index` to
 * build the witness.
 */
int voleith_rs_chunk_cert_prove_secret_dir(
    voleith_proof_t *proof_out, const voleith_params_t *params,
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *merkle_root,
    const uint8_t *siblings, const voleith_rs_metadata_t *metadata);

/*
 * voleith_rs_chunk_cert_verify_secret_dir - verify a SECRET-index certificate.
 *
 * Same two-layer dataset check and proof verification as the public verify,
 * but takes no index (the index is hidden); the circuit is the index-agnostic
 * secret-dir variant.
 */
int voleith_rs_chunk_cert_verify_secret_dir(
    const voleith_proof_t *proof, const voleith_params_t *params,
    voleith_rs_cr_profile_t cr, size_t n_chunks, const uint8_t *chunk_digest,
    const uint8_t *merkle_root, const voleith_rs_metadata_t *metadata,
    const uint8_t *R, size_t R_len);

#endif /* VOLEITH_RS_CHUNK_CERT_PROOF_H */
