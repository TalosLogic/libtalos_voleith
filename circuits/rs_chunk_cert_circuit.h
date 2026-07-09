/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_chunk_cert_circuit.h - RS chunk membership certificate circuit
 * (public-index variant), design section 6.1 / 6.6, plan T6.3.
 *
 * The certificate proves: there exists an FWK such that the FWK-blinded leaf
 *
 *   leaf = leaf_hash(FWK || chunk_digest || index)
 *
 * sits at the public `index` on the path to the public `merkle_root`.  Only
 * an FWK holder (the dataset owner) can produce a satisfying witness, so the
 * certificate is unforgeable and owner-hiding (the FWK is never revealed).
 *
 * The leaf and node hashes are the grostl fixed-input vt selected by CR
 * profile, the SAME hashes the plaintext helpers in erasure/rs_membership.h
 * compute, so a circuit built here verifies a root produced by
 * voleith_rs_tree_root.
 *
 * Two index modes over one tree (design section 6.6):
 *
 *   PUBLIC-index (..._build_circuit): the chunk index is public, so the path
 *     directions and the index bytes in the leaf preimage are resolved at
 *     circuit-build time (compile-time constants, zero mul-gate swap).
 *       Instance (declaration order): merkle_root (node_bytes) then
 *         chunk_digest (digest_bytes).  `index` is a build-time parameter, not
 *         an instance wire; it travels as public data alongside the proof and
 *         the verifier rebuilds the same circuit with it.
 *       Witness (declaration order): FWK (fwk_bytes), the sibling path
 *         (depth * node_bytes), then the leaf-hash and per-level inode inv_in
 *         the path circuit adds internally.
 *
 *   SECRET-index (..._build_circuit_secret_dir): the index is hidden, so the
 *     path directions and the leaf-preimage index bytes are witness wires.
 *     The generic secret-dir path circuit pays node_bytes mul gates/level for
 *     the L/R swap mux and enforces booleanity assert_product(dir, dir, dir)
 *     per level.  Mandatory indexed-consistency constraint: each direction
 *     wire is bound (free linear-map bit extraction, indexed_merkle_gf8
 *     pattern) to the matching bit of the committed index, and the index bits
 *     above the tree depth are forced to zero, so the committed index in the
 *     leaf cannot diverge from the routed position.
 *       Instance (declaration order): merkle_root then chunk_digest (same as
 *         public; only the index moves to the witness).
 *       Witness (declaration order): FWK, per-level direction bits (depth),
 *         the committed index (index_bytes), the sibling path, then the inv_in.
 *
 * See docs/ERASURE_CODES_DESIGN.md sections 6.1 and 6.6.
 */

#ifndef VOLEITH_RS_CHUNK_CERT_CIRCUIT_H
#define VOLEITH_RS_CHUNK_CERT_CIRCUIT_H

#include <stddef.h>
#include <stdint.h>

#include "gf8_circuit.h"
#include "rs_membership.h"

/*
 * voleith_rs_chunk_cert_layout_t - byte offsets into the witness / instance
 * buffers for one certificate circuit.  All offsets are relative to the first
 * wire this build declared (0 for a standalone certificate circuit, which is
 * the normal case); a caller composing the certificate after other gates
 * places the per-invocation slice at the right global offset itself.
 */
typedef struct {
    /* Witness layout. */
    size_t fwk_off; /* FWK bytes. */
    size_t fwk_bytes;
    size_t siblings_off; /* sibling path: depth * node_bytes. */
    size_t siblings_bytes;
    size_t leaf_invin_off; /* leaf-hash inv_in (added by the path circuit). */
    size_t leaf_invin_bytes;
    size_t path_invin_off; /* per-level inode inv_in. */
    size_t path_invin_per_level;
    size_t path_invin_bytes; /* depth * path_invin_per_level. */

    /* Secret-index variant only (all zero for the public-index circuit). */
    int secret_dir;    /* 1 for the secret-index circuit, 0 for public. */
    size_t dirs_off;   /* per-level direction witness: depth bytes. */
    size_t dirs_bytes; /* depth (0 for public-index). */
    size_t index_off;  /* committed index witness: index_bytes bytes. */

    /* Instance layout. */
    size_t inst_root_off; /* merkle_root: node_bytes. */
    size_t inst_root_bytes;
    size_t inst_digest_off; /* chunk_digest: digest_bytes. */
    size_t inst_digest_bytes;

    /* Geometry (echoed for convenience). */
    size_t depth;
    size_t node_bytes;
    size_t index_bytes;
    size_t leaf_data_bytes; /* fwk_bytes + digest_bytes + index_bytes. */

    /* Totals for this invocation. */
    size_t witness_bytes;
    size_t instance_bytes;
} voleith_rs_chunk_cert_layout_t;

/*
 * voleith_rs_chunk_cert_build_circuit - append the public-index certificate
 * circuit for the chunk at `index` of an n_chunks-chunk dataset under CR
 * profile `cr` to circuit `c`, writing the witness / instance layout through
 * layout_out.
 *
 * The tree depth is voleith_rs_tree_depth_for_n(n_chunks) and the index width
 * voleith_rs_index_bytes_for_depth(depth); index must be < n_chunks.  Declares
 * the FWK and sibling witness wires, the merkle_root and chunk_digest instance
 * wires, the constant index wires, composes the FWK-blinded leaf hash with the
 * public-dir Merkle path circuit, and binds the computed root to merkle_root.
 *
 * Returns 0 on success, -1 on a NULL argument, an unknown profile, n_chunks
 * out of range, index >= n_chunks, or a circuit-builder failure.
 */
int voleith_rs_chunk_cert_build_circuit(
    voleith_gf8_circuit_t *c, voleith_rs_cr_profile_t cr, size_t n_chunks,
    size_t index, voleith_rs_chunk_cert_layout_t *layout_out);

/*
 * voleith_rs_chunk_cert_build_witness - assemble the witness buffer matching a
 * circuit built by voleith_rs_chunk_cert_build_circuit with the same (cr,
 * n_chunks, index).
 *
 * Writes layout->witness_bytes bytes into witness_out:
 *   FWK | siblings | leaf inv_in | per-level inode inv_in
 * computing the leaf-hash and inode inv_in via the same grostl fixed-input vt
 * the circuit uses (so the witness satisfies the circuit iff the FWK, digest,
 * index and siblings are genuine).  The FWK-carrying scratch is zeroized.
 *
 *   fwk          - voleith_rs_fwk_bytes(cr) bytes.
 *   chunk_digest - voleith_rs_cr_digest_bytes(cr) bytes (the chunk's digest).
 *   siblings     - depth * node_bytes bytes (may be NULL iff depth == 0),
 *                  e.g. from voleith_rs_tree_sibling_path.
 *
 * Returns 0 on success, -1 on a NULL argument, an out-of-range parameter, or a
 * propagated vt-builder failure.
 */
int voleith_rs_chunk_cert_build_witness(
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *siblings,
    const voleith_rs_chunk_cert_layout_t *layout, uint8_t *witness_out);

/*
 * voleith_rs_chunk_cert_build_circuit_secret_dir - append the SECRET-index
 * certificate circuit for an n_chunks-chunk dataset under CR profile `cr` to
 * circuit `c`, writing the layout through layout_out.
 *
 * The circuit structure depends only on (cr, n_chunks): the index is a witness
 * (per-level direction bits plus the committed index bytes), so a single built
 * circuit serves every chunk of the dataset.  Composes the FWK-blinded leaf
 * hash with the secret-dir Merkle path circuit (per-level mux + booleanity),
 * binds each direction wire to the matching committed-index bit and forces the
 * above-depth index bits to zero (indexed-consistency), and binds the computed
 * root to the merkle_root instance.
 *
 * Returns 0 on success, -1 on a NULL argument, an unknown profile, n_chunks
 * out of range, or a circuit-builder failure.
 */
int voleith_rs_chunk_cert_build_circuit_secret_dir(
    voleith_gf8_circuit_t *c, voleith_rs_cr_profile_t cr, size_t n_chunks,
    voleith_rs_chunk_cert_layout_t *layout_out);

/*
 * voleith_rs_chunk_cert_build_witness_secret_dir - assemble the witness for a
 * circuit built by voleith_rs_chunk_cert_build_circuit_secret_dir, for chunk
 * `index` (index < n_chunks).
 *
 * Writes layout->witness_bytes bytes into witness_out:
 *   FWK | direction bits | committed index | siblings | leaf inv_in |
 *   per-level inode inv_in
 * The direction bits and committed index encode `index` (LSB-first directions,
 * little-endian index), matching the indexed-consistency constraint the
 * circuit enforces.  The FWK-carrying scratch is zeroized.
 *
 * Returns 0 on success, -1 on a NULL/out-of-range argument or a vt-builder
 * failure.
 */
int voleith_rs_chunk_cert_build_witness_secret_dir(
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *siblings,
    const voleith_rs_chunk_cert_layout_t *layout, uint8_t *witness_out);

#endif /* VOLEITH_RS_CHUNK_CERT_CIRCUIT_H */
