/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_membership.h - plaintext leaf / tree / digest helpers for the RS chunk
 * membership certificate (design section 6.1 / 6.6).
 *
 * These compute, OUT of circuit, exactly the values the in-circuit chunk
 * membership certificate proves against: the per-chunk digest, the
 * FWK-blinded leaf node, and the Merkle root / sibling path of a dataset's
 * chunk tree.  The leaf and internal-node hashes are the SAME ones the
 * certificate circuit uses (the grostl fixed-input node-hash vt selected by
 * CR profile), so the software outputs here cross-check the circuit's gate
 * stream (plan T6.3).
 *
 * Leaf layout (design section 6.6), one fixed Grostl compression block:
 *
 *   128-bit CR: FWK(16) || chunk_digest(32) || index(1) || pad(15)  = 64 B
 *   256-bit CR: FWK(32) || chunk_digest(64) || index(1) || pad(31)  = 128 B
 *
 * leaf_node = leaf_hash(FWK || chunk_digest || index); the vt zero-pads the
 * preimage to its single-compression block (the pad above), so this code
 * passes the FWK / digest / index bytes and lets the vt supply the padding.
 *
 * The tree is a balanced binary tree whose depth is a deterministic function
 * of the chunk count: depth = ceil(log2(n)), capacity = 2^depth = next power
 * of two >= n.  A 100-chunk dataset is a depth-7 (128-leaf) tree, a 256-chunk
 * dataset depth-8 (256-leaf), and so on.  Depth follows n, so it costs one
 * fewer inode-hash level per proof for every dataset that fits a shallower
 * tree.  Because n is bound to the dataset root R (rs_dataset.h), depth is
 * recomputable by a verifier and not prover-chosen: a different depth means a
 * different merkle_root, hence a different R.
 *
 * The committed leaf index is encoded in voleith_rs_index_bytes_for_depth()
 * bytes: 1 byte for depth <= 8 (n <= 256, GF(2^8) RS), 2 bytes for depth
 * 9..16 (the future GF(2^16) RS, n up to 65535).  This is the single
 * wire-format lever the GF(2^16) extension flips; everything else here is
 * already depth-agnostic.
 *
 * A dataset with n < capacity fills its first n leaves; vacant leaf slots are
 * the all-zero sentinel node (an all-zero node cannot collide with a real
 * leaf hash), matching the ring builder's convention.
 *
 * This is a plaintext data layer; it is not constant-time.  It does, however,
 * touch the FWK (secret witness material): the leaf-preimage scratch buffer
 * is zeroized after each hash.
 *
 * Naming note: the ring-signature stack in proof/ uses the voleith_rs_*
 * namespace for a Merkle membership proof over public keys.  The Reed-Solomon
 * chunk helpers here use the voleith_rs_chunk_* / voleith_rs_tree_* suffixes
 * to stay clear of the ring-sig voleith_rs_membership_* surface.
 *
 * See docs/ERASURE_CODES_DESIGN.md sections 6.1 and 6.6.
 */

#ifndef VOLEITH_ERASURE_RS_MEMBERSHIP_H
#define VOLEITH_ERASURE_RS_MEMBERSHIP_H

#include <stddef.h>
#include <stdint.h>

#include "erasure.h"
#include "node_hash_vt.h"
#include "rs_dataset.h"

/* ========================================================================
 * Tree and leaf geometry
 *
 * Depth and capacity are per-dataset (derived from n via the helpers below),
 * not compile-time constants.  The MAX_* values bound buffers and index
 * widths across both the current GF(2^8) RS (n <= 256, depth <= 8) and the
 * future GF(2^16) RS (n <= 65535, depth <= 16).
 * ======================================================================== */

/* Deepest tree the geometry supports: GF(2^16) RS, n up to 65535. */
#define VOLEITH_RS_TREE_MAX_DEPTH 16
#define VOLEITH_RS_TREE_MAX_CAPACITY                                           \
    (1u << VOLEITH_RS_TREE_MAX_DEPTH) /* 65536 */

/* Widest committed-index encoding: 2 bytes (depth 9..16).  GF(2^8) datasets
 * use 1 (see voleith_rs_index_bytes_for_depth). */
#define VOLEITH_RS_MAX_INDEX_BYTES 2

/* Upper bound on the FWK || chunk_digest || index preimage across profiles:
 * 32 (FWK) + 64 (chunk_digest) + 2 (index) = 98 bytes (256-bit profile,
 * 2-byte index).  Bounds the leaf-preimage scratch buffer. */
#define VOLEITH_RS_LEAF_PREIMAGE_MAX_BYTES 98u

/*
 * Canonical tree depth for an n-chunk dataset: ceil(log2(n)), i.e. the number
 * of times 1 must double to reach n.  depth 0 for n <= 1 (a single-leaf tree
 * whose root is the leaf).  capacity = 2^depth.  Deterministic in n, which is
 * bound to R, so a verifier recomputes the same depth.
 */
static inline size_t
voleith_rs_tree_depth_for_n(size_t n)
{
    size_t depth = 0;
    size_t cap = 1;

    while (cap < n) {
        cap <<= 1;
        depth++;
    }
    return depth;
}

/* capacity = 2^depth = next power of two >= max(n, 1). */
static inline size_t
voleith_rs_tree_capacity_for_n(size_t n)
{
    return (size_t)1u << voleith_rs_tree_depth_for_n(n);
}

/*
 * Index encoding width in the leaf preimage for a tree of the given depth:
 * 1 byte while depth <= 8 (8 index bits, n <= 256, GF(2^8) RS), 2 bytes for
 * depth 9..16 (the future GF(2^16) RS).  The index is stored little-endian
 * (LSB first, matching the path-direction bit order).
 */
static inline size_t
voleith_rs_index_bytes_for_depth(size_t depth)
{
    return (depth <= 8) ? 1u : 2u;
}

/* ========================================================================
 * Per-profile widths and node-hash vt
 * ======================================================================== */

/* FWK width in bytes for a profile: 16 (128-bit CR) or 32 (256-bit CR),
 * i.e. lambda/8.  Returns 0 for an unknown profile.  The chunk_digest and
 * node widths are voleith_rs_cr_digest_bytes(profile) (32 or 64). */
static inline size_t
voleith_rs_fwk_bytes(voleith_rs_cr_profile_t cr)
{
    switch (cr) {
    case VOLEITH_RS_CR_128:
        return 16;
    case VOLEITH_RS_CR_256:
        return 32;
    default:
        return 0;
    }
}

/*
 * Returns the node-hash vt the chunk tree uses for a profile: grostl256_fixed
 * (128-bit CR, 32-byte nodes) or grostl512_fixed (256-bit CR, 64-byte nodes),
 * or NULL for an unknown profile.  The same vt the certificate circuit binds,
 * so callers (circuit builder, tests) take the leaf / node geometry from here.
 */
const voleith_node_hash_vt *
voleith_rs_chunk_node_vt(voleith_rs_cr_profile_t cr);

/* ========================================================================
 * Chunk digest and leaf hash
 * ======================================================================== */

/*
 * chunk_digest = H(chunk_bytes), the per-profile hash (SHAKE-128 -> 32 bytes,
 * SHAKE-256 -> 64 bytes).  out is voleith_rs_cr_digest_bytes(cr) bytes; a zero
 * chunk_len is permitted (digest of the empty string).  Returns 0 on success,
 * a negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_rs_chunk_digest(voleith_rs_cr_profile_t cr, const uint8_t *chunk,
                            size_t chunk_len, uint8_t *out, size_t out_cap);

/*
 * leaf_node = leaf_hash(FWK || chunk_digest || index): the FWK-blinded Merkle
 * leaf for a chunk.  fwk is voleith_rs_fwk_bytes(cr) bytes, chunk_digest is
 * voleith_rs_cr_digest_bytes(cr) bytes, and out is the vt's node_bytes (32 or
 * 64).  index is encoded little-endian in index_bytes bytes (1 or 2, the
 * dataset-wide value from voleith_rs_index_bytes_for_depth()); index must fit
 * in that width.  The FWK-carrying preimage scratch is zeroized before return.
 * Returns 0 on success, a negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_rs_leaf_hash(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                         const uint8_t *chunk_digest, size_t index,
                         size_t index_bytes, uint8_t *out, size_t out_cap);

/* ========================================================================
 * Tree root, sibling path, and path directions
 * ======================================================================== */

/*
 * Builds the dataset's chunk tree (depth = voleith_rs_tree_depth_for_n(
 * n_chunks)) from the FWK and the n_chunks chunk digests (leaf i =
 * leaf_hash(FWK, chunk_digests[i], i); vacant slots are the zero sentinel)
 * and writes merkle_root through root_out (the vt's node_bytes).
 * chunk_digests is n_chunks contiguous voleith_rs_cr_digest_bytes(cr)-byte
 * digests.  Requires 0 < n_chunks <= VOLEITH_RS_TREE_MAX_CAPACITY.  Returns 0
 * on success, a negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_rs_tree_root(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                         const uint8_t *chunk_digests, size_t n_chunks,
                         uint8_t *root_out, size_t root_cap);

/*
 * Emits the sibling path for the chunk at index (which must be < n_chunks)
 * in the same tree voleith_rs_tree_root builds.  siblings_out is depth *
 * node_bytes bytes (depth = voleith_rs_tree_depth_for_n(n_chunks));
 * siblings_out[k] is the sibling at level k counted from the leaf upward
 * (LSB-first, matching the Merkle path circuit).  Returns 0 on success, a
 * negative VOLEITH_EC_ERR_* on failure.
 */
int voleith_rs_tree_sibling_path(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                                 const uint8_t *chunk_digests, size_t n_chunks,
                                 size_t index, uint8_t *siblings_out,
                                 size_t siblings_cap);

/*
 * Fills dirs_out (depth bytes) with the public path directions for a chunk
 * index: dirs_out[k] = bit k of index (LSB first, 0 or 1), for k in [0, depth).
 * These are the compile-time path directions the public-dir certificate
 * circuit consumes; they correspond byte-for-byte to the sibling ordering of
 * voleith_rs_tree_sibling_path.  depth is voleith_rs_tree_depth_for_n(n_chunks).
 */
void voleith_rs_index_dirs(size_t index, size_t depth, uint8_t *dirs_out);

#endif /* VOLEITH_ERASURE_RS_MEMBERSHIP_H */
