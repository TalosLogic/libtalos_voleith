/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_membership.c - plaintext leaf / tree / digest helpers for the RS chunk
 * membership certificate (design section 6.1 / 6.6).
 *
 * The leaf and internal-node hashes route through the grostl fixed-input
 * node-hash vt (grostl256_fixed / grostl512_fixed by CR profile), the same
 * vt the certificate circuit binds, and the tree walk reuses the shared
 * voleith_merkle_vt_* software helpers.  So the merkle_root / sibling path /
 * leaf node produced here are byte-identical to what the circuit proves
 * (cross-checked in plan T6.3).
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_membership.h"

#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "merkle_vt_gf8_helpers.h"
#include "util.h"

/* ========================================================================
 * Per-profile hash H (same construction as rs_dataset.c)
 * ======================================================================== */

static int
profile_hash(voleith_rs_cr_profile_t cr, const uint8_t *data, size_t len,
             uint8_t *out, size_t out_cap)
{
    voleith_hash_ctx_t ctx;
    size_t dbytes;

    dbytes = voleith_rs_cr_digest_bytes(cr);
    if (dbytes == 0)
        return VOLEITH_EC_ERR_FIELD;
    if (out_cap < dbytes)
        return VOLEITH_EC_ERR_NOMEM;

    if (cr == VOLEITH_RS_CR_128) {
        voleith_shake128_init(&ctx);
        if (voleith_shake128_absorb(&ctx, data, len) != 0) {
            voleith_hash_ctx_clear(&ctx);
            return VOLEITH_EC_ERR_INTERNAL;
        }
        voleith_shake128_squeeze(&ctx, out, dbytes);
    } else {
        voleith_shake256_init(&ctx);
        if (voleith_shake256_absorb(&ctx, data, len) != 0) {
            voleith_hash_ctx_clear(&ctx);
            return VOLEITH_EC_ERR_INTERNAL;
        }
        voleith_shake256_squeeze(&ctx, out, dbytes);
    }
    voleith_hash_ctx_clear(&ctx);
    return VOLEITH_EC_OK;
}

/* ========================================================================
 * Per-profile node-hash vt
 * ======================================================================== */

const voleith_node_hash_vt *
voleith_rs_chunk_node_vt(voleith_rs_cr_profile_t cr)
{
    switch (cr) {
    case VOLEITH_RS_CR_128:
        return &voleith_node_hash_grostl256_fixed;
    case VOLEITH_RS_CR_256:
        return &voleith_node_hash_grostl512_fixed;
    default:
        return NULL;
    }
}

/* ========================================================================
 * Chunk digest and leaf hash
 * ======================================================================== */

int
voleith_rs_chunk_digest(voleith_rs_cr_profile_t cr, const uint8_t *chunk,
                        size_t chunk_len, uint8_t *out, size_t out_cap)
{
    if ((chunk == NULL && chunk_len != 0) || out == NULL)
        return VOLEITH_EC_ERR_PARAM;

    return profile_hash(cr, chunk, chunk_len, out, out_cap);
}

int
voleith_rs_leaf_hash(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                     const uint8_t *chunk_digest, size_t index,
                     size_t index_bytes, uint8_t *out, size_t out_cap)
{
    const voleith_node_hash_vt *vt;
    uint8_t pre[VOLEITH_RS_LEAF_PREIMAGE_MAX_BYTES];
    size_t fwkb, digb, prelen;
    int rc;

    if (fwk == NULL || chunk_digest == NULL || out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (index_bytes < 1 || index_bytes > VOLEITH_RS_MAX_INDEX_BYTES)
        return VOLEITH_EC_ERR_PARAM;
    /* index must fit in index_bytes (8 * index_bytes < 64, so no UB). */
    if (index >> (8u * index_bytes) != 0)
        return VOLEITH_EC_ERR_PARAM;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return VOLEITH_EC_ERR_FIELD;

    fwkb = voleith_rs_fwk_bytes(cr);
    digb = voleith_rs_cr_digest_bytes(cr);
    prelen = fwkb + digb + index_bytes;
    if (out_cap < vt->node_bytes || prelen > sizeof(pre))
        return VOLEITH_EC_ERR_NOMEM;

    /* FWK || chunk_digest || index (little-endian); the vt zero-pads to its
     * block. */
    memcpy(pre, fwk, fwkb);
    memcpy(pre + fwkb, chunk_digest, digb);
    for (size_t b = 0; b < index_bytes; b++)
        pre[fwkb + digb + b] = (uint8_t)((index >> (8u * b)) & 0xffu);

    rc = vt->leaf_hash(pre, prelen, out);

    /* The preimage carries the secret FWK; do not leave it on the stack. */
    voleith_secure_zero(pre, sizeof(pre));

    return (rc == 0) ? VOLEITH_EC_OK : VOLEITH_EC_ERR_NOMEM;
}

/* ========================================================================
 * Tree root, sibling path, and path directions
 * ======================================================================== */

/*
 * Computes the leaf node array into leaf_nodes (caller-supplied, capacity *
 * node_bytes, zero-initialized so vacant slots are the sentinel).  Fills the
 * first n_chunks leaves with the FWK-blinded leaf hashes, encoding each index
 * in index_bytes.  Returns 0 on success, a negative VOLEITH_EC_ERR_* on
 * failure.
 */
static int
build_leaf_nodes(voleith_rs_cr_profile_t cr, const voleith_node_hash_vt *vt,
                 const uint8_t *fwk, const uint8_t *chunk_digests,
                 size_t n_chunks, size_t index_bytes, uint8_t *leaf_nodes)
{
    size_t W = vt->node_bytes;
    size_t digb = voleith_rs_cr_digest_bytes(cr);
    int rc;

    for (size_t i = 0; i < n_chunks; i++) {
        rc = voleith_rs_leaf_hash(cr, fwk, chunk_digests + i * digb, i,
                                  index_bytes, leaf_nodes + i * W, W);
        if (rc != VOLEITH_EC_OK)
            return rc;
    }
    return VOLEITH_EC_OK;
}

int
voleith_rs_tree_root(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                     const uint8_t *chunk_digests, size_t n_chunks,
                     uint8_t *root_out, size_t root_cap)
{
    const voleith_node_hash_vt *vt;
    uint8_t *leaf_nodes;
    size_t W, depth, capacity, index_bytes;
    int rc;

    if (fwk == NULL || chunk_digests == NULL || root_out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY)
        return VOLEITH_EC_ERR_PARAM;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return VOLEITH_EC_ERR_FIELD;
    W = vt->node_bytes;
    if (root_cap < W)
        return VOLEITH_EC_ERR_NOMEM;

    depth = voleith_rs_tree_depth_for_n(n_chunks);
    capacity = voleith_rs_tree_capacity_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);

    leaf_nodes = calloc(capacity, W);
    if (leaf_nodes == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    rc = build_leaf_nodes(cr, vt, fwk, chunk_digests, n_chunks, index_bytes,
                          leaf_nodes);
    if (rc != VOLEITH_EC_OK)
        goto out;

    if (voleith_merkle_vt_build(vt, leaf_nodes, capacity, root_out) != 0) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = VOLEITH_EC_OK;
out:
    voleith_secure_zero(leaf_nodes, capacity * W);
    free(leaf_nodes);
    return rc;
}

int
voleith_rs_tree_sibling_path(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                             const uint8_t *chunk_digests, size_t n_chunks,
                             size_t index, uint8_t *siblings_out,
                             size_t siblings_cap)
{
    const voleith_node_hash_vt *vt;
    uint8_t *leaf_nodes;
    size_t W, depth, capacity, index_bytes;
    int rc;

    if (fwk == NULL || chunk_digests == NULL || siblings_out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY)
        return VOLEITH_EC_ERR_PARAM;
    if (index >= n_chunks)
        return VOLEITH_EC_ERR_PARAM;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return VOLEITH_EC_ERR_FIELD;
    W = vt->node_bytes;

    depth = voleith_rs_tree_depth_for_n(n_chunks);
    capacity = voleith_rs_tree_capacity_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);
    if (siblings_cap < depth * W)
        return VOLEITH_EC_ERR_NOMEM;

    leaf_nodes = calloc(capacity, W);
    if (leaf_nodes == NULL)
        return VOLEITH_EC_ERR_NOMEM;

    rc = build_leaf_nodes(cr, vt, fwk, chunk_digests, n_chunks, index_bytes,
                          leaf_nodes);
    if (rc != VOLEITH_EC_OK)
        goto out;

    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, capacity, index,
                                       siblings_out) != 0) {
        rc = VOLEITH_EC_ERR_NOMEM;
        goto out;
    }

    rc = VOLEITH_EC_OK;
out:
    voleith_secure_zero(leaf_nodes, capacity * W);
    free(leaf_nodes);
    return rc;
}

void
voleith_rs_index_dirs(size_t index, size_t depth, uint8_t *dirs_out)
{
    if (dirs_out == NULL)
        return;
    for (size_t k = 0; k < depth; k++)
        dirs_out[k] = (uint8_t)((index >> k) & 1u);
}
