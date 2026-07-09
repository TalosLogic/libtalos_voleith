/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_retriever.c - retriever-side sufficiency flow (design section 6.8, plan
 * T6.6).
 *
 * Composes the certificate verifier (proof/rs_chunk_cert_proof.h), the tree
 * helpers (erasure/rs_membership.h), and the plaintext RS codec (erasure/rs.h)
 * into a collect / verify / dedup / decode driver.  Plaintext layer.
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_retriever.h"

#include "../proof/rs_chunk_cert_proof.h"
#include "rs.h"
#include "rs_membership.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

/*
 * Walk a leaf node up to the root using a sibling path and the directions of
 * `index` (LSB first, matching the Merkle path circuit and tree helpers).
 */
static int
root_from_leaf(const voleith_node_hash_vt *vt, const uint8_t *leaf,
               const uint8_t *siblings, size_t index, size_t depth,
               uint8_t *root_out)
{
    size_t W = vt->node_bytes;
    uint8_t cur[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next[MERKLE_VT_MAX_NODE_BYTES];

    memcpy(cur, leaf, W);
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = (uint8_t)((index >> k) & 1u);
        const uint8_t *L = dir ? sib : cur;
        const uint8_t *R = dir ? cur : sib;

        if (vt->inode_hash(L, R, next) != 0)
            return -1;
        memcpy(cur, next, W);
    }
    memcpy(root_out, cur, W);
    return 0;
}

int
voleith_rs_recover_index(voleith_rs_cr_profile_t cr, const uint8_t *fwk,
                         const uint8_t *merkle_root, size_t n_chunks,
                         const uint8_t *chunk_digest, const uint8_t *siblings,
                         size_t *index_out)
{
    const voleith_node_hash_vt *vt;
    uint8_t leaf[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t root_c[MERKLE_VT_MAX_NODE_BYTES];
    size_t W, depth, index_bytes;
    int rc = -1;

    if (fwk == NULL || merkle_root == NULL || chunk_digest == NULL ||
        index_out == NULL)
        return -1;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return -1;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY)
        return -1;

    W = vt->node_bytes;
    depth = voleith_rs_tree_depth_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);
    if (depth > 0 && siblings == NULL)
        return -1;

    for (size_t c = 0; c < n_chunks; c++) {
        if (voleith_rs_leaf_hash(cr, fwk, chunk_digest, c, index_bytes, leaf,
                                 W) != VOLEITH_EC_OK)
            goto out;
        if (root_from_leaf(vt, leaf, siblings, c, depth, root_c) != 0)
            goto out;
        if (voleith_const_memcmp(root_c, merkle_root, W) == 0) {
            *index_out = c;
            rc = 0;
            goto out;
        }
    }

out:
    voleith_secure_zero(leaf, sizeof(leaf));
    return rc;
}

int
voleith_rs_retriever_init(voleith_rs_retriever_t *r, voleith_rs_cr_profile_t cr,
                          const voleith_params_t *params,
                          voleith_ec_matrix_kind_t kind, int secret_index,
                          const uint8_t *merkle_root, const uint8_t *R,
                          size_t R_len, const voleith_rs_metadata_t *metadata,
                          const uint8_t *fwk)
{
    const voleith_node_hash_vt *vt;
    size_t n, k, digb;

    if (r == NULL || params == NULL || merkle_root == NULL || R == NULL ||
        metadata == NULL)
        return VOLEITH_EC_ERR_PARAM;

    memset(r, 0, sizeof(*r));

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL || metadata->cr_profile != cr)
        return VOLEITH_EC_ERR_PARAM;
    if (secret_index && fwk == NULL)
        return VOLEITH_EC_ERR_PARAM;

    n = metadata->n;
    k = metadata->k;
    if (n == 0 || k == 0 || k > n || n > VOLEITH_RS_TREE_MAX_CAPACITY)
        return VOLEITH_EC_ERR_PARAM;
    digb = voleith_rs_cr_digest_bytes(cr);
    if (R_len != digb || metadata->chunk_size == 0)
        return VOLEITH_EC_ERR_PARAM;

    r->cr = cr;
    r->params = params;
    r->kind = kind;
    r->secret_index = secret_index ? 1 : 0;
    r->n = n;
    r->k = k;
    r->chunk_bytes = metadata->chunk_size;
    r->digb = digb;
    r->node_bytes = vt->node_bytes;
    r->merkle_root = merkle_root;
    r->R = R;
    r->R_len = R_len;
    r->metadata = metadata;
    r->fwk = secret_index ? fwk : NULL;

    r->seen = calloc(n, 1);
    r->idx_store = calloc(k, sizeof(size_t));
    r->chunk_store = calloc(k, r->chunk_bytes);
    if (r->seen == NULL || r->idx_store == NULL || r->chunk_store == NULL) {
        voleith_rs_retriever_free(r);
        return VOLEITH_EC_ERR_NOMEM;
    }

    r->distinct = 0;
    return VOLEITH_EC_OK;
}

void
voleith_rs_retriever_free(voleith_rs_retriever_t *r)
{
    if (r == NULL)
        return;
    free(r->seen);
    free(r->idx_store);
    if (r->chunk_store != NULL) {
        voleith_secure_zero(r->chunk_store, r->k * r->chunk_bytes);
        free(r->chunk_store);
    }
    r->seen = NULL;
    r->idx_store = NULL;
    r->chunk_store = NULL;
    r->distinct = 0;
}

int
voleith_rs_retriever_offer(voleith_rs_retriever_t *r,
                           const uint8_t *chunk_bytes, size_t chunk_len,
                           const voleith_proof_t *cert, size_t public_index,
                           const uint8_t *siblings,
                           voleith_rs_chunk_disposition_t *disp_out)
{
    uint8_t digest[64];
    size_t index;
    int vrc;

    if (r == NULL || chunk_bytes == NULL || cert == NULL || disp_out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (chunk_len != r->chunk_bytes)
        return VOLEITH_EC_ERR_PARAM;

    if (voleith_rs_chunk_digest(r->cr, chunk_bytes, chunk_len, digest,
                                sizeof(digest)) != VOLEITH_EC_OK)
        return VOLEITH_EC_ERR_PARAM;

    /* Genuineness gate: the certificate must verify against R for this
     * computed digest (so the bytes hash to the committed chunk_digest). */
    if (r->secret_index) {
        vrc = voleith_rs_chunk_cert_verify_secret_dir(
            cert, r->params, r->cr, r->n, digest, r->merkle_root, r->metadata,
            r->R, r->R_len);
    } else {
        if (public_index >= r->n) {
            *disp_out = VOLEITH_RS_CHUNK_REJECTED;
            return VOLEITH_EC_OK;
        }
        vrc = voleith_rs_chunk_cert_verify(cert, r->params, r->cr, r->n,
                                           public_index, digest, r->merkle_root,
                                           r->metadata, r->R, r->R_len);
    }
    if (vrc != 0) {
        *disp_out = VOLEITH_RS_CHUNK_REJECTED;
        return VOLEITH_EC_OK;
    }

    /* Determine the index for dedup / decode. */
    if (r->secret_index) {
        if (voleith_rs_recover_index(r->cr, r->fwk, r->merkle_root, r->n,
                                     digest, siblings, &index) != 0) {
            *disp_out = VOLEITH_RS_CHUNK_REJECTED;
            return VOLEITH_EC_OK;
        }
    } else {
        index = public_index;
    }
    if (index >= r->n) {
        *disp_out = VOLEITH_RS_CHUNK_REJECTED;
        return VOLEITH_EC_OK;
    }

    /* Dedup: duplicates never advance the distinct count. */
    if (r->seen[index]) {
        *disp_out = VOLEITH_RS_CHUNK_DUPLICATE;
        return VOLEITH_EC_OK;
    }
    r->seen[index] = 1;

    /* Keep the first k distinct chunks for the decode. */
    if (r->distinct < r->k) {
        r->idx_store[r->distinct] = index;
        memcpy(r->chunk_store + r->distinct * r->chunk_bytes, chunk_bytes,
               r->chunk_bytes);
    }
    r->distinct++;

    *disp_out = VOLEITH_RS_CHUNK_ACCEPTED;
    return VOLEITH_EC_OK;
}

size_t
voleith_rs_retriever_distinct(const voleith_rs_retriever_t *r)
{
    return r != NULL ? r->distinct : 0;
}

int
voleith_rs_retriever_have_enough(const voleith_rs_retriever_t *r)
{
    return r != NULL && r->distinct >= r->k;
}

size_t
voleith_rs_retriever_need_more(const voleith_rs_retriever_t *r)
{
    if (r == NULL || r->distinct >= r->k)
        return 0;
    return r->k - r->distinct;
}

int
voleith_rs_retriever_decode(const voleith_rs_retriever_t *r,
                            uint8_t *message_out, size_t message_cap)
{
    voleith_rs_t rs;
    int rc;

    if (r == NULL || message_out == NULL)
        return VOLEITH_EC_ERR_PARAM;
    if (r->distinct < r->k)
        return VOLEITH_EC_ERR_INCOMPLETE;
    if (message_cap < r->k * r->chunk_bytes)
        return VOLEITH_EC_ERR_PARAM;

    rc = voleith_rs_init(&rs, r->n, r->k, r->kind);
    if (rc != VOLEITH_EC_OK)
        return rc;

    rc = voleith_rs_decode(&rs, r->idx_store, r->chunk_store, r->k,
                           r->chunk_bytes, message_out);
    voleith_rs_free(&rs);
    return rc;
}
