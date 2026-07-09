/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_chunk_cert_circuit.c - RS chunk membership certificate circuit
 * (public-index variant), plan T6.3.
 *
 * Composes the FWK-blinded leaf hash (leaf_data = FWK || chunk_digest ||
 * index) with the public-dir generic Merkle path circuit, binding the
 * computed root to the public merkle_root instance.  The leaf / node hashes
 * route through the grostl fixed-input vt selected by CR profile, so the gate
 * stream proves exactly the relation the plaintext helpers in
 * erasure/rs_membership.c compute (cross-checked by the eval test).
 *
 * Clean-room implementation.  See docs/ERASURE_CODES_DESIGN.md.
 */

#include "rs_chunk_cert_circuit.h"

#include "merkle_vt_gf8_circuit.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

int
voleith_rs_chunk_cert_build_circuit(voleith_gf8_circuit_t *c,
                                    voleith_rs_cr_profile_t cr, size_t n_chunks,
                                    size_t index,
                                    voleith_rs_chunk_cert_layout_t *layout_out)
{
    const voleith_node_hash_vt *vt;
    voleith_rs_chunk_cert_layout_t layout;
    uint8_t dirs[VOLEITH_RS_TREE_MAX_DEPTH];
    gf8_wire_id *fwk_wires = NULL;
    gf8_wire_id *sibling_wires = NULL;
    gf8_wire_id *root_inst_wires = NULL;
    gf8_wire_id *digest_inst_wires = NULL;
    gf8_wire_id *leaf_data = NULL;
    gf8_wire_id computed_root[MERKLE_VT_MAX_NODE_BYTES];
    size_t W, fwkb, digb, depth, index_bytes, leaf_data_bytes;
    size_t leaf_invin_bytes, inode_invin_bytes;
    size_t first_wit, inst_first_wit, leaf_invin_first_wit;
    int rc = -1;
    size_t i;

    if (c == NULL || layout_out == NULL)
        return -1;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return -1;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY)
        return -1;
    if (index >= n_chunks)
        return -1;

    W = vt->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    fwkb = voleith_rs_fwk_bytes(cr);
    digb = voleith_rs_cr_digest_bytes(cr);
    depth = voleith_rs_tree_depth_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);
    leaf_data_bytes = fwkb + digb + index_bytes;

    leaf_invin_bytes = vt->leaf_invin_bytes(leaf_data_bytes);
    inode_invin_bytes = vt->inode_invin_bytes();

    /* Public path directions: bit k of index, LSB first. */
    voleith_rs_index_dirs(index, depth, dirs);

    first_wit = voleith_gf8_circuit_witness_count(c);
    inst_first_wit = voleith_gf8_circuit_instance_count(c);

    /* ---- 1. FWK witness wires --------------------------------------- */
    fwk_wires = calloc(fwkb, sizeof(*fwk_wires));
    if (fwk_wires == NULL)
        goto out;
    for (i = 0; i < fwkb; i++)
        fwk_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 2. sibling witness wires (depth * node_bytes) -------------- */
    sibling_wires = calloc(depth * W ? depth * W : 1, sizeof(*sibling_wires));
    if (sibling_wires == NULL)
        goto out;
    for (i = 0; i < depth * W; i++)
        sibling_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 3. merkle_root instance wires ------------------------------ */
    root_inst_wires = calloc(W, sizeof(*root_inst_wires));
    if (root_inst_wires == NULL)
        goto out;
    for (i = 0; i < W; i++)
        root_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- 4. chunk_digest instance wires ----------------------------- */
    digest_inst_wires = calloc(digb, sizeof(*digest_inst_wires));
    if (digest_inst_wires == NULL)
        goto out;
    for (i = 0; i < digb; i++)
        digest_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- 5. leaf_data wires: FWK || chunk_digest || index (const, LE) */
    leaf_data = calloc(leaf_data_bytes, sizeof(*leaf_data));
    if (leaf_data == NULL)
        goto out;
    for (i = 0; i < fwkb; i++)
        leaf_data[i] = fwk_wires[i];
    for (i = 0; i < digb; i++)
        leaf_data[fwkb + i] = digest_inst_wires[i];
    for (i = 0; i < index_bytes; i++)
        leaf_data[fwkb + digb + i] =
            voleith_gf8_add_const(c, (uint8_t)((index >> (8u * i)) & 0xffu));

    /* ---- 6. public-dir Merkle path: leaf hash + inode walk ---------- *
     * Adds the leaf-hash inv_in then the per-level inode inv_in witness  *
     * wires internally, leaf-to-root.                                    */
    leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    if (merkle_vt_gf8_path_circuit(c, vt, leaf_data, leaf_data_bytes,
                                   sibling_wires, dirs, depth,
                                   computed_root) != 0)
        goto out;

    /* ---- 7. bind computed root to merkle_root instance -------------- */
    for (i = 0; i < W; i++)
        voleith_gf8_assert_equal(c, computed_root[i], root_inst_wires[i]);

    /* ---- 8. layout (offsets relative to this invocation's first wire) */
    memset(&layout, 0, sizeof(layout));
    layout.fwk_off = 0;
    layout.fwk_bytes = fwkb;
    layout.siblings_off = fwkb;
    layout.siblings_bytes = depth * W;
    layout.leaf_invin_off = leaf_invin_first_wit - first_wit;
    layout.leaf_invin_bytes = leaf_invin_bytes;
    layout.path_invin_off = layout.leaf_invin_off + leaf_invin_bytes;
    layout.path_invin_per_level = inode_invin_bytes;
    layout.path_invin_bytes = depth * inode_invin_bytes;
    layout.inst_root_off = 0;
    layout.inst_root_bytes = W;
    layout.inst_digest_off = W;
    layout.inst_digest_bytes = digb;
    layout.depth = depth;
    layout.node_bytes = W;
    layout.index_bytes = index_bytes;
    layout.leaf_data_bytes = leaf_data_bytes;
    layout.witness_bytes = voleith_gf8_circuit_witness_count(c) - first_wit;
    layout.instance_bytes =
        voleith_gf8_circuit_instance_count(c) - inst_first_wit;

    *layout_out = layout;
    rc = 0;

out:
    free(fwk_wires);
    free(sibling_wires);
    free(root_inst_wires);
    free(digest_inst_wires);
    free(leaf_data);
    return rc;
}

/*
 * Shared witness core for both index modes: writes FWK, the sibling path, the
 * leaf-hash inv_in, and the per-level inode inv_in (the parts whose layout
 * offsets and computation are identical public vs secret - the node values
 * along the path are the same since the per-level direction is bit k of index
 * either way).  The secret-dir wrapper writes the direction-bit and
 * committed-index witness on top.
 */
static int
chunk_cert_pack_core(voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
                     const uint8_t *fwk, const uint8_t *chunk_digest,
                     const uint8_t *siblings,
                     const voleith_rs_chunk_cert_layout_t *layout,
                     uint8_t *witness_out)
{
    const voleith_node_hash_vt *vt;
    uint8_t preimage[VOLEITH_RS_LEAF_PREIMAGE_MAX_BYTES];
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next[MERKLE_VT_MAX_NODE_BYTES];
    size_t W, fwkb, digb, depth, index_bytes, leaf_data_bytes;
    int rc = -1;
    size_t i, k;

    if (layout == NULL || fwk == NULL || chunk_digest == NULL ||
        witness_out == NULL)
        return -1;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return -1;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY ||
        index >= n_chunks)
        return -1;

    W = vt->node_bytes;
    fwkb = voleith_rs_fwk_bytes(cr);
    digb = voleith_rs_cr_digest_bytes(cr);
    depth = voleith_rs_tree_depth_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);
    leaf_data_bytes = fwkb + digb + index_bytes;

    if (depth > 0 && siblings == NULL)
        return -1;
    if (leaf_data_bytes > sizeof(preimage))
        return -1;

    /* 1. FWK. */
    memcpy(witness_out + layout->fwk_off, fwk, fwkb);

    /* 2. siblings. */
    if (depth > 0)
        memcpy(witness_out + layout->siblings_off, siblings, depth * W);

    /* Leaf preimage: FWK || chunk_digest || index (little-endian). */
    memcpy(preimage, fwk, fwkb);
    memcpy(preimage + fwkb, chunk_digest, digb);
    for (i = 0; i < index_bytes; i++)
        preimage[fwkb + digb + i] = (uint8_t)((index >> (8u * i)) & 0xffu);

    /* 3. leaf-hash inv_in. */
    if (vt->leaf_build_witness(preimage, leaf_data_bytes,
                               witness_out + layout->leaf_invin_off) != 0)
        goto out;

    /* 4. per-level inode inv_in: walk the public path from the leaf node,
     *    matching walk_inodes_public_dir (dir = bit k of index, LSB first;
     *    left = dir ? sibling : current). */
    if (vt->leaf_hash(preimage, leaf_data_bytes, current) != 0)
        goto out;
    for (k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = (uint8_t)((index >> k) & 1u);
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        uint8_t *invin = witness_out + layout->path_invin_off +
                         k * layout->path_invin_per_level;

        if (vt->inode_build_witness(L, R, invin) != 0)
            goto out;
        if (vt->inode_hash(L, R, next) != 0)
            goto out;
        memcpy(current, next, W);
    }

    rc = 0;

out:
    voleith_secure_zero(preimage, sizeof(preimage));
    voleith_secure_zero(current, sizeof(current));
    voleith_secure_zero(next, sizeof(next));
    return rc;
}

int
voleith_rs_chunk_cert_build_witness(
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *siblings,
    const voleith_rs_chunk_cert_layout_t *layout, uint8_t *witness_out)
{
    return chunk_cert_pack_core(cr, n_chunks, index, fwk, chunk_digest,
                                siblings, layout, witness_out);
}

/* ========================================================================
 * Secret-index variant (index hidden; indexed-consistency enforced)
 * ======================================================================== */

int
voleith_rs_chunk_cert_build_circuit_secret_dir(
    voleith_gf8_circuit_t *c, voleith_rs_cr_profile_t cr, size_t n_chunks,
    voleith_rs_chunk_cert_layout_t *layout_out)
{
    const voleith_node_hash_vt *vt;
    voleith_rs_chunk_cert_layout_t layout;
    gf8_wire_id *fwk_wires = NULL;
    gf8_wire_id *dir_wires = NULL;
    gf8_wire_id *index_wires = NULL;
    gf8_wire_id *sibling_wires = NULL;
    gf8_wire_id *root_inst_wires = NULL;
    gf8_wire_id *digest_inst_wires = NULL;
    gf8_wire_id *leaf_data = NULL;
    gf8_wire_id computed_root[MERKLE_VT_MAX_NODE_BYTES];
    size_t W, fwkb, digb, depth, index_bytes, index_bits, leaf_data_bytes;
    size_t leaf_invin_bytes, inode_invin_bytes;
    size_t first_wit, inst_first_wit, leaf_invin_first_wit;
    int rc = -1;
    size_t i, k;

    if (c == NULL || layout_out == NULL)
        return -1;

    vt = voleith_rs_chunk_node_vt(cr);
    if (vt == NULL)
        return -1;
    if (n_chunks == 0 || n_chunks > VOLEITH_RS_TREE_MAX_CAPACITY)
        return -1;

    W = vt->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;
    fwkb = voleith_rs_fwk_bytes(cr);
    digb = voleith_rs_cr_digest_bytes(cr);
    depth = voleith_rs_tree_depth_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);
    index_bits = 8u * index_bytes;
    leaf_data_bytes = fwkb + digb + index_bytes;

    leaf_invin_bytes = vt->leaf_invin_bytes(leaf_data_bytes);
    inode_invin_bytes = vt->inode_invin_bytes();

    first_wit = voleith_gf8_circuit_witness_count(c);
    inst_first_wit = voleith_gf8_circuit_instance_count(c);

    /* ---- 1. FWK witness wires --------------------------------------- */
    fwk_wires = calloc(fwkb, sizeof(*fwk_wires));
    if (fwk_wires == NULL)
        goto out;
    for (i = 0; i < fwkb; i++)
        fwk_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 2. per-level direction witness wires (secret index) -------- */
    dir_wires = calloc(depth ? depth : 1, sizeof(*dir_wires));
    if (dir_wires == NULL)
        goto out;
    for (i = 0; i < depth; i++)
        dir_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 3. committed-index witness wires --------------------------- */
    index_wires = calloc(index_bytes, sizeof(*index_wires));
    if (index_wires == NULL)
        goto out;
    for (i = 0; i < index_bytes; i++)
        index_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 4. sibling witness wires (depth * node_bytes) -------------- */
    sibling_wires = calloc(depth * W ? depth * W : 1, sizeof(*sibling_wires));
    if (sibling_wires == NULL)
        goto out;
    for (i = 0; i < depth * W; i++)
        sibling_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 5. merkle_root instance wires ------------------------------ */
    root_inst_wires = calloc(W, sizeof(*root_inst_wires));
    if (root_inst_wires == NULL)
        goto out;
    for (i = 0; i < W; i++)
        root_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- 6. chunk_digest instance wires ----------------------------- */
    digest_inst_wires = calloc(digb, sizeof(*digest_inst_wires));
    if (digest_inst_wires == NULL)
        goto out;
    for (i = 0; i < digb; i++)
        digest_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- 7. leaf_data: FWK || chunk_digest || index (all witness/inst) */
    leaf_data = calloc(leaf_data_bytes, sizeof(*leaf_data));
    if (leaf_data == NULL)
        goto out;
    for (i = 0; i < fwkb; i++)
        leaf_data[i] = fwk_wires[i];
    for (i = 0; i < digb; i++)
        leaf_data[fwkb + i] = digest_inst_wires[i];
    for (i = 0; i < index_bytes; i++)
        leaf_data[fwkb + digb + i] = index_wires[i];

    /* ---- 8. indexed-consistency (indexed_merkle_gf8 bit-extract) ---- *
     * Each committed-index bit k < depth must equal direction wire k;     *
     * bits at/above depth are forced to zero.  So the committed index in   *
     * the leaf is exactly the routed position (cannot diverge).  Free      *
     * linear-map extraction; the equality / zero checks add no mul slot.   */
    for (k = 0; k < index_bits; k++) {
        uint8_t M[8] = {0};
        gf8_wire_id bit_wire;

        M[0] = (uint8_t)(1u << (k % 8u));
        bit_wire = voleith_gf8_add_linear_map(c, index_wires[k / 8u], M);
        if (k < depth)
            voleith_gf8_assert_equal(c, bit_wire, dir_wires[k]);
        else
            voleith_gf8_assert_zero(c, bit_wire);
    }

    /* ---- 9. secret-dir Merkle path: leaf hash + mux walk ------------ *
     * Per level pays node_bytes mul gates and an assert_product(dir, dir,  *
     * dir) booleanity check (enforced inside the generic body).  Adds the  *
     * leaf-hash inv_in then per-level inode inv_in witness, leaf-to-root.  */
    leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    if (merkle_vt_gf8_path_circuit_secret_dir(c, vt, leaf_data, leaf_data_bytes,
                                              sibling_wires, dir_wires, depth,
                                              computed_root) != 0)
        goto out;

    /* ---- 10. bind computed root to merkle_root instance ------------- */
    for (i = 0; i < W; i++)
        voleith_gf8_assert_equal(c, computed_root[i], root_inst_wires[i]);

    /* ---- 11. layout ------------------------------------------------- */
    memset(&layout, 0, sizeof(layout));
    layout.fwk_off = 0;
    layout.fwk_bytes = fwkb;
    layout.secret_dir = 1;
    layout.dirs_off = fwkb;
    layout.dirs_bytes = depth;
    layout.index_off = fwkb + depth;
    layout.siblings_off = fwkb + depth + index_bytes;
    layout.siblings_bytes = depth * W;
    layout.leaf_invin_off = leaf_invin_first_wit - first_wit;
    layout.leaf_invin_bytes = leaf_invin_bytes;
    layout.path_invin_off = layout.leaf_invin_off + leaf_invin_bytes;
    layout.path_invin_per_level = inode_invin_bytes;
    layout.path_invin_bytes = depth * inode_invin_bytes;
    layout.inst_root_off = 0;
    layout.inst_root_bytes = W;
    layout.inst_digest_off = W;
    layout.inst_digest_bytes = digb;
    layout.depth = depth;
    layout.node_bytes = W;
    layout.index_bytes = index_bytes;
    layout.leaf_data_bytes = leaf_data_bytes;
    layout.witness_bytes = voleith_gf8_circuit_witness_count(c) - first_wit;
    layout.instance_bytes =
        voleith_gf8_circuit_instance_count(c) - inst_first_wit;

    *layout_out = layout;
    rc = 0;

out:
    free(fwk_wires);
    free(dir_wires);
    free(index_wires);
    free(sibling_wires);
    free(root_inst_wires);
    free(digest_inst_wires);
    free(leaf_data);
    return rc;
}

int
voleith_rs_chunk_cert_build_witness_secret_dir(
    voleith_rs_cr_profile_t cr, size_t n_chunks, size_t index,
    const uint8_t *fwk, const uint8_t *chunk_digest, const uint8_t *siblings,
    const voleith_rs_chunk_cert_layout_t *layout, uint8_t *witness_out)
{
    size_t depth, index_bytes;
    int rc;
    size_t k;

    if (layout == NULL)
        return -1;

    /* Common witness (FWK, siblings, leaf inv_in, path inv_in).  This also
     * runs the full argument / range validation. */
    rc = chunk_cert_pack_core(cr, n_chunks, index, fwk, chunk_digest, siblings,
                              layout, witness_out);
    if (rc != 0)
        return rc;

    /* Secret-dir extras: per-level direction bits and the committed index. */
    depth = voleith_rs_tree_depth_for_n(n_chunks);
    index_bytes = voleith_rs_index_bytes_for_depth(depth);

    for (k = 0; k < depth; k++)
        witness_out[layout->dirs_off + k] = (uint8_t)((index >> k) & 1u);
    for (k = 0; k < index_bytes; k++)
        witness_out[layout->index_off + k] =
            (uint8_t)((index >> (8u * k)) & 0xffu);

    return 0;
}
