/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ring_sig_v1_gf8_circuit.c - secret-dir Merkle membership circuit
 * builder.
 *
 * Implements voleith_rs_membership_build_circuit per the contract in
 * ring_sig_v1_gf8_circuit.h.  See docs/RSV1_DESIGN.md §4.1 (V1
 * baseline) and docs/RING_SIGNATURE_DESIGN.md (variant matrix).
 */

#include "ring_sig_v1_gf8_circuit.h"

#include "indexed_merkle_vt_gf8_circuit.h"
#include "merkle_vt_gf8_circuit.h"

#include <stdlib.h>
#include <string.h>

int
voleith_rs_membership_build_circuit(voleith_gf8_circuit_t *c,
                                    const voleith_rs_membership_config_t *cfg,
                                    voleith_rs_membership_layout_t *layout_out)
{
    const voleith_node_hash_vt *owf_vt;
    const voleith_node_hash_vt *tree_vt;
    size_t W;
    size_t leaf_invin_bytes;
    size_t inode_invin_bytes;
    size_t sk_first_wit;
    size_t inst_first_wit;
    size_t dirs_first_wit;
    size_t siblings_first_wit;
    size_t leaf_invin_first_wit;
    size_t path_invin_first_wit;
    voleith_rs_membership_layout_t layout;
    gf8_wire_id *sk_wires = NULL;
    gf8_wire_id *sibling_wires = NULL;
    gf8_wire_id *root_inst_wires = NULL;
    gf8_wire_id *dir_wires = NULL;
    gf8_wire_id *rev_low_value_wires = NULL;
    gf8_wire_id *rev_low_next_wires = NULL;
    gf8_wire_id *rev_next_index_wires = NULL;
    gf8_wire_id *rev_dir_wires = NULL;
    gf8_wire_id *rev_sibling_wires = NULL;
    gf8_wire_id *rev_root_inst_wires = NULL;
    gf8_wire_id leaf_node_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id computed_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id rev_computed_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    int rc = -1;
    size_t i;

    if (c == NULL || cfg == NULL || layout_out == NULL)
        return -1;
    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;

    tree_vt = cfg->tree_hash;
    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    W = tree_vt->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    leaf_invin_bytes = owf_vt->leaf_invin_bytes(cfg->sk_bytes);
    inode_invin_bytes = tree_vt->inode_invin_bytes();

    /*
     * Snapshot the pre-call witness / instance counts so the layout's
     * offsets are relative to this invocation's first declared wire,
     * not to whatever the caller may have already put in the circuit.
     */
    sk_first_wit = voleith_gf8_circuit_witness_count(c);
    inst_first_wit = voleith_gf8_circuit_instance_count(c);

    /* ---- 1. sk witness wires ---------------------------------------- */
    sk_wires = calloc(cfg->sk_bytes, sizeof(*sk_wires));
    if (sk_wires == NULL)
        goto out;
    for (i = 0; i < cfg->sk_bytes; i++)
        sk_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 2. dir witness wires (secret leaf index) ------------------- */
    dirs_first_wit = voleith_gf8_circuit_witness_count(c);
    dir_wires = calloc(cfg->depth_m, sizeof(*dir_wires));
    if (dir_wires == NULL)
        goto out;
    for (i = 0; i < cfg->depth_m; i++)
        dir_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 3. sibling witness wires (hidden for ring anonymity) ------- */
    siblings_first_wit = voleith_gf8_circuit_witness_count(c);
    sibling_wires = calloc(cfg->depth_m * W, sizeof(*sibling_wires));
    if (sibling_wires == NULL)
        goto out;
    for (i = 0; i < cfg->depth_m * W; i++)
        sibling_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 4. membership_root instance wires (the only public input) -- */
    root_inst_wires = calloc(W, sizeof(*root_inst_wires));
    if (root_inst_wires == NULL)
        goto out;
    for (i = 0; i < W; i++)
        root_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- 5. owf leaf circuit: sk -> leaf_node ----------------------- */
    leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    owf_vt->leaf_circuit(c, cfg->sk_bytes ? sk_wires : NULL, cfg->sk_bytes,
                         leaf_node_wires);

    /* ---- 6. merkle path from leaf_node to computed root ------------- */
    path_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    if (merkle_vt_gf8_path_from_leaf_node_secret_dir(
            c, tree_vt, leaf_node_wires, sibling_wires, dir_wires, cfg->depth_m,
            computed_root_wires) != 0)
        goto out;

    /* ---- 7. bind computed root to membership_root instance ---------- */
    for (i = 0; i < W; i++)
        voleith_gf8_assert_equal(c, computed_root_wires[i], root_inst_wires[i]);

    /* ---- 8. fill membership layout (byte offsets are
     *         wire-index - first_wit) ----------------------------- */
    memset(&layout, 0, sizeof(layout));

    layout.sk_off = 0;
    layout.sk_bytes = cfg->sk_bytes;

    layout.dirs_off = dirs_first_wit - sk_first_wit;
    layout.dirs_bytes = cfg->depth_m;

    layout.siblings_off = siblings_first_wit - sk_first_wit;
    layout.siblings_bytes = cfg->depth_m * W;

    layout.owf_invin_off = leaf_invin_first_wit - sk_first_wit;
    layout.owf_invin_bytes = leaf_invin_bytes;

    layout.path_invin_off = path_invin_first_wit - sk_first_wit;
    layout.path_invin_per_level = inode_invin_bytes;
    layout.path_invin_bytes = cfg->depth_m * inode_invin_bytes;

    layout.inst_root_off = 0;
    layout.inst_root_bytes = W;

    layout.depth_m = cfg->depth_m;
    layout.node_bytes = W;

    /* ---- 9. revocation branch (cfg->depth_r > 0) ------------------- */
    if (cfg->depth_r > 0) {
        const size_t IDX = VOLEITH_RSV1_REV_INDEX_BYTES;
        size_t leaf_data_bytes = 2 * W + IDX;
        size_t rev_leaf_invin_bytes;
        size_t rev_low_value_first_wit;
        size_t rev_low_next_first_wit;
        size_t rev_next_index_first_wit;
        size_t rev_dirs_first_wit;
        size_t rev_siblings_first_wit;
        size_t rev_leaf_invin_first_wit;
        size_t rev_path_invin_first_wit;

        rev_leaf_invin_bytes = tree_vt->leaf_invin_bytes(leaf_data_bytes);

        /* 9a. low_value witness wires (adjacent record value) */
        rev_low_value_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_low_value_wires = calloc(W, sizeof(*rev_low_value_wires));
        if (rev_low_value_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_low_value_wires[i] = voleith_gf8_add_witness(c);

        /* 9b. low_next witness wires */
        rev_low_next_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_low_next_wires = calloc(W, sizeof(*rev_low_next_wires));
        if (rev_low_next_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_low_next_wires[i] = voleith_gf8_add_witness(c);

        /* 9c. next_index witness wires */
        rev_next_index_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_next_index_wires = calloc(IDX, sizeof(*rev_next_index_wires));
        if (rev_next_index_wires == NULL)
            goto out;
        for (i = 0; i < IDX; i++)
            rev_next_index_wires[i] = voleith_gf8_add_witness(c);

        /* 9d. rev dir witness wires (secret adj_leaf_index) */
        rev_dirs_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_dir_wires = calloc(cfg->depth_r, sizeof(*rev_dir_wires));
        if (rev_dir_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_r; i++)
            rev_dir_wires[i] = voleith_gf8_add_witness(c);

        /* 9e. rev sibling witness wires */
        rev_siblings_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_sibling_wires =
            calloc(cfg->depth_r * W, sizeof(*rev_sibling_wires));
        if (rev_sibling_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_r * W; i++)
            rev_sibling_wires[i] = voleith_gf8_add_witness(c);

        /* 9f. V (revocation root) instance wires */
        rev_root_inst_wires = calloc(W, sizeof(*rev_root_inst_wires));
        if (rev_root_inst_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_root_inst_wires[i] = voleith_gf8_add_instance(c);

        /* 9g. indexed Merkle non-membership: target = signer's leaf
         * node (computed in step 5 by owf_vt->leaf_circuit), value
         * width = W (= node_bytes), index width = IDX.  The internal
         * leaf hash declares rev_leaf_invin_bytes inv_in witness; the
         * inode walk declares depth_r * inode_invin_bytes inv_in
         * witness on top of that. */
        rev_leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
        if (merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
                c, tree_vt, leaf_node_wires, W, rev_low_value_wires,
                rev_low_next_wires, rev_next_index_wires, IDX,
                rev_sibling_wires, rev_dir_wires, cfg->depth_r,
                rev_computed_root_wires) != 0)
            goto out;
        rev_path_invin_first_wit =
            rev_leaf_invin_first_wit + rev_leaf_invin_bytes;

        /* 9h. bind computed revocation root to V instance */
        for (i = 0; i < W; i++)
            voleith_gf8_assert_equal(c, rev_computed_root_wires[i],
                                     rev_root_inst_wires[i]);

        /* 9i. fill revocation layout */
        layout.rev_low_value_off = rev_low_value_first_wit - sk_first_wit;
        layout.rev_low_value_bytes = W;
        layout.rev_low_next_off = rev_low_next_first_wit - sk_first_wit;
        layout.rev_low_next_bytes = W;
        layout.rev_next_index_off = rev_next_index_first_wit - sk_first_wit;
        layout.rev_next_index_bytes = IDX;
        layout.rev_dirs_off = rev_dirs_first_wit - sk_first_wit;
        layout.rev_dirs_bytes = cfg->depth_r;
        layout.rev_siblings_off = rev_siblings_first_wit - sk_first_wit;
        layout.rev_siblings_bytes = cfg->depth_r * W;
        layout.rev_leaf_invin_off = rev_leaf_invin_first_wit - sk_first_wit;
        layout.rev_leaf_invin_bytes = rev_leaf_invin_bytes;
        layout.rev_path_invin_off = rev_path_invin_first_wit - sk_first_wit;
        layout.rev_path_invin_per_level = inode_invin_bytes;
        layout.rev_path_invin_bytes = cfg->depth_r * inode_invin_bytes;

        layout.inst_rev_root_off = layout.inst_root_off + W;
        layout.inst_rev_root_bytes = W;

        layout.depth_r = cfg->depth_r;
        layout.rev_index_bytes = IDX;
    }

    /* ---- 10. finalize totals --------------------------------------- */
    layout.witness_bytes = voleith_gf8_circuit_witness_count(c) - sk_first_wit;
    layout.instance_bytes =
        voleith_gf8_circuit_instance_count(c) - inst_first_wit;

    *layout_out = layout;
    rc = 0;

out:
    free(sk_wires);
    free(sibling_wires);
    free(root_inst_wires);
    free(dir_wires);
    free(rev_low_value_wires);
    free(rev_low_next_wires);
    free(rev_next_index_wires);
    free(rev_dir_wires);
    free(rev_sibling_wires);
    free(rev_root_inst_wires);
    return rc;
}
