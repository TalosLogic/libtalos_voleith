/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_gf8_circuit.c - composable ring-signature circuit builder.
 *
 * voleith_rs_build_circuit: the superset builder.  Mirrors
 * voleith_rs_membership_build_circuit (the V1 baseline) and inserts each
 * enabled module's branch in the canonical §1.3 order.  This file
 * currently implements the V2 nullifier branch; later tickets add the
 * V2 spent-set, V3 attribute, and V4 commitment branches.
 *
 * See rs_gf8_circuit.h for the contract.
 */

#include "rs_gf8_circuit.h"

#include "aes_cmac_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "merkle_vt_gf8_circuit.h"
#include "range_gf8_circuit.h"
#include "rs_leaf_gf8_circuit.h"

#include <stdlib.h>
#include <string.h>

int
voleith_rs_build_circuit(voleith_gf8_circuit_t *c,
                         const voleith_rs_config_t *cfg,
                         voleith_rs_layout_t *layout_out)
{
    const voleith_rs_membership_config_t *mcfg;
    const voleith_node_hash_vt *owf_vt;
    const voleith_node_hash_vt *tree_vt;
    size_t W;
    size_t leaf_invin_bytes;
    size_t inode_invin_bytes;
    int nullifier_enabled;
    int commit_enabled;
    size_t commit_total;
    size_t commit_id_first = 0;
    size_t commit_inst_first = 0;
    const voleith_rs_attr_schema_t *schema;
    size_t attr_total;
    size_t bounds_total;
    size_t attr_first_wit = 0;
    size_t bounds_inst_first = 0;
    size_t base_wit;
    size_t base_inst;
    size_t dirs_first_wit;
    size_t siblings_first_wit;
    size_t leaf_invin_first_wit;
    size_t path_invin_first_wit;
    size_t root_inst_first;
    size_t scope_inst_first = 0;
    size_t t_inst_first = 0;
    voleith_rs_layout_t layout;
    gf8_wire_id *sk_wires = NULL;
    gf8_wire_id *attr_wires = NULL;
    gf8_wire_id *bounds_wires = NULL;
    gf8_wire_id *idrand_wires = NULL;
    gf8_wire_id *c_inst_wires = NULL;
    gf8_wire_id *dir_wires = NULL;
    gf8_wire_id *sibling_wires = NULL;
    gf8_wire_id *root_inst_wires = NULL;
    gf8_wire_id *scope_inst_wires = NULL;
    gf8_wire_id *t_inst_wires = NULL;
    gf8_wire_id *rev_low_value_wires = NULL;
    gf8_wire_id *rev_low_next_wires = NULL;
    gf8_wire_id *rev_next_index_wires = NULL;
    gf8_wire_id *rev_dir_wires = NULL;
    gf8_wire_id *rev_sibling_wires = NULL;
    gf8_wire_id *rev_root_inst_wires = NULL;
    gf8_wire_id *spent_low_value_wires = NULL;
    gf8_wire_id *spent_low_next_wires = NULL;
    gf8_wire_id *spent_next_index_wires = NULL;
    gf8_wire_id *spent_dir_wires = NULL;
    gf8_wire_id *spent_sibling_wires = NULL;
    gf8_wire_id *spent_root_inst_wires = NULL;
    gf8_wire_id leaf_node_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id computed_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id rev_computed_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id spent_computed_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id c_computed_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id t_computed_wires[VOLEITH_RS_NULLIFIER_MAX_BYTES];
    size_t t_bytes;
    int rc = -1;
    size_t i;

    /* ---- V6 epoch locals ------------------------------------------- */
    int epoch_enabled;
    const voleith_node_hash_vt *epoch_vt = NULL;
    size_t epoch_sk_bytes = 0;
    size_t salt_bytes = 0;
    size_t epoch_leaf_invin_bytes = 0;
    size_t epoch_inode_invin_bytes = 0;
    size_t epoch_sk_first = 0;
    size_t salt_first = 0;
    size_t epoch_sib_first = 0;
    size_t epoch_dirs_inst_first = 0;
    size_t epoch_leaf_invin_first = 0;
    size_t epoch_path_invin_first = 0;
    gf8_wire_id *sk_t_wires = NULL;
    gf8_wire_id *salt_wires = NULL;
    gf8_wire_id *epoch_sibling_wires = NULL;
    gf8_wire_id *epoch_dir_inst_wires = NULL;
    gf8_wire_id *owf_tail_wires = NULL;
    gf8_wire_id ht_wires[MERKLE_VT_MAX_NODE_BYTES];
    gf8_wire_id epoch_root_wires[MERKLE_VT_MAX_NODE_BYTES];
    const gf8_wire_id *prf_key_wires;
    size_t prf_key_bytes;
    int owf_used;
    size_t owf_preimage;

    if (c == NULL || cfg == NULL || layout_out == NULL)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;

    mcfg = &cfg->membership;
    t_bytes = voleith_rs_nullifier_bytes(cfg);
    nullifier_enabled = cfg->scope_bytes > 0;
    commit_enabled = cfg->enable_commitment != 0;
    commit_total =
        commit_enabled ? cfg->commit_id_bytes + cfg->commit_rand_bytes : 0;

    /* V6: the leaf secret is sk_t via the epoch subtree; membership.sk_bytes
     * is 0 (EP.CFG), so the nullifier PRF keys off sk_t (Q5). */
    epoch_enabled = cfg->depth_e > 0;
    epoch_sk_bytes = epoch_enabled ? cfg->epoch_sk_bytes : 0;
    salt_bytes = epoch_enabled ? cfg->leaf_salt_bytes : 0;
    prf_key_bytes = epoch_enabled ? epoch_sk_bytes : mcfg->sk_bytes;

    /* V2 PRF key is the AES-CMAC key, so it must be a valid AES key width.
     * (config_validate floors membership.sk_bytes >= 1 for non-V6 and pins
     * epoch_sk_bytes in {16,32} for V6, but the AES-width requirement only
     * applies when the nullifier module is on.) */
    if (nullifier_enabled && prf_key_bytes != 16 && prf_key_bytes != 32)
        return -1;

    tree_vt = mcfg->tree_hash;
    owf_vt = mcfg->owf_hash ? mcfg->owf_hash : mcfg->tree_hash;
    W = tree_vt->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    /* V3 attribute totals: attr_total = sum of field widths (the leaf
     * preimage extension); bounds_total = public bound bytes (EQ -> one
     * width-byte target, RANGE -> width-byte low + high). */
    schema = cfg->attr_schema;
    attr_total = 0;
    bounds_total = 0;
    if (schema != NULL) {
        for (i = 0; i < schema->n_fields; i++) {
            attr_total += schema->fields[i].width_bytes;
            if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_EQ)
                bounds_total += schema->fields[i].width_bytes;
            else if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_RANGE)
                bounds_total += 2 * schema->fields[i].width_bytes;
        }
    }

    if (epoch_enabled) {
        epoch_vt = cfg->epoch_hash ? cfg->epoch_hash : tree_vt;
        epoch_leaf_invin_bytes = epoch_vt->leaf_invin_bytes(epoch_sk_bytes);
        epoch_inode_invin_bytes = epoch_vt->inode_invin_bytes();
    }

    /*
     * OWF leaf preimage.  Non-V6: sk || attrs.  V6 + V3: epoch_root ||
     * attrs || salt (the epoch root heads the preimage in sk's slot).  V6
     * without V3: the leaf IS epoch_root and no OWF runs, so no OWF inv_in.
     */
    if (epoch_enabled) {
        if (schema != NULL) {
            owf_used = 1;
            owf_preimage = W + attr_total + salt_bytes;
        } else {
            owf_used = 0;
            owf_preimage = 0;
        }
    } else {
        owf_used = 1;
        owf_preimage = mcfg->sk_bytes + attr_total;
    }
    leaf_invin_bytes = owf_used ? owf_vt->leaf_invin_bytes(owf_preimage) : 0;
    inode_invin_bytes = tree_vt->inode_invin_bytes();

    base_wit = voleith_gf8_circuit_witness_count(c);
    base_inst = voleith_gf8_circuit_instance_count(c);

    memset(&layout, 0, sizeof(layout));

    /* ---- 1. sk witness wires ---------------------------------------- */
    sk_wires = calloc(mcfg->sk_bytes, sizeof(*sk_wires));
    if (sk_wires == NULL)
        goto out;
    for (i = 0; i < mcfg->sk_bytes; i++)
        sk_wires[i] = voleith_gf8_add_witness(c);

    /* ---- [V6] 1b. sk_t + leaf salt witness (sk's slot) ------------- */
    if (epoch_enabled) {
        epoch_sk_first = voleith_gf8_circuit_witness_count(c);
        sk_t_wires = calloc(epoch_sk_bytes, sizeof(*sk_t_wires));
        if (sk_t_wires == NULL)
            goto out;
        for (i = 0; i < epoch_sk_bytes; i++)
            sk_t_wires[i] = voleith_gf8_add_witness(c);

        if (salt_bytes > 0) {
            salt_first = voleith_gf8_circuit_witness_count(c);
            salt_wires = calloc(salt_bytes, sizeof(*salt_wires));
            if (salt_wires == NULL)
                goto out;
            for (i = 0; i < salt_bytes; i++)
                salt_wires[i] = voleith_gf8_add_witness(c);
        }
    }
    prf_key_wires = epoch_enabled ? sk_t_wires : sk_wires;

    /* ---- [V3] 2. attribute witness wires (leaf preimage tail) ------- */
    if (attr_total > 0) {
        attr_first_wit = voleith_gf8_circuit_witness_count(c);
        attr_wires = calloc(attr_total, sizeof(*attr_wires));
        if (attr_wires == NULL)
            goto out;
        for (i = 0; i < attr_total; i++)
            attr_wires[i] = voleith_gf8_add_witness(c);
    }

    /* ---- [V6] epoch sibling witness wires -------------------------- */
    if (epoch_enabled) {
        epoch_sib_first = voleith_gf8_circuit_witness_count(c);
        epoch_sibling_wires =
            calloc(cfg->depth_e * W, sizeof(*epoch_sibling_wires));
        if (epoch_sibling_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_e * W; i++)
            epoch_sibling_wires[i] = voleith_gf8_add_witness(c);
    }

    /* ---- 3. membership dir witness wires ---------------------------- */
    dirs_first_wit = voleith_gf8_circuit_witness_count(c);
    dir_wires = calloc(mcfg->depth_m, sizeof(*dir_wires));
    if (dir_wires == NULL)
        goto out;
    for (i = 0; i < mcfg->depth_m; i++)
        dir_wires[i] = voleith_gf8_add_witness(c);

    /* ---- 3. membership sibling witness wires ------------------------ */
    siblings_first_wit = voleith_gf8_circuit_witness_count(c);
    sibling_wires = calloc(mcfg->depth_m * W, sizeof(*sibling_wires));
    if (sibling_wires == NULL)
        goto out;
    for (i = 0; i < mcfg->depth_m * W; i++)
        sibling_wires[i] = voleith_gf8_add_witness(c);

    /* ---- [V6] epoch direction instance wires (first instance) ------ */
    if (epoch_enabled) {
        epoch_dirs_inst_first = voleith_gf8_circuit_instance_count(c);
        epoch_dir_inst_wires =
            calloc(cfg->depth_e, sizeof(*epoch_dir_inst_wires));
        if (epoch_dir_inst_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_e; i++)
            epoch_dir_inst_wires[i] = voleith_gf8_add_instance(c);
    }

    /* ---- 4. membership_root instance wires -------------------------- */
    root_inst_first = voleith_gf8_circuit_instance_count(c);
    root_inst_wires = calloc(W, sizeof(*root_inst_wires));
    if (root_inst_wires == NULL)
        goto out;
    for (i = 0; i < W; i++)
        root_inst_wires[i] = voleith_gf8_add_instance(c);

    /* ---- [V4] commit id + rand witness, C instance (§1.3 steps 6-8) - */
    if (commit_enabled) {
        commit_id_first = voleith_gf8_circuit_witness_count(c);
        idrand_wires = calloc(commit_total, sizeof(*idrand_wires));
        if (idrand_wires == NULL)
            goto out;
        for (i = 0; i < commit_total; i++)
            idrand_wires[i] = voleith_gf8_add_witness(c);

        commit_inst_first = voleith_gf8_circuit_instance_count(c);
        c_inst_wires = calloc(W, sizeof(*c_inst_wires));
        if (c_inst_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            c_inst_wires[i] = voleith_gf8_add_instance(c);
    }

    /* ---- [V2] scope + T instance wires (declared before revocation) - */
    if (nullifier_enabled) {
        scope_inst_first = voleith_gf8_circuit_instance_count(c);
        scope_inst_wires = calloc(cfg->scope_bytes, sizeof(*scope_inst_wires));
        if (scope_inst_wires == NULL)
            goto out;
        for (i = 0; i < cfg->scope_bytes; i++)
            scope_inst_wires[i] = voleith_gf8_add_instance(c);

        t_inst_first = voleith_gf8_circuit_instance_count(c);
        t_inst_wires = calloc(t_bytes, sizeof(*t_inst_wires));
        if (t_inst_wires == NULL)
            goto out;
        for (i = 0; i < t_bytes; i++)
            t_inst_wires[i] = voleith_gf8_add_instance(c);
    }

    /* ---- [V3] predicate bound instance wires (after T, §1.3 step 11) - */
    if (bounds_total > 0) {
        bounds_inst_first = voleith_gf8_circuit_instance_count(c);
        bounds_wires = calloc(bounds_total, sizeof(*bounds_wires));
        if (bounds_wires == NULL)
            goto out;
        for (i = 0; i < bounds_total; i++)
            bounds_wires[i] = voleith_gf8_add_instance(c);
    }

    /* ---- [V6] A0. epoch subtree: h_t = leaf(sk_t); epoch_root walk --- */
    if (epoch_enabled) {
        epoch_leaf_invin_first = voleith_gf8_circuit_witness_count(c);
        epoch_vt->leaf_circuit(c, sk_t_wires, epoch_sk_bytes, ht_wires);

        epoch_path_invin_first = voleith_gf8_circuit_witness_count(c);
        if (merkle_vt_gf8_path_from_leaf_node_public_dir(
                c, epoch_vt, ht_wires, epoch_sibling_wires,
                epoch_dir_inst_wires, cfg->depth_e, epoch_root_wires) != 0)
            goto out;
    }

    /* ---- A. leaf circuit --------------------------------------------
     * Non-V6: leaf_node = OWF(sk || attributes).
     * V6 + V3: leaf_node = OWF(epoch_root || attributes || salt).
     * V6 without V3: leaf_node := epoch_root (no OWF).
     */
    leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    if (epoch_enabled && schema == NULL) {
        for (i = 0; i < W; i++)
            leaf_node_wires[i] = epoch_root_wires[i];
    } else if (epoch_enabled) {
        size_t tail = attr_total + salt_bytes;
        owf_tail_wires = calloc(tail > 0 ? tail : 1, sizeof(*owf_tail_wires));
        if (owf_tail_wires == NULL)
            goto out;
        for (i = 0; i < attr_total; i++)
            owf_tail_wires[i] = attr_wires[i];
        for (i = 0; i < salt_bytes; i++)
            owf_tail_wires[attr_total + i] = salt_wires[i];
        if (rs_leaf_gf8_build_circuit(c, owf_vt, epoch_root_wires, W,
                                      owf_tail_wires, tail,
                                      leaf_node_wires) != 0)
            goto out;
    } else {
        if (rs_leaf_gf8_build_circuit(c, owf_vt, sk_wires, mcfg->sk_bytes,
                                      attr_wires, attr_total,
                                      leaf_node_wires) != 0)
            goto out;
    }

    /* ---- B. merkle path from leaf_node to computed root ------------- */
    path_invin_first_wit = voleith_gf8_circuit_witness_count(c);
    if (merkle_vt_gf8_path_from_leaf_node_secret_dir(
            c, tree_vt, leaf_node_wires, sibling_wires, dir_wires,
            mcfg->depth_m, computed_root_wires) != 0)
        goto out;

    /* ---- C. bind computed root to membership_root instance ---------- */
    for (i = 0; i < W; i++)
        voleith_gf8_assert_equal(c, computed_root_wires[i], root_inst_wires[i]);

    /* ---- 8. membership layout (offsets = wire-index - base) --------- */
    layout.membership.sk_off = 0;
    layout.membership.sk_bytes = mcfg->sk_bytes;
    layout.membership.dirs_off = dirs_first_wit - base_wit;
    layout.membership.dirs_bytes = mcfg->depth_m;
    layout.membership.siblings_off = siblings_first_wit - base_wit;
    layout.membership.siblings_bytes = mcfg->depth_m * W;
    layout.membership.owf_invin_off = leaf_invin_first_wit - base_wit;
    layout.membership.owf_invin_bytes = leaf_invin_bytes;
    layout.membership.path_invin_off = path_invin_first_wit - base_wit;
    layout.membership.path_invin_per_level = inode_invin_bytes;
    layout.membership.path_invin_bytes = mcfg->depth_m * inode_invin_bytes;
    layout.membership.inst_root_off = root_inst_first - base_inst;
    layout.membership.inst_root_bytes = W;
    layout.membership.depth_m = mcfg->depth_m;
    layout.membership.node_bytes = W;

    /* ---- [V6] epoch layout ----------------------------------------- */
    if (epoch_enabled) {
        layout.epoch_sk_off = epoch_sk_first - base_wit;
        layout.epoch_sk_bytes = epoch_sk_bytes;
        if (salt_bytes > 0) {
            layout.salt_off = salt_first - base_wit;
            layout.salt_bytes = salt_bytes;
        }
        layout.epoch_siblings_off = epoch_sib_first - base_wit;
        layout.epoch_siblings_bytes = cfg->depth_e * W;
        layout.epoch_leaf_invin_off = epoch_leaf_invin_first - base_wit;
        layout.epoch_leaf_invin_bytes = epoch_leaf_invin_bytes;
        layout.epoch_path_invin_off = epoch_path_invin_first - base_wit;
        layout.epoch_path_invin_per_level = epoch_inode_invin_bytes;
        layout.epoch_path_invin_bytes = cfg->depth_e * epoch_inode_invin_bytes;
        layout.inst_epoch_dirs_off = epoch_dirs_inst_first - base_inst;
        layout.inst_epoch_dirs_bytes = cfg->depth_e;
        layout.depth_e = cfg->depth_e;
    }

    /* ---- D. [V4] commitment: C_computed = H(id || rand) ------------- */
    if (commit_enabled) {
        size_t commit_invin_first = voleith_gf8_circuit_witness_count(c);

        tree_vt->leaf_circuit(c, idrand_wires, commit_total, c_computed_wires);
        for (i = 0; i < W; i++)
            voleith_gf8_assert_equal(c, c_computed_wires[i], c_inst_wires[i]);

        layout.commit_id_off = commit_id_first - base_wit;
        layout.commit_id_bytes = cfg->commit_id_bytes;
        layout.commit_rand_off =
            (commit_id_first - base_wit) + cfg->commit_id_bytes;
        layout.commit_rand_bytes = cfg->commit_rand_bytes;
        layout.commit_invin_off = commit_invin_first - base_wit;
        layout.commit_invin_bytes = tree_vt->leaf_invin_bytes(commit_total);
        layout.inst_commit_off = commit_inst_first - base_inst;
        layout.inst_commit_bytes = W;
    }

    /* ---- E. [V2] nullifier ------------------------------------------ */
    if (nullifier_enabled) {
        size_t nullifier_invin_first = voleith_gf8_circuit_witness_count(c);

        if (t_bytes == VOLEITH_RS_NULLIFIER_BYTES) {
            /* <= 128-bit-CR tree: raw 16-byte tag T = AES-CMAC(sk, scope). */
            aes_cmac_gf8_circuit(c, prf_key_wires, prf_key_bytes,
                                 scope_inst_wires, cfg->scope_bytes,
                                 t_computed_wires);
            layout.nullifier_invin_bytes =
                aes_cmac_gf8_witness_bytes(prf_key_bytes, cfg->scope_bytes) -
                prf_key_bytes;
        } else {
            /*
             * >= 256-bit-CR tree: T = SP 800-108 KDF-CTR-CMAC(sk, ...) at
             * L = t_bytes*8 bits.  FixedInputData = Label || 0x00 || scope
             * || [L]_2; Label and [L]_2 are constant wires, scope reuses the
             * public instance wires.
             */
            const char *label = VOLEITH_RS_NULLIFIER_KDF_LABEL;
            gf8_wire_id *fi = NULL;
            size_t fi_bytes;
            size_t l_bits;
            size_t p = 0;
            size_t j;
            int kdf_rc;

            fi_bytes =
                VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + cfg->scope_bytes + 4;
            l_bits = t_bytes * 8u;
            fi = calloc(fi_bytes, sizeof(*fi));
            if (fi == NULL)
                goto out;
            for (j = 0; j < VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES; j++)
                fi[p++] = voleith_gf8_add_const(c, (uint8_t)label[j]);
            fi[p++] = voleith_gf8_add_const(c, 0x00);
            for (j = 0; j < cfg->scope_bytes; j++)
                fi[p++] = scope_inst_wires[j];
            fi[p++] =
                voleith_gf8_add_const(c, (uint8_t)((l_bits >> 24) & 0xFF));
            fi[p++] =
                voleith_gf8_add_const(c, (uint8_t)((l_bits >> 16) & 0xFF));
            fi[p++] = voleith_gf8_add_const(c, (uint8_t)((l_bits >> 8) & 0xFF));
            fi[p++] = voleith_gf8_add_const(c, (uint8_t)(l_bits & 0xFF));

            kdf_rc =
                kdf_ctr_cmac_gf8_circuit(c, prf_key_wires, prf_key_bytes, fi,
                                         fi_bytes, t_computed_wires, t_bytes);
            free(fi);
            if (kdf_rc != 0)
                goto out;
            layout.nullifier_invin_bytes =
                kdf_ctr_cmac_gf8_witness_bytes(prf_key_bytes, t_bytes,
                                               fi_bytes) -
                prf_key_bytes;
        }

        for (i = 0; i < t_bytes; i++)
            voleith_gf8_assert_equal(c, t_computed_wires[i], t_inst_wires[i]);

        layout.nullifier_invin_off = nullifier_invin_first - base_wit;
        layout.inst_scope_off = scope_inst_first - base_inst;
        layout.inst_scope_bytes = cfg->scope_bytes;
        layout.inst_t_off = t_inst_first - base_inst;
        layout.inst_t_bytes = t_bytes;
    }

    /* ---- [V3] attribute layout + F. predicate gates ---------------- */
    if (schema != NULL) {
        size_t attr_cursor = 0;  /* byte offset within attr_wires */
        size_t bound_cursor = 0; /* byte offset within bounds_wires */

        layout.attr_off = attr_first_wit - base_wit;
        layout.attr_bytes = attr_total;
        if (bounds_total > 0) {
            layout.inst_bounds_off = bounds_inst_first - base_inst;
            layout.inst_bounds_bytes = bounds_total;
        }

        for (i = 0; i < schema->n_fields; i++) {
            size_t w = schema->fields[i].width_bytes;
            const gf8_wire_id *field = attr_wires + attr_cursor;

            switch (schema->fields[i].pred) {
            case VOLEITH_RS_ATTR_PRED_EQ:
                for (size_t j = 0; j < w; j++)
                    voleith_gf8_assert_equal(c, field[j],
                                             bounds_wires[bound_cursor + j]);
                bound_cursor += w;
                break;
            case VOLEITH_RS_ATTR_PRED_RANGE:
                assert_in_range_gf8(c, field, bounds_wires + bound_cursor,
                                    bounds_wires + bound_cursor + w, w);
                bound_cursor += 2 * w;
                break;
            case VOLEITH_RS_ATTR_PRED_NONE:
            default:
                break;
            }
            attr_cursor += w;
        }

        /* Q5: optional escape-hatch callback over the attribute wires,
         * after the built-in schema pass.  Receives wire IDs only.  Its
         * gates are bound by the proof's circuit fingerprint
         * (voleith_gf8_circuit_fingerprint, checked at verify time by
         * voleith_proof_header_check_identity_gf8), NOT by fs_seed: the
         * config fingerprint absorbed into fs_seed deliberately excludes
         * the custom_predicate function pointer. */
        if (cfg->custom_predicate != NULL)
            cfg->custom_predicate(c, attr_wires, attr_total,
                                  cfg->custom_predicate_ctx);
    }

    /* ---- G. revocation branch (cfg->membership.depth_r > 0) --------- */
    if (mcfg->depth_r > 0) {
        const size_t IDX = VOLEITH_RSV1_REV_INDEX_BYTES;
        size_t leaf_data_bytes = 2 * W + IDX;
        size_t rev_leaf_invin_bytes =
            tree_vt->leaf_invin_bytes(leaf_data_bytes);
        size_t rev_low_value_first_wit;
        size_t rev_low_next_first_wit;
        size_t rev_next_index_first_wit;
        size_t rev_dirs_first_wit;
        size_t rev_siblings_first_wit;
        size_t rev_root_inst_first;
        size_t rev_leaf_invin_first_wit;
        size_t rev_path_invin_first_wit;

        rev_low_value_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_low_value_wires = calloc(W, sizeof(*rev_low_value_wires));
        if (rev_low_value_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_low_value_wires[i] = voleith_gf8_add_witness(c);

        rev_low_next_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_low_next_wires = calloc(W, sizeof(*rev_low_next_wires));
        if (rev_low_next_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_low_next_wires[i] = voleith_gf8_add_witness(c);

        rev_next_index_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_next_index_wires = calloc(IDX, sizeof(*rev_next_index_wires));
        if (rev_next_index_wires == NULL)
            goto out;
        for (i = 0; i < IDX; i++)
            rev_next_index_wires[i] = voleith_gf8_add_witness(c);

        rev_dirs_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_dir_wires = calloc(mcfg->depth_r, sizeof(*rev_dir_wires));
        if (rev_dir_wires == NULL)
            goto out;
        for (i = 0; i < mcfg->depth_r; i++)
            rev_dir_wires[i] = voleith_gf8_add_witness(c);

        rev_siblings_first_wit = voleith_gf8_circuit_witness_count(c);
        rev_sibling_wires =
            calloc(mcfg->depth_r * W, sizeof(*rev_sibling_wires));
        if (rev_sibling_wires == NULL)
            goto out;
        for (i = 0; i < mcfg->depth_r * W; i++)
            rev_sibling_wires[i] = voleith_gf8_add_witness(c);

        rev_root_inst_first = voleith_gf8_circuit_instance_count(c);
        rev_root_inst_wires = calloc(W, sizeof(*rev_root_inst_wires));
        if (rev_root_inst_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            rev_root_inst_wires[i] = voleith_gf8_add_instance(c);

        rev_leaf_invin_first_wit = voleith_gf8_circuit_witness_count(c);
        if (merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
                c, tree_vt, leaf_node_wires, W, rev_low_value_wires,
                rev_low_next_wires, rev_next_index_wires, IDX,
                rev_sibling_wires, rev_dir_wires, mcfg->depth_r,
                rev_computed_root_wires) != 0)
            goto out;
        rev_path_invin_first_wit =
            rev_leaf_invin_first_wit + rev_leaf_invin_bytes;

        for (i = 0; i < W; i++)
            voleith_gf8_assert_equal(c, rev_computed_root_wires[i],
                                     rev_root_inst_wires[i]);

        layout.membership.rev_low_value_off =
            rev_low_value_first_wit - base_wit;
        layout.membership.rev_low_value_bytes = W;
        layout.membership.rev_low_next_off = rev_low_next_first_wit - base_wit;
        layout.membership.rev_low_next_bytes = W;
        layout.membership.rev_next_index_off =
            rev_next_index_first_wit - base_wit;
        layout.membership.rev_next_index_bytes = IDX;
        layout.membership.rev_dirs_off = rev_dirs_first_wit - base_wit;
        layout.membership.rev_dirs_bytes = mcfg->depth_r;
        layout.membership.rev_siblings_off = rev_siblings_first_wit - base_wit;
        layout.membership.rev_siblings_bytes = mcfg->depth_r * W;
        layout.membership.rev_leaf_invin_off =
            rev_leaf_invin_first_wit - base_wit;
        layout.membership.rev_leaf_invin_bytes = rev_leaf_invin_bytes;
        layout.membership.rev_path_invin_off =
            rev_path_invin_first_wit - base_wit;
        layout.membership.rev_path_invin_per_level = inode_invin_bytes;
        layout.membership.rev_path_invin_bytes =
            mcfg->depth_r * inode_invin_bytes;
        layout.membership.inst_rev_root_off = rev_root_inst_first - base_inst;
        layout.membership.inst_rev_root_bytes = W;
        layout.membership.depth_r = mcfg->depth_r;
        layout.membership.rev_index_bytes = IDX;
    }

    /* ---- H. [V2] spent-set non-membership on T (cfg->depth_s > 0) -- */
    if (cfg->depth_s > 0) {
        const size_t TV = t_bytes; /* nullifier value width (16 or 32) */
        const size_t IDX = VOLEITH_RSV1_REV_INDEX_BYTES; /* 8 */
        size_t spent_leaf_data_bytes = 2 * TV + IDX;
        size_t spent_leaf_invin_bytes =
            tree_vt->leaf_invin_bytes(spent_leaf_data_bytes);
        size_t spent_low_value_first;
        size_t spent_low_next_first;
        size_t spent_next_index_first;
        size_t spent_dirs_first;
        size_t spent_siblings_first;
        size_t spent_root_inst_first;
        size_t spent_leaf_invin_first;
        size_t spent_path_invin_first;

        spent_low_value_first = voleith_gf8_circuit_witness_count(c);
        spent_low_value_wires = calloc(TV, sizeof(*spent_low_value_wires));
        if (spent_low_value_wires == NULL)
            goto out;
        for (i = 0; i < TV; i++)
            spent_low_value_wires[i] = voleith_gf8_add_witness(c);

        spent_low_next_first = voleith_gf8_circuit_witness_count(c);
        spent_low_next_wires = calloc(TV, sizeof(*spent_low_next_wires));
        if (spent_low_next_wires == NULL)
            goto out;
        for (i = 0; i < TV; i++)
            spent_low_next_wires[i] = voleith_gf8_add_witness(c);

        spent_next_index_first = voleith_gf8_circuit_witness_count(c);
        spent_next_index_wires = calloc(IDX, sizeof(*spent_next_index_wires));
        if (spent_next_index_wires == NULL)
            goto out;
        for (i = 0; i < IDX; i++)
            spent_next_index_wires[i] = voleith_gf8_add_witness(c);

        spent_dirs_first = voleith_gf8_circuit_witness_count(c);
        spent_dir_wires = calloc(cfg->depth_s, sizeof(*spent_dir_wires));
        if (spent_dir_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_s; i++)
            spent_dir_wires[i] = voleith_gf8_add_witness(c);

        spent_siblings_first = voleith_gf8_circuit_witness_count(c);
        spent_sibling_wires =
            calloc(cfg->depth_s * W, sizeof(*spent_sibling_wires));
        if (spent_sibling_wires == NULL)
            goto out;
        for (i = 0; i < cfg->depth_s * W; i++)
            spent_sibling_wires[i] = voleith_gf8_add_witness(c);

        spent_root_inst_first = voleith_gf8_circuit_instance_count(c);
        spent_root_inst_wires = calloc(W, sizeof(*spent_root_inst_wires));
        if (spent_root_inst_wires == NULL)
            goto out;
        for (i = 0; i < W; i++)
            spent_root_inst_wires[i] = voleith_gf8_add_instance(c);

        /* Target is the published nullifier T (bound to CMAC(sk, scope)
         * by the nullifier branch's assert_equal). */
        spent_leaf_invin_first = voleith_gf8_circuit_witness_count(c);
        if (merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
                c, tree_vt, t_inst_wires, TV, spent_low_value_wires,
                spent_low_next_wires, spent_next_index_wires, IDX,
                spent_sibling_wires, spent_dir_wires, cfg->depth_s,
                spent_computed_root_wires) != 0)
            goto out;
        spent_path_invin_first =
            spent_leaf_invin_first + spent_leaf_invin_bytes;

        for (i = 0; i < W; i++)
            voleith_gf8_assert_equal(c, spent_computed_root_wires[i],
                                     spent_root_inst_wires[i]);

        layout.spent_low_value_off = spent_low_value_first - base_wit;
        layout.spent_low_value_bytes = TV;
        layout.spent_low_next_off = spent_low_next_first - base_wit;
        layout.spent_low_next_bytes = TV;
        layout.spent_next_index_off = spent_next_index_first - base_wit;
        layout.spent_next_index_bytes = IDX;
        layout.spent_dirs_off = spent_dirs_first - base_wit;
        layout.spent_dirs_bytes = cfg->depth_s;
        layout.spent_siblings_off = spent_siblings_first - base_wit;
        layout.spent_siblings_bytes = cfg->depth_s * W;
        layout.spent_leaf_invin_off = spent_leaf_invin_first - base_wit;
        layout.spent_leaf_invin_bytes = spent_leaf_invin_bytes;
        layout.spent_path_invin_off = spent_path_invin_first - base_wit;
        layout.spent_path_invin_per_level = inode_invin_bytes;
        layout.spent_path_invin_bytes = cfg->depth_s * inode_invin_bytes;
        layout.inst_spent_root_off = spent_root_inst_first - base_inst;
        layout.inst_spent_root_bytes = W;
        layout.depth_s = cfg->depth_s;
    }

    /* ---- finalize totals ------------------------------------------- */
    layout.witness_bytes = voleith_gf8_circuit_witness_count(c) - base_wit;
    layout.instance_bytes = voleith_gf8_circuit_instance_count(c) - base_inst;
    layout.membership.witness_bytes = layout.witness_bytes;
    layout.membership.instance_bytes = layout.instance_bytes;

    *layout_out = layout;
    rc = 0;

out:
    free(sk_wires);
    free(sk_t_wires);
    free(salt_wires);
    free(epoch_sibling_wires);
    free(epoch_dir_inst_wires);
    free(owf_tail_wires);
    free(attr_wires);
    free(bounds_wires);
    free(idrand_wires);
    free(c_inst_wires);
    free(dir_wires);
    free(sibling_wires);
    free(root_inst_wires);
    free(scope_inst_wires);
    free(t_inst_wires);
    free(rev_low_value_wires);
    free(rev_low_next_wires);
    free(rev_next_index_wires);
    free(rev_dir_wires);
    free(rev_sibling_wires);
    free(rev_root_inst_wires);
    free(spent_low_value_wires);
    free(spent_low_next_wires);
    free(spent_next_index_wires);
    free(spent_dir_wires);
    free(spent_sibling_wires);
    free(spent_root_inst_wires);
    return rc;
}
