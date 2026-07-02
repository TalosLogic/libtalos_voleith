/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_membership_gf8.c - ring-signature membership core (data layer)
 * implementation.
 *
 * The voleith_rs_membership_* validator, canonical-encoding absorber,
 * and witness packer shared by V1/V2/V4/V5/V7.  No fs_seed or
 * serialization machinery lives here; those V1 wrappers stay in
 * proof/ring_sig_v1_gf8.c.
 *
 * See rs_membership_gf8.h for the API contract and docs/RSV1_DESIGN.md
 * §3 for the protocol rationale.
 */

#include "rs_membership_gf8.h"

#include "../circuits/merkle_vt_gf8_helpers.h"
#include "../core/hash.h"
#include "../core/util.h"

#include <stdint.h>
#include <string.h>

int
voleith_rs_membership_validate_structural(
    const voleith_rs_membership_config_t *cfg)
{
    if (cfg == NULL)
        return -1;
    if (cfg->tree_hash == NULL)
        return -1;

    if (cfg->depth_m == 0 || cfg->depth_m > VOLEITH_RS_MEMBERSHIP_MAX_DEPTH)
        return -1;
    if (cfg->depth_r > VOLEITH_RS_MEMBERSHIP_MAX_DEPTH)
        return -1;

    if (cfg->sk_bytes == 0)
        return -1;

    if (cfg->owf_hash != NULL) {
        if (cfg->owf_hash->node_bytes != cfg->tree_hash->node_bytes)
            return -1;
        if (cfg->owf_hash->cr_bits < cfg->tree_hash->cr_bits)
            return -1;
    }

    return 0;
}

int
voleith_rs_membership_validate(const voleith_rs_membership_config_t *cfg)
{
    const voleith_node_hash_vt *owf_vt;

    if (voleith_rs_membership_validate_structural(cfg) != 0)
        return -1;

    /*
     * V1 leaf is OWF(sk), so a fixed-leaf vt requires sk to be exactly
     * its fixed input width.  The composable validator
     * (voleith_rs_config_validate) checks the full OWF preimage
     * sk + attributes against the wider single-compression capacity
     * (leaf_block_bytes) instead, which is why that path uses
     * voleith_rs_membership_validate_structural and does not chain this
     * exact-width check.
     */
    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    if (owf_vt->fixed_leaf_bytes != 0 &&
        cfg->sk_bytes != owf_vt->fixed_leaf_bytes)
        return -1;

    return 0;
}

void
voleith_rs_membership_absorb_canonical(
    voleith_hash_ctx_t *ctx, const voleith_rs_membership_config_t *cfg)
{
    const voleith_node_hash_vt *owf_vt;
    const char *owf_name;
    const char *tree_name;
    size_t owf_name_len;
    size_t tree_name_len;

    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    owf_name = owf_vt->name;
    tree_name = cfg->tree_hash->name;

    owf_name_len = strlen(owf_name);
    voleith_shake256_absorb_u32_le(ctx, (uint32_t)owf_name_len);
    voleith_shake256_absorb(ctx, (const uint8_t *)owf_name, owf_name_len);

    tree_name_len = strlen(tree_name);
    voleith_shake256_absorb_u32_le(ctx, (uint32_t)tree_name_len);
    voleith_shake256_absorb(ctx, (const uint8_t *)tree_name, tree_name_len);

    voleith_shake256_absorb_u64_le(ctx, (uint64_t)cfg->sk_bytes);
    voleith_shake256_absorb_u64_le(ctx, (uint64_t)cfg->depth_m);
    voleith_shake256_absorb_u64_le(ctx, (uint64_t)cfg->depth_r);
}

int
voleith_rs_membership_pack_witness(
    const voleith_rs_membership_config_t *cfg,
    const voleith_rs_membership_layout_t *layout, const uint8_t *sk,
    const voleith_rs_membership_path_t *membership,
    const voleith_rs_membership_path_t *revocation, uint8_t *witness_out)
{
    const voleith_node_hash_vt *owf_vt;
    const voleith_node_hash_vt *tree_vt;
    size_t W;
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next[MERKLE_VT_MAX_NODE_BYTES];

    if (cfg == NULL || layout == NULL || sk == NULL || membership == NULL ||
        membership->siblings == NULL || witness_out == NULL)
        return -1;
    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;

    /*
     * Reject leaf indices outside the ring's capacity.  The ring holds
     * 2^depth_m members; an index >= that cannot map to a valid
     * leaf-direction pattern.  Guard against depth_m >= the size_t bit
     * width before forming the mask (validate already bounds depth_m
     * <= VOLEITH_RS_MEMBERSHIP_MAX_DEPTH = 64; the runtime guard
     * belt-and-braces any caller that wires layout up by hand).
     */
    if (layout->depth_m >= sizeof(size_t) * 8) {
        /* full size_t range -> any leaf_index is in range */
    } else if (membership->leaf_index >= ((size_t)1u << layout->depth_m)) {
        return -1;
    }

    if (cfg->depth_r > 0) {
        if (revocation == NULL || revocation->rev_siblings == NULL ||
            revocation->rev_low_value == NULL ||
            revocation->rev_low_next == NULL ||
            revocation->rev_next_index == NULL)
            return -1;
        if (layout->depth_r >= sizeof(size_t) * 8) {
            /* full size_t range -> any adj_leaf_index is in range */
        } else if (revocation->rev_adj_leaf_index >=
                   ((size_t)1u << layout->depth_r)) {
            return -1;
        }
    }

    tree_vt = cfg->tree_hash;
    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    W = tree_vt->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    /* 1. sk */
    memcpy(witness_out + layout->sk_off, sk, layout->sk_bytes);

    /* 2. dirs: bit k of leaf_index, LSB first */
    for (size_t k = 0; k < layout->depth_m; k++)
        witness_out[layout->dirs_off + k] =
            (uint8_t)((membership->leaf_index >> k) & 1u);

    /* 3. siblings (hidden for ring anonymity) */
    memcpy(witness_out + layout->siblings_off, membership->siblings,
           layout->siblings_bytes);

    /* 4. owf inv_in */
    if (owf_vt->leaf_build_witness(sk, layout->sk_bytes,
                                   witness_out + layout->owf_invin_off) != 0)
        return -1;

    /* 5. per-level inode inv_in (walk the path, recomputing the
     * accumulated chain value at each level - matches the in-circuit
     * inode walk in walk_inodes_secret_dir). */
    if (owf_vt->leaf_hash(sk, layout->sk_bytes, current) != 0)
        return -1;

    for (size_t k = 0; k < layout->depth_m; k++) {
        const uint8_t *sib = membership->siblings + k * W;
        uint8_t dir = (uint8_t)((membership->leaf_index >> k) & 1u);
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        uint8_t *invin = witness_out + layout->path_invin_off +
                         k * layout->path_invin_per_level;

        if (tree_vt->inode_build_witness(L, R, invin) != 0)
            return -1;
        if (tree_vt->inode_hash(L, R, next) != 0)
            return -1;
        memcpy(current, next, W);
    }

    /* 6-10. Revocation slots. */
    if (cfg->depth_r > 0) {
        const size_t IDX = layout->rev_index_bytes;
        uint8_t leaf_data[2 * MERKLE_VT_MAX_NODE_BYTES +
                          VOLEITH_RSV1_REV_INDEX_BYTES];
        size_t leaf_data_bytes = 2 * W + IDX;

        /* 6. adjacent-record fields. */
        memcpy(witness_out + layout->rev_low_value_off,
               revocation->rev_low_value, W);
        memcpy(witness_out + layout->rev_low_next_off, revocation->rev_low_next,
               W);
        memcpy(witness_out + layout->rev_next_index_off,
               revocation->rev_next_index, IDX);

        /* 7. rev dirs: bit k of rev_adj_leaf_index, LSB first. */
        for (size_t k = 0; k < layout->depth_r; k++)
            witness_out[layout->rev_dirs_off + k] =
                (uint8_t)((revocation->rev_adj_leaf_index >> k) & 1u);

        /* 8. rev siblings. */
        memcpy(witness_out + layout->rev_siblings_off, revocation->rev_siblings,
               layout->rev_siblings_bytes);

        /* 9. revocation leaf inv_in (over low_value || low_next || next_index). */
        memcpy(leaf_data, revocation->rev_low_value, W);
        memcpy(leaf_data + W, revocation->rev_low_next, W);
        memcpy(leaf_data + 2 * W, revocation->rev_next_index, IDX);
        if (tree_vt->leaf_build_witness(leaf_data, leaf_data_bytes,
                                        witness_out +
                                            layout->rev_leaf_invin_off) != 0) {
            voleith_secure_zero(leaf_data, sizeof(leaf_data));
            voleith_secure_zero(current, sizeof(current));
            voleith_secure_zero(next, sizeof(next));
            return -1;
        }

        /* 10. per-level revocation inode inv_in: walk the IMT path. */
        if (tree_vt->leaf_hash(leaf_data, leaf_data_bytes, current) != 0) {
            voleith_secure_zero(leaf_data, sizeof(leaf_data));
            voleith_secure_zero(current, sizeof(current));
            voleith_secure_zero(next, sizeof(next));
            return -1;
        }

        for (size_t k = 0; k < layout->depth_r; k++) {
            const uint8_t *sib = revocation->rev_siblings + k * W;
            uint8_t dir = (uint8_t)((revocation->rev_adj_leaf_index >> k) & 1u);
            const uint8_t *L = dir ? sib : current;
            const uint8_t *R = dir ? current : sib;
            uint8_t *invin = witness_out + layout->rev_path_invin_off +
                             k * layout->rev_path_invin_per_level;

            if (tree_vt->inode_build_witness(L, R, invin) != 0) {
                voleith_secure_zero(leaf_data, sizeof(leaf_data));
                voleith_secure_zero(current, sizeof(current));
                voleith_secure_zero(next, sizeof(next));
                return -1;
            }
            if (tree_vt->inode_hash(L, R, next) != 0) {
                voleith_secure_zero(leaf_data, sizeof(leaf_data));
                voleith_secure_zero(current, sizeof(current));
                voleith_secure_zero(next, sizeof(next));
                return -1;
            }
            memcpy(current, next, W);
        }

        voleith_secure_zero(leaf_data, sizeof(leaf_data));
    }

    voleith_secure_zero(current, sizeof(current));
    voleith_secure_zero(next, sizeof(next));
    return 0;
}
