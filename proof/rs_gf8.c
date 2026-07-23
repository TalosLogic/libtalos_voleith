/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_gf8.c - composable ring-signature config (data layer)
 * implementation.
 *
 * The superset config validator, module bitmap, and composable
 * cfg-fingerprint.  No circuit / sign / verify machinery lives here;
 * those arrive in later tickets.  The membership encoding is reused
 * verbatim from the core absorber (voleith_rs_membership_absorb_canonical)
 * so every variant shares one source of truth.
 *
 * See rs_gf8.h for the API contract and
 * the RS implementation plan for the module model.
 */

#include "rs_gf8.h"

#include "../circuits/aes_cmac_gf8_circuit.h"
#include "../circuits/kdf_ctr_cmac_gf8_circuit.h"
#include "../circuits/merkle_vt_gf8_helpers.h"
#include "../circuits/rs_gf8_circuit.h"
#include "../circuits/rs_leaf_gf8_circuit.h"
#include "../core/hash.h"
#include "../core/util.h"
#include "gf8_proof.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t
voleith_rs_module_bitmap(const voleith_rs_config_t *cfg)
{
    uint8_t bitmap = 0;

    if (cfg == NULL)
        return 0;

    if (cfg->membership.depth_r > 0)
        bitmap |= VOLEITH_RS_MODULE_REVOCATION;
    if (cfg->scope_bytes > 0)
        bitmap |= VOLEITH_RS_MODULE_NULLIFIER;

    if (cfg->attr_schema != NULL && cfg->attr_schema->fields != NULL) {
        for (size_t i = 0; i < cfg->attr_schema->n_fields; i++) {
            if (cfg->attr_schema->fields[i].pred != VOLEITH_RS_ATTR_PRED_NONE) {
                bitmap |= VOLEITH_RS_MODULE_PREDICATE;
                break;
            }
        }
    }

    if (cfg->enable_commitment)
        bitmap |= VOLEITH_RS_MODULE_COMMITMENT;
    if (cfg->depth_s > 0)
        bitmap |= VOLEITH_RS_MODULE_SPENT_SET;
    if (cfg->depth_e > 0)
        bitmap |= VOLEITH_RS_MODULE_EPOCH;

    return bitmap;
}

int
voleith_rs_config_validate(const voleith_rs_config_t *cfg)
{
    const voleith_node_hash_vt *owf_vt;
    size_t attr_total = 0;
    size_t leaf_preimage;

    if (cfg == NULL)
        return -1;

    /*
     * Structural membership checks only.  The composable leaf preimage
     * is OWF(sk || attributes), so the V1 "sk == fixed_leaf_bytes" check
     * does not apply; the OWF-input-width check below uses the wider
     * single-compression capacity leaf_block_bytes instead.
     *
     * V6: the membership sk is absent (the leaf secret is sk_t via the
     * epoch subtree), so membership.sk_bytes must be 0.  The shared
     * structural validator predates V6 and rejects sk_bytes == 0, so run
     * it against a copy whose sk_bytes stands in as epoch_sk_bytes purely
     * to satisfy that >= 1 sanity rule; every other structural check
     * (depth_m, tree_hash, owf compatibility) still runs on the real
     * values, and the cfg-fingerprint absorbs the real sk_bytes == 0.
     */
    if (cfg->depth_e > 0) {
        voleith_rs_membership_config_t probe = cfg->membership;
        if (cfg->membership.sk_bytes != 0)
            return -1;
        probe.sk_bytes = cfg->epoch_sk_bytes;
        if (voleith_rs_membership_validate_structural(&probe) != 0)
            return -1;
    } else {
        if (voleith_rs_membership_validate_structural(&cfg->membership) != 0)
            return -1;
    }

    if (cfg->attr_schema != NULL) {
        const voleith_rs_attr_schema_t *schema = cfg->attr_schema;

        if (schema->n_fields == 0 || schema->fields == NULL)
            return -1;

        for (size_t i = 0; i < schema->n_fields; i++) {
            if (schema->fields[i].width_bytes == 0)
                return -1;
            if (schema->fields[i].pred > VOLEITH_RS_ATTR_PRED_MAX)
                return -1;
            /* Guard the running sum against size_t overflow before the
             * cap check; widths are bounded but callers may pass an
             * absurd schema. */
            if (schema->fields[i].width_bytes >
                VOLEITH_RS_ATTR_TOTAL_MAX_BYTES - attr_total)
                return -1;
            attr_total += schema->fields[i].width_bytes;
        }
    }

    /*
     * OWF input width = sk || attributes.  Guard the sum against size_t
     * overflow (structural already requires sk_bytes >= 1; attr_total is
     * capped above), then bound it by the OWF's leaf capacity:
     *
     *   leaf_block_bytes != 0 (fixed-input OWF): the preimage must fit a
     *     single compression, so sk + attributes <= leaf_block_bytes.
     *     The leaf circuit zero-pads any shortfall; the exact length is
     *     fixed by the schema and bound into the fingerprint.
     *   leaf_block_bytes == 0, fixed_leaf_bytes != 0 (fixed-exact OWF
     *     with no block capacity advertised): require exact match.
     *   both 0 (variable-leaf OWF): no upper bound beyond the attribute
     *     cap already enforced.
     */
    const voleith_node_hash_vt *tree_vt = cfg->membership.tree_hash;
    int v6_on = (cfg->depth_e > 0);
    owf_vt = cfg->membership.owf_hash ? cfg->membership.owf_hash : tree_vt;

    /*
     * V6 epoch tree.  When enabled, the leaf secret is sk_t derived
     * through the epoch subtree, so membership.sk_bytes is 0 and the OWF
     * preimage (V3 on) or the leaf itself (V3 off) is headed by the
     * epoch_root, not a static sk.  The epoch fields are meaningful only
     * here, so they must be zero/NULL when V6 is off (otherwise a set
     * field would be silently dropped from the cfg-fingerprint, which
     * absorbs the epoch section only when bit 5 is set).
     */
    if (v6_on) {
        const voleith_node_hash_vt *epoch_vt =
            cfg->epoch_hash ? cfg->epoch_hash : tree_vt;

        if (cfg->depth_e > VOLEITH_RS_EPOCH_MAX_DEPTH)
            return -1;
        /* The epoch root IS the ring leaf value (or the OWF preimage
         * head), so its width must match the membership tree node. */
        if (epoch_vt->node_bytes != tree_vt->node_bytes)
            return -1;
        /* GGM seed / AES key width, and it must fit the epoch_hash's own
         * leaf capacity (sk_t is the epoch leaf preimage). */
        if (cfg->epoch_sk_bytes != 16u && cfg->epoch_sk_bytes != 32u)
            return -1;
        if (epoch_vt->leaf_block_bytes != 0) {
            if (cfg->epoch_sk_bytes > epoch_vt->leaf_block_bytes)
                return -1;
        } else if (epoch_vt->fixed_leaf_bytes != 0) {
            if (cfg->epoch_sk_bytes != epoch_vt->fixed_leaf_bytes)
                return -1;
        }
        /* (membership.sk_bytes == 0 was enforced with the structural
         * probe above.) */
        /* Strength: the epoch tree must not be the weakest link; the
         * preimage-ok opt-in relaxes the rule by one bit-halving (Q4). */
        if (cfg->epoch_hash_preimage_ok) {
            if (2u * epoch_vt->cr_bits < tree_vt->cr_bits)
                return -1;
        } else {
            if (epoch_vt->cr_bits < tree_vt->cr_bits)
                return -1;
        }
        /* Salt blinds V3 attributes; it needs both V6 and V3. */
        if (cfg->leaf_salt_bytes > 0 && cfg->attr_schema == NULL)
            return -1;
    } else {
        if (cfg->epoch_hash != NULL || cfg->epoch_sk_bytes != 0 ||
            cfg->leaf_salt_bytes != 0 || cfg->epoch_hash_preimage_ok != 0)
            return -1;
    }

    /*
     * OWF input width bound.  With V6+V3 the preimage is
     * epoch_root || attributes || salt (epoch_root heads it in sk's
     * slot); with V6 and no V3 the leaf IS epoch_root and no OWF runs, so
     * no width check applies; otherwise (V6 off) it is sk || attributes.
     */
    if (!(v6_on && cfg->attr_schema == NULL)) {
        size_t head = v6_on ? tree_vt->node_bytes : cfg->membership.sk_bytes;
        size_t salt = v6_on ? cfg->leaf_salt_bytes : 0u;

        if (head > SIZE_MAX - attr_total)
            return -1;
        leaf_preimage = head + attr_total;
        if (leaf_preimage > SIZE_MAX - salt)
            return -1;
        leaf_preimage += salt;

        if (owf_vt->leaf_block_bytes != 0) {
            if (leaf_preimage > owf_vt->leaf_block_bytes)
                return -1;
        } else if (owf_vt->fixed_leaf_bytes != 0) {
            if (leaf_preimage != owf_vt->fixed_leaf_bytes)
                return -1;
        }
    }

    if (cfg->depth_s > 0) {
        if (cfg->scope_bytes == 0)
            return -1;
        if (cfg->depth_s > VOLEITH_RS_MEMBERSHIP_MAX_DEPTH)
            return -1;
    }

    if (cfg->enable_commitment) {
        if (cfg->commit_id_bytes == 0 || cfg->commit_rand_bytes == 0)
            return -1;
        /* Guard commit_id_bytes + commit_rand_bytes against size_t overflow
         * (N10-3): the sum is used as a calloc count and memcpy length for
         * the id || rand commitment preimage, so an overflow would
         * under-allocate.  cfg is trusted, but this is cheap defense in
         * depth. */
        if (cfg->commit_id_bytes > SIZE_MAX - cfg->commit_rand_bytes)
            return -1;
    }

    return 0;
}

int
voleith_rs_config_fingerprint(const voleith_rs_config_t *cfg,
                              uint8_t out[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    static const uint8_t domain_tag[] =
        VOLEITH_RS_CONFIG_FINGERPRINT_DOMAIN_TAG;
    const voleith_node_hash_vt *owf_vt;
    uint8_t bitmap;
    int rc = 0;

    if (cfg == NULL || out == NULL)
        return -1;
    if (cfg->membership.tree_hash == NULL)
        return -1;

    owf_vt = cfg->membership.owf_hash ? cfg->membership.owf_hash
                                      : cfg->membership.tree_hash;
    if (cfg->membership.tree_hash->name == NULL || owf_vt->name == NULL)
        return -1;

    bitmap = voleith_rs_module_bitmap(cfg);

    if (bitmap & VOLEITH_RS_MODULE_EPOCH) {
        const voleith_node_hash_vt *epoch_vt =
            cfg->epoch_hash ? cfg->epoch_hash : cfg->membership.tree_hash;
        if (epoch_vt->name == NULL)
            return -1;
    }

    voleith_shake256_init(&ctx);

    /* domain_tag holds the explicit 16-byte tag (including its two
     * padding NULs) plus the string literal's implicit terminator;
     * subtract 1 to drop only that terminator.  Same idiom as
     * ring_sig_v1_gf8.c / params_fingerprint.c. */
    rc |= voleith_shake256_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    /* voleith_rs_membership_absorb_canonical is public and void; it asserts
     * its own absorb status internally (see rs_membership_gf8.c). */
    voleith_rs_membership_absorb_canonical(&ctx, &cfg->membership);

    rc |= voleith_shake256_absorb(&ctx, &bitmap, 1);

    if (bitmap & VOLEITH_RS_MODULE_NULLIFIER) {
        rc |= voleith_shake256_absorb_u64_le(&ctx, (uint64_t)cfg->scope_bytes);
        rc |= voleith_shake256_absorb_u64_le(&ctx, (uint64_t)cfg->depth_s);
    }

    if (bitmap & VOLEITH_RS_MODULE_COMMITMENT) {
        rc |= voleith_shake256_absorb_u64_le(&ctx,
                                             (uint64_t)cfg->commit_id_bytes);
        rc |= voleith_shake256_absorb_u64_le(&ctx,
                                             (uint64_t)cfg->commit_rand_bytes);
    }

    if (bitmap & VOLEITH_RS_MODULE_PREDICATE) {
        const voleith_rs_attr_schema_t *schema = cfg->attr_schema;

        rc |= voleith_shake256_absorb_u64_le(&ctx, (uint64_t)schema->n_fields);
        for (size_t i = 0; i < schema->n_fields; i++) {
            uint8_t pred_byte = (uint8_t)schema->fields[i].pred;

            rc |= voleith_shake256_absorb_u64_le(
                &ctx, (uint64_t)schema->fields[i].width_bytes);
            rc |= voleith_shake256_absorb(&ctx, &pred_byte, 1);
        }
    }

    if (bitmap & VOLEITH_RS_MODULE_EPOCH) {
        const voleith_node_hash_vt *epoch_vt =
            cfg->epoch_hash ? cfg->epoch_hash : cfg->membership.tree_hash;
        const char *epoch_name = epoch_vt->name;
        size_t epoch_name_len = strlen(epoch_name);
        uint8_t flag_byte = cfg->epoch_hash_preimage_ok ? 1u : 0u;

        rc |= voleith_shake256_absorb_u64_le(&ctx, (uint64_t)cfg->depth_e);
        rc |= voleith_shake256_absorb_u32_le(&ctx, (uint32_t)epoch_name_len);
        rc |= voleith_shake256_absorb(&ctx, (const uint8_t *)epoch_name,
                                      epoch_name_len);
        rc |=
            voleith_shake256_absorb_u64_le(&ctx, (uint64_t)cfg->epoch_sk_bytes);
        rc |= voleith_shake256_absorb_u64_le(&ctx,
                                             (uint64_t)cfg->leaf_salt_bytes);
        rc |= voleith_shake256_absorb(&ctx, &flag_byte, 1);
    }

    /* nonzero only on absorb-after-squeeze (unreachable here, single squeeze
     * below); propagated defensively rather than silently dropped. */
    if (rc != 0) {
        voleith_hash_ctx_clear(&ctx);
        return -1;
    }

    voleith_shake256_squeeze(&ctx, out, VOLEITH_RS_CONFIG_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}

/* ================================================================
 * Witness packer + ring builder (RS.PACK).
 * ================================================================ */

/* Walk a Merkle/IMT path from start_node, emitting per-level inode inv_in.
 * Mirrors the secret-dir inode walk in voleith_rs_membership_pack_witness. */
static int
walk_path_invin(const voleith_node_hash_vt *vt, const uint8_t *start_node,
                const uint8_t *siblings, size_t leaf_index, size_t depth,
                size_t per_level, uint8_t *out, uint8_t *root_out)
{
    size_t W = vt->node_bytes;
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next[MERKLE_VT_MAX_NODE_BYTES];
    int rc = 0;

    memcpy(current, start_node, W);
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = (uint8_t)((leaf_index >> k) & 1u);
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;

        if (vt->inode_build_witness(L, R, out + k * per_level) != 0 ||
            vt->inode_hash(L, R, next) != 0) {
            rc = -1;
            break;
        }
        memcpy(current, next, W);
    }

    if (rc == 0 && root_out != NULL)
        memcpy(root_out, current, W);

    voleith_secure_zero(current, sizeof(current));
    voleith_secure_zero(next, sizeof(next));
    return rc;
}

/* Pack one indexed-Merkle non-membership branch (revocation or spent-set):
 * the adjacent record's leaf inv_in, then the per-level path inv_in. */
static int
pack_imt_branch(const voleith_node_hash_vt *vt, const uint8_t *low_value,
                const uint8_t *low_next, const uint8_t *next_index,
                size_t value_bytes, size_t index_bytes, size_t adj_leaf_index,
                const uint8_t *siblings, size_t depth, size_t per_level,
                uint8_t *leaf_invin_out, uint8_t *path_invin_out)
{
    uint8_t
        leaf_data[2 * MERKLE_VT_MAX_NODE_BYTES + VOLEITH_RSV1_REV_INDEX_BYTES];
    uint8_t node[MERKLE_VT_MAX_NODE_BYTES];
    size_t leaf_data_bytes = 2 * value_bytes + index_bytes;
    int rc;

    memcpy(leaf_data, low_value, value_bytes);
    memcpy(leaf_data + value_bytes, low_next, value_bytes);
    memcpy(leaf_data + 2 * value_bytes, next_index, index_bytes);

    if (vt->leaf_build_witness(leaf_data, leaf_data_bytes, leaf_invin_out) !=
            0 ||
        vt->leaf_hash(leaf_data, leaf_data_bytes, node) != 0) {
        voleith_secure_zero(leaf_data, sizeof(leaf_data));
        return -1;
    }
    rc = walk_path_invin(vt, node, siblings, adj_leaf_index, depth, per_level,
                         path_invin_out, NULL);

    voleith_secure_zero(leaf_data, sizeof(leaf_data));
    voleith_secure_zero(node, sizeof(node));
    return rc;
}

int
voleith_rs_pack_witness(const voleith_rs_config_t *cfg,
                        const voleith_rs_layout_t *layout, const uint8_t *sk,
                        const uint8_t *attrs, const voleith_rs_path_t *path,
                        const uint8_t *id, const uint8_t *rand,
                        uint8_t *witness_out)
{
    const voleith_rs_membership_config_t *mcfg;
    const voleith_node_hash_vt *tree_vt;
    const voleith_node_hash_vt *owf_vt;
    const voleith_rs_membership_layout_t *ml;
    size_t W;
    size_t t_bytes;
    size_t attr_total;
    size_t commit_total;
    uint8_t leaf_node[MERKLE_VT_MAX_NODE_BYTES];
    int rc = -1;

    if (cfg == NULL || layout == NULL || path == NULL || witness_out == NULL)
        return -1;
    if (cfg->membership.sk_bytes > 0 && sk == NULL)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;

    mcfg = &cfg->membership;
    ml = &layout->membership;
    tree_vt = mcfg->tree_hash;
    owf_vt = mcfg->owf_hash ? mcfg->owf_hash : mcfg->tree_hash;
    W = tree_vt->node_bytes;
    t_bytes = voleith_rs_nullifier_bytes(cfg);

    /* V6 epoch: sk_t is the leaf secret and the nullifier PRF key. */
    int epoch_enabled = cfg->depth_e > 0;
    const voleith_node_hash_vt *epoch_vt =
        epoch_enabled ? (cfg->epoch_hash ? cfg->epoch_hash : tree_vt) : NULL;
    size_t epoch_sk_bytes = epoch_enabled ? cfg->epoch_sk_bytes : 0;
    size_t salt_bytes = epoch_enabled ? cfg->leaf_salt_bytes : 0;
    size_t prf_key_bytes = epoch_enabled ? epoch_sk_bytes : mcfg->sk_bytes;
    const uint8_t *prf_key = epoch_enabled ? path->epoch_sk : sk;
    uint8_t epoch_root[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t ht[MERKLE_VT_MAX_NODE_BYTES];

    if (epoch_enabled) {
        if (path->epoch_sk == NULL || path->epoch_siblings == NULL)
            return -1;
        if (salt_bytes > 0 && path->epoch_salt == NULL)
            return -1;
        if (cfg->depth_e < sizeof(size_t) * 8 &&
            path->epoch >= ((uint64_t)1u << cfg->depth_e))
            return -1;
    }

    attr_total = layout->attr_bytes;
    commit_total = cfg->enable_commitment
                       ? cfg->commit_id_bytes + cfg->commit_rand_bytes
                       : 0;

    if (attr_total > 0 && attrs == NULL)
        return -1;
    if (path->membership.siblings == NULL)
        return -1;
    if (ml->depth_m < sizeof(size_t) * 8 &&
        path->membership.leaf_index >= ((size_t)1u << ml->depth_m))
        return -1;

    /* 1. sk (nothing under V6, where sk_bytes == 0) */
    if (mcfg->sk_bytes > 0)
        memcpy(witness_out + ml->sk_off, sk, mcfg->sk_bytes);

    /* 1b. [V6] sk_t + salt + epoch siblings + epoch leaf/inode inv_in */
    if (epoch_enabled) {
        memcpy(witness_out + layout->epoch_sk_off, path->epoch_sk,
               epoch_sk_bytes);
        if (salt_bytes > 0)
            memcpy(witness_out + layout->salt_off, path->epoch_salt,
                   salt_bytes);
        memcpy(witness_out + layout->epoch_siblings_off, path->epoch_siblings,
               layout->epoch_siblings_bytes);

        if (epoch_vt->leaf_hash(path->epoch_sk, epoch_sk_bytes, ht) != 0)
            goto out;
        if (epoch_vt->leaf_build_witness(path->epoch_sk, epoch_sk_bytes,
                                         witness_out +
                                             layout->epoch_leaf_invin_off) != 0)
            goto out;
        if (walk_path_invin(
                epoch_vt, ht, path->epoch_siblings, (size_t)path->epoch,
                cfg->depth_e, layout->epoch_path_invin_per_level,
                witness_out + layout->epoch_path_invin_off, epoch_root) != 0)
            goto out;
    }

    /* 2. attributes */
    if (attr_total > 0)
        memcpy(witness_out + layout->attr_off, attrs, attr_total);

    /* 3. membership dirs (bit k of leaf_index, LSB first) */
    for (size_t k = 0; k < ml->depth_m; k++)
        witness_out[ml->dirs_off + k] =
            (uint8_t)((path->membership.leaf_index >> k) & 1u);

    /* 4. membership siblings */
    memcpy(witness_out + ml->siblings_off, path->membership.siblings,
           ml->siblings_bytes);

    /* [V4] id, rand */
    if (commit_total > 0) {
        if (id == NULL || rand == NULL)
            return -1;
        memcpy(witness_out + layout->commit_id_off, id, cfg->commit_id_bytes);
        memcpy(witness_out + layout->commit_rand_off, rand,
               cfg->commit_rand_bytes);
    }

    /* leaf_node and, when an OWF runs, its leaf inv_in.
     *   non-V6:        leaf_node = OWF(sk || attrs)
     *   V6 + V3:       leaf_node = OWF(epoch_root || attrs || salt)
     *   V6 without V3: leaf_node := epoch_root (no OWF inv_in) */
    if (epoch_enabled && cfg->attr_schema == NULL) {
        memcpy(leaf_node, epoch_root, W);
    } else if (epoch_enabled) {
        size_t tail = attr_total + salt_bytes;
        uint8_t *tailbuf = calloc(tail > 0 ? tail : 1, 1);
        int lrc;

        if (tailbuf == NULL)
            goto out;
        if (attr_total > 0)
            memcpy(tailbuf, attrs, attr_total);
        if (salt_bytes > 0)
            memcpy(tailbuf + attr_total, path->epoch_salt, salt_bytes);
        lrc = rs_leaf_gf8_build_witness(owf_vt, epoch_root, W, tailbuf, tail,
                                        witness_out + ml->owf_invin_off);
        if (lrc == 0)
            lrc = rs_leaf_gf8_hash(owf_vt, epoch_root, W, tailbuf, tail,
                                   leaf_node);
        voleith_secure_zero(tailbuf, tail);
        free(tailbuf);
        if (lrc != 0)
            goto out;
    } else {
        if (rs_leaf_gf8_build_witness(owf_vt, sk, mcfg->sk_bytes, attrs,
                                      attr_total,
                                      witness_out + ml->owf_invin_off) != 0)
            goto out;
        if (rs_leaf_gf8_hash(owf_vt, sk, mcfg->sk_bytes, attrs, attr_total,
                             leaf_node) != 0)
            goto out;
    }

    /* membership path inv_in */
    if (walk_path_invin(tree_vt, leaf_node, path->membership.siblings,
                        path->membership.leaf_index, ml->depth_m,
                        ml->path_invin_per_level,
                        witness_out + ml->path_invin_off, NULL) != 0)
        goto out;

    /* [V4] commitment leaf-hash inv_in over id || rand */
    if (commit_total > 0) {
        uint8_t *idrand = calloc(commit_total, 1);
        int crc;

        if (idrand == NULL)
            goto out;
        memcpy(idrand, id, cfg->commit_id_bytes);
        memcpy(idrand + cfg->commit_id_bytes, rand, cfg->commit_rand_bytes);
        crc = tree_vt->leaf_build_witness(
            idrand, commit_total, witness_out + layout->commit_invin_off);
        voleith_secure_zero(idrand, commit_total);
        free(idrand);
        if (crc != 0)
            goto out;
    }

    /* [V2] nullifier inv_in (strip the key prefix the builder shares with
     * the already-packed sk wires).  Width tracks the tree's CR strength:
     * 16-byte raw AES-CMAC vs >= 32-byte SP 800-108 KDF-CTR-CMAC. */
    if (cfg->scope_bytes > 0) {
        if (path->scope == NULL)
            goto out;

        if (t_bytes == VOLEITH_RS_NULLIFIER_BYTES) {
            size_t buf =
                aes_cmac_gf8_witness_bytes(prf_key_bytes, cfg->scope_bytes);
            uint8_t *tmp;

            tmp = calloc(buf, 1);
            if (tmp == NULL)
                goto out;
            aes_cmac_gf8_build_witness(prf_key, prf_key_bytes, path->scope,
                                       cfg->scope_bytes, tmp, NULL);
            memcpy(witness_out + layout->nullifier_invin_off,
                   tmp + prf_key_bytes, layout->nullifier_invin_bytes);
            voleith_secure_zero(tmp, buf);
            free(tmp);
        } else {
            /* FixedInputData = Label || 0x00 || scope || [L]_2 (bits). */
            size_t fi_bytes =
                VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES + 1 + cfg->scope_bytes + 4;
            size_t buf = kdf_ctr_cmac_gf8_witness_bytes(prf_key_bytes, t_bytes,
                                                        fi_bytes);
            size_t l_bits = t_bytes * 8u;
            size_t p = 0;
            uint8_t *fi;
            uint8_t *tmp;
            int krc;

            fi = calloc(fi_bytes, 1);
            tmp = calloc(buf, 1);
            if (fi == NULL || tmp == NULL) {
                free(fi);
                free(tmp);
                goto out;
            }
            memcpy(fi + p, VOLEITH_RS_NULLIFIER_KDF_LABEL,
                   VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES);
            p += VOLEITH_RS_NULLIFIER_KDF_LABEL_BYTES;
            fi[p++] = 0x00;
            memcpy(fi + p, path->scope, cfg->scope_bytes);
            p += cfg->scope_bytes;
            fi[p++] = (uint8_t)((l_bits >> 24) & 0xFF);
            fi[p++] = (uint8_t)((l_bits >> 16) & 0xFF);
            fi[p++] = (uint8_t)((l_bits >> 8) & 0xFF);
            fi[p++] = (uint8_t)(l_bits & 0xFF);

            krc = kdf_ctr_cmac_gf8_build_witness(prf_key, prf_key_bytes, fi,
                                                 fi_bytes, t_bytes, tmp, NULL);
            if (krc == 0)
                memcpy(witness_out + layout->nullifier_invin_off,
                       tmp + prf_key_bytes, layout->nullifier_invin_bytes);
            voleith_secure_zero(tmp, buf);
            free(fi);
            free(tmp);
            if (krc != 0)
                goto out;
        }
    }

    /* revocation branch */
    if (mcfg->depth_r > 0) {
        const voleith_rs_membership_path_t *p = &path->membership;
        const size_t IDX = VOLEITH_RSV1_REV_INDEX_BYTES;

        if (p->rev_siblings == NULL || p->rev_low_value == NULL ||
            p->rev_low_next == NULL || p->rev_next_index == NULL)
            goto out;
        memcpy(witness_out + ml->rev_low_value_off, p->rev_low_value, W);
        memcpy(witness_out + ml->rev_low_next_off, p->rev_low_next, W);
        memcpy(witness_out + ml->rev_next_index_off, p->rev_next_index, IDX);
        for (size_t k = 0; k < ml->depth_r; k++)
            witness_out[ml->rev_dirs_off + k] =
                (uint8_t)((p->rev_adj_leaf_index >> k) & 1u);
        memcpy(witness_out + ml->rev_siblings_off, p->rev_siblings,
               ml->rev_siblings_bytes);
        if (pack_imt_branch(tree_vt, p->rev_low_value, p->rev_low_next,
                            p->rev_next_index, W, IDX, p->rev_adj_leaf_index,
                            p->rev_siblings, ml->depth_r,
                            ml->rev_path_invin_per_level,
                            witness_out + ml->rev_leaf_invin_off,
                            witness_out + ml->rev_path_invin_off) != 0)
            goto out;
    }

    /* spent-set branch (IMT over the nullifier T, width = t_bytes) */
    if (cfg->depth_s > 0) {
        const size_t TV = t_bytes;
        const size_t IDX = VOLEITH_RSV1_REV_INDEX_BYTES;

        if (path->spent_siblings == NULL || path->spent_low_value == NULL ||
            path->spent_low_next == NULL || path->spent_next_index == NULL)
            goto out;
        memcpy(witness_out + layout->spent_low_value_off, path->spent_low_value,
               TV);
        memcpy(witness_out + layout->spent_low_next_off, path->spent_low_next,
               TV);
        memcpy(witness_out + layout->spent_next_index_off,
               path->spent_next_index, IDX);
        for (size_t k = 0; k < layout->spent_dirs_bytes; k++)
            witness_out[layout->spent_dirs_off + k] =
                (uint8_t)((path->spent_adj_leaf_index >> k) & 1u);
        memcpy(witness_out + layout->spent_siblings_off, path->spent_siblings,
               layout->spent_siblings_bytes);
        if (pack_imt_branch(tree_vt, path->spent_low_value,
                            path->spent_low_next, path->spent_next_index, TV,
                            IDX, path->spent_adj_leaf_index,
                            path->spent_siblings, cfg->depth_s,
                            layout->spent_path_invin_per_level,
                            witness_out + layout->spent_leaf_invin_off,
                            witness_out + layout->spent_path_invin_off) != 0)
            goto out;
    }

    rc = 0;
out:
    voleith_secure_zero(leaf_node, sizeof(leaf_node));
    voleith_secure_zero(ht, sizeof(ht));
    voleith_secure_zero(epoch_root, sizeof(epoch_root));
    return rc;
}

int
voleith_rs_ring_build(const voleith_rs_config_t *cfg, const uint8_t *sks,
                      const uint8_t *attrs_or_null, size_t n_members,
                      uint8_t *root_out, voleith_rs_path_t *paths_out,
                      uint8_t *siblings_storage)
{
    const voleith_rs_membership_config_t *mcfg;
    const voleith_node_hash_vt *tree_vt;
    const voleith_node_hash_vt *owf_vt;
    size_t W;
    size_t depth_m;
    size_t capacity;
    size_t attr_total;
    uint8_t *leaf_nodes = NULL;
    int rc = -1;

    if (cfg == NULL || sks == NULL || root_out == NULL || paths_out == NULL ||
        siblings_storage == NULL)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;
    if (n_members == 0)
        return -1;

    mcfg = &cfg->membership;
    tree_vt = mcfg->tree_hash;
    owf_vt = mcfg->owf_hash ? mcfg->owf_hash : mcfg->tree_hash;
    W = tree_vt->node_bytes;
    depth_m = mcfg->depth_m;

    attr_total = 0;
    if (cfg->attr_schema != NULL)
        for (size_t i = 0; i < cfg->attr_schema->n_fields; i++)
            attr_total += cfg->attr_schema->fields[i].width_bytes;

    /* attrs_or_null must be present iff the schema declares attributes. */
    if ((attr_total > 0) != (attrs_or_null != NULL))
        return -1;

    if (depth_m >= sizeof(size_t) * 8) {
        capacity = (size_t)-1;
    } else {
        capacity = (size_t)1u << depth_m;
        if (n_members > capacity)
            return -1;
    }

    /* calloc zero-fills vacant slots with the documented sentinel
     * (VOLEITH_RSV1_SENTINEL_LEAF_BYTE == 0x00): an all-zero leaf node
     * cannot collide with a real OWF output. */
    leaf_nodes = calloc(capacity, W);
    if (leaf_nodes == NULL)
        return -1;

    for (size_t i = 0; i < n_members; i++) {
        const uint8_t *ai =
            attrs_or_null ? attrs_or_null + i * attr_total : NULL;
        if (rs_leaf_gf8_hash(owf_vt, sks + i * mcfg->sk_bytes, mcfg->sk_bytes,
                             ai, attr_total, leaf_nodes + i * W) != 0)
            goto out;
    }

    if (voleith_merkle_vt_build(tree_vt, leaf_nodes, capacity, root_out) != 0)
        goto out;

    for (size_t i = 0; i < n_members; i++) {
        uint8_t *sib = siblings_storage + i * depth_m * W;
        if (voleith_merkle_vt_compute_path(tree_vt, leaf_nodes, capacity, i,
                                           sib) != 0)
            goto out;
        paths_out[i].membership.leaf_index = i;
        paths_out[i].membership.siblings = sib;
    }

    rc = 0;
out:
    if (leaf_nodes != NULL) {
        voleith_secure_zero(leaf_nodes, capacity * W);
        free(leaf_nodes);
    }
    return rc;
}

/* ================================================================
 * Composed Fiat-Shamir seed (RS.FS).
 * ================================================================ */

/* Returns the underlying absorb status (0, or VOLEITH_HASH_ERR_FINALIZED). */
static int
absorb_u64_be(voleith_hash_ctx_t *ctx, uint64_t v)
{
    uint8_t b[8];
    for (size_t i = 0; i < 8; i++)
        b[i] = (uint8_t)((v >> (56 - 8 * i)) & 0xffu);
    return voleith_shake256_absorb(ctx, b, sizeof(b));
}

int
voleith_rs_compute_fs_seed(const voleith_rs_config_t *cfg,
                           const voleith_rs_public_t *pub, const uint8_t *m,
                           size_t m_len, uint8_t out[VOLEITH_RS_FS_SEED_BYTES])
{
    voleith_hash_ctx_t ctx;
    static const uint8_t domain_tag[] = VOLEITH_RS_FS_SEED_DOMAIN_TAG;
    uint8_t version = VOLEITH_RS_FS_SEED_FMT_VERSION;
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t zero_node[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t bitmap;
    size_t W;
    int rc = 0;

    if (cfg == NULL || pub == NULL || out == NULL)
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    if (pub->membership_root == NULL)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;
    if (voleith_rs_config_fingerprint(cfg, fp) != 0)
        return -1;

    W = cfg->membership.tree_hash->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    bitmap = voleith_rs_module_bitmap(cfg);

    /* Per-module required public inputs. */
    if ((bitmap & VOLEITH_RS_MODULE_COMMITMENT) && pub->commitment == NULL)
        return -1;
    if ((bitmap & VOLEITH_RS_MODULE_NULLIFIER) &&
        (pub->scope == NULL || pub->nullifier == NULL))
        return -1;
    if ((bitmap & VOLEITH_RS_MODULE_SPENT_SET) && pub->spent_root == NULL)
        return -1;
    if ((bitmap & VOLEITH_RS_MODULE_EPOCH) && cfg->depth_e < 64 &&
        pub->epoch >= ((uint64_t)1u << cfg->depth_e))
        return -1;
    if (bitmap & VOLEITH_RS_MODULE_PREDICATE) {
        /* Enforce pub->bounds_len against the schema-derived total before the
         * absorb loop reads pub->bounds (N10-2): EQ contributes width, RANGE
         * 2*width, in schema order over fields with pred != NONE.  A short
         * buffer would otherwise be over-read. */
        const voleith_rs_attr_schema_t *schema = cfg->attr_schema;
        size_t expected = 0;

        if (pub->bounds == NULL)
            return -1;
        for (size_t i = 0; i < schema->n_fields; i++) {
            if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_EQ)
                expected += schema->fields[i].width_bytes;
            else if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_RANGE)
                expected += 2u * schema->fields[i].width_bytes;
        }
        if (pub->bounds_len != expected)
            return -1;
    }

    voleith_shake256_init(&ctx);
    rc |= voleith_shake256_absorb(&ctx, &version, 1);
    /* Drop only the string literal's implicit terminator; the two padding
     * NULs in the 16-byte tag are absorbed. */
    rc |= voleith_shake256_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);
    rc |= voleith_shake256_absorb(&ctx, fp, sizeof(fp));
    rc |= voleith_shake256_absorb(&ctx, &bitmap, 1);

    rc |= voleith_shake256_absorb(&ctx, pub->membership_root, W);

    /* revocation_root_or_zero: absorbed unconditionally (§1.4). */
    if (pub->revocation_root != NULL) {
        rc |= voleith_shake256_absorb(&ctx, pub->revocation_root, W);
    } else {
        memset(zero_node, 0, W);
        rc |= voleith_shake256_absorb(&ctx, zero_node, W);
    }

    if (bitmap & VOLEITH_RS_MODULE_COMMITMENT)
        rc |= voleith_shake256_absorb(&ctx, pub->commitment, W);

    if (bitmap & VOLEITH_RS_MODULE_NULLIFIER) {
        rc |= absorb_u64_be(&ctx, (uint64_t)cfg->scope_bytes);
        rc |= voleith_shake256_absorb(&ctx, pub->scope, cfg->scope_bytes);
        rc |= voleith_shake256_absorb(&ctx, pub->nullifier,
                                      voleith_rs_nullifier_bytes(cfg));
    }

    if (bitmap & VOLEITH_RS_MODULE_SPENT_SET)
        rc |= voleith_shake256_absorb(&ctx, pub->spent_root, W);

    if (bitmap & VOLEITH_RS_MODULE_PREDICATE) {
        const voleith_rs_attr_schema_t *schema = cfg->attr_schema;
        size_t cursor = 0; /* byte offset within pub->bounds */
        uint64_t n_pred = 0;

        for (size_t i = 0; i < schema->n_fields; i++)
            if (schema->fields[i].pred != VOLEITH_RS_ATTR_PRED_NONE)
                n_pred++;

        rc |= absorb_u64_be(&ctx, n_pred);
        for (size_t i = 0; i < schema->n_fields; i++) {
            size_t w = schema->fields[i].width_bytes;
            uint8_t kind = (uint8_t)schema->fields[i].pred;

            if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_NONE)
                continue;

            rc |= absorb_u64_be(&ctx, (uint64_t)i);
            rc |= voleith_shake256_absorb(&ctx, &kind, 1);
            if (schema->fields[i].pred == VOLEITH_RS_ATTR_PRED_EQ) {
                rc |= absorb_u64_be(&ctx, (uint64_t)w);
                rc |= voleith_shake256_absorb(&ctx, pub->bounds + cursor, w);
                cursor += w;
            } else { /* RANGE */
                rc |= absorb_u64_be(&ctx, (uint64_t)w);
                rc |= voleith_shake256_absorb(&ctx, pub->bounds + cursor, w);
                cursor += w;
                rc |= absorb_u64_be(&ctx, (uint64_t)w);
                rc |= voleith_shake256_absorb(&ctx, pub->bounds + cursor, w);
                cursor += w;
            }
        }
    }

    /* [V6] epoch section: t as 8-byte big-endian, gated by bit 5, after
     * the predicate section and immediately before m_len || m (design 6.4). */
    if (bitmap & VOLEITH_RS_MODULE_EPOCH)
        rc |= absorb_u64_be(&ctx, pub->epoch);

    rc |= absorb_u64_be(&ctx, (uint64_t)m_len);
    if (m_len != 0)
        rc |= voleith_shake256_absorb(&ctx, m, m_len);

    /* nonzero only on absorb-after-squeeze (unreachable here, single squeeze
     * below); propagated defensively rather than silently dropped. */
    if (rc != 0) {
        voleith_hash_ctx_clear(&ctx);
        voleith_secure_zero(fp, sizeof(fp));
        voleith_secure_zero(zero_node, sizeof(zero_node));
        return -1;
    }

    voleith_shake256_squeeze(&ctx, out, VOLEITH_RS_FS_SEED_BYTES);
    voleith_hash_ctx_clear(&ctx);
    voleith_secure_zero(fp, sizeof(fp));
    voleith_secure_zero(zero_node, sizeof(zero_node));
    return 0;
}

/* ================================================================
 * Sign / verify (RS.SIGN).
 * ================================================================ */

void
voleith_rs_sig_free(voleith_rs_sig_t *sig)
{
    if (sig == NULL)
        return;
    if (sig->data != NULL) {
        voleith_secure_zero(sig->data, sig->len);
        free(sig->data);
    }
    sig->data = NULL;
    sig->len = 0;
}

/* Fill the instance buffer from the public inputs in §1.3 order.  Each
 * module section is written iff its layout byte count is non-zero (set
 * only when the module is enabled).  Returns -1 if an enabled module's
 * public field is NULL. */
static int
rs_fill_instance(const voleith_rs_layout_t *layout,
                 const voleith_rs_public_t *pub, uint8_t *instance)
{
    const voleith_rs_membership_layout_t *ml = &layout->membership;

    /* [V6] epoch direction bytes derived from the public epoch index t; the
     * caller never supplies them. */
    for (size_t k = 0; k < layout->inst_epoch_dirs_bytes; k++)
        instance[layout->inst_epoch_dirs_off + k] =
            (uint8_t)((pub->epoch >> k) & 1u);

    memcpy(instance + ml->inst_root_off, pub->membership_root,
           ml->inst_root_bytes);

    if (layout->inst_commit_bytes > 0) {
        if (pub->commitment == NULL)
            return -1;
        memcpy(instance + layout->inst_commit_off, pub->commitment,
               layout->inst_commit_bytes);
    }
    if (layout->inst_scope_bytes > 0) {
        if (pub->scope == NULL || pub->nullifier == NULL)
            return -1;
        memcpy(instance + layout->inst_scope_off, pub->scope,
               layout->inst_scope_bytes);
        memcpy(instance + layout->inst_t_off, pub->nullifier,
               layout->inst_t_bytes);
    }
    if (layout->inst_bounds_bytes > 0) {
        /* bounds_len is the caller's declared length of pub->bounds.  Enforce
         * it against the schema-derived section size (N10-2): a shorter
         * buffer would otherwise be over-read, and the struct documents
         * bounds_len as a sanity field that must match the schema. */
        if (pub->bounds == NULL || pub->bounds_len != layout->inst_bounds_bytes)
            return -1;
        memcpy(instance + layout->inst_bounds_off, pub->bounds,
               layout->inst_bounds_bytes);
    }
    if (ml->inst_rev_root_bytes > 0) {
        if (pub->revocation_root == NULL)
            return -1;
        memcpy(instance + ml->inst_rev_root_off, pub->revocation_root,
               ml->inst_rev_root_bytes);
    }
    if (layout->inst_spent_root_bytes > 0) {
        if (pub->spent_root == NULL)
            return -1;
        memcpy(instance + layout->inst_spent_root_off, pub->spent_root,
               layout->inst_spent_root_bytes);
    }
    return 0;
}

int
voleith_rs_sign(voleith_rs_sig_t *sig_out, const voleith_rs_config_t *cfg,
                const voleith_params_t *params, const uint8_t *sk,
                const uint8_t *attrs, const voleith_rs_path_t *path,
                const voleith_rs_public_t *pub, const uint8_t *m, size_t m_len)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_layout_t layout;
    uint8_t *witness = NULL;
    uint8_t *instance = NULL;
    uint8_t fs_seed[VOLEITH_RS_FS_SEED_BYTES];
    voleith_proof_t proof = {NULL, 0};
    int rc = -1;

    voleith_rs_path_t local_path;

    if (sig_out == NULL || cfg == NULL || params == NULL || path == NULL ||
        pub == NULL)
        return -1;
    if (cfg->membership.sk_bytes > 0 && sk == NULL) /* sk absent under V6 */
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;

    if (voleith_rs_config_validate(cfg) != 0)
        return -1;

    /* pub->epoch is authoritative: the instance dirs and fs_seed derive from
     * it, so pin the packer's epoch (which orders the epoch inv_in walk) to
     * match, sparing the caller from setting path->epoch too. */
    local_path = *path;
    local_path.epoch = pub->epoch;

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        return -1;
    if (voleith_rs_build_circuit(circuit, cfg, &layout) != 0)
        goto out;

    witness = calloc(layout.witness_bytes ? layout.witness_bytes : 1, 1);
    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (witness == NULL || instance == NULL)
        goto out;

    if (voleith_rs_pack_witness(cfg, &layout, sk, attrs, &local_path,
                                local_path.commit_id, local_path.commit_rand,
                                witness) != 0)
        goto out;
    if (rs_fill_instance(&layout, pub, instance) != 0)
        goto out;

    if (voleith_rs_compute_fs_seed(cfg, pub, m, m_len, fs_seed) != 0)
        goto out;

    /* prove_v2 runs circuit_eval first; a witness that does not satisfy
     * every module constraint (membership, predicate, nullifier,
     * commitment, revocation, spent-set) fails here with -1. */
    if (voleith_gf8_prove_v2(
            &proof, params, circuit, witness, layout.witness_bytes, instance,
            layout.instance_bytes, fs_seed, sizeof(fs_seed)) != 0)
        goto out;

    sig_out->data = proof.data;
    sig_out->len = proof.len;
    proof.data = NULL;
    proof.len = 0;
    rc = 0;

out:
    if (witness != NULL) {
        voleith_secure_zero(witness, layout.witness_bytes);
        free(witness);
    }
    free(instance);
    voleith_secure_zero(fs_seed, sizeof(fs_seed));
    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(circuit);
    return rc;
}

int
voleith_rs_verify(const voleith_rs_sig_t *sig, const voleith_rs_config_t *cfg,
                  const voleith_params_t *params,
                  const voleith_rs_public_t *pub, const uint8_t *m,
                  size_t m_len)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_layout_t layout;
    uint8_t *instance = NULL;
    uint8_t fs_seed[VOLEITH_RS_FS_SEED_BYTES];
    voleith_proof_t proof_view = {NULL, 0};
    int rc = -1;

    if (sig == NULL || sig->data == NULL || cfg == NULL || params == NULL ||
        pub == NULL || pub->membership_root == NULL)
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        return -1;
    if (voleith_rs_build_circuit(circuit, cfg, &layout) != 0)
        goto out;

    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (instance == NULL)
        goto out;
    if (rs_fill_instance(&layout, pub, instance) != 0)
        goto out;

    if (voleith_rs_compute_fs_seed(cfg, pub, m, m_len, fs_seed) != 0)
        goto out;

    proof_view.data = sig->data;
    proof_view.len = sig->len;
    rc = voleith_gf8_verify_v2(&proof_view, params, circuit, instance,
                               layout.instance_bytes, fs_seed, sizeof(fs_seed));

out:
    free(instance);
    voleith_secure_zero(fs_seed, sizeof(fs_seed));
    voleith_gf8_circuit_free(circuit);
    return rc;
}

/* ================================================================
 * Serialization (RS.SER): "VRSC" envelope.
 * ================================================================ */

static void
rs_write_u32_be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)(v >> 24);
    out[1] = (uint8_t)(v >> 16);
    out[2] = (uint8_t)(v >> 8);
    out[3] = (uint8_t)v;
}

static uint32_t
rs_read_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

size_t
voleith_rs_sig_packed_len(const voleith_rs_sig_t *sig)
{
    if (sig == NULL)
        return 0;
    return VOLEITH_RS_SIG_HEADER_BYTES + sig->len;
}

int
voleith_rs_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                    const voleith_rs_sig_t *sig, const voleith_rs_config_t *cfg,
                    const voleith_params_t *params)
{
    uint8_t cfg_fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    size_t off;

    if (out_buf == NULL || sig == NULL || cfg == NULL || params == NULL)
        return -1;
    if ((sig->data == NULL) != (sig->len == 0))
        return -1;
    if (sig->len > UINT32_MAX)
        return -1;
    if (out_len != VOLEITH_RS_SIG_HEADER_BYTES + sig->len)
        return -1;

    if (voleith_rs_config_fingerprint(cfg, cfg_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, params_fp) != 0)
        return -1;

    off = 0;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_0;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_1;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_2;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_3;
    out_buf[off++] = (uint8_t)VOLEITH_RS_SIG_FORMAT_VERSION;
    memcpy(out_buf + off, cfg_fp, sizeof(cfg_fp));
    off += sizeof(cfg_fp);
    memcpy(out_buf + off, params_fp, sizeof(params_fp));
    off += sizeof(params_fp);
    rs_write_u32_be(out_buf + off, (uint32_t)sig->len);
    off += 4;
    if (sig->len != 0)
        memcpy(out_buf + off, sig->data, sig->len);
    off += sig->len;

    if (written_out != NULL)
        *written_out = off;
    return 0;
}

int
voleith_rs_sig_unpack(voleith_rs_sig_t *sig_out, const uint8_t *buf,
                      size_t buf_len, const voleith_rs_config_t *cfg,
                      const voleith_params_t *params)
{
    uint8_t expected_cfg_fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint32_t proof_len;
    size_t off;

    if (sig_out == NULL || buf == NULL || cfg == NULL || params == NULL)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;

    if (buf_len < VOLEITH_RS_SIG_HEADER_BYTES)
        return -1;

    if (buf[0] != VOLEITH_RS_SIG_MAGIC_0 || buf[1] != VOLEITH_RS_SIG_MAGIC_1 ||
        buf[2] != VOLEITH_RS_SIG_MAGIC_2 || buf[3] != VOLEITH_RS_SIG_MAGIC_3)
        return -1;
    if (buf[4] != (uint8_t)VOLEITH_RS_SIG_FORMAT_VERSION)
        return -1;

    if (voleith_rs_config_fingerprint(cfg, expected_cfg_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, expected_params_fp) != 0)
        return -1;

    off = 5;
    if (voleith_const_memcmp(buf + off, expected_cfg_fp,
                             sizeof(expected_cfg_fp)) != 0)
        return -1;
    off += sizeof(expected_cfg_fp);
    if (voleith_const_memcmp(buf + off, expected_params_fp,
                             sizeof(expected_params_fp)) != 0)
        return -1;
    off += sizeof(expected_params_fp);

    proof_len = rs_read_u32_be(buf + off);
    off += 4;

    if (buf_len != (size_t)VOLEITH_RS_SIG_HEADER_BYTES + proof_len)
        return -1;

    if (proof_len == 0)
        return 0;

    sig_out->data = malloc(proof_len);
    if (sig_out->data == NULL)
        return -1;
    memcpy(sig_out->data, buf + off, proof_len);
    sig_out->len = proof_len;
    return 0;
}

/* ================================================================
 * Linkability (V2.LINK).
 * ================================================================ */

size_t
voleith_rs_nullifier_bytes(const voleith_rs_config_t *cfg)
{
    size_t blocks, cr_bytes;

    if (cfg == NULL || cfg->membership.tree_hash == NULL)
        return VOLEITH_RS_NULLIFIER_BYTES;

    /*
     * Minimum width matches the tree's collision-resistance strength
     * (second-preimage parity), floored at the 16-byte AES-CMAC block and
     * rounded up to whole CMAC blocks so the KDF-CTR-CMAC output length
     * stays block-aligned.
     */
    cr_bytes = (cfg->membership.tree_hash->cr_bits + 7u) / 8u;
    if (cr_bytes < VOLEITH_RS_NULLIFIER_BYTES)
        cr_bytes = VOLEITH_RS_NULLIFIER_BYTES;
    blocks = (cr_bytes + VOLEITH_RS_NULLIFIER_BYTES - 1u) /
             VOLEITH_RS_NULLIFIER_BYTES;
    return blocks * VOLEITH_RS_NULLIFIER_BYTES;
}

int
voleith_rs_nullifier_equal(const uint8_t *t1, const uint8_t *t2, size_t t_bytes)
{
    if (t1 == NULL || t2 == NULL || t_bytes == 0)
        return 0;
    return voleith_const_memcmp(t1, t2, t_bytes) == 0 ? 1 : 0;
}

const uint8_t *
voleith_rs_nullifier(const voleith_rs_config_t *cfg,
                     const voleith_rs_public_t *pub)
{
    if (cfg == NULL || pub == NULL)
        return NULL;
    if (cfg->scope_bytes == 0)
        return NULL;
    return pub->nullifier;
}

/* ================================================================
 * Claimable commitment (V4.CLAIM).
 * ================================================================ */

/*
 * Recompute C = tree_hash(id || rand) into c_out (node_bytes wide).
 * Validates cfg, the commitment module, and node_bytes; concatenates the
 * opening into a transient buffer and calls the tree vt's leaf_hash (the
 * same call the circuit's commitment branch emits).  Returns 0 on
 * success, -1 otherwise.
 */
static int
rs_recompute_commitment(const voleith_rs_config_t *cfg, const uint8_t *id,
                        const uint8_t *rand, uint8_t *c_out,
                        size_t *node_bytes_out)
{
    const voleith_node_hash_vt *tree_vt;
    uint8_t idrand[2 * MERKLE_VT_MAX_NODE_BYTES + 64];
    size_t total;
    int rc;

    if (cfg == NULL || id == NULL || rand == NULL || c_out == NULL)
        return -1;
    if (!cfg->enable_commitment)
        return -1;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;

    tree_vt = cfg->membership.tree_hash;
    if (tree_vt->node_bytes > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    total = cfg->commit_id_bytes + cfg->commit_rand_bytes;
    if (total > sizeof(idrand))
        return -1;

    memcpy(idrand, id, cfg->commit_id_bytes);
    memcpy(idrand + cfg->commit_id_bytes, rand, cfg->commit_rand_bytes);

    rc = tree_vt->leaf_hash(idrand, total, c_out);
    voleith_secure_zero(idrand, total);
    if (rc != 0)
        return -1;

    if (node_bytes_out != NULL)
        *node_bytes_out = tree_vt->node_bytes;
    return 0;
}

int
voleith_rs_claim_produce(const voleith_rs_config_t *cfg, const uint8_t *id,
                         const uint8_t *rand, voleith_rs_claim_t *claim_out)
{
    size_t node_bytes = 0;

    if (claim_out == NULL)
        return -1;
    memset(claim_out, 0, sizeof(*claim_out));

    if (rs_recompute_commitment(cfg, id, rand, claim_out->commitment,
                                &node_bytes) != 0) {
        memset(claim_out, 0, sizeof(*claim_out));
        return -1;
    }

    claim_out->id = id;
    claim_out->rand = rand;
    claim_out->commitment_bytes = node_bytes;
    return 0;
}

int
voleith_rs_claim_verify(const voleith_rs_config_t *cfg, const uint8_t *C,
                        const uint8_t *id, const uint8_t *rand)
{
    uint8_t computed[MERKLE_VT_MAX_NODE_BYTES];
    size_t node_bytes = 0;
    int rc;

    if (C == NULL)
        return -1;
    if (rs_recompute_commitment(cfg, id, rand, computed, &node_bytes) != 0)
        return -1;

    rc = voleith_const_memcmp(computed, C, node_bytes) == 0 ? 0 : -1;
    voleith_secure_zero(computed, sizeof(computed));
    return rc;
}
