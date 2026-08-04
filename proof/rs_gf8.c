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
#include "../circuits/rs_opener_gf8_circuit.h"
#include "../core/hash.h"
#include "../core/prg.h" /* V5 opener seal: fresh-e tape expansion */
#include "../core/util.h"
#include "gf8_proof.h"

#include <ichor/sample.h> /* ichor_sample_fixed_weight (opener support draw) */
#include <ichor/util.h>   /* ichor_bitpack_le32 (opener support packing) */

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
    if (cfg->enable_opener)
        bitmap |= VOLEITH_RS_MODULE_OPENER;

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
     * V5 opener.  opener_set selects the Argus (lambda, n0) parameter set;
     * M (opener_pk) must be present with the exact circulant-block length for
     * the set.  The lambda/8-byte id joins the leaf preimage (Q2) and, when V4
     * is also on, is the SAME witness as the commitment id handle
     * (Q8: commit_id_bytes == lambda/8).  When the opener is off the pointer is
     * the "configured" signal (opener_set is a don't-care since the fingerprint
     * absorbs the opener section only when bit 6 is set).
     */
    size_t opener_id_bytes = 0;
    if (cfg->enable_opener) {
        const voleith_rs_opener_argus_params_t *op =
            voleith_rs_opener_argus_params(cfg->opener_set);
        if (op == NULL) /* reserved / unshipped set id */
            return -1;
        if (cfg->opener_pk == NULL)
            return -1;
        if (cfg->opener_pk_bytes != (size_t)(op->n0 - 1u) * op->block_bytes)
            return -1;
        opener_id_bytes = op->key_bytes; /* = lambda/8 */
        if (cfg->enable_commitment && cfg->commit_id_bytes != opener_id_bytes)
            return -1;
    } else {
        if (cfg->opener_pk != NULL || cfg->opener_pk_bytes != 0)
            return -1;
    }

    /*
     * OWF input width bound.  With V6+V3 the preimage is
     * epoch_root || attributes || salt (epoch_root heads it in sk's
     * slot); with V6 and no V3 the leaf IS epoch_root and no OWF runs, so
     * no width check applies; otherwise (V6 off) it is sk || attributes.
     * The V5 opener appends a lambda/8-byte id (Q2), which forces an OWF even
     * in the V6-no-V3 case, so the bound runs whenever the opener is on.
     */
    if (cfg->enable_opener || !(v6_on && cfg->attr_schema == NULL)) {
        size_t head = v6_on ? tree_vt->node_bytes : cfg->membership.sk_bytes;
        size_t salt = v6_on ? cfg->leaf_salt_bytes : 0u;

        if (head > SIZE_MAX - attr_total)
            return -1;
        leaf_preimage = head + attr_total;
        if (leaf_preimage > SIZE_MAX - salt)
            return -1;
        leaf_preimage += salt;
        if (leaf_preimage > SIZE_MAX - opener_id_bytes)
            return -1;
        leaf_preimage += opener_id_bytes;

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

    /* Opener section absorbed last (highest module bit), so every bit-6-off
     * fingerprint is byte-identical to the pre-opener value.  hash_id is the
     * set's prim_default, so absorbing it binds the emitted KDF gadget (Q4). */
    if (bitmap & VOLEITH_RS_MODULE_OPENER) {
        const voleith_rs_opener_argus_params_t *op =
            voleith_rs_opener_argus_params(cfg->opener_set);
        uint8_t mdigest[16];
        uint8_t hash_id;
        voleith_hash_ctx_t mctx;

        if (op == NULL || cfg->opener_pk == NULL) {
            voleith_hash_ctx_clear(&ctx);
            return -1;
        }
        hash_id = op->prim_default;

        voleith_shake256_init(&mctx);
        rc |= voleith_shake256_absorb(&mctx, cfg->opener_pk,
                                      cfg->opener_pk_bytes);
        voleith_shake256_squeeze(&mctx, mdigest, sizeof(mdigest));
        voleith_hash_ctx_clear(&mctx);

        rc |= voleith_shake256_absorb_u32_le(&ctx, (uint32_t)cfg->opener_set);
        rc |= voleith_shake256_absorb(&ctx, mdigest, sizeof(mdigest));
        rc |= voleith_shake256_absorb(&ctx, &hash_id, 1);
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

    /* [V5] opener: resolve params + the id/support inputs.  The id joins the
     * leaf preimage (below) and, when V4 is off, is its own witness section
     * (when V4 is on it already sits at commit_id_off == opener_id_off). */
    int opener_enabled = cfg->enable_opener != 0;
    const voleith_rs_opener_argus_params_t *op = NULL;
    size_t opener_id_bytes = 0;
    if (opener_enabled) {
        op = voleith_rs_opener_argus_params(cfg->opener_set);
        if (op == NULL)
            return -1;
        opener_id_bytes = op->key_bytes;
        if (id == NULL || path->opener_support == NULL)
            return -1;
        if (commit_total == 0)
            memcpy(witness_out + layout->opener_id_off, id, opener_id_bytes);
    }

    /* leaf_node and, when an OWF runs, its leaf inv_in.  Unified tail =
     * attrs || salt || id (salt is V6-only; id is opener-only, Q2), head = sk
     * (non-V6) or epoch_root (V6).  The one no-OWF case is V6 without V3 and
     * without the opener: leaf_node := epoch_root.  Mirrors the builder's
     * leaf stage exactly (rs_gf8_circuit.c). */
    if (epoch_enabled && cfg->attr_schema == NULL && !opener_enabled) {
        memcpy(leaf_node, epoch_root, W);
    } else {
        const uint8_t *head = epoch_enabled ? epoch_root : sk;
        size_t head_bytes = epoch_enabled ? W : mcfg->sk_bytes;
        size_t tail = attr_total + salt_bytes + opener_id_bytes;
        uint8_t *tailbuf = calloc(tail > 0 ? tail : 1, 1);
        size_t off = 0;
        int lrc;

        if (tailbuf == NULL)
            goto out;
        if (attr_total > 0) {
            memcpy(tailbuf + off, attrs, attr_total);
            off += attr_total;
        }
        if (salt_bytes > 0) {
            memcpy(tailbuf + off, path->epoch_salt, salt_bytes);
            off += salt_bytes;
        }
        if (opener_id_bytes > 0) {
            memcpy(tailbuf + off, id, opener_id_bytes);
            off += opener_id_bytes;
        }
        lrc = rs_leaf_gf8_build_witness(owf_vt, head, head_bytes, tailbuf, tail,
                                        witness_out + ml->owf_invin_off);
        if (lrc == 0)
            lrc = rs_leaf_gf8_hash(owf_vt, head, head_bytes, tailbuf, tail,
                                   leaf_node);
        voleith_secure_zero(tailbuf, tail);
        free(tailbuf);
        if (lrc != 0)
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

    /* [V5] opener: bit-pack the support into the support witness (LSB-first at
     * idx_bits, contract A3), then derive the KDF S-box inv_in over those same
     * packed bytes (dispatched on the set's prim_default). */
    if (opener_enabled) {
        uint8_t *support = witness_out + layout->opener_support_off;

        if (ichor_bitpack_le32(support, layout->opener_support_bytes,
                               path->opener_support, op->t, op->idx_bits) != 0)
            goto out;
        if (op->prim_default == VOLEITH_RS_OPENER_ARGUS_PRIM_AESDM)
            voleith_rs_opener_kdf_aesdm_build_witness(
                op->ds_iv, support, op->msg_bytes,
                witness_out + layout->opener_kdf_invin_off);
        else if (op->prim_default == VOLEITH_RS_OPENER_ARGUS_PRIM_GROSTL256)
            voleith_rs_opener_kdf_grostl256_build_witness(
                op->ds_iv, support, op->msg_bytes,
                witness_out + layout->opener_kdf_invin_off);
    }

    rc = 0;
out:
    voleith_secure_zero(leaf_node, sizeof(leaf_node));
    voleith_secure_zero(ht, sizeof(ht));
    voleith_secure_zero(epoch_root, sizeof(epoch_root));
    return rc;
}

/* ================================================================
 * Streaming ring builder (RS.PACK): member_begin / member_set / member_end,
 * enrolling one field at a time.  All leaf material is secret and its byte
 * layout is fixed by cfg (leaf = OWF(sk || attrs || id), salt being V6-only and
 * outside this non-V6 builder); the field selector lets the caller supply the
 * fields in any order while the builder assembles the canonical preimage.  The
 * one-shot voleith_rs_ring_build below is a thin wrapper, byte-identical for the
 * no-id (non-opener) case.
 * ================================================================ */

struct voleith_rs_ring_builder {
    const voleith_node_hash_vt *tree_vt;
    const voleith_node_hash_vt *owf_vt;
    size_t W;
    size_t depth_m;
    size_t capacity;
    size_t sk_bytes;
    size_t attr_total;
    size_t id_bytes; /* opener id width, 0 if opener off */
    int opener_enabled;
    size_t n_members;
    size_t cursor; /* members finalized so far */
    uint8_t *leaf_nodes;
    uint8_t *tailbuf; /* attr_total + id_bytes scratch, reused per member */
    uint8_t *root_out;
    voleith_rs_path_t *paths_out;
    uint8_t *siblings_storage;

    /* per-member staging, valid between member_begin and member_end */
    int in_member;
    const uint8_t *m_sk;
    const uint8_t *m_attrs;
    const uint8_t *m_id;
    int sk_set, attrs_set, id_set;
};

int
voleith_rs_ring_build_init(voleith_rs_ring_builder_t **b_out,
                           const voleith_rs_config_t *cfg, size_t n_members,
                           uint8_t *root_out, voleith_rs_path_t *paths_out,
                           uint8_t *siblings_storage)
{
    const voleith_rs_membership_config_t *mcfg;
    voleith_rs_ring_builder_t *b;
    size_t attr_total = 0, id_bytes = 0, capacity;

    if (b_out == NULL || cfg == NULL || root_out == NULL || paths_out == NULL ||
        siblings_storage == NULL)
        return -1;
    *b_out = NULL;
    if (voleith_rs_config_validate(cfg) != 0)
        return -1;
    if (n_members == 0)
        return -1;

    mcfg = &cfg->membership;
    if (cfg->attr_schema != NULL)
        for (size_t i = 0; i < cfg->attr_schema->n_fields; i++)
            attr_total += cfg->attr_schema->fields[i].width_bytes;

    if (cfg->enable_opener) {
        const voleith_rs_opener_argus_params_t *op =
            voleith_rs_opener_argus_params(cfg->opener_set);

        if (op == NULL)
            return -1;
        id_bytes = op->key_bytes;
    }

    if (mcfg->depth_m >= sizeof(size_t) * 8) {
        capacity = (size_t)-1;
    } else {
        capacity = (size_t)1u << mcfg->depth_m;
        if (n_members > capacity)
            return -1;
    }

    b = calloc(1, sizeof(*b));
    if (b == NULL)
        return -1;
    b->tree_vt = mcfg->tree_hash;
    b->owf_vt = mcfg->owf_hash ? mcfg->owf_hash : mcfg->tree_hash;
    b->W = b->tree_vt->node_bytes;
    b->depth_m = mcfg->depth_m;
    b->capacity = capacity;
    b->sk_bytes = mcfg->sk_bytes;
    b->attr_total = attr_total;
    b->id_bytes = id_bytes;
    b->opener_enabled = cfg->enable_opener != 0;
    b->n_members = n_members;
    b->root_out = root_out;
    b->paths_out = paths_out;
    b->siblings_storage = siblings_storage;

    /* calloc zero-fills vacant slots with the documented sentinel
     * (VOLEITH_RSV1_SENTINEL_LEAF_BYTE == 0x00): an all-zero leaf node
     * cannot collide with a real OWF output. */
    b->leaf_nodes = calloc(capacity, b->W);
    b->tailbuf =
        calloc(attr_total + id_bytes > 0 ? attr_total + id_bytes : 1, 1);
    if (b->leaf_nodes == NULL || b->tailbuf == NULL) {
        voleith_rs_ring_build_free(b);
        return -1;
    }
    *b_out = b;
    return 0;
}

int
voleith_rs_ring_member_begin(voleith_rs_ring_builder_t *b)
{
    if (b == NULL || b->in_member || b->cursor >= b->n_members)
        return -1;
    b->in_member = 1;
    b->sk_set = b->attrs_set = b->id_set = 0;
    b->m_sk = b->m_attrs = b->m_id = NULL;
    return 0;
}

int
voleith_rs_ring_member_set(voleith_rs_ring_builder_t *b,
                           voleith_rs_leaf_field_t field, const uint8_t *data,
                           size_t len)
{
    if (b == NULL || !b->in_member || data == NULL)
        return -1;
    switch (field) {
    case VOLEITH_RS_LEAF_FIELD_SK:
        if (b->sk_bytes == 0 || len != b->sk_bytes)
            return -1;
        b->m_sk = data;
        b->sk_set = 1;
        return 0;
    case VOLEITH_RS_LEAF_FIELD_ATTRS:
        if (b->attr_total == 0 || len != b->attr_total)
            return -1;
        b->m_attrs = data;
        b->attrs_set = 1;
        return 0;
    case VOLEITH_RS_LEAF_FIELD_ID:
        if (!b->opener_enabled || len != b->id_bytes)
            return -1;
        b->m_id = data;
        b->id_set = 1;
        return 0;
    default:
        return -1;
    }
}

int
voleith_rs_ring_member_end(voleith_rs_ring_builder_t *b)
{
    size_t tail = 0, off = 0;
    const uint8_t *tailp;

    if (b == NULL || !b->in_member)
        return -1;
    /* Every cfg-enabled field must be supplied exactly (order-free). */
    if ((b->sk_bytes > 0) != (b->sk_set != 0))
        return -1;
    if ((b->attr_total > 0) != (b->attrs_set != 0))
        return -1;
    if (b->opener_enabled != (b->id_set != 0))
        return -1;

    if (b->attr_total > 0) {
        memcpy(b->tailbuf + off, b->m_attrs, b->attr_total);
        off += b->attr_total;
    }
    if (b->id_bytes > 0) {
        memcpy(b->tailbuf + off, b->m_id, b->id_bytes);
        off += b->id_bytes;
    }
    tail = off;
    tailp = tail > 0 ? b->tailbuf : NULL;

    if (rs_leaf_gf8_hash(b->owf_vt, b->m_sk, b->sk_bytes, tailp, tail,
                         b->leaf_nodes + b->cursor * b->W) != 0)
        return -1;

    b->in_member = 0;
    b->cursor++;
    return 0;
}

int
voleith_rs_ring_build_final(voleith_rs_ring_builder_t *b)
{
    int rc = -1;

    if (b == NULL)
        return -1;
    if (b->in_member || b->cursor != b->n_members)
        goto out;

    if (voleith_merkle_vt_build(b->tree_vt, b->leaf_nodes, b->capacity,
                                b->root_out) != 0)
        goto out;

    for (size_t i = 0; i < b->n_members; i++) {
        uint8_t *sib = b->siblings_storage + i * b->depth_m * b->W;

        if (voleith_merkle_vt_compute_path(b->tree_vt, b->leaf_nodes,
                                           b->capacity, i, sib) != 0)
            goto out;
        b->paths_out[i].membership.leaf_index = i;
        b->paths_out[i].membership.siblings = sib;
    }
    rc = 0;

out:
    voleith_rs_ring_build_free(b);
    return rc;
}

void
voleith_rs_ring_build_free(voleith_rs_ring_builder_t *b)
{
    if (b == NULL)
        return;
    if (b->leaf_nodes != NULL) {
        voleith_secure_zero(b->leaf_nodes, b->capacity * b->W);
        free(b->leaf_nodes);
    }
    if (b->tailbuf != NULL) {
        voleith_secure_zero(b->tailbuf, b->attr_total + b->id_bytes);
        free(b->tailbuf);
    }
    voleith_secure_zero(b, sizeof(*b));
    free(b);
}

int
voleith_rs_ring_build(const voleith_rs_config_t *cfg, const uint8_t *sks,
                      const uint8_t *attrs_or_null, size_t n_members,
                      uint8_t *root_out, voleith_rs_path_t *paths_out,
                      uint8_t *siblings_storage)
{
    voleith_rs_ring_builder_t *b = NULL;
    size_t sk_bytes, attr_total;

    if (cfg == NULL || sks == NULL)
        return -1;
    if (voleith_rs_ring_build_init(&b, cfg, n_members, root_out, paths_out,
                                   siblings_storage) != 0)
        return -1;
    sk_bytes = b->sk_bytes;
    attr_total = b->attr_total;

    /* attrs_or_null must be present iff the schema declares attributes. */
    if ((attr_total > 0) != (attrs_or_null != NULL)) {
        voleith_rs_ring_build_free(b);
        return -1;
    }

    for (size_t i = 0; i < n_members; i++) {
        if (voleith_rs_ring_member_begin(b) != 0)
            goto err;
        if (sk_bytes > 0 &&
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_SK,
                                       sks + i * sk_bytes, sk_bytes) != 0)
            goto err;
        if (attr_total > 0 &&
            voleith_rs_ring_member_set(b, VOLEITH_RS_LEAF_FIELD_ATTRS,
                                       attrs_or_null + i * attr_total,
                                       attr_total) != 0)
            goto err;
        if (voleith_rs_ring_member_end(b) != 0)
            goto err;
    }
    return voleith_rs_ring_build_final(b); /* consumes b */

err:
    voleith_rs_ring_build_free(b);
    return -1;
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
    const voleith_rs_opener_argus_params_t *op = NULL;
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
    if (bitmap & VOLEITH_RS_MODULE_OPENER)
        op = voleith_rs_opener_argus_params(cfg->opener_set);

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
    if (bitmap & VOLEITH_RS_MODULE_OPENER) {
        if (op == NULL || pub->opener_s == NULL || pub->opener_tag_ct == NULL)
            return -1;
    }
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

    /* [V5] opener section: public syndrome s || DEM tag_ct, gated by bit 6,
     * after the epoch section and before m_len || m.  The opener key identity
     * (opener_set || SHAKE256(M)[0:16] || hash_id) already rides the cfg
     * fingerprint absorbed above (fp).  Binding s || tag_ct here makes the
     * per-signature VOLE seed (root_seed || iv = H_3(header || fs_seed),
     * derived before the instance is absorbed) fresh whenever the opener error
     * e is fresh, so two signatures over the same statement never reuse the
     * same VOLE tape under different witnesses. */
    if (bitmap & VOLEITH_RS_MODULE_OPENER) {
        rc |= voleith_shake256_absorb(&ctx, pub->opener_s, op->block_bytes);
        rc |= voleith_shake256_absorb(&ctx, pub->opener_tag_ct, op->key_bytes);
    }

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
    /* [V5] opener: expand the packed syndrome s to p bit wires (LSB-first,
     * s_j at bit j), and copy the DEM tag_ct. */
    if (layout->inst_opener_s_bytes > 0) {
        if (pub->opener_s == NULL || pub->opener_tag_ct == NULL)
            return -1;
        for (size_t j = 0; j < layout->inst_opener_s_bytes; j++)
            instance[layout->inst_opener_s_off + j] =
                (uint8_t)((pub->opener_s[j >> 3] >> (j & 7u)) & 1u);
        memcpy(instance + layout->inst_opener_tag_ct_off, pub->opener_tag_ct,
               layout->inst_opener_tag_ct_bytes);
    }
    return 0;
}

int
voleith_rs_pack_instance(const voleith_rs_config_t *cfg,
                         const voleith_rs_layout_t *layout,
                         const voleith_rs_public_t *pub, uint8_t *instance_out)
{
    if (cfg == NULL || layout == NULL || pub == NULL || instance_out == NULL)
        return -1;
    if (pub->membership_root == NULL)
        return -1;
    memset(instance_out, 0, layout->instance_bytes);
    return rs_fill_instance(layout, pub, instance_out);
}

/* Domain-separating IV for the V5 opener seal's PRG expansion.  Distinct from
 * the GGM vector-commitment PRG (vc.c) and the V6 epoch schedule so the same
 * caller seed never collides across uses.  14 visible bytes + two NUL pad. */
static const uint8_t rs_opener_seal_prg_iv[16] = "VOLEitH-RSv5-e\x00\x00";

int
voleith_rs_opener_seal(const voleith_rs_config_t *cfg,
                       const uint8_t *randomness, size_t randomness_len,
                       const uint8_t *id, size_t id_len, uint32_t *support_out,
                       uint8_t *s_out, uint8_t *tag_ct_out)
{
    const voleith_rs_opener_argus_params_t *op;
    voleith_prg_ctx_t prg;
    uint8_t *tape = NULL;
    uint8_t K[32];
    uint8_t pad[32];
    size_t tape_len, i;
    int lambda, rc = -1;

    if (cfg == NULL || randomness == NULL || id == NULL ||
        support_out == NULL || s_out == NULL || tag_ct_out == NULL)
        return -1;
    if (!cfg->enable_opener || cfg->opener_pk == NULL)
        return -1;

    op = voleith_rs_opener_argus_params(cfg->opener_set);
    if (op == NULL)
        return -1;
    lambda = (int)op->lambda;
    /* Seal id width is fixed to the DEM key width (the ring-opener leaf id, no
     * CTR): matches pub->opener_tag_ct and the in-circuit DEM gadget. */
    if (id_len != op->key_bytes || op->key_bytes > sizeof(K))
        return -1;
    if (randomness_len != (size_t)(lambda / 8))
        return -1;
    if (cfg->opener_pk_bytes != (size_t)(op->n0 - 1u) * op->block_bytes)
        return -1;

    tape_len = ichor_sample_fixed_weight_tape_bytes(lambda, op->t);
    if (tape_len == 0)
        return -1;
    tape = calloc(tape_len, 1);
    if (tape == NULL)
        return -1;

    /* Fresh error support: expand the caller randomness to the sampler tape
     * under the V5 domain IV, then draw t distinct ascending indices in [0,n). */
    if (voleith_prg_init(&prg, randomness, lambda) != 0)
        goto out;
    voleith_prg_gen(&prg, tape, rs_opener_seal_prg_iv, 0, tape_len * 8u);
    voleith_prg_clear(&prg);

    if (ichor_sample_fixed_weight(support_out, op->t, op->n, lambda, tape,
                                  tape_len) != 0)
        goto out;

    /*
     * Canonicalize the support to ascending: the KDF hashes the sparse index
     * list AS AN ORDERED LIST (H(support(e))), so K matches syndrome's decap
     * only if both hash byte-identical sparse bytes.  syndrome's decap rebuilds
     * the list ascending from the recovered dense error, so the seal conforms.
     * The syndrome multiply below scatters and is order-independent; the
     * distinctness gadget consumes this same ascending witness.
     */
    ichor_sample_sort_ascending(support_out, op->t);

    /* Public syndrome s = M*e^T. */
    if (voleith_rs_opener_argus_syndrome(op, s_out, cfg->opener_pk,
                                         support_out) != VOLEITH_RS_OPENER_OK)
        goto out;

    /* DEM: tag_ct = id XOR pad(K), K = KDF(support) under the set's default
     * primitive (id_len == key_bytes, so pad is K truncated, no CTR). */
    if (voleith_rs_opener_argus_kdf(op, K, op->prim_default, support_out) !=
        VOLEITH_RS_OPENER_OK)
        goto out;
    if (voleith_rs_opener_argus_dem_pad(op, pad, id_len, K) !=
        VOLEITH_RS_OPENER_OK)
        goto out;
    for (i = 0; i < id_len; i++)
        tag_ct_out[i] = (uint8_t)(id[i] ^ pad[i]);

    rc = 0;

out:
    if (tape != NULL) {
        voleith_secure_zero(tape, tape_len);
        free(tape);
    }
    voleith_secure_zero(K, sizeof(K));
    voleith_secure_zero(pad, sizeof(pad));
    voleith_secure_zero(&prg, sizeof(prg));
    return rc;
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

/* Reject a non-canonical packed syndrome s: the top (block_bytes*8 - p) pad
 * bits of the last byte MUST be zero (contract A0 canonical packing), mirroring
 * Argus's EMALFORMED check.  s is block_bytes = ceil(p/8) bytes, LSB-first. */
static int
opener_s_canonical(const voleith_rs_opener_argus_params_t *op, const uint8_t *s)
{
    unsigned rem = (unsigned)(op->p & 7u); /* valid bits in the top byte */

    if (rem == 0)
        return 1; /* p a multiple of 8: no pad bits */
    return (s[op->block_bytes - 1] & (uint8_t) ~((1u << rem) - 1u)) == 0;
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

    /* [V5] boundary validation: reject a non-canonical public syndrome s before
     * touching the proof, mirroring Argus's malformed-ciphertext rejection. */
    if (cfg->enable_opener) {
        const voleith_rs_opener_argus_params_t *op =
            voleith_rs_opener_argus_params(cfg->opener_set);

        if (op == NULL || pub->opener_s == NULL)
            return -1;
        if (!opener_s_canonical(op, pub->opener_s))
            return -1;
    }

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

/* ---- streaming builder / reader (RS.SER, OP.SER) ---- */

struct rs_sig_frag {
    const uint8_t *p;
    size_t len;
};

struct rs_sig_section {
    uint8_t tag;
    uint8_t
        inline_byte; /* stable storage for a 1-byte fragment (e.g. hash_id) */
    unsigned nfrag;
    struct rs_sig_frag frag[VOLEITH_RS_SIG_MAX_FRAGS];
};

struct voleith_rs_sig_packer {
    const voleith_rs_config_t *cfg; /* for opener param derivation */
    voleith_rs_sig_format_t format;
    uint8_t cfg_fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    unsigned n_sections;
    struct rs_sig_section sec[VOLEITH_RS_SIG_MAX_SECTIONS];
};

struct voleith_rs_sig_unpacker {
    const uint8_t *buf;
    size_t len;
    uint8_t version;
    unsigned n_sections;
    struct {
        uint8_t tag;
        const uint8_t *payload;
        size_t len;
    } sec[VOLEITH_RS_SIG_MAX_SECTIONS];
};

static size_t
rs_section_payload_len(const struct rs_sig_section *s)
{
    size_t t = 0;
    unsigned i;

    for (i = 0; i < s->nfrag; i++)
        t += s->frag[i].len;
    return t;
}

/* Append a fresh section with a unique tag; NULL if full or duplicate. */
static struct rs_sig_section *
rs_packer_new_section(voleith_rs_sig_packer_t *b, uint8_t tag)
{
    struct rs_sig_section *s;
    unsigned i;

    if (b->n_sections >= VOLEITH_RS_SIG_MAX_SECTIONS)
        return NULL;
    for (i = 0; i < b->n_sections; i++)
        if (b->sec[i].tag == tag)
            return NULL;
    s = &b->sec[b->n_sections++];
    s->tag = tag;
    s->inline_byte = 0;
    s->nfrag = 0;
    return s;
}

static int
rs_section_add_frag(struct rs_sig_section *s, const uint8_t *p, size_t len)
{
    if (len == 0)
        return 0; /* empty fragment contributes nothing */
    if (s->nfrag >= VOLEITH_RS_SIG_MAX_FRAGS)
        return -1;
    s->frag[s->nfrag].p = p;
    s->frag[s->nfrag].len = len;
    s->nfrag++;
    return 0;
}

/*
 * Resolve the effective format and total serialized length for the sections
 * added so far.  Returns -1 (and leaves outputs untouched) if the section set
 * is invalid: no PROOF section, a non-proof section under v1, or a payload that
 * would overflow the be32 length field.
 */
static int
rs_packer_resolve(const voleith_rs_sig_packer_t *b,
                  voleith_rs_sig_format_t *fmt_out, size_t *len_out)
{
    voleith_rs_sig_format_t fmt = b->format;
    int have_proof = 0, have_nonproof = 0;
    size_t total, proof_payload = 0, i;

    for (i = 0; i < b->n_sections; i++) {
        size_t plen = rs_section_payload_len(&b->sec[i]);

        if (plen > UINT32_MAX)
            return -1;
        if (b->sec[i].tag == VOLEITH_RS_SIG_SECTION_PROOF) {
            have_proof = 1;
            proof_payload = plen;
        } else {
            have_nonproof = 1;
        }
    }
    if (!have_proof)
        return -1;

    if (fmt == VOLEITH_RS_SIG_FORMAT_AUTO)
        fmt =
            have_nonproof ? VOLEITH_RS_SIG_FORMAT_V2 : VOLEITH_RS_SIG_FORMAT_V1;
    if (fmt == VOLEITH_RS_SIG_FORMAT_V1 && have_nonproof)
        return -1;

    if (fmt == VOLEITH_RS_SIG_FORMAT_V1) {
        total = VOLEITH_RS_SIG_HEADER_BYTES + proof_payload;
    } else {
        total = VOLEITH_RS_SIG_V2_HEADER_BYTES;
        for (i = 0; i < b->n_sections; i++)
            total += VOLEITH_RS_SIG_SECTION_OVERHEAD +
                     rs_section_payload_len(&b->sec[i]);
    }
    *fmt_out = fmt;
    *len_out = total;
    return 0;
}

int
voleith_rs_sig_pack_init(voleith_rs_sig_packer_t **b_out,
                         const voleith_rs_config_t *cfg,
                         const voleith_params_t *params,
                         voleith_rs_sig_format_t format)
{
    voleith_rs_sig_packer_t *b;

    if (b_out == NULL)
        return -1;
    *b_out = NULL;
    if (cfg == NULL || params == NULL)
        return -1;
    if (format != VOLEITH_RS_SIG_FORMAT_AUTO &&
        format != VOLEITH_RS_SIG_FORMAT_V1 &&
        format != VOLEITH_RS_SIG_FORMAT_V2)
        return -1;

    b = calloc(1, sizeof(*b));
    if (b == NULL)
        return -1;
    if (voleith_rs_config_fingerprint(cfg, b->cfg_fp) != 0 ||
        voleith_params_fingerprint(params, b->params_fp) != 0) {
        free(b);
        return -1;
    }
    b->cfg = cfg;
    b->format = format;
    b->n_sections = 0;
    *b_out = b;
    return 0;
}

int
voleith_rs_sig_pack_proof(voleith_rs_sig_packer_t *b,
                          const voleith_rs_sig_t *sig)
{
    struct rs_sig_section *s;

    if (b == NULL || sig == NULL)
        return -1;
    if ((sig->data == NULL) != (sig->len == 0))
        return -1;
    if (sig->len > UINT32_MAX)
        return -1;

    s = rs_packer_new_section(b, VOLEITH_RS_SIG_SECTION_PROOF);
    if (s == NULL)
        return -1;
    return rs_section_add_frag(s, sig->data, sig->len);
}

int
voleith_rs_sig_pack_opener(voleith_rs_sig_packer_t *b,
                           const voleith_rs_public_t *pub)
{
    const voleith_rs_opener_argus_params_t *op;
    struct rs_sig_section *s;

    if (b == NULL || pub == NULL)
        return -1;
    if (b->cfg == NULL || !b->cfg->enable_opener)
        return -1;
    if (pub->opener_s == NULL || pub->opener_tag_ct == NULL)
        return -1;
    op = voleith_rs_opener_argus_params(b->cfg->opener_set);
    if (op == NULL)
        return -1;

    s = rs_packer_new_section(b, VOLEITH_RS_SIG_SECTION_OPENER);
    if (s == NULL)
        return -1;
    s->inline_byte = op->prim_default; /* hash_id */
    if (rs_section_add_frag(s, &s->inline_byte, 1) != 0 ||
        rs_section_add_frag(s, pub->opener_s, op->block_bytes) != 0 ||
        rs_section_add_frag(s, pub->opener_tag_ct, op->key_bytes) != 0)
        return -1;
    return 0;
}

int
voleith_rs_sig_pack_section(voleith_rs_sig_packer_t *b, uint8_t tag,
                            const uint8_t *payload, size_t len)
{
    struct rs_sig_section *s;

    if (b == NULL)
        return -1;
    if (payload == NULL && len != 0)
        return -1;
    if (len > UINT32_MAX)
        return -1;
    if (tag == VOLEITH_RS_SIG_SECTION_PROOF ||
        tag == VOLEITH_RS_SIG_SECTION_OPENER)
        return -1; /* reserved for the typed helpers */

    s = rs_packer_new_section(b, tag);
    if (s == NULL)
        return -1;
    return rs_section_add_frag(s, payload, len);
}

size_t
voleith_rs_sig_pack_len(const voleith_rs_sig_packer_t *b)
{
    voleith_rs_sig_format_t fmt;
    size_t len;

    if (b == NULL)
        return 0;
    if (rs_packer_resolve(b, &fmt, &len) != 0)
        return 0;
    return len;
}

int
voleith_rs_sig_pack_final(voleith_rs_sig_packer_t *b, uint8_t *out_buf,
                          size_t out_len, size_t *written_out)
{
    voleith_rs_sig_format_t fmt;
    size_t need, off, i, j;
    int rc = -1;

    if (b == NULL)
        return -1;
    if (out_buf == NULL)
        goto out;
    if (rs_packer_resolve(b, &fmt, &need) != 0)
        goto out;
    if (out_len != need)
        goto out;

    off = 0;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_0;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_1;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_2;
    out_buf[off++] = VOLEITH_RS_SIG_MAGIC_3;
    out_buf[off++] = (uint8_t)fmt;
    memcpy(out_buf + off, b->cfg_fp, sizeof(b->cfg_fp));
    off += sizeof(b->cfg_fp);
    memcpy(out_buf + off, b->params_fp, sizeof(b->params_fp));
    off += sizeof(b->params_fp);

    if (fmt == VOLEITH_RS_SIG_FORMAT_V1) {
        /* Legacy bare framing: only the proof section is present. */
        for (i = 0; i < b->n_sections; i++) {
            const struct rs_sig_section *s = &b->sec[i];

            if (s->tag != VOLEITH_RS_SIG_SECTION_PROOF)
                continue;
            rs_write_u32_be(out_buf + off, (uint32_t)rs_section_payload_len(s));
            off += 4;
            for (j = 0; j < s->nfrag; j++) {
                memcpy(out_buf + off, s->frag[j].p, s->frag[j].len);
                off += s->frag[j].len;
            }
        }
    } else {
        for (i = 0; i < b->n_sections; i++) {
            const struct rs_sig_section *s = &b->sec[i];

            out_buf[off++] = s->tag;
            rs_write_u32_be(out_buf + off, (uint32_t)rs_section_payload_len(s));
            off += 4;
            for (j = 0; j < s->nfrag; j++) {
                memcpy(out_buf + off, s->frag[j].p, s->frag[j].len);
                off += s->frag[j].len;
            }
        }
    }

    if (written_out != NULL)
        *written_out = off;
    rc = 0;

out:
    free(b);
    return rc;
}

void
voleith_rs_sig_pack_free(voleith_rs_sig_packer_t *b)
{
    free(b);
}

int
voleith_rs_sig_unpack_init(voleith_rs_sig_unpacker_t **u_out,
                           const uint8_t *buf, size_t buf_len,
                           const voleith_rs_config_t *cfg,
                           const voleith_params_t *params)
{
    uint8_t expected_cfg_fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    voleith_rs_sig_unpacker_t *u;
    uint8_t ver;
    size_t off;

    if (u_out == NULL)
        return -1;
    *u_out = NULL;
    if (buf == NULL || cfg == NULL || params == NULL)
        return -1;
    if (buf_len < VOLEITH_RS_SIG_V2_HEADER_BYTES)
        return -1;
    if (buf[0] != VOLEITH_RS_SIG_MAGIC_0 || buf[1] != VOLEITH_RS_SIG_MAGIC_1 ||
        buf[2] != VOLEITH_RS_SIG_MAGIC_2 || buf[3] != VOLEITH_RS_SIG_MAGIC_3)
        return -1;
    ver = buf[4];
    if (ver != (uint8_t)VOLEITH_RS_SIG_FORMAT_VERSION &&
        ver != (uint8_t)VOLEITH_RS_SIG_FORMAT_VERSION_V2)
        return -1;
    if (voleith_rs_config_fingerprint(cfg, expected_cfg_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, expected_params_fp) != 0)
        return -1;
    if (voleith_const_memcmp(buf + 5, expected_cfg_fp,
                             sizeof(expected_cfg_fp)) != 0)
        return -1;
    if (voleith_const_memcmp(buf + 5 + sizeof(expected_cfg_fp),
                             expected_params_fp,
                             sizeof(expected_params_fp)) != 0)
        return -1;

    u = calloc(1, sizeof(*u));
    if (u == NULL)
        return -1;
    u->buf = buf;
    u->len = buf_len;
    u->version = ver;
    u->n_sections = 0;

    off = VOLEITH_RS_SIG_V2_HEADER_BYTES;
    if (ver == (uint8_t)VOLEITH_RS_SIG_FORMAT_VERSION) {
        uint32_t proof_len;

        if (buf_len < VOLEITH_RS_SIG_HEADER_BYTES)
            goto fail;
        proof_len = rs_read_u32_be(buf + off);
        off += 4;
        if (buf_len != (size_t)VOLEITH_RS_SIG_HEADER_BYTES + proof_len)
            goto fail;
        u->sec[0].tag = VOLEITH_RS_SIG_SECTION_PROOF;
        u->sec[0].payload = buf + off;
        u->sec[0].len = proof_len;
        u->n_sections = 1;
    } else {
        int have_proof = 0;

        while (off < buf_len) {
            uint8_t tag;
            uint32_t slen;
            unsigned k;

            if (buf_len - off < VOLEITH_RS_SIG_SECTION_OVERHEAD)
                goto fail; /* truncated section header */
            tag = buf[off];
            slen = rs_read_u32_be(buf + off + 1);
            off += VOLEITH_RS_SIG_SECTION_OVERHEAD;
            if (slen > buf_len - off)
                goto fail; /* truncated payload */
            if (u->n_sections >= VOLEITH_RS_SIG_MAX_SECTIONS)
                goto fail;
            for (k = 0; k < u->n_sections; k++)
                if (u->sec[k].tag == tag)
                    goto fail; /* duplicate */
            u->sec[u->n_sections].tag = tag;
            u->sec[u->n_sections].payload = buf + off;
            u->sec[u->n_sections].len = slen;
            u->n_sections++;
            off += slen;
            if (tag == VOLEITH_RS_SIG_SECTION_PROOF)
                have_proof = 1;
        }
        if (!have_proof)
            goto fail; /* proof is mandatory */
    }

    *u_out = u;
    return 0;

fail:
    free(u);
    return -1;
}

static int
rs_unpacker_find(const voleith_rs_sig_unpacker_t *u, uint8_t tag,
                 const uint8_t **payload_out, size_t *len_out)
{
    unsigned i;

    for (i = 0; i < u->n_sections; i++)
        if (u->sec[i].tag == tag) {
            *payload_out = u->sec[i].payload;
            *len_out = u->sec[i].len;
            return 0;
        }
    return -1;
}

int
voleith_rs_sig_unpack_proof(voleith_rs_sig_unpacker_t *u,
                            voleith_rs_sig_t *sig_out)
{
    const uint8_t *payload;
    size_t plen;

    if (u == NULL || sig_out == NULL)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;
    if (rs_unpacker_find(u, VOLEITH_RS_SIG_SECTION_PROOF, &payload, &plen) != 0)
        return -1;
    if (plen == 0)
        return 0;
    sig_out->data = malloc(plen);
    if (sig_out->data == NULL)
        return -1;
    memcpy(sig_out->data, payload, plen);
    sig_out->len = plen;
    return 0;
}

int
voleith_rs_sig_unpack_opener(voleith_rs_sig_unpacker_t *u,
                             const uint8_t **tag_out, size_t *tag_len_out)
{
    if (u == NULL || tag_out == NULL || tag_len_out == NULL)
        return -1;
    return rs_unpacker_find(u, VOLEITH_RS_SIG_SECTION_OPENER, tag_out,
                            tag_len_out);
}

int
voleith_rs_sig_unpack_section(voleith_rs_sig_unpacker_t *u, uint8_t tag,
                              const uint8_t **payload_out, size_t *len_out)
{
    if (u == NULL || payload_out == NULL || len_out == NULL)
        return -1;
    return rs_unpacker_find(u, tag, payload_out, len_out);
}

void
voleith_rs_sig_unpack_free(voleith_rs_sig_unpacker_t *u)
{
    free(u);
}

int
voleith_rs_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                    const voleith_rs_sig_t *sig, const voleith_rs_config_t *cfg,
                    const voleith_params_t *params)
{
    voleith_rs_sig_packer_t *b = NULL;
    int rc;

    if (voleith_rs_sig_pack_init(&b, cfg, params, VOLEITH_RS_SIG_FORMAT_V1) !=
        0)
        return -1;
    rc = voleith_rs_sig_pack_proof(b, sig);
    if (rc != 0) {
        voleith_rs_sig_pack_free(b);
        return -1;
    }
    return voleith_rs_sig_pack_final(b, out_buf, out_len, written_out);
}

int
voleith_rs_sig_unpack(voleith_rs_sig_t *sig_out, const uint8_t *buf,
                      size_t buf_len, const voleith_rs_config_t *cfg,
                      const voleith_params_t *params)
{
    voleith_rs_sig_unpacker_t *u = NULL;
    int rc;

    if (sig_out == NULL)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;
    if (voleith_rs_sig_unpack_init(&u, buf, buf_len, cfg, params) != 0)
        return -1;
    rc = voleith_rs_sig_unpack_proof(u, sig_out);
    voleith_rs_sig_unpack_free(u);
    return rc;
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
