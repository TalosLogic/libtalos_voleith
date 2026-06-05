/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * ring_sig_v1_gf8.c - RSv1 data layer implementation.
 *
 * Two layers (matching the header split):
 *   1. voleith_rs_membership_* - reusable membership cfg validate,
 *      canonical-encoding absorber, witness packer.
 *   2. voleith_rsv1_* - V1-specific helpers (the cfg fingerprint
 *      today; T6 adds sign/verify).
 *
 * See ring_sig_v1_gf8.h for the API contract and docs/RSV1_DESIGN.md
 * §3, §5 for the protocol rationale.
 */

#include "ring_sig_v1_gf8.h"

#include "../circuits/merkle_vt_gf8_helpers.h"
#include "../core/hash.h"
#include "../core/util.h"
#include "gf8_proof.h"
#include "params_fingerprint.h"
#include "ring_sig_v1_gf8_circuit.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Membership layer.
 * ================================================================ */

int
voleith_rs_membership_validate(const voleith_rs_membership_config_t *cfg)
{
    const voleith_node_hash_vt *owf_vt;

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

/* ================================================================
 * V1-specific helpers.
 * ================================================================ */

int
voleith_rsv1_config_fingerprint(
    const voleith_rs_membership_config_t *cfg,
    uint8_t out[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES])
{
    voleith_hash_ctx_t ctx;
    static const uint8_t domain_tag[] =
        VOLEITH_RSV1_CONFIG_FINGERPRINT_DOMAIN_TAG "\x00";
    const voleith_node_hash_vt *owf_vt;

    if (cfg == NULL || out == NULL)
        return -1;
    if (cfg->tree_hash == NULL)
        return -1;

    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    if (cfg->tree_hash->name == NULL || owf_vt->name == NULL)
        return -1;

    voleith_shake256_init(&ctx);

    /* Subtract 1 to drop the compiler's implicit '\0' on the string
     * literal; only the explicit 0x00 we appended belongs in the
     * absorbed bytes.  Same idiom as params_fingerprint.c. */
    voleith_shake256_absorb(&ctx, domain_tag, sizeof(domain_tag) - 1);

    voleith_rs_membership_absorb_canonical(&ctx, cfg);

    voleith_shake256_squeeze(&ctx, out, VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES);
    voleith_hash_ctx_clear(&ctx);

    return 0;
}

int
voleith_rsv1_ring_build(const voleith_rs_membership_config_t *cfg,
                        const uint8_t *sks, size_t n_members, uint8_t *root_out,
                        voleith_rs_membership_path_t *paths_out,
                        uint8_t *siblings_storage)
{
    const voleith_node_hash_vt *tree_vt;
    const voleith_node_hash_vt *owf_vt;
    size_t W;
    size_t depth_m;
    size_t capacity;
    uint8_t *leaf_nodes;

    if (cfg == NULL || sks == NULL || root_out == NULL || paths_out == NULL)
        return -1;
    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;
    if (n_members == 0)
        return -1;

    depth_m = cfg->depth_m;
    /*
     * validate already bounds depth_m to [1, VOLEITH_RS_MEMBERSHIP_MAX_DEPTH]
     * (= 64); guard the shift against the size_t bit width for hosts where
     * size_t is narrower, then bound n_members by ring capacity.
     */
    if (depth_m >= sizeof(size_t) * 8u) {
        capacity = (size_t)-1;
    } else {
        capacity = (size_t)1u << depth_m;
        if (n_members > capacity)
            return -1;
    }

    tree_vt = cfg->tree_hash;
    owf_vt = cfg->owf_hash ? cfg->owf_hash : cfg->tree_hash;
    W = tree_vt->node_bytes;

    /*
     * siblings_storage is only consumed when depth_m > 0; validate
     * guarantees that, so NULL siblings_storage is always an error
     * when n_members > 0.
     */
    if (siblings_storage == NULL)
        return -1;

    /*
     * calloc zero-fills, which is exactly the sentinel pattern (see
     * VOLEITH_RSV1_SENTINEL_LEAF_BYTE) for unfilled slots; the per-member
     * loop below overwrites the first n_members slots in place.
     */
    leaf_nodes = calloc(capacity, W);
    if (leaf_nodes == NULL)
        return -1;

    for (size_t i = 0; i < n_members; i++) {
        if (owf_vt->leaf_hash(sks + i * cfg->sk_bytes, cfg->sk_bytes,
                              leaf_nodes + i * W) != 0)
            goto fail;
    }

    if (voleith_merkle_vt_build(tree_vt, leaf_nodes, capacity, root_out) != 0)
        goto fail;

    for (size_t i = 0; i < n_members; i++) {
        uint8_t *sib_buf = siblings_storage + i * depth_m * W;
        if (voleith_merkle_vt_compute_path(tree_vt, leaf_nodes, capacity, i,
                                           sib_buf) != 0)
            goto fail;
        paths_out[i].leaf_index = i;
        paths_out[i].siblings = sib_buf;
    }

    voleith_secure_zero(leaf_nodes, capacity * W);
    free(leaf_nodes);
    return 0;

fail:
    voleith_secure_zero(leaf_nodes, capacity * W);
    free(leaf_nodes);
    return -1;
}

/* ================================================================
 * T6: fs_seed construction, sign, verify.
 * ================================================================ */

const uint8_t voleith_rsv1_domain_tag[VOLEITH_RSV1_DOMAIN_TAG_BYTES] =
    "VOLEitH-RSv1"; /* 12 visible bytes + 4 zero pad (zero-init by C). */

int
voleith_rsv1_compute_fs_seed(const voleith_rs_membership_config_t *cfg,
                             const uint8_t *membership_root,
                             const uint8_t *revocation_root_or_null,
                             const uint8_t *m, size_t m_len,
                             uint8_t out[VOLEITH_RSV1_FS_SEED_BYTES])
{
    voleith_hash_ctx_t ctx;
    uint8_t fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t zero_node[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t m_len_be[8];
    uint8_t version = VOLEITH_RSV1_FS_SEED_FMT_VERSION;
    size_t W;

    if (cfg == NULL || membership_root == NULL || out == NULL)
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;
    W = cfg->tree_hash->node_bytes;
    if (W > MERKLE_VT_MAX_NODE_BYTES)
        return -1;

    if (voleith_rsv1_config_fingerprint(cfg, fp) != 0)
        return -1;

    for (size_t i = 0; i < 8; i++)
        m_len_be[i] = (uint8_t)(((uint64_t)m_len >> (56 - 8 * i)) & 0xffu);

    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, &version, 1);
    voleith_shake256_absorb(&ctx, voleith_rsv1_domain_tag,
                            VOLEITH_RSV1_DOMAIN_TAG_BYTES);
    voleith_shake256_absorb(&ctx, fp, sizeof(fp));
    voleith_shake256_absorb(&ctx, membership_root, W);
    if (revocation_root_or_null != NULL) {
        voleith_shake256_absorb(&ctx, revocation_root_or_null, W);
    } else {
        memset(zero_node, 0, W);
        voleith_shake256_absorb(&ctx, zero_node, W);
    }
    voleith_shake256_absorb(&ctx, m_len_be, sizeof(m_len_be));
    if (m_len != 0)
        voleith_shake256_absorb(&ctx, m, m_len);

    voleith_shake256_squeeze(&ctx, out, VOLEITH_RSV1_FS_SEED_BYTES);
    voleith_hash_ctx_clear(&ctx);
    voleith_secure_zero(fp, sizeof(fp));
    voleith_secure_zero(zero_node, sizeof(zero_node));
    return 0;
}

void
voleith_ring_sig_free(voleith_ring_sig_t *sig)
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

int
voleith_rsv1_sign(voleith_ring_sig_t *sig_out,
                  const voleith_rs_membership_config_t *cfg,
                  const voleith_params_t *params, const uint8_t *sk,
                  const uint8_t *membership_root,
                  const voleith_rs_membership_path_t *membership,
                  const uint8_t *revocation_root,
                  const voleith_rs_membership_path_t *revocation,
                  const uint8_t *m, size_t m_len)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *witness = NULL;
    uint8_t *instance = NULL;
    uint8_t fs_seed[VOLEITH_RSV1_FS_SEED_BYTES];
    voleith_proof_t proof = {NULL, 0};
    int rc = -1;

    if (sig_out == NULL || cfg == NULL || params == NULL || sk == NULL ||
        membership_root == NULL || membership == NULL ||
        membership->siblings == NULL)
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;

    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;
    /* Revocation args required iff depth_r > 0, forbidden otherwise. */
    if (cfg->depth_r == 0) {
        if (revocation_root != NULL || revocation != NULL)
            return -1;
    } else {
        if (revocation_root == NULL || revocation == NULL ||
            revocation->rev_siblings == NULL ||
            revocation->rev_low_value == NULL ||
            revocation->rev_low_next == NULL ||
            revocation->rev_next_index == NULL)
            return -1;
    }

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        return -1;
    if (voleith_rs_membership_build_circuit(circuit, cfg, &layout) != 0)
        goto out;

    witness = calloc(layout.witness_bytes ? layout.witness_bytes : 1, 1);
    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (witness == NULL || instance == NULL)
        goto out;

    if (voleith_rs_membership_pack_witness(cfg, &layout, sk, membership,
                                           revocation, witness) != 0)
        goto out;
    memcpy(instance + layout.inst_root_off, membership_root,
           layout.inst_root_bytes);
    if (cfg->depth_r > 0)
        memcpy(instance + layout.inst_rev_root_off, revocation_root,
               layout.inst_rev_root_bytes);

    if (voleith_rsv1_compute_fs_seed(cfg, membership_root, revocation_root, m,
                                     m_len, fs_seed) != 0)
        goto out;

    /*
     * voleith_gf8_prove_v2 runs circuit_eval on (witness, instance)
     * before generating the proof.  If (sk, path) does not walk to
     * membership_root, the assert_equal_root constraints fail, eval
     * returns 0, and prove returns -1.  That is the X-10 catches-wrong-
     * sk / wrong-sibling guarantee at the sign boundary.
     */
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
voleith_rsv1_verify(const voleith_ring_sig_t *sig,
                    const voleith_rs_membership_config_t *cfg,
                    const voleith_params_t *params,
                    const uint8_t *membership_root,
                    const uint8_t *revocation_root_or_null, const uint8_t *m,
                    size_t m_len)
{
    voleith_gf8_circuit_t *circuit = NULL;
    voleith_rs_membership_layout_t layout;
    uint8_t *instance = NULL;
    uint8_t fs_seed[VOLEITH_RSV1_FS_SEED_BYTES];
    voleith_proof_t proof_view;
    int rc = -1;

    if (sig == NULL || sig->data == NULL || cfg == NULL || params == NULL ||
        membership_root == NULL)
        return -1;
    if (m == NULL && m_len != 0)
        return -1;
    if (voleith_rs_membership_validate(cfg) != 0)
        return -1;
    if (cfg->depth_r == 0) {
        if (revocation_root_or_null != NULL)
            return -1;
    } else {
        if (revocation_root_or_null == NULL)
            return -1;
    }

    circuit = voleith_gf8_circuit_new();
    if (circuit == NULL)
        return -1;
    if (voleith_rs_membership_build_circuit(circuit, cfg, &layout) != 0)
        goto out;

    instance = calloc(layout.instance_bytes ? layout.instance_bytes : 1, 1);
    if (instance == NULL)
        goto out;
    memcpy(instance + layout.inst_root_off, membership_root,
           layout.inst_root_bytes);
    if (cfg->depth_r > 0)
        memcpy(instance + layout.inst_rev_root_off, revocation_root_or_null,
               layout.inst_rev_root_bytes);

    if (voleith_rsv1_compute_fs_seed(cfg, membership_root,
                                     revocation_root_or_null, m, m_len,
                                     fs_seed) != 0)
        goto out;

    proof_view.data = sig->data;
    proof_view.len = sig->len;
    if (voleith_gf8_verify_v2(&proof_view, params, circuit, instance,
                              layout.instance_bytes, fs_seed,
                              sizeof(fs_seed)) != 0)
        goto out;

    rc = 0;

out:
    free(instance);
    voleith_secure_zero(fs_seed, sizeof(fs_seed));
    voleith_gf8_circuit_free(circuit);
    return rc;
}

/* ================================================================
 * T7: voleith_ring_sig_t serialization.
 * ================================================================ */

static void
ring_sig_write_u32_be(uint8_t out[4], uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static uint32_t
ring_sig_read_u32_be(const uint8_t in[4])
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

size_t
voleith_ring_sig_packed_len(const voleith_ring_sig_t *sig)
{
    if (sig == NULL)
        return 0;
    return VOLEITH_RING_SIG_HEADER_BYTES + sig->len;
}

int
voleith_ring_sig_pack(uint8_t *out_buf, size_t out_len, size_t *written_out,
                      const voleith_ring_sig_t *sig,
                      const voleith_rs_membership_config_t *cfg,
                      const voleith_params_t *params)
{
    uint8_t cfg_fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    size_t off;

    if (out_buf == NULL || sig == NULL || cfg == NULL || params == NULL)
        return -1;
    if ((sig->data == NULL) != (sig->len == 0))
        return -1;
    if (sig->len > UINT32_MAX)
        return -1;
    if (out_len != VOLEITH_RING_SIG_HEADER_BYTES + sig->len)
        return -1;

    if (voleith_rsv1_config_fingerprint(cfg, cfg_fp) != 0)
        return -1;
    if (voleith_params_fingerprint(params, params_fp) != 0)
        return -1;

    off = 0;
    out_buf[off++] = VOLEITH_RING_SIG_MAGIC_0;
    out_buf[off++] = VOLEITH_RING_SIG_MAGIC_1;
    out_buf[off++] = VOLEITH_RING_SIG_MAGIC_2;
    out_buf[off++] = VOLEITH_RING_SIG_MAGIC_3;
    out_buf[off++] = (uint8_t)VOLEITH_RING_SIG_FORMAT_VERSION;
    memcpy(out_buf + off, cfg_fp, sizeof(cfg_fp));
    off += sizeof(cfg_fp);
    memcpy(out_buf + off, params_fp, sizeof(params_fp));
    off += sizeof(params_fp);
    ring_sig_write_u32_be(out_buf + off, (uint32_t)sig->len);
    off += 4;
    if (sig->len != 0)
        memcpy(out_buf + off, sig->data, sig->len);
    off += sig->len;

    if (written_out != NULL)
        *written_out = off;
    return 0;
}

int
voleith_ring_sig_unpack(voleith_ring_sig_t *sig_out, const uint8_t *buf,
                        size_t buf_len,
                        const voleith_rs_membership_config_t *cfg,
                        const voleith_params_t *params)
{
    uint8_t expected_cfg_fp[VOLEITH_RSV1_CONFIG_FINGERPRINT_BYTES];
    uint8_t expected_params_fp[VOLEITH_PARAMS_FINGERPRINT_BYTES];
    uint32_t proof_len;
    size_t off;

    if (sig_out == NULL || buf == NULL || cfg == NULL || params == NULL)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;

    if (buf_len < VOLEITH_RING_SIG_HEADER_BYTES)
        return -1;

    if (buf[0] != VOLEITH_RING_SIG_MAGIC_0 ||
        buf[1] != VOLEITH_RING_SIG_MAGIC_1 ||
        buf[2] != VOLEITH_RING_SIG_MAGIC_2 ||
        buf[3] != VOLEITH_RING_SIG_MAGIC_3)
        return -1;
    if (buf[4] != (uint8_t)VOLEITH_RING_SIG_FORMAT_VERSION)
        return -1;

    if (voleith_rsv1_config_fingerprint(cfg, expected_cfg_fp) != 0)
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

    proof_len = ring_sig_read_u32_be(buf + off);
    off += 4;

    if (buf_len != (size_t)VOLEITH_RING_SIG_HEADER_BYTES + proof_len)
        return -1;

    if (proof_len == 0) {
        sig_out->data = NULL;
        sig_out->len = 0;
        return 0;
    }

    sig_out->data = malloc(proof_len);
    if (sig_out->data == NULL)
        return -1;
    memcpy(sig_out->data, buf + off, proof_len);
    sig_out->len = proof_len;
    return 0;
}
