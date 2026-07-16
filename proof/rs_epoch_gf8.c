/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_epoch_gf8.c - V6 forward-secure epoch key schedule (out of circuit).
 *
 * See rs_epoch_gf8.h for the API contract and the forward-security model.
 * The tree is a binary GGM tree with heap-indexed nodes (root = 1); each
 * node expands to its two children via one AES-CTR PRG call under the V6
 * IV, tweaked by the node's heap index.
 */

#include "rs_epoch_gf8.h"

#include "../core/prg.h"
#include "../core/util.h"

#include <stdlib.h>
#include <string.h>

/* The 16-byte V6 PRG IV materialized from the header tag (no NUL: the
 * literal is exactly 16 bytes, so it fills the array without a
 * terminator). */
static const uint8_t EPOCH_PRG_IV[16] = VOLEITH_RS_EPOCH_PRG_IV_TAG;

/* Depth (distance from the root) of a heap-indexed node: floor(log2(H)). */
static size_t
heap_depth(uint64_t heap)
{
    size_t d = 0;
    while (heap > 1u) {
        heap >>= 1;
        d++;
    }
    return d;
}

/*
 * Range of leaves a heap node covers.  A node at depth k (heap in
 * [2^k, 2^{k+1})) has index-in-level j = heap - 2^k and covers the
 * contiguous leaf block [j * size, (j+1) * size) with size = 2^{d-k}.
 */
static void
heap_range(uint64_t heap, size_t depth_e, uint64_t *lo_out, uint64_t *size_out)
{
    size_t k = heap_depth(heap);
    uint64_t size = (uint64_t)1u << (depth_e - k);
    uint64_t j = heap - ((uint64_t)1u << k);
    *lo_out = j * size;
    *size_out = size;
}

/*
 * Expand one node seed into its two children.  PRG(seed, EPOCH_IV,
 * twk = heap; 2 * seed_bytes) split into left || right.  Scratch is
 * zeroized before return.
 */
static void
expand_node(int lambda, size_t sb, const uint8_t *parent_seed, uint64_t heap,
            uint8_t *left_out, uint8_t *right_out)
{
    voleith_prg_ctx_t prg;
    uint8_t out[2u * VOLEITH_RS_EPOCH_SEED_MAX_BYTES];

    voleith_prg_init(&prg, parent_seed, lambda);
    voleith_prg_gen(&prg, out, EPOCH_PRG_IV, (uint32_t)heap, 2u * sb * 8u);
    voleith_prg_clear(&prg);

    memcpy(left_out, out, sb);
    memcpy(right_out, out + sb, sb);
    voleith_secure_zero(out, sizeof(out));
}

/*
 * PRG-walk from a start node (start_heap at start_depth, holding
 * start_seed) down to the descendant node whose leaf range begins at
 * left_edge and sits at target_depth.  Writes seed_bytes to out.  For a
 * leaf, target_depth == depth_e and left_edge == the leaf index.
 *
 * At each step the child bit is the bit of left_edge at the level being
 * entered; because left_edge is the block's left boundary, every leaf in
 * the target block shares those high bits, so the walk reaches exactly
 * the target node.  All scratch seeds are zeroized.
 */
static void
derive_node(int lambda, size_t sb, size_t depth_e, const uint8_t *start_seed,
            uint64_t start_heap, size_t start_depth, uint64_t left_edge,
            size_t target_depth, uint8_t *out)
{
    uint8_t cur[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    uint8_t l[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    uint8_t r[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    uint64_t heap = start_heap;

    memcpy(cur, start_seed, sb);
    for (size_t k = start_depth; k < target_depth; k++) {
        unsigned bit = (unsigned)((left_edge >> (depth_e - k - 1u)) & 1u);
        expand_node(lambda, sb, cur, heap, l, r);
        memcpy(cur, bit ? r : l, sb);
        heap = 2u * heap + bit;
    }
    memcpy(out, cur, sb);

    voleith_secure_zero(cur, sizeof(cur));
    voleith_secure_zero(l, sizeof(l));
    voleith_secure_zero(r, sizeof(r));
}

/*
 * Tile [t, T) into maximal aligned power-of-two subtree blocks and emit
 * their heap indices, leaf-level first.  Returns the block count (at most
 * depth_e).
 */
static size_t
compute_cover(size_t depth_e, uint64_t t, uint64_t *heap_out)
{
    uint64_t T = (uint64_t)1u << depth_e;
    uint64_t lo = t;
    size_t n = 0;

    while (lo < T) {
        uint64_t size = 1u;
        /* Grow to the largest aligned block that still fits in [lo, T). */
        while ((lo % (size << 1u)) == 0u && (lo + (size << 1u)) <= T)
            size <<= 1u;

        size_t log2size = 0;
        for (uint64_t s = size; s > 1u; s >>= 1u)
            log2size++;
        size_t k = depth_e - log2size;
        heap_out[n++] = ((uint64_t)1u << k) + (lo / size);

        lo += size;
    }
    return n;
}

int
voleith_rs_epoch_state_init(voleith_rs_epoch_state_t *st, size_t depth_e,
                            size_t epoch_sk_bytes, const uint8_t *master_seed)
{
    if (st == NULL || master_seed == NULL)
        return -1;
    if (depth_e == 0 || depth_e > VOLEITH_RS_EPOCH_MAX_DEPTH)
        return -1;
    if (epoch_sk_bytes != 16u && epoch_sk_bytes != 32u)
        return -1;

    memset(st, 0, sizeof(*st));
    st->depth_e = depth_e;
    st->seed_bytes = epoch_sk_bytes;
    st->lambda = (int)(epoch_sk_bytes * 8u);
    st->T = (uint64_t)1u << depth_e;
    st->t = 0;

    /* Epoch 0: the whole range [0, T) is the single root subtree. */
    st->n_cover = 1;
    st->cover_heap[0] = 1u; /* root */
    memcpy(st->cover_seed, master_seed, epoch_sk_bytes);
    return 0;
}

int
voleith_rs_epoch_derive_sk(const voleith_rs_epoch_state_t *st, uint64_t t,
                           uint8_t *sk_out)
{
    if (st == NULL || sk_out == NULL)
        return -1;
    if (t < st->t || t >= st->T)
        return -1;

    size_t sb = st->seed_bytes;
    for (size_t i = 0; i < st->n_cover; i++) {
        uint64_t lo, size;
        heap_range(st->cover_heap[i], st->depth_e, &lo, &size);
        if (t >= lo && t < lo + size) {
            derive_node(st->lambda, sb, st->depth_e, st->cover_seed + i * sb,
                        st->cover_heap[i], heap_depth(st->cover_heap[i]), t,
                        st->depth_e, sk_out);
            return 0;
        }
    }
    return -1; /* not covered (should not happen for t in [st->t, T)) */
}

int
voleith_rs_epoch_state_advance(voleith_rs_epoch_state_t *st, uint64_t target_t)
{
    if (st == NULL)
        return -1;
    if (target_t <= st->t || target_t >= st->T)
        return -1;

    size_t sb = st->seed_bytes;
    uint64_t new_heap[VOLEITH_RS_EPOCH_MAX_DEPTH + 1];
    uint8_t new_seed[(VOLEITH_RS_EPOCH_MAX_DEPTH + 1) *
                     VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    size_t new_n = compute_cover(st->depth_e, target_t, new_heap);

    /*
     * Each new block lies inside exactly one old cover block (the new
     * range [target_t, T) is a subset of the old [st->t, T)); derive its
     * seed by walking down from that ancestor.
     */
    for (size_t i = 0; i < new_n; i++) {
        uint64_t nlo, nsize;
        heap_range(new_heap[i], st->depth_e, &nlo, &nsize);
        size_t ndepth = heap_depth(new_heap[i]);

        size_t found = st->n_cover; /* sentinel */
        for (size_t j = 0; j < st->n_cover; j++) {
            uint64_t olo, osize;
            heap_range(st->cover_heap[j], st->depth_e, &olo, &osize);
            if (olo <= nlo && nlo + nsize <= olo + osize) {
                found = j;
                break;
            }
        }
        if (found == st->n_cover) {
            /* Unreachable for a well-formed cover; fail closed. */
            voleith_secure_zero(new_seed, sizeof(new_seed));
            return -1;
        }

        derive_node(st->lambda, sb, st->depth_e, st->cover_seed + found * sb,
                    st->cover_heap[found], heap_depth(st->cover_heap[found]),
                    nlo, ndepth, new_seed + i * sb);
    }

    /* Retire the old cover (forward security), then install the new one. */
    voleith_secure_zero(st->cover_seed, sizeof(st->cover_seed));
    memset(st->cover_heap, 0, sizeof(st->cover_heap));
    for (size_t i = 0; i < new_n; i++) {
        st->cover_heap[i] = new_heap[i];
        memcpy(st->cover_seed + i * sb, new_seed + i * sb, sb);
    }
    st->n_cover = new_n;
    st->t = target_t;

    voleith_secure_zero(new_seed, sizeof(new_seed));
    return 0;
}

void
voleith_rs_epoch_state_clear(voleith_rs_epoch_state_t *st)
{
    if (st == NULL)
        return;
    /* public_nodes are not secret, but zeroize before free is harmless and
     * keeps the whole struct scrub uniform. */
    if (st->public_nodes != NULL) {
        voleith_secure_zero(st->public_nodes, st->public_nodes_len);
        free(st->public_nodes);
    }
    voleith_secure_zero(st, sizeof(*st));
}

/* ================================================================
 * EP.KEYGEN: epoch tree build + public-node store.
 * ================================================================ */

/*
 * Transiently expand the full GGM tree from master and hash each leaf
 * seed into leaf_nodes (T * node_bytes).  The secret seed buffer is
 * zeroized before return.  O(T) PRG calls + O(T) leaf hashes.
 */
static int
full_expand_leaf_nodes(int lambda, size_t sb, size_t depth_e,
                       const uint8_t *master, const voleith_node_hash_vt *ehash,
                       uint8_t *leaf_nodes)
{
    uint64_t T = (uint64_t)1u << depth_e;
    size_t W = ehash->node_bytes;
    uint8_t *seeds = calloc((size_t)(2u * T), sb);
    int rc = 0;

    if (seeds == NULL)
        return -1;

    memcpy(seeds + 1u * sb, master, sb); /* heap index 1 = root */
    for (uint64_t h = 1; h < T; h++)
        expand_node(lambda, sb, seeds + h * sb, h, seeds + (2u * h) * sb,
                    seeds + (2u * h + 1u) * sb);

    for (uint64_t leaf = 0; leaf < T; leaf++) {
        if (ehash->leaf_hash(seeds + (T + leaf) * sb, sb,
                             leaf_nodes + (size_t)leaf * W) != 0) {
            rc = -1;
            break;
        }
    }

    voleith_secure_zero(seeds, (size_t)(2u * T) * sb);
    free(seeds);
    return rc;
}

int
voleith_rs_epoch_keygen(const voleith_rs_config_t *cfg,
                        const uint8_t *master_seed, const uint8_t *leaf_salt,
                        voleith_rs_epoch_state_t *state_out,
                        uint8_t *epoch_root_out)
{
    if (cfg == NULL || master_seed == NULL || state_out == NULL ||
        epoch_root_out == NULL)
        return -1;

    /* Keep state_out clearable from every failure path below. */
    memset(state_out, 0, sizeof(*state_out));

    if (voleith_rs_config_validate(cfg) != 0)
        return -1;
    if (cfg->depth_e == 0)
        return -1;

    const voleith_node_hash_vt *ehash =
        cfg->epoch_hash ? cfg->epoch_hash : cfg->membership.tree_hash;
    size_t d = cfg->depth_e;
    size_t sb = cfg->epoch_sk_bytes;
    size_t W = ehash->node_bytes;
    uint64_t T = (uint64_t)1u << d;
    uint8_t *leaf_nodes = NULL;

    /* Seed the forward-secure cover at epoch 0 (validates sb / depth). */
    if (voleith_rs_epoch_state_init(state_out, d, sb, master_seed) != 0)
        goto fail;

    state_out->epoch_hash = ehash;
    state_out->node_bytes = W;
    if (voleith_rs_config_fingerprint(cfg, state_out->cfg_fingerprint) != 0)
        goto fail;

    state_out->leaf_salt_bytes = cfg->leaf_salt_bytes;
    if (cfg->leaf_salt_bytes > 0) {
        if (leaf_salt == NULL ||
            cfg->leaf_salt_bytes > VOLEITH_RS_EPOCH_SALT_MAX_BYTES)
            goto fail;
        memcpy(state_out->leaf_salt, leaf_salt, cfg->leaf_salt_bytes);
    }

    /* Step 1-2: transient full expansion -> leaf node hashes. */
    leaf_nodes = malloc((size_t)T * W);
    if (leaf_nodes == NULL)
        goto fail;
    if (full_expand_leaf_nodes(state_out->lambda, sb, d, master_seed, ehash,
                               leaf_nodes) != 0)
        goto fail;

    /* Step 3: build the full tree, keeping all 2T-1 public node hashes in
     * level-major order (leaves first).  Total nodes = 2T-1. */
    state_out->public_nodes_len = (size_t)(2u * T - 1u) * W;
    state_out->public_nodes = malloc(state_out->public_nodes_len);
    if (state_out->public_nodes == NULL)
        goto fail;

    memcpy(state_out->public_nodes, leaf_nodes, (size_t)T * W);

    {
        size_t off = 0;     /* byte offset of the current level */
        uint64_t count = T; /* nodes in the current level */
        while (count > 1u) {
            size_t next_off = off + (size_t)count * W;
            for (uint64_t j = 0; j < count / 2u; j++) {
                if (ehash->inode_hash(
                        state_out->public_nodes + off + (2u * j) * W,
                        state_out->public_nodes + off + (2u * j + 1u) * W,
                        state_out->public_nodes + next_off + (size_t)j * W) !=
                    0)
                    goto fail;
            }
            off = next_off;
            count /= 2u;
        }
        /* Step 4: root is the sole node in the last level. */
        memcpy(state_out->epoch_root, state_out->public_nodes + off, W);
        memcpy(epoch_root_out, state_out->public_nodes + off, W);
    }

    voleith_secure_zero(leaf_nodes, (size_t)T * W);
    free(leaf_nodes);
    return 0;

fail:
    if (leaf_nodes != NULL) {
        voleith_secure_zero(leaf_nodes, (size_t)T * W);
        free(leaf_nodes);
    }
    voleith_rs_epoch_state_clear(state_out);
    return -1;
}

int
voleith_rs_epoch_path(const voleith_rs_epoch_state_t *st, uint64_t t,
                      uint8_t *siblings_out)
{
    if (st == NULL || siblings_out == NULL || st->public_nodes == NULL)
        return -1;
    if (t >= st->T)
        return -1;

    size_t W = st->node_bytes;
    size_t off = 0;         /* byte offset of the current level */
    uint64_t count = st->T; /* nodes in the current level */
    for (size_t k = 0; k < st->depth_e; k++) {
        uint64_t sib = (t >> k) ^ 1u; /* sibling index within level k */
        memcpy(siblings_out + k * W, st->public_nodes + off + (size_t)sib * W,
               W);
        off += (size_t)count * W;
        count /= 2u;
    }
    return 0;
}

/* ================================================================
 * EP.STATE: versioned on-disk serialization.
 * ================================================================ */

static void
store_be64(uint8_t *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xffu);
        v >>= 8;
    }
}

static uint64_t
load_be64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

size_t
voleith_rs_epoch_state_serialized_len(const voleith_rs_epoch_state_t *st)
{
    if (st == NULL || st->public_nodes == NULL)
        return 0;
    return (size_t)VOLEITH_RS_EPOCH_STATE_HEADER_BYTES +
           st->n_cover * (8u + st->seed_bytes) + st->leaf_salt_bytes +
           st->public_nodes_len;
}

int
voleith_rs_epoch_state_serialize(const voleith_rs_epoch_state_t *st,
                                 uint8_t *out, size_t out_len,
                                 size_t *written_out)
{
    static const uint8_t magic[4] = VOLEITH_RS_EPOCH_STATE_MAGIC;
    size_t need = voleith_rs_epoch_state_serialized_len(st);
    size_t off = 0;

    if (st == NULL || out == NULL || st->public_nodes == NULL)
        return -1;
    if (need == 0 || out_len != need)
        return -1;

    memcpy(out + off, magic, 4);
    off += 4;
    out[off++] = (uint8_t)VOLEITH_RS_EPOCH_STATE_VERSION;
    memcpy(out + off, st->cfg_fingerprint, VOLEITH_RS_CONFIG_FINGERPRINT_BYTES);
    off += VOLEITH_RS_CONFIG_FINGERPRINT_BYTES;
    store_be64(out + off, st->t);
    off += 8;
    store_be64(out + off, (uint64_t)st->n_cover);
    off += 8;

    for (size_t i = 0; i < st->n_cover; i++) {
        store_be64(out + off, st->cover_heap[i]);
        off += 8;
        memcpy(out + off, st->cover_seed + i * st->seed_bytes, st->seed_bytes);
        off += st->seed_bytes;
    }

    if (st->leaf_salt_bytes > 0) {
        memcpy(out + off, st->leaf_salt, st->leaf_salt_bytes);
        off += st->leaf_salt_bytes;
    }

    memcpy(out + off, st->public_nodes, st->public_nodes_len);
    off += st->public_nodes_len;

    if (written_out != NULL)
        *written_out = off;
    return 0;
}

int
voleith_rs_epoch_state_load(voleith_rs_epoch_state_t *state_out,
                            const voleith_rs_config_t *cfg, const uint8_t *buf,
                            size_t buf_len)
{
    static const uint8_t magic[4] = VOLEITH_RS_EPOCH_STATE_MAGIC;
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint64_t expect_heap[VOLEITH_RS_EPOCH_MAX_DEPTH + 1];

    if (state_out == NULL || cfg == NULL || buf == NULL)
        return -1;

    memset(state_out, 0, sizeof(*state_out));

    if (voleith_rs_config_validate(cfg) != 0 || cfg->depth_e == 0)
        return -1;
    if (voleith_rs_config_fingerprint(cfg, fp) != 0)
        return -1;

    const voleith_node_hash_vt *ehash =
        cfg->epoch_hash ? cfg->epoch_hash : cfg->membership.tree_hash;
    size_t d = cfg->depth_e;
    size_t sb = cfg->epoch_sk_bytes;
    size_t W = ehash->node_bytes;
    uint64_t T = (uint64_t)1u << d;
    size_t salt_bytes = cfg->leaf_salt_bytes;
    size_t public_len = (size_t)(2u * T - 1u) * W;

    if (buf_len < VOLEITH_RS_EPOCH_STATE_HEADER_BYTES)
        return -1;

    size_t off = 0;
    if (voleith_const_memcmp(buf + off, magic, 4) != 0)
        return -1;
    off += 4;
    if (buf[off] != (uint8_t)VOLEITH_RS_EPOCH_STATE_VERSION)
        return -1;
    off += 1;
    if (voleith_const_memcmp(buf + off, fp,
                             VOLEITH_RS_CONFIG_FINGERPRINT_BYTES) != 0)
        return -1;
    off += VOLEITH_RS_CONFIG_FINGERPRINT_BYTES;

    uint64_t t = load_be64(buf + off);
    off += 8;
    uint64_t cover_count = load_be64(buf + off);
    off += 8;

    if (t >= T)
        return -1;
    if (cover_count == 0 ||
        cover_count > (uint64_t)(VOLEITH_RS_EPOCH_MAX_DEPTH + 1))
        return -1;

    /* Exact length: header + cover + salt + public nodes; reject truncation
     * and trailing bytes. */
    size_t expect_len = (size_t)VOLEITH_RS_EPOCH_STATE_HEADER_BYTES +
                        (size_t)cover_count * (8u + sb) + salt_bytes +
                        public_len;
    if (buf_len != expect_len)
        return -1;

    /* The cover is determined by t; the stored heap indices must match the
     * canonical tiling of [t, T). */
    size_t expect_n = compute_cover(d, t, expect_heap);
    if ((uint64_t)expect_n != cover_count)
        return -1;

    state_out->depth_e = d;
    state_out->seed_bytes = sb;
    state_out->lambda = (int)(sb * 8u);
    state_out->T = T;
    state_out->t = t;
    state_out->n_cover = (size_t)cover_count;
    state_out->epoch_hash = ehash;
    state_out->node_bytes = W;
    state_out->leaf_salt_bytes = salt_bytes;
    memcpy(state_out->cfg_fingerprint, fp, VOLEITH_RS_CONFIG_FINGERPRINT_BYTES);

    for (size_t i = 0; i < cover_count; i++) {
        uint64_t heap = load_be64(buf + off);
        off += 8;
        if (heap != expect_heap[i]) {
            voleith_rs_epoch_state_clear(state_out);
            return -1;
        }
        state_out->cover_heap[i] = heap;
        memcpy(state_out->cover_seed + i * sb, buf + off, sb);
        off += sb;
    }

    if (salt_bytes > 0) {
        if (salt_bytes > VOLEITH_RS_EPOCH_SALT_MAX_BYTES) {
            voleith_rs_epoch_state_clear(state_out);
            return -1;
        }
        memcpy(state_out->leaf_salt, buf + off, salt_bytes);
        off += salt_bytes;
    }

    state_out->public_nodes_len = public_len;
    state_out->public_nodes = malloc(public_len);
    if (state_out->public_nodes == NULL) {
        voleith_rs_epoch_state_clear(state_out);
        return -1;
    }
    memcpy(state_out->public_nodes, buf + off, public_len);

    /* Epoch root is the last public node (level-major, root last). */
    memcpy(state_out->epoch_root,
           state_out->public_nodes + (size_t)(2u * T - 2u) * W, W);

    return 0;
}

/* ================================================================
 * EP.SIGN: convenience signer.
 * ================================================================ */

int
voleith_rs_epoch_sign(voleith_rs_sig_t *sig_out,
                      const voleith_rs_epoch_state_t *state,
                      const voleith_rs_config_t *cfg,
                      const voleith_params_t *params, const uint8_t *attrs,
                      const voleith_rs_path_t *path,
                      const voleith_rs_public_t *pub, const uint8_t *m,
                      size_t m_len)
{
    uint8_t fp[VOLEITH_RS_CONFIG_FINGERPRINT_BYTES];
    uint8_t sk_t[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
    uint8_t *epoch_sibs = NULL;
    voleith_rs_path_t local;
    int rc = -1;

    if (sig_out == NULL || state == NULL || cfg == NULL || params == NULL ||
        path == NULL || pub == NULL)
        return -1;
    sig_out->data = NULL;
    sig_out->len = 0;

    if (cfg->depth_e == 0)
        return -1;
    /* State must belong to cfg. */
    if (voleith_rs_config_fingerprint(cfg, fp) != 0)
        return -1;
    if (voleith_const_memcmp(fp, state->cfg_fingerprint,
                             VOLEITH_RS_CONFIG_FINGERPRINT_BYTES) != 0)
        return -1;

    if (voleith_rs_epoch_derive_sk(state, pub->epoch, sk_t) != 0)
        return -1;

    epoch_sibs = malloc(state->depth_e * state->node_bytes);
    if (epoch_sibs == NULL)
        goto out;
    if (voleith_rs_epoch_path(state, pub->epoch, epoch_sibs) != 0)
        goto out;

    local = *path;
    local.epoch_sk = sk_t;
    local.epoch_siblings = epoch_sibs;
    local.epoch_salt = state->leaf_salt_bytes > 0 ? state->leaf_salt : NULL;
    local.epoch = pub->epoch;

    rc = voleith_rs_sign(sig_out, cfg, params, NULL, attrs, &local, pub, m,
                         m_len);

out:
    voleith_secure_zero(sk_t, sizeof(sk_t));
    if (epoch_sibs != NULL) {
        voleith_secure_zero(epoch_sibs, state->depth_e * state->node_bytes);
        free(epoch_sibs);
    }
    return rc;
}
