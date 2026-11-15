/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_vt_gf8_norm.c - Phase 5 norm-vs-frozen tree harness.
 *
 * The vt-parametric Merkle (merkle_vt_gf8_path_circuit) and indexed
 * Merkle (merkle_vt_gf8_indexed_nonmember_circuit) entry points already
 * take a voleith_node_hash_vt * directly, so a consumer selects the norm
 * node hash simply by passing the norm vt pointer in place of the frozen
 * one.  This harness proves that selection is correct and that the win is
 * slots-only: for each (frozen, norm) twin it builds BOTH trees on an
 * identical external-wire layout, at representative depths, and asserts
 *
 *   1. Root parity: the norm tree's root equals the frozen tree's root
 *      and the software-computed root, byte for byte (the output is
 *      defined to be identical; a wrong norm gadget fails here).
 *   2. Slot reduction: the norm circuit carries fewer witness slots than
 *      the frozen circuit, and the reduction holds the exact per-vt ratio
 *      (norm_inv * frozen_unit == frozen_inv * norm_unit) across the whole
 *      tree (leaf + depth inodes).
 *   3. Verify-linearity spot check: the norm circuit's constraint and
 *      multiplication counts are no greater than the frozen twin's, so
 *      verify time (linear in constraints, not witnesses) does not grow.
 *      Both counts are printed so the flat-vs-better relationship is
 *      visible per depth.
 *   4. Tamper: flipping the first inv_in byte makes each circuit reject.
 *
 * Both tree types are driven public-dir and secret-dir.  Indexed
 * non-membership is exercised only for the variable-leaf vts (the fixed-
 * leaf vts carry supports_indexed = 0, matching the conformance suite).
 *
 * Mirrors the conventions of test_node_hash_vt_conformance.c and
 * test_merkle_vt_gf8_equivalence.c: eval-satisfaction (no QuickSilver
 * prove/verify) and no fingerprint goldens; correctness is pinned by root
 * parity against the frozen twin and the software oracle.
 */

#include "merkle_vt_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "../proof/gf8_circuit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Wraps a (possibly fallible) call so the function is ALWAYS evaluated,
 * even when NDEBUG elides assert().  `assert(fn(...) == 0)` would drop the
 * call entirely under -DNDEBUG (Release builds). */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

#define MAX_DEPTH 8
#define MAX_NODE_BYTES 64
#define MAX_LEAF_BYTES 256

/* Indexed non-membership record shape (single-byte value / index, as in
 * the conformance suite): leaf = value || next_value || next_index. */
#define IDX_LEAF_DATA_BYTES 3
#define IDX_TARGET_BYTES 1
#define IDX_INDEX_BYTES 1

static const size_t DEPTHS[] = {1, 2, 4, 8};
#define N_DEPTHS (sizeof(DEPTHS) / sizeof(DEPTHS[0]))

static int total_tests = 0;
static int total_pass = 0;

static void
check(const char *what, int cond)
{
    total_tests++;
    if (cond) {
        total_pass++;
    } else {
        printf("    FAIL: %s\n", what);
    }
}

/* ================================================================
 * Frozen / norm twin pairings.  frozen_unit / norm_unit express the
 * per-inverse slot ratio (norm = norm_unit/frozen_unit of frozen);
 * the same values the conformance suite's check_norm_vs_frozen uses.
 * ================================================================ */

typedef struct {
    const char *label;
    const voleith_node_hash_vt *frozen;
    const voleith_node_hash_vt *norm;
    size_t leaf_bytes; /* membership leaf-data width to test with */
    int supports_indexed;
    size_t frozen_unit;
    size_t norm_unit;
} norm_pair_t;

static const norm_pair_t PAIRS[] = {
    {"aes-dm", &voleith_node_hash_aes_dm, &voleith_node_hash_aes_dm_norm, 16, 1,
     200, 160},
    {"aes-cmac128", &voleith_node_hash_aes_cmac128,
     &voleith_node_hash_aes_cmac128_norm, 16, 1, 200, 160},
    {"hirose-aes-256", &voleith_node_hash_hirose,
     &voleith_node_hash_hirose_norm, 16, 1, 500, 388},
    {"hirose-fixed32", &voleith_node_hash_hirose_fixed32,
     &voleith_node_hash_hirose_fixed32_norm, 16, 0, 500, 388},
    {"hirose-fixed96", &voleith_node_hash_hirose_fixed96,
     &voleith_node_hash_hirose_fixed96_norm, 96, 0, 500, 388},
    {"grostl256-fixed", &voleith_node_hash_grostl256_fixed,
     &voleith_node_hash_grostl256_fixed_norm, 32, 0, 4, 3},
    {"grostl512-fixed", &voleith_node_hash_grostl512_fixed,
     &voleith_node_hash_grostl512_fixed_norm, 64, 0, 4, 3},
    {"grostl256-fixed128", &voleith_node_hash_grostl256_fixed128,
     &voleith_node_hash_grostl256_fixed128_norm, 128, 0, 4, 3},
    {"grostl512-fixed256", &voleith_node_hash_grostl512_fixed256,
     &voleith_node_hash_grostl512_fixed256_norm, 256, 0, 4, 3},
};
#define N_PAIRS (sizeof(PAIRS) / sizeof(PAIRS[0]))

/* ================================================================
 * Software oracle: build a depth-D tree over 2^D leaves and emit the
 * root plus the target leaf's sibling path and direction bits.  The
 * frozen and norm vts produce identical hashes, so either drives it;
 * callers pass the frozen vt.
 * ================================================================ */

static void
build_software_tree(const voleith_node_hash_vt *h, size_t depth,
                    size_t leaf_bytes, const uint8_t *leaves, size_t target,
                    uint8_t *root_out, uint8_t *siblings_out, uint8_t *dirs_out)
{
    size_t W = h->node_bytes;
    size_t n_leaves = (size_t)1u << depth;
    uint8_t *layer[MAX_DEPTH + 1];

    for (size_t k = 0; k <= depth; k++)
        layer[k] = calloc((n_leaves >> k) > 0 ? (n_leaves >> k) : 1, W);

    for (size_t i = 0; i < n_leaves; i++)
        MUST_OK(h->leaf_hash(leaves + i * leaf_bytes, leaf_bytes,
                             layer[0] + i * W));

    for (size_t k = 0; k < depth; k++) {
        size_t n_parents = n_leaves >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(h->inode_hash(layer[k] + (2 * j) * W,
                                  layer[k] + (2 * j + 1) * W,
                                  layer[k + 1] + j * W));
    }

    memcpy(root_out, layer[depth], W);
    for (size_t k = 0; k < depth; k++) {
        size_t cur = target >> k;
        dirs_out[k] = (uint8_t)(cur & 1u);
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }

    for (size_t k = 0; k <= depth; k++)
        free(layer[k]);
}

/*
 * Assemble the witness vector for a membership path circuit under the
 * canonical layout:
 *   leaf_data | path_nodes | [dirs] | leaf_inv_in | inode_inv_in[0..D-1]
 */
static void
build_path_witness(const voleith_node_hash_vt *h, const uint8_t *leaf_data,
                   size_t leaf_bytes, size_t depth, const uint8_t *siblings,
                   const uint8_t *dirs, int secret_dir, uint8_t *witness)
{
    size_t W = h->node_bytes;
    uint8_t *wp = witness;

    memcpy(wp, leaf_data, leaf_bytes);
    wp += leaf_bytes;
    memcpy(wp, siblings, depth * W);
    wp += depth * W;
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            wp[k] = dirs[k];
        wp += depth;
    }

    MUST_OK(h->leaf_build_witness(leaf_data, leaf_bytes, wp));
    wp += h->leaf_invin_bytes(leaf_bytes);

    uint8_t current[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(leaf_data, leaf_bytes, current));
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();
        uint8_t next[MAX_NODE_BYTES];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
}

/*
 * Build a membership path circuit for vt h at the canonical external-wire
 * layout and return the root wire IDs.  dirs_public is consulted only in
 * public-dir mode (directions baked into the gate stream).
 */
static void
build_path_circuit(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
                   size_t leaf_bytes, size_t depth, int secret_dir,
                   const uint8_t *dirs_public, gf8_wire_id *root_w)
{
    size_t W = h->node_bytes;
    gf8_wire_id leaf_w[MAX_LEAF_BYTES];
    for (size_t i = 0; i < leaf_bytes; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *path_w = calloc(depth * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < depth * W; i++)
        path_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id dir_w[MAX_DEPTH];
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            dir_w[k] = voleith_gf8_add_witness(c);
        MUST_OK(merkle_vt_gf8_path_circuit_secret_dir(
            c, h, leaf_w, leaf_bytes, path_w, dir_w, depth, root_w));
    } else {
        MUST_OK(merkle_vt_gf8_path_circuit(c, h, leaf_w, leaf_bytes, path_w,
                                           dirs_public, depth, root_w));
    }
    free(path_w);
}

/* ================================================================
 * Membership: build frozen and norm trees on the same layout and
 * compare.
 * ================================================================ */

static void
run_membership(const norm_pair_t *p, size_t depth, int secret_dir)
{
    const voleith_node_hash_vt *F = p->frozen;
    const voleith_node_hash_vt *N = p->norm;
    size_t W = F->node_bytes;
    size_t lb = p->leaf_bytes;
    size_t n_leaves = (size_t)1u << depth;
    size_t target = n_leaves / 2; /* in range for every depth (>=1) */
    char name[192];

    printf("  %-20s depth=%zu %s membership\n", p->label, depth,
           secret_dir ? "secret-dir" : "public-dir");

    uint8_t *leaves = calloc(n_leaves, lb);
    for (size_t i = 0; i < n_leaves; i++)
        for (size_t j = 0; j < lb; j++)
            leaves[i * lb + j] = (uint8_t)(i * 13 + j + 1);

    uint8_t root_sw[MAX_NODE_BYTES];
    uint8_t *siblings = calloc(depth, W);
    uint8_t dirs[MAX_DEPTH];
    build_software_tree(F, depth, lb, leaves, target, root_sw, siblings, dirs);

    voleith_gf8_circuit_t *cF = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *cN = voleith_gf8_circuit_new();
    gf8_wire_id rootF[MAX_NODE_BYTES], rootN[MAX_NODE_BYTES];
    build_path_circuit(cF, F, lb, depth, secret_dir, dirs, rootF);
    build_path_circuit(cN, N, lb, depth, secret_dir, dirs, rootN);

    /* Slot reduction: external wires are identical, so the witness-count
     * delta is entirely inv_in; it must shrink at the exact per-vt ratio. */
    size_t external = lb + depth * W + (secret_dir ? depth : 0);
    size_t wF = voleith_gf8_circuit_witness_count(cF);
    size_t wN = voleith_gf8_circuit_witness_count(cN);
    size_t invF = wF - external;
    size_t invN = wN - external;
    snprintf(name, sizeof(name),
             "[%s d=%zu %s] norm inv_in=%zu < frozen inv_in=%zu", p->label,
             depth, secret_dir ? "sec" : "pub", invN, invF);
    check(name, invN < invF);
    snprintf(name, sizeof(name),
             "[%s d=%zu %s] slot ratio holds (%zu*%zu == %zu*%zu)", p->label,
             depth, secret_dir ? "sec" : "pub", invN, p->frozen_unit, invF,
             p->norm_unit);
    check(name, invN * p->frozen_unit == invF * p->norm_unit);

    /* Verify-linearity spot check: verify cost tracks constraints/muls, not
     * witnesses, so the norm twin must be no costlier to verify. */
    size_t kF = voleith_gf8_circuit_constraint_count(cF);
    size_t kN = voleith_gf8_circuit_constraint_count(cN);
    size_t mF = voleith_gf8_circuit_mul_count(cF);
    size_t mN = voleith_gf8_circuit_mul_count(cN);
    printf("      verify-cost: constraints frozen=%zu norm=%zu | mul "
           "frozen=%zu norm=%zu\n",
           kF, kN, mF, mN);
    snprintf(name, sizeof(name),
             "[%s d=%zu %s] norm constraint_count <= frozen", p->label, depth,
             secret_dir ? "sec" : "pub");
    check(name, kN <= kF);
    snprintf(name, sizeof(name), "[%s d=%zu %s] norm mul_count <= frozen",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, mN <= mF);

    /* Build each twin's own witness; both satisfy, roots agree and match
     * the software oracle. */
    uint8_t *witF = calloc(wF > 0 ? wF : 1, 1);
    uint8_t *witN = calloc(wN > 0 ? wN : 1, 1);
    build_path_witness(F, leaves + target * lb, lb, depth, siblings, dirs,
                       secret_dir, witF);
    build_path_witness(N, leaves + target * lb, lb, depth, siblings, dirs,
                       secret_dir, witN);

    size_t nWF = voleith_gf8_circuit_wire_count(cF);
    size_t nWN = voleith_gf8_circuit_wire_count(cN);
    uint8_t *wvF = calloc(nWF > 0 ? nWF : 1, 1);
    uint8_t *wvN = calloc(nWN > 0 ? nWN : 1, 1);

    int okF = voleith_gf8_circuit_eval(cF, witF, NULL, wvF);
    int okN = voleith_gf8_circuit_eval(cN, witN, NULL, wvN);
    snprintf(name, sizeof(name), "[%s d=%zu %s] frozen satisfied", p->label,
             depth, secret_dir ? "sec" : "pub");
    check(name, okF == 1);
    snprintf(name, sizeof(name), "[%s d=%zu %s] norm satisfied", p->label,
             depth, secret_dir ? "sec" : "pub");
    check(name, okN == 1);

    int eq_FN = 1, eq_sw = 1;
    for (size_t i = 0; i < W; i++) {
        if (wvF[rootF[i]] != wvN[rootN[i]])
            eq_FN = 0;
        if (wvN[rootN[i]] != root_sw[i])
            eq_sw = 0;
    }
    snprintf(name, sizeof(name), "[%s d=%zu %s] norm root == frozen root",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, eq_FN);
    snprintf(name, sizeof(name), "[%s d=%zu %s] norm root == software root",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, eq_sw);

    /* Tamper the first inv_in byte of each witness; both must reject. */
    if (external < wF) {
        witF[external] ^= 0x01;
        int bad = voleith_gf8_circuit_eval(cF, witF, NULL, wvF);
        snprintf(name, sizeof(name), "[%s d=%zu %s] frozen tamper rejected",
                 p->label, depth, secret_dir ? "sec" : "pub");
        check(name, bad == 0);
        witF[external] ^= 0x01;
    }
    if (external < wN) {
        witN[external] ^= 0x01;
        int bad = voleith_gf8_circuit_eval(cN, witN, NULL, wvN);
        snprintf(name, sizeof(name), "[%s d=%zu %s] norm tamper rejected",
                 p->label, depth, secret_dir ? "sec" : "pub");
        check(name, bad == 0);
        witN[external] ^= 0x01;
    }

    free(wvF);
    free(wvN);
    free(witF);
    free(witN);
    free(siblings);
    free(leaves);
    voleith_gf8_circuit_free(cF);
    voleith_gf8_circuit_free(cN);
}

/* ================================================================
 * Indexed non-membership (variable-leaf vts only).  Record i is
 * (value = 10+10i, next_value = 10+10(i+1), next_index = i+1); the
 * target value 35 is proven absent via the adjacent leaf 2 (30, 40, 3).
 * ================================================================ */

#define IDX_TARGET_VAL 35
#define IDX_ADJ_LEAF 2
#define IDX_LOW_VALUE 30
#define IDX_LOW_NEXT 40
#define IDX_NEXT_INDEX 3

static void
build_indexed_tree(const voleith_node_hash_vt *h, size_t depth,
                   uint8_t *root_out, uint8_t *siblings_out, uint8_t *dirs_out)
{
    size_t W = h->node_bytes;
    size_t n_leaves = (size_t)1u << depth;
    uint8_t *layer[MAX_DEPTH + 1];
    for (size_t k = 0; k <= depth; k++)
        layer[k] = calloc((n_leaves >> k) > 0 ? (n_leaves >> k) : 1, W);

    for (size_t i = 0; i < n_leaves; i++) {
        uint8_t leaf[IDX_LEAF_DATA_BYTES];
        leaf[0] = (uint8_t)(10 + 10 * i);
        leaf[1] = (i == n_leaves - 1) ? 255 : (uint8_t)(10 + 10 * (i + 1));
        leaf[2] = (i == n_leaves - 1) ? 0 : (uint8_t)(i + 1);
        MUST_OK(h->leaf_hash(leaf, IDX_LEAF_DATA_BYTES, layer[0] + i * W));
    }
    for (size_t k = 0; k < depth; k++) {
        size_t n_parents = n_leaves >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(h->inode_hash(layer[k] + (2 * j) * W,
                                  layer[k] + (2 * j + 1) * W,
                                  layer[k + 1] + j * W));
    }

    memcpy(root_out, layer[depth], W);
    for (size_t k = 0; k < depth; k++) {
        size_t cur = (size_t)IDX_ADJ_LEAF >> k;
        dirs_out[k] = (uint8_t)(cur & 1u);
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }

    for (size_t k = 0; k <= depth; k++)
        free(layer[k]);
}

static void
build_indexed_circuit(voleith_gf8_circuit_t *c, const voleith_node_hash_vt *h,
                      size_t depth, int secret_dir, const uint8_t *dirs_public,
                      gf8_wire_id *root_w)
{
    size_t W = h->node_bytes;
    gf8_wire_id tgt[IDX_TARGET_BYTES], lv[IDX_TARGET_BYTES],
        ln[IDX_TARGET_BYTES], ni[IDX_INDEX_BYTES];
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        tgt[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        lv[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        ln[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_INDEX_BYTES; i++)
        ni[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *path_w = calloc(depth * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < depth * W; i++)
        path_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id dir_w[MAX_DEPTH];
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            dir_w[k] = voleith_gf8_add_witness(c);
        MUST_OK(merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
            c, h, tgt, IDX_TARGET_BYTES, lv, ln, ni, IDX_INDEX_BYTES, path_w,
            dir_w, depth, root_w));
    } else {
        MUST_OK(merkle_vt_gf8_indexed_nonmember_circuit(
            c, h, tgt, IDX_TARGET_BYTES, lv, ln, ni, IDX_INDEX_BYTES, path_w,
            dirs_public, depth, root_w));
    }
    free(path_w);
}

static void
build_indexed_witness(const voleith_node_hash_vt *h, size_t depth,
                      const uint8_t *siblings, const uint8_t *dirs,
                      int secret_dir, uint8_t *witness)
{
    size_t W = h->node_bytes;
    uint8_t *wp = witness;
    *wp++ = IDX_TARGET_VAL;
    *wp++ = IDX_LOW_VALUE;
    *wp++ = IDX_LOW_NEXT;
    *wp++ = IDX_NEXT_INDEX;
    memcpy(wp, siblings, depth * W);
    wp += depth * W;
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            wp[k] = dirs[k];
        wp += depth;
    }

    uint8_t leaf[IDX_LEAF_DATA_BYTES] = {IDX_LOW_VALUE, IDX_LOW_NEXT,
                                         IDX_NEXT_INDEX};
    MUST_OK(h->leaf_build_witness(leaf, IDX_LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(IDX_LEAF_DATA_BYTES);

    uint8_t current[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(leaf, IDX_LEAF_DATA_BYTES, current));
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();
        uint8_t next[MAX_NODE_BYTES];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
}

static void
run_indexed(const norm_pair_t *p, size_t depth, int secret_dir)
{
    const voleith_node_hash_vt *F = p->frozen;
    const voleith_node_hash_vt *N = p->norm;
    size_t W = F->node_bytes;
    char name[192];

    printf("  %-20s depth=%zu %s indexed\n", p->label, depth,
           secret_dir ? "secret-dir" : "public-dir");

    uint8_t root_sw[MAX_NODE_BYTES];
    uint8_t *siblings = calloc(depth, W);
    uint8_t dirs[MAX_DEPTH];
    build_indexed_tree(F, depth, root_sw, siblings, dirs);

    voleith_gf8_circuit_t *cF = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *cN = voleith_gf8_circuit_new();
    gf8_wire_id rootF[MAX_NODE_BYTES], rootN[MAX_NODE_BYTES];
    build_indexed_circuit(cF, F, depth, secret_dir, dirs, rootF);
    build_indexed_circuit(cN, N, depth, secret_dir, dirs, rootN);

    /* external = target(1) + lv(1) + ln(1) + ni(1) + path + [dirs]. */
    size_t external = IDX_LEAF_DATA_BYTES + IDX_TARGET_BYTES + depth * W +
                      (secret_dir ? depth : 0);
    size_t wF = voleith_gf8_circuit_witness_count(cF);
    size_t wN = voleith_gf8_circuit_witness_count(cN);
    size_t invF = wF - external;
    size_t invN = wN - external;
    snprintf(name, sizeof(name),
             "[%s d=%zu %s idx] norm inv_in=%zu < frozen inv_in=%zu", p->label,
             depth, secret_dir ? "sec" : "pub", invN, invF);
    check(name, invN < invF);
    snprintf(name, sizeof(name),
             "[%s d=%zu %s idx] slot ratio holds (%zu*%zu == %zu*%zu)",
             p->label, depth, secret_dir ? "sec" : "pub", invN, p->frozen_unit,
             invF, p->norm_unit);
    check(name, invN * p->frozen_unit == invF * p->norm_unit);

    size_t kF = voleith_gf8_circuit_constraint_count(cF);
    size_t kN = voleith_gf8_circuit_constraint_count(cN);
    size_t mF = voleith_gf8_circuit_mul_count(cF);
    size_t mN = voleith_gf8_circuit_mul_count(cN);
    printf("      verify-cost: constraints frozen=%zu norm=%zu | mul "
           "frozen=%zu norm=%zu\n",
           kF, kN, mF, mN);
    snprintf(name, sizeof(name),
             "[%s d=%zu %s idx] norm constraint_count <= frozen", p->label,
             depth, secret_dir ? "sec" : "pub");
    check(name, kN <= kF);
    snprintf(name, sizeof(name), "[%s d=%zu %s idx] norm mul_count <= frozen",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, mN <= mF);

    uint8_t *witF = calloc(wF > 0 ? wF : 1, 1);
    uint8_t *witN = calloc(wN > 0 ? wN : 1, 1);
    build_indexed_witness(F, depth, siblings, dirs, secret_dir, witF);
    build_indexed_witness(N, depth, siblings, dirs, secret_dir, witN);

    size_t nWF = voleith_gf8_circuit_wire_count(cF);
    size_t nWN = voleith_gf8_circuit_wire_count(cN);
    uint8_t *wvF = calloc(nWF > 0 ? nWF : 1, 1);
    uint8_t *wvN = calloc(nWN > 0 ? nWN : 1, 1);

    int okF = voleith_gf8_circuit_eval(cF, witF, NULL, wvF);
    int okN = voleith_gf8_circuit_eval(cN, witN, NULL, wvN);
    snprintf(name, sizeof(name), "[%s d=%zu %s idx] frozen satisfied", p->label,
             depth, secret_dir ? "sec" : "pub");
    check(name, okF == 1);
    snprintf(name, sizeof(name), "[%s d=%zu %s idx] norm satisfied", p->label,
             depth, secret_dir ? "sec" : "pub");
    check(name, okN == 1);

    int eq_FN = 1, eq_sw = 1;
    for (size_t i = 0; i < W; i++) {
        if (wvF[rootF[i]] != wvN[rootN[i]])
            eq_FN = 0;
        if (wvN[rootN[i]] != root_sw[i])
            eq_sw = 0;
    }
    snprintf(name, sizeof(name), "[%s d=%zu %s idx] norm root == frozen root",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, eq_FN);
    snprintf(name, sizeof(name), "[%s d=%zu %s idx] norm root == software root",
             p->label, depth, secret_dir ? "sec" : "pub");
    check(name, eq_sw);

    /* Tamper the first inv_in byte of each witness; both must reject. */
    if (external < wF) {
        witF[external] ^= 0x01;
        int bad = voleith_gf8_circuit_eval(cF, witF, NULL, wvF);
        snprintf(name, sizeof(name), "[%s d=%zu %s idx] frozen tamper rejected",
                 p->label, depth, secret_dir ? "sec" : "pub");
        check(name, bad == 0);
        witF[external] ^= 0x01;
    }
    if (external < wN) {
        witN[external] ^= 0x01;
        int bad = voleith_gf8_circuit_eval(cN, witN, NULL, wvN);
        snprintf(name, sizeof(name), "[%s d=%zu %s idx] norm tamper rejected",
                 p->label, depth, secret_dir ? "sec" : "pub");
        check(name, bad == 0);
        witN[external] ^= 0x01;
    }

    free(wvF);
    free(wvN);
    free(witF);
    free(witN);
    free(siblings);
    voleith_gf8_circuit_free(cF);
    voleith_gf8_circuit_free(cN);
}

int
main(void)
{
    printf("=== Merkle vt norm-vs-frozen (Phase 5) ===\n");

    for (size_t i = 0; i < N_PAIRS; i++) {
        for (size_t d = 0; d < N_DEPTHS; d++) {
            run_membership(&PAIRS[i], DEPTHS[d], 0);
            run_membership(&PAIRS[i], DEPTHS[d], 1);
            /* Indexed non-membership of target 35 is proven via the
             * adjacent leaf 2, so it needs that leaf to exist: depth >= 2
             * (>= 4 leaves).  A depth-1 tree has only leaves {0, 1}. */
            if (PAIRS[i].supports_indexed && DEPTHS[d] >= 2) {
                run_indexed(&PAIRS[i], DEPTHS[d], 0);
                run_indexed(&PAIRS[i], DEPTHS[d], 1);
            }
        }
    }

    printf("\n%d / %d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
