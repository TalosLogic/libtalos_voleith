/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_vt_gf8_helpers.c - exercise voleith_merkle_vt_build and
 * voleith_merkle_vt_compute_path across every wrapped node-hash vt.
 *
 * For each vt:
 *   1. Build a depth-3 (8-leaf) tree from synthetic pre-hashed leaf
 *      nodes; compare the helper's root against a reference root
 *      computed via an inline level-by-level vt->inode_hash walk
 *      (the inline pattern this helper replaces).
 *   2. For each leaf 0..7, compute the sibling path with
 *      voleith_merkle_vt_compute_path and drive it into a small
 *      circuit built around merkle_vt_gf8_path_from_leaf_node_secret_dir;
 *      assert circuit eval returns 1 and the in-circuit root wires
 *      match the helper-computed root byte-for-byte.
 *   3. Argument-validation rejection (NULL args, non-power-of-two
 *      n_leaves, leaf_index out of range).
 *
 * Covers all eight wrapped vts (Hirose 2 + AES 2 + Grøstl 4).
 *
 * See the RS-V1 implementation plan T5a.
 */

#include "merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "../proof/gf8_circuit.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Wraps a (possibly fallible) call so the function is ALWAYS evaluated,
 * even when NDEBUG elides assert().  Mirrors the macro in
 * test_merkle_vt_gf8_equivalence.c.
 */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

#define DEPTH 3
#define N_LEAVES (1u << DEPTH)

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

static const voleith_node_hash_vt *const VTS[] = {
    &voleith_node_hash_hirose,    &voleith_node_hash_hirose_fixed32,
    &voleith_node_hash_aes_dm,    &voleith_node_hash_aes_cmac128,
    &voleith_node_hash_grostl256, &voleith_node_hash_grostl256_t27,
    &voleith_node_hash_grostl512, &voleith_node_hash_grostl512_t59,
};
#define N_VTS (sizeof(VTS) / sizeof(VTS[0]))

/*
 * Synthesize n_leaves * node_bytes of deterministic leaf-node bytes.
 * The helpers operate on already-hashed leaf nodes, so we feed them
 * arbitrary node-wide bytes directly - no leaf_hash call needed and
 * the fixed-vs-variable leaf width distinction is irrelevant here.
 */
static void
fill_leaf_nodes(uint8_t *buf, size_t n_leaves, size_t W)
{
    for (size_t i = 0; i < n_leaves; i++)
        for (size_t j = 0; j < W; j++)
            buf[i * W + j] = (uint8_t)(0x1bu + i * 37u + j * 5u);
}

/*
 * Inline reference root: same level-by-level pattern walk_tree() runs
 * internally, kept independent so a bug in walk_tree does not also
 * compromise the oracle.
 */
static void
reference_root(const voleith_node_hash_vt *vt, const uint8_t *leaf_nodes,
               size_t n_leaves, uint8_t *root_out)
{
    size_t W = vt->node_bytes;
    uint8_t *cur = calloc(n_leaves, W);
    uint8_t *nxt = calloc(n_leaves / 2u, W);
    assert(cur != NULL && nxt != NULL);

    memcpy(cur, leaf_nodes, n_leaves * W);
    size_t cur_n = n_leaves;

    while (cur_n > 1) {
        size_t next_n = cur_n >> 1;
        for (size_t j = 0; j < next_n; j++)
            MUST_OK(vt->inode_hash(cur + (2u * j) * W, cur + (2u * j + 1u) * W,
                                   nxt + j * W));
        memcpy(cur, nxt, next_n * W);
        cur_n = next_n;
    }

    memcpy(root_out, cur, W);
    free(cur);
    free(nxt);
}

/*
 * Drive merkle_vt_gf8_path_from_leaf_node_secret_dir with the
 * (leaf_node, siblings, dirs) produced by voleith_merkle_vt_compute_path.
 * Returns 0 on success and writes the root wire bytes into root_bytes_out.
 *
 * Witness layout (matches the wire-declaration order below):
 *   leaf_node | path_nodes | dirs | inode_inv_in[0..D-1]
 */
static int
drive_circuit(const voleith_node_hash_vt *vt, const uint8_t *leaf_node,
              const uint8_t *siblings, const uint8_t *dirs, size_t depth,
              uint8_t *root_bytes_out)
{
    size_t W = vt->node_bytes;
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (c == NULL)
        return -1;

    gf8_wire_id leaf_wires[MERKLE_VT_MAX_NODE_BYTES];
    for (size_t i = 0; i < W; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *path_wires = calloc(depth * W, sizeof(gf8_wire_id));
    gf8_wire_id dir_wires[16];
    assert(depth <= sizeof(dir_wires) / sizeof(dir_wires[0]));

    for (size_t i = 0; i < depth * W; i++)
        path_wires[i] = voleith_gf8_add_witness(c);
    for (size_t k = 0; k < depth; k++)
        dir_wires[k] = voleith_gf8_add_witness(c);

    gf8_wire_id root_wires[MERKLE_VT_MAX_NODE_BYTES];
    int rc = merkle_vt_gf8_path_from_leaf_node_secret_dir(
        c, vt, leaf_wires, path_wires, dir_wires, depth, root_wires);
    if (rc != 0) {
        free(path_wires);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    /* Assemble witness: leaf | path | dirs | inode_inv_in[*]. */
    size_t n_witness = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(n_witness > 0 ? n_witness : 1, 1);
    uint8_t *wp = witness;
    memcpy(wp, leaf_node, W);
    wp += W;
    memcpy(wp, siblings, depth * W);
    wp += depth * W;
    for (size_t k = 0; k < depth; k++)
        wp[k] = dirs[k];
    wp += depth;

    /* Walk the path to derive inode inv_in bytes level by level. */
    uint8_t current[MERKLE_VT_MAX_NODE_BYTES];
    memcpy(current, leaf_node, W);
    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;

        MUST_OK(vt->inode_build_witness(L, R, wp));
        wp += vt->inode_invin_bytes();

        uint8_t next[MERKLE_VT_MAX_NODE_BYTES];
        MUST_OK(vt->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
    assert((size_t)(wp - witness) == n_witness);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(n_wires > 0 ? n_wires : 1, 1);
    int eval_rc = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);

    int ok = (eval_rc == 1);
    if (ok) {
        for (size_t i = 0; i < W; i++)
            root_bytes_out[i] = wire_vals[root_wires[i]];
    }

    free(witness);
    free(wire_vals);
    free(path_wires);
    voleith_gf8_circuit_free(c);
    return ok ? 0 : -1;
}

static void
run_vt(const voleith_node_hash_vt *vt)
{
    size_t W = vt->node_bytes;
    printf("  %-22s W=%zu\n", vt->name, W);

    uint8_t *leaf_nodes = calloc(N_LEAVES, W);
    fill_leaf_nodes(leaf_nodes, N_LEAVES, W);

    /* 1. Build root and compare against the inline reference. */
    uint8_t root_ref[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t root_helper[MERKLE_VT_MAX_NODE_BYTES];
    reference_root(vt, leaf_nodes, N_LEAVES, root_ref);
    check("build returns 0",
          voleith_merkle_vt_build(vt, leaf_nodes, N_LEAVES, root_helper) == 0);
    check("build root matches inline reference",
          memcmp(root_helper, root_ref, W) == 0);

    /* 2. For each leaf index, compute path + drive secret-dir circuit. */
    for (size_t leaf = 0; leaf < N_LEAVES; leaf++) {
        uint8_t siblings[DEPTH * MERKLE_VT_MAX_NODE_BYTES];
        uint8_t dirs[DEPTH];
        for (size_t k = 0; k < DEPTH; k++)
            dirs[k] = (uint8_t)((leaf >> k) & 1u);

        int rc = voleith_merkle_vt_compute_path(vt, leaf_nodes, N_LEAVES, leaf,
                                                siblings);
        char label[64];
        snprintf(label, sizeof(label), "compute_path(leaf=%zu) returns 0",
                 leaf);
        check(label, rc == 0);

        uint8_t root_circ[MERKLE_VT_MAX_NODE_BYTES];
        int drc = drive_circuit(vt, leaf_nodes + leaf * W, siblings, dirs,
                                DEPTH, root_circ);
        snprintf(label, sizeof(label), "circuit eval ok (leaf=%zu)", leaf);
        check(label, drc == 0);

        if (drc == 0) {
            snprintf(label, sizeof(label),
                     "circuit root matches helper root (leaf=%zu)", leaf);
            check(label, memcmp(root_circ, root_ref, W) == 0);
        }
    }

    free(leaf_nodes);
}

static void
run_validation(void)
{
    printf("  argument validation\n");
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    uint8_t leaves[N_LEAVES * MERKLE_VT_MAX_NODE_BYTES] = {0};
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    uint8_t sibs[DEPTH * MERKLE_VT_MAX_NODE_BYTES] = {0};

    check("build rejects NULL vt",
          voleith_merkle_vt_build(NULL, leaves, N_LEAVES, root) == -1);
    check("build rejects NULL leaf_nodes",
          voleith_merkle_vt_build(vt, NULL, N_LEAVES, root) == -1);
    check("build rejects NULL root_out",
          voleith_merkle_vt_build(vt, leaves, N_LEAVES, NULL) == -1);
    check("build rejects n_leaves=0",
          voleith_merkle_vt_build(vt, leaves, 0, root) == -1);
    check("build rejects non-power-of-two n_leaves",
          voleith_merkle_vt_build(vt, leaves, 6, root) == -1);

    check("compute_path rejects NULL vt",
          voleith_merkle_vt_compute_path(NULL, leaves, N_LEAVES, 0, sibs) ==
              -1);
    check("compute_path rejects NULL leaf_nodes",
          voleith_merkle_vt_compute_path(vt, NULL, N_LEAVES, 0, sibs) == -1);
    check("compute_path rejects non-power-of-two n_leaves",
          voleith_merkle_vt_compute_path(vt, leaves, 6, 0, sibs) == -1);
    check("compute_path rejects leaf_index == n_leaves",
          voleith_merkle_vt_compute_path(vt, leaves, N_LEAVES, N_LEAVES,
                                         sibs) == -1);
    check("compute_path rejects leaf_index > n_leaves",
          voleith_merkle_vt_compute_path(vt, leaves, N_LEAVES, 999, sibs) ==
              -1);
    check("compute_path rejects NULL siblings_out when n_leaves > 1",
          voleith_merkle_vt_compute_path(vt, leaves, N_LEAVES, 0, NULL) == -1);

    /* n_leaves == 1: depth = 0, no siblings.  Both helpers should
     * succeed and build's root should be the (only) leaf node. */
    uint8_t one_leaf[MERKLE_VT_MAX_NODE_BYTES];
    for (size_t j = 0; j < vt->node_bytes; j++)
        one_leaf[j] = (uint8_t)(j + 1);
    check("build n_leaves=1 succeeds",
          voleith_merkle_vt_build(vt, one_leaf, 1, root) == 0);
    check("build n_leaves=1 root == leaf",
          memcmp(root, one_leaf, vt->node_bytes) == 0);
    check("compute_path n_leaves=1 succeeds (NULL siblings ok)",
          voleith_merkle_vt_compute_path(vt, one_leaf, 1, 0, NULL) == 0);
}

int
main(void)
{
    printf("test_merkle_vt_gf8_helpers\n");

    for (size_t i = 0; i < N_VTS; i++)
        run_vt(VTS[i]);

    run_validation();

    printf("\n%d/%d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
