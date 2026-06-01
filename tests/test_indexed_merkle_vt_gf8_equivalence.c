/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_indexed_merkle_vt_gf8_equivalence.c - Branch C equivalence harness.
 *
 * For every existing-entry / equivalent-vt pairing, build two circuits
 * on identical wire declarations:
 *   A: indexed_merkle_gf8_nonmember_circuit (AES family) or
 *      indexed_merkle_grostl_gf8_nonmember_circuit (Grøstl family),
 *      reached through the fixed-hash entry's enum / variant parameter.
 *   B: merkle_vt_gf8_indexed_nonmember_circuit (Branch C), reached
 *      through the voleith_node_hash_vt pointer that wraps the same
 *      hash family.
 *
 * Per docs/MERKLE_TREE_CIRCUITS_DESIGN.md Branch C: same verification
 * shape as Branch B - asserts bit-exact agreement between fixed-hash
 * and vt+generic for every existing-entry / equivalent-vt pair, both
 * direction-bit flavors.
 *
 * Pairings covered (12 cases):
 *   {aes-dm, aes-cmac128, grostl256, grostl256_t27, grostl512,
 *    grostl512_t59} × {public-dir, secret-dir}
 */

#include "indexed_merkle_vt_gf8_circuit.h"
#include "indexed_merkle_gf8_circuit.h"
#include "indexed_merkle_grostl_gf8_circuit.h"
#include "node_hash_vt.h"
#include "../proof/gf8_circuit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Wraps a (possibly fallible) call so the function is ALWAYS evaluated,
 * even when NDEBUG elides assert().  `assert(fn(...) == 0)` would drop
 * the call entirely under -DNDEBUG (Release builds). */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

#define DEPTH 3
#define N_LEAVES (1u << DEPTH)
#define TARGET_BYTES 1
#define INDEX_BYTES 1
#define LEAF_DATA_BYTES (2 * TARGET_BYTES + INDEX_BYTES)

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
 * Per-case dispatch (same shape as Branch B).
 * ================================================================ */

typedef enum {
    FAMILY_AES,
    FAMILY_GROSTL,
} fixed_family_t;

typedef struct {
    const char *name;
    const voleith_node_hash_vt *vt;
    fixed_family_t family;
    int fixed_enum;
} equiv_case_t;

static const equiv_case_t CASES[] = {
    {"aes-dm", &voleith_node_hash_aes_dm, FAMILY_AES,
     VOLEITH_MERKLE_HASH_AES_DM},
    {"aes-cmac128", &voleith_node_hash_aes_cmac128, FAMILY_AES,
     VOLEITH_MERKLE_HASH_AES_CMAC},
    {"grostl256", &voleith_node_hash_grostl256, FAMILY_GROSTL,
     VOLEITH_MERKLE_GROSTL_256},
    {"grostl256_t27", &voleith_node_hash_grostl256_t27, FAMILY_GROSTL,
     VOLEITH_MERKLE_GROSTL_256_T27},
    {"grostl512", &voleith_node_hash_grostl512, FAMILY_GROSTL,
     VOLEITH_MERKLE_GROSTL_512},
    {"grostl512_t59", &voleith_node_hash_grostl512_t59, FAMILY_GROSTL,
     VOLEITH_MERKLE_GROSTL_512_T59},
};
#define N_CASES (sizeof(CASES) / sizeof(CASES[0]))

/* ================================================================
 * Indexed tree:
 *   Leaf i: value = 10 + 10*i, next_value = 10 + 10*(i+1), next_index = i+1
 *   Leaf N_LEAVES-1: next_value = 255 (sentinel), next_index = 0
 *
 * Target = 35: lies strictly between leaf[2] (value=30, next_value=40)
 * and its next_value=40.  Adjacent leaf for non-membership = leaf[2].
 * ================================================================ */

#define TARGET_VAL 35
#define ADJ_LEAF_INDEX 2
#define LOW_VALUE_VAL 30
#define LOW_NEXT_VAL 40
#define NEXT_INDEX_VAL 3

static void
fill_indexed_leaves(uint8_t leaves[][LEAF_DATA_BYTES])
{
    for (size_t i = 0; i < N_LEAVES; i++) {
        uint8_t value = (uint8_t)(10 + 10 * i);
        uint8_t next_value =
            (i == N_LEAVES - 1) ? 255 : (uint8_t)(10 + 10 * (i + 1));
        uint8_t next_index = (i == N_LEAVES - 1) ? 0 : (uint8_t)(i + 1);
        leaves[i][0] = value;
        leaves[i][1] = next_value;
        leaves[i][2] = next_index;
    }
}

/* ================================================================
 * Software helpers (drive the vt's own leaf_hash / inode_hash).
 * ================================================================ */

static void
build_software_tree(const voleith_node_hash_vt *h, size_t depth,
                    size_t n_leaves, size_t target_leaf,
                    const uint8_t leaves[][LEAF_DATA_BYTES], uint8_t *root_out,
                    uint8_t *siblings_out, uint8_t *dirs_out)
{
    size_t W = h->node_bytes;

    uint8_t *layer[16];
    for (size_t k = 0; k <= depth; k++)
        layer[k] = calloc((n_leaves >> k) > 0 ? (n_leaves >> k) : 1, W);

    for (size_t i = 0; i < n_leaves; i++)
        MUST_OK(h->leaf_hash(leaves[i], LEAF_DATA_BYTES, layer[0] + i * W));

    for (size_t k = 0; k < depth; k++) {
        size_t n_parents = n_leaves >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(h->inode_hash(layer[k] + (2 * j) * W,
                                  layer[k] + (2 * j + 1) * W,
                                  layer[k + 1] + j * W));
    }

    memcpy(root_out, layer[depth], W);

    for (size_t k = 0; k < depth; k++) {
        size_t cur = target_leaf >> k;
        dirs_out[k] = (uint8_t)(cur & 1u);
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }

    for (size_t k = 0; k <= depth; k++)
        free(layer[k]);
}

/* ================================================================
 * Circuit builders (declare wires in the same order for A and B):
 *   target | low_value | low_next | next_index | path_nodes | [dirs]
 *   then call the indexed circuit (which adds leaf inv_in then per-level
 *   inode inv_in internally).
 *
 * Witness layout matches that order; layout is identical across A/B.
 * ================================================================ */

static int
build_circuit_fixed(
    voleith_gf8_circuit_t *c, const equiv_case_t *cs, const gf8_wire_id *target,
    const gf8_wire_id *low_value, const gf8_wire_id *low_next,
    const gf8_wire_id *next_index, const gf8_wire_id *path_nodes,
    const uint8_t *path_dirs_public,
    const gf8_wire_id *path_dirs_secret /* NULL for public-dir */, size_t depth,
    gf8_wire_id *root_out)
{
    if (cs->family == FAMILY_AES) {
        voleith_merkle_hash_t hash = (voleith_merkle_hash_t)cs->fixed_enum;
        if (path_dirs_secret) {
            return indexed_merkle_gf8_nonmember_circuit_secret_dir(
                c, target, TARGET_BYTES, low_value, low_next, next_index,
                INDEX_BYTES, path_nodes, path_dirs_secret, depth, hash,
                root_out);
        } else {
            return indexed_merkle_gf8_nonmember_circuit(
                c, target, TARGET_BYTES, low_value, low_next, next_index,
                INDEX_BYTES, path_nodes, path_dirs_public, depth, hash,
                root_out);
        }
    } else {
        voleith_merkle_grostl_variant_t variant =
            (voleith_merkle_grostl_variant_t)cs->fixed_enum;
        if (path_dirs_secret) {
            return indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
                c, target, TARGET_BYTES, low_value, low_next, next_index,
                INDEX_BYTES, path_nodes, path_dirs_secret, depth, variant,
                root_out);
        } else {
            return indexed_merkle_grostl_gf8_nonmember_circuit(
                c, target, TARGET_BYTES, low_value, low_next, next_index,
                INDEX_BYTES, path_nodes, path_dirs_public, depth, variant,
                root_out);
        }
    }
}

static int
build_circuit_vt(voleith_gf8_circuit_t *c, const equiv_case_t *cs,
                 const gf8_wire_id *target, const gf8_wire_id *low_value,
                 const gf8_wire_id *low_next, const gf8_wire_id *next_index,
                 const gf8_wire_id *path_nodes, const uint8_t *path_dirs_public,
                 const gf8_wire_id *path_dirs_secret, size_t depth,
                 gf8_wire_id *root_out)
{
    if (path_dirs_secret) {
        return merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
            c, cs->vt, target, TARGET_BYTES, low_value, low_next, next_index,
            INDEX_BYTES, path_nodes, path_dirs_secret, depth, root_out);
    } else {
        return merkle_vt_gf8_indexed_nonmember_circuit(
            c, cs->vt, target, TARGET_BYTES, low_value, low_next, next_index,
            INDEX_BYTES, path_nodes, path_dirs_public, depth, root_out);
    }
}

/* ================================================================
 * Witness assembly (identical layout for A and B).
 *
 *   target | low_value | low_next | next_index
 *   | path_nodes
 *   | [dirs (secret-dir only)]
 *   | leaf inv_in           (h->leaf_invin_bytes(LEAF_DATA_BYTES))
 *   | per-level inode inv_in  (h->inode_invin_bytes() each)
 * ================================================================ */

static void
build_witness(const voleith_node_hash_vt *h, uint8_t target_val,
              uint8_t low_value_val, uint8_t low_next_val,
              uint8_t next_index_val, size_t depth, const uint8_t *siblings,
              const uint8_t *dirs, int secret_dir, uint8_t *witness)
{
    size_t W = h->node_bytes;
    uint8_t *wp = witness;

    *wp++ = target_val;
    *wp++ = low_value_val;
    *wp++ = low_next_val;
    *wp++ = next_index_val;

    memcpy(wp, siblings, depth * W);
    wp += depth * W;

    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            wp[k] = dirs[k];
        wp += depth;
    }

    /* leaf inv_in - leaf_data = low_value || low_next || next_index */
    uint8_t leaf_data[LEAF_DATA_BYTES] = {low_value_val, low_next_val,
                                          next_index_val};
    MUST_OK(h->leaf_build_witness(leaf_data, LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(LEAF_DATA_BYTES);

    /* per-level inode inv_in */
    uint8_t current[64];
    MUST_OK(h->leaf_hash(leaf_data, LEAF_DATA_BYTES, current));

    for (size_t k = 0; k < depth; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;

        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();

        uint8_t next[64];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }
}

/* ================================================================
 * Run one pairing.
 * ================================================================ */

static void
run_case(const equiv_case_t *cs, int secret_dir)
{
    size_t W = cs->vt->node_bytes;
    size_t depth = DEPTH;

    printf("  %-15s %s\n", cs->name, secret_dir ? "secret-dir" : "public-dir");

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    fill_indexed_leaves(leaves);

    uint8_t root_sw[64];
    uint8_t *siblings = calloc(depth, W);
    uint8_t dirs[16];
    build_software_tree(cs->vt, depth, N_LEAVES, ADJ_LEAF_INDEX, leaves,
                        root_sw, siblings, dirs);

    /* Build both circuits with identical wire-declaration order:
     *   target | low_value | low_next | next_index | path_nodes | [dirs] */
    voleith_gf8_circuit_t *cA = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *cB = voleith_gf8_circuit_new();

    gf8_wire_id tgt_A[TARGET_BYTES], tgt_B[TARGET_BYTES];
    gf8_wire_id lv_A[TARGET_BYTES], lv_B[TARGET_BYTES];
    gf8_wire_id ln_A[TARGET_BYTES], ln_B[TARGET_BYTES];
    gf8_wire_id ni_A[INDEX_BYTES], ni_B[INDEX_BYTES];

    for (size_t i = 0; i < TARGET_BYTES; i++) {
        tgt_A[i] = voleith_gf8_add_witness(cA);
        tgt_B[i] = voleith_gf8_add_witness(cB);
    }
    for (size_t i = 0; i < TARGET_BYTES; i++) {
        lv_A[i] = voleith_gf8_add_witness(cA);
        lv_B[i] = voleith_gf8_add_witness(cB);
    }
    for (size_t i = 0; i < TARGET_BYTES; i++) {
        ln_A[i] = voleith_gf8_add_witness(cA);
        ln_B[i] = voleith_gf8_add_witness(cB);
    }
    for (size_t i = 0; i < INDEX_BYTES; i++) {
        ni_A[i] = voleith_gf8_add_witness(cA);
        ni_B[i] = voleith_gf8_add_witness(cB);
    }

    gf8_wire_id *path_A = calloc(depth * W, sizeof(gf8_wire_id));
    gf8_wire_id *path_B = calloc(depth * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < depth * W; i++) {
        path_A[i] = voleith_gf8_add_witness(cA);
        path_B[i] = voleith_gf8_add_witness(cB);
    }

    gf8_wire_id dir_A[16], dir_B[16];
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++) {
            dir_A[k] = voleith_gf8_add_witness(cA);
            dir_B[k] = voleith_gf8_add_witness(cB);
        }
    }

    gf8_wire_id root_A[64], root_B[64];
    int rA = build_circuit_fixed(cA, cs, tgt_A, lv_A, ln_A, ni_A, path_A, dirs,
                                 secret_dir ? dir_A : NULL, depth, root_A);
    int rB = build_circuit_vt(cB, cs, tgt_B, lv_B, ln_B, ni_B, path_B, dirs,
                              secret_dir ? dir_B : NULL, depth, root_B);

    check("fixed-hash circuit built", rA == 0);
    check("vt+generic circuit built", rB == 0);

    /* Counts. */
    check("witness_count matches", voleith_gf8_circuit_witness_count(cA) ==
                                       voleith_gf8_circuit_witness_count(cB));
    check("mul_count matches", voleith_gf8_circuit_mul_count(cA) ==
                                   voleith_gf8_circuit_mul_count(cB));
    check("assert_product_count matches",
          voleith_gf8_circuit_assert_product_count(cA) ==
              voleith_gf8_circuit_assert_product_count(cB));
    check("constraint_count matches",
          voleith_gf8_circuit_constraint_count(cA) ==
              voleith_gf8_circuit_constraint_count(cB));

    /* Same witness, same eval result, same root. */
    size_t wA = voleith_gf8_circuit_witness_count(cA);
    uint8_t *witness = calloc(wA > 0 ? wA : 1, 1);
    build_witness(cs->vt, TARGET_VAL, LOW_VALUE_VAL, LOW_NEXT_VAL,
                  NEXT_INDEX_VAL, depth, siblings, dirs, secret_dir, witness);

    size_t nW_A = voleith_gf8_circuit_wire_count(cA);
    size_t nW_B = voleith_gf8_circuit_wire_count(cB);
    uint8_t *wireA = calloc(nW_A > 0 ? nW_A : 1, 1);
    uint8_t *wireB = calloc(nW_B > 0 ? nW_B : 1, 1);

    int okA = voleith_gf8_circuit_eval(cA, witness, NULL, wireA);
    int okB = voleith_gf8_circuit_eval(cB, witness, NULL, wireB);

    check("circuit A satisfied by vt-built witness", okA == 1);
    check("circuit B satisfied by vt-built witness", okB == 1);

    int roots_eq_AB = 1, roots_eq_sw = 1;
    for (size_t i = 0; i < W; i++) {
        if (wireA[root_A[i]] != wireB[root_B[i]])
            roots_eq_AB = 0;
        if (wireA[root_A[i]] != root_sw[i])
            roots_eq_sw = 0;
    }
    check("root wires agree byte-for-byte across A and B", roots_eq_AB);
    check("root matches software-computed root", roots_eq_sw);

    /* Tamper test: corrupt the FIRST byte of leaf inv_in.  Both
     * circuits must reject. */
    size_t tamper_off =
        4 /* target+lv+ln+ni */ + depth * W + (secret_dir ? depth : 0);
    if (tamper_off < wA) {
        witness[tamper_off] ^= 0x01;
        int badA = voleith_gf8_circuit_eval(cA, witness, NULL, wireA);
        int badB = voleith_gf8_circuit_eval(cB, witness, NULL, wireB);
        check("tampered inv_in rejected by A", badA == 0);
        check("tampered inv_in rejected by B", badB == 0);
        witness[tamper_off] ^= 0x01;
    }

    /* Tamper test: corrupt the target field so that low_value < target
     * fails.  Set target = 30 (= low_value), so target < low_next holds
     * but low_value < target does NOT.  Both circuits must reject via
     * the shared indexed_merkle_gf8_assert_lt comparison. */
    uint8_t saved_target = witness[0];
    witness[0] = LOW_VALUE_VAL;
    int badA_ord = voleith_gf8_circuit_eval(cA, witness, NULL, wireA);
    int badB_ord = voleith_gf8_circuit_eval(cB, witness, NULL, wireB);
    check("ordering violation rejected by A", badA_ord == 0);
    check("ordering violation rejected by B", badB_ord == 0);
    witness[0] = saved_target;

    free(wireA);
    free(wireB);
    free(witness);
    free(path_A);
    free(path_B);
    free(siblings);
    voleith_gf8_circuit_free(cA);
    voleith_gf8_circuit_free(cB);
}

int
main(void)
{
    printf("=== Indexed Merkle vt equivalence (Branch C) ===\n");

    for (size_t i = 0; i < N_CASES; i++) {
        run_case(&CASES[i], 0); /* public-dir */
        run_case(&CASES[i], 1); /* secret-dir */
    }

    printf("\n%d / %d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
