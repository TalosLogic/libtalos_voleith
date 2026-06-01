/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_vt_gf8_equivalence.c - Branch B equivalence harness.
 *
 * For every existing-entry / equivalent-vt pairing in Branch A, build
 * two circuits on identical wire declarations:
 *   A: merkle_gf8_leaf_hash_circuit + merkle_gf8_path_circuit (or the
 *      Grøstl twin), reached through the fixed-hash entry's enum /
 *      variant parameter.
 *   B: merkle_vt_gf8_path_circuit (Branch B), reached through the
 *      voleith_node_hash_vt pointer that wraps the same hash family.
 *
 * Per docs/MERKLE_TREE_CIRCUITS_DESIGN.md "Branch B verification": for
 * each pairing, assert
 *   1. witness_count, mul_count, and assert_product_count are equal
 *      across both circuits.
 *   2. The same witness either satisfies all constraints in both
 *      circuits or fails in both.
 *   3. The two circuits agree on every output (root) wire byte under
 *      identical evaluation.
 *
 * Pairings covered (12 cases):
 *   {aes-dm, aes-cmac128, grostl256, grostl256_t27, grostl512,
 *    grostl512_t59} × {public-dir, secret-dir}
 *
 * AES-256-CMAC is intentionally NOT covered: the design doc keeps it
 * through 1.x via its fixed-hash entry only, with no vt
 * (strictly dominated by AES-128-CMAC).  Hirose has no fixed-hash
 * entry to compare against; the vts are its only implementation.
 */

#include "merkle_vt_gf8_circuit.h"
#include "merkle_gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
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
#define LEAF_DATA_BYTES 16u

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
 * Per-case dispatch: how to drive the fixed-hash entry point for
 * each pairing (AES family vs Grøstl family).
 *
 * The vt pointer drives the merkle_vt path uniformly.
 * ================================================================ */

typedef enum {
    FAMILY_AES, /* fixed-hash entry: merkle_gf8_*        with voleith_merkle_hash_t */
    FAMILY_GROSTL, /* fixed-hash entry: merkle_grostl_gf8_* with voleith_merkle_grostl_variant_t */
} fixed_family_t;

typedef struct {
    const char *name;
    const voleith_node_hash_vt *vt;
    fixed_family_t family;
    int fixed_enum; /* voleith_merkle_hash_t   (FAMILY_AES) or
                       voleith_merkle_grostl_variant_t (FAMILY_GROSTL) */
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
 * Circuit builders.  All four (fixed/vt × public/secret) declare
 * wires in the SAME order so the witness layout matches across A/B:
 *
 *   leaf_data wires      (LEAF_DATA_BYTES witnesses)
 *   path_nodes wires     (DEPTH * node_bytes witnesses)
 *   [secret-dir only] dir wires (DEPTH witnesses)
 *   then the leaf/inode hash circuits add their inv_in witnesses
 *   internally, in left-to-right hash-call order.
 *
 * Witness layout (matches the wire-declaration order above):
 *   leaf_data | path_nodes | [dirs] | leaf_inv_in | inode_inv_in[0..D-1]
 *
 * The root output wire IDs are returned via *root_out_wires (the test
 * indexes them in wire_vals after voleith_gf8_circuit_eval).
 * ================================================================ */

/*
 * Drive the fixed-hash entry point for a family / variant.  Returns
 * via root_out_wires the node_bytes root wire IDs.
 */
static void
build_circuit_fixed(
    voleith_gf8_circuit_t *c, const equiv_case_t *cs,
    const gf8_wire_id *leaf_wires, size_t leaf_data_bytes,
    const gf8_wire_id *path_node_wires, const uint8_t *path_dirs_public,
    const gf8_wire_id *path_dirs_secret /* NULL for public-dir */, size_t depth,
    gf8_wire_id *root_out_wires)
{
    size_t W = cs->vt->node_bytes;
    gf8_wire_id leaf_hash_wires[64];

    if (cs->family == FAMILY_AES) {
        voleith_merkle_hash_t hash = (voleith_merkle_hash_t)cs->fixed_enum;
        merkle_gf8_leaf_hash_circuit(c, leaf_data_bytes ? leaf_wires : NULL,
                                     leaf_data_bytes, hash, leaf_hash_wires);
        if (path_dirs_secret) {
            merkle_gf8_path_circuit_secret_dir(
                c, leaf_hash_wires, path_node_wires, path_dirs_secret, depth,
                hash, root_out_wires);
        } else {
            merkle_gf8_path_circuit(c, leaf_hash_wires, path_node_wires,
                                    path_dirs_public, depth, hash,
                                    root_out_wires);
        }
    } else {
        voleith_merkle_grostl_variant_t variant =
            (voleith_merkle_grostl_variant_t)cs->fixed_enum;
        merkle_grostl_gf8_leaf_hash_circuit(
            c, leaf_data_bytes ? leaf_wires : NULL, leaf_data_bytes, variant,
            leaf_hash_wires);
        if (path_dirs_secret) {
            merkle_grostl_gf8_path_circuit_secret_dir(
                c, leaf_hash_wires, path_node_wires, path_dirs_secret, depth,
                variant, root_out_wires);
        } else {
            merkle_grostl_gf8_path_circuit(c, leaf_hash_wires, path_node_wires,
                                           path_dirs_public, depth, variant,
                                           root_out_wires);
        }
    }
    (void)W;
}

static void
build_circuit_vt(voleith_gf8_circuit_t *c, const equiv_case_t *cs,
                 const gf8_wire_id *leaf_wires, size_t leaf_data_bytes,
                 const gf8_wire_id *path_node_wires,
                 const uint8_t *path_dirs_public,
                 const gf8_wire_id *path_dirs_secret, size_t depth,
                 gf8_wire_id *root_out_wires)
{
    int rc;
    if (path_dirs_secret) {
        rc = merkle_vt_gf8_path_circuit_secret_dir(
            c, cs->vt, leaf_data_bytes ? leaf_wires : NULL, leaf_data_bytes,
            path_node_wires, path_dirs_secret, depth, root_out_wires);
    } else {
        rc = merkle_vt_gf8_path_circuit(
            c, cs->vt, leaf_data_bytes ? leaf_wires : NULL, leaf_data_bytes,
            path_node_wires, path_dirs_public, depth, root_out_wires);
    }
    (void)rc;
    assert(rc == 0);
}

/* ================================================================
 * Software helpers (drive the vt's own leaf_hash / inode_hash).
 * ================================================================ */

/*
 * Build a depth-D Merkle tree over N_LEAVES leaves using the vt's
 * software helpers; emit the root, the chosen leaf's path siblings,
 * and the chosen leaf's direction bits.
 */
static void
build_software_tree(const voleith_node_hash_vt *h, size_t depth,
                    size_t n_leaves, size_t target_leaf,
                    const uint8_t leaves[][LEAF_DATA_BYTES], uint8_t *root_out,
                    uint8_t *siblings_out, /* depth * node_bytes */
                    uint8_t *dirs_out /* depth */)
{
    size_t W = h->node_bytes;

    /* layer[0]: leaf hashes; layer[k+1]: parent of layer[k]. */
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

/*
 * Assemble the witness vector for either circuit (the wire layout is
 * identical, so the same witness drives both).
 *
 *   leaf_data | path_nodes | [dirs] | leaf_inv_in | inode_inv_in[0..D-1]
 */
static void
build_witness(const voleith_node_hash_vt *h, const uint8_t *leaf_data,
              size_t depth, const uint8_t *siblings, const uint8_t *dirs,
              int secret_dir, uint8_t *witness)
{
    size_t W = h->node_bytes;
    uint8_t *wp = witness;

    /* 1. leaf_data */
    memcpy(wp, leaf_data, LEAF_DATA_BYTES);
    wp += LEAF_DATA_BYTES;

    /* 2. path_nodes (all siblings, concatenated) */
    memcpy(wp, siblings, depth * W);
    wp += depth * W;

    /* 3. dirs (secret-dir only) */
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++)
            wp[k] = dirs[k];
        wp += depth;
    }

    /* 4. leaf inv_in */
    MUST_OK(h->leaf_build_witness(leaf_data, LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(LEAF_DATA_BYTES);

    /* 5. inode inv_in per level (walk the path) */
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
    size_t target = 5; /* arbitrary leaf in a depth-3 tree */

    printf("  %-15s %s\n", cs->name, secret_dir ? "secret-dir" : "public-dir");

    /* Make N_LEAVES distinct leaf records. */
    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (size_t i = 0; i < N_LEAVES; i++)
        for (size_t j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 16 + j);

    uint8_t root_sw[64];
    uint8_t *siblings = calloc(depth, W);
    uint8_t dirs[16];
    build_software_tree(cs->vt, depth, N_LEAVES, target, leaves, root_sw,
                        siblings, dirs);

    /* ------------------------------------------------------------------
     * Build both circuits with identical wire-declaration order.
     * ------------------------------------------------------------------ */

    voleith_gf8_circuit_t *cA = voleith_gf8_circuit_new();
    voleith_gf8_circuit_t *cB = voleith_gf8_circuit_new();

    gf8_wire_id leaf_wires_A[LEAF_DATA_BYTES], leaf_wires_B[LEAF_DATA_BYTES];
    for (size_t i = 0; i < LEAF_DATA_BYTES; i++) {
        leaf_wires_A[i] = voleith_gf8_add_witness(cA);
        leaf_wires_B[i] = voleith_gf8_add_witness(cB);
    }

    gf8_wire_id *path_wires_A = calloc(depth * W, sizeof(gf8_wire_id));
    gf8_wire_id *path_wires_B = calloc(depth * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < depth * W; i++) {
        path_wires_A[i] = voleith_gf8_add_witness(cA);
        path_wires_B[i] = voleith_gf8_add_witness(cB);
    }

    gf8_wire_id dir_wires_A[16], dir_wires_B[16];
    if (secret_dir) {
        for (size_t k = 0; k < depth; k++) {
            dir_wires_A[k] = voleith_gf8_add_witness(cA);
            dir_wires_B[k] = voleith_gf8_add_witness(cB);
        }
    }

    gf8_wire_id root_wires_A[64], root_wires_B[64];
    build_circuit_fixed(cA, cs, leaf_wires_A, LEAF_DATA_BYTES, path_wires_A,
                        dirs, secret_dir ? dir_wires_A : NULL, depth,
                        root_wires_A);
    build_circuit_vt(cB, cs, leaf_wires_B, LEAF_DATA_BYTES, path_wires_B, dirs,
                     secret_dir ? dir_wires_B : NULL, depth, root_wires_B);

    /* ------------------------------------------------------------------
     * Equivalence assertions (1): counts.
     * ------------------------------------------------------------------ */

    size_t wA = voleith_gf8_circuit_witness_count(cA);
    size_t wB = voleith_gf8_circuit_witness_count(cB);
    size_t mA = voleith_gf8_circuit_mul_count(cA);
    size_t mB = voleith_gf8_circuit_mul_count(cB);
    size_t aA = voleith_gf8_circuit_assert_product_count(cA);
    size_t aB = voleith_gf8_circuit_assert_product_count(cB);
    size_t kA = voleith_gf8_circuit_constraint_count(cA);
    size_t kB = voleith_gf8_circuit_constraint_count(cB);

    check("witness_count matches", wA == wB);
    check("mul_count matches", mA == mB);
    check("assert_product_count matches", aA == aB);
    check("constraint_count matches", kA == kB);

    /* ------------------------------------------------------------------
     * Equivalence assertions (2) + (3): same witness, same eval result,
     * same root wire values.
     * ------------------------------------------------------------------ */

    uint8_t *witness = calloc(wA > 0 ? wA : 1, 1);
    build_witness(cs->vt, leaves[target], depth, siblings, dirs, secret_dir,
                  witness);

    size_t nW_A = voleith_gf8_circuit_wire_count(cA);
    size_t nW_B = voleith_gf8_circuit_wire_count(cB);
    uint8_t *wireA = calloc(nW_A > 0 ? nW_A : 1, 1);
    uint8_t *wireB = calloc(nW_B > 0 ? nW_B : 1, 1);

    int okA = voleith_gf8_circuit_eval(cA, witness, NULL, wireA);
    int okB = voleith_gf8_circuit_eval(cB, witness, NULL, wireB);

    check("circuit A satisfied by vt-built witness", okA == 1);
    check("circuit B satisfied by vt-built witness", okB == 1);

    /* Roots agree byte-for-byte, and match the software-computed root. */
    int roots_eq_AB = 1, roots_eq_sw = 1;
    for (size_t i = 0; i < W; i++) {
        if (wireA[root_wires_A[i]] != wireB[root_wires_B[i]])
            roots_eq_AB = 0;
        if (wireA[root_wires_A[i]] != root_sw[i])
            roots_eq_sw = 0;
    }
    check("root wires agree byte-for-byte across A and B", roots_eq_AB);
    check("root matches software-computed root", roots_eq_sw);

    /* ------------------------------------------------------------------
     * Tamper test: corrupt the FIRST inv_in byte (a leaf-side S-box
     * inversion).  Both circuits must reject the witness.  This guards
     * against an A/B divergence where one path stops checking a region
     * that the other still checks.
     * ------------------------------------------------------------------ */

    size_t tamper_off = LEAF_DATA_BYTES + depth * W + (secret_dir ? depth : 0);
    if (tamper_off < wA) {
        witness[tamper_off] ^= 0x01;
        int badA = voleith_gf8_circuit_eval(cA, witness, NULL, wireA);
        int badB = voleith_gf8_circuit_eval(cB, witness, NULL, wireB);
        check("tampered inv_in rejected by A", badA == 0);
        check("tampered inv_in rejected by B", badB == 0);
        witness[tamper_off] ^= 0x01;
    }

    free(wireA);
    free(wireB);
    free(witness);
    free(path_wires_A);
    free(path_wires_B);
    free(siblings);
    voleith_gf8_circuit_free(cA);
    voleith_gf8_circuit_free(cB);
}

int
main(void)
{
    printf("=== Merkle vt equivalence (Branch B) ===\n");

    for (size_t i = 0; i < N_CASES; i++) {
        run_case(&CASES[i], 0); /* public-dir */
        run_case(&CASES[i], 1); /* secret-dir */
    }

    printf("\n%d / %d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
