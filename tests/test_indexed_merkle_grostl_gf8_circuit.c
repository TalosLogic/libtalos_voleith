/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_indexed_merkle_grostl_gf8_circuit.c - Tests for the wide-node
 * Grøstl indexed Merkle non-membership circuit
 * (circuits/indexed_merkle_grostl_gf8_circuit).
 *
 * Test tree: 8 sorted leaves (values 10,20,...,80), 1-byte values and
 * indices.  Leaf i: (value=10+10i, next_value=10+10*(i+1), next_index=i+1);
 * leaf 7 uses next_value=255 (sentinel), next_index=0.  Leaf data hashed
 * is [value, next_value, next_index] (3 bytes).  Depth = 3.
 *
 * Validates (public-dir variant):
 *   - VOLE slot count (ell) matches the structural expectation derived
 *     from the Grøstl sizing helpers (GROSTL_256, depth 3).
 *   - Correctness: circuit-computed root equals the software-built root
 *     for GROSTL_256, GROSTL_256_T27, and GROSTL_512, across leaf
 *     indices exercising all three direction bits.
 *   - Ordering soundness: a target outside (low_value, low_next) makes
 *     the circuit reject, with every hash witness still consistent so
 *     the only failing constraint is the range check.
 *   - Field binding: a wrong next_index yields a different root.
 *   - CIR-2: the stack-VLA bound is signalled as a -1 return.
 */

#include "indexed_merkle_grostl_gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
#include "../proof/gf8_circuit.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

#define DEPTH 3
#define N_LEAVES 8

typedef struct {
    uint8_t value;
    uint8_t next_value;
    uint8_t next_index;
} leaf_rec_t;

static const leaf_rec_t LEAVES[N_LEAVES] = {
    {10, 20, 1}, {20, 30, 2}, {30, 40, 3}, {40, 50, 4},
    {50, 60, 5}, {60, 70, 6}, {70, 80, 7}, {80, 255, 0},
};

/* ================================================================
 * Software reference tree (8 leaves, depth 3).
 *
 * Returns the root and the sibling path (DEPTH * nb) for leaf_index.
 * ================================================================ */

static void
build_tree(voleith_merkle_grostl_variant_t variant, size_t leaf_index,
           uint8_t *root_out /* nb */, uint8_t *siblings_out /* DEPTH * nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t lh[N_LEAVES][64];
    for (int i = 0; i < N_LEAVES; i++) {
        uint8_t d[3] = {LEAVES[i].value, LEAVES[i].next_value,
                        LEAVES[i].next_index};
        merkle_grostl_leaf_hash(d, 3, variant, lh[i]);
    }

    uint8_t l1[4][64];
    for (int i = 0; i < 4; i++)
        merkle_grostl_inode_hash(lh[2 * i], lh[2 * i + 1], variant, l1[i]);

    uint8_t l2[2][64];
    for (int i = 0; i < 2; i++)
        merkle_grostl_inode_hash(l1[2 * i], l1[2 * i + 1], variant, l2[i]);

    uint8_t root[64];
    merkle_grostl_inode_hash(l2[0], l2[1], variant, root);

    size_t i0 = leaf_index & 1;
    size_t i1 = (leaf_index >> 1) & 1;
    size_t i2 = (leaf_index >> 2) & 1;

    memcpy(siblings_out + 0 * nb, lh[(leaf_index & ~(size_t)1) | (i0 ^ 1)], nb);
    size_t l1_idx = leaf_index >> 1;
    memcpy(siblings_out + 1 * nb, l1[(l1_idx & ~(size_t)1) | (i1 ^ 1)], nb);
    size_t l2_idx = leaf_index >> 2;
    memcpy(siblings_out + 2 * nb, l2[(l2_idx & ~(size_t)1) | (i2 ^ 1)], nb);

    memcpy(root_out, root, nb);
}

/* ================================================================
 * Build + evaluate the depth-3 non-membership circuit.
 *
 * All caller-supplied inputs are witness wires.  1-byte target /
 * low_value / low_next / next_index.  Witness layout (declaration
 * order):
 *   [target][low_value][low_next][next_index]
 *   [path_nodes: DEPTH * nb]
 *   [leaf-hash inv_in]
 *   [per-level inode inv_in]
 * (the ordering comparison adds mul-slots and constant wires, no witness.)
 * ================================================================ */

static int
eval_nonmember(voleith_merkle_grostl_variant_t variant, uint8_t target_val,
               uint8_t low_value_val, uint8_t low_next_val,
               uint8_t next_index_val, const uint8_t *siblings /* DEPTH * nb */,
               const uint8_t path_dirs[DEPTH], uint8_t *root_out /* nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return -1;

    gf8_wire_id tgt_w[1], lv_w[1], ln_w[1], ni_w[1];
    tgt_w[0] = voleith_gf8_add_witness(c);
    lv_w[0] = voleith_gf8_add_witness(c);
    ln_w[0] = voleith_gf8_add_witness(c);
    ni_w[0] = voleith_gf8_add_witness(c);

    gf8_wire_id *pn_w = malloc(DEPTH * nb * sizeof(*pn_w));
    for (size_t i = 0; i < DEPTH * nb; i++)
        pn_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[64];
    int rc = indexed_merkle_grostl_gf8_nonmember_circuit(
        c, tgt_w, 1, lv_w, ln_w, ni_w, 1, pn_w, path_dirs, DEPTH, variant,
        root_w);
    if (rc != 0) {
        free(pn_w);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    /* ----- assemble the witness ----- */
    size_t leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(3, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);
    size_t total = 4 + DEPTH * nb + leaf_invin + DEPTH * inode_invin;

    uint8_t *witness = calloc(total, 1);
    uint8_t *wp = witness;

    *wp++ = target_val;
    *wp++ = low_value_val;
    *wp++ = low_next_val;
    *wp++ = next_index_val;

    memcpy(wp, siblings, DEPTH * nb);
    wp += DEPTH * nb;

    uint8_t leaf_data[3] = {low_value_val, low_next_val, next_index_val};
    merkle_grostl_gf8_leaf_build_witness(leaf_data, 3, variant, wp);
    wp += leaf_invin;

    uint8_t current[64];
    merkle_grostl_leaf_hash(leaf_data, 3, variant, current);

    for (size_t lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + lvl * nb;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_grostl_gf8_inode_build_witness(L, R, variant, wp);
        wp += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    /* ----- evaluate ----- */
    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (size_t i = 0; i < nb; i++)
        root_out[i] = vals[root_w[i]];

    free(vals);
    free(witness);
    free(pn_w);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Secret-dir evaluation: path_dirs are private witness wires, muxed
 * in-circuit.  Witness layout inserts the depth direction bytes after
 * the sibling block and before the internal inv_in:
 *   [target][low_value][low_next][next_index]
 *   [path_nodes: DEPTH * nb]
 *   [direction bits: DEPTH]
 *   [leaf-hash inv_in][per-level inode inv_in]
 * Correctness/equivalence/binding tests use 0/1 dirs, so the L/R swap
 * (dir ? sib : current) matches the in-circuit mux.
 * ================================================================ */

static int
eval_nonmember_secret_dir(voleith_merkle_grostl_variant_t variant,
                          uint8_t target_val, uint8_t low_value_val,
                          uint8_t low_next_val, uint8_t next_index_val,
                          const uint8_t *siblings /* DEPTH * nb */,
                          const uint8_t path_dirs[DEPTH],
                          uint8_t *root_out /* nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return -1;

    gf8_wire_id tgt_w[1], lv_w[1], ln_w[1], ni_w[1];
    tgt_w[0] = voleith_gf8_add_witness(c);
    lv_w[0] = voleith_gf8_add_witness(c);
    ln_w[0] = voleith_gf8_add_witness(c);
    ni_w[0] = voleith_gf8_add_witness(c);

    gf8_wire_id *pn_w = malloc(DEPTH * nb * sizeof(*pn_w));
    for (size_t i = 0; i < DEPTH * nb; i++)
        pn_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id pd_w[DEPTH];
    for (size_t i = 0; i < DEPTH; i++)
        pd_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[64];
    int rc = indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
        c, tgt_w, 1, lv_w, ln_w, ni_w, 1, pn_w, pd_w, DEPTH, variant, root_w);
    if (rc != 0) {
        free(pn_w);
        voleith_gf8_circuit_free(c);
        return -1;
    }

    size_t leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(3, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);
    size_t total = 4 + DEPTH * nb + DEPTH + leaf_invin + DEPTH * inode_invin;

    uint8_t *witness = calloc(total, 1);
    uint8_t *wp = witness;

    *wp++ = target_val;
    *wp++ = low_value_val;
    *wp++ = low_next_val;
    *wp++ = next_index_val;

    memcpy(wp, siblings, DEPTH * nb);
    wp += DEPTH * nb;

    for (size_t i = 0; i < DEPTH; i++)
        *wp++ = path_dirs[i];

    uint8_t leaf_data[3] = {low_value_val, low_next_val, next_index_val};
    merkle_grostl_gf8_leaf_build_witness(leaf_data, 3, variant, wp);
    wp += leaf_invin;

    uint8_t current[64];
    merkle_grostl_leaf_hash(leaf_data, 3, variant, current);

    for (size_t lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + lvl * nb;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_grostl_gf8_inode_build_witness(L, R, variant, wp);
        wp += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (size_t i = 0; i < nb; i++)
        root_out[i] = vals[root_w[i]];

    free(vals);
    free(witness);
    free(pn_w);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Tests
 * ================================================================ */

/*
 * ell = n_witness + n_mul, derived structurally from the Grøstl sizing
 * helpers so the assertion validates the wiring rather than a hand
 * count.  n_mul = 2 comparisons × 3 mul-gates/bit × 8 bits × target_bytes.
 */
static void
test_ell_count(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t nb = merkle_grostl_node_bytes(variant);
    size_t leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(3, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);

    size_t expect_witness = 4 + DEPTH * nb + leaf_invin + DEPTH * inode_invin;
    size_t expect_mul = 2 * 3 * 8 * 1;
    size_t expect_ell = expect_witness + expect_mul;

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id tgt[1], lv[1], ln[1], ni[1];
    tgt[0] = voleith_gf8_add_witness(c);
    lv[0] = voleith_gf8_add_witness(c);
    ln[0] = voleith_gf8_add_witness(c);
    ni[0] = voleith_gf8_add_witness(c);
    gf8_wire_id *pn = calloc(DEPTH * nb, sizeof(gf8_wire_id));
    for (size_t i = 0; i < DEPTH * nb; i++)
        pn[i] = voleith_gf8_add_witness(c);

    uint8_t dirs[DEPTH] = {0};
    gf8_wire_id root[64];
    indexed_merkle_grostl_gf8_nonmember_circuit(c, tgt, 1, lv, ln, ni, 1, pn,
                                                dirs, DEPTH, variant, root);

    size_t ell = voleith_gf8_qs_ell(c);
    check("GROSTL_256 ell matches structural expectation", ell == expect_ell);

    free(pn);
    voleith_gf8_circuit_free(c);
}

static void
test_correctness(voleith_merkle_grostl_variant_t variant, size_t leaf_index,
                 const char *label)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    /*
     * target strictly between the adjacent leaf's value and next_value.
     * Values are multiples of 10, so value + 5 is in range for every leaf.
     */
    uint8_t lo = LEAVES[leaf_index].value;
    uint8_t nx = LEAVES[leaf_index].next_value;
    uint8_t tgt = (uint8_t)(lo + 5);

    uint8_t computed_root[64];
    int ok = eval_nonmember(variant, tgt, lo, nx, LEAVES[leaf_index].next_index,
                            siblings, dirs, computed_root);

    char name[128];
    snprintf(name, sizeof(name), "%s: constraints satisfied", label);
    check(name, ok == 1);

    snprintf(name, sizeof(name), "%s: circuit root == software root", label);
    check(name, memcmp(computed_root, root, nb) == 0);
}

/*
 * Ordering soundness: with a target NOT in (low_value, low_next) the
 * circuit must reject.  Every hash witness is built honestly for the
 * real adjacent leaf and path, so the only violated constraint is the
 * range check (target < low_next here: 35 is not < 30).
 */
static void
test_ordering_soundness(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t leaf_index = 1; /* value=20, next_value=30 */

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t computed_root[64];
    int ok = eval_nonmember(variant, 35, 20, 30, LEAVES[leaf_index].next_index,
                            siblings, dirs, computed_root);

    check("out-of-range target rejected (35 not < low_next=30)", ok == 0);
}

/* Field binding: a wrong next_index changes the leaf hash, hence the root. */
static void
test_field_binding(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t nb = merkle_grostl_node_bytes(variant);
    size_t leaf_index = 1;

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    /* Correct next_index is 2; feed 3.  In-range target (25) keeps the
     * ordering constraints satisfied, isolating the hash-binding effect. */
    uint8_t bad_root[64];
    int ok = eval_nonmember(variant, 25, 20, 30, 3, siblings, dirs, bad_root);

    check("wrong next_index: constraints still satisfied", ok == 1);
    check("wrong next_index: root differs from reference",
          memcmp(bad_root, root, nb) != 0);
}

/* Secret-dir correctness: circuit root equals the software root. */
static void
test_correctness_secret_dir(voleith_merkle_grostl_variant_t variant,
                            size_t leaf_index, const char *label)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t lo = LEAVES[leaf_index].value;
    uint8_t nx = LEAVES[leaf_index].next_value;
    uint8_t tgt = (uint8_t)(lo + 5);

    uint8_t computed_root[64];
    int ok = eval_nonmember_secret_dir(variant, tgt, lo, nx,
                                       LEAVES[leaf_index].next_index, siblings,
                                       dirs, computed_root);

    char name[128];
    snprintf(name, sizeof(name), "%s: constraints satisfied", label);
    check(name, ok == 1);

    snprintf(name, sizeof(name), "%s: circuit root == software root", label);
    check(name, memcmp(computed_root, root, nb) == 0);
}

/* Secret-dir and public-dir must produce identical roots for same inputs. */
static void
test_secret_public_equivalence(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t nb = merkle_grostl_node_bytes(variant);
    size_t leaf_index = 5;

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t lo = LEAVES[leaf_index].value;
    uint8_t nx = LEAVES[leaf_index].next_value;
    uint8_t tgt = (uint8_t)(lo + 5);

    uint8_t pub_root[64], sec_root[64];
    int ok_pub =
        eval_nonmember(variant, tgt, lo, nx, LEAVES[leaf_index].next_index,
                       siblings, dirs, pub_root);
    int ok_sec = eval_nonmember_secret_dir(variant, tgt, lo, nx,
                                           LEAVES[leaf_index].next_index,
                                           siblings, dirs, sec_root);

    check("secret-dir and public-dir both satisfied",
          ok_pub == 1 && ok_sec == 1);
    check("secret-dir root == public-dir root (equivalence)",
          memcmp(pub_root, sec_root, nb) == 0);
}

/*
 * Secret-dir direction binding: a wrong (but still 0/1) direction bit
 * places the leaf on the wrong side, yielding a different root.
 */
static void
test_secret_dir_binding(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t nb = merkle_grostl_node_bytes(variant);
    size_t leaf_index = 1; /* correct dirs = {1,0,0} */

    uint8_t root[64], siblings[DEPTH * 64];
    build_tree(variant, leaf_index, root, siblings);

    uint8_t wrong_dirs[DEPTH] = {0, 0, 0};

    uint8_t bad_root[64];
    int ok = eval_nonmember_secret_dir(variant, 25, 20, 30,
                                       LEAVES[leaf_index].next_index, siblings,
                                       wrong_dirs, bad_root);

    check("wrong path_dir: constraints still satisfied (bits are valid)",
          ok == 1);
    check("wrong path_dir: root differs (direction is binding)",
          memcmp(bad_root, root, nb) != 0);
}

/*
 * CIR-2: (2*target_bytes + index_bytes) over the stack-VLA bound must
 * return -1 without building any circuit.  Dummy single-wire pointers
 * suffice because the bound check fires before any dereference.
 */
static void
test_cir2_stack_bound(void)
{
    const size_t HUGE_TGT = 600; /* 2*600 + 1 = 1201 > 1024 */

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id dummy = voleith_gf8_add_witness(c);
    uint8_t dummy_dir = 0;
    gf8_wire_id root[64];

    int rc = indexed_merkle_grostl_gf8_nonmember_circuit(
        c, &dummy, HUGE_TGT, &dummy, &dummy, &dummy, 1, &dummy, &dummy_dir, 1,
        VOLEITH_MERKLE_GROSTL_256, root);
    check("CIR-2: public-dir returns -1 on stack-VLA bound violation",
          rc == -1);

    int rc_sec = indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
        c, &dummy, HUGE_TGT, &dummy, &dummy, &dummy, 1, &dummy, &dummy, 1,
        VOLEITH_MERKLE_GROSTL_256, root);
    check("CIR-2: secret-dir returns -1 on stack-VLA bound violation",
          rc_sec == -1);

    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    printf("=== indexed_merkle_grostl_gf8_circuit tests ===\n");

    test_ell_count();

    test_correctness(VOLEITH_MERKLE_GROSTL_256, 1, "GROSTL_256 leaf1");
    test_correctness(VOLEITH_MERKLE_GROSTL_256, 5, "GROSTL_256 leaf5");
    test_correctness(VOLEITH_MERKLE_GROSTL_256_T27, 6, "GROSTL_256_T27 leaf6");
    test_correctness(VOLEITH_MERKLE_GROSTL_512, 3, "GROSTL_512 leaf3");

    test_ordering_soundness();
    test_field_binding();

    test_correctness_secret_dir(VOLEITH_MERKLE_GROSTL_256, 1,
                                "GROSTL_256 secret-dir leaf1");
    test_correctness_secret_dir(VOLEITH_MERKLE_GROSTL_256_T27, 6,
                                "GROSTL_256_T27 secret-dir leaf6");
    test_correctness_secret_dir(VOLEITH_MERKLE_GROSTL_512, 3,
                                "GROSTL_512 secret-dir leaf3");
    test_secret_public_equivalence();
    test_secret_dir_binding();

    test_cir2_stack_bound();

    printf("\n%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
