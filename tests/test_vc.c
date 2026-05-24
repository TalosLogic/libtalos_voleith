/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_vc.c - Tests for GGM tree expansion and PosInTree
 *
 * Tests:
 *   1. Parameter computation for known FAEST parameter sets
 *   2. PosInTree mapping properties
 *   3. GGM tree expansion determinism
 *   4. GGM tree parent-child PRG consistency
 *   5. GGM tree alloc/free
 *   6. Leaf accessor correctness
 */

#include "vc.h"
#include "prg.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* ================================================================
 * Parameter computation tests
 * ================================================================ */

/*
 * Test 1: FAEST-EM-128f parameters
 * lambda=128, tau=16, w_grind=8
 * Expected: k=8, tau1=8, tau0=8, L=3072
 */
static void
test_params_em128f(void)
{
    voleith_vc_params_t p;
    int rc = voleith_vc_params_init(&p, 128, 16, 8, 2, 112);
    check("params_em128f: init succeeds", rc == 0);
    check("params_em128f: k=8", p.k == 8);
    check("params_em128f: tau1=8", p.tau1 == 8);
    check("params_em128f: tau0=8", p.tau0 == 8);
    check("params_em128f: L=3072", p.L == 3072);
}

/*
 * Test 2: FAEST-128s parameters
 * lambda=128, tau=11, w_grind=7
 * k = floor((128-7)/11) + 1 = floor(121/11) + 1 = 11 + 1 = 12
 * tau1 = (128-7) mod 11 = 121 mod 11 = 0
 * tau0 = 11 - 0 = 11
 * L = 0*2^12 + 11*2^11 = 11*2048 = 22528
 */
static void
test_params_128s(void)
{
    voleith_vc_params_t p;
    int rc = voleith_vc_params_init(&p, 128, 11, 7, 2, 103);
    check("params_128s: init succeeds", rc == 0);
    check("params_128s: k=12", p.k == 12);
    check("params_128s: tau1=0", p.tau1 == 0);
    check("params_128s: tau0=11", p.tau0 == 11);
    check("params_128s: L=22528", p.L == 22528);
}

/*
 * Test 3: FAEST-EM-128s parameters
 * lambda=128, tau=11, w_grind=7
 * Same computation as FAEST-128s (same lambda, tau, w_grind)
 */
static void
test_params_em128s(void)
{
    voleith_vc_params_t p;
    int rc = voleith_vc_params_init(&p, 128, 11, 7, 2, 103);
    check("params_em128s: L=22528", rc == 0 && p.L == 22528);
}

/*
 * Test 4: FAEST-EM-256f parameters
 * lambda=256, tau=32, w_grind=8
 * k = floor((256-8)/32) + 1 = floor(248/32) + 1 = 7 + 1 = 8
 * tau1 = 248 mod 32 = 24
 * tau0 = 32 - 24 = 8
 * L = 24*256 + 8*128 = 6144 + 1024 = 7168
 */
static void
test_params_em256f(void)
{
    voleith_vc_params_t p;
    int rc = voleith_vc_params_init(&p, 256, 32, 8, 2, 234);
    check("params_em256f: init succeeds", rc == 0);
    check("params_em256f: k=8", p.k == 8);
    check("params_em256f: tau1=24", p.tau1 == 24);
    check("params_em256f: tau0=8", p.tau0 == 8);
    check("params_em256f: L=7168", p.L == 7168);
}

/*
 * Test 5: N_i computation
 */
static void
test_N_i(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);
    /* tau1=8, k=8: N_i=256 for i<8, N_i=128 for i>=8 */
    check("N_i: i=0 gives 256", voleith_vc_N(&p, 0) == 256);
    check("N_i: i=7 gives 256", voleith_vc_N(&p, 7) == 256);
    check("N_i: i=8 gives 128", voleith_vc_N(&p, 8) == 128);
    check("N_i: i=15 gives 128", voleith_vc_N(&p, 15) == 128);
}

/*
 * Test 6: Sum of N_i should equal L
 */
static void
test_N_sum_equals_L(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);
    size_t sum = 0;
    for (int i = 0; i < p.tau; i++)
        sum += voleith_vc_N(&p, i);
    check("sum(N_i) == L", sum == p.L);
}

/* ================================================================
 * PosInTree tests
 * ================================================================ */

/*
 * Test 7: PosInTree produces values in [L-1, 2L-2]
 */
static void
test_pos_in_tree_range(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    int ok = 1;
    for (int i = 0; i < p.tau && ok; i++) {
        size_t Ni = voleith_vc_N(&p, i);
        for (size_t j = 0; j < Ni && ok; j++) {
            size_t alpha = voleith_pos_in_tree(&p, i, j);
            if (alpha < p.L - 1 || alpha > 2 * p.L - 2)
                ok = 0;
        }
    }
    check("PosInTree: all results in [L-1, 2L-2]", ok);
}

/*
 * Test 8: PosInTree is a bijection (all L leaves get a unique index)
 */
static void
test_pos_in_tree_bijective(void)
{
    /* Use small parameters to make this tractable */
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    /* L=3072 - allocate a bitmap */
    uint8_t *seen = calloc(p.L, 1);
    if (!seen) {
        check("PosInTree bijective: alloc", 0);
        return;
    }

    int ok = 1;
    for (int i = 0; i < p.tau && ok; i++) {
        size_t Ni = voleith_vc_N(&p, i);
        for (size_t j = 0; j < Ni && ok; j++) {
            size_t alpha = voleith_pos_in_tree(&p, i, j);
            size_t leaf_idx = alpha - (p.L - 1);
            if (leaf_idx >= p.L) {
                ok = 0;
            } else if (seen[leaf_idx]) {
                ok = 0; /* duplicate */
            } else {
                seen[leaf_idx] = 1;
            }
        }
    }

    /* Check all leaves were hit */
    if (ok) {
        for (size_t i = 0; i < p.L; i++) {
            if (!seen[i]) {
                ok = 0;
                break;
            }
        }
    }

    free(seen);
    check("PosInTree: bijective mapping", ok);
}

/* ================================================================
 * GGM tree tests
 * ================================================================ */

/*
 * Test 9: GGM tree alloc and free
 */
static void
test_ggm_tree_alloc_free(void)
{
    voleith_ggm_tree_t tree;
    int rc = voleith_ggm_tree_alloc(&tree, 8, 128);
    check("ggm_tree alloc: succeeds", rc == 0);
    check("ggm_tree alloc: L=8", tree.L == 8);
    check("ggm_tree alloc: seed_bytes=16", tree.seed_bytes == 16);
    check("ggm_tree alloc: nodes not null", tree.nodes != NULL);
    voleith_ggm_tree_free(&tree);
    check("ggm_tree free: nodes null", tree.nodes == NULL);
}

/*
 * Test 10: GGM tree expansion is deterministic
 * Same seed + iv should produce identical trees.
 */
static void
test_ggm_tree_deterministic(void)
{
    uint8_t seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t iv[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    voleith_ggm_tree_t tree1, tree2;
    voleith_ggm_tree_alloc(&tree1, 8, 128);
    voleith_ggm_tree_alloc(&tree2, 8, 128);

    voleith_ggm_tree_expand(&tree1, seed, iv);
    voleith_ggm_tree_expand(&tree2, seed, iv);

    /* Total nodes = 2*8-1 = 15, each 16 bytes */
    int eq = memcmp(tree1.nodes, tree2.nodes, 15 * 16) == 0;
    check("ggm_tree: deterministic expansion", eq);

    voleith_ggm_tree_free(&tree1);
    voleith_ggm_tree_free(&tree2);
}

/*
 * Test 11: Different seeds produce different trees
 */
static void
test_ggm_tree_different_seeds(void)
{
    uint8_t seed1[16] = {0};
    uint8_t seed2[16] = {0};
    seed2[0] = 1;
    uint8_t iv[16] = {0};

    voleith_ggm_tree_t tree1, tree2;
    voleith_ggm_tree_alloc(&tree1, 4, 128);
    voleith_ggm_tree_alloc(&tree2, 4, 128);

    voleith_ggm_tree_expand(&tree1, seed1, iv);
    voleith_ggm_tree_expand(&tree2, seed2, iv);

    /* Leaves should differ */
    int diff = memcmp(voleith_ggm_tree_leaf(&tree1, 0),
                      voleith_ggm_tree_leaf(&tree2, 0), 16) != 0;
    check("ggm_tree: different seeds → different leaves", diff);

    voleith_ggm_tree_free(&tree1);
    voleith_ggm_tree_free(&tree2);
}

/*
 * Test 12: Parent-child PRG consistency
 * For each internal node α, verify that PRG(k_α, iv, α; 2λ) produces
 * exactly (k_{2α+1}, k_{2α+2}).
 */
static void
test_ggm_tree_prg_consistency(void)
{
    uint8_t seed[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    uint8_t iv[16] = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
                      0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};

    size_t L = 16; /* 16 leaves, 15 internal nodes, 31 total */
    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, L, 128);
    voleith_ggm_tree_expand(&tree, seed, iv);

    int ok = 1;
    uint8_t prg_out[32];

    for (size_t alpha = 0; alpha < L - 1; alpha++) {
        const uint8_t *parent = voleith_ggm_tree_node(&tree, alpha);

        voleith_prg_ctx_t prg;
        voleith_prg_init(&prg, parent, 128);
        voleith_prg_gen(&prg, prg_out, iv, (uint32_t)alpha, 256);

        const uint8_t *left = voleith_ggm_tree_node(&tree, 2 * alpha + 1);
        const uint8_t *right = voleith_ggm_tree_node(&tree, 2 * alpha + 2);

        if (memcmp(prg_out, left, 16) != 0 ||
            memcmp(prg_out + 16, right, 16) != 0) {
            ok = 0;
            break;
        }
    }

    check("ggm_tree: parent-child PRG consistency (L=16)", ok);
    voleith_ggm_tree_free(&tree);
}

/*
 * Test 13: Leaf accessor returns correct pointers
 */
static void
test_ggm_tree_leaf_accessor(void)
{
    uint8_t seed[16] = {0x42};
    uint8_t iv[16] = {0};

    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, 4, 128);
    voleith_ggm_tree_expand(&tree, seed, iv);

    /* leaf(i) should point to node(L-1+i) */
    int ok = 1;
    for (size_t i = 0; i < 4; i++) {
        if (voleith_ggm_tree_leaf(&tree, i) !=
            voleith_ggm_tree_node(&tree, tree.L - 1 + i)) {
            ok = 0;
            break;
        }
    }
    check("ggm_tree: leaf accessor matches node(L-1+i)", ok);

    voleith_ggm_tree_free(&tree);
}

/*
 * Test 14: Root node equals the input seed
 */
static void
test_ggm_tree_root_is_seed(void)
{
    uint8_t seed[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                        0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    uint8_t iv[16] = {0};

    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, 8, 128);
    voleith_ggm_tree_expand(&tree, seed, iv);

    check("ggm_tree: root node equals seed",
          memcmp(voleith_ggm_tree_node(&tree, 0), seed, 16) == 0);

    voleith_ggm_tree_free(&tree);
}

/*
 * Test 15: GGM tree with lambda=256
 */
static void
test_ggm_tree_lambda256(void)
{
    uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t iv[16] = {0};

    voleith_ggm_tree_t tree;
    int rc = voleith_ggm_tree_alloc(&tree, 4, 256);
    check("ggm_tree_256: alloc succeeds", rc == 0);
    check("ggm_tree_256: seed_bytes=32", tree.seed_bytes == 32);

    voleith_ggm_tree_expand(&tree, seed, iv);

    /* Verify PRG consistency for node 0 */
    uint8_t prg_out[64];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 256);
    voleith_prg_gen(&prg, prg_out, iv, 0, 512);

    check("ggm_tree_256: left child matches PRG",
          memcmp(voleith_ggm_tree_node(&tree, 1), prg_out, 32) == 0);
    check("ggm_tree_256: right child matches PRG",
          memcmp(voleith_ggm_tree_node(&tree, 2), prg_out + 32, 32) == 0);

    voleith_ggm_tree_free(&tree);
}

/*
 * Test 16: All leaves are non-zero (with overwhelming probability)
 */
static void
test_ggm_tree_leaves_nonzero(void)
{
    uint8_t seed[16] = {0x01, 0x02, 0x03, 0x04};
    uint8_t iv[16] = {0};
    uint8_t zero[16] = {0};

    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, 32, 128);
    voleith_ggm_tree_expand(&tree, seed, iv);

    int ok = 1;
    for (size_t i = 0; i < 32; i++) {
        if (memcmp(voleith_ggm_tree_leaf(&tree, i), zero, 16) == 0) {
            ok = 0;
            break;
        }
    }
    check("ggm_tree: all 32 leaves are nonzero", ok);

    voleith_ggm_tree_free(&tree);
}

/*
 * Test 17: All leaves are distinct (with overwhelming probability)
 */
static void
test_ggm_tree_leaves_distinct(void)
{
    uint8_t seed[16] = {0x55, 0x66, 0x77, 0x88};
    uint8_t iv[16] = {0};

    size_t L = 16;
    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, L, 128);
    voleith_ggm_tree_expand(&tree, seed, iv);

    int ok = 1;
    for (size_t i = 0; i < L && ok; i++) {
        for (size_t j = i + 1; j < L && ok; j++) {
            if (memcmp(voleith_ggm_tree_leaf(&tree, i),
                       voleith_ggm_tree_leaf(&tree, j), 16) == 0) {
                ok = 0;
            }
        }
    }
    check("ggm_tree: all 16 leaves are distinct", ok);

    voleith_ggm_tree_free(&tree);
}

/* ================================================================
 * BAVC Commit tests
 * ================================================================ */

/*
 * Test 18: BAVC commit succeeds and produces non-zero commitment
 */
static void
test_bavc_commit_basic(void)
{
    uint8_t seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t iv[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t zero[32] = {0};

    /* Use FAEST-EM-128f parameters: lambda=128, tau=16, w_grind=8, n_leafcom=2 */
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t result;
    int rc = voleith_bavc_commit(&result, &p, seed, iv);
    check("bavc_commit: succeeds", rc == 0);
    check("bavc_commit: com is non-zero", memcmp(result.com, zero, 32) != 0);
    check("bavc_commit: com_bytes = 32", result.com_bytes == 32);
    check("bavc_commit: leaf_coms not null", result.leaf_coms != NULL);
    check("bavc_commit: leaf_seeds not null", result.leaf_seeds != NULL);

    voleith_bavc_free(&result);
}

/*
 * Test 19: BAVC commit is deterministic
 */
static void
test_bavc_commit_deterministic(void)
{
    uint8_t seed[16] = {0xaa, 0xbb, 0xcc, 0xdd};
    uint8_t iv[16] = {0x11, 0x22, 0x33, 0x44};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t r1, r2;
    voleith_bavc_commit(&r1, &p, seed, iv);
    voleith_bavc_commit(&r2, &p, seed, iv);

    check("bavc_commit: deterministic (same com)",
          memcmp(r1.com, r2.com, 32) == 0);

    /* Check all leaf coms match */
    int ok = 1;
    for (size_t i = 0; i < p.L; i++) {
        if (memcmp(r1.leaf_coms + i * r1.com_bytes,
                   r2.leaf_coms + i * r2.com_bytes, r1.com_bytes) != 0) {
            ok = 0;
            break;
        }
    }
    check("bavc_commit: deterministic (same leaf_coms)", ok);

    voleith_bavc_free(&r1);
    voleith_bavc_free(&r2);
}

/*
 * Test 20: Different seeds produce different commitments
 */
static void
test_bavc_commit_different_seeds(void)
{
    uint8_t seed1[16] = {0};
    uint8_t seed2[16] = {0};
    seed2[0] = 1;
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t r1, r2;
    voleith_bavc_commit(&r1, &p, seed1, iv);
    voleith_bavc_commit(&r2, &p, seed2, iv);

    check("bavc_commit: different seeds → different com",
          memcmp(r1.com, r2.com, 32) != 0);

    voleith_bavc_free(&r1);
    voleith_bavc_free(&r2);
}

/*
 * Test 21: Leaf seeds match tree leaf seeds (FAEST-EM: sd = k_α)
 */
static void
test_bavc_leaf_seeds_match_tree(void)
{
    uint8_t seed[16] = {0xde, 0xad, 0xbe, 0xef};
    uint8_t iv[16] = {0};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    /* For FAEST-EM, sd_{i,j} should equal k_α (the tree leaf seed) */
    int ok = 1;
    for (int i = 0; i < p.tau && ok; i++) {
        size_t Ni = voleith_vc_N(&p, i);
        for (size_t j = 0; j < Ni && ok; j++) {
            size_t alpha = voleith_pos_in_tree(&p, i, j);
            const uint8_t *tree_leaf =
                voleith_ggm_tree_node(&result.tree, alpha);
            const uint8_t *bavc_seed =
                voleith_bavc_leaf_seed(&result, &p, i, j);
            if (memcmp(tree_leaf, bavc_seed, 16) != 0)
                ok = 0;
        }
    }
    check("bavc_commit: leaf seeds match tree leaves (EM)", ok);

    voleith_bavc_free(&result);
}

/*
 * Test 22: Leaf commitment matches manual PRG computation
 * For FAEST-EM: com_{i,j} = PRG(k_α, iv, α; 2λ)
 */
static void
test_bavc_leaf_com_matches_prg(void)
{
    uint8_t seed[16] = {0xca, 0xfe, 0xba, 0xbe};
    uint8_t iv[16] = {0x55};

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    /* Spot-check a few leaf commitments.
     * LeafCommit tweak for vector i is (i + L - 1), per FAEST spec. */
    int ok = 1;
    uint8_t expected_com[32];
    voleith_prg_ctx_t prg;

    /* Check (i=0, j=0) */
    size_t alpha = voleith_pos_in_tree(&p, 0, 0);
    const uint8_t *k_alpha = voleith_ggm_tree_node(&result.tree, alpha);
    uint32_t twk = (uint32_t)(0 + p.L - 1);
    voleith_prg_init(&prg, k_alpha, 128);
    voleith_prg_gen(&prg, expected_com, iv, twk, 256);

    const uint8_t *got_com = voleith_bavc_leaf_com(&result, &p, 0, 0);
    if (memcmp(got_com, expected_com, 32) != 0)
        ok = 0;

    /* Check (i=5, j=100) */
    alpha = voleith_pos_in_tree(&p, 5, 100);
    k_alpha = voleith_ggm_tree_node(&result.tree, alpha);
    twk = (uint32_t)(5 + p.L - 1);
    voleith_prg_init(&prg, k_alpha, 128);
    voleith_prg_gen(&prg, expected_com, iv, twk, 256);

    got_com = voleith_bavc_leaf_com(&result, &p, 5, 100);
    if (memcmp(got_com, expected_com, 32) != 0)
        ok = 0;

    /* Check (i=15, j=0) - last vector, first position */
    alpha = voleith_pos_in_tree(&p, 15, 0);
    k_alpha = voleith_ggm_tree_node(&result.tree, alpha);
    twk = (uint32_t)(15 + p.L - 1);
    voleith_prg_init(&prg, k_alpha, 128);
    voleith_prg_gen(&prg, expected_com, iv, twk, 256);

    got_com = voleith_bavc_leaf_com(&result, &p, 15, 0);
    if (memcmp(got_com, expected_com, 32) != 0)
        ok = 0;

    check("bavc_commit: leaf com matches PRG(k_α, iv, i+L-1; 2λ)", ok);

    voleith_bavc_free(&result);
}

/*
 * Test 23: All leaf commitments are distinct (with overwhelming probability)
 */
static void
test_bavc_leaf_coms_distinct(void)
{
    uint8_t seed[16] = {0x42};
    uint8_t iv[16] = {0};

    /* Use small tree for O(L^2) comparison: tau=2, w_grind=0, n_leafcom=2
     * k = floor(128/2) + 1 = 65, tau1 = 0, tau0 = 2
     * L = 2 * 2^64 - way too big! Use a custom small test instead.
     */

    /* Manually use small params: tau=16, w_grind=120 to get small L
     * effective = 128-120 = 8, k = 8/16 + 1 = 1
     * tau1 = 8 mod 16 = 8, tau0 = 8
     * L = 8*2 + 8*1 = 24
     */
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    int ok = 1;
    for (size_t a = 0; a < p.L && ok; a++) {
        for (size_t b = a + 1; b < p.L && ok; b++) {
            if (memcmp(result.leaf_coms + a * result.com_bytes,
                       result.leaf_coms + b * result.com_bytes,
                       result.com_bytes) == 0) {
                ok = 0;
            }
        }
    }
    check("bavc_commit: all leaf commitments are distinct (L=24)", ok);

    voleith_bavc_free(&result);
}

/*
 * Test 24: BAVC commit with lambda=256
 */
static void
test_bavc_commit_lambda256(void)
{
    uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint8_t iv[16] = {0};
    uint8_t zero[64] = {0};

    /* FAEST-EM-256f: lambda=256, tau=32, w_grind=8, n_leafcom=2 */
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 256, 32, 8, 2, 234);

    voleith_bavc_t result;
    int rc = voleith_bavc_commit(&result, &p, seed, iv);
    check("bavc_commit_256: succeeds", rc == 0);
    check("bavc_commit_256: com_bytes=64", result.com_bytes == 64);
    check("bavc_commit_256: com is non-zero",
          memcmp(result.com, zero, 64) != 0);

    voleith_bavc_free(&result);
}

/* ================================================================
 * BAVC Open tests
 * ================================================================ */

/*
 * Helper: commit with small params (L=24) and return challenge indices.
 * Uses tau=16, w_grind=120 so L = 8*2 + 8*1 = 24.
 * i_delta[i] = i % N_i (simple deterministic challenge).
 */
static void
setup_small_commit(voleith_vc_params_t *p, voleith_bavc_t *result,
                   size_t *i_delta)
{
    voleith_vc_params_init(p, 128, 16, 120, 2, 24);

    uint8_t seed[16];
    memset(seed, 0xAA, 16);
    uint8_t iv[16];
    memset(iv, 0xBB, 16);

    voleith_bavc_commit(result, p, seed, iv);

    for (int i = 0; i < p->tau; i++)
        i_delta[i] = (size_t)i % voleith_vc_N(p, i);
}

/*
 * Test 25: BAVC.Open basic - opens without error
 */
static void
test_bavc_open_basic(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t opening;
    int rc = voleith_bavc_open(&opening, &result, &p, i_delta);
    check("bavc_open_basic: succeeds", rc == 0);
    check("bavc_open_basic: data non-NULL", opening.data != NULL);
    check("bavc_open_basic: data_len correct",
          opening.data_len == voleith_bavc_opening_size(&p));
    check("bavc_open_basic: n_revealed > 0", opening.n_revealed > 0);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 26: Opening contains correct hidden leaf commitments
 */
static void
test_bavc_open_hidden_coms(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    size_t com_bytes = (size_t)p.n_leafcom * (size_t)p.lambda / 8;
    int ok = 1;
    for (int i = 0; i < p.tau; i++) {
        const uint8_t *expected =
            voleith_bavc_leaf_com(&result, &p, i, i_delta[i]);
        const uint8_t *actual = opening.data + (size_t)i * com_bytes;
        if (memcmp(expected, actual, com_bytes) != 0)
            ok = 0;
    }
    check("bavc_open_hidden_coms: match leaf_coms", ok);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 27: Opening is deterministic
 */
static void
test_bavc_open_deterministic(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t open1, open2;
    voleith_bavc_open(&open1, &result, &p, i_delta);
    voleith_bavc_open(&open2, &result, &p, i_delta);

    check("bavc_open_deterministic: same data",
          open1.data_len == open2.data_len &&
              memcmp(open1.data, open2.data, open1.data_len) == 0);

    voleith_bavc_opening_free(&open1);
    voleith_bavc_opening_free(&open2);
    voleith_bavc_free(&result);
}

/*
 * Test 28: Different challenges produce different openings
 */
static void
test_bavc_open_different_challenges(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta1[16], i_delta2[16];
    setup_small_commit(&p, &result, i_delta1);

    /* Different challenge: shift by 1 */
    for (int i = 0; i < p.tau; i++)
        i_delta2[i] = ((size_t)i + 1) % voleith_vc_N(&p, i);

    voleith_bavc_opening_t open1, open2;
    voleith_bavc_open(&open1, &result, &p, i_delta1);
    voleith_bavc_open(&open2, &result, &p, i_delta2);

    check("bavc_open_diff_challenges: different data",
          memcmp(open1.data, open2.data, open1.data_len) != 0);

    voleith_bavc_opening_free(&open1);
    voleith_bavc_opening_free(&open2);
    voleith_bavc_free(&result);
}

/*
 * Test 29: Opening does NOT contain the hidden leaf's tree seed.
 *
 * For each hidden leaf α = PosInTree(i, Δ_i), check that its tree seed
 * does not appear anywhere in the revealed seeds portion of the opening.
 */
static void
test_bavc_open_no_hidden_seeds(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    size_t sb = (size_t)p.lambda / 8;
    size_t com_bytes = (size_t)p.n_leafcom * sb;
    /* Seeds start after the τ hidden commitments */
    const uint8_t *seeds_start = opening.data + (size_t)p.tau * com_bytes;
    size_t seeds_len = opening.n_revealed * sb;

    int ok = 1;
    for (int i = 0; i < p.tau; i++) {
        size_t alpha = voleith_pos_in_tree(&p, i, i_delta[i]);
        const uint8_t *hidden_seed = voleith_ggm_tree_node(&result.tree, alpha);

        /* Scan all revealed seeds */
        for (size_t s = 0; s < seeds_len; s += sb) {
            if (memcmp(seeds_start + s, hidden_seed, sb) == 0) {
                ok = 0;
                break;
            }
        }
    }
    check("bavc_open_no_hidden_seeds: hidden seeds not in opening", ok);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 30: Opening size matches expected fixed size
 */
static void
test_bavc_opening_size(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    size_t sb = (size_t)p.lambda / 8;
    size_t expected =
        (size_t)p.n_leafcom * (size_t)p.tau * sb + (size_t)p.T_open * sb;
    check("bavc_opening_size: matches formula",
          voleith_bavc_opening_size(&p) == expected);
}

/*
 * Test 31: Padding bytes in opening are zero
 */
static void
test_bavc_open_padding_zero(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    size_t sb = (size_t)p.lambda / 8;
    size_t com_bytes = (size_t)p.n_leafcom * sb;
    size_t used = (size_t)p.tau * com_bytes + opening.n_revealed * sb;

    int ok = 1;
    for (size_t i = used; i < opening.data_len; i++) {
        if (opening.data[i] != 0) {
            ok = 0;
            break;
        }
    }
    check("bavc_open_padding_zero: trailing bytes are zero", ok);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 32: n_revealed ≤ T_open
 */
static void
test_bavc_open_n_revealed_bound(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    check("bavc_open_n_revealed_bound: n_revealed <= T_open",
          opening.n_revealed <= (size_t)p.T_open);

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 33: Opening all different single-leaf challenges (one hidden per vector)
 * For each i, try hiding leaf 0 vs leaf 1 - they should produce different openings.
 */
static void
test_bavc_open_varied_indices(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xCC, 16);
    memset(iv, 0xDD, 16);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    /*
     * All-zeros challenge vs a "max index per vector" challenge.  With
     * w_grind=120, tau=16 the params give k=1, tau1=8, so vectors
     * 0..7 have N_i=2 and vectors 8..15 have N_i=1.  We can only vary
     * the first 8 vectors; the rest are forced to 0 (their only legal
     * value).  Earlier versions of this test set every delta_1[i]=1,
     * which silently exercised an out-of-range PosInTree call; the
     * V-12 bounds check in voleith_bavc_open now rejects that, so
     * this test had to be corrected to stay within range.
     */
    size_t delta_0[16], delta_1[16];
    for (int i = 0; i < p.tau; i++) {
        delta_0[i] = 0;
        delta_1[i] = (voleith_vc_N(&p, i) > 1) ? 1 : 0;
    }

    voleith_bavc_opening_t open0, open1;
    int rc0 = voleith_bavc_open(&open0, &result, &p, delta_0);
    int rc1 = voleith_bavc_open(&open1, &result, &p, delta_1);
    check("bavc_open_varied: delta=0 opens", rc0 == 0);
    check("bavc_open_varied: delta=1 opens", rc1 == 0);

    check("bavc_open_varied: delta=0 vs delta=1 differ",
          memcmp(open0.data, open1.data, open0.data_len) != 0);

    voleith_bavc_opening_free(&open0);
    voleith_bavc_opening_free(&open1);
    voleith_bavc_free(&result);
}

/* ================================================================
 * BAVC Reconstruct tests
 * ================================================================ */

/*
 * Helper: commit, open, and reconstruct with small params.
 * Caller must free result, opening, and rec.
 */
static void
setup_small_roundtrip(voleith_vc_params_t *p, voleith_bavc_t *result,
                      voleith_bavc_opening_t *opening,
                      voleith_bavc_reconstruct_t *rec, size_t *i_delta)
{
    voleith_vc_params_init(p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xAA, 16);
    memset(iv, 0xBB, 16);

    voleith_bavc_commit(result, p, seed, iv);

    for (int i = 0; i < p->tau; i++)
        i_delta[i] = (size_t)i % voleith_vc_N(p, i);

    voleith_bavc_open(opening, result, p, i_delta);
    voleith_bavc_reconstruct(rec, opening, p, i_delta, iv);
}

/*
 * Test 34: Reconstruct succeeds
 */
static void
test_bavc_reconstruct_basic(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);

    check("bavc_reconstruct_basic: leaf_seeds non-NULL",
          rec.leaf_seeds != NULL);
    check("bavc_reconstruct_basic: leaf_coms non-NULL", rec.leaf_coms != NULL);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 35: Reconstructed commitment matches prover's commitment
 *
 * This is THE critical test for the VC scheme: the verifier's recomputed
 * commitment must equal the prover's commitment for a valid opening.
 */
static void
test_bavc_reconstruct_com_matches(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);

    size_t hash_bytes = 2 * (size_t)p.lambda / 8;
    check("bavc_reconstruct_com_matches: com equals prover com",
          memcmp(rec.com, result.com, hash_bytes) == 0);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 36: Reconstructed non-hidden leaf seeds match prover's leaf seeds
 */
static void
test_bavc_reconstruct_seeds_match(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);

    size_t sb = rec.seed_bytes;
    int ok = 1;
    for (int i = 0; i < p.tau && ok; i++) {
        size_t Ni = voleith_vc_N(&p, i);
        for (size_t j = 0; j < Ni && ok; j++) {
            if (j == i_delta[i])
                continue; /* skip hidden leaf */

            const uint8_t *prover_seed =
                voleith_bavc_leaf_seed(&result, &p, i, j);
            const uint8_t *rec_seed =
                voleith_bavc_reconstruct_leaf_seed(&rec, &p, i, j, i_delta);

            if (!rec_seed || memcmp(prover_seed, rec_seed, sb) != 0)
                ok = 0;
        }
    }
    check("bavc_reconstruct_seeds_match: all non-hidden seeds match", ok);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 37: Reconstructed non-hidden leaf coms match prover's leaf coms
 */
static void
test_bavc_reconstruct_coms_match(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);

    size_t com_bytes = rec.com_bytes;
    int ok = 1;
    for (int i = 0; i < p.tau && ok; i++) {
        size_t Ni = voleith_vc_N(&p, i);
        for (size_t j = 0; j < Ni && ok; j++) {
            const uint8_t *prover_com =
                voleith_bavc_leaf_com(&result, &p, i, j);
            size_t alpha = voleith_pos_in_tree(&p, i, j);
            size_t leaf_idx = alpha - (p.L - 1);
            const uint8_t *rec_com = rec.leaf_coms + leaf_idx * com_bytes;

            if (memcmp(prover_com, rec_com, com_bytes) != 0)
                ok = 0;
        }
    }
    check("bavc_reconstruct_coms_match: all leaf coms match (incl hidden)", ok);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 38: Hidden leaf seed accessor returns NULL
 */
static void
test_bavc_reconstruct_hidden_returns_null(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);

    int ok = 1;
    for (int i = 0; i < p.tau; i++) {
        const uint8_t *seed = voleith_bavc_reconstruct_leaf_seed(
            &rec, &p, i, i_delta[i], i_delta);
        if (seed != NULL)
            ok = 0;
    }
    check("bavc_reconstruct_hidden_null: hidden seeds return NULL", ok);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 39: Reconstruct with different valid challenges also works
 */
static void
test_bavc_reconstruct_different_challenge(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xAA, 16);
    memset(iv, 0xBB, 16);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    /* Use different challenge: hide last leaf in each vector */
    size_t i_delta[16];
    for (int i = 0; i < p.tau; i++)
        i_delta[i] = voleith_vc_N(&p, i) - 1;

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    voleith_bavc_reconstruct_t rec;
    int rc = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("bavc_reconstruct_diff_challenge: succeeds", rc == 0);

    size_t hash_bytes = 2 * (size_t)p.lambda / 8;
    check("bavc_reconstruct_diff_challenge: com matches",
          memcmp(rec.com, result.com, hash_bytes) == 0);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 40: Reconstruct with lambda=256
 */
static void
test_bavc_reconstruct_lambda256(void)
{
    voleith_vc_params_t p;
    /* Use very small tree: tau=4, w_grind=252 → effective=4, k=2, tau1=0,
     * tau0=4, L=4*2=8 */
    voleith_vc_params_init(&p, 256, 4, 252, 2, 8);

    uint8_t seed[32], iv[16];
    memset(seed, 0x55, 32);
    memset(iv, 0x66, 16);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    size_t i_delta[4] = {0, 1, 0, 1};

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    voleith_bavc_reconstruct_t rec;
    int rc = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("bavc_reconstruct_256: succeeds", rc == 0);

    size_t hash_bytes = 2 * (size_t)p.lambda / 8;
    check("bavc_reconstruct_256: com matches",
          memcmp(rec.com, result.com, hash_bytes) == 0);

    voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * Test 41: Tampered opening fails to reconstruct matching commitment
 *
 * Modify one byte of a revealed seed in the opening and verify that
 * the reconstructed commitment no longer matches.
 */
static void
test_bavc_reconstruct_tampered_fails(void)
{
    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 120, 2, 24);

    uint8_t seed[16], iv[16];
    memset(seed, 0xAA, 16);
    memset(iv, 0xBB, 16);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, seed, iv);

    size_t i_delta[16];
    for (int i = 0; i < p.tau; i++)
        i_delta[i] = 0;

    voleith_bavc_opening_t opening;
    voleith_bavc_open(&opening, &result, &p, i_delta);

    /* Tamper: flip a bit in the first revealed seed */
    size_t com_bytes = (size_t)p.n_leafcom * (size_t)p.lambda / 8;
    size_t seed_offset = (size_t)p.tau * com_bytes;
    opening.data[seed_offset] ^= 0x01;

    voleith_bavc_reconstruct_t rec;
    int rc = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);

    size_t hash_bytes = 2 * (size_t)p.lambda / 8;
    if (rc == 0) {
        check("bavc_reconstruct_tampered: com differs after tampering",
              memcmp(rec.com, result.com, hash_bytes) != 0);
        voleith_bavc_reconstruct_free(&rec);
    } else {
        /* Reconstruct itself failed, which is also acceptable */
        check(
            "bavc_reconstruct_tampered: reconstruct rejected tampered opening",
            1);
    }

    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * V-1 regression: voleith_bavc_reconstruct rejects an opening whose
 * data_len does not match voleith_bavc_opening_size(params).  Covers
 * both undersized and oversized buffers.
 */
static void
test_bavc_reconstruct_wrong_data_len_rejected(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);
    voleith_bavc_reconstruct_free(&rec);

    uint8_t iv[16];
    memset(iv, 0xBB, 16);

    /* Undersized buffer */
    size_t real_len = opening.data_len;
    opening.data_len = real_len - 1;
    int rc_short = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("V-1: reconstruct rejects truncated opening", rc_short != 0);

    /* Oversized buffer */
    opening.data_len = real_len + 1;
    int rc_long = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("V-1: reconstruct rejects oversized opening", rc_long != 0);

    /* Restore and sanity-check the good path still works. */
    opening.data_len = real_len;
    int rc_ok = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("V-1: reconstruct accepts correctly-sized opening", rc_ok == 0);

    if (rc_ok == 0)
        voleith_bavc_reconstruct_free(&rec);
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * V-2 regression: voleith_bavc_reconstruct rejects i_delta[i] >= N_i.
 */
static void
test_bavc_reconstruct_oob_i_delta_rejected(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    voleith_bavc_opening_t opening;
    voleith_bavc_reconstruct_t rec;
    size_t i_delta[16];
    setup_small_roundtrip(&p, &result, &opening, &rec, i_delta);
    voleith_bavc_reconstruct_free(&rec);

    uint8_t iv[16];
    memset(iv, 0xBB, 16);

    /* Set vector 0's i_delta to exactly N_0 (one past the valid range). */
    size_t saved = i_delta[0];
    i_delta[0] = voleith_vc_N(&p, 0);
    int rc_oob = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("V-2: reconstruct rejects i_delta[0] == N_0", rc_oob != 0);

    /* Try an obviously-large value too. */
    i_delta[0] = (size_t)-1;
    int rc_huge = voleith_bavc_reconstruct(&rec, &opening, &p, i_delta, iv);
    check("V-2: reconstruct rejects i_delta[0] = SIZE_MAX", rc_huge != 0);

    i_delta[0] = saved;
    voleith_bavc_opening_free(&opening);
    voleith_bavc_free(&result);
}

/*
 * V-12 regression: voleith_bavc_open rejects i_delta[i] >= N_i.
 */
static void
test_bavc_open_oob_i_delta_rejected(void)
{
    voleith_vc_params_t p;
    voleith_bavc_t result;
    size_t i_delta[16];
    setup_small_commit(&p, &result, i_delta);

    /* One past valid range. */
    size_t saved = i_delta[0];
    i_delta[0] = voleith_vc_N(&p, 0);

    voleith_bavc_opening_t opening;
    int rc_oob = voleith_bavc_open(&opening, &result, &p, i_delta);
    check("V-12: open rejects i_delta[0] == N_0", rc_oob != 0);

    i_delta[0] = (size_t)-1;
    int rc_huge = voleith_bavc_open(&opening, &result, &p, i_delta);
    check("V-12: open rejects i_delta[0] = SIZE_MAX", rc_huge != 0);

    i_delta[0] = saved;
    voleith_bavc_free(&result);
}

/* ================================================================
 * Cross-validation against faest-ref test vectors
 * (from third_party/faest-ref/tests/bavc_tvs.hpp)
 * ================================================================ */

/*
 * Helper: compute SHAKE256 hash of data (64-byte output).
 * Matches faest-ref's hash_array() which uses hash_init(ctx, 256) = SHAKE256.
 */
static void
shake256_hash(const uint8_t *data, size_t len, uint8_t out[64])
{
    voleith_hash_ctx_t ctx;
    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, data, len);
    voleith_shake256_squeeze(&ctx, out, 64);
}

/*
 * Test 42: FAEST-EM LeafCommit matches faest-ref test vector.
 *
 * From bavc_tvs.hpp FAEST_EM_128F:
 *   key    = {0x25, 0xac, ...}
 *   iv     = {0xc4, 0xcd, ...}
 *   tweak  = 226221155
 *   expected_sd  = key (for EM, sd = key)
 *   expected_com = {0x89, 0x5d, ...}
 *
 * This tests that our PRG(key, iv, tweak; 2λ) matches faest-ref's output.
 */
static void
test_xval_leaf_commit_em128f(void)
{
    static const uint8_t key[16] = {
        0x25, 0xac, 0xfc, 0x64, 0xf1, 0x6a, 0xe6, 0xbf,
        0x0a, 0xe0, 0xd7, 0xbe, 0xd3, 0xb7, 0x5d, 0x3d,
    };
    static const uint8_t iv[16] = {
        0xc4, 0xcd, 0xad, 0xb5, 0xdb, 0xaf, 0x4f, 0x13,
        0x2d, 0xd8, 0x20, 0x1d, 0xd7, 0xe7, 0xce, 0x69,
    };
    static const uint32_t tweak = 226221155;
    static const uint8_t expected_sd[16] = {
        0x25, 0xac, 0xfc, 0x64, 0xf1, 0x6a, 0xe6, 0xbf,
        0x0a, 0xe0, 0xd7, 0xbe, 0xd3, 0xb7, 0x5d, 0x3d,
    };
    static const uint8_t expected_com[32] = {
        0x89, 0x5d, 0xe5, 0x66, 0x22, 0x00, 0x7b, 0xf8, 0x91, 0xb4, 0xe7,
        0xfd, 0x6e, 0x46, 0xea, 0x68, 0x2b, 0xc3, 0xf6, 0xcf, 0x13, 0xb3,
        0xbe, 0x3a, 0x17, 0x44, 0xe8, 0xf5, 0x2a, 0x5e, 0xba, 0x19,
    };

    /* For EM, sd = key */
    check("xval_leaf_commit_em128f: sd = key",
          memcmp(key, expected_sd, 16) == 0);

    /* com = PRG(key, iv, tweak; 2λ = 256 bits = 32 bytes) */
    uint8_t com[32];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, key, 128);
    voleith_prg_gen(&prg, com, iv, tweak, 256);

    check("xval_leaf_commit_em128f: com matches faest-ref",
          memcmp(com, expected_com, 32) == 0);
}

/*
 * Test 43: GGM tree expansion matches faest-ref.
 *
 * From bavc_tvs.hpp FAEST_EM_128F:
 *   root_key = {0x00, 0x01, ..., 0x0f}
 *   iv       = {0x00, ..., 0x00}
 *   hashed_k = SHAKE256(tree_nodes, (2L-1)*16) → 64 bytes
 *
 * FAEST-EM-128F: lambda=128, tau=16, w_grind=8 → L=3072
 */
static void
test_xval_ggm_tree_em128f(void)
{
    static const uint8_t expected_hashed_k[64] = {
        0x14, 0x94, 0xec, 0xf6, 0xec, 0x25, 0xd1, 0xf0, 0xa5, 0xbc, 0x16,
        0x0e, 0x12, 0xd0, 0x7b, 0x00, 0x30, 0x1a, 0xe8, 0x45, 0xcd, 0x61,
        0x63, 0xc4, 0x33, 0x57, 0xb5, 0x5f, 0x2f, 0xab, 0x4f, 0x72, 0xbb,
        0xb6, 0x25, 0x0d, 0x35, 0x92, 0x5f, 0x36, 0xcc, 0x7b, 0x38, 0x11,
        0xb4, 0xdb, 0x71, 0xb2, 0x9f, 0xc7, 0x85, 0x97, 0x63, 0x08, 0x42,
        0x00, 0x15, 0xed, 0x96, 0xcc, 0x9a, 0x90, 0x18, 0xc0,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16];
    memset(iv, 0, 16);

    voleith_ggm_tree_t tree;
    voleith_ggm_tree_alloc(&tree, 3072, 128);
    voleith_ggm_tree_expand(&tree, root_key, iv);

    /* Hash the full tree node array and compare */
    size_t total_bytes = (2 * 3072 - 1) * 16;
    uint8_t hashed_k[64];
    shake256_hash(tree.nodes, total_bytes, hashed_k);

    check("xval_ggm_tree_em128f: hashed_k matches faest-ref",
          memcmp(hashed_k, expected_hashed_k, 64) == 0);

    voleith_ggm_tree_free(&tree);
}

/*
 * Test 44: Full BAVC.Commit global commitment matches faest-ref.
 *
 * From bavc_tvs.hpp FAEST_EM_128F:
 *   root_key = {0x00..0x0f}, iv = {0x00..0x00}
 *   h = {0xe7, 0x37, 0xbd, ...} (32 bytes = 2λ/8)
 *
 * This is the critical end-to-end test. If it passes, the full pipeline
 * (GGM tree + LeafCommit + H_1 hashing) matches faest-ref.
 */
static void
test_xval_bavc_commit_em128f(void)
{
    static const uint8_t expected_h[32] = {
        0xe7, 0x37, 0xbd, 0xc5, 0xc5, 0x0e, 0xca, 0x61, 0x8b, 0xf0, 0x5e,
        0xde, 0x6a, 0x37, 0xb7, 0xf3, 0x87, 0x4c, 0xe7, 0xc8, 0x63, 0xb3,
        0x17, 0x70, 0xa2, 0xe4, 0x23, 0x7d, 0x2d, 0x4f, 0x93, 0xf5,
    };

    uint8_t root_key[16];
    for (int i = 0; i < 16; i++)
        root_key[i] = (uint8_t)i;
    uint8_t iv[16];
    memset(iv, 0, 16);

    voleith_vc_params_t p;
    voleith_vc_params_init(&p, 128, 16, 8, 2, 112);

    voleith_bavc_t result;
    voleith_bavc_commit(&result, &p, root_key, iv);

    check("xval_bavc_commit_em128f: h matches faest-ref",
          memcmp(result.com, expected_h, 32) == 0);

    voleith_bavc_free(&result);
}

int
main(void)
{
    printf("test_vc: GGM tree, PosInTree, BAVC commit/open/reconstruct, "
           "faest-ref xval\n");

    /* Parameter tests */
    test_params_em128f();
    test_params_128s();
    test_params_em128s();
    test_params_em256f();
    test_N_i();
    test_N_sum_equals_L();

    /* PosInTree tests */
    test_pos_in_tree_range();
    test_pos_in_tree_bijective();

    /* GGM tree tests */
    test_ggm_tree_alloc_free();
    test_ggm_tree_deterministic();
    test_ggm_tree_different_seeds();
    test_ggm_tree_prg_consistency();
    test_ggm_tree_leaf_accessor();
    test_ggm_tree_root_is_seed();
    test_ggm_tree_lambda256();
    test_ggm_tree_leaves_nonzero();
    test_ggm_tree_leaves_distinct();

    /* BAVC commit tests */
    test_bavc_commit_basic();
    test_bavc_commit_deterministic();
    test_bavc_commit_different_seeds();
    test_bavc_leaf_seeds_match_tree();
    test_bavc_leaf_com_matches_prg();
    test_bavc_leaf_coms_distinct();
    test_bavc_commit_lambda256();

    /* BAVC open tests */
    test_bavc_open_basic();
    test_bavc_open_hidden_coms();
    test_bavc_open_deterministic();
    test_bavc_open_different_challenges();
    test_bavc_open_no_hidden_seeds();
    test_bavc_opening_size();
    test_bavc_open_padding_zero();
    test_bavc_open_n_revealed_bound();
    test_bavc_open_varied_indices();
    test_bavc_open_oob_i_delta_rejected();

    /* BAVC reconstruct tests */
    test_bavc_reconstruct_basic();
    test_bavc_reconstruct_com_matches();
    test_bavc_reconstruct_seeds_match();
    test_bavc_reconstruct_coms_match();
    test_bavc_reconstruct_hidden_returns_null();
    test_bavc_reconstruct_different_challenge();
    test_bavc_reconstruct_lambda256();
    test_bavc_reconstruct_tampered_fails();
    test_bavc_reconstruct_wrong_data_len_rejected();
    test_bavc_reconstruct_oob_i_delta_rejected();

    /* Cross-validation against faest-ref */
    test_xval_leaf_commit_em128f();
    test_xval_ggm_tree_em128f();
    test_xval_bavc_commit_em128f();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
