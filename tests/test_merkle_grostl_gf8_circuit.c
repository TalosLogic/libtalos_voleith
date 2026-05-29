/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_grostl_gf8_circuit.c - Tests for the wide-node Grøstl
 * Merkle circuit (circuits/merkle_grostl_gf8_circuit).
 *
 * Validates:
 *   - node_bytes / inv_in sizing helpers (256 vs 512).
 *   - Software leaf/inode hash helpers agree with core/grostl.c on the
 *     domain-prefixed message (0x00 ‖ data for leaves, 0x01 ‖ L ‖ R for
 *     inodes).
 *   - Domain separation: a leaf hash differs from the inode hash of the
 *     same bytes.
 *   - End-to-end depth-3 path: circuit-evaluated root equals the
 *     software-computed root, and all S-box constraints are satisfied,
 *     for both Grøstl-256 and Grøstl-512.
 *   - Soundness spot-check: a tampered sibling produces a different root.
 */

#include "../circuits/merkle_grostl_gf8_circuit.h"
#include "../core/field.h"
#include "../core/grostl.h"
#include "../proof/gf8_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-60s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

/* ================================================================
 * Reference tree construction (software) for a depth-3, 8-leaf tree.
 * ================================================================ */

#define DEPTH 3
#define N_LEAVES 8
#define LEAF_DATA_BYTES 24

/* Build the full tree; return root and the sibling path for leaf_index. */
static void
build_tree(voleith_merkle_grostl_variant_t variant, size_t leaf_index,
           const uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES], uint8_t *root_out,
           uint8_t *siblings_out /* DEPTH * nb */,
           uint8_t *leaf_hash_out /* nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t lh[N_LEAVES][64];
    for (int i = 0; i < N_LEAVES; i++)
        merkle_grostl_leaf_hash(leaves[i], LEAF_DATA_BYTES, variant, lh[i]);

    uint8_t l1[4][64];
    for (int i = 0; i < 4; i++)
        merkle_grostl_inode_hash(lh[2 * i], lh[2 * i + 1], variant, l1[i]);

    uint8_t l2[2][64];
    for (int i = 0; i < 2; i++)
        merkle_grostl_inode_hash(l1[2 * i], l1[2 * i + 1], variant, l2[i]);

    uint8_t root[64];
    merkle_grostl_inode_hash(l2[0], l2[1], variant, root);

    /* Sibling at each level for the target leaf index. */
    size_t i0 = leaf_index & 1;        /* dir bit 0 */
    size_t i1 = (leaf_index >> 1) & 1; /* dir bit 1 */
    size_t i2 = (leaf_index >> 2) & 1; /* dir bit 2 */

    /* level 0 sibling: the other leaf hash in the pair */
    memcpy(siblings_out + 0 * nb, lh[(leaf_index & ~(size_t)1) | (i0 ^ 1)], nb);
    /* level 1 sibling: the other L1 node in the pair */
    size_t l1_idx = leaf_index >> 1;
    memcpy(siblings_out + 1 * nb, l1[(l1_idx & ~(size_t)1) | (i1 ^ 1)], nb);
    /* level 2 sibling: the other L2 node in the pair */
    size_t l2_idx = leaf_index >> 2;
    memcpy(siblings_out + 2 * nb, l2[(l2_idx & ~(size_t)1) | (i2 ^ 1)], nb);

    memcpy(root_out, root, nb);
    memcpy(leaf_hash_out, lh[leaf_index], nb);
}

/* ================================================================
 * Build + evaluate the depth-3 path circuit; return the circuit-
 * computed root and the constraint-satisfaction flag.
 * ================================================================ */

static int
eval_path(voleith_merkle_grostl_variant_t variant,
          const uint8_t leaf_data[LEAF_DATA_BYTES],
          const uint8_t *siblings /* DEPTH * nb */,
          const uint8_t path_dirs[DEPTH], uint8_t *root_out /* nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return -1;

    /* (1) leaf data witness wires. */
    gf8_wire_id leaf_wires[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    /* (2) leaf hash (adds leaf inv_in internally). */
    gf8_wire_id leaf_hash_wires[64];
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_wires, LEAF_DATA_BYTES, variant,
                                        leaf_hash_wires);

    /* (3) sibling witness wires. */
    gf8_wire_id *node_wires = malloc(DEPTH * nb * sizeof(*node_wires));
    for (size_t i = 0; i < DEPTH * nb; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    /* (4) path circuit (adds per-level inode inv_in internally). */
    gf8_wire_id root_wires[64];
    merkle_grostl_gf8_path_circuit(c, leaf_hash_wires, node_wires, path_dirs,
                                   DEPTH, variant, root_wires);

    /* ----- assemble the witness in declaration order ----- */
    size_t leaf_invin =
        merkle_grostl_gf8_leaf_invin_bytes(LEAF_DATA_BYTES, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);
    size_t total =
        LEAF_DATA_BYTES + leaf_invin + DEPTH * nb + DEPTH * inode_invin;

    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    /* leaf data */
    memcpy(witness + off, leaf_data, LEAF_DATA_BYTES);
    off += LEAF_DATA_BYTES;

    /* leaf inv_in */
    merkle_grostl_gf8_leaf_build_witness(leaf_data, LEAF_DATA_BYTES, variant,
                                         witness + off);
    off += leaf_invin;

    /* siblings */
    memcpy(witness + off, siblings, DEPTH * nb);
    off += DEPTH * nb;

    /* per-level inode inv_in.  Walk the path to know each (L, R). */
    uint8_t current[64];
    merkle_grostl_leaf_hash(leaf_data, LEAF_DATA_BYTES, variant, current);

    for (size_t lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + lvl * nb;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_grostl_gf8_inode_build_witness(L, R, variant, witness + off);
        off += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    /* ----- evaluate ----- */
    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (size_t i = 0; i < nb; i++)
        root_out[i] = vals[root_wires[i]];

    free(vals);
    free(witness);
    free(node_wires);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Secret-dir path: the swap is muxed in-circuit from a private
 * direction wire.  The witness builder mirrors the circuit's
 * voleith_gf8_add_mux:
 *
 *   left[i]  = current[i] XOR dir * (current[i] XOR sibling[i])
 *   right[i] = left[i]    XOR (current[i] XOR sibling[i])
 *
 * Evaluating the GF(2^8) blend (rather than a 0/1 swap) lets the same
 * builder serve the booleanity test, where dir is deliberately not a
 * bit.
 * ================================================================ */

static void
mux_blend(const uint8_t *current, const uint8_t *sibling, uint8_t dir,
          size_t nb, uint8_t *left, uint8_t *right)
{
    for (size_t i = 0; i < nb; i++) {
        uint8_t cs = (uint8_t)(current[i] ^ sibling[i]);
        left[i] = (uint8_t)(current[i] ^ voleith_gf8_mul(dir, cs));
        right[i] = (uint8_t)(left[i] ^ cs);
    }
}

static int
eval_path_secret_dir(voleith_merkle_grostl_variant_t variant,
                     const uint8_t leaf_data[LEAF_DATA_BYTES],
                     const uint8_t *siblings /* DEPTH * nb */,
                     const uint8_t dirs[DEPTH], uint8_t *root_out /* nb */)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return -1;

    /* (1) leaf data witness wires. */
    gf8_wire_id leaf_wires[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    /* (2) leaf hash (adds leaf inv_in internally). */
    gf8_wire_id leaf_hash_wires[64];
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_wires, LEAF_DATA_BYTES, variant,
                                        leaf_hash_wires);

    /* (3) sibling witness wires, then (4) private direction witness wires. */
    gf8_wire_id *node_wires = malloc(DEPTH * nb * sizeof(*node_wires));
    for (size_t i = 0; i < DEPTH * nb; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id dir_wires[DEPTH];
    for (int i = 0; i < DEPTH; i++)
        dir_wires[i] = voleith_gf8_add_witness(c);

    /* (5) secret-dir path circuit (adds per-level inode inv_in internally). */
    gf8_wire_id root_wires[64];
    merkle_grostl_gf8_path_circuit_secret_dir(
        c, leaf_hash_wires, node_wires, dir_wires, DEPTH, variant, root_wires);

    /* ----- assemble the witness in declaration order ----- */
    size_t leaf_invin =
        merkle_grostl_gf8_leaf_invin_bytes(LEAF_DATA_BYTES, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);
    size_t total =
        LEAF_DATA_BYTES + leaf_invin + DEPTH * nb + DEPTH + DEPTH * inode_invin;

    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    /* leaf data */
    memcpy(witness + off, leaf_data, LEAF_DATA_BYTES);
    off += LEAF_DATA_BYTES;

    /* leaf inv_in */
    merkle_grostl_gf8_leaf_build_witness(leaf_data, LEAF_DATA_BYTES, variant,
                                         witness + off);
    off += leaf_invin;

    /* siblings, then direction bits */
    memcpy(witness + off, siblings, DEPTH * nb);
    off += DEPTH * nb;
    memcpy(witness + off, dirs, DEPTH);
    off += DEPTH;

    /* per-level inode inv_in.  Walk the path, muxing (L, R) from dir. */
    uint8_t current[64];
    merkle_grostl_leaf_hash(leaf_data, LEAF_DATA_BYTES, variant, current);

    for (size_t lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + lvl * nb;
        uint8_t L[64], R[64];
        mux_blend(current, sib, dirs[lvl], nb, L, R);

        merkle_grostl_gf8_inode_build_witness(L, R, variant, witness + off);
        off += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    /* ----- evaluate ----- */
    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);

    for (size_t i = 0; i < nb; i++)
        root_out[i] = vals[root_wires[i]];

    free(vals);
    free(witness);
    free(node_wires);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Tests
 * ================================================================ */

static void
test_node_bytes(void)
{
    TEST("node_bytes: 256 -> 32, 256_T27 -> 27, 512 -> 64");
    if (merkle_grostl_node_bytes(VOLEITH_MERKLE_GROSTL_256) == 32 &&
        merkle_grostl_node_bytes(VOLEITH_MERKLE_GROSTL_256_T27) == 27 &&
        merkle_grostl_node_bytes(VOLEITH_MERKLE_GROSTL_512) == 64)
        PASS();
    else
        FAIL("wrong node size");
}

static void
test_inode_invin_sizes(void)
{
    /* GROSTL_256 inode message = 1 + 64 = 65 bytes -> 2 compressions:
     * 2*1280 + 640 = 3200 S-boxes. */
    TEST("inode inv_in size: GROSTL_256 == 3200");
    if (merkle_grostl_gf8_inode_invin_bytes(VOLEITH_MERKLE_GROSTL_256) == 3200)
        PASS();
    else
        FAIL("expected 3200");

    /* GROSTL_256_T27 inode message = 1 + 54 = 55 bytes -> 1 compression
     * (the whole point of the 27-byte truncation): 1280 + 640 = 1920. */
    TEST("inode inv_in size: GROSTL_256_T27 == 1920 (1 block)");
    if (merkle_grostl_gf8_inode_invin_bytes(VOLEITH_MERKLE_GROSTL_256_T27) ==
        1920)
        PASS();
    else
        FAIL("expected 1920");

    /* GROSTL_512 inode message = 1 + 128 = 129 bytes -> 2 compressions:
     * 2*3584 + 1792 = 8960 S-boxes. */
    TEST("inode inv_in size: GROSTL_512 == 8960");
    if (merkle_grostl_gf8_inode_invin_bytes(VOLEITH_MERKLE_GROSTL_512) == 8960)
        PASS();
    else
        FAIL("expected 8960");

    /* GROSTL_512_T59 inode message = 1 + 118 = 119 bytes -> 1 compression
     * (the 27-byte analogue, one tier up): 1*3584 + 1792 = 5376. */
    TEST("inode inv_in size: GROSTL_512_T59 == 5376 (1 block)");
    if (merkle_grostl_gf8_inode_invin_bytes(VOLEITH_MERKLE_GROSTL_512_T59) ==
        5376)
        PASS();
    else
        FAIL("expected 5376");
}

/* The _T27 hash is Grøstl-256 truncated to its first 27 output bytes. */
static void
test_t27_truncation(void)
{
    uint8_t Ln[27], Rn[27];
    for (int i = 0; i < 27; i++) {
        Ln[i] = (uint8_t)(0xA0 + i);
        Rn[i] = (uint8_t)(0x10 + i);
    }

    /* Reference: full Grøstl-256(0x01 ‖ L ‖ R), then take the first 27 bytes. */
    uint8_t pre[1 + 54];
    pre[0] = 0x01;
    memcpy(pre + 1, Ln, 27);
    memcpy(pre + 28, Rn, 27);
    uint8_t full[32];
    voleith_grostl256(full, pre, sizeof(pre));

    uint8_t got[27];
    merkle_grostl_inode_hash(Ln, Rn, VOLEITH_MERKLE_GROSTL_256_T27, got);

    TEST("T27 inode == first 27 bytes of Grøstl-256(0x01 ‖ L ‖ R)");
    if (memcmp(full, got, 27) == 0)
        PASS();
    else
        FAIL("truncation mismatch");
}

/* The _T59 hash is Grøstl-512 truncated to its first 59 output bytes. */
static void
test_t59_truncation(void)
{
    uint8_t Ln[59], Rn[59];
    for (int i = 0; i < 59; i++) {
        Ln[i] = (uint8_t)(0xA0 + i);
        Rn[i] = (uint8_t)(0x10 + i);
    }

    /* Reference: full Grøstl-512(0x01 ‖ L ‖ R), then take the first 59 bytes. */
    uint8_t pre[1 + 118];
    pre[0] = 0x01;
    memcpy(pre + 1, Ln, 59);
    memcpy(pre + 60, Rn, 59);
    uint8_t full[64];
    voleith_grostl512(full, pre, sizeof(pre));

    uint8_t got[59];
    merkle_grostl_inode_hash(Ln, Rn, VOLEITH_MERKLE_GROSTL_512_T59, got);

    TEST("T59 inode == first 59 bytes of Grøstl-512(0x01 ‖ L ‖ R)");
    if (memcmp(full, got, 59) == 0)
        PASS();
    else
        FAIL("truncation mismatch");
}

static void
test_leaf_invin_size(void)
{
    /* GROSTL_256 leaf message = 1 + 24 = 25 bytes -> 1 compression:
     * 1280 + 640 = 1920 S-boxes. */
    TEST("leaf inv_in size: GROSTL_256 24B leaf == 1920");
    if (merkle_grostl_gf8_leaf_invin_bytes(LEAF_DATA_BYTES,
                                           VOLEITH_MERKLE_GROSTL_256) == 1920)
        PASS();
    else
        FAIL("expected 1920");
}

/* Software helper agrees with a hand-rolled prefixed Grøstl call. */
static void
test_sw_helper_matches_grostl(void)
{
    uint8_t data[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        data[i] = (uint8_t)(i * 7 + 1);

    /* leaf: Grøstl-256(0x00 ‖ data) */
    uint8_t prefixed[1 + LEAF_DATA_BYTES];
    prefixed[0] = 0x00;
    memcpy(prefixed + 1, data, LEAF_DATA_BYTES);
    uint8_t ref[32], got[32];
    voleith_grostl256(ref, prefixed, sizeof(prefixed));
    merkle_grostl_leaf_hash(data, LEAF_DATA_BYTES, VOLEITH_MERKLE_GROSTL_256,
                            got);

    TEST("sw leaf hash == Grøstl-256(0x00 ‖ data)");
    if (memcmp(ref, got, 32) == 0)
        PASS();
    else
        FAIL("mismatch");

    /* inode: Grøstl-256(0x01 ‖ L ‖ R) */
    uint8_t Ln[32], Rn[32];
    for (int i = 0; i < 32; i++) {
        Ln[i] = (uint8_t)(0xA0 + i);
        Rn[i] = (uint8_t)(0x10 + i);
    }
    uint8_t pre2[1 + 64];
    pre2[0] = 0x01;
    memcpy(pre2 + 1, Ln, 32);
    memcpy(pre2 + 33, Rn, 32);
    uint8_t ref2[32], got2[32];
    voleith_grostl256(ref2, pre2, sizeof(pre2));
    merkle_grostl_inode_hash(Ln, Rn, VOLEITH_MERKLE_GROSTL_256, got2);

    TEST("sw inode hash == Grøstl-256(0x01 ‖ L ‖ R)");
    if (memcmp(ref2, got2, 32) == 0)
        PASS();
    else
        FAIL("mismatch");
}

/* Domain separation: leaf(x) != inode interpreting x as two halves. */
static void
test_domain_separation(void)
{
    /* 64 bytes that we hash as a leaf, vs as an inode (L=first 32, R=last
     * 32).  The 0x00 vs 0x01 prefix must make these differ. */
    uint8_t data[64];
    for (int i = 0; i < 64; i++)
        data[i] = (uint8_t)i;

    uint8_t as_leaf[32], as_inode[32];
    merkle_grostl_leaf_hash(data, 64, VOLEITH_MERKLE_GROSTL_256, as_leaf);
    merkle_grostl_inode_hash(data, data + 32, VOLEITH_MERKLE_GROSTL_256,
                             as_inode);

    TEST("domain separation: leaf(x) != inode(x[0:32], x[32:64])");
    if (memcmp(as_leaf, as_inode, 32) != 0)
        PASS();
    else
        FAIL("leaf and inode hashes collided");
}

/* End-to-end depth-3 path for one variant + leaf index. */
static void
test_path_roundtrip(voleith_merkle_grostl_variant_t variant, size_t leaf_index,
                    const char *label)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (int i = 0; i < N_LEAVES; i++)
        for (int j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 31 + j);

    uint8_t root[64], siblings[DEPTH * 64], leaf_hash[64];
    build_tree(variant, leaf_index, leaves, root, siblings, leaf_hash);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t computed_root[64];
    int ok =
        eval_path(variant, leaves[leaf_index], siblings, dirs, computed_root);

    char name[96];
    snprintf(name, sizeof(name), "%s: constraints satisfied", label);
    TEST(name);
    if (ok == 1)
        PASS();
    else
        FAIL("circuit constraints not satisfied");

    snprintf(name, sizeof(name), "%s: circuit root == software root", label);
    TEST(name);
    if (memcmp(computed_root, root, nb) == 0)
        PASS();
    else
        FAIL("root mismatch");
}

/* End-to-end depth-3 path with a private (muxed) leaf index. */
static void
test_path_roundtrip_secret_dir(voleith_merkle_grostl_variant_t variant,
                               size_t leaf_index, const char *label)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (int i = 0; i < N_LEAVES; i++)
        for (int j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 31 + j);

    uint8_t root[64], siblings[DEPTH * 64], leaf_hash[64];
    build_tree(variant, leaf_index, leaves, root, siblings, leaf_hash);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t computed_root[64];
    int ok = eval_path_secret_dir(variant, leaves[leaf_index], siblings, dirs,
                                  computed_root);

    char name[96];
    snprintf(name, sizeof(name), "%s: constraints satisfied", label);
    TEST(name);
    if (ok == 1)
        PASS();
    else
        FAIL("circuit constraints not satisfied");

    snprintf(name, sizeof(name), "%s: circuit root == software root", label);
    TEST(name);
    if (memcmp(computed_root, root, nb) == 0)
        PASS();
    else
        FAIL("root mismatch");
}

/*
 * Booleanity: a direction wire carrying a non-bit value (0x02) must make
 * the circuit reject.  The witness is built so that every sibling and
 * every S-box inv_in is internally consistent with the GF(2^8) mux blend
 * for that non-bit selector, so the ONLY violated constraint is the
 * per-level assert_product(dir, dir, dir).  This isolates the in-circuit
 * booleanity enforcement: without it, an unconstrained dir would forge a
 * path through an arbitrary affine blend of the two child orderings.
 */
static void
test_secret_dir_booleanity(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t leaf_index = 5;

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (int i = 0; i < N_LEAVES; i++)
        for (int j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 31 + j);

    uint8_t root[64], siblings[DEPTH * 64], leaf_hash[64];
    build_tree(variant, leaf_index, leaves, root, siblings, leaf_hash);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);
    dirs[1] = 0x02; /* non-bit selector */

    uint8_t computed_root[64];
    int ok = eval_path_secret_dir(variant, leaves[leaf_index], siblings, dirs,
                                  computed_root);

    TEST("secret-dir: non-bit direction wire rejected (dir * dir == dir)");
    if (ok == 0)
        PASS();
    else
        FAIL("non-bit direction accepted");
}

/* Soundness: a tampered sibling must produce a different root. */
static void
test_tamper(void)
{
    voleith_merkle_grostl_variant_t variant = VOLEITH_MERKLE_GROSTL_256;
    size_t nb = merkle_grostl_node_bytes(variant);
    size_t leaf_index = 5;

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (int i = 0; i < N_LEAVES; i++)
        for (int j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 31 + j);

    uint8_t root[64], siblings[DEPTH * 64], leaf_hash[64];
    build_tree(variant, leaf_index, leaves, root, siblings, leaf_hash);

    uint8_t dirs[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    /* Flip one byte of the level-0 sibling. */
    siblings[0] ^= 0xFF;

    uint8_t computed_root[64];
    int ok =
        eval_path(variant, leaves[leaf_index], siblings, dirs, computed_root);

    /* The witness for the (tampered) sibling is still internally
     * consistent, so constraints pass, but the root must differ. */
    TEST("tamper: tampered sibling yields different root");
    if (ok == 1 && memcmp(computed_root, root, nb) != 0)
        PASS();
    else
        FAIL("tampered path still matched root");
}

int
main(void)
{
    printf("=== merkle_grostl_gf8_circuit tests ===\n");

    test_node_bytes();
    test_inode_invin_sizes();
    test_leaf_invin_size();
    test_sw_helper_matches_grostl();
    test_t27_truncation();
    test_t59_truncation();
    test_domain_separation();

    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_256, 5, "GROSTL_256 leaf5");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_256, 0, "GROSTL_256 leaf0");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_256_T27, 5,
                        "GROSTL_256_T27 leaf5");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_256_T27, 2,
                        "GROSTL_256_T27 leaf2");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_512, 5, "GROSTL_512 leaf5");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_512, 3, "GROSTL_512 leaf3");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_512_T59, 5,
                        "GROSTL_512_T59 leaf5");
    test_path_roundtrip(VOLEITH_MERKLE_GROSTL_512_T59, 2,
                        "GROSTL_512_T59 leaf2");

    test_path_roundtrip_secret_dir(VOLEITH_MERKLE_GROSTL_256, 5,
                                   "GROSTL_256 secret-dir leaf5");
    test_path_roundtrip_secret_dir(VOLEITH_MERKLE_GROSTL_256_T27, 6,
                                   "GROSTL_256_T27 secret-dir leaf6");
    test_path_roundtrip_secret_dir(VOLEITH_MERKLE_GROSTL_512, 3,
                                   "GROSTL_512 secret-dir leaf3");
    test_path_roundtrip_secret_dir(VOLEITH_MERKLE_GROSTL_512_T59, 4,
                                   "GROSTL_512_T59 secret-dir leaf4");
    test_secret_dir_booleanity();

    test_tamper();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
