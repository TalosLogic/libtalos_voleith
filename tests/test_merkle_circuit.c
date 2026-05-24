/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_circuit.c - Tests for merkle_circuit.h
 *
 * Tests:
 *   1:  DM leaf hash AND gate count (128-bit leaf = 1 AES = 7,200)
 *   2:  CMAC leaf hash AND gate count (128-bit leaf = 2 AES = 14,400)
 *   3:  DM full circuit AND gate count (128-bit leaf, depth=1: 7,200 + 7,328 = 14,528)
 *   4:  CMAC full circuit AND gate count (128-bit leaf, depth=1: 14,400 + 21,728 = 36,128)
 *   5:  DM leaf hash correctness (16-byte leaf vs software reference)
 *   6:  DM leaf hash correctness (empty leaf vs software reference)
 *   7:  CMAC leaf hash correctness (16-byte leaf vs software reference)
 *   8:  CMAC leaf hash correctness (empty leaf vs software reference)
 *   9:  DM end-to-end depth-3 tree (leaf[5] membership proof)
 *  10:  CMAC end-to-end depth-3 tree (leaf[5] membership proof)
 *  11:  Domain separation - DM leaf hash ≠ DM inode hash for same bytes
 *  12:  Domain separation - CMAC leaf hash ≠ CMAC inode hash for same bytes
 *  13:  DM leaf hash correctness (32-byte leaf - exercises inner MD chain loop)
 *  14:  DM leaf hash correctness (8-byte leaf - partial block, non-zero last_bytes)
 *  15:  Wrong sibling → wrong root (soundness: circuit is sensitive to path data)
 *  16:  CMAC256 leaf hash AND gate count (128-bit leaf = 2×9,936 = 19,872)
 *  17:  CMAC256 full circuit AND gate count (depth=1: 19,872 + 29,936 = 49,808)
 *  18:  CMAC256 leaf hash correctness (16-byte leaf vs software reference)
 *  19:  CMAC256 leaf hash correctness (empty leaf vs software reference)
 *  20:  CMAC256 end-to-end depth-3 tree (leaf[5] membership proof)
 *  21:  Domain separation - CMAC256 leaf hash ≠ CMAC256 inode hash for same bytes
 */

#include "merkle_circuit.h"
#include "circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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
 * Domain constants (must match merkle_circuit.c)
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d,
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00};

static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d,
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00};

static const uint8_t MERKLE_LEAF_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, 0x4c, 0x65, 0x61,
    0x66, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t MERKLE_INODE_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, 0x4e, 0x6f, 0x64,
    0x65, 0x2d, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* ================================================================
 * Software AES-CMAC reference (RFC 4493)
 * ================================================================ */

static void
cmac_ref(const uint8_t *key, int key_bits, const uint8_t *msg, size_t msg_bytes,
         uint8_t tag[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, key_bits);

    uint8_t L[16] = {0};
    voleith_aes_encrypt(&ctx, L, L);

    uint8_t K1[16], K2[16];
    uint8_t msb = (L[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        K1[i] = (uint8_t)((L[i] << 1) | (L[i + 1] >> 7));
    K1[15] = (uint8_t)((L[15] << 1) ^ (msb ? 0x87u : 0u));

    msb = (K1[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        K2[i] = (uint8_t)((K1[i] << 1) | (K1[i + 1] >> 7));
    K2[15] = (uint8_t)((K1[15] << 1) ^ (msb ? 0x87u : 0u));

    size_t n_full_blocks = msg_bytes / 16;
    size_t last_bytes = msg_bytes % 16;
    int needs_padding = (msg_bytes == 0) || (last_bytes != 0);

    uint8_t X[16] = {0};
    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t inp[16];
        for (int i = 0; i < 16; i++)
            inp[i] = X[i] ^ msg[blk * 16 + i];
        voleith_aes_encrypt(&ctx, X, inp);
    }

    uint8_t last_inp[16];
    if (!needs_padding) {
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ msg[(n_full_blocks - 1) * 16 + i] ^ K1[i];
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = msg[n_full_blocks * 16 + b];
        padded[last_bytes] = 0x80;
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ padded[i] ^ K2[i];
    }
    voleith_aes_encrypt(&ctx, tag, last_inp);
}

/* ================================================================
 * Software Merkle hash references
 * ================================================================ */

/*
 * dm_compress_ref - AES_{key}(plaintext) XOR plaintext.
 * Used for both the DM leaf MD chain and the DM inode compression.
 */
static void
dm_compress_ref(const uint8_t key[16], const uint8_t plaintext[16],
                uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, plaintext);
    for (int i = 0; i < 16; i++)
        out[i] ^= plaintext[i];
}

/*
 * leaf_hash_dm_ref - Merkle-Damgård DM chain, IV = MERKLE_LEAF_DOMAIN.
 * Padding: CMAC-style (0x80 || zeros for partial/empty last block).
 */
static void
leaf_hash_dm_ref(const uint8_t *data, size_t data_bytes, uint8_t out[16])
{
    size_t full_blocks = data_bytes / 16;
    size_t last_bytes = data_bytes % 16;
    int needs_padding = (data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t next[16];
        dm_compress_ref(state, data + blk * 16, next);
        memcpy(state, next, 16);
    }

    if (!needs_padding) {
        dm_compress_ref(state, data + (full_blocks - 1) * 16, out);
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = data[full_blocks * 16 + b];
        padded[last_bytes] = 0x80;
        dm_compress_ref(state, padded, out);
    }
}

/* leaf_hash_cmac_ref - CMAC(K_leaf, data). */
static void
leaf_hash_cmac_ref(const uint8_t *data, size_t data_bytes, uint8_t out[16])
{
    cmac_ref(MERKLE_LEAF_DOMAIN, 128, data, data_bytes, out);
}

/* inode_hash_dm_ref - H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode). */
static void
inode_hash_dm_ref(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ MERKLE_INODE_DOMAIN[i];
    dm_compress_ref(L, P, out);
}

/* inode_hash_cmac_ref - H(L, R) = CMAC(K_inode, L || R). */
static void
inode_hash_cmac_ref(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t msg[32];
    memcpy(msg, L, 16);
    memcpy(msg + 16, R, 16);
    cmac_ref(MERKLE_INODE_DOMAIN, 128, msg, 32, out);
}

/* leaf_hash_cmac256_ref - CMAC(K_leaf256, data), 256-bit key. */
static void
leaf_hash_cmac256_ref(const uint8_t *data, size_t data_bytes, uint8_t out[16])
{
    cmac_ref(MERKLE_LEAF_DOMAIN_256, 256, data, data_bytes, out);
}

/* inode_hash_cmac256_ref - H(L, R) = CMAC(K_inode256, L || R), 256-bit key. */
static void
inode_hash_cmac256_ref(const uint8_t L[16], const uint8_t R[16],
                       uint8_t out[16])
{
    uint8_t msg[32];
    memcpy(msg, L, 16);
    memcpy(msg + 16, R, 16);
    cmac_ref(MERKLE_INODE_DOMAIN_256, 256, msg, 32, out);
}

/* ================================================================
 * Circuit evaluation helpers
 * ================================================================ */

/*
 * eval_leaf_hash - build a circuit with leaf_data as witness wires,
 * call merkle_leaf_hash_circuit(), evaluate, return 16-byte hash.
 */
static void
eval_leaf_hash(const uint8_t *data, size_t data_bytes,
               voleith_merkle_hash_t hash, uint8_t out[16])
{
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        memset(out, 0, 16);
        return;
    }

    wire_id *leaf_wires = NULL;
    if (data_bytes > 0) {
        leaf_wires = calloc(data_bytes * 8, sizeof(wire_id));
        if (!leaf_wires) {
            voleith_circuit_free(c);
            memset(out, 0, 16);
            return;
        }
        for (size_t i = 0; i < data_bytes * 8; i++)
            leaf_wires[i] = voleith_circuit_add_witness(c);
    }

    wire_id hash_wires[128];
    merkle_leaf_hash_circuit(c, leaf_wires, data_bytes * 8, hash, hash_wires);

    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *wire_vals = calloc((n_wires + 7) / 8, 1);
    if (!wire_vals) {
        free(leaf_wires);
        voleith_circuit_free(c);
        memset(out, 0, 16);
        return;
    }

    voleith_circuit_eval(c, data, NULL, wire_vals);

    for (int byte = 0; byte < 16; byte++) {
        out[byte] = 0;
        for (int bit = 0; bit < 8; bit++) {
            wire_id w = hash_wires[byte * 8 + bit];
            if ((wire_vals[w / 8] >> (w % 8)) & 1)
                out[byte] |= (uint8_t)(1 << bit);
        }
    }

    free(wire_vals);
    free(leaf_wires);
    voleith_circuit_free(c);
}

/*
 * eval_full_proof - build leaf hash + path circuit, evaluate, return root.
 *
 * Witness layout (in order of voleith_circuit_add_witness calls):
 *   [0 .. leaf_bytes*8 - 1]           leaf_data bits
 *   [leaf_bytes*8 .. +depth*128 - 1]  path_nodes bits (depth * 16 bytes)
 *   [leaf_bytes*8+depth*128 .. +depth] path_dirs bits (depth bits)
 */
static void
eval_full_proof(const uint8_t *leaf_data, size_t leaf_bytes, size_t depth,
                const uint8_t (*path_nodes)[16], const uint8_t *path_dirs_arr,
                voleith_merkle_hash_t hash, uint8_t root_out[16])
{
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        memset(root_out, 0, 16);
        return;
    }

    /* leaf_data wires */
    wire_id *leaf_wires = calloc(leaf_bytes * 8, sizeof(wire_id));
    if (!leaf_wires) {
        voleith_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < leaf_bytes * 8; i++)
        leaf_wires[i] = voleith_circuit_add_witness(c);

    wire_id leaf_hash_wires[128];
    merkle_leaf_hash_circuit(c, leaf_wires, leaf_bytes * 8, hash,
                             leaf_hash_wires);

    /* path_nodes wires */
    wire_id *node_wires = calloc(depth * 128, sizeof(wire_id));
    if (!node_wires) {
        free(leaf_wires);
        voleith_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < depth * 128; i++)
        node_wires[i] = voleith_circuit_add_witness(c);

    /* path_dirs wires */
    wire_id *dir_wires = calloc(depth, sizeof(wire_id));
    if (!dir_wires) {
        free(leaf_wires);
        free(node_wires);
        voleith_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < depth; i++)
        dir_wires[i] = voleith_circuit_add_witness(c);

    wire_id root_wires[128];
    merkle_path_circuit(c, leaf_hash_wires, node_wires, dir_wires, depth, hash,
                        root_wires);

    /* Pack witness array */
    size_t n_witness_bits = leaf_bytes * 8 + depth * 128 + depth;
    size_t n_witness_bytes = (n_witness_bits + 7) / 8;
    uint8_t *witness = calloc(n_witness_bytes, 1);
    if (!witness) {
        free(leaf_wires);
        free(node_wires);
        free(dir_wires);
        voleith_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }

    /* leaf_data - byte-aligned, direct copy */
    memcpy(witness, leaf_data, leaf_bytes);

    /* path_nodes - depth * 16 bytes following leaf_data */
    for (size_t lvl = 0; lvl < depth; lvl++)
        memcpy(witness + leaf_bytes + lvl * 16, path_nodes[lvl], 16);

    /* path_dirs - depth bits packed after path_nodes */
    size_t dir_bit_base = leaf_bytes * 8 + depth * 128;
    for (size_t lvl = 0; lvl < depth; lvl++) {
        if (path_dirs_arr[lvl]) {
            size_t idx = dir_bit_base + lvl;
            witness[idx / 8] |= (uint8_t)(1 << (idx % 8));
        }
    }

    /* Evaluate */
    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *wire_vals = calloc((n_wires + 7) / 8, 1);
    if (!wire_vals) {
        free(leaf_wires);
        free(node_wires);
        free(dir_wires);
        free(witness);
        voleith_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }

    voleith_circuit_eval(c, witness, NULL, wire_vals);

    for (int byte = 0; byte < 16; byte++) {
        root_out[byte] = 0;
        for (int bit = 0; bit < 8; bit++) {
            wire_id w = root_wires[byte * 8 + bit];
            if ((wire_vals[w / 8] >> (w % 8)) & 1)
                root_out[byte] |= (uint8_t)(1 << bit);
        }
    }

    free(wire_vals);
    free(witness);
    free(dir_wires);
    free(node_wires);
    free(leaf_wires);
    voleith_circuit_free(c);
}

/* ================================================================
 * Test 1-4: AND gate counts
 * ================================================================ */

static void
test_and_gate_counts(void)
{
    /* Test 1: DM leaf hash, 128-bit leaf → 1 AES = 7,200 AND gates */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        wire_id h[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES_DM, h);
        check("DM leaf hash AND gates (128-bit leaf = 7,200)",
              voleith_circuit_and_gate_count(c) == 7200);
        voleith_circuit_free(c);
    }

    /* Test 2: CMAC leaf hash, 128-bit leaf → 2 AES = 14,400 AND gates */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        wire_id h[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES_CMAC, h);
        check("CMAC leaf hash AND gates (128-bit leaf = 14,400)",
              voleith_circuit_and_gate_count(c) == 14400);
        voleith_circuit_free(c);
    }

    /* Test 3: DM full circuit, depth=1, 128-bit leaf
     *   leaf hash: 7,200 + path level: 128 (mux) + 7,200 (DM) = 14,528 total */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128], sibling[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        for (int i = 0; i < 128; i++)
            sibling[i] = voleith_circuit_add_witness(c);
        wire_id dir = voleith_circuit_add_witness(c);

        wire_id leaf_h[128], root[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES_DM,
                                 leaf_h);
        merkle_path_circuit(c, leaf_h, sibling, &dir, 1,
                            VOLEITH_MERKLE_HASH_AES_DM, root);
        check("DM full circuit AND gates (depth=1, 128-bit leaf = 14,528)",
              voleith_circuit_and_gate_count(c) == 14528);
        voleith_circuit_free(c);
    }

    /* Test 4: CMAC full circuit, depth=1, 128-bit leaf
     *   leaf hash: 14,400 + path level: 128 (mux) + 21,600 (CMAC) = 36,128 total */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128], sibling[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        for (int i = 0; i < 128; i++)
            sibling[i] = voleith_circuit_add_witness(c);
        wire_id dir = voleith_circuit_add_witness(c);

        wire_id leaf_h[128], root[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES_CMAC,
                                 leaf_h);
        merkle_path_circuit(c, leaf_h, sibling, &dir, 1,
                            VOLEITH_MERKLE_HASH_AES_CMAC, root);
        check("CMAC full circuit AND gates (depth=1, 128-bit leaf = 36,128)",
              voleith_circuit_and_gate_count(c) == 36128);
        voleith_circuit_free(c);
    }
}

/* ================================================================
 * Test 5-8: Leaf hash correctness vs software reference
 * ================================================================ */

static void
test_leaf_hash_correctness(void)
{
    static const uint8_t leaf16[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                       0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                       0x73, 0x93, 0x17, 0x2a};

    uint8_t ref[16], got[16];

    /* Test 5: DM leaf hash, 16-byte leaf */
    leaf_hash_dm_ref(leaf16, 16, ref);
    eval_leaf_hash(leaf16, 16, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash circuit matches software (16-byte leaf)",
          memcmp(got, ref, 16) == 0);

    /* Test 6: DM leaf hash, empty leaf */
    leaf_hash_dm_ref(NULL, 0, ref);
    eval_leaf_hash(NULL, 0, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash circuit matches software (empty leaf)",
          memcmp(got, ref, 16) == 0);

    /* Test 7: CMAC leaf hash, 16-byte leaf */
    leaf_hash_cmac_ref(leaf16, 16, ref);
    eval_leaf_hash(leaf16, 16, VOLEITH_MERKLE_HASH_AES_CMAC, got);
    check("CMAC leaf hash circuit matches software (16-byte leaf)",
          memcmp(got, ref, 16) == 0);

    /* Test 8: CMAC leaf hash, empty leaf */
    leaf_hash_cmac_ref(NULL, 0, ref);
    eval_leaf_hash(NULL, 0, VOLEITH_MERKLE_HASH_AES_CMAC, got);
    check("CMAC leaf hash circuit matches software (empty leaf)",
          memcmp(got, ref, 16) == 0);
}

/* ================================================================
 * Test 9-10: End-to-end depth-3 tree (8 leaves, proving leaf[5])
 *
 * Leaves: leaf[i] = {i, i, ..., i} (16 bytes all equal to i).
 * Tree:
 *   lh[i]  = leaf_hash(leaf[i])
 *   L1[i]  = inode_hash(lh[2i], lh[2i+1])
 *   L2[i]  = inode_hash(L1[2i], L1[2i+1])
 *   root   = inode_hash(L2[0], L2[1])
 *
 * Leaf[5] path (index 5 = binary 101):
 *   path_nodes[0] = lh[4],  path_dirs[0] = 1  (leaf 5 is right child)
 *   path_nodes[1] = L1[3],  path_dirs[1] = 0  (L1[2] is left child)
 *   path_nodes[2] = L2[0],  path_dirs[2] = 1  (L2[1] is right child)
 * ================================================================ */

static void
build_tree(void (*leaf_fn)(const uint8_t *, size_t, uint8_t[16]),
           void (*inode_fn)(const uint8_t[16], const uint8_t[16], uint8_t[16]),
           uint8_t lh[8][16], uint8_t L1[4][16], uint8_t L2[2][16],
           uint8_t root[16])
{
    for (int i = 0; i < 8; i++) {
        uint8_t leaf[16];
        memset(leaf, i, 16);
        leaf_fn(leaf, 16, lh[i]);
    }
    for (int i = 0; i < 4; i++)
        inode_fn(lh[2 * i], lh[2 * i + 1], L1[i]);
    for (int i = 0; i < 2; i++)
        inode_fn(L1[2 * i], L1[2 * i + 1], L2[i]);
    inode_fn(L2[0], L2[1], root);
}

static void
test_end_to_end(void)
{
    for (int use_cmac = 0; use_cmac <= 1; use_cmac++) {
        voleith_merkle_hash_t hash = use_cmac ? VOLEITH_MERKLE_HASH_AES_CMAC
                                              : VOLEITH_MERKLE_HASH_AES_DM;
        void (*leaf_fn)(const uint8_t *, size_t, uint8_t[16]) =
            use_cmac ? leaf_hash_cmac_ref : leaf_hash_dm_ref;
        void (*inode_fn)(const uint8_t[16], const uint8_t[16], uint8_t[16]) =
            use_cmac ? inode_hash_cmac_ref : inode_hash_dm_ref;

        uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
        build_tree(leaf_fn, inode_fn, lh, L1, L2, ref_root);

        /* Prove membership for leaf[5] */
        uint8_t leaf5[16];
        memset(leaf5, 5, 16);

        /* path: [lh[4], L1[3], L2[0]], dirs: [1, 0, 1] */
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[4], 16);
        memcpy(path_nodes[1], L1[3], 16);
        memcpy(path_nodes[2], L2[0], 16);
        uint8_t path_dirs[3] = {1, 0, 1};

        uint8_t circuit_root[16];
        eval_full_proof(leaf5, 16, 3, (const uint8_t (*)[16])path_nodes,
                        path_dirs, hash, circuit_root);

        if (!use_cmac)
            check("DM end-to-end depth-3 tree (leaf[5] → root)",
                  memcmp(circuit_root, ref_root, 16) == 0);
        else
            check("CMAC end-to-end depth-3 tree (leaf[5] → root)",
                  memcmp(circuit_root, ref_root, 16) == 0);
    }
}

/* ================================================================
 * Test 11-12: Domain separation (leaf hash ≠ inode hash for same input)
 * ================================================================ */

static void
test_domain_separation(void)
{
    static const uint8_t X[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                  0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                  0x89, 0xab, 0xcd, 0xef};

    uint8_t lh[16], ih[16];

    /* Test 11: DM - leaf_hash_dm(X) vs inode_hash_dm(X, X) */
    leaf_hash_dm_ref(X, 16, lh);
    inode_hash_dm_ref(X, X, ih);
    check("DM domain separation: leaf hash != inode hash for same bytes",
          memcmp(lh, ih, 16) != 0);

    /* Test 12: CMAC - leaf_hash_cmac(X) vs inode_hash_cmac(X, X) */
    leaf_hash_cmac_ref(X, 16, lh);
    inode_hash_cmac_ref(X, X, ih);
    check("CMAC domain separation: leaf hash != inode hash for same bytes",
          memcmp(lh, ih, 16) != 0);
}

/* ================================================================
 * Test 13-14: DM leaf hash multi-block and partial-block correctness
 * ================================================================ */

static void
test_dm_leaf_edge_cases(void)
{
    uint8_t ref[16], got[16];

    /* Test 13: DM leaf hash, 32-byte input (2 full blocks).
     * Exercises the inner MD chaining loop (n_inner = 1).
     * AND gates = 2 AES calls = 14,400. */
    {
        static const uint8_t leaf32[32] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
            0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
            0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51};

        /* AND gate count: 2 full blocks, no padding → 2 AES calls = 14,400 */
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf_w[256];
        for (int i = 0; i < 256; i++)
            leaf_w[i] = voleith_circuit_add_witness(c);
        wire_id h[128];
        merkle_leaf_hash_circuit(c, leaf_w, 256, VOLEITH_MERKLE_HASH_AES_DM, h);
        check("DM leaf hash AND gates (32-byte leaf = 14,400)",
              voleith_circuit_and_gate_count(c) == 14400);
        voleith_circuit_free(c);

        /* Correctness */
        leaf_hash_dm_ref(leaf32, 32, ref);
        eval_leaf_hash(leaf32, 32, VOLEITH_MERKLE_HASH_AES_DM, got);
        check("DM leaf hash circuit matches software (32-byte leaf, 2-block "
              "chain)",
              memcmp(got, ref, 16) == 0);
    }

    /* Test 14: DM leaf hash, 8-byte input (partial block, last_bytes = 8).
     * Exercises the partial-byte copy loop inside the padded-block path.
     * AND gates = 1 AES call = 7,200. */
    {
        static const uint8_t leaf8[8] = {0xde, 0xad, 0xbe, 0xef,
                                         0xca, 0xfe, 0xf0, 0x0d};

        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf_w[64];
        for (int i = 0; i < 64; i++)
            leaf_w[i] = voleith_circuit_add_witness(c);
        wire_id h[128];
        merkle_leaf_hash_circuit(c, leaf_w, 64, VOLEITH_MERKLE_HASH_AES_DM, h);
        check("DM leaf hash AND gates (8-byte leaf = 7,200)",
              voleith_circuit_and_gate_count(c) == 7200);
        voleith_circuit_free(c);

        leaf_hash_dm_ref(leaf8, 8, ref);
        eval_leaf_hash(leaf8, 8, VOLEITH_MERKLE_HASH_AES_DM, got);
        check("DM leaf hash circuit matches software (8-byte leaf, partial "
              "block)",
              memcmp(got, ref, 16) == 0);
    }
}

/* ================================================================
 * Test 15: Wrong sibling → wrong root (soundness check)
 *
 * A valid proof for leaf[5] computes the correct root.  Providing a
 * corrupted sibling at level 0 must produce a different root - the
 * circuit output is sensitive to the path data.
 * ================================================================ */

static void
test_wrong_path_rejected(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2, ref_root);

    uint8_t leaf5[16];
    memset(leaf5, 5, 16);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[4], 16);
    memcpy(path_nodes[1], L1[3], 16);
    memcpy(path_nodes[2], L2[0], 16);
    uint8_t path_dirs[3] = {1, 0, 1};

    /* Corrupt the level-0 sibling by flipping one byte. */
    uint8_t bad_nodes[3][16];
    memcpy(bad_nodes, path_nodes, sizeof(path_nodes));
    bad_nodes[0][0] ^= 0xff;

    uint8_t bad_root[16];
    eval_full_proof(leaf5, 16, 3, (const uint8_t (*)[16])bad_nodes, path_dirs,
                    VOLEITH_MERKLE_HASH_AES_DM, bad_root);

    check("Wrong sibling produces different root (soundness)",
          memcmp(bad_root, ref_root, 16) != 0);
}

/* ================================================================
 * Tests 16-21: AES-256-CMAC variants
 * ================================================================ */

static void
test_cmac256_gate_counts(void)
{
    /* Test 16: CMAC256 leaf hash, 128-bit leaf
     *   Subkey gen (1 AES-256) + 1 CBC-MAC block (1 AES-256) = 2 × 9,936 = 19,872 */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        wire_id h[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES256_CMAC,
                                 h);
        check("CMAC256 leaf hash AND gates (128-bit leaf = 19,872)",
              voleith_circuit_and_gate_count(c) == 19872);
        voleith_circuit_free(c);
    }

    /* Test 17: CMAC256 full circuit, depth=1, 128-bit leaf
     *   leaf hash: 19,872 + path level: 128 (mux) + 29,808 (CMAC256 inode) = 49,808 */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id leaf[128], sibling[128];
        for (int i = 0; i < 128; i++)
            leaf[i] = voleith_circuit_add_witness(c);
        for (int i = 0; i < 128; i++)
            sibling[i] = voleith_circuit_add_witness(c);
        wire_id dir = voleith_circuit_add_witness(c);

        wire_id leaf_h[128], root[128];
        merkle_leaf_hash_circuit(c, leaf, 128, VOLEITH_MERKLE_HASH_AES256_CMAC,
                                 leaf_h);
        merkle_path_circuit(c, leaf_h, sibling, &dir, 1,
                            VOLEITH_MERKLE_HASH_AES256_CMAC, root);
        check("CMAC256 full circuit AND gates (depth=1, 128-bit leaf = 49,808)",
              voleith_circuit_and_gate_count(c) == 49808);
        voleith_circuit_free(c);
    }
}

static void
test_cmac256_leaf_hash_correctness(void)
{
    static const uint8_t leaf16[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40,
                                       0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11,
                                       0x73, 0x93, 0x17, 0x2a};

    uint8_t ref[16], got[16];

    /* Test 18: CMAC256 leaf hash, 16-byte leaf */
    leaf_hash_cmac256_ref(leaf16, 16, ref);
    eval_leaf_hash(leaf16, 16, VOLEITH_MERKLE_HASH_AES256_CMAC, got);
    check("CMAC256 leaf hash circuit matches software (16-byte leaf)",
          memcmp(got, ref, 16) == 0);

    /* Test 19: CMAC256 leaf hash, empty leaf */
    leaf_hash_cmac256_ref(NULL, 0, ref);
    eval_leaf_hash(NULL, 0, VOLEITH_MERKLE_HASH_AES256_CMAC, got);
    check("CMAC256 leaf hash circuit matches software (empty leaf)",
          memcmp(got, ref, 16) == 0);
}

static void
test_cmac256_end_to_end(void)
{
    /* Test 20: CMAC256 depth-3 tree, leaf[5] membership proof */
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_tree(leaf_hash_cmac256_ref, inode_hash_cmac256_ref, lh, L1, L2,
               ref_root);

    uint8_t leaf5[16];
    memset(leaf5, 5, 16);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[4], 16);
    memcpy(path_nodes[1], L1[3], 16);
    memcpy(path_nodes[2], L2[0], 16);
    uint8_t path_dirs[3] = {1, 0, 1};

    uint8_t circuit_root[16];
    eval_full_proof(leaf5, 16, 3, (const uint8_t (*)[16])path_nodes, path_dirs,
                    VOLEITH_MERKLE_HASH_AES256_CMAC, circuit_root);

    check("CMAC256 end-to-end depth-3 tree (leaf[5] → root)",
          memcmp(circuit_root, ref_root, 16) == 0);
}

static void
test_cmac256_domain_separation(void)
{
    /* Test 21: CMAC256 leaf hash ≠ CMAC256 inode hash for same input bytes */
    static const uint8_t X[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                  0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                  0x89, 0xab, 0xcd, 0xef};

    uint8_t lh[16], ih[16];
    leaf_hash_cmac256_ref(X, 16, lh);
    inode_hash_cmac256_ref(X, X, ih);
    check("CMAC256 domain separation: leaf hash != inode hash for same bytes",
          memcmp(lh, ih, 16) != 0);
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    printf("=== test_merkle_circuit ===\n");

    printf("\n[AND gate counts]\n");
    test_and_gate_counts();

    printf("\n[Leaf hash correctness]\n");
    test_leaf_hash_correctness();

    printf("\n[End-to-end tree proofs]\n");
    test_end_to_end();

    printf("\n[Domain separation]\n");
    test_domain_separation();

    printf("\n[DM leaf hash edge cases]\n");
    test_dm_leaf_edge_cases();

    printf("\n[Soundness: wrong path rejected]\n");
    test_wrong_path_rejected();

    printf("\n[AES-256-CMAC: AND gate counts]\n");
    test_cmac256_gate_counts();

    printf("\n[AES-256-CMAC: leaf hash correctness]\n");
    test_cmac256_leaf_hash_correctness();

    printf("\n[AES-256-CMAC: end-to-end tree proof]\n");
    test_cmac256_end_to_end();

    printf("\n[AES-256-CMAC: domain separation]\n");
    test_cmac256_domain_separation();

    printf("\n  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
