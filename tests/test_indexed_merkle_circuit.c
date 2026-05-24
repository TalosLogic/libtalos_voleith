/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_indexed_merkle_circuit.c - Tests for indexed_merkle_circuit.h
 *
 * Test tree: 8 sorted leaves (values 10,20,...,80), 8-bit values and indices.
 * Target for non-membership proofs: 25 (adjacent leaf: index 1, value=20,
 * next_value=30, next_index=2).  Tree is depth 3.
 *
 * Tests:
 *   1:  AND gate count - DM,   target_bits=8,   index_bits=8,  depth=3 → 29,232
 *   2:  AND gate count - CMAC, target_bits=8,   index_bits=8,  depth=3 → 79,632
 *   3:  AND gate count - DM,   target_bits=16,  index_bits=8,  depth=1 → 14,624
 *       (verifies per-bit scaling of comparison circuit)
 *   4:  AND gate count - DM,   target_bits=128, index_bits=64, depth=1 → 29,696
 *       (multi-block leaf data: 320 bits → 3 DM AES calls = 21,600)
 *   5:  DM   correctness - leaf[1], path {1,0,0}, target=25
 *   6:  CMAC correctness - leaf[1], path {1,0,0}, target=25
 *   7:  DM   correctness - leaf[0], path {0,0,0}, target=15  (all-left path)
 *   8:  DM   correctness - leaf[5], path {1,0,1}, target=65  (mixed directions)
 *   9:  Field binding - wrong next_index produces a different root
 *  10:  Field binding - wrong low_value produces a different root
 *  11:  Soundness - corrupted sibling produces a different root
 */

#include "indexed_merkle_circuit.h"
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

    size_t n_full = msg_bytes / 16;
    size_t last = msg_bytes % 16;
    int pad = (msg_bytes == 0) || (last != 0);

    uint8_t X[16] = {0};
    size_t n_inner = pad ? n_full : (n_full > 0 ? n_full - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t inp[16];
        for (int i = 0; i < 16; i++)
            inp[i] = X[i] ^ msg[blk * 16 + i];
        voleith_aes_encrypt(&ctx, X, inp);
    }

    uint8_t last_inp[16];
    if (!pad) {
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ msg[(n_full - 1) * 16 + i] ^ K1[i];
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last; b++)
            padded[b] = msg[n_full * 16 + b];
        padded[last] = 0x80;
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ padded[i] ^ K2[i];
    }
    voleith_aes_encrypt(&ctx, tag, last_inp);
}

/* ================================================================
 * Software Merkle hash references
 * ================================================================ */

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

static void
leaf_hash_dm_ref(const uint8_t *data, size_t data_bytes, uint8_t out[16])
{
    size_t full = data_bytes / 16;
    size_t last = data_bytes % 16;
    int pad = (data_bytes == 0) || (last != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner = pad ? full : (full > 0 ? full - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t next[16];
        dm_compress_ref(state, data + blk * 16, next);
        memcpy(state, next, 16);
    }

    if (!pad) {
        dm_compress_ref(state, data + (full - 1) * 16, out);
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last; b++)
            padded[b] = data[full * 16 + b];
        padded[last] = 0x80;
        dm_compress_ref(state, padded, out);
    }
}

static void
leaf_hash_cmac_ref(const uint8_t *data, size_t data_bytes, uint8_t out[16])
{
    cmac_ref(MERKLE_LEAF_DOMAIN, 128, data, data_bytes, out);
}

static void
inode_hash_dm_ref(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ MERKLE_INODE_DOMAIN[i];
    dm_compress_ref(L, P, out);
}

static void
inode_hash_cmac_ref(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t msg[32];
    memcpy(msg, L, 16);
    memcpy(msg + 16, R, 16);
    cmac_ref(MERKLE_INODE_DOMAIN, 128, msg, 32, out);
}

/* ================================================================
 * Indexed Merkle tree fixture
 *
 * 8 sorted leaves, 8-bit values 10, 20, …, 80.
 * Leaf i: (value=10+10i, next_value=10+10*(i+1), next_index=i+1).
 * Leaf 7: next_value=255 (sentinel), next_index=0.
 *
 * Leaf data for hashing: [value, next_value, next_index] (3 bytes).
 * ================================================================ */

typedef struct {
    uint8_t value;
    uint8_t next_value;
    uint8_t next_index;
} leaf_rec_t;

static const leaf_rec_t LEAVES[8] = {
    {10, 20, 1}, {20, 30, 2}, {30, 40, 3}, {40, 50, 4},
    {50, 60, 5}, {60, 70, 6}, {70, 80, 7}, {80, 255, 0},
};

static void
build_indexed_tree(void (*lf)(const uint8_t *, size_t, uint8_t[16]),
                   void (*hf)(const uint8_t[16], const uint8_t[16],
                              uint8_t[16]),
                   uint8_t lh[8][16], uint8_t L1[4][16], uint8_t L2[2][16],
                   uint8_t root[16])
{
    for (int i = 0; i < 8; i++) {
        uint8_t d[3] = {LEAVES[i].value, LEAVES[i].next_value,
                        LEAVES[i].next_index};
        lf(d, 3, lh[i]);
    }
    for (int i = 0; i < 4; i++)
        hf(lh[2 * i], lh[2 * i + 1], L1[i]);
    for (int i = 0; i < 2; i++)
        hf(L1[2 * i], L1[2 * i + 1], L2[i]);
    hf(L2[0], L2[1], root);
}

/* ================================================================
 * AND gate count helper
 * ================================================================ */

static size_t
count_and_gates(voleith_merkle_hash_t hash, size_t target_bits,
                size_t index_bits, size_t depth)
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id *tgt = calloc(target_bits, sizeof(wire_id));
    wire_id *lv = calloc(target_bits, sizeof(wire_id));
    wire_id *ln = calloc(target_bits, sizeof(wire_id));
    wire_id *ni = calloc(index_bits, sizeof(wire_id));
    wire_id *pn = calloc(depth * 128, sizeof(wire_id));
    wire_id *pd = calloc(depth, sizeof(wire_id));

    for (size_t i = 0; i < target_bits; i++)
        tgt[i] = voleith_circuit_add_witness(c);
    for (size_t i = 0; i < target_bits; i++)
        lv[i] = voleith_circuit_add_witness(c);
    for (size_t i = 0; i < target_bits; i++)
        ln[i] = voleith_circuit_add_witness(c);
    for (size_t i = 0; i < index_bits; i++)
        ni[i] = voleith_circuit_add_witness(c);
    for (size_t i = 0; i < depth * 128; i++)
        pn[i] = voleith_circuit_add_witness(c);
    for (size_t i = 0; i < depth; i++)
        pd[i] = voleith_circuit_add_witness(c);

    wire_id root[128];
    indexed_merkle_nonmember_circuit(c, tgt, target_bits, lv, ln, ni,
                                     index_bits, pn, pd, depth, hash, root);

    size_t count = voleith_circuit_and_gate_count(c);
    free(tgt);
    free(lv);
    free(ln);
    free(ni);
    free(pn);
    free(pd);
    voleith_circuit_free(c);
    return count;
}

/* ================================================================
 * Circuit evaluation helper
 *
 * All inputs declared as witness wires.
 * Witness layout (8-bit values, 8-bit index, depth=3):
 *   byte  0       target          (8 bits)
 *   byte  1       low_value       (8 bits)
 *   byte  2       low_next        (8 bits)
 *   byte  3       next_index      (8 bits)
 *   bytes 4–51    path_nodes      (3 × 16 bytes = 384 bits)
 *   byte 52 [0:2] path_dirs       (3 bits)
 * Total: 419 bits → 53 bytes.
 * ================================================================ */

static void
eval_nonmember_circuit(uint8_t target_val, uint8_t low_value_val,
                       uint8_t low_next_val, uint8_t next_index_val,
                       const uint8_t path_nodes[3][16],
                       const uint8_t path_dirs_arr[3],
                       voleith_merkle_hash_t hash, uint8_t root_out[16])
{
    voleith_circuit_t *c = voleith_circuit_new();

    wire_id tgt_w[8], lv_w[8], ln_w[8], ni_w[8];
    for (int i = 0; i < 8; i++)
        tgt_w[i] = voleith_circuit_add_witness(c);
    for (int i = 0; i < 8; i++)
        lv_w[i] = voleith_circuit_add_witness(c);
    for (int i = 0; i < 8; i++)
        ln_w[i] = voleith_circuit_add_witness(c);
    for (int i = 0; i < 8; i++)
        ni_w[i] = voleith_circuit_add_witness(c);

    wire_id pn_w[3 * 128];
    for (int i = 0; i < 3 * 128; i++)
        pn_w[i] = voleith_circuit_add_witness(c);

    wire_id pd_w[3];
    for (int i = 0; i < 3; i++)
        pd_w[i] = voleith_circuit_add_witness(c);

    wire_id root_w[128];
    indexed_merkle_nonmember_circuit(c, tgt_w, 8, lv_w, ln_w, ni_w, 8, pn_w,
                                     pd_w, 3, hash, root_w);

    /* Pack witness (419 bits = 53 bytes) */
    uint8_t witness[53] = {0};
    witness[0] = target_val;
    witness[1] = low_value_val;
    witness[2] = low_next_val;
    witness[3] = next_index_val;
    for (int n = 0; n < 3; n++)
        memcpy(witness + 4 + n * 16, path_nodes[n], 16);
    for (int i = 0; i < 3; i++) {
        if (path_dirs_arr[i]) {
            size_t bit =
                416 + (size_t)i; /* bytes 4..51 = 384 bits; starts at bit 32 */
            witness[bit / 8] |= (uint8_t)(1u << (bit % 8));
        }
    }

    /* Evaluate circuit */
    size_t n_wires = voleith_circuit_wire_count(c);
    uint8_t *wv = calloc((n_wires + 7) / 8, 1);
    voleith_circuit_eval(c, witness, NULL, wv);

    /* Extract root bytes */
    for (int byte = 0; byte < 16; byte++) {
        root_out[byte] = 0;
        for (int bit = 0; bit < 8; bit++) {
            wire_id w = root_w[byte * 8 + bit];
            if ((wv[w / 8] >> (w % 8)) & 1)
                root_out[byte] |= (uint8_t)(1u << bit);
        }
    }

    free(wv);
    voleith_circuit_free(c);
}

/* ================================================================
 * Tests 1–3: AND gate counts
 *
 * DM,   8-bit  target,  8-bit  index, depth=3:
 *   leaf hash:  7,200  (24-bit leaf = partial block, 1 AES)
 *   path:       3 × 7,328 = 21,984
 *   ordering:   2 × 3 × 8  = 48
 *   total:      29,232
 *
 * CMAC, 8-bit  target,  8-bit  index, depth=3:
 *   leaf hash: 14,400  (24-bit leaf = 2 AES: subkey + padded block)
 *   path:       3 × 21,728 = 65,184
 *   ordering:   48
 *   total:      79,632
 *
 * DM,  16-bit  target,  8-bit  index, depth=1:
 *   leaf hash:  7,200  (40-bit leaf = partial block, 1 AES)
 *   path:       1 × 7,328 = 7,328
 *   ordering:   2 × 3 × 16 = 96
 *   total:      14,624
 * ================================================================ */

static void
test_and_gate_counts(void)
{
    check("DM  AND gates (target=8b, idx=8b, depth=3 → 29,232)",
          count_and_gates(VOLEITH_MERKLE_HASH_AES_DM, 8, 8, 3) == 29232);
    check("CMAC AND gates (target=8b, idx=8b, depth=3 → 79,632)",
          count_and_gates(VOLEITH_MERKLE_HASH_AES_CMAC, 8, 8, 3) == 79632);
    check("DM  AND gates (target=16b, idx=8b, depth=1 → 14,624)",
          count_and_gates(VOLEITH_MERKLE_HASH_AES_DM, 16, 8, 1) == 14624);
    /*
     * Multi-block leaf data: 2*128 + 64 = 320 bits = 40 bytes.
     * DM: 2 full inner blocks + 1 padded final = 3 AES calls = 21,600.
     * Path: 1 × 7,328.  Comparisons: 2 × 3 × 128 = 768.  Total: 29,696.
     */
    check("DM  AND gates (target=128b, idx=64b, depth=1 → 29,696, multi-block "
          "leaf)",
          count_and_gates(VOLEITH_MERKLE_HASH_AES_DM, 128, 64, 1) == 29696);
}

/* ================================================================
 * Tests 4–5: Correctness (circuit root matches software reference)
 *
 * Tree: 8 sorted leaves; prove target=25 non-membership via leaf[1].
 * Leaf[1]: value=20, next_value=30, next_index=2.
 * leaf_data = [20, 30, 2] (3 bytes).
 *
 * Path for leaf index 1 (binary 001, LSB-first):
 *   path_dirs   = {1, 0, 0}
 *   path_nodes  = {lh[0], L1[1], L2[1]}
 * ================================================================ */

static void
test_correctness(void)
{
    for (int use_cmac = 0; use_cmac <= 1; use_cmac++) {
        voleith_merkle_hash_t hash = use_cmac ? VOLEITH_MERKLE_HASH_AES_CMAC
                                              : VOLEITH_MERKLE_HASH_AES_DM;
        void (*lf)(const uint8_t *, size_t, uint8_t[16]) =
            use_cmac ? leaf_hash_cmac_ref : leaf_hash_dm_ref;
        void (*hf)(const uint8_t[16], const uint8_t[16], uint8_t[16]) =
            use_cmac ? inode_hash_cmac_ref : inode_hash_dm_ref;

        uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
        build_indexed_tree(lf, hf, lh, L1, L2, ref_root);

        /* Path for leaf[1]: sibling at level 0 = lh[0], level 1 = L1[1], level 2 = L2[1] */
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[0], 16);
        memcpy(path_nodes[1], L1[1], 16);
        memcpy(path_nodes[2], L2[1], 16);
        uint8_t path_dirs[3] = {1, 0, 0}; /* leaf index 1 = 0b001 */

        uint8_t circuit_root[16];
        eval_nonmember_circuit(25, 20, 30, 2, (const uint8_t (*)[16])path_nodes,
                               path_dirs, hash, circuit_root);

        if (!use_cmac)
            check("DM   circuit root matches reference (target=25, leaf[1])",
                  memcmp(circuit_root, ref_root, 16) == 0);
        else
            check("CMAC circuit root matches reference (target=25, leaf[1])",
                  memcmp(circuit_root, ref_root, 16) == 0);
    }
}

/* ================================================================
 * Tests 7–8: Path direction coverage
 *
 * leaf[0]: index 0 = 0b000, path_dirs = {0, 0, 0} (all-left path)
 *   path_nodes = {lh[1], L1[1], L2[1]}, target = 15
 *
 * leaf[5]: index 5 = 0b101, path_dirs = {1, 0, 1} (mixed directions)
 *   path_nodes = {lh[4], L1[3], L2[0]}, target = 65
 * ================================================================ */

static void
test_path_directions(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    /* leaf[0]: all-left path */
    {
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[1], 16); /* sibling at level 0 */
        memcpy(path_nodes[1], L1[1], 16); /* sibling at level 1 */
        memcpy(path_nodes[2], L2[1], 16); /* sibling at level 2 */
        uint8_t path_dirs[3] = {0, 0, 0};

        uint8_t circuit_root[16];
        eval_nonmember_circuit(15, 10, 20, 1, (const uint8_t (*)[16])path_nodes,
                               path_dirs, VOLEITH_MERKLE_HASH_AES_DM,
                               circuit_root);
        check("DM circuit root correct (leaf[0], path {0,0,0}, target=15)",
              memcmp(circuit_root, ref_root, 16) == 0);
    }

    /* leaf[5]: mixed directions {1, 0, 1} */
    {
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[4], 16); /* sibling at level 0 */
        memcpy(path_nodes[1], L1[3], 16); /* sibling at level 1 */
        memcpy(path_nodes[2], L2[0], 16); /* sibling at level 2 */
        uint8_t path_dirs[3] = {1, 0, 1};

        uint8_t circuit_root[16];
        eval_nonmember_circuit(65, 60, 70, 6, (const uint8_t (*)[16])path_nodes,
                               path_dirs, VOLEITH_MERKLE_HASH_AES_DM,
                               circuit_root);
        check("DM circuit root correct (leaf[5], path {1,0,1}, target=65)",
              memcmp(circuit_root, ref_root, 16) == 0);
    }
}

/* ================================================================
 * Tests 9–10: Leaf field binding
 *
 * All three fields (low_value, low_next, next_index) must be committed to
 * by the leaf hash.  Changing any one field while keeping the correct path
 * nodes must produce a different root, confirming the field is included.
 * ================================================================ */

static void
test_field_binding(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    /* Correct path for leaf[1] */
    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[0], 16);
    memcpy(path_nodes[1], L1[1], 16);
    memcpy(path_nodes[2], L2[1], 16);
    uint8_t path_dirs[3] = {1, 0, 0};

    /* Test 9: wrong next_index (2 → 3) - leaf hash input changes */
    {
        uint8_t bad_root[16];
        eval_nonmember_circuit(25, 20, 30,
                               3, /* next_index wrong: 3 instead of 2 */
                               (const uint8_t (*)[16])path_nodes, path_dirs,
                               VOLEITH_MERKLE_HASH_AES_DM, bad_root);
        check("Wrong next_index produces different root (field binding)",
              memcmp(bad_root, ref_root, 16) != 0);
    }

    /* Test 10: wrong low_value (20 → 19) - leaf hash input changes */
    {
        uint8_t bad_root[16];
        eval_nonmember_circuit(25, 19, 30,
                               2, /* low_value wrong: 19 instead of 20 */
                               (const uint8_t (*)[16])path_nodes, path_dirs,
                               VOLEITH_MERKLE_HASH_AES_DM, bad_root);
        check("Wrong low_value produces different root (field binding)",
              memcmp(bad_root, ref_root, 16) != 0);
    }
}

/* ================================================================
 * Test 11: Soundness - corrupted sibling produces a different root
 * ================================================================ */

static void
test_soundness(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[0], 16);
    memcpy(path_nodes[1], L1[1], 16);
    memcpy(path_nodes[2], L2[1], 16);
    uint8_t path_dirs[3] = {1, 0, 0};

    /* Corrupt level-0 sibling */
    uint8_t bad_nodes[3][16];
    memcpy(bad_nodes, path_nodes, sizeof(path_nodes));
    bad_nodes[0][0] ^= 0xff;

    uint8_t bad_root[16];
    eval_nonmember_circuit(25, 20, 30, 2, (const uint8_t (*)[16])bad_nodes,
                           path_dirs, VOLEITH_MERKLE_HASH_AES_DM, bad_root);

    check("Corrupted sibling produces different root (soundness)",
          memcmp(bad_root, ref_root, 16) != 0);
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    printf("=== test_indexed_merkle_circuit ===\n");

    printf("\n[AND gate counts]\n");
    test_and_gate_counts();

    printf("\n[Correctness]\n");
    test_correctness();

    printf("\n[Path direction coverage]\n");
    test_path_directions();

    printf("\n[Leaf field binding]\n");
    test_field_binding();

    printf("\n[Soundness]\n");
    test_soundness();

    printf("\n  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
