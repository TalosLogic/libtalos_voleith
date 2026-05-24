/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_indexed_merkle_gf8_circuit.c - Tests for indexed_merkle_gf8_circuit.h
 *
 * Test tree: 8 sorted leaves (values 10,20,...,80), 8-bit (1-byte) values and indices.
 * Target for non-membership proofs: 25 (adjacent leaf: index 1, value=20,
 * next_value=30, next_index=2). Tree depth = 3.
 *
 * Tests (public-dir variant):
 *   1:  VOLE slot count (ell) - DM,   target_bytes=1, index_bytes=1, depth=3 → 900
 *   2:  VOLE slot count (ell) - CMAC, target_bytes=1, index_bytes=1, depth=3 → 2300
 *   3:  VOLE slot count (ell) - DM,   target_bytes=2, index_bytes=1, depth=1 → 519
 *       (verifies per-byte scaling of comparison circuit)
 *   4:  VOLE slot count (ell) - DM,   target_bytes=16, index_bytes=8, depth=1 → 1640
 *       (multi-block leaf data: 40 bytes → 3 DM AES calls)
 *   5:  DM   correctness - leaf[1], path {1,0,0}, target=25
 *   6:  CMAC correctness - leaf[1], path {1,0,0}, target=25
 *   7:  DM   correctness - leaf[0], path {0,0,0}, target=15  (all-left path)
 *   8:  DM   correctness - leaf[5], path {1,0,1}, target=65  (mixed directions)
 *   9:  Field binding - wrong next_index produces a different root
 *  10:  Field binding - wrong low_value produces a different root
 *  11:  Soundness - corrupted sibling produces a different root
 *
 * Tests (secret-dir variant - path_dirs as private witness wires):
 *  12:  VOLE slot count (ell) - DM,   target_bytes=1, index_bytes=1, depth=3 → 951
 *       (+depth witnesses for dir wires, +16×depth mul gates for mux; delta = +51)
 *  13:  VOLE slot count (ell) - CMAC, target_bytes=1, index_bytes=1, depth=3 → 2351
 *  14:  DM   correctness - leaf[1], path {1,0,0}, target=25  (dirs as witnesses)
 *  15:  CMAC correctness - leaf[1], path {1,0,0}, target=25
 *  16:  DM   correctness - leaf[5], path {1,0,1}, target=65  (mixed dirs as witnesses)
 *  17:  Equivalence - secret-dir root equals public-dir root for same inputs
 *  18:  Wrong path_dir produces different root (direction encoding is binding)
 */

#include "indexed_merkle_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
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
 * Domain constants (must match merkle_gf8_circuit.c)
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
 * 8 sorted leaves, 8-bit (1-byte) values 10, 20, …, 80.
 * Leaf i: (value=10+10i, next_value=10+10*(i+1), next_index=i+1).
 * Leaf 7: next_value=255 (sentinel), next_index=0.
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
 * VOLE slot count helper
 *
 * Builds the circuit with all caller-supplied wires as witnesses,
 * returns voleith_gf8_qs_ell(c) = n_witness + n_mul.
 * ================================================================ */

static size_t
count_ell(voleith_merkle_hash_t hash, size_t target_bytes, size_t index_bytes,
          size_t depth)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id *tgt = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *lv = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *ln = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *ni = calloc(index_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *pn = calloc(depth * 16, sizeof(gf8_wire_id));

    for (size_t i = 0; i < target_bytes; i++)
        tgt[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < target_bytes; i++)
        lv[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < target_bytes; i++)
        ln[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < index_bytes; i++)
        ni[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < depth * 16; i++)
        pn[i] = voleith_gf8_add_witness(c);

    uint8_t dirs[64] = {0}; /* all-left path; only depth entries used */
    gf8_wire_id root[16];
    indexed_merkle_gf8_nonmember_circuit(c, tgt, target_bytes, lv, ln, ni,
                                         index_bytes, pn, dirs, depth, hash,
                                         root);

    size_t ell = voleith_gf8_qs_ell(c);
    free(tgt);
    free(lv);
    free(ln);
    free(ni);
    free(pn);
    voleith_gf8_circuit_free(c);
    return ell;
}

/* ================================================================
 * Witness building helpers (reused from Merkle GF8 pattern)
 * ================================================================ */

static void
dm_leaf_inv_in(const uint8_t *data, size_t data_bytes, uint8_t *inv_out,
               uint8_t leaf_hash_out[16])
{
    size_t full_blocks = data_bytes / 16;
    size_t last_bytes = data_bytes % 16;
    int needs_padding = (data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);
    uint8_t *inv_ptr = inv_out;

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t tmp_w[216], cipher[16];
        aes128_gf8_build_witness(state, data + blk * 16, tmp_w, cipher);
        memcpy(inv_ptr, tmp_w + 16, 200);
        inv_ptr += 200;
        for (int i = 0; i < 16; i++)
            state[i] = cipher[i] ^ data[blk * 16 + i];
    }

    uint8_t block[16] = {0};
    if (!needs_padding) {
        memcpy(block, data + (full_blocks - 1) * 16, 16);
    } else {
        if (last_bytes > 0)
            memcpy(block, data + full_blocks * 16, last_bytes);
        block[last_bytes] = 0x80;
    }
    uint8_t tmp_w[216], cipher[16];
    aes128_gf8_build_witness(state, block, tmp_w, cipher);
    memcpy(inv_ptr, tmp_w + 16, 200);
    if (leaf_hash_out)
        for (int i = 0; i < 16; i++)
            leaf_hash_out[i] = cipher[i] ^ block[i];
}

static size_t
dm_n_aes(size_t data_bytes)
{
    size_t full = data_bytes / 16;
    int needs_pad = (data_bytes == 0) || (data_bytes % 16 != 0);
    return needs_pad ? full + 1 : (full > 0 ? full : 1);
}

static void
cmac_leaf_inv_in(const uint8_t *key, size_t key_bytes, const uint8_t *data,
                 size_t data_bytes, uint8_t *inv_out, uint8_t tag[16])
{
    size_t inv_per_call = (key_bytes == 16) ? 200u : 276u;
    size_t n_aes = aes_cmac_gf8_n_aes_calls(data_bytes);
    size_t tmp_size = key_bytes + n_aes * inv_per_call;
    uint8_t *tmp_w = calloc(tmp_size, 1);
    if (!tmp_w)
        return;
    aes_cmac_gf8_build_witness(key, key_bytes, data, data_bytes, tmp_w, tag);
    memcpy(inv_out, tmp_w + key_bytes, n_aes * inv_per_call);
    free(tmp_w);
}

static void
dm_inode_inv_in(const uint8_t L[16], const uint8_t R[16],
                const uint8_t C_inode[16], uint8_t inv_out[200],
                uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ C_inode[i];
    uint8_t tmp_w[216], cipher[16];
    aes128_gf8_build_witness(L, P, tmp_w, cipher);
    memcpy(inv_out, tmp_w + 16, 200);
    if (out)
        for (int i = 0; i < 16; i++)
            out[i] = cipher[i] ^ P[i];
}

static void
cmac_inode_inv_in(const uint8_t *key, size_t key_bytes, const uint8_t L[16],
                  const uint8_t R[16], uint8_t *inv_out, uint8_t out[16])
{
    uint8_t msg[32];
    memcpy(msg, L, 16);
    memcpy(msg + 16, R, 16);
    cmac_leaf_inv_in(key, key_bytes, msg, 32, inv_out, out);
}

/* ================================================================
 * Circuit evaluation helper
 *
 * All caller-supplied inputs declared as witness wires.
 * Uses 1-byte target, low_value, low_next, next_index; depth=3.
 *
 * Witness layout:
 *   Slot 0:       target          (1 byte)
 *   Slot 1:       low_value       (1 byte)
 *   Slot 2:       low_next        (1 byte)
 *   Slot 3:       next_index      (1 byte)
 *   Slots 4..51:  path_nodes      (3 × 16 bytes = 48 bytes)
 *   Slots 52..251: inv_in for leaf hash  (DM: 200; CMAC: 400)
 *   Then inv_in for 3 inode AES calls, in order.
 * ================================================================ */

static void
eval_nonmember_gf8(uint8_t target_val, uint8_t low_value_val,
                   uint8_t low_next_val, uint8_t next_index_val,
                   const uint8_t path_nodes[3][16],
                   const uint8_t path_dirs_arr[3], voleith_merkle_hash_t hash,
                   uint8_t root_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    /* 1-byte wires for each field */
    gf8_wire_id tgt_w[1], lv_w[1], ln_w[1], ni_w[1];
    tgt_w[0] = voleith_gf8_add_witness(c);
    lv_w[0] = voleith_gf8_add_witness(c);
    ln_w[0] = voleith_gf8_add_witness(c);
    ni_w[0] = voleith_gf8_add_witness(c);

    /* 3 × 16 path node wires */
    gf8_wire_id pn_w[48];
    for (int i = 0; i < 48; i++)
        pn_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[16];
    indexed_merkle_gf8_nonmember_circuit(c, tgt_w, 1, lv_w, ln_w, ni_w, 1, pn_w,
                                         path_dirs_arr, 3, hash, root_w);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    size_t n_witness = voleith_gf8_circuit_witness_count(c);

    uint8_t *witness = calloc(n_witness, 1);
    uint8_t *wire_vals = calloc(n_wires, 1);

    /* Fill witness: [target][low_value][low_next][next_index][path_nodes][inv_in...] */
    uint8_t *wp = witness;
    *wp++ = target_val;
    *wp++ = low_value_val;
    *wp++ = low_next_val;
    *wp++ = next_index_val;

    /* path_nodes */
    for (int n = 0; n < 3; n++) {
        memcpy(wp, path_nodes[n], 16);
        wp += 16;
    }

    /* inv_in for leaf hash: leaf_data = [low_value, low_next, next_index] (3 bytes) */
    uint8_t leaf_data[3] = {low_value_val, low_next_val, next_index_val};
    uint8_t leaf_hash_val[16];

    if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
        dm_leaf_inv_in(leaf_data, 3, wp, leaf_hash_val);
        wp += dm_n_aes(3) * 200;
    } else {
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN, 16, leaf_data, 3, wp,
                         leaf_hash_val);
        wp += aes_cmac_gf8_n_aes_calls(3) * 200;
    }

    /* inv_in for 3 inode AES calls */
    uint8_t current[16];
    memcpy(current, leaf_hash_val, 16);

    for (int lvl = 0; lvl < 3; lvl++) {
        const uint8_t *sibling = path_nodes[lvl];
        uint8_t dir = path_dirs_arr[lvl];
        const uint8_t *L = dir ? sibling : current;
        const uint8_t *R = dir ? current : sibling;
        uint8_t next[16];

        if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
            dm_inode_inv_in(L, R, MERKLE_INODE_DOMAIN, wp, next);
            wp += 200;
        } else {
            size_t n = aes_cmac_gf8_n_aes_calls(32);
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN, 16, L, R, wp, next);
            wp += n * 200;
        }
        memcpy(current, next, 16);
    }

    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (int k = 0; k < 16; k++)
        root_out[k] = wire_vals[root_w[k]];

    free(wire_vals);
    free(witness);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Tests 1–4: VOLE slot counts (ell = n_witness + n_mul)
 *
 * DM, target_bytes=1, index_bytes=1, depth=3:
 *   Witnesses: (1+1+1+1) + 3×16 + 1×200 + 3×200 = 852
 *   Mul gates: 2 × 3 × 8 × 1 = 48
 *   ell = 900
 *
 * CMAC, target_bytes=1, index_bytes=1, depth=3:
 *   Witnesses: 4 + 48 + 2×200 + 3×3×200 = 4+48+400+1800 = 2252
 *   Mul gates: 48
 *   ell = 2300
 *
 * DM, target_bytes=2, index_bytes=1, depth=1:
 *   Witnesses: 7 + 16 + 200 + 200 = 423
 *   Mul gates: 2 × 3 × 8 × 2 = 96
 *   ell = 519
 *
 * DM, target_bytes=16, index_bytes=8, depth=1:
 *   leaf=40 bytes → dm_n_aes(40)=3 AES calls → 600 inv_in
 *   Witnesses: (16+16+16+8) + 16 + 600 + 200 = 872
 *   Mul gates: 2 × 3 × 8 × 16 = 768
 *   ell = 1640
 * ================================================================ */

static void
test_ell_counts(void)
{
    check("DM  ell (target=1B, idx=1B, depth=3 → 900)",
          count_ell(VOLEITH_MERKLE_HASH_AES_DM, 1, 1, 3) == 900);
    check("CMAC ell (target=1B, idx=1B, depth=3 → 2300)",
          count_ell(VOLEITH_MERKLE_HASH_AES_CMAC, 1, 1, 3) == 2300);
    check("DM  ell (target=2B, idx=1B, depth=1 → 519)",
          count_ell(VOLEITH_MERKLE_HASH_AES_DM, 2, 1, 1) == 519);
    check("DM  ell (target=16B, idx=8B, depth=1 → 1640, multi-block leaf)",
          count_ell(VOLEITH_MERKLE_HASH_AES_DM, 16, 8, 1) == 1640);
}

/* ================================================================
 * Tests 5–6: Correctness (circuit root matches software reference)
 *
 * Tree: 8 sorted leaves; prove target=25 non-membership via leaf[1].
 * Leaf[1]: value=20, next_value=30, next_index=2.  leaf_data = [20,30,2].
 *
 * Path for leaf index 1 (binary 001, LSB-first): path_dirs = {1, 0, 0}
 * path_nodes = {lh[0], L1[1], L2[1]}
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

        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[0], 16);
        memcpy(path_nodes[1], L1[1], 16);
        memcpy(path_nodes[2], L2[1], 16);
        uint8_t path_dirs[3] = {1, 0, 0};

        uint8_t circuit_root[16];
        eval_nonmember_gf8(25, 20, 30, 2, (const uint8_t (*)[16])path_nodes,
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
 * Tests 7–8: Path direction coverage (DM only)
 *
 * leaf[0]: index 0 = 0b000, path_dirs = {0,0,0}  target=15
 * leaf[5]: index 5 = 0b101, path_dirs = {1,0,1}  target=65
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
        memcpy(path_nodes[0], lh[1], 16);
        memcpy(path_nodes[1], L1[1], 16);
        memcpy(path_nodes[2], L2[1], 16);
        uint8_t path_dirs[3] = {0, 0, 0};

        uint8_t circuit_root[16];
        eval_nonmember_gf8(15, 10, 20, 1, (const uint8_t (*)[16])path_nodes,
                           path_dirs, VOLEITH_MERKLE_HASH_AES_DM, circuit_root);
        check("DM circuit root correct (leaf[0], path {0,0,0}, target=15)",
              memcmp(circuit_root, ref_root, 16) == 0);
    }

    /* leaf[5]: mixed directions {1,0,1} */
    {
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[4], 16);
        memcpy(path_nodes[1], L1[3], 16);
        memcpy(path_nodes[2], L2[0], 16);
        uint8_t path_dirs[3] = {1, 0, 1};

        uint8_t circuit_root[16];
        eval_nonmember_gf8(65, 60, 70, 6, (const uint8_t (*)[16])path_nodes,
                           path_dirs, VOLEITH_MERKLE_HASH_AES_DM, circuit_root);
        check("DM circuit root correct (leaf[5], path {1,0,1}, target=65)",
              memcmp(circuit_root, ref_root, 16) == 0);
    }
}

/* ================================================================
 * Tests 9–10: Leaf field binding
 * ================================================================ */

static void
test_field_binding(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[0], 16);
    memcpy(path_nodes[1], L1[1], 16);
    memcpy(path_nodes[2], L2[1], 16);
    uint8_t path_dirs[3] = {1, 0, 0};

    /* Test 9: wrong next_index (2 → 3) */
    {
        uint8_t bad_root[16];
        eval_nonmember_gf8(25, 20, 30, 3, (const uint8_t (*)[16])path_nodes,
                           path_dirs, VOLEITH_MERKLE_HASH_AES_DM, bad_root);
        check("Wrong next_index produces different root (field binding)",
              memcmp(bad_root, ref_root, 16) != 0);
    }

    /* Test 10: wrong low_value (20 → 19) */
    {
        uint8_t bad_root[16];
        eval_nonmember_gf8(25, 19, 30, 2, (const uint8_t (*)[16])path_nodes,
                           path_dirs, VOLEITH_MERKLE_HASH_AES_DM, bad_root);
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

    uint8_t bad_nodes[3][16];
    memcpy(bad_nodes, path_nodes, sizeof(path_nodes));
    bad_nodes[0][0] ^= 0xff;

    uint8_t bad_root[16];
    eval_nonmember_gf8(25, 20, 30, 2, (const uint8_t (*)[16])bad_nodes,
                       path_dirs, VOLEITH_MERKLE_HASH_AES_DM, bad_root);

    check("Corrupted sibling produces different root (soundness)",
          memcmp(bad_root, ref_root, 16) != 0);
}

/* ================================================================
 * Secret-dir helpers
 * ================================================================ */

/*
 * count_ell_secret_dir - same as count_ell but path_dirs are witness wires.
 *
 * Witness cost delta vs. public-dir:
 *   +depth witness slots (one per direction bit)
 *   +16×depth mul gates (one voleith_gf8_add_mux per output byte per level)
 */
static size_t
count_ell_secret_dir(voleith_merkle_hash_t hash, size_t target_bytes,
                     size_t index_bytes, size_t depth)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id *tgt = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *lv = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *ln = calloc(target_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *ni = calloc(index_bytes, sizeof(gf8_wire_id));
    gf8_wire_id *pn = calloc(depth * 16, sizeof(gf8_wire_id));
    gf8_wire_id *pd = calloc(depth, sizeof(gf8_wire_id));

    for (size_t i = 0; i < target_bytes; i++)
        tgt[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < target_bytes; i++)
        lv[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < target_bytes; i++)
        ln[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < index_bytes; i++)
        ni[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < depth * 16; i++)
        pn[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < depth; i++)
        pd[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root[16];
    indexed_merkle_gf8_nonmember_circuit_secret_dir(c, tgt, target_bytes, lv,
                                                    ln, ni, index_bytes, pn, pd,
                                                    depth, hash, root);

    size_t ell = voleith_gf8_qs_ell(c);
    free(tgt);
    free(lv);
    free(ln);
    free(ni);
    free(pn);
    free(pd);
    voleith_gf8_circuit_free(c);
    return ell;
}

/*
 * eval_nonmember_gf8_secret_dir - evaluates the secret-dir circuit.
 *
 * Witness layout (slot order = declaration order):
 *   [0]       target
 *   [1]       low_value
 *   [2]       low_next
 *   [3]       next_index
 *   [4..51]   path_nodes (3 × 16 bytes)
 *   [52..54]  path_dirs  (3 bytes, each 0x00 or 0x01)
 *   [55+]     inv_in for leaf hash then per-level AES inv_in
 *             (same content as public-dir, starting 3 slots later)
 */
static void
eval_nonmember_gf8_secret_dir(uint8_t target_val, uint8_t low_value_val,
                              uint8_t low_next_val, uint8_t next_index_val,
                              const uint8_t path_nodes[3][16],
                              const uint8_t path_dirs_arr[3],
                              voleith_merkle_hash_t hash, uint8_t root_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id tgt_w[1], lv_w[1], ln_w[1], ni_w[1];
    tgt_w[0] = voleith_gf8_add_witness(c);
    lv_w[0] = voleith_gf8_add_witness(c);
    ln_w[0] = voleith_gf8_add_witness(c);
    ni_w[0] = voleith_gf8_add_witness(c);

    gf8_wire_id pn_w[48];
    for (int i = 0; i < 48; i++)
        pn_w[i] = voleith_gf8_add_witness(c);

    /* Direction bits as private witness wires */
    gf8_wire_id pd_w[3];
    for (int i = 0; i < 3; i++)
        pd_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[16];
    indexed_merkle_gf8_nonmember_circuit_secret_dir(
        c, tgt_w, 1, lv_w, ln_w, ni_w, 1, pn_w, pd_w, 3, hash, root_w);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    size_t n_witness = voleith_gf8_circuit_witness_count(c);

    uint8_t *witness = calloc(n_witness, 1);
    uint8_t *wire_vals = calloc(n_wires, 1);

    uint8_t *wp = witness;
    *wp++ = target_val;
    *wp++ = low_value_val;
    *wp++ = low_next_val;
    *wp++ = next_index_val;

    for (int n = 0; n < 3; n++) {
        memcpy(wp, path_nodes[n], 16);
        wp += 16;
    }

    /* Direction bits */
    for (int i = 0; i < 3; i++)
        *wp++ = path_dirs_arr[i];

    /* inv_in for leaf hash */
    uint8_t leaf_data[3] = {low_value_val, low_next_val, next_index_val};
    uint8_t leaf_hash_val[16];

    if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
        dm_leaf_inv_in(leaf_data, 3, wp, leaf_hash_val);
        wp += dm_n_aes(3) * 200;
    } else {
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN, 16, leaf_data, 3, wp,
                         leaf_hash_val);
        wp += aes_cmac_gf8_n_aes_calls(3) * 200;
    }

    /* inv_in for 3 inode AES calls */
    uint8_t current[16];
    memcpy(current, leaf_hash_val, 16);

    for (int lvl = 0; lvl < 3; lvl++) {
        const uint8_t *sibling = path_nodes[lvl];
        uint8_t dir = path_dirs_arr[lvl];
        const uint8_t *L = dir ? sibling : current;
        const uint8_t *R = dir ? current : sibling;
        uint8_t next[16];

        if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
            dm_inode_inv_in(L, R, MERKLE_INODE_DOMAIN, wp, next);
            wp += 200;
        } else {
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN, 16, L, R, wp, next);
            wp += aes_cmac_gf8_n_aes_calls(32) * 200;
        }
        memcpy(current, next, 16);
    }

    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (int k = 0; k < 16; k++)
        root_out[k] = wire_vals[root_w[k]];

    free(wire_vals);
    free(witness);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Tests 12–13: VOLE slot counts for secret-dir variant
 *
 * vs. public-dir, each depth=3 case adds +3 witnesses + 48 mul gates = +51
 *   DM:   900 + 51 = 951
 *   CMAC: 2300 + 51 = 2351
 * ================================================================ */

static void
test_ell_counts_secret_dir(void)
{
    check("secret-dir DM  ell (target=1B, idx=1B, depth=3 → 951)",
          count_ell_secret_dir(VOLEITH_MERKLE_HASH_AES_DM, 1, 1, 3) == 951);
    check("secret-dir CMAC ell (target=1B, idx=1B, depth=3 → 2351)",
          count_ell_secret_dir(VOLEITH_MERKLE_HASH_AES_CMAC, 1, 1, 3) == 2351);
}

/* ================================================================
 * Tests 14–15: Correctness - secret-dir root matches software reference
 * ================================================================ */

static void
test_correctness_secret_dir(void)
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

        /* leaf[1]: index 1 = 0b001, path_dirs = {1,0,0} */
        uint8_t path_nodes[3][16];
        memcpy(path_nodes[0], lh[0], 16);
        memcpy(path_nodes[1], L1[1], 16);
        memcpy(path_nodes[2], L2[1], 16);
        uint8_t path_dirs[3] = {1, 0, 0};

        uint8_t circuit_root[16];
        eval_nonmember_gf8_secret_dir(25, 20, 30, 2,
                                      (const uint8_t (*)[16])path_nodes,
                                      path_dirs, hash, circuit_root);

        if (!use_cmac)
            check("secret-dir DM   root matches reference (target=25, leaf[1])",
                  memcmp(circuit_root, ref_root, 16) == 0);
        else
            check("secret-dir CMAC root matches reference (target=25, leaf[1])",
                  memcmp(circuit_root, ref_root, 16) == 0);
    }
}

/* ================================================================
 * Test 16: Mixed directions as private witnesses (leaf[5], {1,0,1})
 * ================================================================ */

static void
test_secret_dir_mixed_path(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[4], 16);
    memcpy(path_nodes[1], L1[3], 16);
    memcpy(path_nodes[2], L2[0], 16);
    uint8_t path_dirs[3] = {1, 0, 1};

    uint8_t circuit_root[16];
    eval_nonmember_gf8_secret_dir(65, 60, 70, 6,
                                  (const uint8_t (*)[16])path_nodes, path_dirs,
                                  VOLEITH_MERKLE_HASH_AES_DM, circuit_root);

    check("secret-dir DM root correct (leaf[5], path {1,0,1}, target=65)",
          memcmp(circuit_root, ref_root, 16) == 0);
}

/* ================================================================
 * Test 17: Equivalence - secret-dir and public-dir produce identical roots
 * ================================================================ */

static void
test_secret_public_equivalence(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[0], 16);
    memcpy(path_nodes[1], L1[1], 16);
    memcpy(path_nodes[2], L2[1], 16);
    uint8_t path_dirs[3] = {1, 0, 0};

    uint8_t pub_root[16], sec_root[16];
    eval_nonmember_gf8(25, 20, 30, 2, (const uint8_t (*)[16])path_nodes,
                       path_dirs, VOLEITH_MERKLE_HASH_AES_DM, pub_root);
    eval_nonmember_gf8_secret_dir(25, 20, 30, 2,
                                  (const uint8_t (*)[16])path_nodes, path_dirs,
                                  VOLEITH_MERKLE_HASH_AES_DM, sec_root);

    check(
        "secret-dir root equals public-dir root for same inputs (equivalence)",
        memcmp(pub_root, sec_root, 16) == 0);
}

/* ================================================================
 * Test 18: Wrong direction bit produces different root (direction binding)
 *
 * Flip path_dirs[0] from 1 → 0 for leaf[1] (correct is {1,0,0}).
 * This makes the circuit place the leaf on the wrong side → different root.
 * ================================================================ */

static void
test_secret_dir_binding(void)
{
    uint8_t lh[8][16], L1[4][16], L2[2][16], ref_root[16];
    build_indexed_tree(leaf_hash_dm_ref, inode_hash_dm_ref, lh, L1, L2,
                       ref_root);

    uint8_t path_nodes[3][16];
    memcpy(path_nodes[0], lh[0], 16);
    memcpy(path_nodes[1], L1[1], 16);
    memcpy(path_nodes[2], L2[1], 16);

    uint8_t wrong_dirs[3] = {0, 0, 0}; /* correct is {1, 0, 0} */

    uint8_t bad_root[16];
    eval_nonmember_gf8_secret_dir(25, 20, 30, 2,
                                  (const uint8_t (*)[16])path_nodes, wrong_dirs,
                                  VOLEITH_MERKLE_HASH_AES_DM, bad_root);

    check("Wrong path_dir produces different root (direction encoding is "
          "binding)",
          memcmp(bad_root, ref_root, 16) != 0);
}

/* ================================================================
 * main
 * ================================================================ */

/*
 * CIR-2 regression: both nonmember builders return -1 when
 * (2*target_bytes + index_bytes) exceeds LEAF_DATA_MAX_BYTES
 * (= VOLEITH_STACK_BUF_MAX/sizeof(gf8_wire_id) = 4096/4 = 1024
 * with the current settings).  Previously this case silently
 * returned without building any circuit.
 *
 * Inputs are chosen large enough that the bound check fires
 * before any of target / low_value / low_next / next_index / path
 * is dereferenced, so dummy single-wire pointers are sufficient.
 */
static void
test_cir2_stack_bound_signaled(void)
{
    /* target_bytes = 600 → leaf_data_bytes = 2*600 + 1 = 1201 > 1024 */
    const size_t HUGE_TGT = 600;

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id dummy_w = voleith_gf8_add_witness(c);
    gf8_wire_id dummy_i = voleith_gf8_add_instance(c);
    uint8_t dummy_dir = 0;
    gf8_wire_id root[16];

    int rc_pub = indexed_merkle_gf8_nonmember_circuit(
        c, &dummy_w, HUGE_TGT, &dummy_w, &dummy_w, &dummy_i, 1, &dummy_i,
        &dummy_dir, 1, VOLEITH_MERKLE_HASH_AES_DM, root);
    check("CIR-2: indexed_merkle_gf8_nonmember_circuit returns -1 on "
          "stack-VLA bound violation",
          rc_pub == -1);

    int rc_sec = indexed_merkle_gf8_nonmember_circuit_secret_dir(
        c, &dummy_w, HUGE_TGT, &dummy_w, &dummy_w, &dummy_i, 1, &dummy_i,
        &dummy_w, 1, VOLEITH_MERKLE_HASH_AES_DM, root);
    check("CIR-2: indexed_merkle_gf8_nonmember_circuit_secret_dir returns -1 "
          "on stack-VLA bound violation",
          rc_sec == -1);

    voleith_gf8_circuit_free(c);
}

int
main(void)
{
    test_ell_counts();
    test_correctness();
    test_path_directions();
    test_field_binding();
    test_soundness();

    test_ell_counts_secret_dir();
    test_correctness_secret_dir();
    test_secret_dir_mixed_path();
    test_secret_public_equivalence();
    test_secret_dir_binding();

    test_cir2_stack_bound_signaled();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
