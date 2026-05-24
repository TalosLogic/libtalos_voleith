/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_merkle_gf8_circuit.c - Tests for merkle_gf8_circuit.h
 *
 * Tests (public-dir):
 *   1:  DM leaf hash witness count (128-bit leaf = 16 + 200 = 216)
 *   2:  CMAC leaf hash witness count (128-bit leaf = 16 + 2×200 = 416)
 *   3:  DM full circuit witness count (128-bit leaf, depth=1: 16+200+16+200=432)
 *   4:  CMAC full circuit witness count (128-bit leaf, depth=1: 16+400+16+600=1032)
 *   5:  DM leaf hash correctness (16-byte leaf vs software reference)
 *   6:  DM leaf hash correctness (empty leaf vs software reference)
 *   7:  CMAC leaf hash correctness (16-byte leaf vs software reference)
 *   8:  CMAC leaf hash correctness (empty leaf vs software reference)
 *   9:  DM end-to-end depth-3 tree (leaf[5] membership proof)
 *  10:  CMAC end-to-end depth-3 tree (leaf[5] membership proof)
 *  11:  Domain separation - DM leaf hash ≠ DM inode hash for same bytes
 *  12:  Domain separation - CMAC leaf hash ≠ CMAC inode hash for same bytes
 *  13:  DM leaf hash correctness (32-byte leaf - exercises inner MD chain loop)
 *  14:  DM leaf hash correctness (8-byte leaf - partial block)
 *  15:  Wrong sibling → wrong root (soundness: circuit is sensitive to path data)
 *  16:  CMAC256 leaf hash witness count (128-bit leaf = 16 + 2×276 = 568)
 *  17:  CMAC256 full circuit witness count (depth=1: 568+16+3×276=1412)
 *  18:  CMAC256 leaf hash correctness (16-byte leaf vs software reference)
 *  19:  CMAC256 leaf hash correctness (empty leaf vs software reference)
 *  20:  CMAC256 end-to-end depth-3 tree (leaf[5] membership proof)
 *  21:  Domain separation - CMAC256 leaf hash ≠ CMAC256 inode hash for same bytes
 *
 * Tests (secret-dir - path_dirs as private gf8_wire_id witnesses):
 *  22:  DM  secret-dir witness count (depth=1: 16+200+16+1+200 = 433, +1 vs public-dir)
 *  23:  CMAC secret-dir witness count (depth=1: 16+400+16+1+600 = 1033)
 *  24:  DM  secret-dir depth-3 correctness (leaf[5], dirs as witnesses)
 *  25:  CMAC secret-dir depth-3 correctness (leaf[5], dirs as witnesses)
 *  26:  Equivalence - secret-dir root equals public-dir root for same inputs
 *  27:  Wrong direction bit produces different root (direction encoding is binding)
 */

#include "merkle_gf8_circuit.h"
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

/* dm_compress_ref - AES_{key}(plaintext) XOR plaintext. */
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

/* leaf_hash_dm_ref - Merkle-Damgård DM chain, IV = MERKLE_LEAF_DOMAIN. */
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
 * Witness building helpers
 *
 * The GF8 circuit witness vector has one byte per witness slot, in
 * declaration order.  For Merkle circuits:
 *   slots 0..data_bytes-1      : leaf_data (added by caller before leaf_hash)
 *   slots data_bytes..          : inv_in for AES calls inside leaf_hash
 *   slots (after leaf_hash)..  : path_node bytes (added by caller before path_circuit)
 *   slots (after path_nodes).. : inv_in for AES calls inside path_circuit
 *
 * These helpers fill the inv_in portion of the witness.
 * ================================================================ */

/*
 * dm_leaf_inv_in - compute inv_in bytes for DM leaf hash.
 *
 * Also returns the leaf hash value (for use as circuit input to path level).
 * inv_out must have dm_n_aes * 200 bytes allocated.
 */
static size_t
dm_n_aes(size_t data_bytes)
{
    size_t full_blocks = data_bytes / 16;
    int needs_padding = (data_bytes == 0) || (data_bytes % 16 != 0);
    return needs_padding ? full_blocks + 1
                         : (full_blocks > 0 ? full_blocks : 1);
}

static void
dm_leaf_inv_in(const uint8_t *data, size_t data_bytes, uint8_t *inv_out,
               uint8_t leaf_hash[16])
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
    if (leaf_hash)
        for (int i = 0; i < 16; i++)
            leaf_hash[i] = cipher[i] ^ block[i];
}

/*
 * cmac_leaf_inv_in - compute inv_in bytes for CMAC leaf hash.
 *
 * Strips the key prefix from aes_cmac_gf8_build_witness output.
 * inv_out must have aes_cmac_gf8_n_aes_calls(data_bytes) * inv_per_call bytes.
 */
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

/*
 * dm_inode_inv_in - compute inv_in bytes for one DM inode compression.
 *
 * H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode).
 * inv_out must have 200 bytes.
 */
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

/*
 * cmac_inode_inv_in - compute inv_in bytes for one CMAC inode compression.
 *
 * H(L, R) = CMAC(K_inode, L || R).
 * inv_out must have aes_cmac_gf8_n_aes_calls(32) * inv_per_call bytes.
 */
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
 * Circuit evaluation helpers
 * ================================================================ */

/*
 * eval_leaf_hash_gf8 - build a GF8 circuit with leaf_data as witness wires,
 * call merkle_gf8_leaf_hash_circuit(), build witness, evaluate, return 16-byte hash.
 */
static void
eval_leaf_hash_gf8(const uint8_t *data, size_t data_bytes,
                   voleith_merkle_hash_t hash, uint8_t out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        memset(out, 0, 16);
        return;
    }

    gf8_wire_id *leaf_wires = NULL;
    if (data_bytes > 0) {
        leaf_wires = calloc(data_bytes, sizeof(gf8_wire_id));
        if (!leaf_wires) {
            voleith_gf8_circuit_free(c);
            memset(out, 0, 16);
            return;
        }
        for (size_t i = 0; i < data_bytes; i++)
            leaf_wires[i] = voleith_gf8_add_witness(c);
    }

    gf8_wire_id hash_wires[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_wires, data_bytes, hash, hash_wires);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    size_t n_witness = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(n_witness, 1);
    uint8_t *wire_vals = calloc(n_wires, 1);
    if (!witness || !wire_vals) {
        free(witness);
        free(wire_vals);
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(out, 0, 16);
        return;
    }

    /* Fill witness: leaf_data bytes followed by inv_in bytes. */
    if (data_bytes > 0)
        memcpy(witness, data, data_bytes);

    uint8_t *inv_ptr = witness + data_bytes;
    size_t inv_per_call;

    if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
        dm_leaf_inv_in(data, data_bytes, inv_ptr, NULL);
    } else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC) {
        inv_per_call = 276u;
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN_256, 32, data, data_bytes, inv_ptr,
                         NULL);
    } else {
        inv_per_call = 200u;
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN, 16, data, data_bytes, inv_ptr,
                         NULL);
    }
    (void)inv_per_call;

    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (int k = 0; k < 16; k++)
        out[k] = wire_vals[hash_wires[k]];

    free(wire_vals);
    free(witness);
    free(leaf_wires);
    voleith_gf8_circuit_free(c);
}

/*
 * eval_full_proof_gf8 - build leaf hash + path circuit, evaluate, return root.
 *
 * Witness layout (in order of voleith_gf8_add_witness calls):
 *   [leaf_bytes]              leaf_data bytes
 *   [inv_leaf]                inv_in for leaf hash AES calls
 *   [depth × 16]              path_node bytes (all nodes added before path_circuit)
 *   [inv_path]                inv_in for path AES calls (one per level, in order)
 *
 * path_dirs: plain uint8_t array (0 or 1), NOT witness wires.
 */
static void
eval_full_proof_gf8(const uint8_t *leaf_data, size_t leaf_bytes, size_t depth,
                    uint8_t (*path_nodes)[16], const uint8_t *path_dirs_arr,
                    voleith_merkle_hash_t hash, uint8_t root_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        memset(root_out, 0, 16);
        return;
    }

    /* Leaf data wires */
    gf8_wire_id *leaf_wires =
        calloc(leaf_bytes > 0 ? leaf_bytes : 1, sizeof(gf8_wire_id));
    if (!leaf_wires) {
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < leaf_bytes; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id leaf_hash_wires[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_bytes > 0 ? leaf_wires : NULL,
                                 leaf_bytes, hash, leaf_hash_wires);

    /* Path node wires (all depth*16 wires added together before path_circuit) */
    gf8_wire_id *node_wires = calloc(depth * 16 + 1, sizeof(gf8_wire_id));
    if (!node_wires) {
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < depth * 16; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_wires[16];
    merkle_gf8_path_circuit(c, leaf_hash_wires, node_wires, path_dirs_arr,
                            depth, hash, root_wires);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    size_t n_witness = voleith_gf8_circuit_witness_count(c);

    uint8_t *witness = calloc(n_witness, 1);
    uint8_t *wire_vals = calloc(n_wires, 1);
    if (!witness || !wire_vals) {
        free(witness);
        free(wire_vals);
        free(node_wires);
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }

    /* Fill witness: leaf_data | inv_leaf | path_nodes | inv_path */
    uint8_t *wp = witness;

    /* 1. leaf_data */
    memcpy(wp, leaf_data, leaf_bytes);
    wp += leaf_bytes;

    /* 2. inv_in for leaf hash AES calls + compute leaf hash value */
    uint8_t leaf_hash_val[16];
    if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
        size_t n = dm_n_aes(leaf_bytes);
        dm_leaf_inv_in(leaf_data, leaf_bytes, wp, leaf_hash_val);
        wp += n * 200;
    } else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC) {
        size_t n = aes_cmac_gf8_n_aes_calls(leaf_bytes);
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN_256, 32, leaf_data, leaf_bytes, wp,
                         leaf_hash_val);
        wp += n * 276;
    } else {
        size_t n = aes_cmac_gf8_n_aes_calls(leaf_bytes);
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN, 16, leaf_data, leaf_bytes, wp,
                         leaf_hash_val);
        wp += n * 200;
    }

    /* 3. path_node bytes */
    for (size_t lvl = 0; lvl < depth; lvl++) {
        memcpy(wp, path_nodes[lvl], 16);
        wp += 16;
    }

    /* 4. inv_in for path AES calls, one level at a time */
    uint8_t current[16];
    memcpy(current, leaf_hash_val, 16);

    for (size_t lvl = 0; lvl < depth; lvl++) {
        const uint8_t *sibling = path_nodes[lvl];
        uint8_t dir = path_dirs_arr[lvl];
        const uint8_t *L = dir ? sibling : current;
        const uint8_t *R = dir ? current : sibling;
        uint8_t next[16];

        if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
            dm_inode_inv_in(L, R, MERKLE_INODE_DOMAIN, wp, next);
            wp += 200;
        } else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC) {
            size_t n = aes_cmac_gf8_n_aes_calls(32);
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN_256, 32, L, R, wp, next);
            wp += n * 276;
        } else {
            size_t n = aes_cmac_gf8_n_aes_calls(32);
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN, 16, L, R, wp, next);
            wp += n * 200;
        }

        memcpy(current, next, 16);
    }

    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (int k = 0; k < 16; k++)
        root_out[k] = wire_vals[root_wires[k]];

    free(wire_vals);
    free(witness);
    free(node_wires);
    free(leaf_wires);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Test 1-4: Witness counts
 * ================================================================ */

static void
test_witness_counts(void)
{
    /* Test 1: DM leaf hash, 128-bit leaf → 16 (leaf) + 200 (1 AES) = 216 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_DM,
                                     h);
        check("DM leaf hash witnesses (128-bit leaf = 216)",
              voleith_gf8_circuit_witness_count(c) == 216);
        voleith_gf8_circuit_free(c);
    }

    /* Test 2: CMAC leaf hash, 128-bit leaf → 16 (leaf) + 2×200 = 416 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_CMAC,
                                     h);
        check("CMAC leaf hash witnesses (128-bit leaf = 416)",
              voleith_gf8_circuit_witness_count(c) == 416);
        voleith_gf8_circuit_free(c);
    }

    /* Test 3: DM full circuit, depth=1, 128-bit leaf
     *   leaf: 16+200=216; path_node: 16; inode: 200; total: 432 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16], sibling[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id leaf_h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_DM,
                                     leaf_h);
        for (int i = 0; i < 16; i++)
            sibling[i] = voleith_gf8_add_witness(c);
        uint8_t dir = 0;
        gf8_wire_id root[16];
        merkle_gf8_path_circuit(c, leaf_h, sibling, &dir, 1,
                                VOLEITH_MERKLE_HASH_AES_DM, root);
        check("DM full circuit witnesses (depth=1, 128-bit leaf = 432)",
              voleith_gf8_circuit_witness_count(c) == 432);
        voleith_gf8_circuit_free(c);
    }

    /* Test 4: CMAC full circuit, depth=1, 128-bit leaf
     *   leaf: 16+2×200=416; path_node: 16; inode(32B msg): 3×200=600; total: 1032 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16], sibling[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id leaf_h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_CMAC,
                                     leaf_h);
        for (int i = 0; i < 16; i++)
            sibling[i] = voleith_gf8_add_witness(c);
        uint8_t dir = 0;
        gf8_wire_id root[16];
        merkle_gf8_path_circuit(c, leaf_h, sibling, &dir, 1,
                                VOLEITH_MERKLE_HASH_AES_CMAC, root);
        check("CMAC full circuit witnesses (depth=1, 128-bit leaf = 1032)",
              voleith_gf8_circuit_witness_count(c) == 1032);
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * Tests 5-8: Leaf hash correctness
 * ================================================================ */

static void
test_leaf_hash_correctness(void)
{
    static const uint8_t leaf16[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                       0x0d, 0x0e, 0x0f, 0x10};

    uint8_t got[16], expected[16];

    /* Test 5: DM, 16-byte leaf */
    leaf_hash_dm_ref(leaf16, 16, expected);
    eval_leaf_hash_gf8(leaf16, 16, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash (16-byte) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 6: DM, empty leaf */
    leaf_hash_dm_ref(NULL, 0, expected);
    eval_leaf_hash_gf8(NULL, 0, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash (empty) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 7: CMAC128, 16-byte leaf */
    leaf_hash_cmac_ref(leaf16, 16, expected);
    eval_leaf_hash_gf8(leaf16, 16, VOLEITH_MERKLE_HASH_AES_CMAC, got);
    check("CMAC leaf hash (16-byte) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 8: CMAC128, empty leaf */
    leaf_hash_cmac_ref(NULL, 0, expected);
    eval_leaf_hash_gf8(NULL, 0, VOLEITH_MERKLE_HASH_AES_CMAC, got);
    check("CMAC leaf hash (empty) matches reference",
          memcmp(got, expected, 16) == 0);
}

/* ================================================================
 * Build an 8-leaf binary Merkle tree and return membership proof for leaf_idx.
 *
 * Uses the given inode_fn as the tree hash.
 * Path nodes and dirs are returned in path_nodes[3] / path_dirs[3].
 * Returns the root hash.
 * ================================================================ */

typedef void (*inode_fn_t)(const uint8_t[16], const uint8_t[16], uint8_t[16]);

static void
build_tree_proof(uint8_t leaves[][16], size_t n_leaves, size_t leaf_idx,
                 inode_fn_t inode_fn, uint8_t path_nodes[][16],
                 uint8_t path_dirs[], uint8_t root[16])
{
    /* Allocate level arrays: level[0] = leaves, level[k] = internal nodes */
    /* For n_leaves = 8 (depth=3), 3 levels of internal nodes. */
    size_t n = n_leaves;
    uint8_t level[4][8][16];
    for (size_t i = 0; i < n; i++)
        memcpy(level[0][i], leaves[i], 16);

    size_t idx = leaf_idx;
    for (size_t d = 0; d < 3; d++) {
        path_dirs[d] = (uint8_t)(idx & 1); /* bit d of leaf_idx */
        size_t sibling = idx ^ 1;
        memcpy(path_nodes[d], level[d][sibling], 16);
        size_t n_next = n / 2;
        for (size_t k = 0; k < n_next; k++)
            inode_fn(level[d][2 * k], level[d][2 * k + 1], level[d + 1][k]);
        idx /= 2;
        n = n_next;
    }
    memcpy(root, level[3][0], 16);
}

/* ================================================================
 * Tests 9-10: End-to-end depth-3 tree membership proof
 * ================================================================ */

static void
test_end_to_end(void)
{
    /* 8 distinct 16-byte leaves */
    static const uint8_t leaves[8][16] = {
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
         0xcc, 0xdd, 0xee, 0xff},
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
         0x89, 0xab, 0xcd, 0xef},
        {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
         0x98, 0xba, 0xdc, 0xfe},
        {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
         0x76, 0x54, 0x32, 0x10},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
         0x66, 0x77, 0x88, 0x99},
        {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
         0xde, 0xad, 0xbe, 0xef},
        {0x13, 0x57, 0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce, 0x13, 0x57, 0x9b, 0xdf,
         0x02, 0x46, 0x8a, 0xce},
        {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
         0x3c, 0x2d, 0x1e, 0x0f}};

    size_t leaf_idx = 5; /* test leaf[5]; index 5 = 101b → dirs = {1,0,1} */

    /* The leaves passed to the tree are pre-hashed for DM/CMAC. For simplicity,
     * we use the leaf bytes directly AS the hashed leaf values in the tree,
     * then verify using the merkle_gf8_leaf_hash_circuit on a different leaf input. */

    /* Test 9: DM - build tree with DM inode hash, verify leaf[5] membership */
    {
        /* Pre-compute leaf hashes using DM */
        uint8_t leaf_hashes[8][16];
        for (int i = 0; i < 8; i++)
            leaf_hash_dm_ref(leaves[i], 16, leaf_hashes[i]);

        uint8_t path_nodes[3][16], path_dirs[3], tree_root[16];
        build_tree_proof(leaf_hashes, 8, leaf_idx, inode_hash_dm_ref,
                         path_nodes, path_dirs, tree_root);

        uint8_t circuit_root[16];
        eval_full_proof_gf8(leaves[leaf_idx], 16, 3, path_nodes, path_dirs,
                            VOLEITH_MERKLE_HASH_AES_DM, circuit_root);

        check("DM depth-3 tree: circuit root matches tree root",
              memcmp(circuit_root, tree_root, 16) == 0);
    }

    /* Test 10: CMAC - same tree with CMAC inode hash */
    {
        uint8_t leaf_hashes[8][16];
        for (int i = 0; i < 8; i++)
            leaf_hash_cmac_ref(leaves[i], 16, leaf_hashes[i]);

        uint8_t path_nodes[3][16], path_dirs[3], tree_root[16];
        build_tree_proof(leaf_hashes, 8, leaf_idx, inode_hash_cmac_ref,
                         path_nodes, path_dirs, tree_root);

        uint8_t circuit_root[16];
        eval_full_proof_gf8(leaves[leaf_idx], 16, 3, path_nodes, path_dirs,
                            VOLEITH_MERKLE_HASH_AES_CMAC, circuit_root);

        check("CMAC depth-3 tree: circuit root matches tree root",
              memcmp(circuit_root, tree_root, 16) == 0);
    }
}

/* ================================================================
 * Tests 11-12: Domain separation
 * ================================================================ */

static void
test_domain_separation(void)
{
    static const uint8_t data[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                     0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                     0x89, 0xab, 0xcd, 0xef};

    uint8_t leaf_hash[16], inode_hash[16];

    /* Test 11: DM leaf hash ≠ DM inode hash for same 16-byte input */
    {
        leaf_hash_dm_ref(data, 16, leaf_hash);
        /* DM inode: H(data, data) - uses different IV (C_inode instead of C_leaf) */
        inode_hash_dm_ref(data, data, inode_hash);
        check("DM: leaf hash ≠ inode hash for same 16-byte input",
              memcmp(leaf_hash, inode_hash, 16) != 0);
    }

    /* Test 12: CMAC leaf hash ≠ CMAC inode hash for same 16-byte input */
    {
        leaf_hash_cmac_ref(data, 16, leaf_hash);
        /* CMAC inode: H(data, data) - uses K_inode ≠ K_leaf */
        inode_hash_cmac_ref(data, data, inode_hash);
        check("CMAC: leaf hash ≠ inode hash for same 16-byte input",
              memcmp(leaf_hash, inode_hash, 16) != 0);
    }
}

/* ================================================================
 * Tests 13-14: Multi-block and partial-block DM leaf hash
 * ================================================================ */

static void
test_dm_multiblock(void)
{
    uint8_t got[16], expected[16];

    /* Test 13: DM, 32-byte leaf (2 full blocks → inner MD chain loop) */
    static const uint8_t leaf32[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    leaf_hash_dm_ref(leaf32, 32, expected);
    eval_leaf_hash_gf8(leaf32, 32, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash (32-byte, 2 blocks) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 14: DM, 8-byte leaf (partial block with padding) */
    static const uint8_t leaf8[8] = {0xaa, 0xbb, 0xcc, 0xdd,
                                     0xee, 0xff, 0x11, 0x22};
    leaf_hash_dm_ref(leaf8, 8, expected);
    eval_leaf_hash_gf8(leaf8, 8, VOLEITH_MERKLE_HASH_AES_DM, got);
    check("DM leaf hash (8-byte, partial block) matches reference",
          memcmp(got, expected, 16) == 0);
}

/* ================================================================
 * Test 15: Wrong sibling → wrong root (soundness)
 * ================================================================ */

static void
test_wrong_sibling(void)
{
    static const uint8_t leaf[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                     0x0d, 0x0e, 0x0f, 0x10};
    static uint8_t sibling[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                  0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                  0x66, 0x77, 0x88, 0x99};
    static uint8_t wrong_sibling[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00};
    uint8_t dir = 0; /* leaf is left child */

    uint8_t root_correct[16], root_wrong[16];
    eval_full_proof_gf8(leaf, 16, 1, &sibling, &dir, VOLEITH_MERKLE_HASH_AES_DM,
                        root_correct);
    eval_full_proof_gf8(leaf, 16, 1, &wrong_sibling, &dir,
                        VOLEITH_MERKLE_HASH_AES_DM, root_wrong);

    check("Wrong sibling produces different root",
          memcmp(root_correct, root_wrong, 16) != 0);
}

/* ================================================================
 * Tests 16-17: CMAC256 witness counts
 * ================================================================ */

static void
test_cmac256_witness_counts(void)
{
    /* Test 16: CMAC256 leaf hash, 128-bit leaf → 16 + 2×276 = 568 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16,
                                     VOLEITH_MERKLE_HASH_AES256_CMAC, h);
        check("CMAC256 leaf hash witnesses (128-bit leaf = 568)",
              voleith_gf8_circuit_witness_count(c) == 568);
        voleith_gf8_circuit_free(c);
    }

    /* Test 17: CMAC256 full circuit, depth=1 → 568 + 16 + 3×276 = 1412 */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16], sibling[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id leaf_h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16,
                                     VOLEITH_MERKLE_HASH_AES256_CMAC, leaf_h);
        for (int i = 0; i < 16; i++)
            sibling[i] = voleith_gf8_add_witness(c);
        uint8_t dir = 0;
        gf8_wire_id root[16];
        merkle_gf8_path_circuit(c, leaf_h, sibling, &dir, 1,
                                VOLEITH_MERKLE_HASH_AES256_CMAC, root);
        check("CMAC256 full circuit witnesses (depth=1 = 1412)",
              voleith_gf8_circuit_witness_count(c) == 1412);
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * Tests 18-21: CMAC256 correctness and domain separation
 * ================================================================ */

static void
test_cmac256(void)
{
    static const uint8_t leaf16[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                       0x0d, 0x0e, 0x0f, 0x10};

    uint8_t got[16], expected[16];

    /* Test 18: CMAC256, 16-byte leaf */
    leaf_hash_cmac256_ref(leaf16, 16, expected);
    eval_leaf_hash_gf8(leaf16, 16, VOLEITH_MERKLE_HASH_AES256_CMAC, got);
    check("CMAC256 leaf hash (16-byte) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 19: CMAC256, empty leaf */
    leaf_hash_cmac256_ref(NULL, 0, expected);
    eval_leaf_hash_gf8(NULL, 0, VOLEITH_MERKLE_HASH_AES256_CMAC, got);
    check("CMAC256 leaf hash (empty) matches reference",
          memcmp(got, expected, 16) == 0);

    /* Test 20: CMAC256 end-to-end depth-3 tree */
    {
        static const uint8_t leaves[8][16] = {
            {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
             0xbb, 0xcc, 0xdd, 0xee, 0xff},
            {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
             0x67, 0x89, 0xab, 0xcd, 0xef},
            {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54,
             0x76, 0x98, 0xba, 0xdc, 0xfe},
            {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba,
             0x98, 0x76, 0x54, 0x32, 0x10},
            {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
             0x55, 0x66, 0x77, 0x88, 0x99},
            {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba,
             0xbe, 0xde, 0xad, 0xbe, 0xef},
            {0x13, 0x57, 0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce, 0x13, 0x57, 0x9b,
             0xdf, 0x02, 0x46, 0x8a, 0xce},
            {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a,
             0x4b, 0x3c, 0x2d, 0x1e, 0x0f}};
        size_t leaf_idx = 5;

        uint8_t leaf_hashes[8][16];
        for (int i = 0; i < 8; i++)
            leaf_hash_cmac256_ref(leaves[i], 16, leaf_hashes[i]);

        uint8_t path_nodes[3][16], path_dirs[3], tree_root[16];
        build_tree_proof(leaf_hashes, 8, leaf_idx, inode_hash_cmac256_ref,
                         path_nodes, path_dirs, tree_root);

        uint8_t circuit_root[16];
        eval_full_proof_gf8(leaves[leaf_idx], 16, 3, path_nodes, path_dirs,
                            VOLEITH_MERKLE_HASH_AES256_CMAC, circuit_root);

        check("CMAC256 depth-3 tree: circuit root matches tree root",
              memcmp(circuit_root, tree_root, 16) == 0);
    }

    /* Test 21: CMAC256 domain separation */
    {
        static const uint8_t data[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                         0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                         0x89, 0xab, 0xcd, 0xef};
        uint8_t leaf_hash[16], inode_hash[16];
        leaf_hash_cmac256_ref(data, 16, leaf_hash);
        inode_hash_cmac256_ref(data, data, inode_hash);
        check("CMAC256: leaf hash ≠ inode hash for same 16-byte input",
              memcmp(leaf_hash, inode_hash, 16) != 0);
    }
}

/* ================================================================
 * Secret-dir helpers
 * ================================================================ */

/*
 * eval_full_proof_gf8_secret_dir - leaf hash + secret-dir path circuit.
 *
 * Witness layout (declaration order):
 *   [leaf_bytes]     leaf_data bytes
 *   [inv_leaf]       inv_in for leaf hash AES calls  (internally added)
 *   [depth × 16]     path_node bytes  (caller-declared before dir wires)
 *   [depth]          path_dir wires   (caller-declared, each 0x00 or 0x01)
 *   [inv_path]       inv_in for path AES calls  (internally added)
 */
static void
eval_full_proof_gf8_secret_dir(const uint8_t *leaf_data, size_t leaf_bytes,
                               size_t depth, uint8_t (*path_nodes)[16],
                               const uint8_t *path_dirs_arr,
                               voleith_merkle_hash_t hash, uint8_t root_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        memset(root_out, 0, 16);
        return;
    }

    /* Leaf data wires */
    gf8_wire_id *leaf_wires =
        calloc(leaf_bytes > 0 ? leaf_bytes : 1, sizeof(gf8_wire_id));
    if (!leaf_wires) {
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < leaf_bytes; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id leaf_hash_wires[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_bytes > 0 ? leaf_wires : NULL,
                                 leaf_bytes, hash, leaf_hash_wires);

    /* Path node wires */
    gf8_wire_id *node_wires = calloc(depth * 16 + 1, sizeof(gf8_wire_id));
    if (!node_wires) {
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < depth * 16; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    /* Direction wires (private) */
    gf8_wire_id *dir_wires = calloc(depth, sizeof(gf8_wire_id));
    if (!dir_wires) {
        free(node_wires);
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }
    for (size_t i = 0; i < depth; i++)
        dir_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_wires[16];
    merkle_gf8_path_circuit_secret_dir(c, leaf_hash_wires, node_wires,
                                       dir_wires, depth, hash, root_wires);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    size_t n_witness = voleith_gf8_circuit_witness_count(c);

    uint8_t *witness = calloc(n_witness, 1);
    uint8_t *wire_vals = calloc(n_wires, 1);
    if (!witness || !wire_vals) {
        free(witness);
        free(wire_vals);
        free(dir_wires);
        free(node_wires);
        free(leaf_wires);
        voleith_gf8_circuit_free(c);
        memset(root_out, 0, 16);
        return;
    }

    uint8_t *wp = witness;

    /* 1. leaf_data */
    memcpy(wp, leaf_data, leaf_bytes);
    wp += leaf_bytes;

    /* 2. inv_in for leaf hash + compute leaf hash value */
    uint8_t leaf_hash_val[16];
    if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
        dm_leaf_inv_in(leaf_data, leaf_bytes, wp, leaf_hash_val);
        wp += dm_n_aes(leaf_bytes) * 200;
    } else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC) {
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN_256, 32, leaf_data, leaf_bytes, wp,
                         leaf_hash_val);
        wp += aes_cmac_gf8_n_aes_calls(leaf_bytes) * 276;
    } else {
        cmac_leaf_inv_in(MERKLE_LEAF_DOMAIN, 16, leaf_data, leaf_bytes, wp,
                         leaf_hash_val);
        wp += aes_cmac_gf8_n_aes_calls(leaf_bytes) * 200;
    }

    /* 3. path_node bytes */
    for (size_t lvl = 0; lvl < depth; lvl++) {
        memcpy(wp, path_nodes[lvl], 16);
        wp += 16;
    }

    /* 4. direction bytes (0x00 or 0x01) */
    for (size_t lvl = 0; lvl < depth; lvl++)
        *wp++ = path_dirs_arr[lvl];

    /* 5. inv_in for path AES calls, one level at a time */
    uint8_t current[16];
    memcpy(current, leaf_hash_val, 16);

    for (size_t lvl = 0; lvl < depth; lvl++) {
        const uint8_t *sibling = path_nodes[lvl];
        uint8_t dir = path_dirs_arr[lvl];
        const uint8_t *L = dir ? sibling : current;
        const uint8_t *R = dir ? current : sibling;
        uint8_t next[16];

        if (hash == VOLEITH_MERKLE_HASH_AES_DM) {
            dm_inode_inv_in(L, R, MERKLE_INODE_DOMAIN, wp, next);
            wp += 200;
        } else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC) {
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN_256, 32, L, R, wp, next);
            wp += aes_cmac_gf8_n_aes_calls(32) * 276;
        } else {
            cmac_inode_inv_in(MERKLE_INODE_DOMAIN, 16, L, R, wp, next);
            wp += aes_cmac_gf8_n_aes_calls(32) * 200;
        }

        memcpy(current, next, 16);
    }

    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (int k = 0; k < 16; k++)
        root_out[k] = wire_vals[root_wires[k]];

    free(wire_vals);
    free(witness);
    free(dir_wires);
    free(node_wires);
    free(leaf_wires);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Tests 22–23: secret-dir witness counts
 *
 * Each depth-1 circuit has one extra witness slot (the dir wire)
 * compared to the public-dir variant.
 *   DM  public-dir depth=1: 432 → secret-dir: 433 (+1)
 *   CMAC public-dir depth=1: 1032 → secret-dir: 1033 (+1)
 * ================================================================ */

static void
test_secret_dir_witness_counts(void)
{
    /* Test 22: DM secret-dir, depth=1, 128-bit leaf */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16], sibling[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id leaf_h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_DM,
                                     leaf_h);
        for (int i = 0; i < 16; i++)
            sibling[i] = voleith_gf8_add_witness(c);
        gf8_wire_id dir_w = voleith_gf8_add_witness(c);
        gf8_wire_id root[16];
        merkle_gf8_path_circuit_secret_dir(c, leaf_h, sibling, &dir_w, 1,
                                           VOLEITH_MERKLE_HASH_AES_DM, root);
        check("DM secret-dir witnesses (depth=1, 128-bit leaf = 433)",
              voleith_gf8_circuit_witness_count(c) == 433);
        voleith_gf8_circuit_free(c);
    }

    /* Test 23: CMAC secret-dir, depth=1, 128-bit leaf */
    {
        voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
        gf8_wire_id leaf[16], sibling[16];
        for (int i = 0; i < 16; i++)
            leaf[i] = voleith_gf8_add_witness(c);
        gf8_wire_id leaf_h[16];
        merkle_gf8_leaf_hash_circuit(c, leaf, 16, VOLEITH_MERKLE_HASH_AES_CMAC,
                                     leaf_h);
        for (int i = 0; i < 16; i++)
            sibling[i] = voleith_gf8_add_witness(c);
        gf8_wire_id dir_w = voleith_gf8_add_witness(c);
        gf8_wire_id root[16];
        merkle_gf8_path_circuit_secret_dir(c, leaf_h, sibling, &dir_w, 1,
                                           VOLEITH_MERKLE_HASH_AES_CMAC, root);
        check("CMAC secret-dir witnesses (depth=1, 128-bit leaf = 1033)",
              voleith_gf8_circuit_witness_count(c) == 1033);
        voleith_gf8_circuit_free(c);
    }
}

/* ================================================================
 * Tests 24–25: secret-dir depth-3 end-to-end correctness
 * ================================================================ */

static void
test_secret_dir_end_to_end(void)
{
    static const uint8_t leaves[8][16] = {
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
         0xcc, 0xdd, 0xee, 0xff},
        {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
         0x89, 0xab, 0xcd, 0xef},
        {0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
         0x98, 0xba, 0xdc, 0xfe},
        {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98,
         0x76, 0x54, 0x32, 0x10},
        {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
         0x66, 0x77, 0x88, 0x99},
        {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
         0xde, 0xad, 0xbe, 0xef},
        {0x13, 0x57, 0x9b, 0xdf, 0x02, 0x46, 0x8a, 0xce, 0x13, 0x57, 0x9b, 0xdf,
         0x02, 0x46, 0x8a, 0xce},
        {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
         0x3c, 0x2d, 0x1e, 0x0f}};
    size_t leaf_idx = 5; /* dirs = {1,0,1} */

    /* Test 24: DM */
    {
        uint8_t leaf_hashes[8][16];
        for (int i = 0; i < 8; i++)
            leaf_hash_dm_ref(leaves[i], 16, leaf_hashes[i]);

        uint8_t path_nodes[3][16], path_dirs[3], tree_root[16];
        build_tree_proof(leaf_hashes, 8, leaf_idx, inode_hash_dm_ref,
                         path_nodes, path_dirs, tree_root);

        uint8_t circuit_root[16];
        eval_full_proof_gf8_secret_dir(leaves[leaf_idx], 16, 3, path_nodes,
                                       path_dirs, VOLEITH_MERKLE_HASH_AES_DM,
                                       circuit_root);

        check("DM secret-dir depth-3: circuit root matches tree root",
              memcmp(circuit_root, tree_root, 16) == 0);
    }

    /* Test 25: CMAC */
    {
        uint8_t leaf_hashes[8][16];
        for (int i = 0; i < 8; i++)
            leaf_hash_cmac_ref(leaves[i], 16, leaf_hashes[i]);

        uint8_t path_nodes[3][16], path_dirs[3], tree_root[16];
        build_tree_proof(leaf_hashes, 8, leaf_idx, inode_hash_cmac_ref,
                         path_nodes, path_dirs, tree_root);

        uint8_t circuit_root[16];
        eval_full_proof_gf8_secret_dir(leaves[leaf_idx], 16, 3, path_nodes,
                                       path_dirs, VOLEITH_MERKLE_HASH_AES_CMAC,
                                       circuit_root);

        check("CMAC secret-dir depth-3: circuit root matches tree root",
              memcmp(circuit_root, tree_root, 16) == 0);
    }
}

/* ================================================================
 * Test 26: Equivalence - secret-dir root equals public-dir root
 * ================================================================ */

static void
test_secret_public_equivalence(void)
{
    static const uint8_t leaf[16] = {0xca, 0xfe, 0xba, 0xbe, 0xde, 0xad,
                                     0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                                     0xde, 0xad, 0xbe, 0xef};
    static uint8_t sibling[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                                  0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
                                  0x76, 0x54, 0x32, 0x10};
    uint8_t dir = 1; /* leaf is right child */

    uint8_t pub_root[16], sec_root[16];
    eval_full_proof_gf8(leaf, 16, 1, &sibling, &dir, VOLEITH_MERKLE_HASH_AES_DM,
                        pub_root);
    eval_full_proof_gf8_secret_dir(leaf, 16, 1, &sibling, &dir,
                                   VOLEITH_MERKLE_HASH_AES_DM, sec_root);

    check(
        "secret-dir root equals public-dir root for same inputs (equivalence)",
        memcmp(pub_root, sec_root, 16) == 0);
}

/* ================================================================
 * Test 27: Wrong direction bit → different root
 * ================================================================ */

static void
test_secret_dir_binding(void)
{
    static const uint8_t leaf[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                                     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                     0x0d, 0x0e, 0x0f, 0x10};
    static uint8_t sibling[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                                  0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                  0x66, 0x77, 0x88, 0x99};

    uint8_t dir0 = 0, dir1 = 1; /* same leaf+sibling, different direction */

    uint8_t root0[16], root1[16];
    eval_full_proof_gf8_secret_dir(leaf, 16, 1, &sibling, &dir0,
                                   VOLEITH_MERKLE_HASH_AES_DM, root0);
    eval_full_proof_gf8_secret_dir(leaf, 16, 1, &sibling, &dir1,
                                   VOLEITH_MERKLE_HASH_AES_DM, root1);

    check("Wrong path_dir (0 vs 1) produces different root (direction binding)",
          memcmp(root0, root1, 16) != 0);
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    test_witness_counts();
    test_leaf_hash_correctness();
    test_end_to_end();
    test_domain_separation();
    test_dm_multiblock();
    test_wrong_sibling();
    test_cmac256_witness_counts();
    test_cmac256();

    test_secret_dir_witness_counts();
    test_secret_dir_end_to_end();
    test_secret_public_equivalence();
    test_secret_dir_binding();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
