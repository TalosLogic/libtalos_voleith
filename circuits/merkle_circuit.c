/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_circuit.c - Merkle path verification as a Boolean circuit
 *
 * Domain constants (nothing-up-my-sleeve ASCII labels padded to block size):
 *   MERKLE_LEAF_DOMAIN      = "VOLEitH-Leaf\0\0\0\0"        (16 bytes, AES-128 key)
 *   MERKLE_INODE_DOMAIN     = "VOLEitH-Node\0\0\0\0"        (16 bytes, AES-128 key)
 *   MERKLE_LEAF_DOMAIN_256  = "VOLEitH-Leaf-256\0...\0"     (32 bytes, AES-256 key)
 *   MERKLE_INODE_DOMAIN_256 = "VOLEitH-Node-256\0...\0"     (32 bytes, AES-256 key)
 *
 * For DM (AES-128 only - AES-256-DM is not supported; see merkle_circuit.h):
 *   leaf  - Merkle-Damgård chain: state_0 = IV = MERKLE_LEAF_DOMAIN;
 *            state_i = AES_{state_{i-1}}(block_i) XOR block_i
 *   inode - H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode)
 *            where C_inode = MERKLE_INODE_DOMAIN
 *
 * For CMAC (AES-128):
 *   leaf  - CMAC(K_leaf,  leaf_data),  K_leaf  = MERKLE_LEAF_DOMAIN
 *   inode - CMAC(K_inode, L || R),     K_inode = MERKLE_INODE_DOMAIN
 *
 * For CMAC256 (AES-256):
 *   leaf  - CMAC(K_leaf,  leaf_data),  K_leaf  = MERKLE_LEAF_DOMAIN_256
 *   inode - CMAC(K_inode, L || R),     K_inode = MERKLE_INODE_DOMAIN_256
 *
 * Padding (both DM and CMAC leaf hash):
 *   Follows CMAC/ISO 7816-4: complete blocks use no padding; partial or
 *   empty last block gets 0x80 appended, then zero-filled to 128 bits.
 */

#include "merkle_circuit.h"
#include "aes_cmac_circuit.h"
#include "aes_circuit.h"
#include <stdint.h>

/* ================================================================
 * Domain constants
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00  /* "Leaf\0\0\0\0" */
};

static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00  /* "Node\0\0\0\0" */
};

/* AES-256 domain constants: 32-byte keys, distinct from AES-128 constants. */
static const uint8_t MERKLE_LEAF_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x2d, 0x32, 0x35, 0x36, /* "Leaf-256" */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* \0 × 8   */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* \0 × 8   */
};

static const uint8_t MERKLE_INODE_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x2d, 0x32, 0x35, 0x36, /* "Node-256" */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* \0 × 8   */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  /* \0 × 8   */
};

/* ================================================================
 * Internal helpers
 * ================================================================ */

/* Emit 128 constant wires for a 16-byte value (LSB-first per byte). */
static void
add_const_block(voleith_circuit_t *c, const uint8_t bytes[16], wire_id out[128])
{
    for (int k = 0; k < 16; k++)
        for (int b = 0; b < 8; b++)
            out[8 * k + b] = voleith_circuit_add_const(c, (bytes[k] >> b) & 1);
}

/* Emit 256 constant wires for a 32-byte value (LSB-first per byte). */
static void
add_const_block256(voleith_circuit_t *c, const uint8_t bytes[32],
                   wire_id out[256])
{
    for (int k = 0; k < 32; k++)
        for (int b = 0; b < 8; b++)
            out[8 * k + b] = voleith_circuit_add_const(c, (bytes[k] >> b) & 1);
}

/* XOR two 128-wire blocks bitwise. */
static void
xor128(voleith_circuit_t *c, const wire_id a[128], const wire_id b[128],
       wire_id out[128])
{
    for (int i = 0; i < 128; i++)
        out[i] = voleith_circuit_add_xor(c, a[i], b[i]);
}

/* ================================================================
 * DM leaf hash - Merkle-Damgård with Davies-Meyer compression.
 *
 *   state_0   = MERKLE_LEAF_DOMAIN  (constant wires - the domain IV)
 *   state_i   = AES_{state_{i-1}}(block_i) XOR block_i
 *   leaf_hash = state_n
 * ================================================================ */

static void
leaf_hash_dm(voleith_circuit_t *c, const wire_id *leaf_data,
             size_t leaf_data_bits, wire_id leaf_hash[128])
{
    size_t leaf_bytes = leaf_data_bits / 8;
    size_t full_blocks = leaf_bytes / 16;
    size_t last_bytes = leaf_bytes % 16;
    int needs_padding = (leaf_data_bits == 0) || (last_bytes != 0);

    /* state_0 = IV (constant wires for MERKLE_LEAF_DOMAIN) */
    wire_id state[128];
    add_const_block(c, MERKLE_LEAF_DOMAIN, state);

    /* Process complete inner blocks (all but the last when complete). */
    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        const wire_id *block = leaf_data + blk * 128;
        wire_id aes_out[128];
        aes128_circuit(c, state, block, aes_out);
        xor128(c, aes_out, block, state);
    }

    /* Last block: either a complete block or a padded partial/empty block. */
    if (!needs_padding) {
        const wire_id *block = leaf_data + (full_blocks - 1) * 128;
        wire_id aes_out[128];
        aes128_circuit(c, state, block, aes_out);
        xor128(c, aes_out, block, leaf_hash);
    } else {
        wire_id padded[128];

        /* Copy partial message bytes. */
        for (size_t b = 0; b < last_bytes; b++)
            for (int bit = 0; bit < 8; bit++)
                padded[b * 8 + bit] =
                    leaf_data[full_blocks * 128 + b * 8 + bit];

        /* 0x80: bit 7 (MSB) = 1, bits 0-6 = 0 of byte last_bytes. */
        padded[last_bytes * 8 + 7] = voleith_circuit_add_const(c, 1);
        for (int bit = 0; bit < 7; bit++)
            padded[last_bytes * 8 + bit] = voleith_circuit_add_const(c, 0);

        /* Remaining bytes: all zeros. */
        for (size_t b = last_bytes + 1; b < 16; b++)
            for (int bit = 0; bit < 8; bit++)
                padded[b * 8 + bit] = voleith_circuit_add_const(c, 0);

        wire_id aes_out[128];
        aes128_circuit(c, state, padded, aes_out);
        xor128(c, aes_out, padded, leaf_hash);
    }
}

/* ================================================================
 * CMAC leaf hash - CMAC(K_leaf, leaf_data), K_leaf = MERKLE_LEAF_DOMAIN.
 * ================================================================ */

static void
leaf_hash_cmac(voleith_circuit_t *c, const wire_id *leaf_data,
               size_t leaf_data_bits, wire_id leaf_hash[128])
{
    wire_id key[128];
    add_const_block(c, MERKLE_LEAF_DOMAIN, key);
    aes_cmac_circuit(c, key, 128, leaf_data, leaf_data_bits, leaf_hash);
}

/* ================================================================
 * DM inode compression: H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode)
 * ================================================================ */

static void
compress_dm(voleith_circuit_t *c, const wire_id left[128],
            const wire_id right[128], wire_id out[128])
{
    wire_id c_inode[128];
    add_const_block(c, MERKLE_INODE_DOMAIN, c_inode);

    wire_id P[128];
    xor128(c, right, c_inode, P);

    wire_id cipher[128];
    aes128_circuit(c, left, P, cipher);

    xor128(c, cipher, P, out);
}

/* ================================================================
 * CMAC inode compression: H(L, R) = CMAC(K_inode, L || R)
 *   K_inode = MERKLE_INODE_DOMAIN
 *   Message = L || R = 256 bits (two complete blocks, no padding).
 * ================================================================ */

static void
compress_cmac(voleith_circuit_t *c, const wire_id left[128],
              const wire_id right[128], wire_id out[128])
{
    wire_id key[128];
    add_const_block(c, MERKLE_INODE_DOMAIN, key);

    wire_id msg[256];
    for (int i = 0; i < 128; i++)
        msg[i] = left[i];
    for (int i = 0; i < 128; i++)
        msg[128 + i] = right[i];

    aes_cmac_circuit(c, key, 128, msg, 256, out);
}

/* ================================================================
 * AES-256-CMAC leaf hash - CMAC(K_leaf256, leaf_data), 256-bit key.
 * ================================================================ */

static void
leaf_hash_cmac256(voleith_circuit_t *c, const wire_id *leaf_data,
                  size_t leaf_data_bits, wire_id leaf_hash[128])
{
    wire_id key[256];
    add_const_block256(c, MERKLE_LEAF_DOMAIN_256, key);
    aes_cmac_circuit(c, key, 256, leaf_data, leaf_data_bits, leaf_hash);
}

/* ================================================================
 * AES-256-CMAC inode compression: H(L, R) = CMAC(K_inode256, L || R)
 *   K_inode256 = MERKLE_INODE_DOMAIN_256  (32-byte AES-256 key)
 *   Message    = L || R = 256 bits (two complete blocks, no padding).
 * ================================================================ */

static void
compress_cmac256(voleith_circuit_t *c, const wire_id left[128],
                 const wire_id right[128], wire_id out[128])
{
    wire_id key[256];
    add_const_block256(c, MERKLE_INODE_DOMAIN_256, key);

    wire_id msg[256];
    for (int i = 0; i < 128; i++)
        msg[i] = left[i];
    for (int i = 0; i < 128; i++)
        msg[128 + i] = right[i];

    aes_cmac_circuit(c, key, 256, msg, 256, out);
}

/* ================================================================
 * Level processing: mux by direction, then compress.
 *
 * dir = 0 → H(current, sibling)  (current is left child)
 * dir = 1 → H(sibling, current)  (current is right child)
 *
 * MUX: 128 AND gates per level.
 *   diff[i]     = current[i] XOR sibling[i]
 *   sel_diff[i] = dir AND diff[i]
 *   left[i]     = current[i] XOR sel_diff[i]
 *   right[i]    = sibling[i] XOR sel_diff[i]
 * ================================================================ */

static void
process_level(voleith_circuit_t *c, const wire_id current[128],
              const wire_id sibling[128], wire_id dir,
              voleith_merkle_hash_t hash, wire_id out[128])
{
    wire_id left[128], right[128];
    for (int i = 0; i < 128; i++) {
        wire_id diff = voleith_circuit_add_xor(c, current[i], sibling[i]);
        wire_id sel_diff = voleith_circuit_add_and(c, dir, diff);
        left[i] = voleith_circuit_add_xor(c, current[i], sel_diff);
        right[i] = voleith_circuit_add_xor(c, sibling[i], sel_diff);
    }

    if (hash == VOLEITH_MERKLE_HASH_AES_DM)
        compress_dm(c, left, right, out);
    else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC)
        compress_cmac256(c, left, right, out);
    else
        compress_cmac(c, left, right, out);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
merkle_leaf_hash_circuit(voleith_circuit_t *c, const wire_id *leaf_data,
                         size_t leaf_data_bits, voleith_merkle_hash_t hash,
                         wire_id leaf_hash[128])
{
    if (hash == VOLEITH_MERKLE_HASH_AES_DM)
        leaf_hash_dm(c, leaf_data, leaf_data_bits, leaf_hash);
    else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC)
        leaf_hash_cmac256(c, leaf_data, leaf_data_bits, leaf_hash);
    else
        leaf_hash_cmac(c, leaf_data, leaf_data_bits, leaf_hash);
}

void
merkle_path_circuit(voleith_circuit_t *c, const wire_id leaf_hash[128],
                    const wire_id *path_nodes, const wire_id *path_dirs,
                    size_t depth, voleith_merkle_hash_t hash, wire_id root[128])
{
    wire_id current[128];
    for (int i = 0; i < 128; i++)
        current[i] = leaf_hash[i];

    for (size_t level = 0; level < depth; level++) {
        const wire_id *sibling = path_nodes + level * 128;
        wire_id next[128];
        process_level(c, current, sibling, path_dirs[level], hash, next);
        for (int i = 0; i < 128; i++)
            current[i] = next[i];
    }

    for (int i = 0; i < 128; i++)
        root[i] = current[i];
}
