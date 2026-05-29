/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_gf8_circuit.c - Merkle path verification as a GF(2⁸) element-level circuit
 *
 * Domain constants (same as merkle_circuit.c):
 *   MERKLE_LEAF_DOMAIN      = "VOLEitH-Leaf\0\0\0\0"        (16 bytes, AES-128 key)
 *   MERKLE_INODE_DOMAIN     = "VOLEitH-Node\0\0\0\0"        (16 bytes, AES-128 key)
 *   MERKLE_LEAF_DOMAIN_256  = "VOLEitH-Leaf-256\0...\0"     (32 bytes, AES-256 key)
 *   MERKLE_INODE_DOMAIN_256 = "VOLEitH-Node-256\0...\0"     (32 bytes, AES-256 key)
 *
 * For DM (AES-128 only):
 *   leaf  - Merkle-Damgård chain: state_0 = IV = MERKLE_LEAF_DOMAIN (constant);
 *            state_i = AES_{state_{i-1}}(block_i) XOR block_i
 *   inode - H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode)
 *
 * For CMAC (AES-128):
 *   leaf  - CMAC(K_leaf,  leaf_data),  K_leaf  = MERKLE_LEAF_DOMAIN  (constant)
 *   inode - CMAC(K_inode, L || R),     K_inode = MERKLE_INODE_DOMAIN (constant)
 *
 * For CMAC256 (AES-256):
 *   leaf  - CMAC(K_leaf,  leaf_data),  K_leaf  = MERKLE_LEAF_DOMAIN_256  (constant)
 *   inode - CMAC(K_inode, L || R),     K_inode = MERKLE_INODE_DOMAIN_256 (constant)
 *
 * Direction bits: path_dirs are plain uint8_t values (0 or 1), resolved at
 * circuit-build time. No mul gates for direction selection.
 */

#include "merkle_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include <stdint.h>

/* ================================================================
 * Domain constants (must match merkle_circuit.c)
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00  /* "Leaf\0\0\0\0" */
};

static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00  /* "Node\0\0\0\0" */
};

static const uint8_t MERKLE_LEAF_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x2d, 0x32, 0x35, 0x36, /* "Leaf-256" */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static const uint8_t MERKLE_INODE_DOMAIN_256[32] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x2d, 0x32, 0x35, 0x36, /* "Node-256" */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* ================================================================
 * Internal helpers
 * ================================================================ */

/* Emit 16 constant byte-wires for a 16-byte value. */
static void
add_const_block_gf8(voleith_gf8_circuit_t *c, const uint8_t bytes[16],
                    gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_const(c, bytes[k]);
}

/* Emit 32 constant byte-wires for a 32-byte value. */
static void
add_const_block256_gf8(voleith_gf8_circuit_t *c, const uint8_t bytes[32],
                       gf8_wire_id out[32])
{
    for (int k = 0; k < 32; k++)
        out[k] = voleith_gf8_add_const(c, bytes[k]);
}

/* XOR two 16-byte-wire blocks. */
static void
xor_block_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id a[16],
              const gf8_wire_id b[16], gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_xor(c, a[k], b[k]);
}

/* ================================================================
 * DM leaf hash - Merkle-Damgård with Davies-Meyer compression.
 *
 *   state_0   = MERKLE_LEAF_DOMAIN  (constant byte-wires)
 *   state_i   = AES_{state_{i-1}}(block_i) XOR block_i
 *   leaf_hash = state_n
 *
 * The DM key is the previous state - it can be either constant wires
 * (first iteration) or computed wires (subsequent iterations).  This is
 * valid because gf8_wire_id is uniform over all wire kinds.
 * ================================================================ */

static void
leaf_hash_dm_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
                 size_t leaf_data_bytes, gf8_wire_id leaf_hash[16])
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    /* state_0 = IV (constant wires for MERKLE_LEAF_DOMAIN) */
    gf8_wire_id state[16];
    add_const_block_gf8(c, MERKLE_LEAF_DOMAIN, state);

    /* Process complete inner blocks. */
    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        const gf8_wire_id *block = leaf_data + blk * 16;
        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, block, aes_out);
        xor_block_gf8(c, aes_out, block, state);
    }

    /* Last block: either a complete block or a padded partial/empty block. */
    if (!needs_padding) {
        const gf8_wire_id *block = leaf_data + (full_blocks - 1) * 16;
        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, block, aes_out);
        xor_block_gf8(c, aes_out, block, leaf_hash);
    } else {
        /* Build padded block: leaf_data[full_blocks*16..+last_bytes-1] || 0x80 || 0x00... */
        gf8_wire_id padded[16];

        /* Copy partial message bytes (wire IDs from caller). */
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];

        /* 0x80 padding byte and trailing zero bytes as constants. */
        padded[last_bytes] = voleith_gf8_add_const(c, 0x80);
        for (size_t b = last_bytes + 1; b < 16; b++)
            padded[b] = voleith_gf8_add_const(c, 0x00);

        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, padded, aes_out);
        xor_block_gf8(c, aes_out, padded, leaf_hash);
    }
}

/* ================================================================
 * CMAC leaf hash - CMAC(K_leaf, leaf_data), K_leaf = MERKLE_LEAF_DOMAIN.
 * ================================================================ */

static void
leaf_hash_cmac_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
                   size_t leaf_data_bytes, gf8_wire_id leaf_hash[16])
{
    gf8_wire_id key[16];
    add_const_block_gf8(c, MERKLE_LEAF_DOMAIN, key);
    aes_cmac_gf8_circuit(c, key, 16, leaf_data, leaf_data_bytes, leaf_hash);
}

/* ================================================================
 * AES-256-CMAC leaf hash - CMAC(K_leaf256, leaf_data), 256-bit key.
 * ================================================================ */

static void
leaf_hash_cmac256_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
                      size_t leaf_data_bytes, gf8_wire_id leaf_hash[16])
{
    gf8_wire_id key[32];
    add_const_block256_gf8(c, MERKLE_LEAF_DOMAIN_256, key);
    aes_cmac_gf8_circuit(c, key, 32, leaf_data, leaf_data_bytes, leaf_hash);
}

/* ================================================================
 * DM inode compression: H(L, R) = AES_L(R XOR C_inode) XOR (R XOR C_inode)
 * ================================================================ */

static void
compress_dm_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id left[16],
                const gf8_wire_id right[16], gf8_wire_id out[16])
{
    gf8_wire_id c_inode[16];
    add_const_block_gf8(c, MERKLE_INODE_DOMAIN, c_inode);

    gf8_wire_id P[16];
    xor_block_gf8(c, right, c_inode, P);

    gf8_wire_id cipher[16];
    aes128_gf8_circuit(c, left, P, cipher);

    xor_block_gf8(c, cipher, P, out);
}

/* ================================================================
 * CMAC inode compression: H(L, R) = CMAC(K_inode, L || R)
 * ================================================================ */

static void
compress_cmac_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id left[16],
                  const gf8_wire_id right[16], gf8_wire_id out[16])
{
    gf8_wire_id key[16];
    add_const_block_gf8(c, MERKLE_INODE_DOMAIN, key);

    gf8_wire_id msg[32];
    for (int i = 0; i < 16; i++)
        msg[i] = left[i];
    for (int i = 0; i < 16; i++)
        msg[16 + i] = right[i];

    aes_cmac_gf8_circuit(c, key, 16, msg, 32, out);
}

/* ================================================================
 * AES-256-CMAC inode compression: H(L, R) = CMAC(K_inode256, L || R)
 * ================================================================ */

static void
compress_cmac256_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id left[16],
                     const gf8_wire_id right[16], gf8_wire_id out[16])
{
    gf8_wire_id key[32];
    add_const_block256_gf8(c, MERKLE_INODE_DOMAIN_256, key);

    gf8_wire_id msg[32];
    for (int i = 0; i < 16; i++)
        msg[i] = left[i];
    for (int i = 0; i < 16; i++)
        msg[16 + i] = right[i];

    aes_cmac_gf8_circuit(c, key, 32, msg, 32, out);
}

/* ================================================================
 * Level processing: static direction swap (public leaf index), then compress.
 *
 * dir = 0 → current is left child:  H(current, sibling)
 * dir = 1 → current is right child: H(sibling, current)
 *
 * Zero mul gates - direction resolved at circuit-build time.
 * ================================================================ */

static void
process_level_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id current[16],
                  const gf8_wire_id sibling[16], uint8_t dir,
                  voleith_merkle_hash_t hash, gf8_wire_id out[16])
{
    const gf8_wire_id *left = dir ? sibling : current;
    const gf8_wire_id *right = dir ? current : sibling;

    if (hash == VOLEITH_MERKLE_HASH_AES_DM)
        compress_dm_gf8(c, left, right, out);
    else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC)
        compress_cmac256_gf8(c, left, right, out);
    else
        compress_cmac_gf8(c, left, right, out);
}

/* ================================================================
 * Level processing: secret direction bit (private leaf index).
 *
 * dir is a gf8_wire_id carrying 0x00 (left child) or 0x01 (right child).
 *
 * left[i]  = mux(current[i], sibling[i], dir)   - 1 mul gate per byte
 * right[i] = left[i] XOR current[i] XOR sibling[i]  - free (XOR only)
 *
 * Total: 16 mul gates per level.
 * ================================================================ */

static void
process_level_gf8_secret_dir(voleith_gf8_circuit_t *c,
                             const gf8_wire_id current[16],
                             const gf8_wire_id sibling[16], gf8_wire_id dir,
                             voleith_merkle_hash_t hash, gf8_wire_id out[16])
{
    /*
     * Soundness: dir must be a single bit.  add_mux does not enforce this,
     * and an unconstrained dir lets the prover make neither mux output equal
     * to current, erasing the carried-up chain value and forging a path.
     * dir == dir * dir holds only for dir in {0, 1} in GF(2^8), and the check
     * is free (no mul-slot, no witness).
     */
    voleith_gf8_assert_product(c, dir, dir, dir);

    gf8_wire_id left[16], right[16];
    for (int i = 0; i < 16; i++) {
        left[i] = voleith_gf8_add_mux(c, current[i], sibling[i], dir);
        gf8_wire_id cs = voleith_gf8_add_xor(c, current[i], sibling[i]);
        right[i] = voleith_gf8_add_xor(c, left[i], cs);
    }

    if (hash == VOLEITH_MERKLE_HASH_AES_DM)
        compress_dm_gf8(c, left, right, out);
    else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC)
        compress_cmac256_gf8(c, left, right, out);
    else
        compress_cmac_gf8(c, left, right, out);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
merkle_gf8_leaf_hash_circuit(voleith_gf8_circuit_t *c,
                             const gf8_wire_id *leaf_data,
                             size_t leaf_data_bytes, voleith_merkle_hash_t hash,
                             gf8_wire_id leaf_hash[16])
{
    if (hash == VOLEITH_MERKLE_HASH_AES_DM)
        leaf_hash_dm_gf8(c, leaf_data, leaf_data_bytes, leaf_hash);
    else if (hash == VOLEITH_MERKLE_HASH_AES256_CMAC)
        leaf_hash_cmac256_gf8(c, leaf_data, leaf_data_bytes, leaf_hash);
    else
        leaf_hash_cmac_gf8(c, leaf_data, leaf_data_bytes, leaf_hash);
}

void
merkle_gf8_path_circuit(voleith_gf8_circuit_t *c,
                        const gf8_wire_id leaf_hash[16],
                        const gf8_wire_id *path_nodes, const uint8_t *path_dirs,
                        size_t depth, voleith_merkle_hash_t hash,
                        gf8_wire_id root[16])
{
    gf8_wire_id current[16];
    for (int i = 0; i < 16; i++)
        current[i] = leaf_hash[i];

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * 16;
        gf8_wire_id next[16];
        process_level_gf8(c, current, sibling, path_dirs[level], hash, next);
        for (int i = 0; i < 16; i++)
            current[i] = next[i];
    }

    for (int i = 0; i < 16; i++)
        root[i] = current[i];
}

void
merkle_gf8_path_circuit_secret_dir(voleith_gf8_circuit_t *c,
                                   const gf8_wire_id leaf_hash[16],
                                   const gf8_wire_id *path_nodes,
                                   const gf8_wire_id *path_dirs, size_t depth,
                                   voleith_merkle_hash_t hash,
                                   gf8_wire_id root[16])
{
    gf8_wire_id current[16];
    for (int i = 0; i < 16; i++)
        current[i] = leaf_hash[i];

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * 16;
        gf8_wire_id next[16];
        process_level_gf8_secret_dir(c, current, sibling, path_dirs[level],
                                     hash, next);
        for (int i = 0; i < 16; i++)
            current[i] = next[i];
    }

    for (int i = 0; i < 16; i++)
        root[i] = current[i];
}
