/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_gf8.c - AES-DM and AES-128-CMAC vt implementations.
 *
 * "AES-DM" is a historical label: the compression is actually Matyas-
 * Meyer-Oseas (chaining-value-keyed), NOT Davies-Meyer.  See the keying
 * note above the AES-DM section.
 *
 * Branch A of the merkle tree circuits hash-agnostic refactor: wraps
 * the leaf/inode compressions already used by merkle_gf8_circuit.c
 * (with the matching domain constants) behind the voleith_node_hash_vt
 * function-pointer interface.  Bit-exact gate-stream equivalence with
 * the existing fixed-hash entry point is intentional and is the
 * load-bearing invariant the Branch B equivalence harness will assert.
 *
 * No proof-time cost: the vt is consumed at circuit-build time only.
 */

#include "node_hash_aes_gf8.h"
#include "aes_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include "../core/aes.h"
#include "../core/util.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Domain constants - byte-for-byte identical to merkle_gf8_circuit.c
 * so the resulting circuit matches the existing fixed-hash entry.
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00  /* "Leaf\0\0\0\0" */
};

static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00  /* "Node\0\0\0\0" */
};

/* ================================================================
 * Shared helpers
 * ================================================================ */

static void
add_const_block_gf8(voleith_gf8_circuit_t *c, const uint8_t bytes[16],
                    gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_const(c, bytes[k]);
}

static void
xor_block_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id a[16],
              const gf8_wire_id b[16], gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_xor(c, a[k], b[k]);
}

/* Software AES-128(key, pt) -> out. */
static void
sw_aes128(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    voleith_aes_ctx_clear(&ctx);
}

/* ================================================================
 * AES-DM
 *
 * NOTE ON KEYING (do not confuse with Davies-Meyer): despite the "DM" in
 * the vt name (historical / matching merkle_gf8_circuit.c), the single-
 * block-length compression here is MATYAS-MEYER-OSEAS, not Davies-Meyer.
 * Each iteration keys the AES block cipher with the CHAINING VALUE and
 * feeds forward the MESSAGE block:
 *
 *     H_i = E_{H_{i-1}}(m_i) XOR m_i          (MMO: chaining value = key)
 *
 * see the leaf loop below (aes128_gf8_circuit(c, state, block, ...) then
 * XOR block).  The inode form H(L,R) = AES_L(R XOR C) XOR (R XOR C) is the
 * same MMO keying with L as the key.  Standard Davies-Meyer keys with the
 * MESSAGE instead (H_i = E_{m_i}(H_{i-1}) XOR H_{i-1}); that is what
 * ichor_aesdm_* / the V5 opener KDF use, so those must NOT reuse this
 * gadget's compression.
 *
 * Number of AES calls in the leaf chain for an n-byte input:
 *   dm_n_aes(0) = 1   (one padding-only block)
 *   dm_n_aes(n) = ceil(n/16)         if n > 0 and n % 16 == 0
 *               = n/16 + 1           if n > 0 and n % 16 != 0
 * ================================================================ */

static size_t
dm_n_aes(size_t n)
{
    size_t full = n / 16;
    int needs_pad = (n == 0) || (n % 16 != 0);
    return needs_pad ? full + 1 : full;
}

static size_t
node_hash_aes_dm_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return dm_n_aes(leaf_data_bytes) * 200u;
}

static size_t
node_hash_aes_dm_inode_invin_bytes(void)
{
    return 200u; /* one AES-128 call */
}

static void
node_hash_aes_dm_leaf_circuit(voleith_gf8_circuit_t *c,
                              const gf8_wire_id *leaf_data,
                              size_t leaf_data_bytes, gf8_wire_id *out_node)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    gf8_wire_id state[16];
    add_const_block_gf8(c, MERKLE_LEAF_DOMAIN, state);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        const gf8_wire_id *block = leaf_data + blk * 16;
        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, block, aes_out);
        xor_block_gf8(c, aes_out, block, state);
    }

    if (!needs_padding) {
        const gf8_wire_id *block = leaf_data + (full_blocks - 1) * 16;
        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, block, aes_out);
        xor_block_gf8(c, aes_out, block, out_node);
    } else {
        gf8_wire_id padded[16];
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = voleith_gf8_add_const(c, 0x80);
        for (size_t b = last_bytes + 1; b < 16; b++)
            padded[b] = voleith_gf8_add_const(c, 0x00);

        gf8_wire_id aes_out[16];
        aes128_gf8_circuit(c, state, padded, aes_out);
        xor_block_gf8(c, aes_out, padded, out_node);
    }
}

static void
node_hash_aes_dm_inode_circuit(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *left,
                               const gf8_wire_id *right, gf8_wire_id *out_node)
{
    gf8_wire_id c_inode[16];
    add_const_block_gf8(c, MERKLE_INODE_DOMAIN, c_inode);

    gf8_wire_id P[16];
    xor_block_gf8(c, right, c_inode, P);

    gf8_wire_id cipher[16];
    aes128_gf8_circuit(c, left, P, cipher);

    xor_block_gf8(c, cipher, P, out_node);
}

static int
node_hash_aes_dm_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                           uint8_t *out)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t aes_out[16];
        sw_aes128(state, leaf_data + blk * 16, aes_out);
        for (int i = 0; i < 16; i++)
            state[i] = aes_out[i] ^ leaf_data[blk * 16 + i];
    }

    if (!needs_padding) {
        const uint8_t *block = leaf_data + (full_blocks - 1) * 16;
        uint8_t aes_out[16];
        sw_aes128(state, block, aes_out);
        for (int i = 0; i < 16; i++)
            out[i] = aes_out[i] ^ block[i];
    } else {
        uint8_t padded[16];
        memset(padded, 0, 16);
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = 0x80;

        uint8_t aes_out[16];
        sw_aes128(state, padded, aes_out);
        for (int i = 0; i < 16; i++)
            out[i] = aes_out[i] ^ padded[i];

        voleith_secure_zero(padded, sizeof(padded));
    }

    voleith_secure_zero(state, sizeof(state));
    return 0;
}

static int
node_hash_aes_dm_inode_hash(const uint8_t *left, const uint8_t *right,
                            uint8_t *out)
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = right[i] ^ MERKLE_INODE_DOMAIN[i];

    uint8_t cipher[16];
    sw_aes128(left, P, cipher);

    for (int i = 0; i < 16; i++)
        out[i] = cipher[i] ^ P[i];

    voleith_secure_zero(P, sizeof(P));
    voleith_secure_zero(cipher, sizeof(cipher));
    return 0;
}

/*
 * DM leaf witness builder.
 *
 * Mirrors the in-circuit chain: for each AES call, produce the 200
 * inv_in bytes via aes128_gf8_build_witness (which emits a 216-byte
 * [key||inv_in] block; we copy the 200 inv_in bytes only) and update
 * the chaining state for the next iteration.
 */
static int
node_hash_aes_dm_leaf_build_witness(const uint8_t *leaf_data,
                                    size_t leaf_data_bytes, uint8_t *inv_out)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);

    uint8_t aes_w[216];
    uint8_t aes_ct[16];
    size_t pos = 0;

    for (size_t blk = 0; blk < n_inner; blk++) {
        aes128_gf8_build_witness(state, leaf_data + blk * 16, aes_w, aes_ct);
        memcpy(inv_out + pos, aes_w + 16, 200);
        pos += 200;
        for (int i = 0; i < 16; i++)
            state[i] = aes_ct[i] ^ leaf_data[blk * 16 + i];
    }

    if (!needs_padding) {
        const uint8_t *block = leaf_data + (full_blocks - 1) * 16;
        aes128_gf8_build_witness(state, block, aes_w, aes_ct);
        memcpy(inv_out + pos, aes_w + 16, 200);
    } else {
        uint8_t padded[16];
        memset(padded, 0, 16);
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = 0x80;

        aes128_gf8_build_witness(state, padded, aes_w, aes_ct);
        memcpy(inv_out + pos, aes_w + 16, 200);

        voleith_secure_zero(padded, sizeof(padded));
    }

    voleith_secure_zero(state, sizeof(state));
    voleith_secure_zero(aes_w, sizeof(aes_w));
    voleith_secure_zero(aes_ct, sizeof(aes_ct));
    return 0;
}

static int
node_hash_aes_dm_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                     uint8_t *inv_out)
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = right[i] ^ MERKLE_INODE_DOMAIN[i];

    uint8_t aes_w[216];
    aes128_gf8_build_witness(left, P, aes_w, NULL);
    memcpy(inv_out, aes_w + 16, 200);

    voleith_secure_zero(P, sizeof(P));
    voleith_secure_zero(aes_w, sizeof(aes_w));
    return 0;
}

/* ================================================================
 * AES-128-CMAC
 * ================================================================ */

static size_t
node_hash_aes_cmac128_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return aes_cmac_gf8_n_aes_calls(leaf_data_bytes) * 200u;
}

static size_t
node_hash_aes_cmac128_inode_invin_bytes(void)
{
    return aes_cmac_gf8_n_aes_calls(32) * 200u; /* L || R = 32 bytes */
}

static void
node_hash_aes_cmac128_leaf_circuit(voleith_gf8_circuit_t *c,
                                   const gf8_wire_id *leaf_data,
                                   size_t leaf_data_bytes,
                                   gf8_wire_id *out_node)
{
    gf8_wire_id key[16];
    add_const_block_gf8(c, MERKLE_LEAF_DOMAIN, key);
    aes_cmac_gf8_circuit(c, key, 16, leaf_data, leaf_data_bytes, out_node);
}

static void
node_hash_aes_cmac128_inode_circuit(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *left,
                                    const gf8_wire_id *right,
                                    gf8_wire_id *out_node)
{
    gf8_wire_id key[16];
    add_const_block_gf8(c, MERKLE_INODE_DOMAIN, key);

    gf8_wire_id msg[32];
    for (int i = 0; i < 16; i++)
        msg[i] = left[i];
    for (int i = 0; i < 16; i++)
        msg[16 + i] = right[i];

    aes_cmac_gf8_circuit(c, key, 16, msg, 32, out_node);
}

/*
 * CMAC software helper: piggyback on aes_cmac_gf8_build_witness (which
 * computes the tag as a side effect) to avoid duplicating an out-of-
 * circuit CMAC implementation.  The variable-leaf path allocates a
 * transient witness buffer on the heap (size unbounded by leaf input);
 * on malloc failure the function returns -1 and leaves `out` /
 * `inv_out` untouched.  The inode path uses a fixed 616-byte stack
 * buffer (CMAC of a 32-byte message is always 3 AES calls) and cannot
 * fail.
 */
static int
node_hash_aes_cmac128_leaf_hash(const uint8_t *leaf_data,
                                size_t leaf_data_bytes, uint8_t *out)
{
    size_t wbytes = aes_cmac_gf8_witness_bytes(16, leaf_data_bytes);
    uint8_t *w = (uint8_t *)malloc(wbytes);
    if (!w)
        return -1;
    aes_cmac_gf8_build_witness(MERKLE_LEAF_DOMAIN, 16, leaf_data,
                               leaf_data_bytes, w, out);
    voleith_secure_zero(w, wbytes);
    free(w);
    return 0;
}

static int
node_hash_aes_cmac128_inode_hash(const uint8_t *left, const uint8_t *right,
                                 uint8_t *out)
{
    uint8_t msg[32];
    memcpy(msg, left, 16);
    memcpy(msg + 16, right, 16);

    uint8_t w[16 + 200 * 3]; /* CMAC(16-byte key, 32-byte msg) = 3 AES calls */
    aes_cmac_gf8_build_witness(MERKLE_INODE_DOMAIN, 16, msg, 32, w, out);

    voleith_secure_zero(msg, sizeof(msg));
    voleith_secure_zero(w, sizeof(w));
    return 0;
}

static int
node_hash_aes_cmac128_leaf_build_witness(const uint8_t *leaf_data,
                                         size_t leaf_data_bytes,
                                         uint8_t *inv_out)
{
    size_t wbytes = aes_cmac_gf8_witness_bytes(16, leaf_data_bytes);
    size_t inv_bytes = wbytes - 16;
    uint8_t *w = (uint8_t *)malloc(wbytes);
    if (!w)
        return -1;
    aes_cmac_gf8_build_witness(MERKLE_LEAF_DOMAIN, 16, leaf_data,
                               leaf_data_bytes, w, NULL);
    memcpy(inv_out, w + 16, inv_bytes);
    voleith_secure_zero(w, wbytes);
    free(w);
    return 0;
}

static int
node_hash_aes_cmac128_inode_build_witness(const uint8_t *left,
                                          const uint8_t *right,
                                          uint8_t *inv_out)
{
    uint8_t msg[32];
    memcpy(msg, left, 16);
    memcpy(msg + 16, right, 16);

    /* CMAC(16-byte key, 32-byte msg) = 3 AES calls -> 616 byte witness. */
    uint8_t w[16 + 200 * 3];
    aes_cmac_gf8_build_witness(MERKLE_INODE_DOMAIN, 16, msg, 32, w, NULL);
    memcpy(inv_out, w + 16, 200 * 3);

    voleith_secure_zero(msg, sizeof(msg));
    voleith_secure_zero(w, sizeof(w));
    return 0;
}

/* ================================================================
 * vt instances
 * ================================================================ */

/* Compile-time bound check: node_bytes must fit the merkle_vt stack
 * arrays.  See MERKLE_VT_MAX_NODE_BYTES in node_hash_vt.h. */
_Static_assert(16 <= MERKLE_VT_MAX_NODE_BYTES,
               "aes-family node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

const voleith_node_hash_vt voleith_node_hash_aes_dm = {
    .name = "aes-dm",
    .node_bytes = 16,
    .cr_bits = 64,
    .leaf_invin_bytes = node_hash_aes_dm_leaf_invin_bytes,
    .inode_invin_bytes = node_hash_aes_dm_inode_invin_bytes,
    .leaf_circuit = node_hash_aes_dm_leaf_circuit,
    .inode_circuit = node_hash_aes_dm_inode_circuit,
    .leaf_build_witness = node_hash_aes_dm_leaf_build_witness,
    .inode_build_witness = node_hash_aes_dm_inode_build_witness,
    .leaf_hash = node_hash_aes_dm_leaf_hash,
    .inode_hash = node_hash_aes_dm_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_aes_cmac128 = {
    .name = "aes-128-cmac",
    .node_bytes = 16,
    .cr_bits = 64,
    .leaf_invin_bytes = node_hash_aes_cmac128_leaf_invin_bytes,
    .inode_invin_bytes = node_hash_aes_cmac128_inode_invin_bytes,
    .leaf_circuit = node_hash_aes_cmac128_leaf_circuit,
    .inode_circuit = node_hash_aes_cmac128_inode_circuit,
    .leaf_build_witness = node_hash_aes_cmac128_leaf_build_witness,
    .inode_build_witness = node_hash_aes_cmac128_inode_build_witness,
    .leaf_hash = node_hash_aes_cmac128_leaf_hash,
    .inode_hash = node_hash_aes_cmac128_inode_hash,
};
