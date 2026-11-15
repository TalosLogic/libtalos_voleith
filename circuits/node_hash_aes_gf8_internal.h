/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_gf8_internal.h - shared AES-family node-hash skeletons.
 *
 * The AES-DM (Matyas-Meyer-Oseas) and AES-128-CMAC node-hash
 * constructions are identical between the frozen 8-bit-inverse data
 * path and the FAEST paired-round norm data path EXCEPT at three
 * points: the inner AES block circuit, the inner AES witness builder,
 * and the per-call inv_in size.  This header holds every function body
 * once, threading an `int norm` flag through those three points:
 *
 *   norm = 0 -> aes128_gf8_circuit / aes128_gf8_build_witness,
 *              aes_cmac_gf8_*;      per-call inv_in = 200 bytes.
 *   norm = 1 -> aes128_norm_gf8_circuit / aes128_norm_gf8_build_witness,
 *              aes_cmac_norm_gf8_*; per-call inv_in = 160 bytes
 *              (AES128_NORM_GF8_WITNESS_BYTES - 16; the key schedule
 *              stays frozen 8-bit, so only the encryption S-boxes
 *              shrink).
 *
 * The emitted node output is byte-for-byte identical for both values of
 * norm (same cipher, same CMAC), so the software helpers
 * nh_aes_*_hash carry no norm flag and are shared verbatim.
 *
 * node_hash_aes_gf8.c drives these with norm = 0 (the frozen vts,
 * unchanged gate stream and fingerprint); node_hash_aes_norm_gf8.c
 * drives them with norm = 1 (the norm vts).
 */

#ifndef VOLEITH_NODE_HASH_AES_GF8_INTERNAL_H
#define VOLEITH_NODE_HASH_AES_GF8_INTERNAL_H

#include "node_hash_vt.h"
#include "aes_gf8_circuit.h"
#include "aes_norm_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include "aes_cmac_norm_gf8_circuit.h"
#include "../core/aes.h"
#include "../core/util.h"
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Domain constants - byte-for-byte identical to merkle_gf8_circuit.c
 * so the resulting circuit matches the existing fixed-hash entry.
 * ================================================================ */

static const uint8_t NH_AES_MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00  /* "Leaf\0\0\0\0" */
};

static const uint8_t NH_AES_MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00  /* "Node\0\0\0\0" */
};

/*
 * Per-AES-call inv_in byte count.  Frozen commits 200 bytes per
 * AES-128 call; norm commits AES128_NORM_GF8_WITNESS_BYTES - 16 = 160
 * (the 16 key bytes are not part of the per-call inv_in).
 */
static inline size_t
nh_aes_inv_per_call(int norm)
{
    return norm ? (size_t)(AES128_NORM_GF8_WITNESS_BYTES - 16u) : 200u;
}

/* ================================================================
 * Shared helpers
 * ================================================================ */

static inline void
nh_aes_add_const_block_gf8(voleith_gf8_circuit_t *c, const uint8_t bytes[16],
                           gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_const(c, bytes[k]);
}

static inline void
nh_aes_xor_block_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id a[16],
                     const gf8_wire_id b[16], gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_xor(c, a[k], b[k]);
}

/* Software AES-128(key, pt) -> out.  Output-only; norm-independent. */
static inline void
nh_aes_sw_aes128(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    voleith_aes_ctx_clear(&ctx);
}

/*
 * One AES-128 block in-circuit, dispatching on norm.  key, in and out
 * are 16-wire blocks.
 */
static inline void
nh_aes_block_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[16],
                     const gf8_wire_id in[16], gf8_wire_id out[16], int norm)
{
    if (norm)
        aes128_norm_gf8_circuit(c, key, in, out);
    else
        aes128_gf8_circuit(c, key, in, out);
}

/*
 * One AES-128 block witness, dispatching on norm.  Writes the per-call
 * inv_in (nh_aes_inv_per_call(norm) bytes) to inv_out; ct_out, if
 * non-NULL, receives the 16-byte ciphertext.  Uses a 216-byte scratch
 * buffer that covers both the frozen (216) and norm (176) builder
 * output sizes.
 */
static inline void
nh_aes_block_witness(const uint8_t key[16], const uint8_t in[16],
                     uint8_t *inv_out, uint8_t ct_out[16], int norm)
{
    uint8_t w[216];

    if (norm)
        aes128_norm_gf8_build_witness(key, in, w, ct_out);
    else
        aes128_gf8_build_witness(key, in, w, ct_out);
    memcpy(inv_out, w + 16, nh_aes_inv_per_call(norm));
    voleith_secure_zero(w, sizeof(w));
}

/* ================================================================
 * AES-DM (Matyas-Meyer-Oseas; see keying note in node_hash_aes_gf8.c)
 * ================================================================ */

static inline size_t
nh_aes_dm_n_aes(size_t n)
{
    size_t full = n / 16;
    int needs_pad = (n == 0) || (n % 16 != 0);
    return needs_pad ? full + 1 : full;
}

static inline size_t
nh_aes_dm_leaf_invin_bytes(size_t leaf_data_bytes, int norm)
{
    return nh_aes_dm_n_aes(leaf_data_bytes) * nh_aes_inv_per_call(norm);
}

static inline size_t
nh_aes_dm_inode_invin_bytes(int norm)
{
    return nh_aes_inv_per_call(norm); /* one AES-128 call */
}

static inline void
nh_aes_dm_leaf_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
                       size_t leaf_data_bytes, gf8_wire_id *out_node, int norm)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    gf8_wire_id state[16];
    nh_aes_add_const_block_gf8(c, NH_AES_MERKLE_LEAF_DOMAIN, state);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        const gf8_wire_id *block = leaf_data + blk * 16;
        gf8_wire_id aes_out[16];
        nh_aes_block_circuit(c, state, block, aes_out, norm);
        nh_aes_xor_block_gf8(c, aes_out, block, state);
    }

    if (!needs_padding) {
        const gf8_wire_id *block = leaf_data + (full_blocks - 1) * 16;
        gf8_wire_id aes_out[16];
        nh_aes_block_circuit(c, state, block, aes_out, norm);
        nh_aes_xor_block_gf8(c, aes_out, block, out_node);
    } else {
        gf8_wire_id padded[16];
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = voleith_gf8_add_const(c, 0x80);
        for (size_t b = last_bytes + 1; b < 16; b++)
            padded[b] = voleith_gf8_add_const(c, 0x00);

        gf8_wire_id aes_out[16];
        nh_aes_block_circuit(c, state, padded, aes_out, norm);
        nh_aes_xor_block_gf8(c, aes_out, padded, out_node);
    }
}

static inline void
nh_aes_dm_inode_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
                        const gf8_wire_id *right, gf8_wire_id *out_node,
                        int norm)
{
    gf8_wire_id c_inode[16];
    nh_aes_add_const_block_gf8(c, NH_AES_MERKLE_INODE_DOMAIN, c_inode);

    gf8_wire_id P[16];
    nh_aes_xor_block_gf8(c, right, c_inode, P);

    gf8_wire_id cipher[16];
    nh_aes_block_circuit(c, left, P, cipher, norm);

    nh_aes_xor_block_gf8(c, cipher, P, out_node);
}

static inline int
nh_aes_dm_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                    uint8_t *out)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, NH_AES_MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t aes_out[16];
        nh_aes_sw_aes128(state, leaf_data + blk * 16, aes_out);
        for (int i = 0; i < 16; i++)
            state[i] = aes_out[i] ^ leaf_data[blk * 16 + i];
    }

    if (!needs_padding) {
        const uint8_t *block = leaf_data + (full_blocks - 1) * 16;
        uint8_t aes_out[16];
        nh_aes_sw_aes128(state, block, aes_out);
        for (int i = 0; i < 16; i++)
            out[i] = aes_out[i] ^ block[i];
    } else {
        uint8_t padded[16];
        memset(padded, 0, 16);
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = 0x80;

        uint8_t aes_out[16];
        nh_aes_sw_aes128(state, padded, aes_out);
        for (int i = 0; i < 16; i++)
            out[i] = aes_out[i] ^ padded[i];

        voleith_secure_zero(padded, sizeof(padded));
    }

    voleith_secure_zero(state, sizeof(state));
    return 0;
}

static inline int
nh_aes_dm_inode_hash(const uint8_t *left, const uint8_t *right, uint8_t *out)
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = right[i] ^ NH_AES_MERKLE_INODE_DOMAIN[i];

    uint8_t cipher[16];
    nh_aes_sw_aes128(left, P, cipher);

    for (int i = 0; i < 16; i++)
        out[i] = cipher[i] ^ P[i];

    voleith_secure_zero(P, sizeof(P));
    voleith_secure_zero(cipher, sizeof(cipher));
    return 0;
}

/*
 * DM leaf witness builder.  Mirrors the in-circuit chain: for each AES
 * call, produce the per-call inv_in via nh_aes_block_witness and update
 * the chaining state for the next iteration.
 */
static inline int
nh_aes_dm_leaf_build_witness(const uint8_t *leaf_data, size_t leaf_data_bytes,
                             uint8_t *inv_out, int norm)
{
    size_t full_blocks = leaf_data_bytes / 16;
    size_t last_bytes = leaf_data_bytes % 16;
    int needs_padding = (leaf_data_bytes == 0) || (last_bytes != 0);

    uint8_t state[16];
    memcpy(state, NH_AES_MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner =
        needs_padding ? full_blocks : (full_blocks > 0 ? full_blocks - 1 : 0);

    size_t inv_per_call = nh_aes_inv_per_call(norm);
    uint8_t aes_ct[16];
    size_t pos = 0;

    for (size_t blk = 0; blk < n_inner; blk++) {
        nh_aes_block_witness(state, leaf_data + blk * 16, inv_out + pos, aes_ct,
                             norm);
        pos += inv_per_call;
        for (int i = 0; i < 16; i++)
            state[i] = aes_ct[i] ^ leaf_data[blk * 16 + i];
    }

    if (!needs_padding) {
        const uint8_t *block = leaf_data + (full_blocks - 1) * 16;
        nh_aes_block_witness(state, block, inv_out + pos, aes_ct, norm);
    } else {
        uint8_t padded[16];
        memset(padded, 0, 16);
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = leaf_data[full_blocks * 16 + b];
        padded[last_bytes] = 0x80;

        nh_aes_block_witness(state, padded, inv_out + pos, aes_ct, norm);

        voleith_secure_zero(padded, sizeof(padded));
    }

    voleith_secure_zero(state, sizeof(state));
    voleith_secure_zero(aes_ct, sizeof(aes_ct));
    return 0;
}

static inline int
nh_aes_dm_inode_build_witness(const uint8_t *left, const uint8_t *right,
                              uint8_t *inv_out, int norm)
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = right[i] ^ NH_AES_MERKLE_INODE_DOMAIN[i];

    nh_aes_block_witness(left, P, inv_out, NULL, norm);

    voleith_secure_zero(P, sizeof(P));
    return 0;
}

/* ================================================================
 * AES-128-CMAC
 *
 * node_bytes = 16, cr_bits = 64.  The CMAC mode logic itself lives in
 * aes_cmac_gf8_circuit.c / aes_cmac_norm_gf8_circuit.c; this family
 * just keys CMAC with a domain-separated constant and dispatches on
 * norm.  n_aes_calls is identical for both data paths; only the
 * per-call inv_in size (and thus the witness builder) differs.
 * ================================================================ */

static inline size_t
nh_aes_cmac128_leaf_invin_bytes(size_t leaf_data_bytes, int norm)
{
    return aes_cmac_gf8_n_aes_calls(leaf_data_bytes) *
           nh_aes_inv_per_call(norm);
}

static inline size_t
nh_aes_cmac128_inode_invin_bytes(int norm)
{
    /* L || R = 32 bytes */
    return aes_cmac_gf8_n_aes_calls(32) * nh_aes_inv_per_call(norm);
}

static inline void
nh_aes_cmac128_leaf_circuit(voleith_gf8_circuit_t *c,
                            const gf8_wire_id *leaf_data,
                            size_t leaf_data_bytes, gf8_wire_id *out_node,
                            int norm)
{
    gf8_wire_id key[16];
    nh_aes_add_const_block_gf8(c, NH_AES_MERKLE_LEAF_DOMAIN, key);
    if (norm)
        aes_cmac_norm_gf8_circuit(c, key, 16, leaf_data, leaf_data_bytes,
                                  out_node);
    else
        aes_cmac_gf8_circuit(c, key, 16, leaf_data, leaf_data_bytes, out_node);
}

static inline void
nh_aes_cmac128_inode_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
                             const gf8_wire_id *right, gf8_wire_id *out_node,
                             int norm)
{
    gf8_wire_id key[16];
    nh_aes_add_const_block_gf8(c, NH_AES_MERKLE_INODE_DOMAIN, key);

    gf8_wire_id msg[32];
    for (int i = 0; i < 16; i++)
        msg[i] = left[i];
    for (int i = 0; i < 16; i++)
        msg[16 + i] = right[i];

    if (norm)
        aes_cmac_norm_gf8_circuit(c, key, 16, msg, 32, out_node);
    else
        aes_cmac_gf8_circuit(c, key, 16, msg, 32, out_node);
}

/*
 * CMAC software helpers: piggyback on aes_cmac_gf8_build_witness (which
 * computes the tag as a side effect) to avoid duplicating an out-of-
 * circuit CMAC implementation.  The tag is the node output, identical
 * for frozen and norm, so these use the frozen witness builder
 * regardless of the circuit's data path and carry no norm flag.  The
 * variable-leaf path allocates a transient witness buffer on the heap;
 * on malloc failure it returns -1 and leaves `out` untouched.
 */
static inline int
nh_aes_cmac128_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                         uint8_t *out)
{
    size_t wbytes = aes_cmac_gf8_witness_bytes(16, leaf_data_bytes);
    uint8_t *w = (uint8_t *)malloc(wbytes);
    if (!w)
        return -1;
    aes_cmac_gf8_build_witness(NH_AES_MERKLE_LEAF_DOMAIN, 16, leaf_data,
                               leaf_data_bytes, w, out);
    voleith_secure_zero(w, wbytes);
    free(w);
    return 0;
}

static inline int
nh_aes_cmac128_inode_hash(const uint8_t *left, const uint8_t *right,
                          uint8_t *out)
{
    uint8_t msg[32];
    memcpy(msg, left, 16);
    memcpy(msg + 16, right, 16);

    uint8_t w[16 + 200 * 3]; /* CMAC(16-byte key, 32-byte msg) = 3 AES calls */
    aes_cmac_gf8_build_witness(NH_AES_MERKLE_INODE_DOMAIN, 16, msg, 32, w, out);

    voleith_secure_zero(msg, sizeof(msg));
    voleith_secure_zero(w, sizeof(w));
    return 0;
}

static inline int
nh_aes_cmac128_leaf_build_witness(const uint8_t *leaf_data,
                                  size_t leaf_data_bytes, uint8_t *inv_out,
                                  int norm)
{
    size_t wbytes = norm ? aes_cmac_norm_gf8_witness_bytes(16, leaf_data_bytes)
                         : aes_cmac_gf8_witness_bytes(16, leaf_data_bytes);
    size_t inv_bytes = wbytes - 16;
    uint8_t *w = (uint8_t *)malloc(wbytes);
    if (!w)
        return -1;
    if (norm)
        aes_cmac_norm_gf8_build_witness(NH_AES_MERKLE_LEAF_DOMAIN, 16,
                                        leaf_data, leaf_data_bytes, w, NULL);
    else
        aes_cmac_gf8_build_witness(NH_AES_MERKLE_LEAF_DOMAIN, 16, leaf_data,
                                   leaf_data_bytes, w, NULL);
    memcpy(inv_out, w + 16, inv_bytes);
    voleith_secure_zero(w, wbytes);
    free(w);
    return 0;
}

static inline int
nh_aes_cmac128_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                   uint8_t *inv_out, int norm)
{
    uint8_t msg[32];
    memcpy(msg, left, 16);
    memcpy(msg + 16, right, 16);

    /*
     * CMAC(16-byte key, 32-byte msg) = 3 AES calls.  The 616-byte buffer
     * covers the frozen witness (16 + 200*3); norm uses 16 + 160*3.
     */
    uint8_t w[16 + 200 * 3];
    size_t wbytes = norm ? aes_cmac_norm_gf8_witness_bytes(16, 32)
                         : aes_cmac_gf8_witness_bytes(16, 32);
    if (norm)
        aes_cmac_norm_gf8_build_witness(NH_AES_MERKLE_INODE_DOMAIN, 16, msg, 32,
                                        w, NULL);
    else
        aes_cmac_gf8_build_witness(NH_AES_MERKLE_INODE_DOMAIN, 16, msg, 32, w,
                                   NULL);
    memcpy(inv_out, w + 16, wbytes - 16);

    voleith_secure_zero(msg, sizeof(msg));
    voleith_secure_zero(w, sizeof(w));
    return 0;
}

#endif /* VOLEITH_NODE_HASH_AES_GF8_INTERNAL_H */
