/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_gf8_internal.h - shared Hirose node-hash skeletons.
 *
 * The Hirose double-block construction (one AES-256 key schedule, two
 * same-key encryptions per iteration, feed-forward XORs, 10* padding,
 * domain-separating IV / c constants) is identical between the frozen
 * 8-bit-inverse data path and the FAEST paired-round norm data path
 * EXCEPT at the two inner AES-256 encryptions.  This header holds every
 * construction body once, threading an `int norm` flag through those
 * two encrypt sites (and the matching inv_in offsets / per-iteration
 * stride):
 *
 *   norm = 0 -> aes256_gf8_encrypt_rk / _witness; enc inv_in = 224.
 *   norm = 1 -> aes256_norm_gf8_encrypt_rk / _witness; enc inv_in = 168.
 *
 * The AES-256 KEY SCHEDULE STAYS FROZEN (8-bit inverse S-boxes,
 * aes256_gf8_expand_key(_witness)) for both values of norm: the Hirose
 * key-schedule sharing is unchanged, only the two encryptions' S-boxes
 * shrink.  Round count (14) and the c constants are untouched, so the
 * dense-c / full-round quantum-collision posture is preserved
 * (docs/DESIGN.md Hirose section).
 *
 * The node output is byte-for-byte identical for both values of norm
 * (same ideal-cipher construction), so the software helpers
 * nh_hirose_*_hash carry no norm flag and are shared verbatim.
 *
 * node_hash_hirose_gf8.c drives these with norm = 0 (the frozen vts,
 * unchanged gate stream); node_hash_hirose_norm_gf8.c drives them with
 * norm = 1 (the norm vts).
 */

#ifndef VOLEITH_NODE_HASH_HIROSE_GF8_INTERNAL_H
#define VOLEITH_NODE_HASH_HIROSE_GF8_INTERNAL_H

#include "node_hash_vt.h"
#include "aes_gf8_circuit.h"
#include "aes_norm_gf8_circuit.h"
#include "../core/hirose.h"
#include "../core/util.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ================================================================
 * Domain-separation constants (see docs/HIROSE_MERKLE_DESIGN.md §2.4).
 * IV_LEAF is the 2n-bit leaf chaining IV; the c constants are n-bit
 * half-block tweaks, nonzero and pairwise distinct, realizing both the
 * inner f gating and leaf-vs-inode / fixed-vs-variable domain
 * separation.  Byte-identical to the frozen vts (same node output).
 * ================================================================ */

static const uint8_t NH_HIROSE_IV_LEAF[32] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'H', 'i', 'r',
    'o', 's', 'e', '-', 'I', 'V', 0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};
static const uint8_t NH_HIROSE_C_LEAF_FIXED32[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'L',
};
static const uint8_t NH_HIROSE_C_LEAF_FIXED96[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '9', '6',
};
static const uint8_t NH_HIROSE_C_LEAF_VAR[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'V',
};
static const uint8_t NH_HIROSE_C_INODE[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'N',
};

/* ================================================================
 * Per-iteration inv_in size, and the two norm-dispatched AES-256
 * encrypt primitives.  The key schedule is always the frozen one.
 * ================================================================ */

static inline size_t
nh_hirose_enc_invin_bytes(int norm)
{
    return norm ? (size_t)AES256_NORM_GF8_ENC_INVIN_BYTES
                : (size_t)AES256_GF8_ENC_INVIN_BYTES;
}

/* Iteration witness = frozen KS inv_in + 2 * (norm-dependent) enc inv_in. */
static inline size_t
nh_hirose_iteration_witness_bytes(int norm)
{
    return (size_t)AES256_GF8_KS_INVIN_BYTES +
           2u * nh_hirose_enc_invin_bytes(norm);
}

static inline void
nh_hirose_encrypt_rk(voleith_gf8_circuit_t *c, const gf8_wire_id rk[15][16],
                     const gf8_wire_id plaintext[16], gf8_wire_id output[16],
                     int norm)
{
    if (norm)
        aes256_norm_gf8_encrypt_rk(c, rk, plaintext, output);
    else
        aes256_gf8_encrypt_rk(c, rk, plaintext, output);
}

static inline void
nh_hirose_encrypt_rk_witness(const uint8_t rk[15][16],
                             const uint8_t plaintext[16], uint8_t *inv_out,
                             uint8_t ciphertext[16], int norm)
{
    if (norm)
        aes256_norm_gf8_encrypt_rk_witness(rk, plaintext, inv_out, ciphertext);
    else
        aes256_gf8_encrypt_rk_witness(rk, plaintext, inv_out, ciphertext);
}

/* ================================================================
 * One Hirose iteration.  G_out = AES_K(G) XOR G; H_out = AES_K(G XOR c)
 * XOR (G XOR c), K = H || M.  (G, H) is the 2n-bit chaining state, M
 * the n-bit message block, c the nonzero half-block tweak.
 * ================================================================ */

static inline void
nh_hirose_iteration_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id G[16],
                            const gf8_wire_id H[16], const gf8_wire_id M[16],
                            const uint8_t c_const[16], gf8_wire_id G_out[16],
                            gf8_wire_id H_out[16], int norm)
{
    /* Snapshot G: it is read after G_out may alias it (see the frozen
     * file's note on in-place chaining). */
    gf8_wire_id G_in[16];
    for (int i = 0; i < 16; i++)
        G_in[i] = G[i];

    /* K = H || M (pure wire reshape, no gates). */
    gf8_wire_id key_wires[32];
    for (int i = 0; i < 16; i++)
        key_wires[i] = H[i];
    for (int i = 0; i < 16; i++)
        key_wires[16 + i] = M[i];

    /* Frozen AES-256 key schedule, expanded ONCE (shared across both
     * encryptions - the Hirose cost advantage, unchanged by norm). */
    gf8_wire_id rk[15][16];
    aes256_gf8_expand_key(c, key_wires, rk);

    /* G_out = AES_K(G) XOR G. */
    gf8_wire_id ct_G[16];
    nh_hirose_encrypt_rk(c, rk, G_in, ct_G, norm);
    for (int i = 0; i < 16; i++)
        G_out[i] = voleith_gf8_add_xor(c, ct_G[i], G_in[i]);

    /* Gxc = G XOR c_const (free xor-with-constant). */
    gf8_wire_id Gxc[16];
    for (int i = 0; i < 16; i++)
        Gxc[i] = voleith_gf8_add_xor_const(c, G_in[i], c_const[i]);

    /* H_out = AES_K(Gxc) XOR Gxc.  Reuses rk. */
    gf8_wire_id ct_Gxc[16];
    nh_hirose_encrypt_rk(c, rk, Gxc, ct_Gxc, norm);
    for (int i = 0; i < 16; i++)
        H_out[i] = voleith_gf8_add_xor(c, ct_Gxc[i], Gxc[i]);
}

static inline void
nh_hirose_iteration_build_witness(const uint8_t G[16], const uint8_t H[16],
                                  const uint8_t M[16],
                                  const uint8_t c_const[16], uint8_t *inv_out,
                                  uint8_t G_out[16], uint8_t H_out[16],
                                  int norm)
{
    /* Mirror the circuit's emission order:
     *   [0 .. ks)          expand_key (frozen)
     *   [ks .. ks+enc)     encrypt_rk for AES_K(G)
     *   [ks+enc .. ks+2enc) encrypt_rk for AES_K(G ^ c) */
    size_t ks = (size_t)AES256_GF8_KS_INVIN_BYTES;
    size_t enc = nh_hirose_enc_invin_bytes(norm);

    uint8_t key[32];
    memcpy(key, H, 16);
    memcpy(key + 16, M, 16);

    uint8_t rk[15][16];
    uint8_t ct_G[16];
    uint8_t Gxc[16];
    uint8_t ct_Gxc[16];

    aes256_gf8_expand_key_witness(key, inv_out, rk);

    nh_hirose_encrypt_rk_witness(rk, G, inv_out + ks, ct_G, norm);

    for (int i = 0; i < 16; i++)
        Gxc[i] = G[i] ^ c_const[i];

    nh_hirose_encrypt_rk_witness(rk, Gxc, inv_out + ks + enc, ct_Gxc, norm);

    if (G_out != NULL) {
        for (int i = 0; i < 16; i++)
            G_out[i] = ct_G[i] ^ G[i];
    }
    if (H_out != NULL) {
        for (int i = 0; i < 16; i++)
            H_out[i] = ct_Gxc[i] ^ Gxc[i];
    }

    voleith_secure_zero(key, sizeof(key));
    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(ct_G, sizeof(ct_G));
    voleith_secure_zero(Gxc, sizeof(Gxc));
    voleith_secure_zero(ct_Gxc, sizeof(ct_Gxc));
}

/* ================================================================
 * inv_in byte-size accessors
 * ================================================================ */

static inline size_t
nh_hirose_fixed32_leaf_invin_bytes(size_t leaf_data_bytes, int norm)
{
    (void)leaf_data_bytes; /* 2 iterations regardless */
    return 2u * nh_hirose_iteration_witness_bytes(norm);
}

static inline size_t
nh_hirose_fixed96_leaf_invin_bytes(size_t leaf_data_bytes, int norm)
{
    (void)leaf_data_bytes; /* 6 iterations regardless */
    return 6u * nh_hirose_iteration_witness_bytes(norm);
}

static inline size_t
nh_hirose_variable_leaf_invin_bytes(size_t leaf_data_bytes, int norm)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16; /* 10* always-pad */
    return n_iter * nh_hirose_iteration_witness_bytes(norm);
}

static inline size_t
nh_hirose_inode_invin_bytes(int norm)
{
    return 2u * nh_hirose_iteration_witness_bytes(norm);
}

/* ================================================================
 * Software helpers - independent oracles using core/hirose.c.  The
 * node output is identical for frozen and norm, so these carry no norm
 * flag and are shared by both vt families.
 * ================================================================ */

static inline int
nh_hirose_fixed32_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                            uint8_t *out)
{
    size_t n = leaf_data_bytes;
    uint8_t block[32];
    uint8_t G[16], H[16];

    if (leaf_data_bytes > 32)
        return -1;

    memcpy(block, leaf_data, n);
    memset(block + n, 0, 32 - n);

    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);
    voleith_hirose_iteration(G, H, block + 0, NH_HIROSE_C_LEAF_FIXED32, G, H);
    voleith_hirose_iteration(G, H, block + 16, NH_HIROSE_C_LEAF_FIXED32, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(block, sizeof(block));
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_fixed96_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                            uint8_t *out)
{
    size_t n = leaf_data_bytes;
    uint8_t block[96];
    uint8_t G[16], H[16];

    if (leaf_data_bytes > 96)
        return -1;

    memcpy(block, leaf_data, n);
    memset(block + n, 0, 96 - n);

    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);
    for (int k = 0; k < 6; k++)
        voleith_hirose_iteration(G, H, block + 16 * k, NH_HIROSE_C_LEAF_FIXED96,
                                 G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(block, sizeof(block));
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_variable_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                             uint8_t *out)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;

    uint8_t G[16], H[16];
    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);

    for (size_t k = 0; k < n_iter; k++) {
        uint8_t M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = 0x80;
            else
                M[i] = 0x00;
        }
        voleith_hirose_iteration(G, H, M, NH_HIROSE_C_LEAF_VAR, G, H);
        voleith_secure_zero(M, sizeof(M));
    }

    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_inode_hash(const uint8_t *left, const uint8_t *right, uint8_t *out)
{
    uint8_t G[16], H[16];
    memcpy(G, left + 0, 16);
    memcpy(H, left + 16, 16);
    voleith_hirose_iteration(G, H, right + 0, NH_HIROSE_C_INODE, G, H);
    voleith_hirose_iteration(G, H, right + 16, NH_HIROSE_C_INODE, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

/* ================================================================
 * Witness builders - mirror the in-circuit emission order; the
 * per-iteration stride is the norm-dependent iteration witness size.
 * ================================================================ */

static inline int
nh_hirose_fixed32_leaf_build_witness(const uint8_t *leaf_data,
                                     size_t leaf_data_bytes, uint8_t *inv_out,
                                     int norm)
{
    size_t n = leaf_data_bytes;
    size_t stride = nh_hirose_iteration_witness_bytes(norm);
    uint8_t block[32];
    uint8_t G[16], H[16];

    if (leaf_data_bytes > 32)
        return -1;

    memcpy(block, leaf_data, n);
    memset(block + n, 0, 32 - n);

    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);

    nh_hirose_iteration_build_witness(G, H, block + 0, NH_HIROSE_C_LEAF_FIXED32,
                                      inv_out, G, H, norm);
    nh_hirose_iteration_build_witness(G, H, block + 16,
                                      NH_HIROSE_C_LEAF_FIXED32,
                                      inv_out + stride, G, H, norm);

    voleith_secure_zero(block, sizeof(block));
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_fixed96_leaf_build_witness(const uint8_t *leaf_data,
                                     size_t leaf_data_bytes, uint8_t *inv_out,
                                     int norm)
{
    size_t n = leaf_data_bytes;
    size_t stride = nh_hirose_iteration_witness_bytes(norm);
    uint8_t block[96];
    uint8_t G[16], H[16];

    if (leaf_data_bytes > 96)
        return -1;

    memcpy(block, leaf_data, n);
    memset(block + n, 0, 96 - n);

    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);

    for (int k = 0; k < 6; k++)
        nh_hirose_iteration_build_witness(
            G, H, block + 16 * k, NH_HIROSE_C_LEAF_FIXED96,
            inv_out + (size_t)k * stride, G, H, norm);

    voleith_secure_zero(block, sizeof(block));
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_variable_leaf_build_witness(const uint8_t *leaf_data,
                                      size_t leaf_data_bytes, uint8_t *inv_out,
                                      int norm)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;
    size_t stride = nh_hirose_iteration_witness_bytes(norm);

    uint8_t G[16], H[16];
    memcpy(G, NH_HIROSE_IV_LEAF + 0, 16);
    memcpy(H, NH_HIROSE_IV_LEAF + 16, 16);

    for (size_t k = 0; k < n_iter; k++) {
        uint8_t M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = 0x80;
            else
                M[i] = 0x00;
        }
        nh_hirose_iteration_build_witness(G, H, M, NH_HIROSE_C_LEAF_VAR,
                                          inv_out + k * stride, G, H, norm);
        voleith_secure_zero(M, sizeof(M));
    }

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

static inline int
nh_hirose_inode_build_witness(const uint8_t *left, const uint8_t *right,
                              uint8_t *inv_out, int norm)
{
    size_t stride = nh_hirose_iteration_witness_bytes(norm);
    uint8_t G[16], H[16];
    memcpy(G, left + 0, 16);
    memcpy(H, left + 16, 16);

    nh_hirose_iteration_build_witness(G, H, right + 0, NH_HIROSE_C_INODE,
                                      inv_out, G, H, norm);
    nh_hirose_iteration_build_witness(G, H, right + 16, NH_HIROSE_C_INODE,
                                      inv_out + stride, G, H, norm);

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

/* ================================================================
 * In-circuit leaf / inode emission.  IV / padding bytes enter as free
 * add_const wires.
 * ================================================================ */

static inline void
nh_hirose_fixed32_leaf_circuit(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *leaf_data,
                               size_t leaf_data_bytes, gf8_wire_id *out_node,
                               int norm)
{
    size_t n = leaf_data_bytes < 32 ? leaf_data_bytes : 32;

    gf8_wire_id G[16], H[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[16 + i]);

    gf8_wire_id msg[32];
    for (size_t i = 0; i < n; i++)
        msg[i] = leaf_data[i];
    if (n < 32) {
        gf8_wire_id c00 = voleith_gf8_add_const(c, 0x00);
        for (size_t i = n; i < 32; i++)
            msg[i] = c00;
    }

    nh_hirose_iteration_circuit(c, G, H, &msg[0], NH_HIROSE_C_LEAF_FIXED32, G,
                                H, norm);
    nh_hirose_iteration_circuit(c, G, H, &msg[16], NH_HIROSE_C_LEAF_FIXED32, G,
                                H, norm);

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

static inline void
nh_hirose_fixed96_leaf_circuit(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *leaf_data,
                               size_t leaf_data_bytes, gf8_wire_id *out_node,
                               int norm)
{
    size_t n = leaf_data_bytes < 96 ? leaf_data_bytes : 96;

    gf8_wire_id G[16], H[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[16 + i]);

    gf8_wire_id msg[96];
    for (size_t i = 0; i < n; i++)
        msg[i] = leaf_data[i];
    if (n < 96) {
        gf8_wire_id c00 = voleith_gf8_add_const(c, 0x00);
        for (size_t i = n; i < 96; i++)
            msg[i] = c00;
    }

    for (int k = 0; k < 6; k++)
        nh_hirose_iteration_circuit(c, G, H, &msg[16 * k],
                                    NH_HIROSE_C_LEAF_FIXED96, G, H, norm);

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

static inline void
nh_hirose_variable_leaf_circuit(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *leaf_data,
                                size_t leaf_data_bytes, gf8_wire_id *out_node,
                                int norm)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;

    gf8_wire_id G[16], H[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_const(c, NH_HIROSE_IV_LEAF[16 + i]);

    gf8_wire_id c80 = voleith_gf8_add_const(c, 0x80);
    gf8_wire_id c00 = voleith_gf8_add_const(c, 0x00);

    for (size_t k = 0; k < n_iter; k++) {
        gf8_wire_id M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = c80;
            else
                M[i] = c00;
        }
        nh_hirose_iteration_circuit(c, G, H, M, NH_HIROSE_C_LEAF_VAR, G, H,
                                    norm);
    }

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

static inline void
nh_hirose_inode_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
                        const gf8_wire_id *right, gf8_wire_id *out_node,
                        int norm)
{
    gf8_wire_id G[16], H[16];
    nh_hirose_iteration_circuit(c, &left[0], &left[16], &right[0],
                                NH_HIROSE_C_INODE, G, H, norm);
    nh_hirose_iteration_circuit(c, G, H, &right[16], NH_HIROSE_C_INODE, G, H,
                                norm);

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

#endif /* VOLEITH_NODE_HASH_HIROSE_GF8_INTERNAL_H */
