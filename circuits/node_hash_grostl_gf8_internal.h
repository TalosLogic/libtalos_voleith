/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_grostl_gf8_internal.h - shared fixed-input Grostl node-hash
 * skeletons (single-block and two-block-leaf families).
 *
 * The fixed-input Grostl node hashes (H = Omega(f(IV, block)), leaf vs
 * inode domain-separated by distinct chaining values) are identical
 * between the frozen 8-bit-inverse data path and the FAEST paired-round
 * norm data path EXCEPT at the Grostl compression primitive: frozen
 * uses grostl{256,512}_gf8_node{,2}_*, norm uses
 * grostl{256,512}_norm_gf8_node{,2}_*.  Grostl has no key schedule, so
 * the norm witness is a clean 0.75 of the frozen one (every S-box
 * shrinks).
 *
 * This header holds every construction body once, threading an `int
 * norm` flag through the compression calls (and the matching inv_in
 * size accessor).  The node output is byte-for-byte identical for both
 * values of norm (same Grostl compression), so the software helpers
 * carry no norm flag and are shared verbatim.
 *
 * node_hash_grostl_gf8.c drives these with norm = 0 (the frozen fixed
 * vts, unchanged gate stream and fingerprint); node_hash_grostl_norm_
 * gf8.c drives them with norm = 1 (the norm vts).  The four DEPRECATED
 * Merkle-Damgard variants (grostl256 / _t27 / 512 / _t59) are NOT
 * covered here: they have no norm twin (frozen wire-format commitments,
 * no consumer) and stay entirely in node_hash_grostl_gf8.c.
 */

#ifndef VOLEITH_NODE_HASH_GROSTL_GF8_INTERNAL_H
#define VOLEITH_NODE_HASH_GROSTL_GF8_INTERNAL_H

#include "node_hash_vt.h"
#include "grostl_gf8_circuit.h"
#include "grostl_norm_gf8_circuit.h"
#include "../core/grostl.h"
#include "../core/util.h"
#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Domain-separation chaining values.  ASCII label zero-padded to the
 * full chaining-slot width (64 / 128 bytes).  PERMANENT wire-format
 * commitments, byte-identical to the frozen vts (same node output):
 * distinct leaf vs inode (type-confusion safety), distinct across the
 * 256 / 512 variants, and distinct single- vs two-block leaf (the
 * trailing '2', block-count domain separation, Q11).
 * ================================================================ */

static const uint8_t NH_GROSTL_IV_LEAF_256[64] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '2', '5', '6', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f',
};
static const uint8_t NH_GROSTL_IV_INODE_256[64] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '2', '5', '6', '-', 'F', 'i', 'x', 'e', 'd', '-', 'N', 'o', 'd', 'e',
};
static const uint8_t NH_GROSTL_IV_LEAF_512[128] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '5', '1', '2', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f',
};
static const uint8_t NH_GROSTL_IV_INODE_512[128] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '5', '1', '2', '-', 'F', 'i', 'x', 'e', 'd', '-', 'N', 'o', 'd', 'e',
};
static const uint8_t NH_GROSTL_IV_LEAF_256_2BLK[64] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l', '2',
    '5', '6', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f', '2',
};
static const uint8_t NH_GROSTL_IV_LEAF_512_2BLK[128] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l', '5',
    '1', '2', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f', '2',
};

/* ================================================================
 * Single-block fixed family skeletons (per BITS = 256 / 512).
 *
 * H_leaf(x) = Omega(f(IV_leaf, x || 0-pad-to-block)),
 * H(L,R)    = Omega(f(IV_inode, L || R)), one full-width block each.
 * ================================================================ */

#define NH_GROSTL_FIXED_SKELETON(BITS, NODE_BYTES)                             \
    static inline size_t nh_grostl##BITS##_fixed_node_invin(int norm)          \
    {                                                                          \
        return norm ? grostl##BITS##_norm_gf8_node_invin_bytes()               \
                    : grostl##BITS##_gf8_node_invin_bytes();                   \
    }                                                                          \
    static inline void nh_grostl##BITS##_fixed_leaf_circuit(                   \
        voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,                \
        size_t leaf_data_bytes, gf8_wire_id *out_node, int norm)               \
    {                                                                          \
        gf8_wire_id block[2 * (NODE_BYTES)];                                   \
        size_t n = leaf_data_bytes < 2 * (NODE_BYTES) ? leaf_data_bytes        \
                                                      : 2 * (NODE_BYTES);      \
        for (size_t i = 0; i < n; i++)                                         \
            block[i] = leaf_data[i];                                           \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                          \
            block[i] = voleith_gf8_add_const(c, 0x00);                         \
        if (norm)                                                              \
            grostl##BITS##_norm_gf8_node_circuit(c, NH_GROSTL_IV_LEAF_##BITS,  \
                                                 block, out_node);             \
        else                                                                   \
            grostl##BITS##_gf8_node_circuit(c, NH_GROSTL_IV_LEAF_##BITS,       \
                                            block, out_node);                  \
    }                                                                          \
    static inline void nh_grostl##BITS##_fixed_inode_circuit(                  \
        voleith_gf8_circuit_t *c, const gf8_wire_id *left,                     \
        const gf8_wire_id *right, gf8_wire_id *out_node, int norm)             \
    {                                                                          \
        gf8_wire_id block[2 * (NODE_BYTES)];                                   \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[i] = left[i];                                                \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[(NODE_BYTES) + i] = right[i];                                \
        if (norm)                                                              \
            grostl##BITS##_norm_gf8_node_circuit(c, NH_GROSTL_IV_INODE_##BITS, \
                                                 block, out_node);             \
        else                                                                   \
            grostl##BITS##_gf8_node_circuit(c, NH_GROSTL_IV_INODE_##BITS,      \
                                            block, out_node);                  \
    }                                                                          \
    static inline int nh_grostl##BITS##_fixed_leaf_build_witness(              \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *inv_out,    \
        int norm)                                                              \
    {                                                                          \
        uint8_t block[2 * (NODE_BYTES)];                                       \
        size_t n = leaf_data_bytes;                                            \
        if (leaf_data_bytes > 2 * (NODE_BYTES))                                \
            return -1;                                                         \
        for (size_t i = 0; i < n; i++)                                         \
            block[i] = leaf_data[i];                                           \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                          \
            block[i] = 0x00;                                                   \
        if (norm)                                                              \
            grostl##BITS##_norm_gf8_node_build_witness(                        \
                NH_GROSTL_IV_LEAF_##BITS, block, inv_out);                     \
        else                                                                   \
            grostl##BITS##_gf8_node_build_witness(NH_GROSTL_IV_LEAF_##BITS,    \
                                                  block, inv_out);             \
        voleith_secure_zero(block, sizeof(block));                             \
        return 0;                                                              \
    }                                                                          \
    static inline int nh_grostl##BITS##_fixed_inode_build_witness(             \
        const uint8_t *left, const uint8_t *right, uint8_t *inv_out, int norm) \
    {                                                                          \
        uint8_t block[2 * (NODE_BYTES)];                                       \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[i] = left[i];                                                \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[(NODE_BYTES) + i] = right[i];                                \
        if (norm)                                                              \
            grostl##BITS##_norm_gf8_node_build_witness(                        \
                NH_GROSTL_IV_INODE_##BITS, block, inv_out);                    \
        else                                                                   \
            grostl##BITS##_gf8_node_build_witness(NH_GROSTL_IV_INODE_##BITS,   \
                                                  block, inv_out);             \
        voleith_secure_zero(block, sizeof(block));                             \
        return 0;                                                              \
    }                                                                          \
    static inline int nh_grostl##BITS##_fixed_leaf_hash(                       \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *out)        \
    {                                                                          \
        uint8_t block[2 * (NODE_BYTES)];                                       \
        size_t n = leaf_data_bytes;                                            \
        int rc;                                                                \
        if (leaf_data_bytes > 2 * (NODE_BYTES))                                \
            return -1;                                                         \
        for (size_t i = 0; i < n; i++)                                         \
            block[i] = leaf_data[i];                                           \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                          \
            block[i] = 0x00;                                                   \
        rc = voleith_grostl##BITS##_compress_node(NH_GROSTL_IV_LEAF_##BITS,    \
                                                  block, out);                 \
        voleith_secure_zero(block, sizeof(block));                             \
        return rc;                                                             \
    }                                                                          \
    static inline int nh_grostl##BITS##_fixed_inode_hash(                      \
        const uint8_t *left, const uint8_t *right, uint8_t *out)               \
    {                                                                          \
        uint8_t block[2 * (NODE_BYTES)];                                       \
        int rc;                                                                \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[i] = left[i];                                                \
        for (size_t i = 0; i < (NODE_BYTES); i++)                              \
            block[(NODE_BYTES) + i] = right[i];                                \
        rc = voleith_grostl##BITS##_compress_node(NH_GROSTL_IV_INODE_##BITS,   \
                                                  block, out);                 \
        voleith_secure_zero(block, sizeof(block));                             \
        return rc;                                                             \
    }

NH_GROSTL_FIXED_SKELETON(256, 32)
NH_GROSTL_FIXED_SKELETON(512, 64)

/* ================================================================
 * Two-block fixed-leaf family skeletons (leaf side only; the inode
 * reuses the single-block fixed inode above).
 *
 * H_leaf(x) = Omega(f(f(IV_leaf_2blk, x0), x1)), x zero-padded to two
 * full blocks (4*node_bytes).
 * ================================================================ */

#define NH_GROSTL_FIXED2_SKELETON(BITS, NODE_BYTES)                             \
    static inline size_t nh_grostl##BITS##_fixed2_node2_invin(int norm)         \
    {                                                                           \
        return norm ? grostl##BITS##_norm_gf8_node2_invin_bytes()               \
                    : grostl##BITS##_gf8_node2_invin_bytes();                   \
    }                                                                           \
    static inline void nh_grostl##BITS##_fixed2_leaf_circuit(                   \
        voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,                 \
        size_t leaf_data_bytes, gf8_wire_id *out_node, int norm)                \
    {                                                                           \
        gf8_wire_id block[4 * (NODE_BYTES)];                                    \
        size_t n = leaf_data_bytes < 4 * (NODE_BYTES) ? leaf_data_bytes         \
                                                      : 4 * (NODE_BYTES);       \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 4 * (NODE_BYTES); i++)                           \
            block[i] = voleith_gf8_add_const(c, 0x00);                          \
        if (norm)                                                               \
            grostl##BITS##_norm_gf8_node2_circuit(                              \
                c, NH_GROSTL_IV_LEAF_##BITS##_2BLK, block, out_node);           \
        else                                                                    \
            grostl##BITS##_gf8_node2_circuit(                                   \
                c, NH_GROSTL_IV_LEAF_##BITS##_2BLK, block, out_node);           \
    }                                                                           \
    static inline int nh_grostl##BITS##_fixed2_leaf_build_witness(              \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *inv_out,     \
        int norm)                                                               \
    {                                                                           \
        uint8_t block[4 * (NODE_BYTES)];                                        \
        size_t n = leaf_data_bytes;                                             \
        if (leaf_data_bytes > 4 * (NODE_BYTES))                                 \
            return -1;                                                          \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 4 * (NODE_BYTES); i++)                           \
            block[i] = 0x00;                                                    \
        if (norm)                                                               \
            grostl##BITS##_norm_gf8_node2_build_witness(                        \
                NH_GROSTL_IV_LEAF_##BITS##_2BLK, block, inv_out);               \
        else                                                                    \
            grostl##BITS##_gf8_node2_build_witness(                             \
                NH_GROSTL_IV_LEAF_##BITS##_2BLK, block, inv_out);               \
        voleith_secure_zero(block, sizeof(block));                              \
        return 0;                                                               \
    }                                                                           \
    static inline int nh_grostl##BITS##_fixed2_leaf_hash(                       \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *out)         \
    {                                                                           \
        /* Independent oracle: ichor streaming chain (init_iv + absorb the    \
         * two full blocks + finalize_fixed), NOT the circuit witness path. */ \
        uint8_t block[4 * (NODE_BYTES)];                                        \
        size_t n = leaf_data_bytes;                                             \
        ichor_grostl_ctx_t ctx;                                                 \
        if (leaf_data_bytes > 4 * (NODE_BYTES))                                 \
            return -1;                                                          \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 4 * (NODE_BYTES); i++)                           \
            block[i] = 0x00;                                                    \
        ichor_grostl##BITS##_init_iv(&ctx, NH_GROSTL_IV_LEAF_##BITS##_2BLK);    \
        ichor_grostl_absorb(&ctx, block, 4 * (NODE_BYTES));                     \
        ichor_grostl_finalize_fixed(&ctx, out);                                 \
        ichor_grostl_clear(&ctx);                                               \
        voleith_secure_zero(block, sizeof(block));                              \
        return 0;                                                               \
    }

NH_GROSTL_FIXED2_SKELETON(256, 32)
NH_GROSTL_FIXED2_SKELETON(512, 64)

/* ================================================================
 * vt-instance generators.  TAG makes the static vt-slot wrapper names
 * unique within a TU; NORM selects the data path; PUBSYM is the public
 * vt symbol.  The leaf_hash / inode_hash slots point straight at the
 * shared (norm-independent) software helpers.
 * ================================================================ */

#define NH_GROSTL_FIXED_VT(BITS, NODE_BYTES, NAME, CRBITS, PUBSYM, NORM, TAG)  \
    static size_t TAG##_leaf_invin(size_t n)                                   \
    {                                                                          \
        (void)n; /* fixed width: contract requires <= 2*node_bytes */          \
        return nh_grostl##BITS##_fixed_node_invin(NORM);                       \
    }                                                                          \
    static size_t TAG##_inode_invin(void)                                      \
    {                                                                          \
        return nh_grostl##BITS##_fixed_node_invin(NORM);                       \
    }                                                                          \
    static void TAG##_leaf_circuit(voleith_gf8_circuit_t *c,                   \
                                   const gf8_wire_id *ld, size_t n,            \
                                   gf8_wire_id *o)                             \
    {                                                                          \
        nh_grostl##BITS##_fixed_leaf_circuit(c, ld, n, o, NORM);               \
    }                                                                          \
    static void TAG##_inode_circuit(voleith_gf8_circuit_t *c,                  \
                                    const gf8_wire_id *l,                      \
                                    const gf8_wire_id *r, gf8_wire_id *o)      \
    {                                                                          \
        nh_grostl##BITS##_fixed_inode_circuit(c, l, r, o, NORM);               \
    }                                                                          \
    static int TAG##_leaf_bw(const uint8_t *ld, size_t n, uint8_t *iv)         \
    {                                                                          \
        return nh_grostl##BITS##_fixed_leaf_build_witness(ld, n, iv, NORM);    \
    }                                                                          \
    static int TAG##_inode_bw(const uint8_t *l, const uint8_t *r, uint8_t *iv) \
    {                                                                          \
        return nh_grostl##BITS##_fixed_inode_build_witness(l, r, iv, NORM);    \
    }                                                                          \
    const voleith_node_hash_vt PUBSYM = {                                      \
        .name = NAME,                                                          \
        .node_bytes = NODE_BYTES,                                              \
        .cr_bits = CRBITS,                                                     \
        .fixed_leaf_bytes = NODE_BYTES,                                        \
        .leaf_block_bytes = 2 * (NODE_BYTES),                                  \
        .leaf_invin_bytes = TAG##_leaf_invin,                                  \
        .inode_invin_bytes = TAG##_inode_invin,                                \
        .leaf_circuit = TAG##_leaf_circuit,                                    \
        .inode_circuit = TAG##_inode_circuit,                                  \
        .leaf_build_witness = TAG##_leaf_bw,                                   \
        .inode_build_witness = TAG##_inode_bw,                                 \
        .leaf_hash = nh_grostl##BITS##_fixed_leaf_hash,                        \
        .inode_hash = nh_grostl##BITS##_fixed_inode_hash,                      \
    }

#define NH_GROSTL_FIXED2_VT(BITS, NODE_BYTES, NAME, CRBITS, PUBSYM, NORM, TAG) \
    static size_t TAG##_leaf_invin(size_t n)                                   \
    {                                                                          \
        (void)n;                                                               \
        return nh_grostl##BITS##_fixed2_node2_invin(NORM);                     \
    }                                                                          \
    static size_t TAG##_inode_invin(void)                                      \
    {                                                                          \
        return nh_grostl##BITS##_fixed_node_invin(NORM);                       \
    }                                                                          \
    static void TAG##_leaf_circuit(voleith_gf8_circuit_t *c,                   \
                                   const gf8_wire_id *ld, size_t n,            \
                                   gf8_wire_id *o)                             \
    {                                                                          \
        nh_grostl##BITS##_fixed2_leaf_circuit(c, ld, n, o, NORM);              \
    }                                                                          \
    static void TAG##_inode_circuit(voleith_gf8_circuit_t *c,                  \
                                    const gf8_wire_id *l,                      \
                                    const gf8_wire_id *r, gf8_wire_id *o)      \
    {                                                                          \
        nh_grostl##BITS##_fixed_inode_circuit(c, l, r, o, NORM);               \
    }                                                                          \
    static int TAG##_leaf_bw(const uint8_t *ld, size_t n, uint8_t *iv)         \
    {                                                                          \
        return nh_grostl##BITS##_fixed2_leaf_build_witness(ld, n, iv, NORM);   \
    }                                                                          \
    static int TAG##_inode_bw(const uint8_t *l, const uint8_t *r, uint8_t *iv) \
    {                                                                          \
        return nh_grostl##BITS##_fixed_inode_build_witness(l, r, iv, NORM);    \
    }                                                                          \
    const voleith_node_hash_vt PUBSYM = {                                      \
        .name = NAME,                                                          \
        .node_bytes = NODE_BYTES,                                              \
        .cr_bits = CRBITS,                                                     \
        .fixed_leaf_bytes = NODE_BYTES,                                        \
        .leaf_block_bytes = 4 * (NODE_BYTES),                                  \
        .leaf_invin_bytes = TAG##_leaf_invin,                                  \
        .inode_invin_bytes = TAG##_inode_invin,                                \
        .leaf_circuit = TAG##_leaf_circuit,                                    \
        .inode_circuit = TAG##_inode_circuit,                                  \
        .leaf_build_witness = TAG##_leaf_bw,                                   \
        .inode_build_witness = TAG##_inode_bw,                                 \
        .leaf_hash = nh_grostl##BITS##_fixed2_leaf_hash,                       \
        .inode_hash = nh_grostl##BITS##_fixed_inode_hash,                      \
    }

#endif /* VOLEITH_NODE_HASH_GROSTL_GF8_INTERNAL_H */
