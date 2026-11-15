/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_gf8.c - Hirose double-block-length node hash as a
 * GF(2^8) circuit (frozen 8-bit-inverse data path).
 *
 * Optimization: every linear operation is a free wire-graph
 * construction (add_xor / add_xor_const).  The only VOLE-slot
 * consumers are AES-256 S-boxes, and the key-schedule sharing across
 * the two same-key encryptions is structural (one expand_key, two
 * encrypt_rk).  See the header for the per-iteration gate accounting.
 *
 * The construction bodies live in node_hash_hirose_gf8_internal.h,
 * shared with the norm-S-box variant (node_hash_hirose_norm_gf8.c).
 * This file is the frozen instantiation: it drives the shared skeletons
 * with norm = 0, so the emitted circuit, its fingerprint and the KATs
 * are exactly what they were before the skeleton was extracted.  Round
 * count (14) and the c constants are untouched by either data path,
 * preserving the dense-c / full-round quantum-collision posture.
 */

#include "node_hash_hirose_gf8.h"
#include "node_hash_hirose_gf8_internal.h"

/* ================================================================
 * Iteration primitive (norm = 0 wrappers; public, used by examples
 * and tests directly).
 * ================================================================ */

size_t
hirose_gf8_iteration_witness_bytes(void)
{
    return HIROSE_GF8_ITERATION_WITNESS_BYTES;
}

void
hirose_gf8_iteration_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id G[16],
                             const gf8_wire_id H[16], const gf8_wire_id M[16],
                             const uint8_t c_const[16], gf8_wire_id G_out[16],
                             gf8_wire_id H_out[16])
{
    nh_hirose_iteration_circuit(c, G, H, M, c_const, G_out, H_out, 0);
}

void
hirose_gf8_iteration_build_witness(
    const uint8_t G[16], const uint8_t H[16], const uint8_t M[16],
    const uint8_t c_const[16],
    uint8_t inv_out[HIROSE_GF8_ITERATION_WITNESS_BYTES], uint8_t G_out[16],
    uint8_t H_out[16])
{
    nh_hirose_iteration_build_witness(G, H, M, c_const, inv_out, G_out, H_out,
                                      0);
}

/* ================================================================
 * inv_in byte-size accessors (norm = 0)
 * ================================================================ */

size_t
merkle_hirose_gf8_fixed32_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_fixed32_leaf_invin_bytes(leaf_data_bytes, 0);
}

size_t
merkle_hirose_gf8_fixed96_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_fixed96_leaf_invin_bytes(leaf_data_bytes, 0);
}

size_t
merkle_hirose_gf8_variable_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_variable_leaf_invin_bytes(leaf_data_bytes, 0);
}

size_t
merkle_hirose_gf8_inode_invin_bytes(void)
{
    return nh_hirose_inode_invin_bytes(0);
}

/* ================================================================
 * Software helpers (output-only; norm-independent)
 * ================================================================ */

int
merkle_hirose_fixed32_leaf_hash(const uint8_t *leaf_data,
                                size_t leaf_data_bytes, uint8_t *out)
{
    return nh_hirose_fixed32_leaf_hash(leaf_data, leaf_data_bytes, out);
}

int
merkle_hirose_fixed96_leaf_hash(const uint8_t *leaf_data,
                                size_t leaf_data_bytes, uint8_t *out)
{
    return nh_hirose_fixed96_leaf_hash(leaf_data, leaf_data_bytes, out);
}

int
merkle_hirose_variable_leaf_hash(const uint8_t *leaf_data,
                                 size_t leaf_data_bytes, uint8_t *out)
{
    return nh_hirose_variable_leaf_hash(leaf_data, leaf_data_bytes, out);
}

int
merkle_hirose_inode_hash(const uint8_t *left, const uint8_t *right,
                         uint8_t *out)
{
    return nh_hirose_inode_hash(left, right, out);
}

/* ================================================================
 * Witness builders (norm = 0)
 * ================================================================ */

int
merkle_hirose_gf8_fixed32_leaf_build_witness(const uint8_t *leaf_data,
                                             size_t leaf_data_bytes,
                                             uint8_t *inv_out)
{
    return nh_hirose_fixed32_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                inv_out, 0);
}

int
merkle_hirose_gf8_fixed96_leaf_build_witness(const uint8_t *leaf_data,
                                             size_t leaf_data_bytes,
                                             uint8_t *inv_out)
{
    return nh_hirose_fixed96_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                inv_out, 0);
}

int
merkle_hirose_gf8_variable_leaf_build_witness(const uint8_t *leaf_data,
                                              size_t leaf_data_bytes,
                                              uint8_t *inv_out)
{
    return nh_hirose_variable_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                 inv_out, 0);
}

int
merkle_hirose_gf8_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                      uint8_t *inv_out)
{
    return nh_hirose_inode_build_witness(left, right, inv_out, 0);
}

/* ================================================================
 * In-circuit emission (norm = 0)
 * ================================================================ */

void
merkle_hirose_gf8_fixed32_leaf_circuit(voleith_gf8_circuit_t *c,
                                       const gf8_wire_id *leaf_data,
                                       size_t leaf_data_bytes,
                                       gf8_wire_id *out_node)
{
    nh_hirose_fixed32_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 0);
}

void
merkle_hirose_gf8_fixed96_leaf_circuit(voleith_gf8_circuit_t *c,
                                       const gf8_wire_id *leaf_data,
                                       size_t leaf_data_bytes,
                                       gf8_wire_id *out_node)
{
    nh_hirose_fixed96_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 0);
}

void
merkle_hirose_gf8_variable_leaf_circuit(voleith_gf8_circuit_t *c,
                                        const gf8_wire_id *leaf_data,
                                        size_t leaf_data_bytes,
                                        gf8_wire_id *out_node)
{
    nh_hirose_variable_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 0);
}

void
merkle_hirose_gf8_inode_circuit(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *left,
                                const gf8_wire_id *right, gf8_wire_id *out_node)
{
    nh_hirose_inode_circuit(c, left, right, out_node, 0);
}

/* ================================================================
 * vt instances
 *
 * node_bytes = 32 (256-bit Hirose state), cr_bits = 128 (FSE 2006
 * ideal-cipher bound).  The three vts differ only in the leaf_* fields
 * (gated by distinct c_leaf constants); they share the inode.
 * ================================================================ */

/* Compile-time bound check.  See MERKLE_VT_MAX_NODE_BYTES in node_hash_vt.h. */
_Static_assert(32 <= MERKLE_VT_MAX_NODE_BYTES,
               "hirose node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

const voleith_node_hash_vt voleith_node_hash_hirose_fixed32 = {
    .name = "hirose-aes-256-fixed32",
    .node_bytes = 32,
    .cr_bits = 128,
    .fixed_leaf_bytes = 32,
    .leaf_block_bytes = 32,
    .leaf_invin_bytes = merkle_hirose_gf8_fixed32_leaf_invin_bytes,
    .inode_invin_bytes = merkle_hirose_gf8_inode_invin_bytes,
    .leaf_circuit = merkle_hirose_gf8_fixed32_leaf_circuit,
    .inode_circuit = merkle_hirose_gf8_inode_circuit,
    .leaf_build_witness = merkle_hirose_gf8_fixed32_leaf_build_witness,
    .inode_build_witness = merkle_hirose_gf8_inode_build_witness,
    .leaf_hash = merkle_hirose_fixed32_leaf_hash,
    .inode_hash = merkle_hirose_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_hirose_fixed96 = {
    .name = "hirose-aes-256-fixed96",
    .node_bytes = 32,
    .cr_bits = 128,
    .fixed_leaf_bytes = 32,
    .leaf_block_bytes = 96,
    .leaf_invin_bytes = merkle_hirose_gf8_fixed96_leaf_invin_bytes,
    .inode_invin_bytes = merkle_hirose_gf8_inode_invin_bytes,
    .leaf_circuit = merkle_hirose_gf8_fixed96_leaf_circuit,
    .inode_circuit = merkle_hirose_gf8_inode_circuit,
    .leaf_build_witness = merkle_hirose_gf8_fixed96_leaf_build_witness,
    .inode_build_witness = merkle_hirose_gf8_inode_build_witness,
    .leaf_hash = merkle_hirose_fixed96_leaf_hash,
    .inode_hash = merkle_hirose_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_hirose = {
    .name = "hirose-aes-256",
    .node_bytes = 32,
    .cr_bits = 128,
    .leaf_invin_bytes = merkle_hirose_gf8_variable_leaf_invin_bytes,
    .inode_invin_bytes = merkle_hirose_gf8_inode_invin_bytes,
    .leaf_circuit = merkle_hirose_gf8_variable_leaf_circuit,
    .inode_circuit = merkle_hirose_gf8_inode_circuit,
    .leaf_build_witness = merkle_hirose_gf8_variable_leaf_build_witness,
    .inode_build_witness = merkle_hirose_gf8_inode_build_witness,
    .leaf_hash = merkle_hirose_variable_leaf_hash,
    .inode_hash = merkle_hirose_inode_hash,
};
