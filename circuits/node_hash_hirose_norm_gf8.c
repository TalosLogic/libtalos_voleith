/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_norm_gf8.c - Hirose double-block node-hash vts with
 * the FAEST paired-round norm S-box.  See node_hash_hirose_norm_gf8.h.
 *
 * The Hirose construction bodies are shared with the frozen vts through
 * node_hash_hirose_gf8_internal.h; this file is the norm instantiation,
 * driving the shared skeletons with norm = 1.  Same node output as the
 * frozen vts, smaller witness (per-iteration 388 vs 500).  The AES-256
 * key schedule stays frozen; round count (14) and the c constants are
 * untouched, so the dense-c / full-round quantum-collision posture is
 * preserved.  The software helpers (leaf_hash / inode_hash) are reused
 * unchanged: the node output is identical, so they carry no norm flag.
 */

#include "node_hash_hirose_norm_gf8.h"
#include "node_hash_hirose_gf8_internal.h"

/* ================================================================
 * Iteration primitive (norm = 1 wrappers; public, for direct testing)
 * ================================================================ */

size_t
hirose_norm_gf8_iteration_witness_bytes(void)
{
    return HIROSE_NORM_GF8_ITERATION_WITNESS_BYTES;
}

void
hirose_norm_gf8_iteration_circuit(voleith_gf8_circuit_t *c,
                                  const gf8_wire_id G[16],
                                  const gf8_wire_id H[16],
                                  const gf8_wire_id M[16],
                                  const uint8_t c_const[16],
                                  gf8_wire_id G_out[16], gf8_wire_id H_out[16])
{
    nh_hirose_iteration_circuit(c, G, H, M, c_const, G_out, H_out, 1);
}

void
hirose_norm_gf8_iteration_build_witness(
    const uint8_t G[16], const uint8_t H[16], const uint8_t M[16],
    const uint8_t c_const[16],
    uint8_t inv_out[HIROSE_NORM_GF8_ITERATION_WITNESS_BYTES], uint8_t G_out[16],
    uint8_t H_out[16])
{
    nh_hirose_iteration_build_witness(G, H, M, c_const, inv_out, G_out, H_out,
                                      1);
}

/* ================================================================
 * inv_in byte-size accessors (norm = 1)
 * ================================================================ */

static size_t
hirose_norm_fixed32_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_fixed32_leaf_invin_bytes(leaf_data_bytes, 1);
}

static size_t
hirose_norm_fixed96_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_fixed96_leaf_invin_bytes(leaf_data_bytes, 1);
}

static size_t
hirose_norm_variable_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_hirose_variable_leaf_invin_bytes(leaf_data_bytes, 1);
}

static size_t
hirose_norm_inode_invin_bytes(void)
{
    return nh_hirose_inode_invin_bytes(1);
}

/* ================================================================
 * Witness builders (norm = 1)
 * ================================================================ */

static int
hirose_norm_fixed32_leaf_build_witness(const uint8_t *leaf_data,
                                       size_t leaf_data_bytes, uint8_t *inv_out)
{
    return nh_hirose_fixed32_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                inv_out, 1);
}

static int
hirose_norm_fixed96_leaf_build_witness(const uint8_t *leaf_data,
                                       size_t leaf_data_bytes, uint8_t *inv_out)
{
    return nh_hirose_fixed96_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                inv_out, 1);
}

static int
hirose_norm_variable_leaf_build_witness(const uint8_t *leaf_data,
                                        size_t leaf_data_bytes,
                                        uint8_t *inv_out)
{
    return nh_hirose_variable_leaf_build_witness(leaf_data, leaf_data_bytes,
                                                 inv_out, 1);
}

static int
hirose_norm_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                uint8_t *inv_out)
{
    return nh_hirose_inode_build_witness(left, right, inv_out, 1);
}

/* ================================================================
 * In-circuit emission (norm = 1)
 * ================================================================ */

static void
hirose_norm_fixed32_leaf_circuit(voleith_gf8_circuit_t *c,
                                 const gf8_wire_id *leaf_data,
                                 size_t leaf_data_bytes, gf8_wire_id *out_node)
{
    nh_hirose_fixed32_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 1);
}

static void
hirose_norm_fixed96_leaf_circuit(voleith_gf8_circuit_t *c,
                                 const gf8_wire_id *leaf_data,
                                 size_t leaf_data_bytes, gf8_wire_id *out_node)
{
    nh_hirose_fixed96_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 1);
}

static void
hirose_norm_variable_leaf_circuit(voleith_gf8_circuit_t *c,
                                  const gf8_wire_id *leaf_data,
                                  size_t leaf_data_bytes, gf8_wire_id *out_node)
{
    nh_hirose_variable_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 1);
}

static void
hirose_norm_inode_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
                          const gf8_wire_id *right, gf8_wire_id *out_node)
{
    nh_hirose_inode_circuit(c, left, right, out_node, 1);
}

/* ================================================================
 * vt instances
 *
 * node_bytes / cr_bits / fixed_leaf_bytes / leaf_block_bytes match the
 * frozen twins exactly (identical node output).  The software hash
 * slots reuse the shared helpers directly (no norm-specific path).
 * ================================================================ */

_Static_assert(32 <= MERKLE_VT_MAX_NODE_BYTES,
               "hirose node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

const voleith_node_hash_vt voleith_node_hash_hirose_fixed32_norm = {
    .name = "hirose-aes-256-fixed32-norm",
    .node_bytes = 32,
    .cr_bits = 128,
    .fixed_leaf_bytes = 32,
    .leaf_block_bytes = 32,
    .leaf_invin_bytes = hirose_norm_fixed32_leaf_invin_bytes,
    .inode_invin_bytes = hirose_norm_inode_invin_bytes,
    .leaf_circuit = hirose_norm_fixed32_leaf_circuit,
    .inode_circuit = hirose_norm_inode_circuit,
    .leaf_build_witness = hirose_norm_fixed32_leaf_build_witness,
    .inode_build_witness = hirose_norm_inode_build_witness,
    .leaf_hash = nh_hirose_fixed32_leaf_hash,
    .inode_hash = nh_hirose_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_hirose_fixed96_norm = {
    .name = "hirose-aes-256-fixed96-norm",
    .node_bytes = 32,
    .cr_bits = 128,
    .fixed_leaf_bytes = 32,
    .leaf_block_bytes = 96,
    .leaf_invin_bytes = hirose_norm_fixed96_leaf_invin_bytes,
    .inode_invin_bytes = hirose_norm_inode_invin_bytes,
    .leaf_circuit = hirose_norm_fixed96_leaf_circuit,
    .inode_circuit = hirose_norm_inode_circuit,
    .leaf_build_witness = hirose_norm_fixed96_leaf_build_witness,
    .inode_build_witness = hirose_norm_inode_build_witness,
    .leaf_hash = nh_hirose_fixed96_leaf_hash,
    .inode_hash = nh_hirose_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_hirose_norm = {
    .name = "hirose-aes-256-norm",
    .node_bytes = 32,
    .cr_bits = 128,
    .leaf_invin_bytes = hirose_norm_variable_leaf_invin_bytes,
    .inode_invin_bytes = hirose_norm_inode_invin_bytes,
    .leaf_circuit = hirose_norm_variable_leaf_circuit,
    .inode_circuit = hirose_norm_inode_circuit,
    .leaf_build_witness = hirose_norm_variable_leaf_build_witness,
    .inode_build_witness = hirose_norm_inode_build_witness,
    .leaf_hash = nh_hirose_variable_leaf_hash,
    .inode_hash = nh_hirose_inode_hash,
};
