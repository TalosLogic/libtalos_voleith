/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_norm_gf8.c - AES-DM and AES-128-CMAC node-hash vts with
 * the FAEST paired-round norm S-box.  See node_hash_aes_norm_gf8.h.
 *
 * The AES-DM (Matyas-Meyer-Oseas) and AES-128-CMAC construction bodies
 * are shared with the frozen vts through node_hash_aes_gf8_internal.h;
 * this file is the norm instantiation, driving the shared skeletons
 * with norm = 1.  Same node output as the frozen vts, smaller witness
 * (per-call inv_in 160 vs 200).  The software helpers (leaf_hash /
 * inode_hash) are reused unchanged: the node output is identical, so
 * they carry no norm flag.
 */

#include "node_hash_aes_norm_gf8.h"
#include "node_hash_aes_gf8_internal.h"

/* ================================================================
 * AES-DM (norm = 1 wrappers)
 * ================================================================ */

static size_t
node_hash_aes_dm_norm_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_aes_dm_leaf_invin_bytes(leaf_data_bytes, 1);
}

static size_t
node_hash_aes_dm_norm_inode_invin_bytes(void)
{
    return nh_aes_dm_inode_invin_bytes(1);
}

static void
node_hash_aes_dm_norm_leaf_circuit(voleith_gf8_circuit_t *c,
                                   const gf8_wire_id *leaf_data,
                                   size_t leaf_data_bytes,
                                   gf8_wire_id *out_node)
{
    nh_aes_dm_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 1);
}

static void
node_hash_aes_dm_norm_inode_circuit(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *left,
                                    const gf8_wire_id *right,
                                    gf8_wire_id *out_node)
{
    nh_aes_dm_inode_circuit(c, left, right, out_node, 1);
}

static int
node_hash_aes_dm_norm_leaf_build_witness(const uint8_t *leaf_data,
                                         size_t leaf_data_bytes,
                                         uint8_t *inv_out)
{
    return nh_aes_dm_leaf_build_witness(leaf_data, leaf_data_bytes, inv_out, 1);
}

static int
node_hash_aes_dm_norm_inode_build_witness(const uint8_t *left,
                                          const uint8_t *right,
                                          uint8_t *inv_out)
{
    return nh_aes_dm_inode_build_witness(left, right, inv_out, 1);
}

/* ================================================================
 * AES-128-CMAC (norm = 1 wrappers)
 * ================================================================ */

static size_t
node_hash_aes_cmac128_norm_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_aes_cmac128_leaf_invin_bytes(leaf_data_bytes, 1);
}

static size_t
node_hash_aes_cmac128_norm_inode_invin_bytes(void)
{
    return nh_aes_cmac128_inode_invin_bytes(1);
}

static void
node_hash_aes_cmac128_norm_leaf_circuit(voleith_gf8_circuit_t *c,
                                        const gf8_wire_id *leaf_data,
                                        size_t leaf_data_bytes,
                                        gf8_wire_id *out_node)
{
    nh_aes_cmac128_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 1);
}

static void
node_hash_aes_cmac128_norm_inode_circuit(voleith_gf8_circuit_t *c,
                                         const gf8_wire_id *left,
                                         const gf8_wire_id *right,
                                         gf8_wire_id *out_node)
{
    nh_aes_cmac128_inode_circuit(c, left, right, out_node, 1);
}

static int
node_hash_aes_cmac128_norm_leaf_build_witness(const uint8_t *leaf_data,
                                              size_t leaf_data_bytes,
                                              uint8_t *inv_out)
{
    return nh_aes_cmac128_leaf_build_witness(leaf_data, leaf_data_bytes,
                                             inv_out, 1);
}

static int
node_hash_aes_cmac128_norm_inode_build_witness(const uint8_t *left,
                                               const uint8_t *right,
                                               uint8_t *inv_out)
{
    return nh_aes_cmac128_inode_build_witness(left, right, inv_out, 1);
}

/* ================================================================
 * vt instances
 *
 * The leaf_hash / inode_hash slots reuse the shared software helpers
 * directly: the node output is identical to the frozen vts, so there
 * is no norm-specific software path.
 * ================================================================ */

_Static_assert(16 <= MERKLE_VT_MAX_NODE_BYTES,
               "aes-family node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

const voleith_node_hash_vt voleith_node_hash_aes_dm_norm = {
    .name = "aes-dm-norm",
    .node_bytes = 16,
    .cr_bits = 64,
    .leaf_invin_bytes = node_hash_aes_dm_norm_leaf_invin_bytes,
    .inode_invin_bytes = node_hash_aes_dm_norm_inode_invin_bytes,
    .leaf_circuit = node_hash_aes_dm_norm_leaf_circuit,
    .inode_circuit = node_hash_aes_dm_norm_inode_circuit,
    .leaf_build_witness = node_hash_aes_dm_norm_leaf_build_witness,
    .inode_build_witness = node_hash_aes_dm_norm_inode_build_witness,
    .leaf_hash = nh_aes_dm_leaf_hash,
    .inode_hash = nh_aes_dm_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_aes_cmac128_norm = {
    .name = "aes-128-cmac-norm",
    .node_bytes = 16,
    .cr_bits = 64,
    .leaf_invin_bytes = node_hash_aes_cmac128_norm_leaf_invin_bytes,
    .inode_invin_bytes = node_hash_aes_cmac128_norm_inode_invin_bytes,
    .leaf_circuit = node_hash_aes_cmac128_norm_leaf_circuit,
    .inode_circuit = node_hash_aes_cmac128_norm_inode_circuit,
    .leaf_build_witness = node_hash_aes_cmac128_norm_leaf_build_witness,
    .inode_build_witness = node_hash_aes_cmac128_norm_inode_build_witness,
    .leaf_hash = nh_aes_cmac128_leaf_hash,
    .inode_hash = nh_aes_cmac128_inode_hash,
};
