/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_gf8.c - AES-DM and AES-128-CMAC vt implementations.
 *
 * "AES-DM" is a historical label: the compression is actually Matyas-
 * Meyer-Oseas (chaining-value-keyed), NOT Davies-Meyer.  See the keying
 * note below.
 *
 * Branch A of the merkle tree circuits hash-agnostic refactor: wraps
 * the leaf/inode compressions already used by merkle_gf8_circuit.c
 * (with the matching domain constants) behind the voleith_node_hash_vt
 * function-pointer interface.  Bit-exact gate-stream equivalence with
 * the existing fixed-hash entry point is intentional and is the
 * load-bearing invariant the Branch B equivalence harness will assert.
 *
 * No proof-time cost: the vt is consumed at circuit-build time only.
 *
 * NOTE ON KEYING (do not confuse with Davies-Meyer): despite the "DM"
 * in the vt name (historical / matching merkle_gf8_circuit.c), the
 * single-block-length compression here is MATYAS-MEYER-OSEAS, not
 * Davies-Meyer.  Each iteration keys the AES block cipher with the
 * CHAINING VALUE and feeds forward the MESSAGE block:
 *
 *     H_i = E_{H_{i-1}}(m_i) XOR m_i          (MMO: chaining value = key)
 *
 * The inode form H(L,R) = AES_L(R XOR C) XOR (R XOR C) is the same MMO
 * keying with L as the key.  Standard Davies-Meyer keys with the
 * MESSAGE instead (H_i = E_{m_i}(H_{i-1}) XOR H_{i-1}); that is what
 * ichor_aesdm_* / the V5 opener KDF use, so those must NOT reuse this
 * gadget's compression.
 *
 * The construction bodies live in node_hash_aes_gf8_internal.h, shared
 * with the norm-S-box variant (node_hash_aes_norm_gf8.c).  This file is
 * the frozen 8-bit-inverse instantiation: it drives the shared
 * skeletons with norm = 0, so the emitted circuit, its fingerprint and
 * the KATs are exactly what they were before the skeleton was
 * extracted.
 */

#include "node_hash_aes_gf8.h"
#include "node_hash_aes_gf8_internal.h"

/* ================================================================
 * AES-DM (norm = 0 wrappers)
 * ================================================================ */

static size_t
node_hash_aes_dm_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_aes_dm_leaf_invin_bytes(leaf_data_bytes, 0);
}

static size_t
node_hash_aes_dm_inode_invin_bytes(void)
{
    return nh_aes_dm_inode_invin_bytes(0);
}

static void
node_hash_aes_dm_leaf_circuit(voleith_gf8_circuit_t *c,
                              const gf8_wire_id *leaf_data,
                              size_t leaf_data_bytes, gf8_wire_id *out_node)
{
    nh_aes_dm_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 0);
}

static void
node_hash_aes_dm_inode_circuit(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *left,
                               const gf8_wire_id *right, gf8_wire_id *out_node)
{
    nh_aes_dm_inode_circuit(c, left, right, out_node, 0);
}

static int
node_hash_aes_dm_leaf_build_witness(const uint8_t *leaf_data,
                                    size_t leaf_data_bytes, uint8_t *inv_out)
{
    return nh_aes_dm_leaf_build_witness(leaf_data, leaf_data_bytes, inv_out, 0);
}

static int
node_hash_aes_dm_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                     uint8_t *inv_out)
{
    return nh_aes_dm_inode_build_witness(left, right, inv_out, 0);
}

static int
node_hash_aes_dm_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                           uint8_t *out)
{
    return nh_aes_dm_leaf_hash(leaf_data, leaf_data_bytes, out);
}

static int
node_hash_aes_dm_inode_hash(const uint8_t *left, const uint8_t *right,
                            uint8_t *out)
{
    return nh_aes_dm_inode_hash(left, right, out);
}

/* ================================================================
 * AES-128-CMAC (norm = 0 wrappers)
 * ================================================================ */

static size_t
node_hash_aes_cmac128_leaf_invin_bytes(size_t leaf_data_bytes)
{
    return nh_aes_cmac128_leaf_invin_bytes(leaf_data_bytes, 0);
}

static size_t
node_hash_aes_cmac128_inode_invin_bytes(void)
{
    return nh_aes_cmac128_inode_invin_bytes(0);
}

static void
node_hash_aes_cmac128_leaf_circuit(voleith_gf8_circuit_t *c,
                                   const gf8_wire_id *leaf_data,
                                   size_t leaf_data_bytes,
                                   gf8_wire_id *out_node)
{
    nh_aes_cmac128_leaf_circuit(c, leaf_data, leaf_data_bytes, out_node, 0);
}

static void
node_hash_aes_cmac128_inode_circuit(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *left,
                                    const gf8_wire_id *right,
                                    gf8_wire_id *out_node)
{
    nh_aes_cmac128_inode_circuit(c, left, right, out_node, 0);
}

static int
node_hash_aes_cmac128_leaf_build_witness(const uint8_t *leaf_data,
                                         size_t leaf_data_bytes,
                                         uint8_t *inv_out)
{
    return nh_aes_cmac128_leaf_build_witness(leaf_data, leaf_data_bytes,
                                             inv_out, 0);
}

static int
node_hash_aes_cmac128_inode_build_witness(const uint8_t *left,
                                          const uint8_t *right,
                                          uint8_t *inv_out)
{
    return nh_aes_cmac128_inode_build_witness(left, right, inv_out, 0);
}

static int
node_hash_aes_cmac128_leaf_hash(const uint8_t *leaf_data,
                                size_t leaf_data_bytes, uint8_t *out)
{
    return nh_aes_cmac128_leaf_hash(leaf_data, leaf_data_bytes, out);
}

static int
node_hash_aes_cmac128_inode_hash(const uint8_t *left, const uint8_t *right,
                                 uint8_t *out)
{
    return nh_aes_cmac128_inode_hash(left, right, out);
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
