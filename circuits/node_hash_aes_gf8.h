/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_aes_gf8.h - AES-DM and AES-128-CMAC node-hash vts.
 *
 * The vt instances themselves are declared in circuits/node_hash_vt.h
 * (the umbrella vt header).  This file exists as the implementation-
 * side anchor for the AES family and documents the construction
 * details that the umbrella header summarises briefly.
 *
 * Branch A of the merkle tree circuits hash-agnostic refactor
 * (docs/HASH_AGNOSTIC_MERKLE_DESIGN.md, docs/MERKLE_TREE_CIRCUITS_DESIGN.md):
 * purely additive - the existing fixed-hash circuits in
 * circuits/merkle_gf8_circuit.c remain in place unchanged and
 * continue to dispatch through their enum-based entry points.  The
 * vts here exist so future hash-agnostic Merkle / IMT / ring-signature
 * circuits can be parameterised on a single voleith_node_hash_vt *
 * without paying any proof-time cost (the vt is consumed at circuit-
 * build time only).
 *
 * AES-256-CMAC is intentionally NOT wrapped: strictly dominated by
 * AES-128-CMAC (same 2^64 collision resistance, ~1.4x the S-box cost).
 * The existing VOLEITH_MERKLE_HASH_AES256_CMAC enum value continues
 * to work through its existing fixed-hash entry point.  See
 * docs/HASH_AGNOSTIC_MERKLE_DESIGN.md section 6.
 *
 * Domain constants (must match circuits/merkle_gf8_circuit.c for
 * bit-exact gate-stream equivalence against the existing fixed-hash
 * entry, the load-bearing invariant of the Branch B equivalence
 * harness):
 *
 *   MERKLE_LEAF_DOMAIN  = "VOLEitH-Leaf\0\0\0\0"  (16 bytes)
 *   MERKLE_INODE_DOMAIN = "VOLEitH-Node\0\0\0\0"  (16 bytes)
 *
 * Per-call witness sizes:
 *
 *   AES-DM (node_bytes=16, cr_bits=64)
 *     leaf_invin_bytes(n) = dm_n_aes(n) * 200
 *       where dm_n_aes(n) = (n == 0 || n % 16 != 0) ? n/16 + 1 : n/16
 *     inode_invin_bytes() = 200  (one AES-128 call)
 *
 *   AES-128-CMAC (node_bytes=16, cr_bits=64)
 *     leaf_invin_bytes(n) = aes_cmac_gf8_n_aes_calls(n) * 200
 *     inode_invin_bytes() = aes_cmac_gf8_n_aes_calls(32) * 200 = 600
 */

#ifndef VOLEITH_NODE_HASH_AES_GF8_H
#define VOLEITH_NODE_HASH_AES_GF8_H

#include "node_hash_vt.h"

#endif /* VOLEITH_NODE_HASH_AES_GF8_H */
