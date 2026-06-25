/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_grostl_gf8.h - Grøstl node-hash vts (4 variants).
 *
 * The vt instances themselves are declared in circuits/node_hash_vt.h
 * (the umbrella vt header).  This file exists as the implementation-
 * side anchor for the Grøstl family and documents the construction
 * details that the umbrella header summarises briefly.
 *
 * Branch A of the merkle tree circuits hash-agnostic refactor
 * (docs/HASH_AGNOSTIC_MERKLE_DESIGN.md, docs/MERKLE_TREE_CIRCUITS_DESIGN.md):
 * purely additive - the existing fixed-hash circuits in
 * circuits/merkle_grostl_gf8_circuit.c remain in place unchanged and
 * continue to dispatch through their variant-enum entry points.  The
 * vts here exist so future hash-agnostic Merkle / IMT / ring-signature
 * circuits can be parameterised on a single voleith_node_hash_vt *
 * without paying any proof-time cost (the vt is consumed at circuit-
 * build time only).
 *
 * Domain separation (RFC 6962 style; matches merkle_grostl_gf8_circuit.c
 * for bit-exact gate-stream equivalence):
 *
 *   leaf_hash = Grøstl(0x00 ‖ leaf_data)
 *   inode     = Grøstl(0x01 ‖ L ‖ R)
 *
 * The single domain byte is a constant circuit wire, so it is
 * enforced - not prover-chosen.
 *
 * Variant matrix:
 *
 *   vt                                node_bytes   cr_bits   inode S-boxes
 *   voleith_node_hash_grostl256             32        128         3200  (2 compressions)
 *   voleith_node_hash_grostl256_t27         27        108         1920  (1 compression)
 *   voleith_node_hash_grostl512             64        256         8960  (2 compressions)
 *   voleith_node_hash_grostl512_t59         59        236         5376  (1 compression)
 *   voleith_node_hash_grostl256_fixed       32        128         1920  (1 compression)
 *   voleith_node_hash_grostl512_fixed       64        256         5376  (1 compression)
 *
 * The _T27 and _T59 truncations land each inode in a single Grøstl
 * compression block (block sizes 64 and 128 bytes respectively; need
 * 9 padding bytes; so the max single-block inode message lengths are
 * 1 + 2*27 = 55 <= 64-9 and 1 + 2*59 = 119 <= 128-9), cutting the
 * per-inode S-box count roughly in half at the cost of 20 bits of
 * collision resistance.  Both remaining CR bounds (2^108, 2^236) sit
 * well above any practical adversary.
 *
 * DEPRECATED: the four variants above (grostl256, grostl256_t27,
 * grostl512, grostl512_t59) are superseded by the fixed-input variants
 * grostl256_fixed / grostl512_fixed, which deliver FULL collision
 * resistance (2^128 / 2^256) at the same single-compression cost as the
 * _T27 / _T59 truncations (1920 / 5376 inode S-boxes), by dropping the
 * Merkle-Damgaard padding and moving leaf/inode domain separation into
 * the IV instead of a prefix byte.  See node_hash_grostl_gf8.c and
 * docs/DESIGN.md "Grostl fixed-input node hashes".  The four older vts
 * are RETAINED as frozen wire-format commitments (existing proofs and
 * Shipshape selectors keep working) but are not recommended for new
 * circuits.
 */

#ifndef VOLEITH_NODE_HASH_GROSTL_GF8_H
#define VOLEITH_NODE_HASH_GROSTL_GF8_H

#include "node_hash_vt.h"

#endif /* VOLEITH_NODE_HASH_GROSTL_GF8_H */
