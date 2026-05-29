/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_grostl_gf8_circuit.h - Wide-node Merkle path verification using
 * Grøstl as the GF(2⁸) element-level compression function.
 *
 * Companion to merkle_gf8_circuit.h.  That circuit uses 128-bit
 * (16-byte) nodes hashed with AES-DM or AES-CMAC, giving 2⁶⁴ collision
 * resistance (birthday bound on a 128-bit node) - a cheap, compact tree.
 * This circuit uses wider nodes hashed with Grøstl, giving the full
 * collision resistance of the digest:
 *
 *   VOLEITH_MERKLE_GROSTL_256     : 32-byte (256-bit) nodes, 2¹²⁸ CR.
 *   VOLEITH_MERKLE_GROSTL_256_T27 : 27-byte (216-bit) nodes, 2¹⁰⁸ CR.
 *   VOLEITH_MERKLE_GROSTL_512     : 64-byte (512-bit) nodes, 2²⁵⁶ CR.
 *   VOLEITH_MERKLE_GROSTL_512_T59 : 59-byte (472-bit) nodes, 2²³⁶ CR.
 *
 * Pick the AES-DM/CMAC tree (merkle_gf8_circuit.h) when 2⁶⁴ CR is
 * acceptable and proof size matters; pick this one when you need
 * 128-bit (or more) collision resistance.
 *
 * The _T27 variant is the same Grøstl-256 hash truncated to its first 27
 * output bytes (216 bits).  27 bytes is the largest node size whose inode
 * input (1 + 2·27 = 55 bytes + ≥9 Grøstl padding = 64) still fits in a
 * single Grøstl block, so each inode costs ONE compression instead of two
 * - a ~40% mul-gate saving over the full 32-byte variant, at 2¹⁰⁸ instead
 * of 2¹²⁸ CR.  Truncation soundness is the standard SHA-512/t pattern: a
 * collision-resistant hash truncated to t bits has min(orig, 2^(t/2)) CR.
 * 2¹⁰⁸ is far beyond any feasible adversary; the only cost is that it does
 * not "match" a clean 128-bit security label.
 *
 * _T59 is the same idea one tier up: Grøstl-512 truncated to its first 59
 * output bytes (472 bits).  59 bytes is the largest node whose inode input
 * (1 + 2·59 = 119 bytes + ≥9 padding = 128) still fits a single 128-byte
 * Grøstl-512 block, so each inode costs ONE compression (5,376 S-boxes)
 * instead of the full Grøstl-512's two (8,960), at 2²³⁶ instead of 2²⁵⁶ CR.
 * Within single-block Grøstl-512 the compression S-box count is fixed
 * regardless of fill, so 59 maximises collision resistance at no extra
 * proof cost.  Use a Grøstl-512 variant only when more than 2¹²⁸ CR is
 * required (Grøstl-256's 32-byte output caps at 2¹²⁸).
 *
 * Domain separation (RFC 6962 style): a single prefix byte is prepended
 * to the hashed message, 0x00 for leaves and 0x01 for internal nodes,
 * preventing leaf/node confusion (second-preimage) attacks.  The prefix
 * byte is a constant circuit wire, so it is enforced - not prover-chosen.
 *
 *   leaf_hash = Grøstl(0x00 ‖ leaf_data)
 *   inode     = Grøstl(0x01 ‖ L ‖ R)
 *
 * Direction bits (path_dirs) come in two forms, mirroring
 * merkle_gf8_circuit.h.  The public-dir circuit takes plain uint8_t
 * values (0 or 1) resolved at circuit-build time - zero mul-gate cost,
 * correct when the leaf index is public.  The secret-dir circuit
 * (merkle_grostl_gf8_path_circuit_secret_dir) takes gf8_wire_id witness
 * wires and muxes each node byte (node_bytes mul gates per level),
 * hiding the leaf index - required for anonymous-credential and
 * ring-signature trees, which is also the setting whose
 * adversary-chooses-leaves threat model motivates the wide Grøstl node
 * in the first place.
 *
 * Direction convention (same as merkle_gf8_circuit.h):
 *   path_dirs[i] = 0: accumulated hash is the LEFT  child → inode(current, sibling)
 *   path_dirs[i] = 1: accumulated hash is the RIGHT child → inode(sibling, current)
 *   path_dirs[0]        = leaf level; path_dirs[depth-1] = below root.
 *   For leaf index j: path_dirs[k] = bit k of j (LSB first).
 *
 * Mul-gate cost (= one VOLE slot per Grøstl S-box).  With the 1-byte
 * domain prefix, an inode hashes 1 + 2·node_bytes message bytes:
 *
 *   GROSTL_256     inode: 1 + 64  = 65  bytes → 2 compressions → 2·1280 + 640  = 3,200 / level
 *   GROSTL_256_T27 inode: 1 + 54  = 55  bytes → 1 compression  → 1·1280 + 640  = 1,920 / level
 *   GROSTL_512     inode: 1 + 128 = 129 bytes → 2 compressions → 2·3584 + 1792 = 8,960 / level
 *   GROSTL_512_T59 inode: 1 + 118 = 119 bytes → 1 compression  → 1·3584 + 1792 = 5,376 / level
 *
 * Leaf-hash cost depends on leaf_data length; see
 * merkle_grostl_gf8_leaf_invin_bytes().
 */

#ifndef VOLEITH_MERKLE_GROSTL_GF8_CIRCUIT_H
#define VOLEITH_MERKLE_GROSTL_GF8_CIRCUIT_H

#include "../proof/gf8_circuit.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    VOLEITH_MERKLE_GROSTL_256 =
        0, /* 32-byte nodes, 2¹²⁸ CR, 2-block inode (3,200) */
    VOLEITH_MERKLE_GROSTL_256_T27 =
        1, /* 27-byte nodes (Grøstl-256 trunc), 2¹⁰⁸ CR, 1-block inode (1,920) */
    VOLEITH_MERKLE_GROSTL_512 =
        2, /* 64-byte nodes, 2²⁵⁶ CR, 2-block inode (8,960) */
    VOLEITH_MERKLE_GROSTL_512_T59 =
        3 /* 59-byte nodes (Grøstl-512 trunc), 2²³⁶ CR, 1-block inode (5,376) */
} voleith_merkle_grostl_variant_t;

/*
 * Node size in bytes for a variant: 32 (GROSTL_256), 27 (GROSTL_256_T27),
 * 64 (GROSTL_512), or 59 (GROSTL_512_T59).
 */
size_t merkle_grostl_node_bytes(voleith_merkle_grostl_variant_t variant);

/* ================================================================
 * Circuit builders
 * ================================================================ */

/*
 * merkle_grostl_gf8_leaf_hash_circuit - hash raw leaf data to a node-sized
 * leaf hash via Grøstl(0x00 ‖ leaf_data).
 *
 * c               - circuit to append to
 * leaf_data       - leaf_data_bytes wire IDs for raw leaf bytes; may be
 *                   NULL when leaf_data_bytes == 0
 * leaf_data_bytes - byte length of leaf data
 * variant         - GROSTL_256 (32-byte hash) or GROSTL_512 (64-byte hash)
 * leaf_hash       - output: merkle_grostl_node_bytes(variant) wire IDs
 *
 * Adds the Grøstl S-box inv_in witnesses internally.  The caller must
 * declare its leaf_data witness wires BEFORE calling this function.
 */
void merkle_grostl_gf8_leaf_hash_circuit(
    voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,
    size_t leaf_data_bytes, voleith_merkle_grostl_variant_t variant,
    gf8_wire_id *leaf_hash);

/*
 * merkle_grostl_gf8_path_circuit - verify a Merkle authentication path.
 *
 * Computes the root from a pre-hashed leaf and the sibling hashes along
 * the path.  inode(L, R) = Grøstl(0x01 ‖ L ‖ R).  The caller should
 * assert the node_bytes root wires equal the known public root instance
 * wires.
 *
 * c          - circuit to append to
 * leaf_hash  - node_bytes wire IDs for the pre-hashed leaf
 * path_nodes - depth × node_bytes wire IDs for sibling hashes, leaf-level first
 * path_dirs  - depth plain 0/1 values (not wire IDs); zero mul-gate cost
 * depth      - number of levels from leaf hash to root
 * variant    - must match what was used for leaf_hash
 * root       - output: node_bytes wire IDs for the computed root
 */
void merkle_grostl_gf8_path_circuit(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *leaf_hash,
                                    const gf8_wire_id *path_nodes,
                                    const uint8_t *path_dirs, size_t depth,
                                    voleith_merkle_grostl_variant_t variant,
                                    gf8_wire_id *root);

/*
 * merkle_grostl_gf8_path_circuit_secret_dir - verify a Merkle path with
 * private direction bits (hidden leaf index).
 *
 * Same as merkle_grostl_gf8_path_circuit, but path_dirs is an array of
 * gf8_wire_id (one per level), each a private witness carrying 0x00
 * (accumulated hash is the LEFT child) or 0x01 (RIGHT child).  Use this
 * when the leaf index must stay hidden - ring signatures and the Signal
 * KVAC anonymous credential, where the position would deanonymize the
 * member.
 *
 * Each level muxes the two child orderings per node byte, costing
 * node_bytes mul gates per level (one voleith_gf8_add_mux per byte).
 * The direction wire is constrained to {0, 1} inside the circuit via a
 * free assert_product(dir, dir, dir); booleanity is never left to the
 * caller, because an unconstrained mux selector is a silent soundness
 * break (the prover could blend the orderings and forge a path).
 *
 * c          - circuit to append to
 * leaf_hash  - node_bytes wire IDs for the pre-hashed leaf
 * path_nodes - depth × node_bytes wire IDs for sibling hashes, leaf-level first
 * path_dirs  - depth gf8_wire_id, each 0x00 or 0x01 (private leaf index bits)
 * depth      - number of levels from leaf hash to root
 * variant    - must match what was used for leaf_hash
 * root       - output: node_bytes wire IDs for the computed root
 */
void merkle_grostl_gf8_path_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_hash,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root);

/* ================================================================
 * Witness sizing and builders
 *
 * The Merkle witness is assembled by the caller in the same order the
 * circuit declares wires (see example_merkle_grostl_gf8.c):
 *
 *   [leaf_data]                                  caller's leaf bytes
 *   [leaf-hash inv_in]                           merkle_grostl_gf8_leaf_build_witness
 *   [all siblings, depth × node_bytes]           caller's sibling bytes
 *   [level 0 inode inv_in]                       merkle_grostl_gf8_inode_build_witness
 *   [level 1 inode inv_in]
 *   ...
 *
 * The *_invin_bytes() helpers give the inv_in section sizes; the
 * *_build_witness() helpers fill them.
 * ================================================================ */

/*
 * Number of leaf-hash inv_in witness bytes (Grøstl S-box count for
 * hashing 0x00 ‖ leaf_data).
 */
size_t
merkle_grostl_gf8_leaf_invin_bytes(size_t leaf_data_bytes,
                                   voleith_merkle_grostl_variant_t variant);

/*
 * Number of per-level inode inv_in witness bytes (Grøstl S-box count for
 * hashing 0x01 ‖ L ‖ R).  Constant per variant.
 */
size_t
merkle_grostl_gf8_inode_invin_bytes(voleith_merkle_grostl_variant_t variant);

/*
 * Fill the leaf-hash inv_in section.
 *
 * leaf_data       - leaf bytes (NULL allowed when leaf_data_bytes == 0)
 * leaf_data_bytes - byte length
 * variant         - GROSTL_256 or GROSTL_512
 * inv_out         - output buffer of merkle_grostl_gf8_leaf_invin_bytes()
 *                   bytes
 */
void merkle_grostl_gf8_leaf_build_witness(
    const uint8_t *leaf_data, size_t leaf_data_bytes,
    voleith_merkle_grostl_variant_t variant, uint8_t *inv_out);

/*
 * Fill one level's inode inv_in section for inode(left, right).
 *
 * left, right - node_bytes each
 * variant     - GROSTL_256 or GROSTL_512
 * inv_out     - output buffer of merkle_grostl_gf8_inode_invin_bytes() bytes
 */
void
merkle_grostl_gf8_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                      voleith_merkle_grostl_variant_t variant,
                                      uint8_t *inv_out);

/* ================================================================
 * Software hash helpers (for out-of-circuit tree construction)
 * ================================================================ */

/*
 * leaf_hash = Grøstl(0x00 ‖ leaf_data).  out is node_bytes long.
 */
void merkle_grostl_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                             voleith_merkle_grostl_variant_t variant,
                             uint8_t *out);

/*
 * inode = Grøstl(0x01 ‖ left ‖ right).  left/right/out are node_bytes long.
 */
void merkle_grostl_inode_hash(const uint8_t *left, const uint8_t *right,
                              voleith_merkle_grostl_variant_t variant,
                              uint8_t *out);

#endif /* VOLEITH_MERKLE_GROSTL_GF8_CIRCUIT_H */
