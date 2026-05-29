/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * merkle_grostl_gf8_circuit.c - Wide-node Merkle path verification using
 * Grøstl as the GF(2⁸) compression function.
 *
 * Domain separation (RFC 6962 style): a single prefix byte is prepended
 * to the hashed message - 0x00 for leaves, 0x01 for internal nodes.  The
 * prefix is a constant circuit wire, so it is enforced, not prover-chosen.
 *
 *   leaf_hash = Grøstl(0x00 ‖ leaf_data)
 *   inode     = Grøstl(0x01 ‖ L ‖ R)
 *
 * SubBytes inv_in witnesses are added inside grostl{256,512}_gf8_circuit;
 * the inv_in section of the Merkle witness is identical to the tail of
 * grostl{256,512}_gf8_build_witness (which is itself NIST-KAT-validated),
 * minus the leading message bytes - the domain prefix is a constant wire
 * here, not a witness slot, but it does not change the S-box trace.
 */

#include "merkle_grostl_gf8_circuit.h"
#include "../core/grostl.h"
#include "../core/util.h"
#include "grostl_gf8_circuit.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LEAF_DOMAIN_BYTE 0x00
#define INODE_DOMAIN_BYTE 0x01

/* node_bytes for the widest variant; sizes a stack buffer for the inode
 * message (1 domain byte + 2 nodes). */
#define MAX_NODE_BYTES 64
#define MAX_INODE_MSG_BYTES (1 + 2 * MAX_NODE_BYTES)

size_t
merkle_grostl_node_bytes(voleith_merkle_grostl_variant_t variant)
{
    switch (variant) {
    case VOLEITH_MERKLE_GROSTL_512:
        return 64u;
    case VOLEITH_MERKLE_GROSTL_512_T59:
        return 59u;
    case VOLEITH_MERKLE_GROSTL_256_T27:
        return 27u;
    default:
        return 32u;
    }
}

/* ================================================================
 * Variant dispatch for the Grøstl circuit / witness primitives.
 * ================================================================ */

/*
 * True for the Grøstl-512-based variants (the full 64-byte hash and the
 * _T59 truncation); false for the Grøstl-256-based ones (full and _T27).
 * Selects which underlying hash drives the circuit, witness, and software
 * paths; node-size truncation is handled separately by
 * merkle_grostl_node_bytes.
 */
static int
grostl_uses_512(voleith_merkle_grostl_variant_t variant)
{
    return variant == VOLEITH_MERKLE_GROSTL_512 ||
           variant == VOLEITH_MERKLE_GROSTL_512_T59;
}

/* Emits the Grøstl hash wires for the variant's underlying hash, then
 * keeps the first node_bytes wires (truncation for the _T27 / _T59
 * variants; a no-op for the full 32/64-byte variants). */
static void
grostl_hash_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                    size_t msg_bytes, voleith_merkle_grostl_variant_t variant,
                    gf8_wire_id *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    if (grostl_uses_512(variant)) {
        gf8_wire_id full[64];
        grostl512_gf8_circuit(c, msg, msg_bytes, full);
        for (size_t i = 0; i < nb; i++)
            out[i] = full[i];
    } else {
        gf8_wire_id full[32];
        grostl256_gf8_circuit(c, msg, msg_bytes, full);
        for (size_t i = 0; i < nb; i++)
            out[i] = full[i];
    }
}

static size_t
grostl_witness_bytes(size_t msg_bytes, voleith_merkle_grostl_variant_t variant)
{
    return (grostl_uses_512(variant)) ? grostl512_gf8_witness_bytes(msg_bytes)
                                      : grostl256_gf8_witness_bytes(msg_bytes);
}

static void
grostl_build_witness(const uint8_t *msg, size_t msg_bytes,
                     voleith_merkle_grostl_variant_t variant, uint8_t *witness)
{
    if (grostl_uses_512(variant))
        grostl512_gf8_build_witness(msg, msg_bytes, witness);
    else
        grostl256_gf8_build_witness(msg, msg_bytes, witness);
}

static void
grostl_hash_sw(const uint8_t *msg, size_t msg_bytes,
               voleith_merkle_grostl_variant_t variant, uint8_t *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    if (grostl_uses_512(variant)) {
        uint8_t full[64];
        voleith_grostl512(full, msg, msg_bytes);
        memcpy(out, full, nb);
        voleith_secure_zero(full, sizeof(full));
    } else {
        uint8_t full[32];
        voleith_grostl256(full, msg, msg_bytes);
        memcpy(out, full, nb);
        voleith_secure_zero(full, sizeof(full));
    }
}

/* Compute the inv_in section for Grøstl(msg) - the build_witness output
 * with the leading msg_bytes message bytes stripped. */
static void
grostl_invin(const uint8_t *msg, size_t msg_bytes,
             voleith_merkle_grostl_variant_t variant, uint8_t *inv_out)
{
    size_t wb = grostl_witness_bytes(msg_bytes, variant);
    uint8_t *tmp = (uint8_t *)malloc(wb);
    if (!tmp)
        return;
    grostl_build_witness(msg, msg_bytes, variant, tmp);
    memcpy(inv_out, tmp + msg_bytes, wb - msg_bytes);
    voleith_secure_zero(tmp, wb);
    free(tmp);
}

/* ================================================================
 * Inode compression at the wire level: Grøstl(0x01 ‖ L ‖ R).
 * ================================================================ */

static void
inode_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
              const gf8_wire_id *right, voleith_merkle_grostl_variant_t variant,
              gf8_wire_id *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    gf8_wire_id msg[MAX_INODE_MSG_BYTES];

    msg[0] = voleith_gf8_add_const(c, INODE_DOMAIN_BYTE);
    for (size_t i = 0; i < nb; i++)
        msg[1 + i] = left[i];
    for (size_t i = 0; i < nb; i++)
        msg[1 + nb + i] = right[i];

    grostl_hash_circuit(c, msg, 1 + 2 * nb, variant, out);
}

/* ================================================================
 * Public API: circuit builders
 * ================================================================ */

void
merkle_grostl_gf8_leaf_hash_circuit(voleith_gf8_circuit_t *c,
                                    const gf8_wire_id *leaf_data,
                                    size_t leaf_data_bytes,
                                    voleith_merkle_grostl_variant_t variant,
                                    gf8_wire_id *leaf_hash)
{
    size_t msg_bytes = 1 + leaf_data_bytes;
    gf8_wire_id *msg = (gf8_wire_id *)malloc(msg_bytes * sizeof(gf8_wire_id));
    if (!msg)
        return;

    msg[0] = voleith_gf8_add_const(c, LEAF_DOMAIN_BYTE);
    for (size_t i = 0; i < leaf_data_bytes; i++)
        msg[1 + i] = leaf_data[i];

    grostl_hash_circuit(c, msg, msg_bytes, variant, leaf_hash);
    free(msg);
}

void
merkle_grostl_gf8_path_circuit(voleith_gf8_circuit_t *c,
                               const gf8_wire_id *leaf_hash,
                               const gf8_wire_id *path_nodes,
                               const uint8_t *path_dirs, size_t depth,
                               voleith_merkle_grostl_variant_t variant,
                               gf8_wire_id *root)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    gf8_wire_id current[MAX_NODE_BYTES];
    for (size_t i = 0; i < nb; i++)
        current[i] = leaf_hash[i];

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * nb;
        const gf8_wire_id *left = path_dirs[level] ? sibling : current;
        const gf8_wire_id *right = path_dirs[level] ? current : sibling;

        gf8_wire_id next[MAX_NODE_BYTES];
        inode_circuit(c, left, right, variant, next);
        for (size_t i = 0; i < nb; i++)
            current[i] = next[i];
    }

    for (size_t i = 0; i < nb; i++)
        root[i] = current[i];
}

/* ================================================================
 * Secret direction bit (private leaf index): per-byte mux into the
 * Grøstl inode.
 *
 * dir is a gf8_wire_id carrying 0x00 (accumulated hash is the left
 * child) or 0x01 (right child).
 *
 *   left[i]  = mux(current[i], sibling[i], dir)        - 1 mul gate
 *   right[i] = left[i] XOR current[i] XOR sibling[i]   - free
 *
 * Total: node_bytes mul gates per level.  Booleanity of dir is enforced
 * here, not by the caller: add_mux does not constrain its selector, and
 * an unconstrained dir lets the prover blend the two child orderings
 * into an arbitrary affine interpolation, unbinding the path from any
 * discrete tree position.  dir == dir * dir holds only for dir in
 * {0, 1} in GF(2^8), and the check is free (no mul-slot, no witness).
 * ================================================================ */

static void
inode_circuit_secret_dir(voleith_gf8_circuit_t *c, const gf8_wire_id *current,
                         const gf8_wire_id *sibling, gf8_wire_id dir,
                         voleith_merkle_grostl_variant_t variant,
                         gf8_wire_id *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    gf8_wire_id left[MAX_NODE_BYTES], right[MAX_NODE_BYTES];

    voleith_gf8_assert_product(c, dir, dir, dir);

    for (size_t i = 0; i < nb; i++) {
        gf8_wire_id cs = voleith_gf8_add_xor(c, current[i], sibling[i]);
        left[i] = voleith_gf8_add_mux(c, current[i], sibling[i], dir);
        right[i] = voleith_gf8_add_xor(c, left[i], cs);
    }

    inode_circuit(c, left, right, variant, out);
}

void
merkle_grostl_gf8_path_circuit_secret_dir(
    voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_hash,
    const gf8_wire_id *path_nodes, const gf8_wire_id *path_dirs, size_t depth,
    voleith_merkle_grostl_variant_t variant, gf8_wire_id *root)
{
    size_t nb = merkle_grostl_node_bytes(variant);

    gf8_wire_id current[MAX_NODE_BYTES];
    for (size_t i = 0; i < nb; i++)
        current[i] = leaf_hash[i];

    for (size_t level = 0; level < depth; level++) {
        const gf8_wire_id *sibling = path_nodes + level * nb;

        gf8_wire_id next[MAX_NODE_BYTES];
        inode_circuit_secret_dir(c, current, sibling, path_dirs[level], variant,
                                 next);
        for (size_t i = 0; i < nb; i++)
            current[i] = next[i];
    }

    for (size_t i = 0; i < nb; i++)
        root[i] = current[i];
}

/* ================================================================
 * Witness sizing and builders
 * ================================================================ */

size_t
merkle_grostl_gf8_leaf_invin_bytes(size_t leaf_data_bytes,
                                   voleith_merkle_grostl_variant_t variant)
{
    size_t msg_bytes = 1 + leaf_data_bytes;
    return grostl_witness_bytes(msg_bytes, variant) - msg_bytes;
}

size_t
merkle_grostl_gf8_inode_invin_bytes(voleith_merkle_grostl_variant_t variant)
{
    size_t msg_bytes = 1 + 2 * merkle_grostl_node_bytes(variant);
    return grostl_witness_bytes(msg_bytes, variant) - msg_bytes;
}

void
merkle_grostl_gf8_leaf_build_witness(const uint8_t *leaf_data,
                                     size_t leaf_data_bytes,
                                     voleith_merkle_grostl_variant_t variant,
                                     uint8_t *inv_out)
{
    size_t msg_bytes = 1 + leaf_data_bytes;
    uint8_t *msg = (uint8_t *)malloc(msg_bytes);
    if (!msg)
        return;

    msg[0] = LEAF_DOMAIN_BYTE;
    if (leaf_data_bytes > 0)
        memcpy(msg + 1, leaf_data, leaf_data_bytes);

    grostl_invin(msg, msg_bytes, variant, inv_out);

    voleith_secure_zero(msg, msg_bytes);
    free(msg);
}

void
merkle_grostl_gf8_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                      voleith_merkle_grostl_variant_t variant,
                                      uint8_t *inv_out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    uint8_t msg[MAX_INODE_MSG_BYTES];

    msg[0] = INODE_DOMAIN_BYTE;
    memcpy(msg + 1, left, nb);
    memcpy(msg + 1 + nb, right, nb);

    grostl_invin(msg, 1 + 2 * nb, variant, inv_out);

    voleith_secure_zero(msg, sizeof(msg));
}

/* ================================================================
 * Software hash helpers
 * ================================================================ */

void
merkle_grostl_leaf_hash(const uint8_t *leaf_data, size_t leaf_data_bytes,
                        voleith_merkle_grostl_variant_t variant, uint8_t *out)
{
    size_t msg_bytes = 1 + leaf_data_bytes;
    uint8_t *msg = (uint8_t *)malloc(msg_bytes);
    if (!msg)
        return;

    msg[0] = LEAF_DOMAIN_BYTE;
    if (leaf_data_bytes > 0)
        memcpy(msg + 1, leaf_data, leaf_data_bytes);

    grostl_hash_sw(msg, msg_bytes, variant, out);

    voleith_secure_zero(msg, msg_bytes);
    free(msg);
}

void
merkle_grostl_inode_hash(const uint8_t *left, const uint8_t *right,
                         voleith_merkle_grostl_variant_t variant, uint8_t *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    uint8_t msg[MAX_INODE_MSG_BYTES];

    msg[0] = INODE_DOMAIN_BYTE;
    memcpy(msg + 1, left, nb);
    memcpy(msg + 1 + nb, right, nb);

    grostl_hash_sw(msg, 1 + 2 * nb, variant, out);

    voleith_secure_zero(msg, sizeof(msg));
}
