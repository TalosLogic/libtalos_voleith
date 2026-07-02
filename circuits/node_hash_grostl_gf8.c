/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_grostl_gf8.c - Grøstl vt implementations (4 variants).
 *
 * Branch A of the merkle tree circuits hash-agnostic refactor: wraps
 * the leaf/inode compressions already used by merkle_grostl_gf8_circuit.c
 * (Grøstl(0x00 || data) for leaves, Grøstl(0x01 || L || R) for inodes,
 * truncated to node_bytes for the _T27 / _T59 variants) behind the
 * voleith_node_hash_vt function-pointer interface.
 *
 * Bit-exact gate-stream equivalence with the existing variant-enum
 * entry point is intentional and is the load-bearing invariant the
 * Branch B equivalence harness will assert.
 *
 * Per-variant fan-out:
 *   leaf_*  slots delegate to the public merkle_grostl_gf8_*
 *           variant-parameterised helpers exposed by
 *           merkle_grostl_gf8_circuit.h.
 *   inode_* circuit replicates the (currently file-static) inode_circuit
 *           in merkle_grostl_gf8_circuit.c using the public
 *           grostl{256,512}_gf8_circuit primitives; build_witness and
 *           sw_hash slots delegate to the public merkle_grostl_gf8_*
 *           helpers.
 *
 * Replication (rather than exposing the static inode_circuit) keeps
 * merkle_grostl_gf8_circuit.c untouched.  The two paths are gate-stream
 * identical because they construct the same wire layout (0x01 || L || R
 * with the prefix as a constant wire) and call the same public Grøstl
 * primitives.
 */

#include "node_hash_grostl_gf8.h"
#include "merkle_grostl_gf8_circuit.h"
#include "grostl_gf8_circuit.h"
#include "../core/grostl.h"
#include "../core/util.h"
#include <stdint.h>
#include <stddef.h>

#define INODE_DOMAIN_BYTE 0x01

/* Widest variant: 64-byte Grøstl-512 nodes.  Bounds the inode-message
 * stack buffer (1 domain byte + 2 * node_bytes). */
#define GROSTL_MAX_NODE_BYTES 64
#define GROSTL_MAX_INODE_MSG_BYTES (1 + 2 * GROSTL_MAX_NODE_BYTES)

/* ================================================================
 * Shared inode-circuit emitter, parameterised by variant.
 *
 * Identical wire layout to inode_circuit in merkle_grostl_gf8_circuit.c:
 *   msg[0]            = const 0x01
 *   msg[1 .. nb]      = left node bytes
 *   msg[1+nb .. 2nb]  = right node bytes
 * Then Grøstl-{256,512}(msg) truncated to nb output bytes.
 * ================================================================ */

static void
grostl_inode_emit(voleith_gf8_circuit_t *c, const gf8_wire_id *left,
                  const gf8_wire_id *right,
                  voleith_merkle_grostl_variant_t variant, gf8_wire_id *out)
{
    size_t nb = merkle_grostl_node_bytes(variant);
    gf8_wire_id msg[GROSTL_MAX_INODE_MSG_BYTES];

    msg[0] = voleith_gf8_add_const(c, INODE_DOMAIN_BYTE);
    for (size_t i = 0; i < nb; i++)
        msg[1 + i] = left[i];
    for (size_t i = 0; i < nb; i++)
        msg[1 + nb + i] = right[i];

    int uses_512 = (variant == VOLEITH_MERKLE_GROSTL_512 ||
                    variant == VOLEITH_MERKLE_GROSTL_512_T59);
    if (uses_512) {
        gf8_wire_id full[64];
        grostl512_gf8_circuit(c, msg, 1 + 2 * nb, full);
        for (size_t i = 0; i < nb; i++)
            out[i] = full[i];
    } else {
        gf8_wire_id full[32];
        grostl256_gf8_circuit(c, msg, 1 + 2 * nb, full);
        for (size_t i = 0; i < nb; i++)
            out[i] = full[i];
    }
}

/* ================================================================
 * Per-variant vt slot wrappers.
 *
 * Each variant's vt closes over its voleith_merkle_grostl_variant_t
 * value through these thin static functions.  Macro-generated to keep
 * the 4 variants * 8 slots = 32 wrappers consistent.
 * ================================================================ */

#define VARIANT_WRAPPERS(SUFFIX, VARIANT)                                      \
    static size_t node_hash_grostl_##SUFFIX##_leaf_invin_bytes(                \
        size_t leaf_data_bytes)                                                \
    {                                                                          \
        return merkle_grostl_gf8_leaf_invin_bytes(leaf_data_bytes, VARIANT);   \
    }                                                                          \
    static size_t node_hash_grostl_##SUFFIX##_inode_invin_bytes(void)          \
    {                                                                          \
        return merkle_grostl_gf8_inode_invin_bytes(VARIANT);                   \
    }                                                                          \
    static void node_hash_grostl_##SUFFIX##_leaf_circuit(                      \
        voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,                \
        size_t leaf_data_bytes, gf8_wire_id *out_node)                         \
    {                                                                          \
        merkle_grostl_gf8_leaf_hash_circuit(c, leaf_data, leaf_data_bytes,     \
                                            VARIANT, out_node);                \
    }                                                                          \
    static void node_hash_grostl_##SUFFIX##_inode_circuit(                     \
        voleith_gf8_circuit_t *c, const gf8_wire_id *left,                     \
        const gf8_wire_id *right, gf8_wire_id *out_node)                       \
    {                                                                          \
        grostl_inode_emit(c, left, right, VARIANT, out_node);                  \
    }                                                                          \
    static int node_hash_grostl_##SUFFIX##_leaf_build_witness(                 \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *inv_out)    \
    {                                                                          \
        merkle_grostl_gf8_leaf_build_witness(leaf_data, leaf_data_bytes,       \
                                             VARIANT, inv_out);                \
        return 0;                                                              \
    }                                                                          \
    static int node_hash_grostl_##SUFFIX##_inode_build_witness(                \
        const uint8_t *left, const uint8_t *right, uint8_t *inv_out)           \
    {                                                                          \
        merkle_grostl_gf8_inode_build_witness(left, right, VARIANT, inv_out);  \
        return 0;                                                              \
    }                                                                          \
    static int node_hash_grostl_##SUFFIX##_leaf_hash(                          \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *out)        \
    {                                                                          \
        merkle_grostl_leaf_hash(leaf_data, leaf_data_bytes, VARIANT, out);     \
        return 0;                                                              \
    }                                                                          \
    static int node_hash_grostl_##SUFFIX##_inode_hash(                         \
        const uint8_t *left, const uint8_t *right, uint8_t *out)               \
    {                                                                          \
        merkle_grostl_inode_hash(left, right, VARIANT, out);                   \
        return 0;                                                              \
    }

VARIANT_WRAPPERS(256, VOLEITH_MERKLE_GROSTL_256)
VARIANT_WRAPPERS(256_t27, VOLEITH_MERKLE_GROSTL_256_T27)
VARIANT_WRAPPERS(512, VOLEITH_MERKLE_GROSTL_512)
VARIANT_WRAPPERS(512_t59, VOLEITH_MERKLE_GROSTL_512_T59)

#undef VARIANT_WRAPPERS

/* ================================================================
 * vt instances
 * ================================================================ */

/* Compile-time bound check: widest node here is 64-byte Grøstl-512.
 * See MERKLE_VT_MAX_NODE_BYTES in node_hash_vt.h. */
_Static_assert(64 <= MERKLE_VT_MAX_NODE_BYTES,
               "grostl node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

#define VT_INSTANCE(SUFFIX, NAME, NODE_BYTES, CR_BITS)                         \
    {                                                                          \
        .name = NAME, .node_bytes = NODE_BYTES, .cr_bits = CR_BITS,            \
        .leaf_invin_bytes = node_hash_grostl_##SUFFIX##_leaf_invin_bytes,      \
        .inode_invin_bytes = node_hash_grostl_##SUFFIX##_inode_invin_bytes,    \
        .leaf_circuit = node_hash_grostl_##SUFFIX##_leaf_circuit,              \
        .inode_circuit = node_hash_grostl_##SUFFIX##_inode_circuit,            \
        .leaf_build_witness = node_hash_grostl_##SUFFIX##_leaf_build_witness,  \
        .inode_build_witness =                                                 \
            node_hash_grostl_##SUFFIX##_inode_build_witness,                   \
        .leaf_hash = node_hash_grostl_##SUFFIX##_leaf_hash,                    \
        .inode_hash = node_hash_grostl_##SUFFIX##_inode_hash,                  \
    }

const voleith_node_hash_vt voleith_node_hash_grostl256 =
    VT_INSTANCE(256, "grostl-256", 32, 128);

const voleith_node_hash_vt voleith_node_hash_grostl256_t27 =
    VT_INSTANCE(256_t27, "grostl-256-t27", 27, 108);

const voleith_node_hash_vt voleith_node_hash_grostl512 =
    VT_INSTANCE(512, "grostl-512", 64, 256);

const voleith_node_hash_vt voleith_node_hash_grostl512_t59 =
    VT_INSTANCE(512_t59, "grostl-512-t59", 59, 236);

#undef VT_INSTANCE

/* ================================================================
 * Fixed-input single-compression Grøstl node-hash vts.
 *
 * H(L, R) = Omega(f(IV_inode, L ‖ R)) and
 * H_leaf(x) = Omega(f(IV_leaf, x ‖ 0-pad-to-block)): one Grøstl
 * compression of exactly one full-width block, no Merkle-Damgård
 * padding (the input is fixed-length, so the padding does no security
 * work; dropping it removes the second compression the existing
 * grostl256 / grostl512 vts pay).  Leaf and inode are domain-separated
 * by distinct chaining values IV_leaf / IV_inode, NOT by a 1-byte
 * in-message prefix; that keeps L ‖ R to exactly one block.  Reuses
 * the W0 node circuit / oracle in grostl_gf8_circuit.c + core/grostl.c.
 *
 * Cost: grostl256_fixed inode = 1,920 S-boxes (vs grostl256 3,200,
 * grostl256_t27 1,920); grostl512_fixed = 5,376 (vs grostl512 8,960,
 * grostl512_t59 5,376).  Both deliver FULL collision resistance
 * (2^128 / 2^256), dominating all four existing Grøstl vts.  See the
 * design note for the cost/CR table and security basis.
 * ================================================================ */

/* Domain-separation chaining values.  ASCII label zero-padded to the
 * full chaining-slot width (64 / 128 bytes), mirroring the Hirose
 * convention.  These are PERMANENT wire-format commitments: distinct
 * leaf vs inode (type-confusion safety) and distinct across the 256 /
 * 512 variants. */
static const uint8_t IV_LEAF_256[64] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '2', '5', '6', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f',
};
static const uint8_t IV_INODE_256[64] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '2', '5', '6', '-', 'F', 'i', 'x', 'e', 'd', '-', 'N', 'o', 'd', 'e',
};
static const uint8_t IV_LEAF_512[128] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '5', '1', '2', '-', 'F', 'i', 'x', 'e', 'd', '-', 'L', 'e', 'a', 'f',
};
static const uint8_t IV_INODE_512[128] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'G', 'r', 'o', 's', 't', 'l',
    '5', '1', '2', '-', 'F', 'i', 'x', 'e', 'd', '-', 'N', 'o', 'd', 'e',
};

/* Per-variant vt slot wrappers.  The leaf payload is node_bytes wide
 * (fixed_leaf_bytes); it is zero-padded to the 2*node_bytes block.  The
 * inode block is L ‖ R, filling the block exactly.  BITS = 256 or 512;
 * NODE_BYTES = 32 or 64. */
#define FIXED_WRAPPERS(BITS, NODE_BYTES)                                        \
    static size_t node_hash_grostl##BITS##_fixed_leaf_invin_bytes(              \
        size_t leaf_data_bytes)                                                 \
    {                                                                           \
        (void)leaf_data_bytes; /* fixed width: contract requires NODE_BYTES */  \
        return grostl##BITS##_gf8_node_invin_bytes();                           \
    }                                                                           \
    static size_t node_hash_grostl##BITS##_fixed_inode_invin_bytes(void)        \
    {                                                                           \
        return grostl##BITS##_gf8_node_invin_bytes();                           \
    }                                                                           \
    static void node_hash_grostl##BITS##_fixed_leaf_circuit(                    \
        voleith_gf8_circuit_t *c, const gf8_wire_id *leaf_data,                 \
        size_t leaf_data_bytes, gf8_wire_id *out_node)                          \
    {                                                                           \
        /* Leaf preimage sk || attrs occupies the low leaf_data_bytes of      \
         * the single-compression block; the remainder is zero-padded.  At    \
         * leaf_data_bytes == NODE_BYTES this is byte-identical to the V1      \
         * leaf (low half data, high half zero).  An over-capacity preimage   \
         * is clamped here only to bound the block buffer; the matching       \
         * leaf_hash / leaf_build_witness reject it, so no valid proof is      \
         * built over a truncated leaf. */ \
        gf8_wire_id block[2 * (NODE_BYTES)];                                    \
        size_t n = leaf_data_bytes < 2 * (NODE_BYTES) ? leaf_data_bytes         \
                                                      : 2 * (NODE_BYTES);       \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                           \
            block[i] = voleith_gf8_add_const(c, 0x00);                          \
        grostl##BITS##_gf8_node_circuit(c, IV_LEAF_##BITS, block, out_node);    \
    }                                                                           \
    static void node_hash_grostl##BITS##_fixed_inode_circuit(                   \
        voleith_gf8_circuit_t *c, const gf8_wire_id *left,                      \
        const gf8_wire_id *right, gf8_wire_id *out_node)                        \
    {                                                                           \
        gf8_wire_id block[2 * (NODE_BYTES)];                                    \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[i] = left[i];                                                 \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[(NODE_BYTES) + i] = right[i];                                 \
        grostl##BITS##_gf8_node_circuit(c, IV_INODE_##BITS, block, out_node);   \
    }                                                                           \
    static int node_hash_grostl##BITS##_fixed_leaf_build_witness(               \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *inv_out)     \
    {                                                                           \
        uint8_t block[2 * (NODE_BYTES)];                                        \
        size_t n = leaf_data_bytes;                                             \
        if (leaf_data_bytes > 2 * (NODE_BYTES))                                 \
            return -1;                                                          \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                           \
            block[i] = 0x00;                                                    \
        grostl##BITS##_gf8_node_build_witness(IV_LEAF_##BITS, block, inv_out);  \
        voleith_secure_zero(block, sizeof(block));                              \
        return 0;                                                               \
    }                                                                           \
    static int node_hash_grostl##BITS##_fixed_inode_build_witness(              \
        const uint8_t *left, const uint8_t *right, uint8_t *inv_out)            \
    {                                                                           \
        uint8_t block[2 * (NODE_BYTES)];                                        \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[i] = left[i];                                                 \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[(NODE_BYTES) + i] = right[i];                                 \
        grostl##BITS##_gf8_node_build_witness(IV_INODE_##BITS, block,           \
                                              inv_out);                         \
        voleith_secure_zero(block, sizeof(block));                              \
        return 0;                                                               \
    }                                                                           \
    static int node_hash_grostl##BITS##_fixed_leaf_hash(                        \
        const uint8_t *leaf_data, size_t leaf_data_bytes, uint8_t *out)         \
    {                                                                           \
        uint8_t block[2 * (NODE_BYTES)];                                        \
        size_t n = leaf_data_bytes;                                             \
        int rc;                                                                 \
        if (leaf_data_bytes > 2 * (NODE_BYTES))                                 \
            return -1;                                                          \
        for (size_t i = 0; i < n; i++)                                          \
            block[i] = leaf_data[i];                                            \
        for (size_t i = n; i < 2 * (NODE_BYTES); i++)                           \
            block[i] = 0x00;                                                    \
        rc = voleith_grostl##BITS##_compress_node(IV_LEAF_##BITS, block, out);  \
        voleith_secure_zero(block, sizeof(block));                              \
        return rc;                                                              \
    }                                                                           \
    static int node_hash_grostl##BITS##_fixed_inode_hash(                       \
        const uint8_t *left, const uint8_t *right, uint8_t *out)                \
    {                                                                           \
        uint8_t block[2 * (NODE_BYTES)];                                        \
        int rc;                                                                 \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[i] = left[i];                                                 \
        for (size_t i = 0; i < (NODE_BYTES); i++)                               \
            block[(NODE_BYTES) + i] = right[i];                                 \
        rc =                                                                    \
            voleith_grostl##BITS##_compress_node(IV_INODE_##BITS, block, out);  \
        voleith_secure_zero(block, sizeof(block));                              \
        return rc;                                                              \
    }

FIXED_WRAPPERS(256, 32)
FIXED_WRAPPERS(512, 64)

#undef FIXED_WRAPPERS

#define VT_FIXED_INSTANCE(BITS, NAME, NODE_BYTES, CR_BITS)                     \
    {                                                                          \
        .name = NAME, .node_bytes = NODE_BYTES, .cr_bits = CR_BITS,            \
        .fixed_leaf_bytes = NODE_BYTES, .leaf_block_bytes = 2 * (NODE_BYTES),  \
        .leaf_invin_bytes = node_hash_grostl##BITS##_fixed_leaf_invin_bytes,   \
        .inode_invin_bytes = node_hash_grostl##BITS##_fixed_inode_invin_bytes, \
        .leaf_circuit = node_hash_grostl##BITS##_fixed_leaf_circuit,           \
        .inode_circuit = node_hash_grostl##BITS##_fixed_inode_circuit,         \
        .leaf_build_witness =                                                  \
            node_hash_grostl##BITS##_fixed_leaf_build_witness,                 \
        .inode_build_witness =                                                 \
            node_hash_grostl##BITS##_fixed_inode_build_witness,                \
        .leaf_hash = node_hash_grostl##BITS##_fixed_leaf_hash,                 \
        .inode_hash = node_hash_grostl##BITS##_fixed_inode_hash,               \
    }

const voleith_node_hash_vt voleith_node_hash_grostl256_fixed =
    VT_FIXED_INSTANCE(256, "grostl-256-fixed", 32, 128);

const voleith_node_hash_vt voleith_node_hash_grostl512_fixed =
    VT_FIXED_INSTANCE(512, "grostl-512-fixed", 64, 256);

#undef VT_FIXED_INSTANCE
