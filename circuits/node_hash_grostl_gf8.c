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
