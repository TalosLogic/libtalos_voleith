/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_indexed_merkle.c - ZK non-membership proof for indexed Merkle tree
 *                            (bit-level circuit)
 *
 * An indexed Merkle tree is a sorted Merkle tree where each leaf stores a
 * (value, next_value, next_index) record.  To prove T is NOT a member, the
 * prover reveals the adjacent leaf L where L.value < T < L.next_value.
 *
 * Statement: "T is not in the set; I know adjacent leaf (low, next, idx) and
 *             its Merkle path, and the path recomputes to root R"
 *
 * Public (instance): target T (8 bits = 1 byte) || root R (128 bits = 16 bytes)
 * Private (witness): low_value, low_next, next_index (3 x 8 bits) ||
 *                    path_nodes (2 x 128 bits) || path_dirs (2 bits)
 *
 * Tree: depth=2, 4 sorted leaves, DM hash.
 * Sorted set: {0x00, 0x10, 0x50, 0x80}.  Target T = 0x30.
 * Adjacent leaf (proving 0x10 < 0x30 < 0x50): leaf[1] = (0x10, 0x50, 0x02)
 * Leaf index 1 = binary 01: path_dirs[0]=1 (right child), path_dirs[1]=0 (left child)
 *
 * AND gate cost:
 *   Leaf hash (3-byte data, DM):  7,200
 *   Path (depth=2, DM):           2 x 7,328 = 14,656
 *   Ordering (2 comparisons, 8 bits each, 3 AND/bit): 48
 *   Total: 21,904
 * ell = 282 (witness bits) + 21,904 = 22,186
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "indexed_merkle_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t LEAF_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4c, 0x65, 0x61, 0x66,
                                     0x00, 0x00, 0x00, 0x00};
static const uint8_t NODE_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4e, 0x6f, 0x64, 0x65,
                                     0x00, 0x00, 0x00, 0x00};

static void
dm_compress(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    for (int i = 0; i < 16; i++)
        out[i] ^= pt[i];
}

/* DM leaf hash for a partial block (< 16 bytes), CMAC-style padding. */
static void
leaf_hash_dm_partial(const uint8_t *data, size_t len, uint8_t out[16])
{
    uint8_t padded[16] = {0};
    memcpy(padded, data, len);
    padded[len] = 0x80;
    dm_compress(LEAF_DOM, padded, out);
}

static void
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ NODE_DOM[i];
    dm_compress(L, P, out);
}

int
main(void)
{
    printf("=== Indexed Merkle non-membership ZK proof (bit-level) ===\n");
    printf("Statement: 0x30 is not in {0x00, 0x10, 0x50, 0x80}\n");
    printf("Tree: 4 leaves (depth 2), Davies-Meyer AES-128\n\n");

    /* ================================================================
     * Build 4-leaf depth-2 indexed Merkle tree.
     * Leaf records: (value, next_value, next_index) - each 1 byte field.
     * ================================================================ */
    /* leaf[0]=(0x00, 0x10, 0x01)  leaf[1]=(0x10, 0x50, 0x02)
       leaf[2]=(0x50, 0x80, 0x03)  leaf[3]=(0x80, 0x00, 0x00) */
    const uint8_t leaf_records[4][3] = {{0x00, 0x10, 0x01},
                                        {0x10, 0x50, 0x02},
                                        {0x50, 0x80, 0x03},
                                        {0x80, 0x00, 0x00}};

    uint8_t lh[4][16];
    for (int i = 0; i < 4; i++)
        leaf_hash_dm_partial(leaf_records[i], 3, lh[i]);

    uint8_t L1[2][16];
    for (int i = 0; i < 2; i++)
        inode_hash_dm(lh[2 * i], lh[2 * i + 1], L1[i]);

    uint8_t root[16];
    inode_hash_dm(L1[0], L1[1], root);

    /* Adjacent leaf = leaf[1]; index=1=0b01 */
    const uint8_t TARGET = 0x30;
    const uint8_t LOW_VALUE = 0x10;      /* leaf[1].value */
    const uint8_t LOW_NEXT = 0x50;       /* leaf[1].next_value */
    const uint8_t NEXT_INDEX = 0x02;     /* leaf[1].next_index */
    const uint8_t path_dirs[2] = {1, 0}; /* index 1 = 0b01 */

    /* ================================================================
     * Build circuit
     * ================================================================ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Target T: 8 public instance wires */
    wire_id target_wires[8];
    for (int i = 0; i < 8; i++)
        target_wires[i] = voleith_circuit_add_instance(c);

    /* Adjacent leaf fields: 8+8+8 private witness wires */
    wire_id low_val_wires[8], low_next_wires[8], next_idx_wires[8];
    for (int i = 0; i < 8; i++)
        low_val_wires[i] = voleith_circuit_add_witness(c);
    for (int i = 0; i < 8; i++)
        low_next_wires[i] = voleith_circuit_add_witness(c);
    for (int i = 0; i < 8; i++)
        next_idx_wires[i] = voleith_circuit_add_witness(c);

    /* Path nodes: depth*128 witness wires */
    wire_id node_wires[2 * 128];
    for (int i = 0; i < 2 * 128; i++)
        node_wires[i] = voleith_circuit_add_witness(c);

    /* Path direction bits: 2 witness wires */
    wire_id dir_wires[2];
    for (int i = 0; i < 2; i++)
        dir_wires[i] = voleith_circuit_add_witness(c);

    /* Indexed Merkle non-membership circuit */
    wire_id root_computed[128];
    indexed_merkle_nonmember_circuit(c, target_wires, 8, /* target: 8 bits */
                                     low_val_wires,      /* low_value */
                                     low_next_wires,     /* low_next */
                                     next_idx_wires, 8, /* next_index: 8 bits */
                                     node_wires,        /* path nodes */
                                     dir_wires,         /* path dirs */
                                     2,                 /* depth */
                                     VOLEITH_MERKLE_HASH_AES_DM, root_computed);

    /* Root: 128 public instance wires; assert equal */
    for (int i = 0; i < 128; i++) {
        wire_id root_inst = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, root_computed[i], root_inst);
    }

    size_t ell = voleith_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu\n", voleith_circuit_and_gate_count(c));
    printf("  Witness wires:   %zu\n", voleith_circuit_witness_count(c));
    printf("  Instance wires:  %zu (8 target + 128 root)\n",
           voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (36 bytes, ceil(282/8)):
     *   [0..0]:    low_value (8 bits)
     *   [1..1]:    low_next (8 bits)
     *   [2..2]:    next_index (8 bits)
     *   [3..34]:   path_nodes: lh[0] | L1[1] (32 bytes)
     *   bit 264:   path_dirs[0]=1
     *   bit 265:   path_dirs[1]=0
     * ================================================================ */
    uint8_t witness[36];
    memset(witness, 0, sizeof(witness));

    witness[0] = LOW_VALUE;
    witness[1] = LOW_NEXT;
    witness[2] = NEXT_INDEX;

    /* path_nodes: lh[0] (sibling of lh[1]), L1[1] (sibling of L1[0]) */
    memcpy(witness + 3, lh[0], 16);
    memcpy(witness + 3 + 16, L1[1], 16);

    /* path_dirs: 3 bytes (24 bits) after 3+32=35 bytes = bit 3*8+2*128 = 24+256 = 280
       Actually, witness_count before dirs = 8+8+8 + 256 = 280 bits = 35 bytes exactly.
       So path_dirs[0] is at bit 280, path_dirs[1] at bit 281. */
    size_t dir_base = 3u * 8u + 2u * 128u; /* 24 + 256 = 280 */
    for (int lvl = 0; lvl < 2; lvl++) {
        if (path_dirs[lvl]) {
            size_t bit = dir_base + (size_t)lvl;
            witness[bit / 8] |= (uint8_t)(1u << (bit % 8));
        }
    }

    /* Instance: target (1 byte) || root (16 bytes) */
    uint8_t instance[17];
    instance[0] = TARGET;
    memcpy(instance + 1, root, 16);

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    int rc = voleith_prove(&proof, params, c, witness, instance,
                           "example_indexed_merkle:T=0x30",
                           sizeof("example_indexed_merkle:T=0x30") - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove failed\n");
        voleith_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_verify(&proof, params, c, instance,
                        "example_indexed_merkle:T=0x30",
                        sizeof("example_indexed_merkle:T=0x30") - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
