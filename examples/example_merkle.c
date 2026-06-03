/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_merkle.c - ZK proof of Merkle path membership (bit-level circuit)
 *
 * Statement: "I know a leaf value and its siblings such that the Merkle path
 *             starting from leaf[5] in an 8-leaf tree recomputes to root R"
 *
 * Public (instance): root R (128 bits = 16 bytes)
 * Private (witness): leaf_data (16 bytes) || path_nodes (3 x 16 bytes) ||
 *                    path_dirs (3 bits)
 *
 * Tree: depth=3, 8 leaves.  Hash function: Davies-Meyer AES-128.
 * Leaf[i] data: 16 bytes all equal to i (0x00..0x07).
 * Leaf index 5 = binary 101:
 *   path_dirs[0]=1 (right child at leaf level)
 *   path_dirs[1]=0 (left child at level 1)
 *   path_dirs[2]=1 (right child at level 2)
 *
 * AND gate cost:
 *   Leaf hash (16-byte leaf, DM): 7,200
 *   Path (depth=3, DM):           3 x 7,328 = 21,984
 *   Total: 29,184
 * ell = 515 (witness bits) + 29,184 = 29,699
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "merkle_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Domain constants (must match merkle_circuit.c)
 * ================================================================ */
static const uint8_t LEAF_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4c, 0x65, 0x61, 0x66,
                                     0x00, 0x00, 0x00, 0x00};
static const uint8_t NODE_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4e, 0x6f, 0x64, 0x65,
                                     0x00, 0x00, 0x00, 0x00};

/* ================================================================
 * Software DM hash reference
 * ================================================================ */

static void
dm_compress(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    for (int i = 0; i < 16; i++)
        out[i] ^= pt[i];
}

/* DM leaf hash: Merkle-Damgård chain, IV = LEAF_DOM, CMAC-style padding.
   For a 16-byte leaf with no partial block: dm_compress(LEAF_DOM, leaf, out). */
static void
leaf_hash_dm(const uint8_t leaf[16], uint8_t out[16])
{
    dm_compress(LEAF_DOM, leaf, out);
}

/* DM inode hash: H(L, R) = AES_L(R XOR NODE_DOM) XOR (R XOR NODE_DOM) */
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
    printf("=== Merkle path ZK proof (bit-level DM circuit) ===\n");
    printf(
        "Statement: knowledge of leaf[5] and path s.t. Merkle path → root\n");
    printf("Tree: 8 leaves (depth 3), Davies-Meyer AES-128 hash\n\n");

    /* ================================================================
     * Build 8-leaf DM tree.  leaf[i] = {i,i,...,i} (16 bytes).
     * ================================================================ */
    uint8_t leaf[8][16];
    for (int i = 0; i < 8; i++)
        memset(leaf[i], i, 16);

    uint8_t lh[8][16];
    for (int i = 0; i < 8; i++)
        leaf_hash_dm(leaf[i], lh[i]);

    uint8_t L1[4][16];
    for (int i = 0; i < 4; i++)
        inode_hash_dm(lh[2 * i], lh[2 * i + 1], L1[i]);

    uint8_t L2[2][16];
    for (int i = 0; i < 2; i++)
        inode_hash_dm(L1[2 * i], L1[2 * i + 1], L2[i]);

    uint8_t root[16];
    inode_hash_dm(L2[0], L2[1], root);

    /* Path for leaf index 5 = 0b101 */
    const uint8_t path_dirs[3] = {1, 0, 1};
    /* path_nodes[0] = lh[4]  (left sibling of lh[5]) */
    /* path_nodes[1] = L1[3]  (right sibling of L1[2]) */
    /* path_nodes[2] = L2[0]  (left sibling of L2[1]) */

    /* ================================================================
     * Build circuit
     * ================================================================ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Leaf data: 128 witness wires */
    wire_id leaf_wires[128];
    for (int i = 0; i < 128; i++)
        leaf_wires[i] = voleith_circuit_add_witness(c);

    /* Leaf hash */
    wire_id leaf_hash_wires[128];
    merkle_leaf_hash_circuit(c, leaf_wires, 128, VOLEITH_MERKLE_HASH_AES_DM,
                             leaf_hash_wires);

    /* Path nodes: depth*128 witness wires */
    wire_id node_wires[3 * 128];
    for (int i = 0; i < 3 * 128; i++)
        node_wires[i] = voleith_circuit_add_witness(c);

    /* Path direction bits: 3 witness wires */
    wire_id dir_wires[3];
    for (int i = 0; i < 3; i++)
        dir_wires[i] = voleith_circuit_add_witness(c);

    /* Merkle path circuit */
    wire_id root_computed[128];
    merkle_path_circuit(c, leaf_hash_wires, node_wires, dir_wires, 3,
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
    printf("  Instance wires:  %zu (root)\n",
           voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness
     * Witness layout (bit-packed):
     *   [0..127]      leaf_data (16 bytes)
     *   [128..511]    path_nodes: lh[4] | L1[3] | L2[0]  (48 bytes)
     *   [512..514]    path_dirs (3 bits, LSB-first)
     * Total: 65 bytes (ceil(515/8))
     * ================================================================ */
    uint8_t witness[65];
    memset(witness, 0, sizeof(witness));

    /* Leaf data */
    memcpy(witness, leaf[5], 16);

    /* Path nodes */
    memcpy(witness + 16, lh[4], 16);
    memcpy(witness + 16 + 16, L1[3], 16);
    memcpy(witness + 16 + 32, L2[0], 16);

    /* Path direction bits at bit positions 512..514 */
    size_t dir_base = 128u + 3u * 128u; /* = 512 */
    for (int lvl = 0; lvl < 3; lvl++) {
        if (path_dirs[lvl]) {
            size_t bit = dir_base + (size_t)lvl;
            witness[bit / 8] |= (uint8_t)(1u << (bit % 8));
        }
    }

    /* Instance: root (16 bytes = 128 bits) */
    const uint8_t *instance = root;

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    int rc = voleith_prove_v2(&proof, params, c, witness,
                              voleith_circuit_witness_byte_len(c), instance,
                              voleith_circuit_instance_byte_len(c),
                              "example_merkle:depth3-DM-leaf5",
                              sizeof("example_merkle:depth3-DM-leaf5") - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove_v2 failed\n");
        voleith_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_verify_v2(&proof, params, c, instance,
                           voleith_circuit_instance_byte_len(c),
                           "example_merkle:depth3-DM-leaf5",
                           sizeof("example_merkle:depth3-DM-leaf5") - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
