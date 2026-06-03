/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_indexed_merkle_grostl_gf8.c - ZK non-membership proof for an
 * indexed Merkle tree whose internal nodes are Grøstl hashes
 * (GF(2^8) element circuit).
 *
 * Same statement as example_indexed_merkle_gf8.c, but the node hash is
 * the wide-pipe Grøstl-256 truncated to 27-byte nodes (the _T27 variant:
 * 2^108 collision resistance, single-block inodes) instead of 16-byte
 * AES-DM (2^64).  Use a Grøstl variant when an adversary can choose leaf
 * values: non-membership soundness then rests on the node hash's
 * collision resistance, and a 16-byte node's 2^64 birthday bound is
 * below the security level.  (Swap the VARIANT constant below for
 * VOLEITH_MERKLE_GROSTL_256 for the full 32-byte / 2^128 nodes, at a
 * larger proof.)
 *
 * Public  (instance): target T (1 byte) || root R (27 bytes)
 * Private (witness):   low_value, low_next, next_index (3 bytes) +
 *                      path siblings (depth x 27 bytes) +
 *                      Grøstl S-box inv_in for the leaf hash and each
 *                      inode (filled by the merkle_grostl witness helpers)
 *
 * Tree: depth=3, 8 sorted leaves (values 10,20,...,80), Grøstl-256 _T27
 * (27-byte) nodes.  Target T = 25, proven absent via the adjacent leaf
 * (value=20, next_value=30, next_index=2).  path_dirs are public uint8_t
 * (zero mul-gate cost); the comparison adds 2 x 8 x 3 = 48 mul gates.
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "indexed_merkle_grostl_gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEPTH 3
#define N_LEAVES 8

static const uint8_t LEAF_VALUE[N_LEAVES] = {10, 20, 30, 40, 50, 60, 70, 80};
static const uint8_t LEAF_NEXT[N_LEAVES] = {20, 30, 40, 50, 60, 70, 80, 255};
static const uint8_t LEAF_NEXT_IDX[N_LEAVES] = {1, 2, 3, 4, 5, 6, 7, 0};

int
main(void)
{
    const voleith_merkle_grostl_variant_t variant =
        VOLEITH_MERKLE_GROSTL_256_T27;
    const size_t nb = merkle_grostl_node_bytes(variant);

    printf("=== Indexed Merkle non-membership ZK proof "
           "(Grøstl-256 T27 nodes, GF(2^8)) ===\n");
    printf("Statement: 25 is not in {10,20,30,40,50,60,70,80}\n");
    printf("Tree: 8 leaves (depth 3), Grøstl-256 T27 nodes "
           "(27 bytes, 2^108 CR), public leaf index\n\n");

    /* ================================================================
     * Build the 8-leaf depth-3 indexed tree (software).
     * Leaf record = value || next_value || next_index (3 bytes).
     * Adjacent leaf for target 25 is leaf index 1 (value 20, next 30).
     * ================================================================ */
    const size_t leaf_index = 1;
    const uint8_t TARGET = 25;

    uint8_t lh[N_LEAVES][64];
    for (int i = 0; i < N_LEAVES; i++) {
        uint8_t d[3] = {LEAF_VALUE[i], LEAF_NEXT[i], LEAF_NEXT_IDX[i]};
        merkle_grostl_leaf_hash(d, 3, variant, lh[i]);
    }

    uint8_t l1[4][64], l2[2][64], root[64];
    for (int i = 0; i < 4; i++)
        merkle_grostl_inode_hash(lh[2 * i], lh[2 * i + 1], variant, l1[i]);
    for (int i = 0; i < 2; i++)
        merkle_grostl_inode_hash(l1[2 * i], l1[2 * i + 1], variant, l2[i]);
    merkle_grostl_inode_hash(l2[0], l2[1], variant, root);

    /* Sibling path for leaf index 1 = 0b001 (dirs LSB-first {1,0,0}). */
    uint8_t path_dirs[DEPTH];
    for (int k = 0; k < DEPTH; k++)
        path_dirs[k] = (uint8_t)((leaf_index >> k) & 1);

    uint8_t siblings[DEPTH * 64];
    memcpy(siblings + 0 * nb, lh[0], nb); /* sibling of leaf[1] */
    memcpy(siblings + 1 * nb, l1[1], nb); /* sibling of l1[0]   */
    memcpy(siblings + 2 * nb, l2[1], nb); /* sibling of l2[0]   */

    /* ================================================================
     * Build the circuit.
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id target_wire = voleith_gf8_add_instance(c);

    gf8_wire_id low_val_wire = voleith_gf8_add_witness(c);
    gf8_wire_id low_next_wire = voleith_gf8_add_witness(c);
    gf8_wire_id next_idx_wire = voleith_gf8_add_witness(c);

    gf8_wire_id *node_wires = malloc(DEPTH * nb * sizeof(*node_wires));
    for (size_t i = 0; i < DEPTH * nb; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_computed[64];
    if (indexed_merkle_grostl_gf8_nonmember_circuit(
            c, &target_wire, 1, &low_val_wire, &low_next_wire, &next_idx_wire,
            1, node_wires, path_dirs, DEPTH, variant, root_computed) != 0) {
        fprintf(stderr, "indexed_merkle_grostl_gf8_nonmember_circuit: leaf "
                        "data exceeds stack-VLA bound\n");
        free(node_wires);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    for (size_t i = 0; i < nb; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], ri);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (2 comparisons x 8 bits x 3)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (1 target + %zu root)\n",
           voleith_gf8_circuit_instance_count(c), nb);
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build the witness.
     * Layout (add_witness order):
     *   [low_value][low_next][next_index]
     *   [path siblings: DEPTH * nb]
     *   [leaf-hash inv_in][per-level inode inv_in]
     * ================================================================ */
    size_t leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(3, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);
    size_t witness_bytes = 3 + DEPTH * nb + leaf_invin + DEPTH * inode_invin;

    uint8_t *witness = calloc(witness_bytes, 1);
    uint8_t *wp = witness;

    *wp++ = LEAF_VALUE[leaf_index];
    *wp++ = LEAF_NEXT[leaf_index];
    *wp++ = LEAF_NEXT_IDX[leaf_index];

    memcpy(wp, siblings, DEPTH * nb);
    wp += DEPTH * nb;

    uint8_t leaf_data[3] = {LEAF_VALUE[leaf_index], LEAF_NEXT[leaf_index],
                            LEAF_NEXT_IDX[leaf_index]};
    merkle_grostl_gf8_leaf_build_witness(leaf_data, 3, variant, wp);
    wp += leaf_invin;

    uint8_t current[64];
    merkle_grostl_leaf_hash(leaf_data, 3, variant, current);
    for (size_t lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + lvl * nb;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_grostl_gf8_inode_build_witness(L, R, variant, wp);
        wp += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    if (memcmp(current, root, nb) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        free(witness);
        free(node_wires);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: target (1 byte) || root (nb bytes). */
    uint8_t *instance = malloc(1 + nb);
    instance[0] = TARGET;
    memcpy(instance + 1, root, nb);

    /* ================================================================
     * Prove and verify.
     * ================================================================ */
    static const char FS_SEED[] = "example_indexed_merkle_grostl_gf8:T=25";

    voleith_proof_t proof = {0};
    int rc = voleith_gf8_prove_v2(
        &proof, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
        instance, voleith_gf8_circuit_instance_byte_len(c), FS_SEED,
        sizeof(FS_SEED) - 1);
    free(witness);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        free(instance);
        free(node_wires);
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    rc = voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c),
                               FS_SEED, sizeof(FS_SEED) - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    free(instance);
    free(node_wires);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
