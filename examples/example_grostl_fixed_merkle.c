/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_grostl_fixed_merkle.c - ZK proof of Merkle path membership
 * using the fixed-input single-compression Grøstl-256 node-hash vt
 * (voleith_node_hash_grostl256_fixed) through the generic vt-driven
 * Merkle path circuit (circuits/merkle_vt_gf8_circuit).
 *
 * Counterpart to example_merkle_hirose_gf8.c (Hirose-AES-256, 32-byte
 * nodes, 2^128 CR) and example_merkle_grostl_gf8.c (the older full-hash
 * wide-node Grøstl variants).  The fixed-input construction is
 * H = Omega(f(IV, block)): one Grøstl compression of a single block
 * (no Merkle-Damgaard padding), leaf vs inode separated by distinct
 * chaining values IV.  That delivers FULL 2^128 collision resistance at
 * the same per-inode S-box cost as the truncated grostl256_t27 variant
 * (1,920 S-boxes), and 40% under the full-hash grostl256 (3,200):
 *
 *   AES-DM             : 16-byte nodes, 2^64  CR,   ~200 S-boxes / inode
 *   Hirose-AES-256     : 32-byte nodes, 2^128 CR, ~1,000 S-boxes / inode
 *   Grostl-256-fixed   : 32-byte nodes, 2^128 CR, ~1,920 S-boxes / inode (this)
 *   Grostl-256 (full)  : 32-byte nodes, 2^128 CR, ~3,200 S-boxes / inode
 *
 * Tree: depth 4 (16 leaves), 32-byte fixed leaf, 32-byte nodes
 * (2^128 CR), public leaf index.
 *
 * Public  (instance): root R (32 bytes)
 * Private (witness):  leaf data + sibling hashes along the path +
 *                     Grostl inv_in (leaf and inode).
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEPTH 4
#define N_LEAVES (1u << DEPTH) /* 16 */
#define NODE_BYTES 32          /* Grostl-256 fixed node width */
#define LEAF_DATA_BYTES 32     /* fixed leaf width == node width */
#define LEAF_INDEX 11          /* 0b1011 - a mixed-bit path */

int
main(void)
{
    const voleith_node_hash_vt *h = &voleith_node_hash_grostl256_fixed;

    printf(
        "=== Merkle path ZK proof (vt-driven, Grostl-256 fixed-input) ===\n");
    printf("Statement: knowledge of leaf[%u] and path s.t. Merkle path -> "
           "root\n",
           LEAF_INDEX);
    printf("Tree: %u leaves (depth %u), Grostl-256 fixed 32-byte nodes "
           "(2^128 CR), public index\n",
           N_LEAVES, DEPTH);
    printf("vt: %s (node_bytes=%zu, cr_bits=%zu)\n\n", h->name, h->node_bytes,
           h->cr_bits);

    /* ================================================================
     * Build the depth-4 tree in software via the vt's own hash slots.
     * ================================================================ */
    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (unsigned i = 0; i < N_LEAVES; i++)
        for (unsigned j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 7 + j);

    uint8_t *layer[DEPTH + 1];
    for (unsigned k = 0; k <= DEPTH; k++)
        layer[k] = malloc(((size_t)N_LEAVES >> k) * NODE_BYTES);

    for (unsigned i = 0; i < N_LEAVES; i++)
        h->leaf_hash(leaves[i], LEAF_DATA_BYTES,
                     layer[0] + (size_t)i * NODE_BYTES);

    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned n_parents = N_LEAVES >> (k + 1);
        for (unsigned j = 0; j < n_parents; j++)
            h->inode_hash(layer[k] + (size_t)(2 * j) * NODE_BYTES,
                          layer[k] + (size_t)(2 * j + 1) * NODE_BYTES,
                          layer[k + 1] + (size_t)j * NODE_BYTES);
    }

    const uint8_t *root = layer[DEPTH]; /* layer[DEPTH][0] */

    /* Sibling and direction at each path level for LEAF_INDEX. */
    uint8_t path_dirs[DEPTH];
    uint8_t siblings[DEPTH * NODE_BYTES];
    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned cur = LEAF_INDEX >> k;
        path_dirs[k] = (uint8_t)(cur & 1u);
        memcpy(siblings + (size_t)k * NODE_BYTES,
               layer[k] + (size_t)(cur ^ 1u) * NODE_BYTES, NODE_BYTES);
    }

    /* ================================================================
     * Build the circuit.  Declaration order fixes the witness layout:
     *   (1) leaf data wires,
     *   (2) sibling wires,
     *   (3) merkle_vt_gf8_path_circuit, which appends leaf inv_in then
     *       per-level inode inv_in internally.
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id leaf_wires[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *node_wires =
        malloc((size_t)DEPTH * NODE_BYTES * sizeof(*node_wires));
    for (size_t i = 0; i < (size_t)DEPTH * NODE_BYTES; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_computed[NODE_BYTES];
    if (merkle_vt_gf8_path_circuit(c, h, leaf_wires, LEAF_DATA_BYTES,
                                   node_wires, path_dirs, DEPTH,
                                   root_computed) != 0) {
        fprintf(stderr, "merkle_vt_gf8_path_circuit failed\n");
        return 1;
    }

    /* Root: NODE_BYTES public instance wires; assert equal. */
    for (int i = 0; i < NODE_BYTES; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t leaf_invin = h->leaf_invin_bytes(LEAF_DATA_BYTES);
    size_t inode_invin = h->inode_invin_bytes();

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (S-box uses assert_product, not add_mul)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("    = %d leaf + %u siblings + %zu leaf inv_in + %u x %zu inode "
           "inv_in\n",
           LEAF_DATA_BYTES, (unsigned)(DEPTH * NODE_BYTES), leaf_invin, DEPTH,
           inode_invin);
    printf("  Instance wires:  %zu (root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Assemble the witness in declaration order.  merkle_vt_gf8_path_circuit
     * calls h->leaf_circuit before walking the path, so leaf inv_in
     * precedes the per-level inode inv_in.
     *
     * Layout: leaf data | siblings | leaf inv_in | per-level inode inv_in
     * ================================================================ */
    size_t total = LEAF_DATA_BYTES + (size_t)DEPTH * NODE_BYTES + leaf_invin +
                   (size_t)DEPTH * inode_invin;
    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    memcpy(witness + off, leaves[LEAF_INDEX], LEAF_DATA_BYTES);
    off += LEAF_DATA_BYTES;

    memcpy(witness + off, siblings, (size_t)DEPTH * NODE_BYTES);
    off += (size_t)DEPTH * NODE_BYTES;

    h->leaf_build_witness(leaves[LEAF_INDEX], LEAF_DATA_BYTES, witness + off);
    off += leaf_invin;

    uint8_t current[NODE_BYTES];
    h->leaf_hash(leaves[LEAF_INDEX], LEAF_DATA_BYTES, current);
    for (unsigned lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + (size_t)lvl * NODE_BYTES;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        h->inode_build_witness(L, R, witness + off);
        off += inode_invin;

        uint8_t next[NODE_BYTES];
        h->inode_hash(L, R, next);
        memcpy(current, next, NODE_BYTES);
    }

    /* Sanity: walked root must equal the tree root. */
    if (memcmp(current, root, NODE_BYTES) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        return 1;
    }

    /* ================================================================
     * Prove and verify.
     * ================================================================ */
    const uint8_t *instance = root;
    const char *ds =
        "example_grostl_fixed_merkle:depth4-grostl256-fixed-leaf11";

    voleith_proof_t proof = {0};
    if (voleith_gf8_prove_v2(&proof, params, c, witness,
                             voleith_gf8_circuit_witness_byte_len(c), instance,
                             voleith_gf8_circuit_instance_byte_len(c), ds,
                             strlen(ds)) != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        return 1;
    }

    int verify_ok =
        (voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c), ds,
                               strlen(ds)) == 0);

    printf("Proof size:   %zu bytes\n", proof.len);
    printf("Verification: %s\n", verify_ok ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    free(witness);
    free(node_wires);
    for (unsigned k = 0; k <= DEPTH; k++)
        free(layer[k]);

    return verify_ok ? 0 : 1;
}
