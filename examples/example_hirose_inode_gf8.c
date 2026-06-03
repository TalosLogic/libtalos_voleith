/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_hirose_inode_gf8.c - ZK proof of a Merkle internal-node
 * preimage under the Hirose-AES-256 inode hash (GF(2^8) element
 * circuit).
 *
 * This previews the cost shape of the inode side of the
 * voleith_node_hash_hirose / voleith_node_hash_hirose_fixed32 vts
 * that will land in step 9.4 of docs/HIROSE_MERKLE_DESIGN.md.  The
 * inode is shared between the two leaf vts (no padding ambiguity at
 * the inode level - both children are always exactly 32 bytes), so
 * one inode_circuit serves both.  The example composes the iteration
 * primitive twice with c_inode hard-coded; the c_inode value moves
 * into the vt instance in step 9.4.
 *
 * Statement: "I know children (L, R) such that
 *             hirose_inode(L, R) = parent"
 *
 *   (G1, H1) = f( (L_G, L_H),  R[ 0..15], c_inode )
 *   (G2, H2) = f( (G1,  H1 ),  R[16..31], c_inode )
 *   parent   = G2 || H2
 *
 * Public (instance): parent     (32 bytes / 32 wires)
 * Private (witness): L = (L_G, L_H)  (32 bytes / 32 wires)
 *                  + R                (32 bytes / 32 wires)
 *                  + 2 x 500 inv_in bytes for the two Hirose
 *                                                    iterations
 *                                                = 1064 bytes total
 * Constant in circuit:
 *   c_inode (16 bytes, applied via add_xor_const inside the
 *            iteration primitive - zero VOLE slots).
 *
 * Note: unlike the fixed-32 leaf hash, the inode's IV slot holds
 * L (a witness, the left child), NOT a circuit constant.  That is
 * the entire point of the "L as IV" trick: it lets the inode
 * absorb R alone as message (32 bytes -> 2 iterations) instead of
 * absorbing L || R as message (64 bytes -> 4 iterations).  Two
 * iterations is the structural floor for an inode at > 2^64 CR.
 *
 * Circuit costs:
 *   1000 inv_in witness slots (2 x 500 for two iterations, same
 *                              S-box count as the fixed-32 leaf)
 *   0 mul gates
 *   2000 assert_product constraints (2 per S-box, 1000 S-boxes)
 *   ell = 1064 (64 external witness + 1000 inv_in)
 *
 * Step 9.4 will rename the placeholder c_inode constant to the
 * design doc's HIROSE_C_INODE once the vt instance owns it.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "node_hash_hirose_gf8.h"
#include "../core/hirose.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/*
 * Placeholder vt constant - step 9.4 of docs/HIROSE_MERKLE_DESIGN.md
 * relocates this into circuits/node_hash_hirose_gf8.c alongside the
 * vt instance.  The inode c is shared by both leaf-vt flavors
 * because the inode has no padding ambiguity (fixed 32-byte
 * children); only c_leaf differs between fixed-32 and variable-leaf
 * vts.
 *
 * C_INODE: "VOLEitH-Hirose-N" (exactly 16 bytes, distinct from
 *          C_LEAF / C_LEAF_FIXED32).
 */
static const uint8_t C_INODE[16] = {'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
                                    'H', 'i', 'r', 'o', 's', 'e', '-', 'N'};

/*
 * Fictional sibling Merkle nodes.  In a real consumer these would
 * typically themselves be 32-byte Hirose leaf hashes or inode
 * outputs; the inode hash doesn't care about provenance.
 */
static const uint8_t L_CHILD[32] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
    0xcc, 0xdd, 0xee, 0xff, 0x00, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
    0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
};
static const uint8_t R_CHILD[32] = {
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45,
    0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static const uint8_t FS_SEED[] = "example_hirose_inode_gf8:inode-preimage";

/* Software oracle: compute the inode hash via core/hirose.h. */
static void
hirose_inode_hash_sw(const uint8_t L[32], const uint8_t R[32], uint8_t out[32])
{
    uint8_t G[16], H[16];
    memcpy(G, L + 0, 16);  /* L_G as initial chaining G */
    memcpy(H, L + 16, 16); /* L_H as initial chaining H */
    voleith_hirose_iteration(G, H, R + 0, C_INODE, G, H);
    voleith_hirose_iteration(G, H, R + 16, C_INODE, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
}

int
main(void)
{
    printf("=== Hirose inode hash ZK proof (GF(2^8) element circuit) ===\n");
    printf("Statement: knowledge of (L, R) s.t. hirose_inode(L, R) = parent\n");
    printf("Construction: 2-iter Hirose / AES-256 inode, 2^128 CR\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Private witness wires: 32-byte L (left child) and 32-byte R
     * (right child).  L is split into (L_G, L_H) for the iteration
     * primitive's chaining-value slots. */
    gf8_wire_id L_G_w[16], L_H_w[16], R_w[32];
    for (int i = 0; i < 16; i++)
        L_G_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        L_H_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 32; i++)
        R_w[i] = voleith_gf8_add_witness(c);

    /* Iteration 1: chain = L = (L_G, L_H), message = R[0..15]. */
    gf8_wire_id G1_w[16], H1_w[16];
    hirose_gf8_iteration_circuit(c, L_G_w, L_H_w, &R_w[0], C_INODE, G1_w, H1_w);

    /* Iteration 2: chain = (G1, H1), message = R[16..31]. */
    gf8_wire_id G2_w[16], H2_w[16];
    hirose_gf8_iteration_circuit(c, G1_w, H1_w, &R_w[16], C_INODE, G2_w, H2_w);

    /* Public instance: parent (G2 || H2), 32 wires.  Assert equality
     * byte-by-byte against the computed output. */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id inst_i = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, G2_w[i], inst_i);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id inst_i = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, H2_w[i], inst_i);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf(
        "  S-box inv_in:    1000 (2 iterations x 500 per iter, KS-shared)\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  assert_product:  %zu (2 per S-box)\n",
           voleith_gf8_circuit_assert_product_count(c));
    printf("  Witness wires:   %zu (32 L + 32 R + 1000 inv_in)\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (16 parent_G + 16 parent_H)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* Witness layout:
     *   [0..31]:        L = (L_G, L_H)   (external witness)
     *   [32..63]:       R                (external witness)
     *   [64..563]:      iter 1 inv_in
     *   [564..1063]:    iter 2 inv_in */
    uint8_t witness[64 + 2 * HIROSE_GF8_ITERATION_WITNESS_BYTES];
    memcpy(witness + 0, L_CHILD, 32);
    memcpy(witness + 32, R_CHILD, 32);

    /* Iter 1 witness + chaining output for iter 2. */
    uint8_t G1_b[16], H1_b[16];
    hirose_gf8_iteration_build_witness(L_CHILD + 0, L_CHILD + 16, R_CHILD + 0,
                                       C_INODE, witness + 64, G1_b, H1_b);
    /* Iter 2 witness + final output. */
    uint8_t G2_b[16], H2_b[16];
    hirose_gf8_iteration_build_witness(
        G1_b, H1_b, R_CHILD + 16, C_INODE,
        witness + 64 + HIROSE_GF8_ITERATION_WITNESS_BYTES, G2_b, H2_b);

    /* Instance = expected parent node, computed via the software oracle. */
    uint8_t instance[32];
    hirose_inode_hash_sw(L_CHILD, R_CHILD, instance);

    /* Cross-check: the build_witness chain agrees with the software
     * oracle (different code paths, same function). */
    if (memcmp(G2_b, instance + 0, 16) != 0 ||
        memcmp(H2_b, instance + 16, 16) != 0) {
        fprintf(stderr, "internal: build_witness chain disagrees with software "
                        "oracle - aborting\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 3. Prove                                                             */
    /* ------------------------------------------------------------------ */
    voleith_proof_t proof = {0};
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = voleith_gf8_prove_v2(
        &proof, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
        instance, voleith_gf8_circuit_instance_byte_len(c), FS_SEED,
        sizeof(FS_SEED) - 1);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }
    uint64_t delta_us = (end.tv_sec - start.tv_sec) * 1000000 +
                        (end.tv_nsec - start.tv_nsec) / 1000;
    double ms = (double)delta_us / 1000;
    printf("Proof generated: %zu bytes in %.4f ms\n", proof.len, ms);

    /* ------------------------------------------------------------------ */
    /* 4. Verify                                                            */
    /* ------------------------------------------------------------------ */
    clock_gettime(CLOCK_MONOTONIC, &start);
    rc = voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c),
                               FS_SEED, sizeof(FS_SEED) - 1);
    clock_gettime(CLOCK_MONOTONIC, &end);
    delta_us = (end.tv_sec - start.tv_sec) * 1000000 +
               (end.tv_nsec - start.tv_nsec) / 1000;
    ms = (double)delta_us / 1000;
    if (rc == 0) {
        printf("Verification: PASS in %.4f ms\n", ms);
    } else {
        printf("Verification: FAIL\n");
    }

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
