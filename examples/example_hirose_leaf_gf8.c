/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_hirose_leaf_gf8.c - ZK proof of a 32-byte leaf preimage
 * under the Hirose-AES-256 leaf hash (GF(2^8) element circuit).
 *
 * This previews the cost shape of the
 * voleith_node_hash_hirose_fixed32 vt that will land in step 9.4 of
 * docs/HIROSE_MERKLE_DESIGN.md.  The vt itself does not exist yet;
 * the example composes the iteration primitive
 * (hirose_gf8_iteration_circuit) with a hard-coded leaf IV constant
 * to assemble the same gate stream the vt will emit.
 *
 * Statement: "I know a 32-byte preimage X such that
 *             hirose_leaf(X) = parent_node"
 *
 *   (G1, H1) = f( (IV_G, IV_H), X[ 0..15], c_leaf )
 *   (G2, H2) = f( (G1,  H1   ), X[16..31], c_leaf )
 *   leaf     = G2 || H2
 *
 * Public (instance): leaf      (32 bytes / 32 wires)
 * Private (witness): X          (32 bytes / 32 wires)
 *                  + 2 x 500 inv_in bytes for the two Hirose
 *                                                    iterations
 *                                                 = 1032 bytes total
 * Constants in circuit:
 *   IV_LEAF (32 bytes, declared via add_const - zero VOLE slots)
 *   c_leaf  (16 bytes, applied via add_xor_const inside the
 *            iteration primitive - zero VOLE slots)
 *
 * Circuit costs:
 *   1000 inv_in witness slots (2 x 500 for two iterations)
 *   0 mul gates
 *   2000 assert_product constraints (2 per S-box, 1000 S-boxes)
 *   ell = 1032 (32 external witness + 1000 inv_in)
 *
 * Compare with example_hirose_gf8.c (one bare iteration, 548 ell):
 * the leaf hash doubles the iteration count to two but FIXES the
 * IV as a circuit constant, so external witness shrinks from 48
 * (G + H + M) to 32 (X only).  The structural floor is set by
 * the two iterations' AES work: 1000 inv_in slots is the cheapest
 * 32-byte preimage proof achievable at 2^128 CR.
 *
 * Step 9.4 will rename the placeholder IV / c_leaf constants to
 * the design doc's HIROSE_IV_LEAF and HIROSE_C_LEAF_FIXED32 once
 * the vt instance owns them.
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
 * Placeholder vt constants - step 9.4 of docs/HIROSE_MERKLE_DESIGN.md
 * relocates these into circuits/node_hash_hirose_gf8.c alongside the
 * vt instances.
 *
 * IV_LEAF: "VOLEitH-Hirose-IV" (17 bytes) zero-padded to 32.
 * C_LEAF:  "VOLEitH-Hirose-L"  (exactly 16 bytes).
 */
static const uint8_t IV_LEAF[32] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'H', 'i', 'r',
    'o', 's', 'e', '-', 'I', 'V', 0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};
static const uint8_t C_LEAF[16] = {'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
                                   'H', 'i', 'r', 'o', 's', 'e', '-', 'L'};

/* The witness: a fictional 32-byte leaf commitment value. */
static const uint8_t LEAF_DATA[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static const uint8_t FS_SEED[] = "example_hirose_leaf_gf8:fixed32-preimage";

/* Software oracle: compute the same leaf hash via core/hirose.h. */
static void
hirose_fixed32_leaf_hash_sw(const uint8_t data[32], uint8_t out[32])
{
    uint8_t G[16], H[16];
    memcpy(G, IV_LEAF + 0, 16);
    memcpy(H, IV_LEAF + 16, 16);
    voleith_hirose_iteration(G, H, data + 0, C_LEAF, G, H);
    voleith_hirose_iteration(G, H, data + 16, C_LEAF, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
}

int
main(void)
{
    printf("=== Hirose leaf hash ZK proof (GF(2^8) element circuit) ===\n");
    printf("Statement: knowledge of 32-byte X s.t. hirose_leaf(X) = leaf\n");
    printf("Construction: 2-iter Hirose / AES-256 leaf, 2^128 CR\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Private witness wires: 32-byte leaf preimage X. */
    gf8_wire_id X_w[32];
    for (int i = 0; i < 32; i++)
        X_w[i] = voleith_gf8_add_witness(c);

    /* IV_LEAF as 32 constant wires (free - zero VOLE slots).  Split
     * into the iteration primitive's (G, H) shape. */
    gf8_wire_id IV_G_w[16], IV_H_w[16];
    for (int i = 0; i < 16; i++)
        IV_G_w[i] = voleith_gf8_add_const(c, IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        IV_H_w[i] = voleith_gf8_add_const(c, IV_LEAF[16 + i]);

    /* Iteration 1: chain = IV_LEAF, message = X[0..15]. */
    gf8_wire_id G1_w[16], H1_w[16];
    hirose_gf8_iteration_circuit(c, IV_G_w, IV_H_w, &X_w[0], C_LEAF, G1_w,
                                 H1_w);

    /* Iteration 2: chain = (G1, H1), message = X[16..31]. */
    gf8_wire_id G2_w[16], H2_w[16];
    hirose_gf8_iteration_circuit(c, G1_w, H1_w, &X_w[16], C_LEAF, G2_w, H2_w);

    /* Public instance: leaf output (G2 || H2), 32 wires.  Assert
     * equality byte-by-byte against the computed output. */
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
    printf("  Witness wires:   %zu (32 leaf data + 1000 inv_in)\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (16 leaf_G + 16 leaf_H)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* Witness layout:
     *   [0..31]:        leaf data X (external witness)
     *   [32..531]:      iter 1 inv_in
     *   [532..1031]:    iter 2 inv_in */
    uint8_t witness[32 + 2 * HIROSE_GF8_ITERATION_WITNESS_BYTES];
    memcpy(witness, LEAF_DATA, 32);

    /* Iter 1 witness + chaining output for iter 2. */
    uint8_t G1_b[16], H1_b[16];
    hirose_gf8_iteration_build_witness(IV_LEAF + 0, IV_LEAF + 16, LEAF_DATA + 0,
                                       C_LEAF, witness + 32, G1_b, H1_b);
    /* Iter 2 witness + final output. */
    uint8_t G2_b[16], H2_b[16];
    hirose_gf8_iteration_build_witness(
        G1_b, H1_b, LEAF_DATA + 16, C_LEAF,
        witness + 32 + HIROSE_GF8_ITERATION_WITNESS_BYTES, G2_b, H2_b);

    /* Instance = expected leaf hash, computed via the software oracle. */
    uint8_t instance[32];
    hirose_fixed32_leaf_hash_sw(LEAF_DATA, instance);

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
