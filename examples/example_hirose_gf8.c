/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_hirose_gf8.c - ZK proof of one Hirose iteration's inputs
 * (GF(2^8) element circuit).
 *
 * Statement: "I know (G, H, M) such that one Hirose iteration
 *             f(G, H, M, c) = (G_out, H_out)"
 *
 *   K       = H || M                  (256-bit AES-256 key)
 *   G_out   = AES_K(G)        XOR G
 *   H_out   = AES_K(G XOR c)  XOR G XOR c
 *
 * Public (instance): G_out || H_out  (32 bytes / 32 wires)
 * Private (witness): G (16) || H (16) || M (16)
 *                  + 500 inv_in bytes for the in-circuit Hirose
 *                                                = 548 bytes total
 * Constant in circuit: c (16 bytes, free xor-with-constant)
 *
 * Circuit costs (target floor):
 *   500 inv_in witness slots
 *     = 52 from one shared aes256_gf8_expand_key emit
 *     + 224 from one aes256_gf8_encrypt_rk emit on G
 *     + 224 from one aes256_gf8_encrypt_rk emit on G XOR c
 *   0 mul gates    (all S-box inversions go through assert_product)
 *   1000 assert_product constraints (2 per S-box)
 *   ell = 548 (48 external witness + 500 inv_in)
 *
 * KS sharing across the two same-key AES calls is the load-bearing
 * optimization: emitting aes256_gf8_expand_key once instead of twice
 * saves 52 S-boxes (104 assert_products) per iteration vs. two
 * independent aes256_gf8_circuit calls.  See docs/HIROSE_MERKLE_DESIGN.md
 * for the construction and gate-accounting derivation.
 *
 * The Hirose construction provides 2^128 collision resistance in the
 * ideal-cipher model (Hirose, FSE 2006), so 128f is the appropriate
 * VOLEitH parameter set.  This example reuses the future inode
 * constant ("VOLEitH-Hirose-N") as the c value; the real Merkle
 * inode / leaf vts that own that constant land in step 9.4 of
 * docs/HIROSE_MERKLE_DESIGN.md.
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

/* Witness inputs.  All three blocks are private to the prover. */
static const uint8_t G_IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t H_IN[16] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
static const uint8_t M_IN[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};

/* c is a circuit constant, not a wire (xor-with-constant is free). */
static const uint8_t C_CONST[16] = {'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
                                    'H', 'i', 'r', 'o', 's', 'e', '-', 'N'};

static const uint8_t FS_SEED[] = "example_hirose_gf8:1-iter-preimage";

int
main(void)
{
    printf("=== Hirose iteration ZK proof (GF(2^8) element circuit) ===\n");
    printf(
        "Statement: knowledge of (G, H, M) s.t. f(G,H,M,c) = (G_out,H_out)\n");
    printf("Construction: Hirose DBL / AES-256 (FSE 2006), 2^128 CR\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Private witness wires: G || H || M = 48 bytes total. */
    gf8_wire_id G_w[16], H_w[16], M_w[16];
    for (int i = 0; i < 16; i++)
        G_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        H_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        M_w[i] = voleith_gf8_add_witness(c);

    /* Emit one Hirose iteration (adds 500 inv_in witnesses internally
     * and 1000 assert_product constraints; zero mul gates). */
    gf8_wire_id G_out_w[16], H_out_w[16];
    hirose_gf8_iteration_circuit(c, G_w, H_w, M_w, C_CONST, G_out_w, H_out_w);

    /* Public instance: G_out || H_out (32 wires).  Assert equality
     * to the computed output, one byte at a time. */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id inst_i = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, G_out_w[i], inst_i);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id inst_i = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, H_out_w[i], inst_i);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  S-box inv_in:    500 (52 KS + 2 x 224 encrypt, KS-shared)\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  assert_product:  %zu (2 per S-box)\n",
           voleith_gf8_circuit_assert_product_count(c));
    printf("  Witness wires:   %zu (48 external + 500 inv_in)\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (16 G_out + 16 H_out)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* Witness layout: 48 external bytes (G || H || M) followed by
     * the 500 inv_in bytes the Hirose iteration consumes. */
    uint8_t witness[48 + HIROSE_GF8_ITERATION_WITNESS_BYTES];
    memcpy(witness + 0, G_IN, 16);
    memcpy(witness + 16, H_IN, 16);
    memcpy(witness + 32, M_IN, 16);

    uint8_t G_chk[16], H_chk[16];
    hirose_gf8_iteration_build_witness(G_IN, H_IN, M_IN, C_CONST, witness + 48,
                                       G_chk, H_chk);

    /* Instance = expected (G_out || H_out), computed via the
     * core/hirose.h software primitive.  The naive two-encrypt
     * software form and the KS-shared circuit form must agree
     * byte-for-byte; if they did not, the prover would reject
     * the witness as inconsistent. */
    uint8_t instance[32];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_CONST, instance,
                             instance + 16);

    /* Sanity: builder's optional outputs agree with the software
     * primitive (these two routines compute the same function via
     * different paths). */
    if (memcmp(G_chk, instance, 16) != 0 ||
        memcmp(H_chk, instance + 16, 16) != 0) {
        fprintf(stderr, "internal: build_witness output disagrees with "
                        "voleith_hirose_iteration - aborting\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 3. Prove                                                             */
    /* ------------------------------------------------------------------ */
    voleith_proof_t proof = {0};
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = voleith_gf8_prove(&proof, params, c, witness, instance, FS_SEED,
                               sizeof(FS_SEED) - 1);
    clock_gettime(CLOCK_MONOTONIC, &end);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove failed\n");
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
    rc = voleith_gf8_verify(&proof, params, c, instance, FS_SEED,
                            sizeof(FS_SEED) - 1);
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
