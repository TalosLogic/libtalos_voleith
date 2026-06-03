/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_aes_cmac_gf8.c - ZK proof of AES-CMAC key knowledge (GF(2^8) circuit)
 *
 * Same statement as example_aes_cmac.c but using a 40-byte message to
 * demonstrate the multi-block case.
 *
 * Statement: "I know K such that AES-128-CMAC(K, M) = T"
 *
 * Public (instance): M (40 bytes) || T (16 bytes)
 * Private (witness): K (16 bytes) + inv_in for 4 AES calls = 816 bytes total
 *
 * AES call breakdown for 40-byte message:
 *   1 subkey AES call + 3 CBC AES calls (2 full blocks + 1 partial) = 4 total
 *   inv_in per call: 200 bytes (AES-128)
 *   Total witness: 16 + 4*200 = 816 bytes
 *   ell = 816  (vs 14,528 for bit-level with a 16-byte message)
 *
 * Test vector: RFC 4493 Example 3 (AES-128-CMAC, 40-byte message)
 *   Key: 2b7e151628aed2a6abf7158809cf4f3c
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "aes_cmac_gf8_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> /* needed for timing */

static const uint8_t KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
/* RFC 4493 Example 3: 40-byte message */
static const uint8_t MSG[40] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11};
/* Expected tag per this library's verified test suite */
static const uint8_t TAG[16] = {0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
                                0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27};

static const uint8_t FS_SEED[] = "example_aes_cmac_gf8:RFC4493-Ex3";

int
main(void)
{
    printf("=== AES-128-CMAC ZK proof (GF(2^8) circuit) ===\n");
    printf("Statement: knowledge of K s.t. CMAC(K, M) = T\n");
    printf("Test vector: RFC 4493 Example 3 (40-byte message)\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Key: 16 private witness wires */
    gf8_wire_id key_wires[16];
    for (int i = 0; i < 16; i++)
        key_wires[i] = voleith_gf8_add_witness(c);

    /* Message: 40 public instance wires */
    gf8_wire_id msg_wires[40];
    for (int i = 0; i < 40; i++)
        msg_wires[i] = voleith_gf8_add_instance(c);

    /* AES-CMAC circuit */
    gf8_wire_id tag_computed[16];
    aes_cmac_gf8_circuit(c, key_wires, 16, msg_wires, 40, tag_computed);

    /* Expected tag: 16 public instance wires; assert equal */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id tag_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, tag_computed[i], tag_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);
    size_t n_aes = aes_cmac_gf8_n_aes_calls(40);

    printf("Circuit statistics:\n");
    printf("  AES calls:       %zu (1 subkey + 3 CBC)\n", n_aes);
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu (16 key + %zu inv_in)\n",
           voleith_gf8_circuit_witness_count(c), n_aes * 200u);
    printf("  Instance wires:  %zu (40 msg + 16 tag)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    size_t wit_bytes = aes_cmac_gf8_witness_bytes(16, 40);
    uint8_t *witness = malloc(wit_bytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return 1;
    }

    uint8_t tag_ref[16];
    aes_cmac_gf8_build_witness(KEY, 16, MSG, 40, witness, tag_ref);

    if (memcmp(tag_ref, TAG, 16) != 0) {
        fprintf(stderr, "witness build produced wrong tag\n");
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: MSG || TAG */
    uint8_t instance[56];
    memcpy(instance, MSG, 40);
    memcpy(instance + 40, TAG, 16);

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
    free(witness);
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
    printf("Verification: %s in %.4f ms\n", (rc == 0) ? "PASS" : "FAIL", ms);

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
