/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_aes_gf8.c - ZK proof of AES-128 key knowledge (GF(2^8) element circuit)
 *
 * Same statement as example_aes.c but using the element-level GF(2^8) circuit,
 * which operates one byte per wire instead of one bit per wire.
 *
 * Statement: "I know a 128-bit key K such that AES-128(K, PT) = CT"
 *
 * Public (instance): PT (16 bytes) || CT (16 bytes)  - one wire per byte
 * Private (witness): K (16 bytes) + 200 S-box inv_in bytes = 216 bytes total
 *
 * Circuit costs:
 *   200 witness slots  (16 key bytes + 200 inv_in bytes)
 *   0 mul gates        (S-box inversions use assert_product, not add_mul)
 *   ell = 216
 *
 * Compared to the bit-level variant (ell=7,328), the GF(2^8) circuit reduces
 * ell by ~34x, yielding a significantly smaller proof.
 *
 * Test vector: FIPS 197 Appendix B (same as example_aes.c)
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "aes_gf8_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h> /* needed for timing */

static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t CT[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                               0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

static const uint8_t FS_SEED[] = "example_aes_gf8:FIPS197-AppB";

int
main(void)
{
    printf("=== AES-128 ZK proof (GF(2^8) element circuit) ===\n");
    printf("Statement: knowledge of K s.t. AES-128(K, PT) = CT\n");
    printf("Test vector: FIPS 197 Appendix B\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Key: 16 private witness wires (one byte per wire) */
    gf8_wire_id key_wires[16];
    for (int i = 0; i < 16; i++)
        key_wires[i] = voleith_gf8_add_witness(c);

    /* Plaintext: 16 public instance wires */
    gf8_wire_id pt_wires[16];
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);

    /* AES-128 encryption circuit (adds 200 inv_in witness wires internally) */
    gf8_wire_id ct_computed[16];
    aes128_gf8_circuit(c, key_wires, pt_wires, ct_computed);

    /* Expected ciphertext: 16 public instance wires; assert equal */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id ct_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_computed[i], ct_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  S-box inv_in:    200 (one per S-box, via assert_product)\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu (16 key + 200 inv_in)\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (16 PT + 16 CT)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* aes128_gf8_build_witness constructs the full 216-byte witness:
       [0..15]:   key bytes
       [16..55]:  inv_in for 10 key schedule SubWord rounds (4 S-boxes each)
       [56..215]: inv_in for 10 data path SubBytes rounds (16 S-boxes each) */
    uint8_t witness[216];
    uint8_t ct_ref[16];
    aes128_gf8_build_witness(KEY, PT, witness, ct_ref);

    /* Verify that the circuit will match our expected CT */
    if (memcmp(ct_ref, CT, 16) != 0) {
        fprintf(stderr, "witness build produced wrong ciphertext\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: PT || CT, one byte per wire */
    uint8_t instance[32];
    memcpy(instance, PT, 16);
    memcpy(instance + 16, CT, 16);

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
