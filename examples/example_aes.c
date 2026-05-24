/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_aes.c - ZK proof of AES-128 key knowledge (bit-level GF(2) circuit)
 *
 * Statement: "I know a 128-bit key K such that AES-128(K, PT) = CT"
 *
 * Public (instance): PT (plaintext, 16 bytes) || CT (ciphertext, 16 bytes)
 * Private (witness): K  (key, 16 bytes)
 *
 * Circuit:
 *   128 witness wires  (key bits, LSB-first per byte)
 *   128 instance wires (plaintext bits)
 *   → aes128_circuit()
 *   → 128 output wires compared to 128 instance wires (ciphertext)
 *
 * Test vector: FIPS 197 Appendix B
 *   Key:        00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
 *   Plaintext:  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff
 *   Ciphertext: 69 c4 e0 d8 6a 7b 04 30  d8 cd b7 80 70 b4 c5 5a
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "aes_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* FIPS 197 Appendix B test vector */
static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t CT[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                               0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};

/* Fixed Fiat-Shamir seed for reproducibility.  In production, include fresh
   randomness so that each proof is unlinkable. */
static const uint8_t FS_SEED[] = "example_aes:FIPS197-AppB";

int
main(void)
{
    printf("=== AES-128 ZK proof (bit-level circuit) ===\n");
    printf("Statement: knowledge of K s.t. AES-128(K, PT) = CT\n");
    printf("Test vector: FIPS 197 Appendix B\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Key: 128 private witness wires (bit 0 = LSB of byte 0, etc.) */
    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);

    /* Plaintext: 128 public instance wires */
    wire_id pt_wires[128];
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(c);

    /* AES-128 encryption circuit */
    wire_id ct_computed[128];
    aes128_circuit(c, key_wires, pt_wires, ct_computed);

    /* Expected ciphertext: 128 public instance wires; assert equal */
    for (int i = 0; i < 128; i++) {
        wire_id ct_inst = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, ct_computed[i], ct_inst);
    }

    size_t ell = voleith_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu (200 S-boxes x 36)\n",
           voleith_circuit_and_gate_count(c));
    printf("  Witness wires:   %zu (128 key bits)\n",
           voleith_circuit_witness_count(c));
    printf("  Instance wires:  %zu (128 PT bits + 128 CT bits)\n",
           voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* Witness: key bits, packed LSB-first per byte = raw key bytes */
    const uint8_t *witness = KEY; /* 16 bytes */

    /* Instance: PT || CT, packed LSB-first per byte = raw bytes */
    uint8_t instance[32];
    memcpy(instance, PT, 16);
    memcpy(instance + 16, CT, 16);

    /* ------------------------------------------------------------------ */
    /* 3. Prove                                                             */
    /* ------------------------------------------------------------------ */
    voleith_proof_t proof = {0};
    int rc = voleith_prove(&proof, params, c, witness, instance, FS_SEED,
                           sizeof(FS_SEED) - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove failed\n");
        voleith_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ------------------------------------------------------------------ */
    /* 4. Verify                                                            */
    /* ------------------------------------------------------------------ */
    rc = voleith_verify(&proof, params, c, instance, FS_SEED,
                        sizeof(FS_SEED) - 1);
    if (rc == 0) {
        printf("Verification: PASS\n");
    } else {
        printf("Verification: FAIL\n");
    }

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
