/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_aes_cmac.c - ZK proof of AES-CMAC key knowledge (bit-level circuit)
 *
 * Statement: "I know a 128-bit key K such that AES-128-CMAC(K, M) = T"
 *
 * Public (instance): M (message, 16 bytes) || T (CMAC tag, 16 bytes)
 * Private (witness): K (key, 16 bytes)
 *
 * Circuit:
 *   128 witness wires  (key bits)
 *   128 instance wires (message bits)
 *   → aes_cmac_circuit() with 1 complete block → 2 AES calls total
 *   → 128 output tag wires compared to 128 instance wires (expected tag)
 *
 * AND gate cost: (1 CBC block + 1 subkey AES) x 7,200 = 14,400
 * ell = 128 + 14,400 = 14,528
 *
 * Test vector: RFC 4493 Example 2 (AES-128-CMAC, 16-byte message)
 *   Key: 2b7e151628aed2a6abf7158809cf4f3c
 *   Msg: 6bc1bee22e409f96e93d7e1173931726 ...2a
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "aes_cmac_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* RFC 4493, Section 4, Example 2 */
static const uint8_t KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t MSG[16] = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a};
/* Expected tag per this library's verified test suite */
static const uint8_t TAG[16] = {0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
                                0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c};

static const uint8_t FS_SEED[] = "example_aes_cmac:RFC4493-Ex2";

int
main(void)
{
    printf("=== AES-128-CMAC ZK proof (bit-level circuit) ===\n");
    printf("Statement: knowledge of K s.t. CMAC(K, M) = T\n");
    printf("Test vector: RFC 4493 Example 2 (16-byte message)\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Key: 128 private witness wires */
    wire_id key_wires[128];
    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(c);

    /* Message: 128 public instance wires */
    wire_id msg_wires[128];
    for (int i = 0; i < 128; i++)
        msg_wires[i] = voleith_circuit_add_instance(c);

    /* AES-CMAC circuit */
    wire_id tag_computed[128];
    aes_cmac_circuit(c, key_wires, 128, msg_wires, 128, tag_computed);

    /* Expected tag: 128 public instance wires; assert equal */
    for (int i = 0; i < 128; i++) {
        wire_id tag_inst = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, tag_computed[i], tag_inst);
    }

    size_t ell = voleith_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu (2 AES calls x 7,200)\n",
           voleith_circuit_and_gate_count(c));
    printf("  Witness wires:   %zu\n", voleith_circuit_witness_count(c));
    printf("  Instance wires:  %zu\n", voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    const uint8_t *witness = KEY; /* 16 bytes (key bits, LSB-first = raw) */

    uint8_t instance[32];
    memcpy(instance, MSG, 16);
    memcpy(instance + 16, TAG, 16);

    /* ------------------------------------------------------------------ */
    /* 3. Prove                                                             */
    /* ------------------------------------------------------------------ */
    voleith_proof_t proof = {0};
    int rc = voleith_prove_v2(&proof, params, c, witness,
                              voleith_circuit_witness_byte_len(c), instance,
                              voleith_circuit_instance_byte_len(c), FS_SEED,
                              sizeof(FS_SEED) - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove_v2 failed\n");
        voleith_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ------------------------------------------------------------------ */
    /* 4. Verify                                                            */
    /* ------------------------------------------------------------------ */
    rc = voleith_verify_v2(&proof, params, c, instance,
                           voleith_circuit_instance_byte_len(c), FS_SEED,
                           sizeof(FS_SEED) - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
