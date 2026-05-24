/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kdf.c - ZK proof of KDF-CTR-CMAC key derivation (bit-level circuit)
 *
 * Statement: "I know a KDK K such that KDF-CTR(K, FI) = KO"
 * where KDF-CTR is NIST SP 800-108r1 Section 4.1 in counter mode using
 * AES-128-CMAC as the PRF.
 *
 * Public (instance): FI (60-byte FixedInputData) || KO (16-byte derived key)
 * Private (witness): K  (16-byte KDK)
 *
 * Circuit:
 *   128 witness wires (KDK bits)
 *   480 instance wires (FI bits) + 128 instance wires (KO bits)
 *   → kdf_ctr_cmac_circuit() with 1 iteration, 60-byte FI
 *   → 128 output wires compared to 128 instance wires (KO)
 *
 * AND gate cost for 1 iteration, msg=4+60=64 bytes (4 complete AES blocks):
 *   n_aes = 1 (subkey) + 4 (CBC) = 5 AES calls = 5 x 7,200 = 36,000 AND gates
 * ell = 128 + 36,000 = 36,128
 *
 * Test vector: NIST CAVS 14.4, SP800-108 Counter Mode, CMAC_AES128,
 *              CTRLOCATION=BEFORE_FIXED, RLEN=32_BITS, COUNT=0, L=128
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "kdf_ctr_cmac_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* NIST CAVS 14.4, AES-128, L=128, COUNT=0 */
static const uint8_t KI[16] = {0xc1, 0x0b, 0x15, 0x2e, 0x8c, 0x97, 0xb7, 0x7e,
                               0x18, 0x70, 0x4e, 0x0f, 0x0b, 0xd3, 0x83, 0x05};
static const uint8_t FI[60] = {
    0x98, 0xcd, 0x4c, 0xbb, 0xbe, 0xbe, 0x15, 0xd1, 0x7d, 0xc8, 0x6e, 0x6d,
    0xba, 0xd8, 0x00, 0xa2, 0xdc, 0xbd, 0x64, 0xf7, 0xc7, 0xad, 0x0e, 0x78,
    0xe9, 0xcf, 0x94, 0xff, 0xdb, 0xa8, 0x9d, 0x03, 0xe9, 0x7e, 0xad, 0xf6,
    0xc4, 0xf7, 0xb8, 0x06, 0xca, 0xf5, 0x2a, 0xa3, 0x8f, 0x09, 0xd0, 0xeb,
    0x71, 0xd7, 0x1f, 0x49, 0x7b, 0xcc, 0x69, 0x06, 0xb4, 0x8d, 0x36, 0xc4};
static const uint8_t KO[16] = {0x26, 0xfa, 0xf6, 0x19, 0x08, 0xad, 0x9e, 0xe8,
                               0x81, 0xb8, 0x30, 0x5c, 0x22, 0x1d, 0xb5, 0x3f};

static const uint8_t FS_SEED[] = "example_kdf:NIST-CAVS14.4-AES128-L128";

int
main(void)
{
    printf("=== KDF-CTR-CMAC ZK proof (bit-level circuit) ===\n");
    printf("Statement: knowledge of KDK K s.t. KDF-CTR(K, FI) = KO\n");
    printf("Test vector: NIST CAVS 14.4, AES-128, L=128\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* KDK: 128 private witness wires */
    wire_id ki_wires[128];
    for (int i = 0; i < 128; i++)
        ki_wires[i] = voleith_circuit_add_witness(c);

    /* FixedInputData: 60 * 8 = 480 public instance wires */
    wire_id *fi_wires = calloc(60 * 8, sizeof(wire_id));
    if (!fi_wires) {
        voleith_circuit_free(c);
        return 1;
    }
    for (int i = 0; i < 60 * 8; i++)
        fi_wires[i] = voleith_circuit_add_instance(c);

    /* KDF: 1 iteration, 16-byte output */
    wire_id ko_computed[128];
    kdf_ctr_cmac_circuit(c, ki_wires, 128, fi_wires, 60 * 8, ko_computed, 128);
    free(fi_wires);

    /* Expected derived key: 128 public instance wires; assert equal */
    for (int i = 0; i < 128; i++) {
        wire_id ko_inst = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, ko_computed[i], ko_inst);
    }

    size_t ell = voleith_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu (5 AES calls x 7,200)\n",
           voleith_circuit_and_gate_count(c));
    printf("  Witness wires:   %zu\n", voleith_circuit_witness_count(c));
    printf("  Instance wires:  %zu (480 FI bits + 128 KO bits)\n",
           voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    /* Witness: KI (16 bytes, bit-packed = raw bytes) */
    const uint8_t *witness = KI;

    /* Instance: FI (60 bytes) || KO (16 bytes) */
    uint8_t instance[76];
    memcpy(instance, FI, 60);
    memcpy(instance + 60, KO, 16);

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
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
