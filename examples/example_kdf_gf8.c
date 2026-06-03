/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kdf_gf8.c - ZK proof of KDF-CTR-CMAC key derivation (GF(2^8) circuit)
 *
 * Same statement as example_kdf.c using the element-level circuit.
 *
 * Statement: "I know a KDK K such that KDF-CTR(K, FI) = KO"
 *
 * Public (instance): FI (60 bytes) || KO (16 bytes) - one wire per byte
 * Private (witness): K (16 bytes) + inv_in for 5 AES calls = 1016 bytes total
 *
 * AES calls: 5 (1 subkey + 4 CBC for 64-byte CMAC input)
 *   inv_in per call: 200 bytes (AES-128)
 *   Total witness: 16 + 5*200 = 1016 bytes
 *   ell = 1016  (vs 36,128 for bit-level)
 *
 * Test vector: NIST CAVS 14.4, SP800-108 Counter Mode, AES-128, L=128
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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

static const uint8_t FS_SEED[] = "example_kdf_gf8:NIST-CAVS14.4-AES128-L128";

int
main(void)
{
    printf("=== KDF-CTR-CMAC ZK proof (GF(2^8) circuit) ===\n");
    printf("Statement: knowledge of KDK K s.t. KDF-CTR(K, FI) = KO\n");
    printf("Test vector: NIST CAVS 14.4, AES-128, L=128\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Build circuit                                                     */
    /* ------------------------------------------------------------------ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* KDK: 16 private witness wires */
    gf8_wire_id ki_wires[16];
    for (int i = 0; i < 16; i++)
        ki_wires[i] = voleith_gf8_add_witness(c);

    /* FixedInputData: 60 public instance wires */
    gf8_wire_id fi_wires[60];
    for (int i = 0; i < 60; i++)
        fi_wires[i] = voleith_gf8_add_instance(c);

    /* KDF: 1 iteration, 16-byte output */
    gf8_wire_id ko_computed[16];
    if (kdf_ctr_cmac_gf8_circuit(c, ki_wires, 16, fi_wires, 60, ko_computed,
                                 16) != 0) {
        fprintf(stderr, "kdf_ctr_cmac_gf8_circuit: stack-VLA bound exceeded\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Expected derived key: 16 public instance wires; assert equal */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id ko_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ko_computed[i], ko_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);
    size_t n_aes = kdf_ctr_cmac_gf8_n_aes_calls(16, 60);
    size_t wit_bytes = kdf_ctr_cmac_gf8_witness_bytes(16, 16, 60);

    printf("Circuit statistics:\n");
    printf("  AES calls:       %zu\n", n_aes);
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu (16 KDK + %zu inv_in)\n",
           voleith_gf8_circuit_witness_count(c), n_aes * 200u);
    printf("  Instance wires:  %zu (60 FI + 16 KO)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 2. Build witness and instance                                        */
    /* ------------------------------------------------------------------ */
    uint8_t *witness = malloc(wit_bytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return 1;
    }

    uint8_t ko_ref[16];
    kdf_ctr_cmac_gf8_build_witness(KI, 16, FI, 60, 16, witness, ko_ref);

    if (memcmp(ko_ref, KO, 16) != 0) {
        fprintf(stderr, "witness build produced wrong derived key\n");
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: FI || KO */
    uint8_t instance[76];
    memcpy(instance, FI, 60);
    memcpy(instance + 60, KO, 16);

    /* ------------------------------------------------------------------ */
    /* 3. Prove                                                             */
    /* ------------------------------------------------------------------ */
    voleith_proof_t proof = {0};
    int rc = voleith_gf8_prove_v2(
        &proof, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
        instance, voleith_gf8_circuit_instance_byte_len(c), FS_SEED,
        sizeof(FS_SEED) - 1);
    free(witness);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ------------------------------------------------------------------ */
    /* 4. Verify                                                            */
    /* ------------------------------------------------------------------ */
    rc = voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c),
                               FS_SEED, sizeof(FS_SEED) - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
