/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_bristol_aes128.c - ZK proof of AES-128 key knowledge via Bristol
 * Fashion circuit parser.
 *
 * Statement: "I know a 128-bit key K such that AES-128(K, PT) = CT"
 *
 * Public (instance): PT (plaintext, 16 bytes) in Bristol wire order
 * Private (witness): K  (key, 16 bytes) in Bristol wire order
 *
 * The Bristol AES-128 circuit uses reversed bit/byte ordering: wire 0
 * carries bit 0 of the LAST byte (byte 15) of each 128-bit value.
 * Both witness and instance bytes are supplied in reverse order accordingly.
 *
 * Test vector: FIPS 197 Appendix B
 *   Key:        2b 7e 15 16 28 ae d2 a6  ab f7 15 88 09 cf 4f 3c
 *   Plaintext:  32 43 f6 a8 88 5a 30 8d  31 31 98 a2 e0 37 07 34
 *   Ciphertext: 39 25 84 1d 02 dc 09 fb  dc 11 85 97 19 6a 0b 32
 *
 * Usage: example_bristol_aes128 <path-to-aes_128.txt>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bristol.h"
#include "circuit.h"
#include "proof.h"
#include "prover.h"

/* FIPS 197 Appendix B test vector */
static const uint8_t KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t PT[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
static const uint8_t CT[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                               0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

/* Fixed Fiat-Shamir seed for reproducibility.  In production, include fresh
   randomness so that each proof is unlinkable. */
static const uint8_t FS_SEED[] = "example_bristol_aes128:FIPS197-AppB";

int
main(int argc, char **argv)
{
    voleith_bristol_input_role_t roles[2];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    const voleith_params_t *params;
    voleith_proof_t proof;
    uint8_t witness[16];
    uint8_t instance[16];
    wire_id cw;
    size_t ell, proof_bytes;
    int bit, rc, i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <path-to-aes_128.txt>\n", argv[0]);
        fprintf(stderr, "  e.g. %s tests/data/bristol/aes_128.txt\n", argv[0]);
        return 1;
    }

    printf("=== Bristol Fashion AES-128 ZK proof ===\n");
    printf("Statement: knowledge of K s.t. AES-128(K, PT) = CT\n");
    printf("Test vector: FIPS 197 Appendix B\n\n");

    /* ------------------------------------------------------------------ */
    /* 1. Parse Bristol circuit                                             */
    /* ------------------------------------------------------------------ */
    roles[0] = VOLEITH_BRISTOL_WITNESS;  /* key */
    roles[1] = VOLEITH_BRISTOL_INSTANCE; /* plaintext */
    cfg.input_roles = roles;
    cfg.n_input_roles = 2;

    memset(&p, 0, sizeof(p));
    rc = voleith_bristol_parse_file(&p, argv[1], &cfg);
    if (rc != 0) {
        fprintf(stderr, "Parse failed: error %d\n", rc);
        return 1;
    }

    /* Validate that the parsed circuit has the AES-128 shape we expect.
     * Without this check, the output-wire loop and fixed-size witness/instance
     * buffers below would read out of bounds on a mismatched circuit file. */
    if (p.n_input_values != 2 || p.input_value_sizes[0] != 128 ||
        p.input_value_sizes[1] != 128 || p.n_output_wires < 128) {
        fprintf(stderr, "not an AES-128 circuit\n");
        voleith_bristol_parsed_free(&p);
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Constrain output wires to expected ciphertext                     */
    /* ------------------------------------------------------------------ */
    /*
     * Bristol byte order: output wire i = bit (i%8) of CT byte (15 - i/8).
     * Using add_const bakes the expected CT into the circuit rather than
     * passing it as a public instance value.
     */
    for (i = 0; i < 128; i++) {
        bit = (CT[15 - i / 8] >> (i % 8)) & 1;
        cw = voleith_circuit_add_const(p.circuit, (uint8_t)bit);
        voleith_circuit_assert_equal(p.circuit, p.output_wires[i], cw);
    }

    params = &voleith_params_em_128f;
    ell = voleith_qs_ell(p.circuit);
    proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu (200 S-boxes x 32, Boyar-Peralta)\n",
           voleith_circuit_and_gate_count(p.circuit));
    printf("  Witness wires:   %zu (128 key bits)\n",
           voleith_circuit_witness_count(p.circuit));
    printf("  Instance wires:  %zu (128 PT bits; CT baked as constants)\n",
           voleith_circuit_instance_count(p.circuit));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ------------------------------------------------------------------ */
    /* 3. Build witness and instance buffers                                */
    /* ------------------------------------------------------------------ */
    /*
     * Bristol wire ordering is reversed: wire 0 = bit 0 of KEY[15].
     * Supply bytes in reverse order so the bit-packed buffer aligns.
     */
    for (i = 0; i < 16; i++)
        witness[i] = KEY[15 - i];
    for (i = 0; i < 16; i++)
        instance[i] = PT[15 - i];

    /* ------------------------------------------------------------------ */
    /* 4. Prove                                                             */
    /* ------------------------------------------------------------------ */
    memset(&proof, 0, sizeof(proof));
    rc = voleith_prove_v2(&proof, params, p.circuit, witness,
                          voleith_circuit_witness_byte_len(p.circuit), instance,
                          voleith_circuit_instance_byte_len(p.circuit), FS_SEED,
                          sizeof(FS_SEED) - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove_v2 failed\n");
        voleith_bristol_parsed_free(&p);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ------------------------------------------------------------------ */
    /* 5. Verify                                                            */
    /* ------------------------------------------------------------------ */
    rc = voleith_verify_v2(&proof, params, p.circuit, instance,
                           voleith_circuit_instance_byte_len(p.circuit),
                           FS_SEED, sizeof(FS_SEED) - 1);
    printf("Verification: %s\n", rc == 0 ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_bristol_parsed_free(&p);
    return (rc == 0) ? 0 : 1;
}
