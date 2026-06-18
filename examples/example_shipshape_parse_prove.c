/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_shipshape_parse_prove.c - end-to-end Shipshape pipeline (W7.2 of
 * docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md).
 *
 * Loads a `.ship` file, parses it to a GF(2^8) circuit, generates the full
 * witness from the external input, then proves and verifies with the
 * GF(2^8) VOLEitH backend.  The default circuit is the shipped
 * tests/data/shipshape/aes128_key_knowledge.ship: prove knowledge of an
 * AES-128 key K with AES_K(pt) = ct for public (pt, ct).  Pass a path as
 * argv[1] to load a different file (it must have the same witness / instance
 * layout: a 16-byte WITNESS key, then INSTANCE pt[16] and ct[16]).
 *
 *   ./example_shipshape_parse_prove [path/to/file.ship]
 */

#include "aes.h"
#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "shipshape.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VOLEITH_SHIPSHAPE_DATA_DIR
#define VOLEITH_SHIPSHAPE_DATA_DIR "tests/data/shipshape"
#endif

/* Demo inputs: a fixed key and plaintext (any values work). */
static const uint8_t KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
static const uint8_t PT[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

int
main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1]
                                  : VOLEITH_SHIPSHAPE_DATA_DIR
                           "/aes128_key_knowledge.ship";
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_aes_ctx_t aes;
    voleith_proof_t proof;
    uint8_t ct[16];
    uint8_t instance[32]; /* pt || ct, in declaration order */
    uint8_t fs_seed[16];
    uint8_t *witness = NULL;
    size_t witness_len = 0;
    size_t ext_len, inst_count;
    int rc = 1;
    int r;

    printf("Shipshape parse + prove example\n");
    printf("  file: %s\n\n", path);

    /* 1. Parse the .ship file into a GF(2^8) circuit. */
    r = voleith_shipshape_parse_file(&p, path, NULL);
    if (r != 0 || p.circuit == NULL) {
        fprintf(stderr, "parse failed (%d): %s\n", r, path);
        return 1;
    }

    printf("Parsed circuit:\n");
    printf("  wires:        %zu\n", voleith_gf8_circuit_wire_count(p.circuit));
    printf("  witness:      %zu\n",
           voleith_gf8_circuit_witness_count(p.circuit));
    printf("  instance:     %zu\n",
           voleith_gf8_circuit_instance_count(p.circuit));
    printf("  gates:        %zu\n", voleith_gf8_circuit_gate_count(p.circuit));
    printf("  nonlinear mul:%zu\n", voleith_gf8_circuit_mul_count(p.circuit));
    printf("  constraints:  %zu\n\n",
           voleith_gf8_circuit_constraint_count(p.circuit));

    /* Confirm the file matches the AES-128 key-knowledge layout. */
    ext_len = voleith_shipshape_external_witness_len(&p);
    inst_count = voleith_gf8_circuit_instance_count(p.circuit);
    if (ext_len != 16 || inst_count != 32) {
        fprintf(stderr,
                "circuit layout is not AES-128 key knowledge "
                "(external witness %zu != 16 or instance %zu != 32)\n",
                ext_len, inst_count);
        goto out;
    }

    /* 2. Compute the public ciphertext ct = AES-128_K(pt). */
    if (voleith_aes_key_expand(&aes, KEY, 128) != 0) {
        fprintf(stderr, "AES key expansion failed\n");
        goto out;
    }
    voleith_aes_encrypt(&aes, ct, PT);
    voleith_aes_ctx_clear(&aes);
    memcpy(instance, PT, 16);
    memcpy(instance + 16, ct, 16);

    /* 3. Generate the full witness from the external input (the key). */
    r = voleith_shipshape_witness_gen(&p, KEY, 16, instance, 32,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &witness, &witness_len);
    if (r != 0) {
        fprintf(stderr, "witness generation failed (%d)\n", r);
        goto out;
    }
    printf("Generated witness: %zu bytes\n", witness_len);

    /* 4. Prove. */
    memset(fs_seed, 0x5A, sizeof(fs_seed));
    r = voleith_gf8_prove_v2(&proof, params, p.circuit, witness, witness_len,
                             instance, 32, fs_seed, sizeof(fs_seed));
    if (r != 0) {
        fprintf(stderr, "prove failed (%d)\n", r);
        goto out_witness;
    }
    printf("Proof:             %zu bytes\n\n", proof.len);

    /* 5. Verify. */
    r = voleith_gf8_verify_v2(&proof, params, p.circuit, instance, 32, fs_seed,
                              sizeof(fs_seed));
    printf("Verification: %s\n", r == 0 ? "PASS" : "FAIL");
    rc = (r == 0) ? 0 : 1;

    voleith_proof_free(&proof);

out_witness:
    voleith_secure_zero(witness, witness_len);
    free(witness);
out:
    voleith_shipshape_parsed_free(&p);
    return rc;
}
