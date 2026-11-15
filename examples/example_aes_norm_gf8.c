/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_aes_norm_gf8.c - frozen vs norm AES S-box, side by side.
 *
 * Proves "I know K such that AES(K, PT) = CT" with the GF(2^8) circuit, once
 * with the frozen per-call S-box and once with the FAEST paired-round norm
 * S-box, for AES-128 and AES-256.  The norm form commits ~25% fewer witness
 * bytes on the data path (the key schedule stays frozen, so the overall
 * witness ratio is ~0.8, not 0.75), and its degree-3 packing also lowers the
 * verify-side constraint count.  Both forms produce the identical ciphertext;
 * only the proof-side witness/circuit differ.
 *
 * Run it to see the witness-byte, proof-size, and prove/verify-time deltas on
 * your machine.  bench_util.h documents the timing methodology.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC (via bench_util.h) */
#define _POSIX_C_SOURCE 199309L

#include "aes_gf8_circuit.h"
#include "aes_norm_gf8_circuit.h"
#include "gf8_circuit.h"
#include "gf8_proof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25
#define BENCH_VERIFY_ITERS 100

/* Arbitrary key/plaintext; the ciphertext is taken from build_witness, so no
 * hardcoded KAT is needed (output parity vs NIST is covered by the tests). */
static const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

/* Bench one built circuit + witness/instance and print size + timing. */
static int
bench_report(const char *label, voleith_gf8_circuit_t *c,
             const uint8_t *witness, const uint8_t *instance)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t ell = voleith_gf8_qs_ell(c);
    size_t wlen = voleith_gf8_circuit_witness_byte_len(c);
    size_t ilen = voleith_gf8_circuit_instance_byte_len(c);
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};
    int verify_ok = 1;

    printf("  [%s]\n", label);
    printf("    witness bytes:  %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("    mul gates:      %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("    ell:            %zu\n", ell);
    printf("    proof bytes:    %zu\n",
           voleith_gf8_proof_byte_size(params, ell));

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance, ilen,
                                 label, strlen(label)) != 0) {
            fprintf(stderr, "prove failed (warmup)\n");
            return 1;
        }
        voleith_gf8_verify_v2(&p, params, c, instance, ilen, label,
                              strlen(label));
        voleith_proof_free(&p);
    }

    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance,
                                      ilen, label, strlen(label));
        uint64_t t1 = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "prove failed\n");
            return 1;
        }
        prove_ms[i] = (double)(t1 - t0) / 1e6;
        if (i == BENCH_PROVE_ITERS - 1)
            kept = p;
        else
            voleith_proof_free(&p);
    }
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_verify_v2(&kept, params, c, instance, ilen, label,
                                       strlen(label));
        uint64_t t1 = bench_now_ns();
        if (rc != 0)
            verify_ok = 0;
        verify_ms[i] = (double)(t1 - t0) / 1e6;
    }

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);
    printf("    proof size:     %zu bytes (verify %s)\n", kept.len,
           verify_ok ? "PASS" : "FAIL");
    bench_print("    prove", ps);
    bench_print("    verify", vs);
    printf("\n");

    voleith_proof_free(&kept);
    return verify_ok ? 0 : 1;
}

/* key_bits is 128 or 256; norm selects the paired-round S-box data path. */
static int
run_aes(const char *label, int key_bits, int norm)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t key_bytes = (key_bits == 256) ? 32u : 16u;
    gf8_wire_id key_wires[32];
    gf8_wire_id pt_wires[16];
    gf8_wire_id ct_computed[16];
    uint8_t witness[AES256_NORM_GF8_WITNESS_BYTES > 512
                        ? AES256_NORM_GF8_WITNESS_BYTES
                        : 512];
    uint8_t ct_ref[16];
    uint8_t instance[32];
    int rc;

    if (c == NULL)
        return 1;

    for (size_t i = 0; i < key_bytes; i++)
        key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);

    if (key_bits == 256) {
        if (norm)
            aes256_norm_gf8_circuit(c, key_wires, pt_wires, ct_computed);
        else
            aes256_gf8_circuit(c, key_wires, pt_wires, ct_computed);
    } else {
        if (norm)
            aes128_norm_gf8_circuit(c, key_wires, pt_wires, ct_computed);
        else
            aes128_gf8_circuit(c, key_wires, pt_wires, ct_computed);
    }

    for (int i = 0; i < 16; i++) {
        gf8_wire_id ct_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_computed[i], ct_inst);
    }

    if (key_bits == 256) {
        if (norm)
            aes256_norm_gf8_build_witness(KEY, PT, witness, ct_ref);
        else
            aes256_gf8_build_witness(KEY, PT, witness, ct_ref);
    } else {
        if (norm)
            aes128_norm_gf8_build_witness(KEY, PT, witness, ct_ref);
        else
            aes128_gf8_build_witness(KEY, PT, witness, ct_ref);
    }

    memcpy(instance, PT, 16);
    memcpy(instance + 16, ct_ref, 16);

    rc = bench_report(label, c, witness, instance);
    voleith_gf8_circuit_free(c);
    return rc;
}

int
main(void)
{
    int rc = 0;

    printf("=== AES frozen vs norm S-box (GF(2^8) circuit) ===\n");
    printf("Statement: knowledge of K s.t. AES(K, PT) = CT.  Same CT both "
           "ways; only the witness/circuit differ.\n\n");

    printf("AES-128:\n");
    rc |= run_aes("aes128-frozen", 128, 0);
    rc |= run_aes("aes128-norm", 128, 1);

    printf("AES-256:\n");
    rc |= run_aes("aes256-frozen", 256, 0);
    rc |= run_aes("aes256-norm", 256, 1);

    return rc ? 1 : 0;
}
