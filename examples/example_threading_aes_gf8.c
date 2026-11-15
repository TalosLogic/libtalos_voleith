/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_threading_aes_gf8.c - prover speedup from the tau-rep thread pool,
 * on the AES-128 and AES-256 GF(2^8) circuits (FAEST paired-round norm S-box,
 * the smaller/faster default most deployments use).
 *
 * Proves the same statement (knowledge of a key K such that AES(K, PT) = CT)
 * repeatedly, varying only the worker-thread count passed through
 * voleith_gf8_prove_v2_ex's threading options.  The circuit, witness, instance,
 * and domain tag are identical across every run, so the emitted proof is
 * byte-identical regardless of thread count (the test suite asserts that); this
 * program only measures wall-clock prove time.
 *
 * What is parallelized: the prover commits tau VOLE repetitions (tau = 16 for
 * em_128f), and the pool runs those tau jobs across workers.  Speedup is
 * therefore bounded by min(tau, physical cores) and by the fraction of prove
 * time spent in the VOLE commit (BAVC tree + ConvertToVOLE) versus the serial
 * QuickSilver / Fiat-Shamir work that follows.  Verify is not threaded and is
 * not benchmarked here.
 *
 * bench_util.h documents the timing methodology (min = intrinsic cost,
 * median = typical run).  nthreads = 0 requests the physical-core default.
 */

/* POSIX.1-2001 for clock_gettime (via bench_util.h); 200112L (not 199309L) so
 * macOS keeps __DARWIN_C_LEVEL above the guard that would otherwise hide
 * snprintf in <stdio.h>. */
#define _POSIX_C_SOURCE 200112L

#include "aes_norm_gf8_circuit.h"
#include "gf8_circuit.h"
#include "gf8_proof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25

/* Worker counts to sweep; 0 = the physical-core default. */
static const unsigned int THREAD_CONFIGS[] = {1, 2, 4, 8, 0};

static const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

/*
 * Sweep prove across THREAD_CONFIGS for one built circuit + witness/instance
 * and print a worker-count / time / speedup table.  Returns 0 on success.
 */
static int
bench_sweep(const char *label, voleith_gf8_circuit_t *c, const uint8_t *witness,
            const uint8_t *instance)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t wlen = voleith_gf8_circuit_witness_byte_len(c);
    size_t ilen = voleith_gf8_circuit_instance_byte_len(c);
    size_t ell = voleith_gf8_qs_ell(c);
    size_t n_cfg = sizeof(THREAD_CONFIGS) / sizeof(*THREAD_CONFIGS);
    double base_min = 0.0;

    printf("  [%s]  witness %zu B, mul gates %zu, proof %zu B\n", label,
           voleith_gf8_circuit_witness_count(c),
           voleith_gf8_circuit_mul_count(c),
           voleith_gf8_proof_byte_size(params, ell));
    printf("    %-10s %10s %10s %9s\n", "workers", "min(ms)", "median(ms)",
           "speedup");

    for (size_t k = 0; k < n_cfg; k++) {
        unsigned int nt = THREAD_CONFIGS[k];
        voleith_threading_opts_t opts = {.nthreads = nt, .pool = NULL};
        double samples[BENCH_PROVE_ITERS];
        int verify_ok = 1;

        for (int w = 0; w < BENCH_WARMUP; w++) {
            voleith_proof_t p = {0};
            if (voleith_gf8_prove_v2_ex(&p, params, c, witness, wlen, instance,
                                        ilen, label, strlen(label),
                                        &opts) != 0) {
                fprintf(stderr, "%s: prove failed (warmup, n=%u)\n", label, nt);
                return 1;
            }
            voleith_proof_free(&p);
        }
        for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
            voleith_proof_t p = {0};
            uint64_t t0 = bench_now_ns();
            int rc =
                voleith_gf8_prove_v2_ex(&p, params, c, witness, wlen, instance,
                                        ilen, label, strlen(label), &opts);
            uint64_t t1 = bench_now_ns();
            if (rc != 0) {
                fprintf(stderr, "%s: prove failed (n=%u)\n", label, nt);
                return 1;
            }
            samples[i] = (double)(t1 - t0) / 1e6;
            if (i == BENCH_PROVE_ITERS - 1 &&
                voleith_gf8_verify_v2(&p, params, c, instance, ilen, label,
                                      strlen(label)) != 0)
                verify_ok = 0;
            voleith_proof_free(&p);
        }

        bench_stats_t s = bench_compute(samples, BENCH_PROVE_ITERS);
        if (k == 0)
            base_min = s.min;

        char wlabel[12];
        if (nt == 0)
            snprintf(wlabel, sizeof(wlabel), "physical");
        else
            snprintf(wlabel, sizeof(wlabel), "%u", nt);
        printf("    %-10s %10.4f %10.4f %8.2fx%s\n", wlabel, s.min, s.median,
               base_min > 0.0 ? base_min / s.min : 1.0,
               verify_ok ? "" : "  (VERIFY FAIL)");
    }
    printf("\n");
    return 0;
}

/* Build the AES-key_bits GF(2^8) circuit (norm S-box) and sweep it. */
static int
run_aes(const char *label, int key_bits)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t key_bytes = (key_bits == 256) ? 32u : 16u;
    gf8_wire_id key_wires[32], pt_wires[16], ct_computed[16];
    uint8_t ct_ref[16], instance[32];
    uint8_t *witness = NULL;
    size_t wlen;
    int rc = 1;

    if (c == NULL)
        return 1;

    for (size_t i = 0; i < key_bytes; i++)
        key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);

    if (key_bits == 256)
        aes256_norm_gf8_circuit(c, key_wires, pt_wires, ct_computed);
    else
        aes128_norm_gf8_circuit(c, key_wires, pt_wires, ct_computed);

    for (int i = 0; i < 16; i++) {
        gf8_wire_id ct_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_computed[i], ct_inst);
    }

    wlen = voleith_gf8_circuit_witness_byte_len(c);
    witness = calloc(wlen, 1);
    if (witness == NULL)
        goto done;

    if (key_bits == 256)
        aes256_norm_gf8_build_witness(KEY, PT, witness, ct_ref);
    else
        aes128_norm_gf8_build_witness(KEY, PT, witness, ct_ref);

    memcpy(instance, PT, 16);
    memcpy(instance + 16, ct_ref, 16);

    rc = bench_sweep(label, c, witness, instance);

done:
    free(witness);
    voleith_gf8_circuit_free(c);
    return rc;
}

int
main(void)
{
    int rc = 0;

    printf("=== Prover threading speedup: AES norm S-box GF(2^8) "
           "(em_128f, tau=16) ===\n");
    printf("Statement: knowledge of K s.t. AES(K, PT) = CT.  Same proof bytes "
           "at every thread count; only prove wall-clock varies.\n");
    printf("Parallelism is across the tau=16 VOLE repetitions; speedup is "
           "bounded by min(16, physical cores) and the serial tail.\n\n");

    rc |= run_aes("aes128-norm", 128);
    rc |= run_aes("aes256-norm", 256);

    printf("(speedup is relative to the 1-worker run, measured on min.)\n");
    return rc ? 1 : 0;
}
