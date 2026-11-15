/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_threading_verify_aes_gf8.c - VERIFIER-side speedup from the tau-rep
 * thread pool (T3.4a), the verifier twin of example_threading_aes_gf8.c, on the
 * AES-128 and AES-256 GF(2^8) circuits (FAEST paired-round norm S-box).
 *
 * A proof is produced once (single-threaded) and then verified repeatedly,
 * varying only the worker-thread count passed through
 * voleith_gf8_verify_reconstruct_ex's threading options.  What is parallelized
 * is VOLE reconstruct: the tau leaf-commitment loop (BAVC.Reconstruct) and the
 * per-vector ConvertToVOLE loop, mirroring the prover's tau-rep commit.  Phase
 * 2 (the QuickSilver verify / respond) is NOT threaded by T3.4a and is not
 * timed here; this program isolates the reconstruct phase, which is the part
 * that scales.
 *
 * The reconstructed commitment blob is bit-identical regardless of thread count
 * (the determinism column asserts it run-to-run), and the proof verifies end to
 * end once up front (the VERIFY column).  Speedup is bounded by min(tau,
 * physical cores) and the fraction of reconstruct time in the threaded loops.
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

#include <ichor/cpu.h>
#include <ichor/pool.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define BENCH_WARMUP 2
#define BENCH_VERIFY_ITERS 25

/* Worker counts to sweep; 0 = the physical-core default. */
static const unsigned int THREAD_CONFIGS[] = {1, 2, 4, 8, 0};

static const uint8_t KEY[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

/*
 * Prove once (serial), then sweep verify_reconstruct across THREAD_CONFIGS for
 * one built circuit + witness/instance and print a worker-count / time /
 * speedup table.  Returns 0 on success.
 */
static int
bench_sweep(const char *label, voleith_gf8_circuit_t *c, const uint8_t *witness,
            const uint8_t *instance)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t wlen = voleith_gf8_circuit_witness_byte_len(c);
    size_t ilen = voleith_gf8_circuit_instance_byte_len(c);
    size_t ell = voleith_gf8_qs_ell(c);
    size_t blob_sz = voleith_gf8_commit_blob_size(params, c);
    size_t n_cfg = sizeof(THREAD_CONFIGS) / sizeof(*THREAD_CONFIGS);
    double base_min = 0.0;
    int rc = 1;

    voleith_proof_t p = {0};
    voleith_threading_opts_t serial = {.nthreads = 1, .pool = NULL};
    uint8_t *blob = malloc(blob_sz);
    uint8_t *ref_blob = malloc(blob_sz);
    if (!blob || !ref_blob)
        goto done;

    /* Produce one proof single-threaded; reused across every verify below. */
    if (voleith_gf8_prove_v2_ex(&p, params, c, witness, wlen, instance, ilen,
                                label, strlen(label), &serial) != 0) {
        fprintf(stderr, "%s: prove failed\n", label);
        goto done;
    }
    int full_ok = (voleith_gf8_verify_v2(&p, params, c, instance, ilen, label,
                                         strlen(label)) == 0);

    printf("  [%s]  witness %zu B, mul gates %zu, proof %zu B  verify=%s\n",
           label, voleith_gf8_circuit_witness_count(c),
           voleith_gf8_circuit_mul_count(c),
           voleith_gf8_proof_byte_size(params, ell), full_ok ? "OK" : "FAIL");
    printf("    %-10s %10s %10s %9s %6s\n", "workers", "min(ms)", "median(ms)",
           "speedup", "det");

    int have_ref = 0;
    for (size_t k = 0; k < n_cfg; k++) {
        unsigned int nt = THREAD_CONFIGS[k];
        double samples[BENCH_VERIFY_ITERS];
        int det_ok = 1;

        /* One pool per config, reused across the iterations so pool spawn is
         * not timed per call (the per-call create/destroy otherwise dominates a
         * few-ms verify).  Cap at tau: only tau independent reconstruct jobs, so
         * a wider pool idles and over-allocates scratch.  nt == 1 is serial. */
        unsigned int eff = (nt == 0) ? ichor_cpu_physical_cores() : nt;
        if (eff > (unsigned int)params->tau)
            eff = (unsigned int)params->tau;
        struct ichor_pool *pool = NULL;
        if (eff > 1 && ichor_pool_create(&pool, eff) != 0) {
            fprintf(stderr, "%s: pool create failed (n=%u)\n", label, nt);
            goto done;
        }
        voleith_threading_opts_t opts = {.nthreads = pool ? 0 : 1,
                                         .pool = pool};

        for (int w = 0; w < BENCH_WARMUP; w++) {
            voleith_gf8_verifier_reconstruct_t *vc = NULL;
            if (voleith_gf8_verify_reconstruct_ex(&vc, &p, params, c, blob,
                                                  &opts) != 0) {
                fprintf(stderr, "%s: reconstruct failed (warmup, n=%u)\n",
                        label, nt);
                goto done;
            }
            voleith_gf8_verifier_reconstruct_free(vc);
        }
        for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
            voleith_gf8_verifier_reconstruct_t *vc = NULL;
            uint64_t t0 = bench_now_ns();
            int r = voleith_gf8_verify_reconstruct_ex(&vc, &p, params, c, blob,
                                                      &opts);
            uint64_t t1 = bench_now_ns();
            if (r != 0) {
                fprintf(stderr, "%s: reconstruct failed (n=%u)\n", label, nt);
                goto done;
            }
            samples[i] = (double)(t1 - t0) / 1e6;
            /* The reconstructed blob must be identical at every thread count. */
            if (!have_ref) {
                memcpy(ref_blob, blob, blob_sz);
                have_ref = 1;
            } else if (memcmp(blob, ref_blob, blob_sz) != 0) {
                det_ok = 0;
            }
            voleith_gf8_verifier_reconstruct_free(vc);
        }

        bench_stats_t s = bench_compute(samples, BENCH_VERIFY_ITERS);
        if (k == 0)
            base_min = s.min;

        char wlabel[12];
        if (nt == 0)
            snprintf(wlabel, sizeof(wlabel), "physical");
        else
            snprintf(wlabel, sizeof(wlabel), "%u", nt);
        printf("    %-10s %10.4f %10.4f %8.2fx %6s\n", wlabel, s.min, s.median,
               base_min > 0.0 ? base_min / s.min : 1.0, det_ok ? "ok" : "DIFF");
        if (pool)
            ichor_pool_destroy(pool);
    }
    printf("\n");
    rc = 0;

done:
    voleith_proof_free(&p);
    free(blob);
    free(ref_blob);
    return rc;
}

/* Build the AES-key_bits GF(2^8) circuit (norm S-box) and sweep verify. */
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

    printf("=== Verifier threading speedup (T3.4a): AES norm S-box GF(2^8) "
           "(em_128f, tau=16) ===\n");
    printf(
        "One proof, verified at every thread count.  Timed: VOLE "
        "reconstruct (tau leaf-commit + ConvertToVOLE).  QuickSilver respond "
        "is serial and not timed.\n");
    printf("Reconstruct is bit-identical at every thread count (det column); "
           "speedup is bounded by min(16, physical cores) and the serial "
           "tail.\n\n");

    rc |= run_aes("aes128-norm", 128);
    rc |= run_aes("aes256-norm", 256);

    printf("(speedup is relative to the 1-worker run, measured on min.)\n");
    return rc ? 1 : 0;
}
