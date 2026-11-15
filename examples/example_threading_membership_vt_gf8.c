/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_threading_membership_vt_gf8.c - prover speedup from the tau-rep
 * thread pool on a real depth-10 Merkle ring-membership proof, across the
 * leaf/node node-hash choices a deployment would actually pick.  Uses the FAEST
 * paired-round norm S-box node hashes (the smaller/faster default).
 *
 * The circuit (prove "I am a member of the tree with root R" without revealing
 * which leaf) is built on the node_hash_vt layer, which lets the LEAF hash
 * (owf_hash) and internal-NODE hash (tree_hash) be chosen independently.  For
 * each (leaf, node) configuration the same proof is produced repeatedly,
 * varying only the worker-thread count passed through
 * voleith_gf8_prove_v2_ex's threading options; the emitted proof is
 * byte-identical at every thread count (the test suite asserts that), so this
 * program only measures wall-clock prove time.
 *
 * Four configurations (leaf / node), heaviest last:
 *   1. Hirose / Hirose          one AES-based primitive, 128-bit CR.
 *   2. Grostl-256 / Hirose      wide cheap leaf, cheap fixed node; 128-bit CR.
 *   3. Grostl-256 / Grostl-256  all-Grostl, 128-bit CR (avoids Hirose posture).
 *   4. Grostl-512 / Grostl-512  the only 256-bit-CR config here (64-byte nodes).
 *
 * Heavier circuits spend proportionally more time in the threaded VOLE commit,
 * so the speedup trend across these four is itself informative.  Parallelism is
 * across the tau=16 VOLE repetitions; speedup is bounded by min(16, cores) and
 * the serial QuickSilver / Fiat-Shamir tail.  bench_util.h documents the timing
 * methodology; nthreads = 0 requests the physical-core default.
 */

/* POSIX.1-2001 for clock_gettime (via bench_util.h); 200112L (not 199309L) so
 * macOS keeps __DARWIN_C_LEVEL above the guard that would otherwise hide
 * snprintf in <stdio.h>. */
#define _POSIX_C_SOURCE 200112L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"
#include "rs_membership_gf8.h"
#include "rs_membership_gf8_circuit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define DEPTH 10
#define N_MEMBERS 8u /* real members; the rest of the 2^10 tree is sentinel. */
#define SIGNER 5u

/* Depth-10 proofs are heavy, so fewer iterations per thread count. */
#define BENCH_WARMUP 1
#define BENCH_PROVE_ITERS 5

/* Worker counts to sweep; 0 = the physical-core default. */
static const unsigned int THREAD_CONFIGS[] = {1, 2, 4, 8, 0};

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

    printf("    [%s]  witness %zu B, mul gates %zu, proof %zu B\n", label,
           voleith_gf8_circuit_witness_count(c),
           voleith_gf8_circuit_mul_count(c),
           voleith_gf8_proof_byte_size(params, ell));
    printf("      %-10s %10s %10s %9s\n", "workers", "min(ms)", "median(ms)",
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
        printf("      %-10s %10.4f %10.4f %8.2fx%s\n", wlabel, s.min, s.median,
               base_min > 0.0 ? base_min / s.min : 1.0,
               verify_ok ? "" : "  (VERIFY FAIL)");
    }
    printf("\n");
    return 0;
}

/*
 * Build the depth-DEPTH membership circuit for (tree_vt = node hash,
 * owf_vt = leaf hash; NULL leaf means the leaf reuses the node hash) and sweep
 * prove across thread counts.
 */
static int
run_config(const char *label, const voleith_node_hash_vt *tree_vt,
           const voleith_node_hash_vt *owf_vt, size_t sk_bytes)
{
    voleith_rs_membership_config_t cfg;
    voleith_rs_membership_layout_t layout;
    voleith_gf8_circuit_t *c = NULL;
    size_t W = tree_vt->node_bytes;
    uint8_t *sks = NULL, *root = NULL, *sib = NULL, *witness = NULL,
            *instance = NULL;
    voleith_rs_membership_path_t *paths = NULL;
    int rc = 1;

    cfg.tree_hash = tree_vt;
    cfg.owf_hash = owf_vt;
    cfg.sk_bytes = sk_bytes;
    cfg.depth_m = DEPTH;
    cfg.depth_r = 0;

    if (voleith_rs_membership_validate(&cfg) != 0) {
        fprintf(stderr, "%s: config rejected\n", label);
        return 1;
    }

    sks = calloc(N_MEMBERS * sk_bytes, 1);
    root = calloc(W, 1);
    paths = calloc(N_MEMBERS, sizeof(*paths));
    sib = calloc(N_MEMBERS * (size_t)DEPTH * W, 1);
    if (!sks || !root || !paths || !sib)
        goto done;
    for (size_t i = 0; i < N_MEMBERS; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    if (voleith_rsv1_ring_build(&cfg, sks, N_MEMBERS, root, paths, sib) != 0) {
        fprintf(stderr, "%s: ring_build failed\n", label);
        goto done;
    }

    c = voleith_gf8_circuit_new();
    if (c == NULL || voleith_rs_membership_build_circuit(c, &cfg, &layout) != 0)
        goto done;

    witness = calloc(layout.witness_bytes, 1);
    instance = calloc(layout.instance_bytes, 1);
    if (!witness || !instance)
        goto done;
    if (voleith_rs_membership_pack_witness(&cfg, &layout,
                                           sks + SIGNER * sk_bytes,
                                           &paths[SIGNER], NULL, witness) != 0)
        goto done;
    memcpy(instance + layout.inst_root_off, root, layout.inst_root_bytes);

    rc = bench_sweep(label, c, witness, instance);

done:
    if (c != NULL)
        voleith_gf8_circuit_free(c);
    free(sks);
    free(root);
    free(paths);
    free(sib);
    free(witness);
    free(instance);
    return rc;
}

int
main(void)
{
    int rc = 0;

    printf("=== Prover threading speedup: Merkle membership (norm S-box), "
           "depth %d (em_128f, tau=16) ===\n",
           DEPTH);
    printf(
        "Same proof bytes at every thread count; only prove wall-clock "
        "varies.  Four leaf/node node-hash configurations, heaviest last.\n");
    printf("Parallelism is across the tau=16 VOLE repetitions; speedup is "
           "bounded by min(16, physical cores) and the serial tail.\n\n");

    printf("1. Hirose / Hirose (128-bit CR):\n");
    rc |= run_config("hirose/hirose", &voleith_node_hash_hirose_norm, NULL, 32);

    printf("2. Grostl-256 / Hirose (wide cheap leaf, cheap fixed node; "
           "128-bit CR):\n");
    rc |= run_config("grostl256/hirose", &voleith_node_hash_hirose_norm,
                     &voleith_node_hash_grostl256_fixed_norm, 32);

    printf("3. Grostl-256 / Grostl-256 (all-Grostl, 128-bit CR):\n");
    rc |= run_config("grostl256/grostl256",
                     &voleith_node_hash_grostl256_fixed_norm, NULL, 32);

    printf("4. Grostl-512 / Grostl-512 (256-bit CR):\n");
    rc |= run_config("grostl512/grostl512",
                     &voleith_node_hash_grostl512_fixed_norm, NULL, 64);

    printf("(speedup is relative to the 1-worker run, measured on min.)\n");
    return rc ? 1 : 0;
}
