/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_bench_release.c - release benchmark harness for the 1.12.0 notes.
 *
 * Produces two tables over a fixed set of four frozen (non-norm) proofs:
 *
 *   1. AES-128            basic key-knowledge proof, 1:1 with FAEST.
 *   2. AES-256            the larger basic proof.
 *   3. Merkle membership  depth-10, Hirose-fixed32 leaf + node (cheapest
 *                         128-bit CR, inputs up to 32 bytes).
 *   4. Merkle membership  depth-10, Grostl-256-fixed leaf + node (128-bit CR,
 *                         the choice once inputs exceed 32 bytes; no keyed
 *                         cipher, so no Hirose-style quantum surface).
 *
 * SPEED table (prove + verify, min/median ms, worker-count sweep): the same
 * source compiles two ways.
 *   - Built in the current tree it first prints a `serial` row that calls the
 *     plain (non-_ex) _v2 path (the true single-thread reference, and the 1:1
 *     match for the v1.11.0 column), then threads via the _ex entry points and
 *     sweeps 1 -> up to 16 workers (or VOLEITH_BENCH_MAX_WORKERS if set),
 *     capped at the physical-core count. Set VOLEITH_BENCH_MAX_WORKERS to one
 *     NUMA node's core count (and taskset onto it) for a pinned single-socket
 *     run, since the core query counts the whole machine. The sweep speedups
 *     are measured against the `serial` row, so the small _ex pool-setup cost
 *     at one worker does not inflate them.
 *   - Built in a v1.11.0 worktree it has no threading API, so it falls back to
 *     a single serial run via the plain _v2 entry points. That row is the
 *     "v1.11.0" baseline column of the release table.
 *   Detection is automatic: v1.11.0 pins ichor 1.1.0, which has no
 *   <ichor/pool.h>. Define VOLEITH_BENCH_BASELINE to force the serial path.
 *
 * SIZE table (current tree only): the same four circuits built frozen and with
 * the FAEST norm S-box, reporting ell (VOLE slots) and proof bytes, so the
 * per-circuit proof-size saving is visible. The saving grows with how
 * S-box-dominated the circuit is (small on AES-128, where the key schedule
 * stays frozen and fixed proof overhead is a larger fraction; largest on the
 * Grostl-256 depth-10 tree, which is almost all S-boxes).
 *
 * The emitted proof is byte-identical at every worker count, so a threaded run
 * proves/verifies the same bytes as serial; the "ok" field flags any failure.
 *
 * bench_util.h documents the timing methodology (min = intrinsic cost on a
 * one-sided-slow noise floor; median = typical run). Pin the process to cores
 * and quiesce the host; see docs/BENCHMARKS.md for the full run recipe.
 */

/* POSIX.1-2001 for clock_gettime (via bench_util.h); 200112L (not 199309L) so
 * macOS keeps __DARWIN_C_LEVEL above the guard that would otherwise hide
 * snprintf in <stdio.h>. */
#define _POSIX_C_SOURCE 200112L

#include "aes_gf8_circuit.h"
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

/*
 * BENCH_FULL = 1 selects the threaded + norm-size build (current tree);
 * BENCH_FULL = 0 selects the serial, frozen-only baseline (v1.11.0 worktree).
 * v1.11.0 pins ichor 1.1.0, which does not ship <ichor/pool.h>, so the absence
 * of that header is the auto-detect. VOLEITH_BENCH_BASELINE forces the baseline.
 */
#if defined(VOLEITH_BENCH_BASELINE)
#define BENCH_FULL 0
#elif defined(__has_include) && __has_include(<ichor/pool.h>)
#define BENCH_FULL 1
#else
#define BENCH_FULL 0
#endif

#if BENCH_FULL
#include "aes_norm_gf8_circuit.h"

#include <ichor/cpu.h>
#include <ichor/pool.h>

/* Worker counts to sweep; 0 = min(16, physical cores). Counts above the host's
 * physical-core count are skipped. */
static const unsigned int THREAD_CONFIGS[] = {1, 2, 4, 8, 16, 0};
#endif

#define DEPTH 10
#define N_MEMBERS 8u
#define SIGNER 5u

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 10
#define BENCH_VERIFY_ITERS 10

static const uint8_t AES_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
static const uint8_t AES_PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};

/*
 * Build the frozen (norm == 0) or norm (norm == 1) AES-key_bits circuit. When
 * w_out is non-NULL, also build the witness and instance. Returns 0 on success.
 * The norm builders exist only in the current tree (BENCH_FULL), so a norm
 * request is rejected in a baseline build.
 */
static int
build_aes(int key_bits, int norm, const voleith_params_t **params_out,
          voleith_gf8_circuit_t **c_out, uint8_t **w_out, size_t *wlen_out,
          uint8_t **inst_out, size_t *ilen_out)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    size_t key_bytes = (key_bits == 256) ? 32u : 16u;
    gf8_wire_id key_w[32], pt_w[16], ct_w[16];

    if (c == NULL)
        return 1;

#if !BENCH_FULL
    if (norm)
        return 1;
#endif

    for (size_t i = 0; i < key_bytes; i++)
        key_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_w[i] = voleith_gf8_add_instance(c);

    if (norm) {
#if BENCH_FULL
        if (key_bits == 256)
            aes256_norm_gf8_circuit(c, key_w, pt_w, ct_w);
        else
            aes128_norm_gf8_circuit(c, key_w, pt_w, ct_w);
#endif
    } else {
        if (key_bits == 256)
            aes256_gf8_circuit(c, key_w, pt_w, ct_w);
        else
            aes128_gf8_circuit(c, key_w, pt_w, ct_w);
    }

    for (int i = 0; i < 16; i++) {
        gf8_wire_id ci = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_w[i], ci);
    }

    *params_out =
        (key_bits == 256) ? &voleith_params_em_256f : &voleith_params_em_128f;

    if (w_out != NULL) {
        size_t wlen = voleith_gf8_circuit_witness_byte_len(c);
        size_t ilen = voleith_gf8_circuit_instance_byte_len(c);
        uint8_t *w = calloc(wlen, 1);
        uint8_t *inst = calloc(ilen, 1);
        uint8_t ct_ref[16];

        if (w == NULL || inst == NULL) {
            free(w);
            free(inst);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        if (norm) {
#if BENCH_FULL
            if (key_bits == 256)
                aes256_norm_gf8_build_witness(AES_KEY, AES_PT, w, ct_ref);
            else
                aes128_norm_gf8_build_witness(AES_KEY, AES_PT, w, ct_ref);
#endif
        } else {
            if (key_bits == 256)
                aes256_gf8_build_witness(AES_KEY, AES_PT, w, ct_ref);
            else
                aes128_gf8_build_witness(AES_KEY, AES_PT, w, ct_ref);
        }
        memcpy(inst, AES_PT, 16);
        memcpy(inst + 16, ct_ref, 16);
        *w_out = w;
        *wlen_out = wlen;
        *inst_out = inst;
        *ilen_out = ilen;
    }

    *c_out = c;
    return 0;
}

/*
 * Build a depth-DEPTH secret-dir membership circuit over tree_vt (leaf reuses
 * the node hash). When w_out is non-NULL, run the ring build and pack the
 * signer's witness + instance; temporaries are freed before returning. Returns
 * 0 on success.
 */
static int
build_membership(const voleith_node_hash_vt *tree_vt, size_t sk_bytes,
                 voleith_gf8_circuit_t **c_out, uint8_t **w_out,
                 size_t *wlen_out, uint8_t **inst_out, size_t *ilen_out)
{
    voleith_rs_membership_config_t cfg;
    voleith_rs_membership_layout_t layout;
    voleith_gf8_circuit_t *c = NULL;
    uint8_t *sks = NULL, *root = NULL, *sib = NULL, *witness = NULL,
            *instance = NULL;
    voleith_rs_membership_path_t *paths = NULL;
    size_t W = tree_vt->node_bytes;
    int rc = 1;

    cfg.tree_hash = tree_vt;
    cfg.owf_hash = NULL;
    cfg.sk_bytes = sk_bytes;
    cfg.depth_m = DEPTH;
    cfg.depth_r = 0;

    if (voleith_rs_membership_validate(&cfg) != 0)
        return 1;

    c = voleith_gf8_circuit_new();
    if (c == NULL || voleith_rs_membership_build_circuit(c, &cfg, &layout) != 0)
        goto done;

    if (w_out == NULL) {
        /* Circuit-only (size table): no witness needed. */
        *c_out = c;
        return 0;
    }

    sks = calloc(N_MEMBERS * sk_bytes, 1);
    root = calloc(W, 1);
    paths = calloc(N_MEMBERS, sizeof(*paths));
    sib = calloc(N_MEMBERS * (size_t)DEPTH * W, 1);
    witness = calloc(layout.witness_bytes, 1);
    instance = calloc(layout.instance_bytes, 1);
    if (!sks || !root || !paths || !sib || !witness || !instance)
        goto done;

    for (size_t i = 0; i < N_MEMBERS; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    if (voleith_rsv1_ring_build(&cfg, sks, N_MEMBERS, root, paths, sib) != 0)
        goto done;
    if (voleith_rs_membership_pack_witness(&cfg, &layout,
                                           sks + SIGNER * sk_bytes,
                                           &paths[SIGNER], NULL, witness) != 0)
        goto done;
    memcpy(instance + layout.inst_root_off, root, layout.inst_root_bytes);

    *c_out = c;
    *w_out = witness;
    *wlen_out = layout.witness_bytes;
    *inst_out = instance;
    *ilen_out = layout.instance_bytes;
    witness = NULL;
    instance = NULL;
    c = NULL;
    rc = 0;

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

/*
 * Prove + verify timing for one built circuit. In the full build this sweeps
 * worker counts through the _ex entry points; in the baseline build it does a
 * single serial run through the plain _v2 entry points. Returns 0 on success.
 */
static int
run_speed(const char *label, const voleith_params_t *params,
          voleith_gf8_circuit_t *c, const uint8_t *witness, size_t wlen,
          const uint8_t *instance, size_t ilen)
{
    size_t ell = voleith_gf8_qs_ell(c);
    voleith_proof_t rp = {0};
    int rc = 1;

    printf("  [%s]  witness %zu B, mul gates %zu, proof %zu B\n", label,
           voleith_gf8_circuit_witness_count(c),
           voleith_gf8_circuit_mul_count(c),
           voleith_gf8_proof_byte_size(params, ell));
    printf("    %-10s %10s %10s %10s %10s %8s %8s %4s\n", "workers",
           "prove_min", "prove_med", "vrfy_min", "vrfy_med", "P-x", "V-x",
           "ok");

#if BENCH_FULL
    unsigned int phys = ichor_cpu_physical_cores();
    size_t n_cfg = sizeof(THREAD_CONFIGS) / sizeof(*THREAD_CONFIGS);
    double p_base = 0.0, v_base = 0.0;
    unsigned int max_workers = 16;
    unsigned int cap;
    const char *mw_env = getenv("VOLEITH_BENCH_MAX_WORKERS");

    /*
     * ichor_cpu_physical_cores() counts the whole machine, so on a multi-socket
     * host it cannot tell the run was pinned (taskset) to one socket. Cap the
     * worker sweep with VOLEITH_BENCH_MAX_WORKERS (default 16) so one binary
     * serves both a laptop and a single NUMA node: set it to that node's
     * physical-core count and taskset the run onto those cores, so the sweep
     * never oversubscribes the pinned set.
     */
    if (mw_env != NULL) {
        unsigned long v = strtoul(mw_env, NULL, 10);
        if (v >= 1 && v <= 1024)
            max_workers = (unsigned int)v;
    }
    cap = (phys != 0 && phys < max_workers) ? phys : max_workers;

    /*
     * True single-thread reference via the plain (non-_ex) entry points: the
     * path a serial caller actually uses, and the apples-to-apples match for
     * the v1.11.0 column (which has only the plain path). The _ex sweep rows
     * below take their speedup against this, not against the _ex 1-worker row,
     * so the _ex-at-1-worker pool setup cost does not inflate the ratios. The
     * reference proof is produced here and reused for every verify below.
     */
    {
        double ps0[BENCH_PROVE_ITERS], vs0[BENCH_VERIFY_ITERS];
        bench_stats_t P0, V0;
        int ok0 = 1;

        for (int w = 0; w < BENCH_WARMUP; w++) {
            voleith_proof_t p = {0};
            if (voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance,
                                     ilen, label, strlen(label)) != 0)
                ok0 = 0;
            voleith_proof_free(&p);
        }
        for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
            voleith_proof_t p = {0};
            uint64_t t0 = bench_now_ns();
            int r = voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance,
                                         ilen, label, strlen(label));
            uint64_t t1 = bench_now_ns();
            if (r != 0)
                ok0 = 0;
            ps0[i] = (double)(t1 - t0) / 1e6;
            voleith_proof_free(&p);
        }

        if (voleith_gf8_prove_v2(&rp, params, c, witness, wlen, instance, ilen,
                                 label, strlen(label)) != 0) {
            fprintf(stderr, "%s: reference prove failed\n", label);
            goto done;
        }
        for (int w = 0; w < BENCH_WARMUP; w++)
            if (voleith_gf8_verify_v2(&rp, params, c, instance, ilen, label,
                                      strlen(label)) != 0)
                ok0 = 0;
        for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
            uint64_t t0 = bench_now_ns();
            int r = voleith_gf8_verify_v2(&rp, params, c, instance, ilen, label,
                                          strlen(label));
            uint64_t t1 = bench_now_ns();
            if (r != 0)
                ok0 = 0;
            vs0[i] = (double)(t1 - t0) / 1e6;
        }

        P0 = bench_compute(ps0, BENCH_PROVE_ITERS);
        V0 = bench_compute(vs0, BENCH_VERIFY_ITERS);
        p_base = P0.min;
        v_base = V0.min;
        printf("    %-10s %10.4f %10.4f %10.4f %10.4f %8s %8s %4s\n", "serial",
               P0.min, P0.median, V0.min, V0.median, "-", "-",
               ok0 ? "ok" : "ERR");
    }

    for (size_t k = 0; k < n_cfg; k++) {
        unsigned int nt = THREAD_CONFIGS[k];
        unsigned int eff;
        struct ichor_pool *pool = NULL;
        voleith_threading_opts_t opts;
        double ps[BENCH_PROVE_ITERS], vs[BENCH_VERIFY_ITERS];
        bench_stats_t P, V;
        char wl[16];
        int ok = 1;

        if (nt != 0 && nt > cap)
            continue;
        eff = (nt == 0) ? cap : nt;
        if (eff > 1 && ichor_pool_create(&pool, eff) != 0) {
            fprintf(stderr, "%s: pool create failed (n=%u)\n", label, eff);
            goto done;
        }
        opts.nthreads = pool ? 0 : 1;
        opts.pool = pool;

        for (int w = 0; w < BENCH_WARMUP; w++) {
            voleith_proof_t p = {0};
            if (voleith_gf8_prove_v2_ex(&p, params, c, witness, wlen, instance,
                                        ilen, label, strlen(label), &opts) != 0)
                ok = 0;
            voleith_proof_free(&p);
        }
        for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
            voleith_proof_t p = {0};
            uint64_t t0 = bench_now_ns();
            int r =
                voleith_gf8_prove_v2_ex(&p, params, c, witness, wlen, instance,
                                        ilen, label, strlen(label), &opts);
            uint64_t t1 = bench_now_ns();
            if (r != 0)
                ok = 0;
            ps[i] = (double)(t1 - t0) / 1e6;
            voleith_proof_free(&p);
        }

        for (int w = 0; w < BENCH_WARMUP; w++)
            if (voleith_gf8_verify_v2_ex(&rp, params, c, instance, ilen, label,
                                         strlen(label), &opts) != 0)
                ok = 0;
        for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
            uint64_t t0 = bench_now_ns();
            int r = voleith_gf8_verify_v2_ex(&rp, params, c, instance, ilen,
                                             label, strlen(label), &opts);
            uint64_t t1 = bench_now_ns();
            if (r != 0)
                ok = 0;
            vs[i] = (double)(t1 - t0) / 1e6;
        }

        P = bench_compute(ps, BENCH_PROVE_ITERS);
        V = bench_compute(vs, BENCH_VERIFY_ITERS);
        if (nt == 0)
            snprintf(wl, sizeof(wl), "cap(%u)", eff);
        else
            snprintf(wl, sizeof(wl), "%u", nt);
        printf("    %-10s %10.4f %10.4f %10.4f %10.4f %7.2fx %7.2fx %4s\n", wl,
               P.min, P.median, V.min, V.median,
               p_base > 0.0 ? p_base / P.min : 1.0,
               v_base > 0.0 ? v_base / V.min : 1.0, ok ? "ok" : "ERR");
        if (pool)
            ichor_pool_destroy(pool);
    }
    rc = 0;
#else
    double ps[BENCH_PROVE_ITERS], vs[BENCH_VERIFY_ITERS];
    bench_stats_t P, V;
    int ok = 1;

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance, ilen,
                                 label, strlen(label)) != 0)
            ok = 0;
        voleith_proof_free(&p);
    }
    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int r = voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance,
                                     ilen, label, strlen(label));
        uint64_t t1 = bench_now_ns();
        if (r != 0)
            ok = 0;
        ps[i] = (double)(t1 - t0) / 1e6;
        voleith_proof_free(&p);
    }

    if (voleith_gf8_prove_v2(&rp, params, c, witness, wlen, instance, ilen,
                             label, strlen(label)) != 0)
        ok = 0;
    for (int w = 0; w < BENCH_WARMUP; w++)
        if (voleith_gf8_verify_v2(&rp, params, c, instance, ilen, label,
                                  strlen(label)) != 0)
            ok = 0;
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int r = voleith_gf8_verify_v2(&rp, params, c, instance, ilen, label,
                                      strlen(label));
        uint64_t t1 = bench_now_ns();
        if (r != 0)
            ok = 0;
        vs[i] = (double)(t1 - t0) / 1e6;
    }

    P = bench_compute(ps, BENCH_PROVE_ITERS);
    V = bench_compute(vs, BENCH_VERIFY_ITERS);
    printf("    %-10s %10.4f %10.4f %10.4f %10.4f %8s %8s %4s\n", "1(serial)",
           P.min, P.median, V.min, V.median, "-", "-", ok ? "ok" : "ERR");
    rc = 0;
    goto done;
#endif

done:
    voleith_proof_free(&rp);
    return rc;
}

/* Run the speed table for one AES circuit. */
static int
speed_aes(const char *label, int key_bits)
{
    const voleith_params_t *params = NULL;
    voleith_gf8_circuit_t *c = NULL;
    uint8_t *w = NULL, *inst = NULL;
    size_t wlen = 0, ilen = 0;
    int rc;

    if (build_aes(key_bits, 0, &params, &c, &w, &wlen, &inst, &ilen) != 0)
        return 1;
    rc = run_speed(label, params, c, w, wlen, inst, ilen);
    free(w);
    free(inst);
    voleith_gf8_circuit_free(c);
    return rc;
}

/* Run the speed table for one frozen membership circuit. */
static int
speed_membership(const char *label, const voleith_node_hash_vt *tree_vt,
                 size_t sk_bytes)
{
    voleith_gf8_circuit_t *c = NULL;
    uint8_t *w = NULL, *inst = NULL;
    size_t wlen = 0, ilen = 0;
    int rc;

    if (build_membership(tree_vt, sk_bytes, &c, &w, &wlen, &inst, &ilen) != 0) {
        fprintf(stderr, "%s: build failed\n", label);
        return 1;
    }
    rc = run_speed(label, &voleith_params_em_128f, c, w, wlen, inst, ilen);
    free(w);
    free(inst);
    voleith_gf8_circuit_free(c);
    return rc;
}

#if BENCH_FULL
/* One size-table row: ell and proof bytes, frozen vs norm, with the saving. */
static void
size_row(const char *label, const voleith_params_t *params,
         voleith_gf8_circuit_t *frozen, voleith_gf8_circuit_t *norm)
{
    size_t ell_f = voleith_gf8_qs_ell(frozen);
    size_t ell_n = voleith_gf8_qs_ell(norm);
    size_t b_f = voleith_gf8_proof_byte_size(params, ell_f);
    size_t b_n = voleith_gf8_proof_byte_size(params, ell_n);
    double saved = b_f > 0 ? 100.0 * (double)(b_f - b_n) / (double)b_f : 0.0;

    printf("  %-22s %10zu %10zu %10zu %10zu %8.1f%%\n", label, ell_f, ell_n,
           b_f, b_n, saved);
}

/* Build frozen + norm AES circuits and emit a size row. */
static int
size_aes(const char *label, int key_bits)
{
    const voleith_params_t *pf = NULL, *pn = NULL;
    voleith_gf8_circuit_t *cf = NULL, *cn = NULL;
    int rc = 1;

    if (build_aes(key_bits, 0, &pf, &cf, NULL, NULL, NULL, NULL) != 0)
        goto done;
    if (build_aes(key_bits, 1, &pn, &cn, NULL, NULL, NULL, NULL) != 0)
        goto done;
    size_row(label, pf, cf, cn);
    rc = 0;

done:
    if (cf)
        voleith_gf8_circuit_free(cf);
    if (cn)
        voleith_gf8_circuit_free(cn);
    return rc;
}

/* Build frozen + norm membership circuits and emit a size row. */
static int
size_membership(const char *label, const voleith_node_hash_vt *frozen_vt,
                const voleith_node_hash_vt *norm_vt, size_t sk_bytes)
{
    voleith_gf8_circuit_t *cf = NULL, *cn = NULL;
    int rc = 1;

    if (build_membership(frozen_vt, sk_bytes, &cf, NULL, NULL, NULL, NULL) != 0)
        goto done;
    if (build_membership(norm_vt, sk_bytes, &cn, NULL, NULL, NULL, NULL) != 0)
        goto done;
    size_row(label, &voleith_params_em_128f, cf, cn);
    rc = 0;

done:
    if (cf)
        voleith_gf8_circuit_free(cf);
    if (cn)
        voleith_gf8_circuit_free(cn);
    return rc;
}
#endif /* BENCH_FULL */

int
main(void)
{
    int rc = 0;

#if BENCH_FULL
    printf("=== libtalos_voleith release benchmark (current tree: threaded + "
           "norm) ===\n");
    printf("Speed: frozen circuits, prove + verify min/median ms, worker sweep "
           "1 -> up to 16 (capped at physical cores).\n");
    printf("Proof bytes are identical at every worker count; the ok column "
           "flags any prove/verify failure.\n\n");
#else
    printf("=== libtalos_voleith release benchmark (v1.11.0 baseline: serial) "
           "===\n");
    printf("Speed: frozen circuits, prove + verify min/median ms, single "
           "serial run (no threading API in this version).\n\n");
#endif

    printf("[SPEED] AES-128 (em_128f):\n");
    rc |= speed_aes("aes128", 128);
    printf("[SPEED] AES-256 (em_256f):\n");
    rc |= speed_aes("aes256", 256);
    printf("[SPEED] Merkle membership depth-%d, Hirose (em_128f):\n", DEPTH);
    rc |= speed_membership("merkle-hirose", &voleith_node_hash_hirose_fixed32,
                           32);
    printf("[SPEED] Merkle membership depth-%d, Grostl-256 (em_128f):\n",
           DEPTH);
    rc |= speed_membership("merkle-grostl256",
                           &voleith_node_hash_grostl256_fixed, 32);

#if BENCH_FULL
    printf("\n=== Norm S-box proof-size savings (frozen vs norm) ===\n");
    printf("  %-22s %10s %10s %10s %10s %9s\n", "circuit", "frozen_ell",
           "norm_ell", "frozen_B", "norm_B", "saved");
    rc |= size_aes("aes128 (em_128f)", 128);
    rc |= size_aes("aes256 (em_256f)", 256);
    rc |= size_membership("merkle-hirose (em_128f)",
                          &voleith_node_hash_hirose_fixed32,
                          &voleith_node_hash_hirose_fixed32_norm, 32);
    rc |= size_membership("merkle-grostl256 (em_128f)",
                          &voleith_node_hash_grostl256_fixed,
                          &voleith_node_hash_grostl256_fixed_norm, 32);
#endif

    printf("\n(min is the intrinsic-cost estimate; speedup is vs the 1-worker "
           "run. Pin cores and quiesce the host; see docs/BENCHMARKS.md.)\n");
    return rc ? 1 : 0;
}
