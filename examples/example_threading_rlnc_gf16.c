/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_threading_rlnc_gf16.c - prover threading speedup on a GF(2^16)
 * circuit, the gf16 counterpart of example_threading_aes_gf8 /
 * example_threading_membership_vt_gf8.
 *
 * The statement is RLNC generation membership: knowledge of a secret generation
 * X such that the public coded symbol y = c . X for the public coefficient
 * vector c (see example_rlnc_gf16.c).  It is proven over the native GF(2^16)
 * QuickSilver system and the tau VOLE repetitions are threaded across the pool.
 *
 * NOTE on what this measures.  Because every coefficient c_j is public, x ->
 * c_j*x is a free GF(2)-linear map, so this circuit has ZERO MUL gates and a
 * tiny QuickSilver accumulate.  The speedup here is therefore driven almost
 * entirely by the tau-repetition threading of the VOLE commit (WS1), not by the
 * QuickSilver accumulate threading (T3.1): gf16's real workloads are linear, so
 * T3.1 has little to bite on here.  It is still an apples-to-apples whole-proof
 * speedup demo in the same format as the gf8 examples, and the proof bytes are
 * identical at every worker count.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC, and snprintf on macOS. */
#define _POSIX_C_SOURCE 200112L

#include "rlnc_gf16_circuit.h"
#include "rlnc.h"
#include "gf16_circuit.h"
#include "gf16_proof.h"
#include "field16.h"
#include "proof.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define K 16     /* sources in the generation */
#define ELEMS 32 /* GF(2^16) elements per symbol */
#define SYMBOL_BYTES (2 * ELEMS)

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25

/* Worker counts to sweep; 0 = the physical-core default. */
static const unsigned int THREAD_CONFIGS[] = {1, 2, 4, 8, 0};

/* Deterministic GF(2^16) sample stream. */
static uint64_t sm_state = UINT64_C(0xC0FFEE16);

static uint16_t
sm_next16(void)
{
    uint64_t z = (sm_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    return (uint16_t)(z & 0xffff);
}

int
main(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    const char *ds = "example_threading_rlnc_gf16:k16-elems32";

    printf("=== Prover threading speedup: RLNC membership GF(2^16) "
           "(em_128f, tau=16) ===\n");
    printf("Statement: knowledge of a generation X s.t. y = c . X for the "
           "public coefficient vector c.  Same proof bytes at every thread "
           "count; only prove wall-clock varies.\n");
    printf("Parallelism is across the tau=16 VOLE repetitions (WS1); this "
           "linear circuit has no MUL gates, so QuickSilver accumulate "
           "threading (T3.1) is not the lever here.\n\n");

    /* Build the generation, public coefficients, and the public coded symbol. */
    uint8_t sources[K * SYMBOL_BYTES];
    for (size_t i = 0; i < sizeof(sources); i++)
        sources[i] = (uint8_t)(sm_next16() & 0xff);

    voleith_gf16_t coeffs[K];
    for (size_t j = 0; j < K; j++) {
        uint16_t v = sm_next16();
        coeffs[j] = (voleith_gf16_t)(v == 0 ? 1 : v);
    }

    uint8_t packet[VOLEITH_RLNC_GEN_ID_BYTES + 2 * K + SYMBOL_BYTES];
    if (voleith_rlnc_encode(0x1A2B3C4Du, sources, K, SYMBOL_BYTES, coeffs,
                            packet) != 0) {
        fprintf(stderr, "rlnc encode failed\n");
        return 1;
    }
    voleith_gf16_t y[ELEMS];
    const uint8_t *payload = voleith_rlnc_packet_payload(packet, K);
    for (size_t e = 0; e < ELEMS; e++)
        y[e] = voleith_gf16_from_bytes(payload + 2 * e);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];
    for (size_t i = 0; i < (size_t)K * ELEMS; i++)
        src_wires[i] = voleith_gf16_add_witness(c);
    for (size_t e = 0; e < ELEMS; e++)
        y_wires[e] = voleith_gf16_add_instance(c);
    voleith_rlnc_gf16_membership_circuit(c, src_wires, coeffs, y_wires, K,
                                         ELEMS);
    if (!voleith_gf16_circuit_ok(c)) {
        fprintf(stderr, "circuit build failed\n");
        voleith_gf16_circuit_free(c);
        return 1;
    }

    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);

    size_t ell = voleith_gf16_qs_ell(c);
    printf("  RLNC k=%u, %u elems/symbol; mul gates %zu, witness %zu, "
           "proof %zu B\n",
           K, ELEMS, voleith_gf16_circuit_mul_count(c),
           voleith_gf16_circuit_witness_count(c),
           voleith_gf16_proof_byte_size(params, ell));
    printf("    %-10s %10s %10s %9s\n", "workers", "min(ms)", "median(ms)",
           "speedup");

    double base_min = 0.0;
    size_t n_cfg = sizeof(THREAD_CONFIGS) / sizeof(*THREAD_CONFIGS);
    int rc = 0;

    for (size_t k = 0; k < n_cfg; k++) {
        unsigned int nt = THREAD_CONFIGS[k];
        voleith_threading_opts_t opts = {.nthreads = nt, .pool = NULL};
        double samples[BENCH_PROVE_ITERS];
        int verify_ok = 1;

        for (int w = 0; w < BENCH_WARMUP; w++) {
            voleith_proof_t p = {0};
            if (voleith_gf16_prove_ex(&p, params, c, witness, y,
                                      (const uint8_t *)ds, strlen(ds),
                                      &opts) != 0) {
                fprintf(stderr, "prove failed (warmup, n=%u)\n", nt);
                rc = 1;
                goto done;
            }
            voleith_proof_free(&p);
        }
        for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
            voleith_proof_t p = {0};
            uint64_t t0 = bench_now_ns();
            int pr =
                voleith_gf16_prove_ex(&p, params, c, witness, y,
                                      (const uint8_t *)ds, strlen(ds), &opts);
            uint64_t t1 = bench_now_ns();
            if (pr != 0) {
                fprintf(stderr, "prove failed (n=%u)\n", nt);
                rc = 1;
                goto done;
            }
            samples[i] = (double)(t1 - t0) / 1e6;
            if (i == BENCH_PROVE_ITERS - 1 &&
                voleith_gf16_verify(&p, params, c, y, (const uint8_t *)ds,
                                    strlen(ds)) != 0)
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
    printf("\n(speedup is relative to the 1-worker run, measured on min.)\n");

done:
    voleith_gf16_circuit_free(c);
    return rc;
}
