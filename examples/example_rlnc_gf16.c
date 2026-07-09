/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rlnc_gf16.c - ZK proof of RLNC generation membership (GF(2^16)).
 *
 * A transport node holds a generation of k source symbols and forwards coded
 * symbols (random linear combinations) over the network.  This example proves,
 * in zero knowledge, that a public coded symbol y is a genuine combination of
 * the generation the node holds:
 *
 *     y[e] = sum_{j=0}^{k-1} c_j * X[j][e]     (element-wise in GF(2^16))
 *
 * The coefficient vector c is PUBLIC (it rides in the RLNC packet header); the
 * k source symbols X are the SECRET witness.  Because each c_j is a public
 * constant, x -> c_j * x is a GF(2)-linear map, so the entire relation costs
 * ZERO multiplication gates: it is a free linear combination plus one equality
 * check per element.  Proven over the native GF(2^16) QuickSilver proof system
 * (proof/gf16_proof.c).
 *
 * Public  (instance): the coded symbol y (elems GF(2^16) elements)
 * Private (witness):  the k source symbols X (k * elems elements)
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "rlnc_gf16_circuit.h"
#include "rlnc.h" /* plaintext encoder, used to produce the public symbol */
#include "gf16_circuit.h"
#include "gf16_proof.h"
#include "field16.h"
#include "proof.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bench_util.h"

#define K 16     /* sources in the generation */
#define ELEMS 32 /* GF(2^16) elements per symbol */
#define SYMBOL_BYTES (2 * ELEMS)

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 20
#define BENCH_VERIFY_ITERS 80

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
    printf("=== RLNC generation-membership ZK proof (GF(2^16) circuit) ===\n");
    printf("Statement: knowledge of a generation X s.t. y = c . X for the "
           "public coefficient vector c\n");
    printf("Generation: k=%u sources, %u GF(2^16) elements/symbol (%u-byte "
           "symbols), native gf16 proof\n\n",
           K, ELEMS, SYMBOL_BYTES);

    /* ----------------------------------------------------------------
     * Build the generation (the node's secret sources) and a public
     * coefficient vector, then produce the public coded symbol y via the
     * plaintext RLNC encoder.
     * ---------------------------------------------------------------- */
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

    /* ----------------------------------------------------------------
     * Build the circuit.  Declaration order fixes the witness layout:
     *   (1) k*elems source witnesses (row-major X[j][e]),
     *   (2) elems instance wires carrying the public coded symbol y.
     * ---------------------------------------------------------------- */
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

    size_t ell = voleith_gf16_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf16_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (c_j is public => free linear map)\n",
           voleith_gf16_circuit_mul_count(c));
    printf("  Witness wires:   %zu (= k*elems source elements)\n",
           voleith_gf16_circuit_witness_count(c));
    printf("  Instance wires:  %zu (= coded symbol y)\n",
           voleith_gf16_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* Witness: the secret sources, in row-major element order. */
    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);

    const char *ds = "example_rlnc_gf16:k16-elems32";

    /* ----------------------------------------------------------------
     * Benchmark prove + verify (witness build stays outside the timed
     * region).  Same methodology as the other examples (bench_util.h).
     * ---------------------------------------------------------------- */
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf16_prove(&p, params, c, witness, y, (const uint8_t *)ds,
                               strlen(ds)) != 0) {
            fprintf(stderr, "voleith_gf16_prove failed (warmup)\n");
            voleith_gf16_circuit_free(c);
            return 1;
        }
        voleith_gf16_verify(&p, params, c, y, (const uint8_t *)ds, strlen(ds));
        voleith_proof_free(&p);
    }

    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf16_prove(&p, params, c, witness, y,
                                    (const uint8_t *)ds, strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "voleith_gf16_prove failed\n");
            voleith_gf16_circuit_free(c);
            return 1;
        }
        prove_ms[i] = (double)(t1 - t0) / 1e6;
        if (i == BENCH_PROVE_ITERS - 1)
            kept = p;
        else
            voleith_proof_free(&p);
    }

    int verify_ok = 1;
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf16_verify(&kept, params, c, y, (const uint8_t *)ds,
                                     strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0)
            verify_ok = 0;
        verify_ms[i] = (double)(t1 - t0) / 1e6;
    }

    /* ----------------------------------------------------------------
     * Negative control: a coded symbol that is NOT c . X must be rejected
     * at prove time (the honest prover refuses a witness violating the
     * circuit's equality constraints).
     * ---------------------------------------------------------------- */
    voleith_gf16_t y_bad[ELEMS];
    memcpy(y_bad, y, sizeof(y_bad));
    y_bad[0] ^= 0x0001;
    voleith_proof_t pbad = {0};
    int forged_rejected =
        (voleith_gf16_prove(&pbad, params, c, witness, y_bad,
                            (const uint8_t *)ds, strlen(ds)) != 0);
    if (!forged_rejected)
        voleith_proof_free(&pbad);

    /* ----------------------------------------------------------------
     * Sufficiency: collecting k coded symbols rebuilds the generation iff
     * their (public) coefficient vectors have rank k.  This is a plaintext
     * check, not part of the proof.
     * ---------------------------------------------------------------- */
    voleith_gf16_t coeff_rows[K * K];
    for (size_t r = 0; r < K; r++)
        for (size_t j = 0; j < K; j++) {
            uint16_t v = sm_next16();
            coeff_rows[r * K + j] = (voleith_gf16_t)(v == 0 ? 1 : v);
        }
    int sufficient = voleith_rlnc_gf16_coeffs_full_rank(coeff_rows, K, K);

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);

    printf("Proof size:   %zu bytes\n", kept.len);
    printf("Verification: %s\n", verify_ok ? "PASS" : "FAIL");
    printf("Forged symbol rejected: %s\n", forged_rejected ? "PASS" : "FAIL");
    printf("Sufficiency (k random coeff vectors full rank): %s\n",
           sufficient ? "PASS" : "FAIL");
    printf("Timing (%d prove / %d verify iters, %d warmup):\n",
           BENCH_PROVE_ITERS, BENCH_VERIFY_ITERS, BENCH_WARMUP);
    bench_print("prove", ps);
    bench_print("verify", vs);

    int ok = verify_ok && forged_rejected && sufficient;
    voleith_proof_free(&kept);
    voleith_gf16_circuit_free(c);

    return ok ? 0 : 1;
}
