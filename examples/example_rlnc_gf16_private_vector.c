/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rlnc_gf16_private_vector.c - ZK proof with a SECRET coding vector
 * (GF(2^16)).  The "dual" of example_rlnc_gf16.c.
 *
 * Routing-privacy overlay: a relay mixes publicly-known data blocks X into a
 * coded packet y, and proves y is a genuine combination of those blocks
 * WITHOUT revealing WHICH combination (the coding vector c) it used:
 *
 *     y[e] = sum_{j=0}^{k-1} c_j * X[j][e]     (element-wise in GF(2^16))
 *
 * Here the data blocks X are PUBLIC and the coding vector c is the SECRET
 * witness.  Because each public source element is a constant, c_j * X[j][e] is
 * a free GF(2)-linear map of the secret c_j: ZERO multiplication gates, and
 * ell = k (the proof size depends only on the coding-vector length, not the
 * symbol length).
 *
 * SCOPE: this hides the COMBINATION, not the DATA.  X is public, so it is a
 * traffic-analysis / linkage-resistance overlay, NOT a cipher for the payload.
 * Encrypting the data as well (secret data AND secret key) is the both-secret
 * path, which costs k*elems mul gates; see docs/private/LINEAR_CODING_CIRCUITS.md
 * section B.8.
 *
 * Public  (instance): the coded packet y (elems GF(2^16) elements)
 * Public  (constants): the data blocks X (baked into the circuit)
 * Private (witness):  the coding vector c (k elements)
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "rlnc_gf16_circuit.h"
#include "rlnc.h"
#include "gf16_circuit.h"
#include "gf16_proof.h"
#include "field16.h"
#include "proof.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bench_util.h"

#define K 16     /* sources mixed into each coded packet */
#define ELEMS 32 /* GF(2^16) elements per symbol */
#define SYMBOL_BYTES (2 * ELEMS)

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 20
#define BENCH_VERIFY_ITERS 80

static uint64_t sm_state = UINT64_C(0xBADC0DE16);

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
    printf("=== RLNC private-coding-vector ZK proof (GF(2^16) circuit) ===\n");
    printf("Statement: knowledge of a SECRET coding vector c s.t. y = c . X "
           "for PUBLIC data blocks X\n");
    printf("Relay mixes k=%u public blocks, %u elements/symbol; the coding "
           "vector stays hidden\n\n",
           K, ELEMS);

    /* ----------------------------------------------------------------
     * Public data blocks X and a secret coding vector c; produce the
     * public coded packet y via the plaintext encoder.
     * ---------------------------------------------------------------- */
    uint8_t sources[K * SYMBOL_BYTES];
    for (size_t i = 0; i < sizeof(sources); i++)
        sources[i] = (uint8_t)(sm_next16() & 0xff);

    voleith_gf16_t coeffs[K]; /* the SECRET coding vector (the witness) */
    for (size_t j = 0; j < K; j++) {
        uint16_t v = sm_next16();
        coeffs[j] = (voleith_gf16_t)(v == 0 ? 1 : v);
    }

    uint8_t packet[VOLEITH_RLNC_GEN_ID_BYTES + 2 * K + SYMBOL_BYTES];
    if (voleith_rlnc_encode(0x5EC0DE16u, sources, K, SYMBOL_BYTES, coeffs,
                            packet) != 0) {
        fprintf(stderr, "rlnc encode failed\n");
        return 1;
    }
    voleith_gf16_t y[ELEMS];
    const uint8_t *payload = voleith_rlnc_packet_payload(packet, K);
    for (size_t e = 0; e < ELEMS; e++)
        y[e] = voleith_gf16_from_bytes(payload + 2 * e);

    /* Public source data as row-major GF(2^16) constants for the circuit. */
    voleith_gf16_t src_elems[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, src_elems);

    /* ----------------------------------------------------------------
     * Build the circuit: k coding-vector witnesses, elems instance wires
     * for the public coded packet y.  The data blocks are constants.
     * ---------------------------------------------------------------- */
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf16_wire_id coeff_wires[K], y_wires[ELEMS];
    for (size_t j = 0; j < K; j++)
        coeff_wires[j] = voleith_gf16_add_witness(c);
    for (size_t e = 0; e < ELEMS; e++)
        y_wires[e] = voleith_gf16_add_instance(c);

    voleith_rlnc_gf16_coded_vector_circuit(c, coeff_wires, src_elems, y_wires,
                                           K, ELEMS);
    if (!voleith_gf16_circuit_ok(c)) {
        fprintf(stderr, "circuit build failed\n");
        voleith_gf16_circuit_free(c);
        return 1;
    }

    size_t ell = voleith_gf16_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf16_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (public source X_je => free linear map)\n",
           voleith_gf16_circuit_mul_count(c));
    printf("  Witness wires:   %zu (= k coding-vector elements only)\n",
           voleith_gf16_circuit_witness_count(c));
    printf("  Instance wires:  %zu (= coded packet y)\n",
           voleith_gf16_circuit_instance_count(c));
    printf("  ell:             %zu (independent of symbol length)\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    const char *ds = "example_rlnc_gf16_private_vector:k16-elems32";

    /* ----------------------------------------------------------------
     * Benchmark prove + verify (the witness is the secret coding vector).
     * ---------------------------------------------------------------- */
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf16_prove(&p, params, c, coeffs, y, (const uint8_t *)ds,
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
        int rc = voleith_gf16_prove(&p, params, c, coeffs, y,
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

    /* Negative control: a coding vector that does not produce y is rejected. */
    voleith_gf16_t coeffs_bad[K];
    memcpy(coeffs_bad, coeffs, sizeof(coeffs_bad));
    coeffs_bad[0] ^= 0x0001;
    voleith_proof_t pbad = {0};
    int forged_rejected =
        (voleith_gf16_prove(&pbad, params, c, coeffs_bad, y,
                            (const uint8_t *)ds, strlen(ds)) != 0);
    if (!forged_rejected)
        voleith_proof_free(&pbad);

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);

    printf("Proof size:   %zu bytes\n", kept.len);
    printf("Verification: %s\n", verify_ok ? "PASS" : "FAIL");
    printf("Forged coding vector rejected: %s\n",
           forged_rejected ? "PASS" : "FAIL");
    printf("Privacy: the coding vector c stays in the witness (never "
           "revealed); the data X is public.\n");
    printf("Timing (%d prove / %d verify iters, %d warmup):\n",
           BENCH_PROVE_ITERS, BENCH_VERIFY_ITERS, BENCH_WARMUP);
    bench_print("prove", ps);
    bench_print("verify", vs);

    int ok = verify_ok && forged_rejected;
    voleith_proof_free(&kept);
    voleith_gf16_circuit_free(c);

    return ok ? 0 : 1;
}
