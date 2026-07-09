/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rlnc_confidential.c - ZK proof of a correct confidential-RLNC packet
 * (paper 2 scheme 1, GF(2^16) / t=2 instantiation, P7).
 *
 * A source confidentially encodes a generation of m source symbols under a
 * SECRET coefficient matrix L and a SECRET partial permutation:
 *
 *     data = T^{-1}( permute( T( L . P ) ) )
 *
 * and transmits [I_m | data].  This example proves, in zero knowledge over the
 * native GF(2^16) QuickSilver system, that the public packet `data` is exactly
 * that encoding of the public generation P, WITHOUT revealing L or the
 * permutation, and (via the optional certificate) that L is full rank so the
 * packet is decodable.
 *
 * Public  (instance): the coded packet data (m*l GF(2^16) elements)
 * Private (witness):  the coefficient matrix L, its inverse, and the
 *                     permutation control bits
 * The source generation P is public (baked in as constants), so the L.P encode
 * and the T / T^{-1} maps are FREE; the only mul gates are the permutation
 * network switches plus the m^3 products of the decodability certificate.
 *
 * SECURITY POSTURE (read before reuse): confidential RLNC is WEAK /
 * COMPUTATIONAL security in the permutation-cipher family (P-Coding / SPOC
 * lineage).  It is strictly weaker than a standard cipher and AUTHENTICATES
 * NOTHING: it is NOT an AEAD.  The robust deployment shape is an AEAD payload
 * (for semantic security + integrity) composed with this codec for the
 * coding-structure / generation-linkage hiding it uniquely adds.  This ZK proof
 * attests correct encoding; it neither strengthens nor weakens that posture.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "rlnc_confidential_gf16_circuit.h"
#include "rlnc_confidential.h" /* plaintext codec + safe-default keygen */
#include "gf16_circuit.h"
#include "gf16_proof.h"
#include "field16.h"
#include "proof.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "bench_util.h"

#define M 8u      /* generation size (source symbols) */
#define L_COLS 4u /* GF(2^16) coding elements per symbol */
#define T 2u      /* sub-symbols per element (byte split) */
#define GRID (M * L_COLS * T)

#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 10
#define BENCH_VERIFY_ITERS 40

/* Deterministic GF(2^16) sample stream (for the public generation P). */
static uint64_t sm_state = UINT64_C(0xC0FFEE0C0DEC0DE5);

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
    printf("=== Confidential-RLNC correct-encoding ZK proof (GF(2^16)) ===\n");
    printf(
        "Statement: data = T^-1(permute(T(L.P))) for SECRET L + permutation, "
        "with L full rank (decodable)\n");
    printf("Generation: m=%u sources, l=%u GF(2^16) elements/symbol, grid "
           "n=%u sub-symbols, native gf16 proof\n",
           M, L_COLS, GRID);
    printf("NOTE: confidential RLNC is WEAK/computational security and "
           "authenticates NOTHING (not an AEAD).\n\n");

    voleith_confrlnc_params_t cp = {VOLEITH_EC_FIELD_GF16, T, M, L_COLS};

    /* ----------------------------------------------------------------
     * Safe-default key: derive a uniform permutation and a full-rank L from a
     * seed + generation id (the misuse-resistant API).  The source generation
     * P is public; encrypt it to the public coded packet.
     * ---------------------------------------------------------------- */
    uint8_t seed[16];
    memset(seed, 0x5a, sizeof(seed));
    size_t *perm = calloc(GRID, sizeof(size_t));
    uint16_t *L = calloc(M * M, sizeof(uint16_t));
    if (!perm || !L) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    if (voleith_confrlnc_keygen(&cp, seed, sizeof(seed), 0xA1B2C3D4u, perm,
                                L) != 0) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }

    voleith_gf16_t P[M * L_COLS];
    for (size_t i = 0; i < M * L_COLS; i++)
        P[i] = sm_next16();

    voleith_gf16_t data[M * L_COLS];
    if (voleith_confrlnc_encrypt(&cp, L, perm, P, data) != 0) {
        fprintf(stderr, "encrypt failed\n");
        return 1;
    }

    /* ----------------------------------------------------------------
     * Build the circuit (with the decodability certificate).  Declaration
     * order fixes the witness layout: coeff L (m*m), Linv (m*m), ctrl bits
     * (S(n)); the instance is the public coded packet.
     * ---------------------------------------------------------------- */
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    size_t s = voleith_rlnc_confidential_gf16_n_ctrl(M, L_COLS);
    gf16_wire_id *coeff = calloc(M * M, sizeof(gf16_wire_id));
    gf16_wire_id *cinv = calloc(M * M, sizeof(gf16_wire_id));
    gf16_wire_id *ctrl = calloc(s, sizeof(gf16_wire_id));
    gf16_wire_id *data_wires = calloc(M * L_COLS, sizeof(gf16_wire_id));
    if (!coeff || !cinv || !ctrl || !data_wires) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    for (size_t i = 0; i < M * M; i++)
        coeff[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < M * M; i++)
        cinv[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < M * L_COLS; i++)
        data_wires[i] = voleith_gf16_add_instance(c);

    /* P is public: passed as a constant array. */
    voleith_gf16_t source[M * L_COLS];
    for (size_t i = 0; i < M * L_COLS; i++)
        source[i] = P[i];

    voleith_rlnc_confidential_gf16_circuit(c, source, coeff, cinv, ctrl,
                                           data_wires, M, L_COLS);
    if (!voleith_gf16_circuit_ok(c)) {
        fprintf(stderr, "circuit build failed\n");
        return 1;
    }

    size_t ell = voleith_gf16_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;

    printf("Circuit statistics (with decodability certificate):\n");
    printf("  mul gates:       %zu (= S(n) permutation switches + m^3 cert)\n",
           voleith_gf16_circuit_mul_count(c));
    printf("  Witness wires:   %zu (L, Linv, %zu permutation control bits)\n",
           voleith_gf16_circuit_witness_count(c), s);
    printf("  Instance wires:  %zu (= coded packet data)\n",
           voleith_gf16_circuit_instance_count(c));
    printf("  ell:             %zu\n\n", ell);

    /* Witness: L, Linv, control bits (the layout the circuit expects). */
    size_t nwit = voleith_rlnc_confidential_gf16_n_witness(M, L_COLS, 1);
    voleith_gf16_t *witness = calloc(nwit, sizeof(voleith_gf16_t));
    if (!witness) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    if (voleith_rlnc_confidential_gf16_build_witness(L, M, L_COLS, perm, 1,
                                                     witness) != 0) {
        fprintf(stderr, "witness build failed\n");
        return 1;
    }

    const char *ds = "example_rlnc_confidential:m8-l4";

    /* ----------------------------------------------------------------
     * Benchmark prove + verify (witness build outside the timed region).
     * ---------------------------------------------------------------- */
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf16_prove(&p, params, c, witness, data,
                               (const uint8_t *)ds, strlen(ds)) != 0) {
            fprintf(stderr, "prove failed (warmup)\n");
            return 1;
        }
        voleith_gf16_verify(&p, params, c, data, (const uint8_t *)ds,
                            strlen(ds));
        voleith_proof_free(&p);
    }

    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf16_prove(&p, params, c, witness, data,
                                    (const uint8_t *)ds, strlen(ds));
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

    int verify_ok = 1;
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf16_verify(&kept, params, c, data,
                                     (const uint8_t *)ds, strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0)
            verify_ok = 0;
        verify_ms[i] = (double)(t1 - t0) / 1e6;
    }

    /* ----------------------------------------------------------------
     * Negative control: a forged packet (not the genuine encoding) must be
     * rejected at prove time (the honest prover refuses a witness that
     * violates the equality constraints).
     * ---------------------------------------------------------------- */
    voleith_gf16_t data_bad[M * L_COLS];
    memcpy(data_bad, data, sizeof(data_bad));
    data_bad[0] ^= 0x0001;
    voleith_proof_t pbad = {0};
    int forged_rejected =
        (voleith_gf16_prove(&pbad, params, c, witness, data_bad,
                            (const uint8_t *)ds, strlen(ds)) != 0);
    if (!forged_rejected)
        voleith_proof_free(&pbad);

    /* Confirm the codec round-trips (decrypt recovers P), independent of the
     * proof: a sanity check that the encoding we proved is invertible. */
    voleith_gf16_t P_back[M * L_COLS];
    int roundtrip =
        (voleith_confrlnc_decrypt(&cp, L, perm, data, P_back) == 0 &&
         memcmp(P, P_back, sizeof(P)) == 0);

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);

    printf("Proof size:   %zu bytes\n", kept.len);
    printf("Verification: %s\n", verify_ok ? "PASS" : "FAIL");
    printf("Forged packet rejected: %s\n", forged_rejected ? "PASS" : "FAIL");
    printf("Codec round-trip (decrypt recovers P): %s\n",
           roundtrip ? "PASS" : "FAIL");
    printf("Timing (%d prove / %d verify iters, %d warmup):\n",
           BENCH_PROVE_ITERS, BENCH_VERIFY_ITERS, BENCH_WARMUP);
    bench_print("prove", ps);
    bench_print("verify", vs);

    int ok = verify_ok && forged_rejected && roundtrip;
    voleith_proof_free(&kept);
    voleith_gf16_circuit_free(c);
    free(perm);
    free(L);
    free(coeff);
    free(cinv);
    free(ctrl);
    free(data_wires);
    free(witness);

    return ok ? 0 : 1;
}
