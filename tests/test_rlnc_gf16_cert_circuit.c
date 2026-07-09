/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rlnc_gf16_cert_circuit.c - GF(2^16) RLNC decodability / sufficiency
 * certificate circuit tests (P7 T7.1).
 *
 * Tests:
 *   1: circuit shape - n_witness = 2*m*m, n_mul = m^3, no instance wires
 *   2: a full-rank C with its plaintext inverse satisfies C.Cinv = I (eval)
 *   3: plaintext cross-check - C.Cinv = I via erasure/matrix.c (the oracle)
 *   4: full prove + verify roundtrip over the native gf16 proof system
 *   5: a singular C is rejected at witness-build time (no satisfying witness)
 *   6: a tampered Cinv witness fails eval and is rejected at prove time
 */

#include "rlnc_gf16_cert_circuit.h"
#include "matrix.h"  /* full-rank C via the validated generator + invert */
#include "erasure.h" /* VOLEITH_EC_FIELD_GF16, error codes */
#include "gf16_proof.h"
#include "gf16_circuit.h"
#include "proof.h" /* voleith_params_em_128f, voleith_proof_free */
#include "field16.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

#define M 4

/*
 * Fill c_mat (M*M GF(2^16) elements, row-major) with a guaranteed-invertible
 * matrix: an M-by-M Vandermonde over GF(2^16) (distinct points, MDS).  Uses
 * the validated erasure/matrix.c generator.  Returns 0 on success.
 */
static int
make_full_rank_C(voleith_gf16_t *c_mat)
{
    voleith_ec_matrix_t g;
    memset(&g, 0, sizeof(g));
    int rc = voleith_ec_matrix_generator(&g, VOLEITH_EC_FIELD_GF16,
                                         VOLEITH_EC_MATRIX_VANDERMONDE, M, M);
    if (rc != 0)
        return rc;
    for (size_t i = 0; i < (size_t)M * M; i++)
        c_mat[i] = (voleith_gf16_t)g.e[i];
    voleith_ec_matrix_free(&g);
    return 0;
}

/* Build a fresh certificate circuit with C / Cinv witness wires filled. */
static voleith_gf16_circuit_t *
build_circuit(gf16_wire_id *c_wires, gf16_wire_id *cinv_wires)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    if (!c)
        return NULL;
    for (size_t i = 0; i < (size_t)M * M; i++)
        c_wires[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < (size_t)M * M; i++)
        cinv_wires[i] = voleith_gf16_add_witness(c);
    voleith_rlnc_gf16_cert_circuit(c, c_wires, cinv_wires, M);
    return c;
}

/* =====================================================================
 * Test 1: circuit shape
 * ===================================================================== */
static void
test_shape(void)
{
    gf16_wire_id c_wires[M * M], cinv_wires[M * M];
    voleith_gf16_circuit_t *c = build_circuit(c_wires, cinv_wires);

    check("circuit builds ok", c && voleith_gf16_circuit_ok(c));
    check("n_witness = 2*m*m",
          voleith_gf16_circuit_witness_count(c) == 2u * M * M);
    check("n_mul = m^3",
          voleith_gf16_circuit_mul_count(c) == (size_t)M * M * M);
    check("ell = 2*m*m + m^3",
          voleith_gf16_qs_ell(c) == 2u * M * M + (size_t)M * M * M);
    check("no instance wires", voleith_gf16_circuit_instance_count(c) == 0);
    check("helper n_witness agrees",
          voleith_rlnc_gf16_cert_n_witness(M) == 2u * M * M);
    check("helper n_mul agrees",
          voleith_rlnc_gf16_cert_n_mul(M) == (size_t)M * M * M);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 2: a full-rank C satisfies C.Cinv = I in-circuit
 * ===================================================================== */
static void
test_valid_eval(void)
{
    voleith_gf16_t c_mat[M * M];
    check("full-rank C built", make_full_rank_C(c_mat) == 0);

    voleith_gf16_t witness[2 * M * M];
    int wb = voleith_rlnc_gf16_cert_build_witness(c_mat, M, witness);
    check("witness builds (C invertible)", wb == 0);

    gf16_wire_id c_wires[M * M], cinv_wires[M * M];
    voleith_gf16_circuit_t *c = build_circuit(c_wires, cinv_wires);

    size_t n = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(n, sizeof(voleith_gf16_t));
    int ev = voleith_gf16_circuit_eval(c, witness, NULL, vals);
    check("eval passes: C.Cinv = I", ev == 1);

    free(vals);
    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 3: plaintext cross-check against erasure/matrix.c
 * ===================================================================== */
static void
test_plaintext_crosscheck(void)
{
    voleith_gf16_t c_mat[M * M];
    if (make_full_rank_C(c_mat) != 0) {
        check("full-rank C built (crosscheck)", 0);
        return;
    }

    voleith_gf16_t witness[2 * M * M];
    if (voleith_rlnc_gf16_cert_build_witness(c_mat, M, witness) != 0) {
        check("witness builds (crosscheck)", 0);
        return;
    }

    /* witness[m*m ..] is Cinv; multiply C.Cinv in the plaintext field and
     * confirm it is the identity, independently of the circuit. */
    const voleith_gf16_t *cinv = witness + (size_t)M * M;
    int is_identity = 1;
    for (size_t i = 0; i < M; i++) {
        for (size_t j = 0; j < M; j++) {
            voleith_gf16_t acc = 0;
            for (size_t l = 0; l < M; l++)
                acc = voleith_gf16_add(
                    acc, voleith_gf16_mul(c_mat[i * M + l], cinv[l * M + j]));
            voleith_gf16_t want = (i == j) ? 1 : 0;
            if (acc != want)
                is_identity = 0;
        }
    }
    check("plaintext C.Cinv = I (matrix.c inverse)", is_identity);
}

/* =====================================================================
 * Test 4: full prove + verify roundtrip
 * ===================================================================== */
static void
test_roundtrip(void)
{
    voleith_gf16_t c_mat[M * M];
    if (make_full_rank_C(c_mat) != 0) {
        check("full-rank C built (roundtrip)", 0);
        return;
    }
    voleith_gf16_t witness[2 * M * M];
    if (voleith_rlnc_gf16_cert_build_witness(c_mat, M, witness) != 0) {
        check("witness builds (roundtrip)", 0);
        return;
    }

    gf16_wire_id c_wires[M * M], cinv_wires[M * M];
    voleith_gf16_circuit_t *c = build_circuit(c_wires, cinv_wires);

    uint8_t fs_seed[16];
    memset(fs_seed, 0x5a, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  NULL, fs_seed, sizeof(fs_seed));
    check("prove succeeds", pret == 0);

    if (pret == 0) {
        int vret = voleith_gf16_verify(&proof, &voleith_params_em_128f, c, NULL,
                                       fs_seed, sizeof(fs_seed));
        check("verify accepts valid decodability certificate", vret == 0);
        voleith_proof_free(&proof);
    }

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 5: a singular C is rejected at witness-build time
 * ===================================================================== */
static void
test_singular_rejected(void)
{
    voleith_gf16_t c_mat[M * M];
    if (make_full_rank_C(c_mat) != 0) {
        check("full-rank C built (singular)", 0);
        return;
    }
    /* Make row 1 a copy of row 0: the matrix loses rank, hence no inverse. */
    for (size_t j = 0; j < M; j++)
        c_mat[1 * M + j] = c_mat[0 * M + j];

    voleith_gf16_t witness[2 * M * M];
    int wb = voleith_rlnc_gf16_cert_build_witness(c_mat, M, witness);
    check("singular C rejected at build (no decodable set)",
          wb == VOLEITH_EC_ERR_SINGULAR);
}

/* =====================================================================
 * Test 6: a tampered Cinv witness fails eval and prove
 * ===================================================================== */
static void
test_tamper_rejected(void)
{
    voleith_gf16_t c_mat[M * M];
    if (make_full_rank_C(c_mat) != 0) {
        check("full-rank C built (tamper)", 0);
        return;
    }
    voleith_gf16_t witness[2 * M * M];
    if (voleith_rlnc_gf16_cert_build_witness(c_mat, M, witness) != 0) {
        check("witness builds (tamper)", 0);
        return;
    }
    witness[M * M] ^= 0x0001; /* corrupt one entry of Cinv */

    gf16_wire_id c_wires[M * M], cinv_wires[M * M];
    voleith_gf16_circuit_t *c = build_circuit(c_wires, cinv_wires);

    size_t n = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(n, sizeof(voleith_gf16_t));
    int ev = voleith_gf16_circuit_eval(c, witness, NULL, vals);
    check("eval fails on tampered Cinv", ev == 0);
    free(vals);

    uint8_t fs_seed[16];
    memset(fs_seed, 0x33, sizeof(fs_seed));
    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  NULL, fs_seed, sizeof(fs_seed));
    check("prove rejects tampered Cinv", pret != 0);
    if (pret == 0)
        voleith_proof_free(&proof);

    voleith_gf16_circuit_free(c);
}

int
main(void)
{
    printf("=== GF(2^16) RLNC decodability certificate circuit (T7.1) ===\n");
    test_shape();
    test_valid_eval();
    test_plaintext_crosscheck();
    test_roundtrip();
    test_singular_rejected();
    test_tamper_rejected();
    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
