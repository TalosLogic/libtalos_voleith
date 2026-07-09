/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rlnc_confidential_gf16_circuit.c - GF(2^16) confidential-RLNC proof
 * wrapper tests (P7 T7.6).
 *
 * The plaintext codec (T7.2, voleith_confrlnc_encrypt) is the ORACLE: the
 * circuit must reproduce its output.  Tests:
 *   1: shape - witness / mul counts, with and without the decodability cert.
 *   2: eval reproduces the plaintext codec output (positive), and a wrong
 *      packet fails (negative).
 *   3: prove + verify roundtrip, without and with the certificate.
 *   4: soundness - flipped permutation bit, wrong coefficient, and wrong packet
 *      are rejected; a singular L is rejected at witness-build (cert path).
 */

#include "rlnc_confidential_gf16_circuit.h"
#include "permutation_gf16_circuit.h"
#include "rlnc_confidential.h" /* plaintext codec oracle */
#include "matrix.h"            /* full-rank L via Vandermonde generator */
#include "erasure.h"
#include "gf16_circuit.h"
#include "gf16_proof.h"
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
    if (cond)
        pass_count++;
    else
        printf("  FAIL: %s\n", name);
}

#define M 3u
#define L_COLS 2u
#define T 2u
#define GRID (M * L_COLS * T) /* 12 */

static uint64_t rng_state = UINT64_C(0xD1CE5EED12345678);
static uint16_t
rng16(void)
{
    uint64_t z = (rng_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z ^= z >> 31;
    return (uint16_t)(z & 0xffff);
}

/* Guaranteed-invertible M-by-M GF(2^16) matrix (Vandermonde, MDS). */
static int
make_full_rank_L(voleith_gf16_t *L)
{
    voleith_ec_matrix_t g;
    memset(&g, 0, sizeof(g));
    int rc = voleith_ec_matrix_generator(&g, VOLEITH_EC_FIELD_GF16,
                                         VOLEITH_EC_MATRIX_VANDERMONDE, M, M);
    if (rc != 0)
        return rc;
    for (size_t i = 0; i < (size_t)M * M; i++)
        L[i] = (voleith_gf16_t)g.e[i];
    voleith_ec_matrix_free(&g);
    return 0;
}

static void
random_perm(size_t *perm, size_t n)
{
    for (size_t i = 0; i < n; i++)
        perm[i] = i;
    for (size_t i = n; i-- > 1;) {
        size_t j = (size_t)(rng16() % (uint16_t)(i + 1));
        size_t t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
    }
}

/*
 * Build a circuit and the matching witness / instance.  source P and perm are
 * inputs; the expected packet is the plaintext codec's output (the oracle).
 * Returns the circuit; fills witness (caller frees), instance, and the wire-id
 * arrays needed for tampering.
 */
static voleith_gf16_circuit_t *
build(const voleith_gf16_t *L, const voleith_gf16_t *P, const size_t *perm,
      int with_cert, voleith_gf16_t **witness, voleith_gf16_t *instance,
      size_t *coeff0_widx, size_t *ctrl0_widx)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();

    size_t s = voleith_rlnc_confidential_gf16_n_ctrl(M, L_COLS);
    gf16_wire_id *coeff = calloc(M * M, sizeof(gf16_wire_id));
    gf16_wire_id *cinv = with_cert ? calloc(M * M, sizeof(gf16_wire_id)) : NULL;
    gf16_wire_id *ctrl = calloc(s, sizeof(gf16_wire_id));
    gf16_wire_id *data = calloc(M * L_COLS, sizeof(gf16_wire_id));

    /* Witness add-order: coeff, [cinv], ctrl.  Record witness indices. */
    *coeff0_widx = 0;
    for (size_t i = 0; i < M * M; i++)
        coeff[i] = voleith_gf16_add_witness(c);
    if (with_cert)
        for (size_t i = 0; i < M * M; i++)
            cinv[i] = voleith_gf16_add_witness(c);
    *ctrl0_widx = with_cert ? 2u * M * M : M * M;
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);

    /* Instance: the public coded packet. */
    for (size_t i = 0; i < M * L_COLS; i++)
        data[i] = voleith_gf16_add_instance(c);

    voleith_rlnc_confidential_gf16_circuit(c, P, coeff, cinv, ctrl, data, M,
                                           L_COLS);

    /* Witness values. */
    size_t nwit =
        voleith_rlnc_confidential_gf16_n_witness(M, L_COLS, with_cert);
    voleith_gf16_t *wit = calloc(nwit, sizeof(voleith_gf16_t));
    int wb = voleith_rlnc_confidential_gf16_build_witness(L, M, L_COLS, perm,
                                                          with_cert, wit);
    if (wb != 0) {
        free(coeff);
        free(cinv);
        free(ctrl);
        free(data);
        free(wit);
        voleith_gf16_circuit_free(c);
        return NULL;
    }
    *witness = wit;

    /* Instance values = plaintext codec output (the oracle). */
    voleith_confrlnc_params_t cp = {VOLEITH_EC_FIELD_GF16, T, M, L_COLS};
    uint16_t enc[M * L_COLS];
    voleith_confrlnc_encrypt(&cp, L, perm, P, enc);
    for (size_t i = 0; i < M * L_COLS; i++)
        instance[i] = enc[i];

    free(coeff);
    free(cinv);
    free(ctrl);
    free(data);
    return c;
}

static void
test_shape(void)
{
    size_t s = voleith_rlnc_confidential_gf16_n_ctrl(M, L_COLS);
    check("n_ctrl == S(m*l*t)", s == voleith_perm_gf16_n_switches(GRID));

    voleith_gf16_t L[M * M], P[M * L_COLS], inst[M * L_COLS], *wit = NULL;
    size_t perm[GRID], ci, ti;
    make_full_rank_L(L);
    for (size_t i = 0; i < M * L_COLS; i++)
        P[i] = rng16();
    random_perm(perm, GRID);

    voleith_gf16_circuit_t *c = build(L, P, perm, 0, &wit, inst, &ci, &ti);
    check("builds (no cert)", c && voleith_gf16_circuit_ok(c));
    check("witness count (no cert) = m*m + S(n)",
          voleith_gf16_circuit_witness_count(c) ==
              voleith_rlnc_confidential_gf16_n_witness(M, L_COLS, 0));
    check("mul count (no cert) = S(n)",
          voleith_gf16_circuit_mul_count(c) ==
              voleith_rlnc_confidential_gf16_n_mul(M, L_COLS, 0));
    check("instance count = m*l",
          voleith_gf16_circuit_instance_count(c) == M * L_COLS);
    free(wit);
    voleith_gf16_circuit_free(c);

    c = build(L, P, perm, 1, &wit, inst, &ci, &ti);
    check("builds (cert)", c && voleith_gf16_circuit_ok(c));
    check("witness count (cert) = 2*m*m + S(n)",
          voleith_gf16_circuit_witness_count(c) ==
              voleith_rlnc_confidential_gf16_n_witness(M, L_COLS, 1));
    check("mul count (cert) = S(n) + m^3",
          voleith_gf16_circuit_mul_count(c) ==
              voleith_rlnc_confidential_gf16_n_mul(M, L_COLS, 1));
    free(wit);
    voleith_gf16_circuit_free(c);
}

static void
test_eval_matches_codec(void)
{
    voleith_gf16_t L[M * M], P[M * L_COLS], inst[M * L_COLS], *wit = NULL;
    size_t perm[GRID], ci, ti;
    make_full_rank_L(L);
    for (size_t i = 0; i < M * L_COLS; i++)
        P[i] = rng16();
    random_perm(perm, GRID);

    voleith_gf16_circuit_t *c = build(L, P, perm, 0, &wit, inst, &ci, &ti);
    size_t nw = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));

    int ev = voleith_gf16_circuit_eval(c, wit, inst, vals);
    check("circuit reproduces plaintext codec output (eval == 1)", ev == 1);

    /* Negative: a wrong packet must fail the equality constraints. */
    voleith_gf16_t bad[M * L_COLS];
    memcpy(bad, inst, sizeof(bad));
    bad[0] ^= 0x0001;
    int ev_bad = voleith_gf16_circuit_eval(c, wit, bad, vals);
    check("wrong packet fails eval", ev_bad == 0);

    free(vals);
    free(wit);
    voleith_gf16_circuit_free(c);
}

static void
test_prove_verify(void)
{
    for (int with_cert = 0; with_cert <= 1; with_cert++) {
        voleith_gf16_t L[M * M], P[M * L_COLS], inst[M * L_COLS], *wit = NULL;
        size_t perm[GRID], ci, ti;
        make_full_rank_L(L);
        for (size_t i = 0; i < M * L_COLS; i++)
            P[i] = rng16();
        random_perm(perm, GRID);

        voleith_gf16_circuit_t *c =
            build(L, P, perm, with_cert, &wit, inst, &ci, &ti);
        check("build for prove", c != NULL);

        uint8_t fs[16];
        memset(fs, 0x5a, sizeof(fs));
        voleith_proof_t proof;
        int pr = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, wit,
                                    inst, fs, sizeof(fs));
        check(with_cert ? "prove ok (cert)" : "prove ok (no cert)", pr == 0);
        if (pr == 0) {
            int vr = voleith_gf16_verify(&proof, &voleith_params_em_128f, c,
                                         inst, fs, sizeof(fs));
            check(with_cert ? "verify ok (cert)" : "verify ok (no cert)",
                  vr == 0);
            voleith_proof_free(&proof);
        }
        free(wit);
        voleith_gf16_circuit_free(c);
    }
}

static void
test_soundness(void)
{
    voleith_gf16_t L[M * M], P[M * L_COLS], inst[M * L_COLS], *wit = NULL;
    size_t perm[GRID], ci, ti;
    make_full_rank_L(L);
    for (size_t i = 0; i < M * L_COLS; i++)
        P[i] = rng16();
    random_perm(perm, GRID);

    voleith_gf16_circuit_t *c = build(L, P, perm, 0, &wit, inst, &ci, &ti);
    size_t nw = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));

    /* Flip one permutation control bit: the encoding changes, packet mismatch. */
    voleith_gf16_t saved = wit[ti];
    wit[ti] ^= 0x0001;
    check("flipped permutation bit rejected",
          voleith_gf16_circuit_eval(c, wit, inst, vals) == 0);
    wit[ti] = saved;

    /* Wrong coefficient: different L, encoding no longer matches the packet. */
    saved = wit[ci];
    wit[ci] ^= 0x0007;
    check("wrong coefficient rejected",
          voleith_gf16_circuit_eval(c, wit, inst, vals) == 0);
    wit[ci] = saved;

    /* Sanity: restored witness still verifies. */
    check("restored witness still passes",
          voleith_gf16_circuit_eval(c, wit, inst, vals) == 1);

    free(vals);
    free(wit);
    voleith_gf16_circuit_free(c);

    /* Singular L is rejected at witness-build time on the certificate path. */
    voleith_gf16_t Lsing[M * M];
    make_full_rank_L(Lsing);
    for (size_t j = 0; j < M; j++)
        Lsing[1 * M + j] = Lsing[0 * M + j]; /* row 1 = row 0 -> singular */
    voleith_gf16_t out[64];
    int wb = voleith_rlnc_confidential_gf16_build_witness(Lsing, M, L_COLS,
                                                          perm, 1, out);
    check("singular L rejected at build (cert)", wb == VOLEITH_EC_ERR_SINGULAR);
}

int
main(void)
{
    printf("=== GF(2^16) confidential-RLNC proof wrapper (T7.6) ===\n");
    test_shape();
    test_eval_matches_codec();
    test_prove_verify();
    test_soundness();
    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
