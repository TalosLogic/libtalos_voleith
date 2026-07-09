/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rlnc_gf16_circuit.c - GF(2^16) RLNC membership circuit tests (T5.6).
 *
 * Tests:
 *   1: circuit shape - ell = k*elems witnesses, zero mul gates
 *   2: in-circuit y = c.X matches the plaintext RLNC encoder (P3 oracle)
 *   3: full prove + verify roundtrip over the native gf16 proof system
 *   4: wrong generation (tampered source) rejected at prove time
 *   5: wrong coded symbol (tampered instance y) rejected at prove time
 *   6: sufficiency - full-rank coefficient set accepted, deficient rejected
 */

#include "rlnc_gf16_circuit.h"
#include "rlnc.h" /* plaintext oracle: voleith_rlnc_encode */
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

/* Deterministic GF(2^16) sample stream. */
static uint64_t sm_state = UINT64_C(0x12345678);

static uint16_t
sm_next16(void)
{
    uint64_t z = (sm_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    z = z ^ (z >> 31);
    return (uint16_t)(z & 0xffff);
}

/* Test parameters: a small generation. */
#define K 4
#define ELEMS 3
#define SYMBOL_BYTES (2 * ELEMS)

/*
 * Build sources (k*symbol_bytes bytes), a nonzero coefficient vector (k
 * elements), and the plaintext coded symbol y (elems elements) via the RLNC
 * oracle.  Fills the supplied buffers.
 */
static void
make_generation(uint8_t *sources, voleith_gf16_t *coeffs, voleith_gf16_t *y)
{
    for (size_t i = 0; i < (size_t)K * SYMBOL_BYTES; i++)
        sources[i] = (uint8_t)(sm_next16() & 0xff);

    for (size_t j = 0; j < K; j++) {
        uint16_t v = sm_next16();
        coeffs[j] = (voleith_gf16_t)(v == 0 ? 1 : v);
    }

    uint8_t packet[VOLEITH_RLNC_GEN_ID_BYTES + 2 * K + SYMBOL_BYTES];
    int rc = voleith_rlnc_encode(0xABCD1234u, sources, K, SYMBOL_BYTES, coeffs,
                                 packet);
    if (rc != 0) {
        /* Surface as a failed test rather than crashing later. */
        memset(y, 0, ELEMS * sizeof(voleith_gf16_t));
        return;
    }
    const uint8_t *payload = voleith_rlnc_packet_payload(packet, K);
    for (size_t e = 0; e < ELEMS; e++)
        y[e] = voleith_gf16_from_bytes(payload + 2 * e);
}

/* Build a fresh membership circuit; returns it with src/y wire ids filled. */
static voleith_gf16_circuit_t *
build_circuit(const voleith_gf16_t *coeffs, gf16_wire_id *src_wires,
              gf16_wire_id *y_wires)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    if (!c)
        return NULL;
    for (size_t i = 0; i < (size_t)K * ELEMS; i++)
        src_wires[i] = voleith_gf16_add_witness(c);
    for (size_t e = 0; e < ELEMS; e++)
        y_wires[e] = voleith_gf16_add_instance(c);
    voleith_rlnc_gf16_membership_circuit(c, src_wires, coeffs, y_wires, K,
                                         ELEMS);
    return c;
}

/* =====================================================================
 * Test 1: circuit shape
 * ===================================================================== */
static void
test_shape(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];

    make_generation(sources, coeffs, y);
    voleith_gf16_circuit_t *c = build_circuit(coeffs, src_wires, y_wires);

    check("circuit builds ok", c && voleith_gf16_circuit_ok(c));
    check("ell = k*elems witnesses",
          voleith_gf16_qs_ell(c) == (size_t)K * ELEMS);
    check("zero mul gates (free linear combination)",
          voleith_gf16_circuit_mul_count(c) == 0);
    check("witness_count = k*elems",
          voleith_gf16_circuit_witness_count(c) == (size_t)K * ELEMS);
    check("instance_count = elems",
          voleith_gf16_circuit_instance_count(c) == (size_t)ELEMS);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 2: in-circuit y = c.X matches the plaintext oracle
 * ===================================================================== */
static void
test_matches_plaintext(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];

    make_generation(sources, coeffs, y);
    voleith_gf16_circuit_t *c = build_circuit(coeffs, src_wires, y_wires);

    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);

    size_t n = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(n, sizeof(voleith_gf16_t));
    /* instance y comes from the plaintext encoder; eval == 1 means the
     * in-circuit combination reproduced it. */
    int ev = voleith_gf16_circuit_eval(c, witness, y, vals);
    check("eval passes: in-circuit y == plaintext encode", ev == 1);

    free(vals);
    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 3: full prove + verify roundtrip
 * ===================================================================== */
static void
test_roundtrip(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];

    make_generation(sources, coeffs, y);
    voleith_gf16_circuit_t *c = build_circuit(coeffs, src_wires, y_wires);

    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);

    uint8_t fs_seed[16];
    memset(fs_seed, 0x5a, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  y, fs_seed, sizeof(fs_seed));
    check("prove succeeds", pret == 0);

    if (pret == 0) {
        int vret = voleith_gf16_verify(&proof, &voleith_params_em_128f, c, y,
                                       fs_seed, sizeof(fs_seed));
        check("verify accepts valid membership proof", vret == 0);
        voleith_proof_free(&proof);
    }

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 4: wrong generation (tampered source) rejected at prove time
 * ===================================================================== */
static void
test_wrong_generation(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];

    make_generation(sources, coeffs, y);
    voleith_gf16_circuit_t *c = build_circuit(coeffs, src_wires, y_wires);

    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);
    witness[0] ^= 0x0001; /* a source the committed y does not match */

    uint8_t fs_seed[16];
    memset(fs_seed, 0x33, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  y, fs_seed, sizeof(fs_seed));
    check("prove rejects a witness not matching y", pret != 0);
    if (pret == 0)
        voleith_proof_free(&proof);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 5: wrong coded symbol (tampered instance y) rejected at prove time
 * ===================================================================== */
static void
test_wrong_symbol(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    gf16_wire_id src_wires[K * ELEMS], y_wires[ELEMS];

    make_generation(sources, coeffs, y);
    voleith_gf16_circuit_t *c = build_circuit(coeffs, src_wires, y_wires);

    voleith_gf16_t witness[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, witness);

    voleith_gf16_t y_bad[ELEMS];
    memcpy(y_bad, y, sizeof(y_bad));
    y_bad[0] ^= 0x0001; /* not the genuine coded symbol */

    uint8_t fs_seed[16];
    memset(fs_seed, 0x44, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  y_bad, fs_seed, sizeof(fs_seed));
    check("prove rejects a coded symbol that is not c.X", pret != 0);
    if (pret == 0)
        voleith_proof_free(&proof);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 6: sufficiency (plaintext rank over public coefficients)
 * ===================================================================== */
static void
test_sufficiency(void)
{
    /* A full-rank set: the k standard basis vectors. */
    voleith_gf16_t full[K * K];
    memset(full, 0, sizeof(full));
    for (size_t r = 0; r < K; r++)
        full[r * K + r] = 1;
    check("sufficiency: full-rank coefficient set accepted",
          voleith_rlnc_gf16_coeffs_full_rank(full, K, K) == 1);

    /* Rank-deficient: duplicate the first row over the last. */
    voleith_gf16_t deficient[K * K];
    memcpy(deficient, full, sizeof(deficient));
    for (size_t j = 0; j < K; j++)
        deficient[(K - 1) * K + j] = deficient[0 * K + j];
    check("sufficiency: rank-deficient set rejected",
          voleith_rlnc_gf16_coeffs_full_rank(deficient, K, K) == 0);

    /* Too few rows to ever reach rank k. */
    check("sufficiency: fewer than k rows rejected",
          voleith_rlnc_gf16_coeffs_full_rank(full, K - 1, K) == 0);

    /* More rows than k, still full rank (extra independent / dependent mix). */
    voleith_gf16_t wide[(K + 1) * K];
    memset(wide, 0, sizeof(wide));
    for (size_t r = 0; r < K; r++)
        wide[r * K + r] = 1;
    for (size_t j = 0; j < K; j++)
        wide[K * K + j] = 7; /* an extra dependent row */
    check("sufficiency: n_rows > k with full rank accepted",
          voleith_rlnc_gf16_coeffs_full_rank(wide, K + 1, K) == 1);
}

/* =====================================================================
 * Test 7: secret-coefficient (coded-vector) orientation
 *
 * Dual relation: public sources, SECRET coding vector.  ell = k (the proof
 * is independent of the symbol length); zero mul gates.  Proves y = c.X
 * without revealing c.
 * ===================================================================== */
static void
test_coded_vector(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    make_generation(sources, coeffs, y);

    /* Public source elements, row-major (build-time constants here). */
    voleith_gf16_t src_elems[K * ELEMS];
    voleith_rlnc_gf16_build_witness(sources, K, SYMBOL_BYTES, src_elems);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id coeff_wires[K], y_wires[ELEMS];
    for (size_t j = 0; j < K; j++)
        coeff_wires[j] = voleith_gf16_add_witness(c);
    for (size_t e = 0; e < ELEMS; e++)
        y_wires[e] = voleith_gf16_add_instance(c);
    voleith_rlnc_gf16_coded_vector_circuit(c, coeff_wires, src_elems, y_wires,
                                           K, ELEMS);

    check("coded_vector: ell = k (only the hidden coding vector)",
          voleith_gf16_qs_ell(c) == (size_t)K);
    check("coded_vector: zero mul gates",
          voleith_gf16_circuit_mul_count(c) == 0);
    check("coded_vector: witness_count = k",
          voleith_gf16_circuit_witness_count(c) == (size_t)K);

    /* The witness IS the secret coefficient vector. */
    uint8_t fs_seed[16];
    memset(fs_seed, 0x6b, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, coeffs, y,
                                  fs_seed, sizeof(fs_seed));
    check("coded_vector: prove succeeds", pret == 0);
    if (pret == 0) {
        int vret = voleith_gf16_verify(&proof, &voleith_params_em_128f, c, y,
                                       fs_seed, sizeof(fs_seed));
        check("coded_vector: verify accepts", vret == 0);
        voleith_proof_free(&proof);
    }

    /* Wrong coding vector (does not produce y) rejected at prove time. */
    voleith_gf16_t coeffs_bad[K];
    memcpy(coeffs_bad, coeffs, sizeof(coeffs_bad));
    coeffs_bad[0] ^= 0x0001;
    voleith_proof_t pbad;
    int pbret = voleith_gf16_prove(&pbad, &voleith_params_em_128f, c,
                                   coeffs_bad, y, fs_seed, sizeof(fs_seed));
    check("coded_vector: wrong coding vector rejected", pbret != 0);
    if (pbret == 0)
        voleith_proof_free(&pbad);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 8: both-secret (data-blind) membership orientation (P8 T8.1)
 *
 * BOTH the source generation X and the coding vector c are secret witnesses;
 * y is the public coded packet.  ell = k*elems + k witnesses + k*elems muls.
 * Proves y = c.X while hiding both the data and the combination.
 * ===================================================================== */
static void
test_membership_secret(void)
{
    uint8_t sources[K * SYMBOL_BYTES];
    voleith_gf16_t coeffs[K], y[ELEMS];
    make_generation(sources, coeffs, y);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id src_wires[K * ELEMS], coeff_wires[K], y_wires[ELEMS];
    /* X prefix, then c, then public y (matches the witness-layout contract). */
    for (size_t i = 0; i < (size_t)K * ELEMS; i++)
        src_wires[i] = voleith_gf16_add_witness(c);
    for (size_t j = 0; j < K; j++)
        coeff_wires[j] = voleith_gf16_add_witness(c);
    for (size_t e = 0; e < ELEMS; e++)
        y_wires[e] = voleith_gf16_add_instance(c);
    voleith_rlnc_gf16_membership_secret_circuit(c, src_wires, coeff_wires,
                                                y_wires, K, ELEMS);

    check("membership_secret: builds ok", voleith_gf16_circuit_ok(c));
    check("membership_secret: witness_count = k*elems + k",
          voleith_gf16_circuit_witness_count(c) ==
              voleith_rlnc_gf16_membership_secret_n_witness(K, ELEMS));
    check("membership_secret: mul_count = k*elems",
          voleith_gf16_circuit_mul_count(c) ==
              voleith_rlnc_gf16_membership_secret_n_mul(K, ELEMS));
    check("membership_secret: ell = k*elems + k + k*elems",
          voleith_gf16_qs_ell(c) ==
              voleith_rlnc_gf16_membership_secret_n_witness(K, ELEMS) +
                  voleith_rlnc_gf16_membership_secret_n_mul(K, ELEMS));

    size_t nwit = voleith_rlnc_gf16_membership_secret_n_witness(K, ELEMS);
    voleith_gf16_t *witness = calloc(nwit, sizeof(voleith_gf16_t));
    int bret = voleith_rlnc_gf16_membership_secret_build_witness(
        sources, K, SYMBOL_BYTES, coeffs, witness);
    check("membership_secret: build_witness ok", bret == 0);

    uint8_t fs_seed[16];
    memset(fs_seed, 0x7c, sizeof(fs_seed));

    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, witness,
                                  y, fs_seed, sizeof(fs_seed));
    check("membership_secret: prove succeeds", pret == 0);
    if (pret == 0) {
        int vret = voleith_gf16_verify(&proof, &voleith_params_em_128f, c, y,
                                       fs_seed, sizeof(fs_seed));
        check("membership_secret: verify accepts", vret == 0);
        voleith_proof_free(&proof);
    }

    /* Tampered source (wrong X) rejected at prove time. */
    witness[0] ^= 0x0001;
    voleith_proof_t pbadx;
    int pxret = voleith_gf16_prove(&pbadx, &voleith_params_em_128f, c, witness,
                                   y, fs_seed, sizeof(fs_seed));
    check("membership_secret: wrong X rejected", pxret != 0);
    if (pxret == 0)
        voleith_proof_free(&pbadx);
    witness[0] ^= 0x0001;

    /* Tampered coding vector (wrong c) rejected at prove time. */
    witness[(size_t)K * ELEMS] ^= 0x0001;
    voleith_proof_t pbadc;
    int pcret = voleith_gf16_prove(&pbadc, &voleith_params_em_128f, c, witness,
                                   y, fs_seed, sizeof(fs_seed));
    check("membership_secret: wrong c rejected", pcret != 0);
    if (pcret == 0)
        voleith_proof_free(&pbadc);

    free(witness);
    voleith_gf16_circuit_free(c);
}

int
main(void)
{
    printf("test_rlnc_gf16_circuit\n");

    test_shape();
    test_matches_plaintext();
    test_roundtrip();
    test_wrong_generation();
    test_wrong_symbol();
    test_sufficiency();
    test_coded_vector();
    test_membership_secret();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
