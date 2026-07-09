/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf16_quicksilver.c - Tests for the element-level (GF(2^16))
 * QuickSilver prover / verifier (T5.4).  The GF(2^16) counterpart to
 * test_gf8_quicksilver.c.
 *
 * Tests:
 *   1:  ell / ellhat calculations
 *   2:  Prove + verify roundtrip - correct witness (lambda = 128, 192, 256)
 *   3:  Invalid witness - a0_tilde must not match (soundness)
 *   4:  Tampered a1_tilde - a0_tilde must not match
 *   5:  assert_product inversion (Prop 6.4 over GF(2^16)), all lambda
 *   5b: assert_product soundness (eval gate rejects c != a*b)
 *   5c: assert_product soundness by forgery (verifier rejects via unchecked
 *       seam; isolates the v2 = embed(val_c) invariant)
 *   6:  assert_zero constraint
 *   7:  assert_equal constraint
 *   8:  XOR_CONST + LINEAR_MAP (identity) gate tag propagation
 *   9:  SQUARE gate tag propagation (prove a^2 over GF(2^16))
 *   10: Multiple MUL gates - accumulation correctness
 *
 * VOLE setup: VOLE correlations are synthesized directly for testing.
 *   Q[j] = V[j] XOR (delta_j ? u : 0)   for each row j = 0..lambda-1.
 *
 * Verify-cost note (informational): this native gf16 path keeps one VOLE
 * slot per GF(2^16) multiplication.  A GF(2^8)^2 tower realization of the
 * same statement would expand each GF(2^16) multiply into ~3 GF(2^8)
 * multiplies (Karatsuba), so the verifier - whose cost is linear in the
 * slot / mul count - would do ~3x the work.  The native path is therefore
 * the right choice for the standalone high-throughput RLNC membership case;
 * the tower stays the planned mechanism for CROSS-FIELD composition (a
 * GF(2^16) minority inside a gf8-dominated proof), per design section 5.1.
 */

#include "gf16_prover.h"
#include "gf16_prover_internal.h" /* test-only unchecked prove seam */
#include "gf16_verifier.h"
#include "gf16_circuit.h"
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

/* =====================================================================
 * Minimal deterministic PRNG
 * ===================================================================== */

static uint32_t g_prng = 0xABCDEF01u;

static uint8_t
prng_byte(void)
{
    g_prng ^= g_prng << 13;
    g_prng ^= g_prng >> 17;
    g_prng ^= g_prng << 5;
    return (uint8_t)(g_prng & 0xFFu);
}

static void
prng_fill(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = prng_byte();
}

static void
prng_reset(uint32_t seed)
{
    g_prng = seed;
}

/* =====================================================================
 * VOLE scaffolding (element-level, GF(2^16))
 *
 * u has ellhat_bytes bytes:
 *   u[0 .. 2*ell-1]            = element slot values (16-bit LE each)
 *   u[2*ell .. ellhat_bytes-1] = correction bytes
 *
 * VOLE relation: Q[j] = V[j] XOR (delta_j ? u : 0)  for each row j.
 * ===================================================================== */

static inline unsigned int
get_bit_t(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

typedef struct {
    uint8_t *u;
    uint8_t **V_rows;
    uint8_t **Q_rows;
    uint8_t *V_data;
    uint8_t *Q_data;
    uint8_t *delta;
    uint8_t *chall_2;
    unsigned int lambda;
    size_t ellhat_bytes;
} vole_state_t;

static int
vole_alloc(vole_state_t *vs, unsigned int lambda, size_t ellhat_bytes)
{
    unsigned int nb = lambda / 8;
    vs->lambda = lambda;
    vs->ellhat_bytes = ellhat_bytes;

    vs->u = malloc(ellhat_bytes);
    vs->V_data = malloc((size_t)lambda * ellhat_bytes);
    vs->Q_data = malloc((size_t)lambda * ellhat_bytes);
    vs->V_rows = malloc(lambda * sizeof(uint8_t *));
    vs->Q_rows = malloc(lambda * sizeof(uint8_t *));
    vs->delta = malloc(nb);
    vs->chall_2 = malloc(3 * nb + 8);
    if (!vs->u || !vs->V_data || !vs->Q_data || !vs->V_rows || !vs->Q_rows ||
        !vs->delta || !vs->chall_2) {
        free(vs->u);
        free(vs->V_data);
        free(vs->Q_data);
        free(vs->V_rows);
        free(vs->Q_rows);
        free(vs->delta);
        free(vs->chall_2);
        return -1;
    }
    for (unsigned int j = 0; j < lambda; j++) {
        vs->V_rows[j] = vs->V_data + j * ellhat_bytes;
        vs->Q_rows[j] = vs->Q_data + j * ellhat_bytes;
    }
    return 0;
}

static void
vole_fill(vole_state_t *vs)
{
    unsigned int nb = vs->lambda / 8;
    prng_fill(vs->u, vs->ellhat_bytes);
    prng_fill(vs->V_data, (size_t)vs->lambda * vs->ellhat_bytes);
    prng_fill(vs->delta, nb);
    prng_fill(vs->chall_2, 3 * nb + 8);

    for (unsigned int j = 0; j < vs->lambda; j++) {
        uint8_t dj = (uint8_t)get_bit_t(vs->delta, j);
        for (size_t k = 0; k < vs->ellhat_bytes; k++)
            vs->Q_rows[j][k] = vs->V_rows[j][k] ^ (dj ? vs->u[k] : 0u);
    }
}

static void
vole_free(vole_state_t *vs)
{
    free(vs->u);
    free(vs->V_data);
    free(vs->Q_data);
    free(vs->V_rows);
    free(vs->Q_rows);
    free(vs->delta);
    free(vs->chall_2);
}

/* =====================================================================
 * Helper: prove + verify round-trip.  Returns 1 = a0 match, 0 = mismatch,
 * -2 = setup/prove/verify error.
 * ===================================================================== */

static int
prove_verify(voleith_gf16_circuit_t *c, const voleith_gf16_t *witness,
             const voleith_gf16_t *instance, unsigned int lambda,
             uint32_t prng_seed)
{
    size_t ell = voleith_gf16_qs_ell(c);
    size_t ellhat_bytes = voleith_gf16_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0)
        return -2;

    prng_reset(prng_seed);
    vole_fill(&vs);

    /* d is 2*ell bytes (16-bit LE per slot). */
    uint8_t *d = calloc(2 * ell + 1, 1);
    if (!d) {
        vole_free(&vs);
        return -2;
    }
    if (voleith_gf16_qs_compute_d(c, witness, instance, vs.u, d) < 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0};
    int pr = voleith_gf16_qs_prove(c, witness, instance, lambda, vs.u,
                                   (const uint8_t **)vs.V_rows, vs.chall_2, d,
                                   a0, a1, a2);
    if (pr != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0_v[32] = {0};
    int vr =
        voleith_gf16_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
                               d, vs.delta, vs.chall_2, a1, a2, a0_v);
    if (vr != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    int match = (memcmp(a0, a0_v, nb) == 0) ? 1 : 0;
    free(d);
    vole_free(&vs);
    return match;
}

/* =====================================================================
 * Test 1: ell / ellhat calculations
 * ===================================================================== */

static void
test_ell_ellhat(void)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wc = voleith_gf16_add_mul(c, wa, wb);
    (void)wc;

    check("ell = 2+1 = 3", voleith_gf16_qs_ell(c) == 3);
    /* ellhat_bytes = 2*3 + ceil((3*128+16)/8) = 6 + 50 = 56 */
    check("ellhat(128) = 56", voleith_gf16_qs_ellhat(c, 128) == 56);
    /* ellhat_bytes = 6 + ceil((3*192+16)/8) = 6 + 74 = 80 */
    check("ellhat(192) = 80", voleith_gf16_qs_ellhat(c, 192) == 80);
    /* ellhat_bytes = 6 + ceil((3*256+16)/8) = 6 + 98 = 104 */
    check("ellhat(256) = 104", voleith_gf16_qs_ellhat(c, 256) == 104);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 2: Prove + verify roundtrip (lambda = 128, 192, 256)
 * Circuit: a * b = c  (one MUL gate, output checked against an instance)
 * ===================================================================== */

static void
test_roundtrip(void)
{
    uint16_t val_a = 0x5301, val_b = 0xCA7F;
    uint16_t val_c = voleith_gf16_mul(val_a, val_b);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wout = voleith_gf16_add_mul(c, wa, wb);
    gf16_wire_id w_expected = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, wout, w_expected);

    voleith_gf16_t witness[] = {val_a, val_b};
    voleith_gf16_t instance[] = {val_c};

    check("roundtrip lambda=128",
          prove_verify(c, witness, instance, 128, 0x11111111u) == 1);
    check("roundtrip lambda=192",
          prove_verify(c, witness, instance, 192, 0x22222222u) == 1);
    check("roundtrip lambda=256",
          prove_verify(c, witness, instance, 256, 0x33333333u) == 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 3: Invalid witness - a0_tilde must NOT match (soundness)
 * ===================================================================== */

static void
test_soundness(void)
{
    uint16_t val_a = 0x0007, val_b = 0x0003;
    uint16_t val_c = voleith_gf16_mul(val_a, val_b);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wout = voleith_gf16_add_mul(c, wa, wb);
    gf16_wire_id wexp = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, wout, wexp);

    voleith_gf16_t witness_bad[] = {0xFFFF, val_b}; /* wrong val_a */
    voleith_gf16_t instance[] = {val_c};

    check("invalid witness: a0_tilde mismatch or error",
          prove_verify(c, witness_bad, instance, 128, 0x44444444u) != 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 4: Tampered a1_tilde => a0_tilde mismatch
 * ===================================================================== */

static void
test_tampered_a1(void)
{
    uint16_t val_a = 0x1F2E, val_b = 0x2E1F;
    uint16_t val_c = voleith_gf16_mul(val_a, val_b);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wout = voleith_gf16_add_mul(c, wa, wb);
    gf16_wire_id wexp = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, wout, wexp);

    voleith_gf16_t witness[] = {val_a, val_b};
    voleith_gf16_t instance[] = {val_c};

    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;
    size_t ell = voleith_gf16_qs_ell(c);
    size_t ellhat_bytes = voleith_gf16_qs_ellhat(c, lambda);

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0) {
        voleith_gf16_circuit_free(c);
        return;
    }
    prng_reset(0x55555555u);
    vole_fill(&vs);

    uint8_t *d = calloc(2 * ell + 1, 1);
    voleith_gf16_qs_compute_d(c, witness, instance, vs.u, d);

    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0}, a0_v[32] = {0};
    voleith_gf16_qs_prove(c, witness, instance, lambda, vs.u,
                          (const uint8_t **)vs.V_rows, vs.chall_2, d, a0, a1,
                          a2);

    a1[0] ^= 0x42u; /* tamper */
    voleith_gf16_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows, d,
                           vs.delta, vs.chall_2, a1, a2, a0_v);

    check("tampered a1_tilde: mismatch", memcmp(a0, a0_v, nb) != 0);

    free(d);
    vole_free(&vs);
    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 5: assert_product inversion (Prop 6.4 over GF(2^16))
 * If a^2 * y = a and a * y^2 = y, then y = a^-1 (or a = y = 0).
 * ===================================================================== */

static void
test_assert_product_inversion(void)
{
    uint16_t a_val = 0x0053;
    uint16_t y_val = voleith_gf16_inv(a_val);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wy = voleith_gf16_add_witness(c);
    gf16_wire_id wa2 = voleith_gf16_add_square(c, wa);
    gf16_wire_id wy2 = voleith_gf16_add_square(c, wy);
    voleith_gf16_assert_product(c, wa2, wy, wa);
    voleith_gf16_assert_product(c, wa, wy2, wy);

    check("assert_product: ell = 2", voleith_gf16_qs_ell(c) == 2);

    voleith_gf16_t witness[] = {a_val, y_val};

    check("assert_product inversion: roundtrip lambda=128",
          prove_verify(c, witness, NULL, 128, 0x66666666u) == 1);
    check("assert_product inversion: roundtrip lambda=192",
          prove_verify(c, witness, NULL, 192, 0xAAAAAAAAu) == 1);
    check("assert_product inversion: roundtrip lambda=256",
          prove_verify(c, witness, NULL, 256, 0xBBBBBBBBu) == 1);

    /* Wrong inverse must fail at all lambda. */
    voleith_gf16_t witness_bad[] = {a_val, (uint16_t)(y_val ^ 0x0001)};
    check("assert_product wrong inverse: mismatch lambda=128",
          prove_verify(c, witness_bad, NULL, 128, 0x77777777u) != 1);
    check("assert_product wrong inverse: mismatch lambda=192",
          prove_verify(c, witness_bad, NULL, 192, 0x88888888u) != 1);
    check("assert_product wrong inverse: mismatch lambda=256",
          prove_verify(c, witness_bad, NULL, 256, 0x99999999u) != 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 5b: assert_product soundness (eval gate rejects c != a*b)
 * ===================================================================== */

static void
test_assert_product_soundness(void)
{
    uint16_t a = 0x0053, b = 0x00ca;
    uint16_t prod = voleith_gf16_mul(a, b);
    uint16_t cheat = (uint16_t)(prod ^ 0x0001);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wc = voleith_gf16_add_witness(c);
    voleith_gf16_assert_product(c, wa, wb, wc);

    voleith_gf16_t w_ok[3] = {a, b, prod};
    check("assert_product soundness: valid c=a*b accepted (128)",
          prove_verify(c, w_ok, NULL, 128, 0x5b000001u) == 1);

    voleith_gf16_t w_bad[3] = {a, b, cheat};
    check("assert_product soundness: c!=a*b rejected (128)",
          prove_verify(c, w_bad, NULL, 128, 0x5b000002u) != 1);
    check("assert_product soundness: c!=a*b rejected (192)",
          prove_verify(c, w_bad, NULL, 192, 0x5b000003u) != 1);
    check("assert_product soundness: c!=a*b rejected (256)",
          prove_verify(c, w_bad, NULL, 256, 0x5b000004u) != 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 5c: assert_product soundness by FORGERY (verifier-side rejection)
 *
 * Drives the unchecked prover seam so an inconsistent witness (c != a*b)
 * is carried past the eval gate to the verifier, which must reject it.
 * This isolates the v2 = embed(val_c) invariant: a forced degree-2 term
 * key[a]*key[b] cannot equal key[c] when c != a*b, so a0 diverges.
 * ===================================================================== */

static int
forge_verify(voleith_gf16_circuit_t *c, const voleith_gf16_t *witness,
             unsigned int lambda, uint32_t prng_seed)
{
    size_t ell = voleith_gf16_qs_ell(c);
    size_t ellhat_bytes = voleith_gf16_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0)
        return -2;

    prng_reset(prng_seed);
    vole_fill(&vs);

    uint8_t *d = calloc(2 * ell + 1, 1);
    if (!d) {
        vole_free(&vs);
        return -2;
    }
    if (voleith_gf16_qs_compute_d_unchecked(c, witness, NULL, vs.u, d) < 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0};
    if (voleith_gf16_qs_prove_unchecked(c, witness, NULL, lambda, vs.u,
                                        (const uint8_t **)vs.V_rows, vs.chall_2,
                                        d, a0, a1, a2) != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0_v[32] = {0};
    if (voleith_gf16_qs_verify(c, NULL, lambda, (const uint8_t **)vs.Q_rows, d,
                               vs.delta, vs.chall_2, a1, a2, a0_v) != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    int match = (memcmp(a0, a0_v, nb) == 0) ? 1 : 0;
    free(d);
    vole_free(&vs);
    return match;
}

static void
test_assert_product_forgery(void)
{
    uint16_t a = 0x0053, b = 0x00ca;
    uint16_t prod = voleith_gf16_mul(a, b);
    uint16_t cheat = (uint16_t)(prod ^ 0x0001);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wc = voleith_gf16_add_witness(c);
    voleith_gf16_assert_product(c, wa, wb, wc);

    voleith_gf16_t w_ok[3] = {a, b, prod};
    check("forgery seam: honest witness still verifies (128)",
          forge_verify(c, w_ok, 128, 0x5c000001u) == 1);

    voleith_gf16_t w_bad[3] = {a, b, cheat};
    check("forgery: c!=a*b rejected by verifier (128)",
          forge_verify(c, w_bad, 128, 0x5c000002u) == 0);
    check("forgery: c!=a*b rejected by verifier (192)",
          forge_verify(c, w_bad, 192, 0x5c000003u) == 0);
    check("forgery: c!=a*b rejected by verifier (256)",
          forge_verify(c, w_bad, 256, 0x5c000004u) == 0);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 6: assert_zero constraint
 * ===================================================================== */

static void
test_assert_zero(void)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id w = voleith_gf16_add_witness(c);
    gf16_wire_id z = voleith_gf16_add_instance(c);
    gf16_wire_id xr = voleith_gf16_add_xor(c, w, z);
    voleith_gf16_assert_zero(c, xr);

    voleith_gf16_t witness[] = {0xABCD};
    voleith_gf16_t instance[] = {0xABCD};
    check("assert_zero valid",
          prove_verify(c, witness, instance, 128, 0x88888888u) == 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 7: assert_equal constraint
 * ===================================================================== */

static void
test_assert_equal(void)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    voleith_gf16_assert_equal(c, wa, wb);

    voleith_gf16_t witness_eq[] = {0x7777, 0x7777};
    check("assert_equal valid",
          prove_verify(c, witness_eq, NULL, 128, 0x99999999u) == 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 8: XOR_CONST + LINEAR_MAP (identity) gate tag propagation
 * ===================================================================== */

static void
test_xor_const_linear_map(void)
{
    uint16_t key = 0x0001;
    uint16_t expected = key ^ 0x0063;

    /* Identity matrix (16x16): row i = (1 << i). */
    uint16_t ident[16];
    for (int i = 0; i < 16; i++)
        ident[i] = (uint16_t)(1u << i);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id w = voleith_gf16_add_witness(c);
    gf16_wire_id xc = voleith_gf16_add_xor_const(c, w, 0x0063);
    gf16_wire_id lm = voleith_gf16_add_linear_map(c, xc, ident);
    gf16_wire_id exp = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, lm, exp);

    voleith_gf16_t witness[] = {key};
    voleith_gf16_t instance[] = {expected};
    check("xor_const + linear_map: roundtrip",
          prove_verify(c, witness, instance, 128, 0xAAAAAAAAu) == 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 9: SQUARE gate tag propagation
 * Prove that s = a^2 in GF(2^16) (s checked against a public instance).
 * Exercises the prover/verifier squaring-matrix tag path.
 * ===================================================================== */

static void
test_square_gate(void)
{
    uint16_t a = 0xBEEF;
    uint16_t a2 = voleith_gf16_mul(a, a);

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id ws = voleith_gf16_add_square(c, wa);
    gf16_wire_id wexp = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, ws, wexp);

    check("square gate: ell = 1 (no mul slot)", voleith_gf16_qs_ell(c) == 1);

    voleith_gf16_t witness[] = {a};
    voleith_gf16_t instance[] = {a2};
    check("square gate: roundtrip lambda=128",
          prove_verify(c, witness, instance, 128, 0x59000001u) == 1);
    check("square gate: roundtrip lambda=256",
          prove_verify(c, witness, instance, 256, 0x59000002u) == 1);

    /* Wrong square value rejected. */
    voleith_gf16_t instance_bad[] = {(uint16_t)(a2 ^ 0x0001)};
    check("square gate: wrong a^2 rejected",
          prove_verify(c, witness, instance_bad, 128, 0x59000003u) != 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Test 10: Multiple MUL gates - accumulation correctness
 * Compute a*b XOR c*d = e, assert e == instance.
 * ===================================================================== */

static void
test_multiple_mul_gates(void)
{
    uint16_t a = 0x1122, b = 0x2233, cv = 0x3344, dv = 0x4455;
    uint16_t ab = voleith_gf16_mul(a, b);
    uint16_t cd = voleith_gf16_mul(cv, dv);
    uint16_t e = ab ^ cd;

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id wa = voleith_gf16_add_witness(c);
    gf16_wire_id wb = voleith_gf16_add_witness(c);
    gf16_wire_id wc = voleith_gf16_add_witness(c);
    gf16_wire_id wd = voleith_gf16_add_witness(c);
    gf16_wire_id wab = voleith_gf16_add_mul(c, wa, wb);
    gf16_wire_id wcd = voleith_gf16_add_mul(c, wc, wd);
    gf16_wire_id we = voleith_gf16_add_xor(c, wab, wcd);
    gf16_wire_id wexp = voleith_gf16_add_instance(c);
    voleith_gf16_assert_equal(c, we, wexp);

    check("multiple mul: ell = 6", voleith_gf16_qs_ell(c) == 6);

    voleith_gf16_t witness[] = {a, b, cv, dv};
    voleith_gf16_t instance[] = {e};
    check("multiple mul gates: roundtrip 128",
          prove_verify(c, witness, instance, 128, 0xBBBBBBBBu) == 1);
    check("multiple mul gates: roundtrip 256",
          prove_verify(c, witness, instance, 256, 0xCCCCCCCCu) == 1);

    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * main
 * ===================================================================== */

int
main(void)
{
    printf("test_gf16_quicksilver\n");

    test_ell_ellhat();
    test_roundtrip();
    test_soundness();
    test_tampered_a1();
    test_assert_product_inversion();
    test_assert_product_soundness();
    test_assert_product_forgery();
    test_assert_zero();
    test_assert_equal();
    test_xor_const_linear_map();
    test_square_gate();
    test_multiple_mul_gates();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
