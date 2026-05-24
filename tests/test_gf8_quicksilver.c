/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_gf8_quicksilver.c - Tests for the element-level (GF(2⁸)) QuickSilver
 *
 * Tests:
 *   1:  ell / ellhat calculations
 *   2:  Prove + verify roundtrip - correct witness (lambda = 128, 192, 256)
 *   3:  Invalid witness - a0_tilde must not match (soundness)
 *   4:  Tampered a1_tilde - a0_tilde must not match
 *   5:  assert_product only (no add_mul gates) - AES S-box inversion pattern
 *   6:  assert_zero constraint
 *   7:  assert_equal constraint
 *   8:  XOR_CONST and LINEAR_MAP gate tags
 *   9:  Multiple MUL gates - accumulation correctness
 *   10: AES-128 integration - prove knowledge of key via gf8 circuit
 *
 * VOLE setup: VOLE correlations are synthesized directly for testing.
 *   Q[j] = V[j] XOR (delta_j ? u : 0)   for each row j = 0..lambda-1.
 */

#include "gf8_prover.h"
#include "gf8_verifier.h"
#include "gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "field.h"

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
 * VOLE scaffolding (element-level)
 *
 * u has ellhat_bytes bytes:
 *   u[0..ell-1]            = element slot values (one byte each)
 *   u[ell..ellhat_bytes-1] = correction bytes
 *
 * VOLE relation (same as bit-level):
 *   Q[j] = V[j] XOR (delta_j ? u : 0)  for each row j
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

    /* Build Q[j] = V[j] XOR (delta_j ? u : 0) */
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
 * Helper: prove + verify round-trip
 * ===================================================================== */

static int
prove_verify(voleith_gf8_circuit_t *c, const uint8_t *witness, size_t n_witness,
             const uint8_t *instance, size_t n_instance, unsigned int lambda,
             uint32_t prng_seed)
{
    (void)n_witness;
    (void)n_instance;
    size_t ell = voleith_gf8_qs_ell(c);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0)
        return -2;

    prng_reset(prng_seed);
    vole_fill(&vs);

    /* Prover: compute d */
    uint8_t *d = calloc(ell, 1);
    if (!d) {
        vole_free(&vs);
        return -2;
    }
    if (voleith_gf8_qs_compute_d(c, witness, instance, vs.u, d) < 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    /* Prover: prove */
    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0};
    int pr = voleith_gf8_qs_prove(c, witness, instance, lambda, vs.u,
                                  (const uint8_t **)vs.V_rows, vs.chall_2, d,
                                  a0, a1, a2);
    if (pr != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    /* Verifier: verify */
    uint8_t a0_v[32] = {0};
    int vr =
        voleith_gf8_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
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
    /* Circuit: 2 witness wires, 1 mul gate */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wc = voleith_gf8_add_mul(c, wa, wb);
    (void)wc;

    check("ell = 2+1 = 3", voleith_gf8_qs_ell(c) == 3);
    /* ellhat_bytes = 3 + ceil((3*128+16)/8) = 3 + ceil(400/8) = 3 + 50 = 53 */
    check("ellhat(128) = 53", voleith_gf8_qs_ellhat(c, 128) == 53);
    /* ellhat_bytes = 3 + ceil((3*192+16)/8) = 3 + ceil(592/8) = 3 + 74 = 77 */
    check("ellhat(192) = 77", voleith_gf8_qs_ellhat(c, 192) == 77);
    /* ellhat_bytes = 3 + ceil((3*256+16)/8) = 3 + ceil(784/8) = 3 + 98 = 101 */
    check("ellhat(256) = 101", voleith_gf8_qs_ellhat(c, 256) == 101);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 2: Prove + verify roundtrip (lambda = 128, 192, 256)
 *
 * Circuit: a * b = c  (one MUL gate + one assert_product to check c = a*b)
 * ===================================================================== */

static void
test_roundtrip(void)
{
    /* Use GF(2^8) multiplication: 0x53 * 0xCA = ? */
    uint8_t val_a = 0x53, val_b = 0xCA;
    uint8_t val_c = voleith_gf8_mul(val_a, val_b);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);       /* a */
    gf8_wire_id wb = voleith_gf8_add_witness(c);       /* b */
    gf8_wire_id wout = voleith_gf8_add_mul(c, wa, wb); /* a*b */
    /* Assert the product matches a public instance */
    gf8_wire_id w_expected = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, wout, w_expected);

    uint8_t witness[] = {val_a, val_b};
    uint8_t instance[] = {val_c};

    int r128 = prove_verify(c, witness, 2, instance, 1, 128, 0x11111111u);
    int r192 = prove_verify(c, witness, 2, instance, 1, 192, 0x22222222u);
    int r256 = prove_verify(c, witness, 2, instance, 1, 256, 0x33333333u);

    check("roundtrip lambda=128", r128 == 1);
    check("roundtrip lambda=192", r192 == 1);
    check("roundtrip lambda=256", r256 == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 3: Invalid witness - a0_tilde must NOT match (soundness)
 * ===================================================================== */

static void
test_soundness(void)
{
    uint8_t val_a = 0x07, val_b = 0x03;
    uint8_t val_c = voleith_gf8_mul(val_a, val_b);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wout = voleith_gf8_add_mul(c, wa, wb);
    gf8_wire_id wexp = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, wout, wexp);

    uint8_t witness_bad[] = {0xFF, val_b}; /* wrong val_a */
    uint8_t instance[] = {val_c};

    int r = prove_verify(c, witness_bad, 2, instance, 1, 128, 0x44444444u);
    /* With wrong witness, either prove returns error (circuit_eval fails
     * constraint check) or a0_tilde doesn't match. Either way r != 1. */
    check("invalid witness: a0_tilde mismatch or error", r != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 4: Tampered a1_tilde → a0_tilde mismatch
 * ===================================================================== */

static void
test_tampered_a1(void)
{
    uint8_t val_a = 0x1F, val_b = 0x2E;
    uint8_t val_c = voleith_gf8_mul(val_a, val_b);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wout = voleith_gf8_add_mul(c, wa, wb);
    gf8_wire_id wexp = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, wout, wexp);

    uint8_t witness[] = {val_a, val_b};
    uint8_t instance[] = {val_c};

    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;
    size_t ell = voleith_gf8_qs_ell(c);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(c, lambda);

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0) {
        voleith_gf8_circuit_free(c);
        return;
    }
    prng_reset(0x55555555u);
    vole_fill(&vs);

    uint8_t *d = calloc(ell, 1);
    voleith_gf8_qs_compute_d(c, witness, instance, vs.u, d);

    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0}, a0_v[32] = {0};
    voleith_gf8_qs_prove(c, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d, a0, a1,
                         a2);

    /* Tamper a1_tilde */
    a1[0] ^= 0x42u;
    voleith_gf8_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows, d,
                          vs.delta, vs.chall_2, a1, a2, a0_v);

    check("tampered a1_tilde: mismatch", memcmp(a0, a0_v, nb) != 0);

    free(d);
    vole_free(&vs);
    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 5: assert_product only - AES S-box inversion pattern
 *
 * Prop 6.4: if a²·y = a and a·y² = y, then y = a⁻¹ (or a=y=0).
 * No add_mul gates; assert_product is free (zero VOLE slots added).
 * ===================================================================== */

static void
test_assert_product_inversion(void)
{
    /* Use a = 0x53, y = gf8_inv(0x53) */
    uint8_t a_val = 0x53;
    /* Compute inverse: find y s.t. gf8_mul(a, y) = 1 */
    uint8_t y_val = 0;
    for (uint16_t x = 1; x < 256; x++) {
        if (voleith_gf8_mul(a_val, (uint8_t)x) == 1) {
            y_val = (uint8_t)x;
            break;
        }
    }

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);     /* a */
    gf8_wire_id wy = voleith_gf8_add_witness(c);     /* y = a⁻¹ */
    gf8_wire_id wa2 = voleith_gf8_add_square(c, wa); /* a² (free) */
    gf8_wire_id wy2 = voleith_gf8_add_square(c, wy); /* y² (free) */
    /* assert a² · y = a */
    voleith_gf8_assert_product(c, wa2, wy, wa);
    /* assert a · y² = y */
    voleith_gf8_assert_product(c, wa, wy2, wy);

    /* ell = 2 (just the two witness bytes), n_mul = 0 */
    check("assert_product: ell = 2", voleith_gf8_qs_ell(c) == 2);

    uint8_t witness[] = {a_val, y_val};
    uint8_t instance[] = {0}; /* no instance wires */

    int r = prove_verify(c, witness, 2, instance, 0, 128, 0x66666666u);
    check("assert_product inversion: roundtrip", r == 1);

    int r192 = prove_verify(c, witness, 2, instance, 0, 192, 0xAAAAAAAAu);
    int r256 = prove_verify(c, witness, 2, instance, 0, 256, 0xBBBBBBBBu);
    check("assert_product inversion: roundtrip lambda=192", r192 == 1);
    check("assert_product inversion: roundtrip lambda=256", r256 == 1);

    /* Wrong inverse - must fail at all lambda sizes */
    uint8_t witness_bad[] = {a_val, 0x42}; /* 0x42 != gf8_inv(0x53) */
    int r2 = prove_verify(c, witness_bad, 2, instance, 0, 128, 0x77777777u);
    int r2_192 = prove_verify(c, witness_bad, 2, instance, 0, 192, 0x88888888u);
    int r2_256 = prove_verify(c, witness_bad, 2, instance, 0, 256, 0x99999999u);
    check("assert_product wrong inverse: mismatch lambda=128", r2 != 1);
    check("assert_product wrong inverse: mismatch lambda=192", r2_192 != 1);
    check("assert_product wrong inverse: mismatch lambda=256", r2_256 != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 6: assert_zero constraint
 * ===================================================================== */

static void
test_assert_zero(void)
{
    /* Circuit: witness w, instance z, assert w XOR z = 0 (i.e. w = z) */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id w = voleith_gf8_add_witness(c);
    gf8_wire_id z = voleith_gf8_add_instance(c);
    gf8_wire_id xr = voleith_gf8_add_xor(c, w, z);
    voleith_gf8_assert_zero(c, xr);

    uint8_t witness[] = {0xAB};
    uint8_t instance[] = {0xAB};
    int r = prove_verify(c, witness, 1, instance, 1, 128, 0x88888888u);
    check("assert_zero valid", r == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 7: assert_equal constraint
 * ===================================================================== */

static void
test_assert_equal(void)
{
    /* Circuit: two witness wires, assert they're equal */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    voleith_gf8_assert_equal(c, wa, wb);

    uint8_t witness_eq[] = {0x77, 0x77};
    int r = prove_verify(c, witness_eq, 2, NULL, 0, 128, 0x99999999u);
    check("assert_equal valid", r == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 8: XOR_CONST and LINEAR_MAP gate tag propagation
 *
 * Build: w → xor_const(w, 0x63) → out; assert_equal(out, instance)
 * The LINEAR_MAP gate: apply an identity matrix (should be transparent).
 * ===================================================================== */

static void
test_xor_const_linear_map(void)
{
    uint8_t key = 0x01;
    /* Identity matrix (8×8) */
    static const uint8_t IDENT[8] = {0x01, 0x02, 0x04, 0x08,
                                     0x10, 0x20, 0x40, 0x80};
    uint8_t expected = key ^ 0x63;

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id w = voleith_gf8_add_witness(c);
    gf8_wire_id xc = voleith_gf8_add_xor_const(c, w, 0x63);
    gf8_wire_id lm = voleith_gf8_add_linear_map(c, xc, IDENT);
    gf8_wire_id exp = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, lm, exp);

    uint8_t witness[] = {key};
    uint8_t instance[] = {expected};
    int r = prove_verify(c, witness, 1, instance, 1, 128, 0xAAAAAAAAu);
    check("xor_const + linear_map: roundtrip", r == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 9: Multiple MUL gates - accumulation correctness
 * ===================================================================== */

static void
test_multiple_mul_gates(void)
{
    /* Compute a*b + c*d as (a*b) XOR (c*d) = e, assert e == instance */
    uint8_t a = 0x11, b = 0x22, cv = 0x33, dv = 0x44;
    uint8_t ab = voleith_gf8_mul(a, b);
    uint8_t cd = voleith_gf8_mul(cv, dv);
    uint8_t e = ab ^ cd;

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wc = voleith_gf8_add_witness(c);
    gf8_wire_id wd = voleith_gf8_add_witness(c);
    gf8_wire_id wab = voleith_gf8_add_mul(c, wa, wb);
    gf8_wire_id wcd = voleith_gf8_add_mul(c, wc, wd);
    gf8_wire_id we = voleith_gf8_add_xor(c, wab, wcd);
    gf8_wire_id wexp = voleith_gf8_add_instance(c);
    voleith_gf8_assert_equal(c, we, wexp);

    check("multiple mul: ell = 6", voleith_gf8_qs_ell(c) == 6);

    uint8_t witness[] = {a, b, cv, dv};
    uint8_t instance[] = {e};
    int r128 = prove_verify(c, witness, 4, instance, 1, 128, 0xBBBBBBBBu);
    int r256 = prove_verify(c, witness, 4, instance, 1, 256, 0xCCCCCCCCu);
    check("multiple mul gates: roundtrip 128", r128 == 1);
    check("multiple mul gates: roundtrip 256", r256 == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 10: AES-128 integration - prove key knowledge via gf8 circuit
 *
 * Key: 00 01 02 ... 0f
 * PT:  00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
 * CT:  69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a
 * ===================================================================== */

static void
test_aes128_integration(void)
{
    static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t CT[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                   0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                   0x70, 0xb4, 0xc5, 0x5a};

    /* Build the GF(2^8) AES-128 circuit:
     * Key bytes are witness (slots 0..15).
     * Plaintext bytes are instance.
     * Ciphertext bytes are constrained to equal the public CT. */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        check("aes128 integration: circuit alloc", 0);
        return;
    }

    gf8_wire_id key_wires[16], pt_wires[16], ct_wires[16];
    for (int i = 0; i < 16; i++)
        key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt_wires[i] = voleith_gf8_add_instance(c);

    aes128_gf8_circuit(c, key_wires, pt_wires, ct_wires);

    /* Constrain output = public CT */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id w_ct = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, ct_wires[i], w_ct);
    }

    if (!voleith_gf8_circuit_ok(c)) {
        check("aes128 integration: circuit build ok", 0);
        voleith_gf8_circuit_free(c);
        return;
    }

    check("aes128 integration: ell = 216", voleith_gf8_qs_ell(c) == 216);

    /* Build witness: key bytes (16) + inv_in bytes (200) */
    uint8_t ct_out[16];
    uint8_t witness[216];
    aes128_gf8_build_witness(KEY, PT, witness, ct_out);

    check("aes128 integration: ct matches", memcmp(ct_out, CT, 16) == 0);

    /* Instance: PT (16 bytes) + CT (16 bytes) */
    uint8_t instance[32];
    memcpy(instance, PT, 16);
    memcpy(instance + 16, CT, 16);

    int r = prove_verify(c, witness, 216, instance, 32, 128, 0xDDDDDDDDu);
    check("aes128 integration: roundtrip lambda=128", r == 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * main
 * ===================================================================== */

int
main(void)
{
    printf("test_gf8_quicksilver\n");

    test_ell_ellhat();
    test_roundtrip();
    test_soundness();
    test_tampered_a1();
    test_assert_product_inversion();
    test_assert_zero();
    test_assert_equal();
    test_xor_const_linear_map();
    test_multiple_mul_gates();
    test_aes128_integration();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
