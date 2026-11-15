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
#include "gf8_prover_internal.h" /* test-only unchecked prove seam (S-6) */
#include "gf8_verifier.h"
#include "gf8_circuit.h"
#include "qs_degree.h" /* VOLEITH_QS_COEFFS_MAX */
#include "aes_gf8_circuit.h"
#include "aes_norm_gf8_circuit.h"
#include "gf8_grostl_norm_const.h"
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
    uint8_t *a_out[3] = {a0, a1, a2};
    int pr =
        voleith_gf8_qs_prove(c, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d, a_out);
    if (pr != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    /* Verifier: verify */
    uint8_t a0_v[32] = {0};
    const uint8_t *a_in[3] = {NULL, a1, a2};
    int vr =
        voleith_gf8_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
                              d, vs.delta, vs.chall_2, a_in, a0_v);
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
    uint8_t *a_out[3] = {a0, a1, a2};
    voleith_gf8_qs_prove(c, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d, a_out);

    /* Tamper a1_tilde */
    a1[0] ^= 0x42u;
    const uint8_t *a_in[3] = {NULL, a1, a2};
    voleith_gf8_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows, d,
                          vs.delta, vs.chall_2, a_in, a0_v);

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
 * Test 5b: assert_product soundness invariant (embed(val_c))
 *
 * Pins the requirement that a PRODUCT constraint a*b = c with a claimed
 * c != a*b is rejected.  This is the invariant behind gf8_prover.c: the
 * PRODUCT-constraint degree-2 term uses v2 = embed(val_c) (the *claimed*
 * product), NOT embed(val_a*val_b).  Using the actual product would make
 * the ZK hash consistent regardless of whether c = a*b, silently
 * breaking soundness - a documented past regression.  The honest prover
 * also rejects such a witness at its up-front circuit_eval gate; either
 * path must yield rejection (prove_verify != 1), so this test fails
 * loudly if either guard is removed.
 *
 * Unlike test_assert_product_inversion (a composite x/x^-1 circuit), this
 * is a single bare PRODUCT constraint, so a failure points straight at
 * the product check.
 * ===================================================================== */

static void
test_assert_product_soundness(void)
{
    uint8_t a = 0x53, b = 0xca;
    uint8_t prod = voleith_gf8_mul(a, b);
    uint8_t cheat = (uint8_t)(prod ^ 0x01); /* guaranteed != a*b */

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wc = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product(c, wa, wb, wc);

    /* Positive control: c = a*b verifies. */
    uint8_t w_ok[3] = {a, b, prod};
    check("assert_product soundness: valid c=a*b accepted (128)",
          prove_verify(c, w_ok, 3, NULL, 0, 128, 0x5b000001u) == 1);

    /* Cheat: c != a*b rejected at all three security levels. */
    uint8_t w_bad[3] = {a, b, cheat};
    check("assert_product soundness: c!=a*b rejected (128)",
          prove_verify(c, w_bad, 3, NULL, 0, 128, 0x5b000002u) != 1);
    check("assert_product soundness: c!=a*b rejected (192)",
          prove_verify(c, w_bad, 3, NULL, 0, 192, 0x5b000003u) != 1);
    check("assert_product soundness: c!=a*b rejected (256)",
          prove_verify(c, w_bad, 3, NULL, 0, 256, 0x5b000004u) != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test 5c: assert_product soundness by FORGERY (embed(val_c) isolation)
 *
 * test_assert_product_soundness above only exercises the prover's
 * up-front circuit_eval gate: the honest prover refuses to emit a proof
 * for c != a*b, so the verifier-side check is never reached.  This test
 * uses the prover's unchecked test seam (gf8_prover_internal.h) to emit
 * a proof for the inconsistent witness anyway, then confirms the
 * VERIFIER rejects it - the reconstructed a0 diverges from the prover's
 * committed a0 because the forced degree-2 term key[a]*key[b] cannot
 * equal key[c] when c != a*b.  That divergence is exactly what
 * v2 = embed(val_c) (NOT embed(val_a*val_b)) guarantees, so this test
 * fails if the embed invariant regresses, independent of the eval gate.
 * ===================================================================== */

/* Like prove_verify, but drives the unchecked prover seam so a
 * constraint-violating witness is carried through to the verifier.
 * Returns 1 = verifier accepts (a0 match), 0 = verifier rejects
 * (mismatch), -2 = setup/prove error. */
static int
forge_verify(voleith_gf8_circuit_t *c, const uint8_t *witness,
             unsigned int lambda, uint32_t prng_seed)
{
    size_t ell = voleith_gf8_qs_ell(c);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0)
        return -2;

    prng_reset(prng_seed);
    vole_fill(&vs);

    uint8_t *d = calloc(ell, 1);
    if (!d) {
        vole_free(&vs);
        return -2;
    }
    if (voleith_gf8_qs_compute_d_unchecked(c, witness, NULL, vs.u, d) < 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0[32] = {0}, a1[32] = {0}, a2[32] = {0};
    uint8_t *a_out[3] = {a0, a1, a2};
    if (voleith_gf8_qs_prove_unchecked(c, witness, NULL, lambda, vs.u,
                                       (const uint8_t **)vs.V_rows, vs.chall_2,
                                       d, a_out) != 0) {
        free(d);
        vole_free(&vs);
        return -2;
    }

    uint8_t a0_v[32] = {0};
    const uint8_t *a_in[3] = {NULL, a1, a2};
    if (voleith_gf8_qs_verify(c, NULL, lambda, (const uint8_t **)vs.Q_rows, d,
                              vs.delta, vs.chall_2, a_in, a0_v) != 0) {
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
    uint8_t a = 0x53, b = 0xca;
    uint8_t prod = voleith_gf8_mul(a, b);
    uint8_t cheat = (uint8_t)(prod ^ 0x01); /* guaranteed != a*b */

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wc = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product(c, wa, wb, wc);

    /* Control: the unchecked seam still verifies an HONEST witness. */
    uint8_t w_ok[3] = {a, b, prod};
    check("forgery seam: honest witness still verifies (128)",
          forge_verify(c, w_ok, 128, 0x5c000001u) == 1);

    /* Forgery: c != a*b emitted past the eval gate must be REJECTED by
     * the verifier (a0 mismatch) at all three security levels. */
    uint8_t w_bad[3] = {a, b, cheat};
    check("forgery: c!=a*b rejected by verifier (128)",
          forge_verify(c, w_bad, 128, 0x5c000002u) == 0);
    check("forgery: c!=a*b rejected by verifier (192)",
          forge_verify(c, w_bad, 192, 0x5c000003u) == 0);
    check("forgery: c!=a*b rejected by verifier (256)",
          forge_verify(c, w_bad, 256, 0x5c000004u) == 0);

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
 * Less-than (NLT) degree-(w+1) constraint tests
 *
 * These are the first d>2 QuickSilver consumer.  The negative cases use the
 * UNCHECKED prover so it commits a witness violating the constraint; a sound
 * verifier must then reject (a0 mismatch).  This is what proves the degree-d
 * path binds, which the d=2 suite cannot exercise.
 * ===================================================================== */

/*
 * Run one prove+verify over an arbitrary circuit with witness `witness`.
 * use_unchecked=1 uses the unchecked prover (commits invalid witnesses).
 * Returns 1 if a0 matches (verify accepts), 0 if mismatch (reject), -2 error.
 */
static int
run_proof(voleith_gf8_circuit_t *c, const uint8_t *witness, unsigned int lambda,
          int use_unchecked)
{
    size_t ell = voleith_gf8_qs_ell(c);
    size_t ellhat_bytes = voleith_gf8_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;
    unsigned int d = voleith_gf8_circuit_qs_degree(c);

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes) < 0)
        return -2;
    prng_reset(0x51EED123u);
    vole_fill(&vs);

    uint8_t *dcorr = calloc(ell ? ell : 1, 1);
    int rc = -2;
    if (!dcorr)
        goto done;
    if (voleith_gf8_qs_compute_d_unchecked(c, witness, NULL, vs.u, dcorr) < 0)
        goto done;

    uint8_t a_buf[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t *a_out[VOLEITH_QS_COEFFS_MAX];
    memset(a_buf, 0, sizeof(a_buf));
    for (unsigned int i = 0; i <= d; i++)
        a_out[i] = a_buf[i];

    int pr = use_unchecked
                 ? voleith_gf8_qs_prove_unchecked(
                       c, witness, NULL, lambda, vs.u,
                       (const uint8_t **)vs.V_rows, vs.chall_2, dcorr, a_out)
                 : voleith_gf8_qs_prove(c, witness, NULL, lambda, vs.u,
                                        (const uint8_t **)vs.V_rows, vs.chall_2,
                                        dcorr, a_out);
    if (pr != 0) {
        rc = -2;
        goto done;
    }

    const uint8_t *a_in[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int i = 1; i <= d; i++)
        a_in[i] = a_buf[i];
    uint8_t a0_v[32] = {0};
    if (voleith_gf8_qs_verify(c, NULL, lambda, (const uint8_t **)vs.Q_rows,
                              dcorr, vs.delta, vs.chall_2, a_in, a0_v) != 0) {
        rc = -2;
        goto done;
    }
    rc = (memcmp(a_buf[0], a0_v, nb) == 0) ? 1 : 0;

done:
    free(dcorr);
    vole_free(&vs);
    return rc;
}

/* Build a circuit asserting A < B over `w` witness bit wires each (MSB-first),
 * plus optionally one PRODUCT gate (p_a*p_b == p_c) to test mixed degree.
 * Witness layout: [A bits (w)] [B bits (w)] [p_a p_b p_c if with_product]. */
static voleith_gf8_circuit_t *
build_lt_circuit(unsigned int w, int with_product)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c)
        return NULL;
    gf8_wire_id a_bits[32], b_bits[32];
    for (unsigned int i = 0; i < w; i++)
        a_bits[i] = voleith_gf8_add_witness(c);
    for (unsigned int i = 0; i < w; i++)
        b_bits[i] = voleith_gf8_add_witness(c);
    voleith_gf8_assert_lt(c, a_bits, b_bits, w);
    if (with_product) {
        gf8_wire_id pa = voleith_gf8_add_witness(c);
        gf8_wire_id pb = voleith_gf8_add_witness(c);
        gf8_wire_id pc = voleith_gf8_add_witness(c);
        voleith_gf8_assert_product(c, pa, pb, pc);
    }
    return c;
}

/* Fill witness bits (MSB-first) for w-bit values A,B into buf[0..2w-1]. */
static void
fill_lt_witness(uint8_t *buf, unsigned int w, unsigned int A, unsigned int B)
{
    for (unsigned int i = 0; i < w; i++)
        buf[i] = (uint8_t)((A >> (w - 1 - i)) & 1u);
    for (unsigned int i = 0; i < w; i++)
        buf[w + i] = (uint8_t)((B >> (w - 1 - i)) & 1u);
}

static void
test_lt_basic(void)
{
    const unsigned int w = 4;
    unsigned int lambda = 128;
    /* Accept: A < B (checked prover ok). */
    struct {
        unsigned int A, B;
        int expect; /* 1 accept, 0 reject */
    } cases[] = {
        {3, 5, 1}, {0, 15, 1}, {6, 7, 1},   {5, 3, 0},
        {7, 7, 0}, {15, 0, 0}, {10, 10, 0}, {8, 9, 1},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        voleith_gf8_circuit_t *c = build_lt_circuit(w, 0);
        uint8_t wit[8];
        fill_lt_witness(wit, w, cases[i].A, cases[i].B);
        int r =
            run_proof(c, wit, lambda, 1 /* unchecked: exercise soundness */);
        char name[64];
        snprintf(name, sizeof(name), "LT w=4 A=%u B=%u -> %s", cases[i].A,
                 cases[i].B, cases[i].expect ? "accept" : "reject");
        check(name, r == cases[i].expect);
        voleith_gf8_circuit_free(c);
    }
    /* A<B via the CHECKED prover must also produce an accepting proof. */
    {
        voleith_gf8_circuit_t *c = build_lt_circuit(w, 0);
        uint8_t wit[8];
        fill_lt_witness(wit, w, 4, 9);
        check("LT checked prover A<B accepts",
              run_proof(c, wit, lambda, 0) == 1);
        voleith_gf8_circuit_free(c);
    }
    /* A>=B via the CHECKED prover must be refused at eval (returns error). */
    {
        voleith_gf8_circuit_t *c = build_lt_circuit(w, 0);
        uint8_t wit[8];
        fill_lt_witness(wit, w, 9, 4);
        check("LT checked prover A>=B refused",
              run_proof(c, wit, lambda, 0) == -2);
        voleith_gf8_circuit_free(c);
    }
}

static void
test_lt_mixed_degree(void)
{
    /* Circuit mixes a degree-2 PRODUCT and a degree-(w+1) LT.  Violating
     * EITHER must reject: this proves the natural-position batching binds both
     * degrees (the discriminator for zero-pad vs top-align soundness). */
    const unsigned int w = 4;
    unsigned int lambda = 192;
    uint8_t wit[11];

    /* both hold: A<B and pa*pb==pc (2*3=6). */
    voleith_gf8_circuit_t *c = build_lt_circuit(w, 1);
    fill_lt_witness(wit, w, 5, 12);
    wit[8] = 2;
    wit[9] = 3;
    wit[10] = voleith_gf8_mul(2, 3);
    check("mixed both-hold accepts", run_proof(c, wit, lambda, 1) == 1);
    voleith_gf8_circuit_free(c);

    /* violate PRODUCT only (LT still holds). */
    c = build_lt_circuit(w, 1);
    fill_lt_witness(wit, w, 5, 12);
    wit[8] = 2;
    wit[9] = 3;
    wit[10] = voleith_gf8_mul(2, 3) ^ 0x01; /* wrong product */
    check("mixed violate-product rejects", run_proof(c, wit, lambda, 1) == 0);
    voleith_gf8_circuit_free(c);

    /* violate LT only (product still holds). */
    c = build_lt_circuit(w, 1);
    fill_lt_witness(wit, w, 12, 5); /* A>=B */
    wit[8] = 2;
    wit[9] = 3;
    wit[10] = voleith_gf8_mul(2, 3);
    check("mixed violate-LT rejects", run_proof(c, wit, lambda, 1) == 0);
    voleith_gf8_circuit_free(c);
}

static void
test_lt_degree_accessor(void)
{
    voleith_gf8_circuit_t *c0 = voleith_gf8_circuit_new();
    gf8_wire_id a = voleith_gf8_add_witness(c0);
    gf8_wire_id b = voleith_gf8_add_witness(c0);
    (void)voleith_gf8_add_mul(c0, a, b);
    check("qs_degree=2 for LT-free circuit",
          voleith_gf8_circuit_qs_degree(c0) == 2);
    voleith_gf8_circuit_free(c0);

    voleith_gf8_circuit_t *c = build_lt_circuit(15, 0);
    check("qs_degree=w+1 for LT circuit (w=15 -> 16)",
          voleith_gf8_circuit_qs_degree(c) == 16);
    voleith_gf8_circuit_free(c);
}

static void
test_lt_wide(void)
{
    /* Opener-scale width (w=15 -> d=16) at lambda 256, accept + reject. */
    const unsigned int w = 15;
    unsigned int lambda = 256;
    uint8_t wit[30];

    voleith_gf8_circuit_t *c = build_lt_circuit(w, 0);
    fill_lt_witness(wit, w, 0x1234, 0x5678);
    check("LT w=15 A<B accepts", run_proof(c, wit, lambda, 1) == 1);
    voleith_gf8_circuit_free(c);

    c = build_lt_circuit(w, 0);
    fill_lt_witness(wit, w, 0x5678, 0x1234);
    check("LT w=15 A>B rejects", run_proof(c, wit, lambda, 1) == 0);
    voleith_gf8_circuit_free(c);

    c = build_lt_circuit(w, 0);
    fill_lt_witness(wit, w, 0x2AAA, 0x2AAA);
    check("LT w=15 A==B rejects", run_proof(c, wit, lambda, 1) == 0);
    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Three-way product (PRODUCT3) degree-3 constraint tests
 *
 * PRODUCT3 asserts a·b·c == d (FAEST norm S-box, spec Fig 6.19).  The
 * relation has degree 3 but parks the target at the top (∆³) coefficient,
 * which vanishes for an honest prover, so it opens at d = 2 like PRODUCT.
 * The forgery cases drive the UNCHECKED prover past the eval gate to prove
 * the verifier binds the parked degree-3 relation (a cheat's ∆³ term is
 * caught); the d = 2 PRODUCT suite cannot exercise this.
 * ===================================================================== */

/* a·b·c == d.  Witness layout: [a b c d]. */
static voleith_gf8_circuit_t *
build_product3_circuit(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (c == NULL)
        return NULL;
    gf8_wire_id wa = voleith_gf8_add_witness(c);
    gf8_wire_id wb = voleith_gf8_add_witness(c);
    gf8_wire_id wc = voleith_gf8_add_witness(c);
    gf8_wire_id wd = voleith_gf8_add_witness(c);
    voleith_gf8_assert_product3(c, wa, wb, wc, wd);
    return c;
}

static void
test_product3_basic(void)
{
    uint8_t a = 0x53, b = 0xca, cc = 0x1f;
    uint8_t prod = voleith_gf8_mul(voleith_gf8_mul(a, b), cc);

    /* Opening count stays d = 2 (parked top): no VOLEITH_QS_D_MAX need. */
    voleith_gf8_circuit_t *cq = build_product3_circuit();
    check("product3: qs_degree == 2 (rides d=2 opening)",
          voleith_gf8_circuit_qs_degree(cq) == 2);
    voleith_gf8_circuit_free(cq);

    /* Honest a·b·c == d accepts at all three levels. */
    uint8_t w_ok[4] = {a, b, cc, prod};
    voleith_gf8_circuit_t *c = build_product3_circuit();
    check("product3: honest accept (128)",
          prove_verify(c, w_ok, 4, NULL, 0, 128, 0xd3000001u) == 1);
    check("product3: honest accept (192)",
          prove_verify(c, w_ok, 4, NULL, 0, 192, 0xd3000002u) == 1);
    check("product3: honest accept (256)",
          prove_verify(c, w_ok, 4, NULL, 0, 256, 0xd3000003u) == 1);
    voleith_gf8_circuit_free(c);

    /* Wrong d: the checked prover refuses at its eval gate (!= accept). */
    uint8_t w_bad[4] = {a, b, cc, (uint8_t)(prod ^ 0x01)};
    c = build_product3_circuit();
    check("product3: wrong d rejected by checked prover (128)",
          prove_verify(c, w_bad, 4, NULL, 0, 128, 0xd3000004u) != 1);
    voleith_gf8_circuit_free(c);
}

static void
test_product3_forgery(void)
{
    uint8_t a = 0x53, b = 0xca, cc = 0x1f;
    uint8_t prod = voleith_gf8_mul(voleith_gf8_mul(a, b), cc);

    /* Control: unchecked seam still accepts an honest witness. */
    uint8_t w_ok[4] = {a, b, cc, prod};
    voleith_gf8_circuit_t *c = build_product3_circuit();
    check("product3 forgery seam: honest still verifies (128)",
          run_proof(c, w_ok, 128, 1) == 1);
    voleith_gf8_circuit_free(c);

    /*
     * Forgery: a·b·c != d pushed past the eval gate must be REJECTED by the
     * verifier at all three levels.  This is the parked-degree-3 bind: the
     * cheat leaves a nonzero ∆³ term the d = 2 opening cannot match, so the
     * reconstructed a0 diverges.  Validates the target-parking / a_3-vanishes
     * soundness that the d = 2 PRODUCT path cannot reach.
     */
    uint8_t w_bad[4] = {a, b, cc, (uint8_t)(prod ^ 0x01)};
    c = build_product3_circuit();
    check("product3 forgery: a·b·c != d rejected by verifier (128)",
          run_proof(c, w_bad, 128, 1) == 0);
    voleith_gf8_circuit_free(c);
    c = build_product3_circuit();
    check("product3 forgery: a·b·c != d rejected by verifier (192)",
          run_proof(c, w_bad, 192, 1) == 0);
    voleith_gf8_circuit_free(c);
    c = build_product3_circuit();
    check("product3 forgery: a·b·c != d rejected by verifier (256)",
          run_proof(c, w_bad, 256, 1) == 0);
    voleith_gf8_circuit_free(c);
}

static void
test_product3_norm(void)
{
    /*
     * The real FAEST norm relation y·a²·a¹⁶ == a (spec Fig 6.19), wired with
     * free Frobenius (square) gates as Phase 1 will build it.  y is the
     * inverse F2⁴-norm a⁻¹⁷.  Validates honest accept and wrong-y reject on
     * the exact operand pattern the AES norm circuit will emit.
     */
    uint8_t a = 0x53;
    uint8_t a2 = voleith_gf8_mul(a, a);
    uint8_t a16 = a;
    for (int i = 0; i < 4; i++)
        a16 = voleith_gf8_mul(a16, a16);     /* a^16 */
    uint8_t base = voleith_gf8_mul(a2, a16); /* a^18 */
    uint8_t y = 0;
    for (uint16_t x = 1; x < 256; x++)
        if (voleith_gf8_mul((uint8_t)x, base) == a) { /* y·a^18 == a */
            y = (uint8_t)x;
            break;
        }

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa = voleith_gf8_add_witness(c);       /* a */
    gf8_wire_id wy = voleith_gf8_add_witness(c);       /* y = a⁻¹⁷ */
    gf8_wire_id wa2 = voleith_gf8_add_square(c, wa);   /* a² (free) */
    gf8_wire_id wa4 = voleith_gf8_add_square(c, wa2);  /* a⁴ */
    gf8_wire_id wa8 = voleith_gf8_add_square(c, wa4);  /* a⁸ */
    gf8_wire_id wa16 = voleith_gf8_add_square(c, wa8); /* a¹⁶ (free) */
    voleith_gf8_assert_product3(c, wy, wa2, wa16, wa);

    /* ell = 2 (just a and y); the conjugates are free squaring gates. */
    check("product3 norm: ell == 2 (zero slots for the check)",
          voleith_gf8_qs_ell(c) == 2);

    uint8_t w_ok[2] = {a, y};
    check("product3 norm: honest y accepts (128)",
          prove_verify(c, w_ok, 2, NULL, 0, 128, 0x6e000001u) == 1);
    check("product3 norm: honest y accepts (256)",
          prove_verify(c, w_ok, 2, NULL, 0, 256, 0x6e000002u) == 1);

    uint8_t w_bad[2] = {a, (uint8_t)(y ^ 0x01)};
    check("product3 norm: wrong y rejected (128)",
          prove_verify(c, w_bad, 2, NULL, 0, 128, 0x6e000003u) != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Test: sub-byte norm packing helpers (add_nibble + add_norm_embed)
 *
 * Phase 0 child 2.  Exercises the free packing path the norm S-box builders
 * use: two 4-bit subfield norms packed into one witness byte (FAEST's
 * (i % 2) * 4 layout), extracted with add_nibble, embedded to their GF(2^8)
 * bytes with add_norm_embed, then checked against the S-box inputs via the
 * degree-3 norm relation c * a^2 * a^16 = a (assert_product3).  Confirms the
 * pack/extract/embed maps are free (no VOLE slots, qs_degree stays 2), that
 * eval reproduces the norm bytes, and that an honest packed witness verifies
 * while a corrupted nibble is rejected, at lambda = 128/192/256.
 * ===================================================================== */

/* 4-bit code of a norm byte in the GF(2^4) basis {0x01,0x50,0xb0,0x0c}
 * (mirrors proof/gf8_circuit.c::gf8_norm_nibble_basis), or 0xff if the byte
 * is not in the subfield. */
static uint8_t
norm_nibble_of(uint8_t cbyte)
{
    static const uint8_t B[4] = {0x01, 0x50, 0xb0, 0x0c};
    for (unsigned int n = 0; n < 16; n++) {
        uint8_t v = 0;
        for (int k = 0; k < 4; k++)
            if (n & (1u << k))
                v ^= B[k];
        if (v == cbyte)
            return (uint8_t)n;
    }
    return 0xff;
}

/* Subfield norm c = a^-17, the y with y * a^18 == a. */
static uint8_t
norm_of(uint8_t a)
{
    uint8_t a2 = voleith_gf8_mul(a, a);
    uint8_t a16 = a;
    for (int i = 0; i < 4; i++)
        a16 = voleith_gf8_mul(a16, a16);
    uint8_t base = voleith_gf8_mul(a2, a16); /* a^18 */
    for (uint16_t x = 1; x < 256; x++)
        if (voleith_gf8_mul((uint8_t)x, base) == a)
            return (uint8_t)x;
    return 0;
}

static void
test_norm_packing(void)
{
    uint8_t a_lo = 0x53, a_hi = 0xca;
    uint8_t c_lo = norm_of(a_lo), c_hi = norm_of(a_hi);
    uint8_t n_lo = norm_nibble_of(c_lo), n_hi = norm_nibble_of(c_hi);

    check("norm packing: norms lie in GF(2^4) subfield",
          n_lo != 0xff && n_hi != 0xff);

    uint8_t packed = (uint8_t)(n_lo | (n_hi << 4));

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id wa_lo = voleith_gf8_add_witness(c);
    gf8_wire_id wa_hi = voleith_gf8_add_witness(c);
    gf8_wire_id wpack = voleith_gf8_add_witness(c);

    /* Extract + embed: all free. */
    gf8_wire_id nlo = voleith_gf8_add_nibble(c, wpack, 0);
    gf8_wire_id nhi = voleith_gf8_add_nibble(c, wpack, 1);
    gf8_wire_id clo = voleith_gf8_add_norm_embed(c, nlo);
    gf8_wire_id chi = voleith_gf8_add_norm_embed(c, nhi);

    /* Conjugates a^2, a^16: free Frobenius squares. */
    gf8_wire_id a2_lo = voleith_gf8_add_square(c, wa_lo);
    gf8_wire_id a4_lo = voleith_gf8_add_square(c, a2_lo);
    gf8_wire_id a8_lo = voleith_gf8_add_square(c, a4_lo);
    gf8_wire_id a16_lo = voleith_gf8_add_square(c, a8_lo);
    gf8_wire_id a2_hi = voleith_gf8_add_square(c, wa_hi);
    gf8_wire_id a4_hi = voleith_gf8_add_square(c, a2_hi);
    gf8_wire_id a8_hi = voleith_gf8_add_square(c, a4_hi);
    gf8_wire_id a16_hi = voleith_gf8_add_square(c, a8_hi);

    voleith_gf8_assert_product3(c, clo, a2_lo, a16_lo, wa_lo);
    voleith_gf8_assert_product3(c, chi, a2_hi, a16_hi, wa_hi);

    /* Pack/extract/embed add no VOLE slots: ell = 3 witness, 0 mul. */
    check("norm packing: ell == 3 (zero slots for pack/extract/embed)",
          voleith_gf8_qs_ell(c) == 3);
    check("norm packing: zero mul gates",
          voleith_gf8_circuit_mul_count(c) == 0);
    check("norm packing: qs_degree == 2",
          voleith_gf8_circuit_qs_degree(c) == 2);

    /* Direct eval: extracted + embedded wires reproduce the norm bytes. */
    size_t nwires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wv = calloc(nwires, 1);
    uint8_t wit[3] = {a_lo, a_hi, packed};
    check("norm packing: eval ok",
          wv != NULL && voleith_gf8_circuit_eval(c, wit, NULL, wv) == 1);
    if (wv) {
        check("norm packing: low nibble embeds to c_lo", wv[clo] == c_lo);
        check("norm packing: high nibble embeds to c_hi", wv[chi] == c_hi);
    }
    free(wv);

    uint8_t w_ok[3] = {a_lo, a_hi, packed};
    check("norm packing: honest accepts (128)",
          prove_verify(c, w_ok, 3, NULL, 0, 128, 0x7a000001u) == 1);
    check("norm packing: honest accepts (192)",
          prove_verify(c, w_ok, 3, NULL, 0, 192, 0x7a000002u) == 1);
    check("norm packing: honest accepts (256)",
          prove_verify(c, w_ok, 3, NULL, 0, 256, 0x7a000003u) == 1);

    /* Corrupt the packed low nibble: the norm relation for a_lo breaks. */
    uint8_t w_bad[3] = {a_lo, a_hi, (uint8_t)(packed ^ 0x01)};
    check("norm packing: corrupted nibble rejected (128)",
          prove_verify(c, w_bad, 3, NULL, 0, 128, 0x7a000004u) != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Norm round-pair gadget: one paired-round circuit, honest round-trip +
 * tamper rejection.  Exercises voleith_gf8_assert_aes_norm_roundpair end to
 * end (prover + verifier accumulate) without the full AES.
 * ===================================================================== */

/* a^-1 = a^254 in GF(2^8) (0 maps to 0). */
static uint8_t
rp_inv(uint8_t a)
{
    uint8_t r = 1;
    if (a == 0)
        return 0;
    for (int i = 0; i < 254; i++)
        r = voleith_gf8_mul(r, a);
    return r;
}

/* AES affine linear part M*z (no 0x63). */
static uint8_t
rp_aff_lin(uint8_t z)
{
    static const uint8_t M[8] = {0xF1, 0xE3, 0xC7, 0x8F,
                                 0x1F, 0x3E, 0x7C, 0xF8};
    uint8_t o = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t m = (uint8_t)(M[i] & z);
        int p = 0;
        for (int j = 0; j < 8; j++)
            p ^= (m >> j) & 1;
        o |= (uint8_t)((p & 1) << i);
    }
    return o;
}

static uint8_t
rp_sbox(uint8_t a)
{
    return (uint8_t)(rp_aff_lin(rp_inv(a)) ^ 0x63);
}

static const unsigned int RP_SR[16] = {0, 5,  10, 15, 4,  9, 14, 3,
                                       8, 13, 2,  7,  12, 1, 6,  11};

static void
rp_shiftrows(uint8_t out[16], const uint8_t in[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = in[RP_SR[k]];
}

static void
rp_mixcolumns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2],
                a3 = s[4 * c + 3];
        s[4 * c] = (uint8_t)(voleith_gf8_mul(2, a0) ^ voleith_gf8_mul(3, a1) ^
                             a2 ^ a3);
        s[4 * c + 1] = (uint8_t)(a0 ^ voleith_gf8_mul(2, a1) ^
                                 voleith_gf8_mul(3, a2) ^ a3);
        s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ voleith_gf8_mul(2, a2) ^
                                 voleith_gf8_mul(3, a3));
        s[4 * c + 3] = (uint8_t)(voleith_gf8_mul(3, a0) ^ a1 ^ a2 ^
                                 voleith_gf8_mul(2, a3));
    }
}

static void
test_norm_roundpair(void)
{
    /* Fixed nonzero state and round key. */
    uint8_t a[16], k0[16];
    for (int i = 0; i < 16; i++) {
        a[i] = (uint8_t)(0x31 + 7 * i);
        k0[i] = (uint8_t)(0xa5 ^ (3 * i));
    }

    /* Reference trace: norms, even-round output st0, recovered s, s_tilde. */
    uint8_t packed[8], st0[16], sbox_out[16], sr[16], s[16], t[16], s_tilde[16];
    uint8_t nib[16];
    int norms_ok = 1;
    for (int i = 0; i < 16; i++) {
        uint8_t cb = norm_of(a[i]);
        nib[i] = norm_nibble_of(cb);
        if (nib[i] == 0xff)
            norms_ok = 0;
    }
    check("norm roundpair: all norms in GF(2^4) subfield", norms_ok);
    for (int j = 0; j < 8; j++)
        packed[j] = (uint8_t)(nib[2 * j] | (nib[2 * j + 1] << 4));

    for (int i = 0; i < 16; i++)
        sbox_out[i] = rp_sbox(a[i]);
    rp_shiftrows(sr, sbox_out);
    rp_mixcolumns(sr);
    for (int i = 0; i < 16; i++)
        st0[i] = (uint8_t)(sr[i] ^ k0[i]); /* even-round output */
    for (int i = 0; i < 16; i++)
        s[i] = rp_inv(st0[i]); /* odd-round S-box input inverse */
    for (int i = 0; i < 16; i++)
        t[i] = (uint8_t)(rp_aff_lin(s[i]) ^ 0x63); /* odd S-box output */
    rp_shiftrows(s_tilde, t);                      /* committed reset state */

    /* Build the circuit: witness order a[16], packed[8], s_tilde[16], k0[16]. */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a_w[16], pk_w[8], st_w[16], k_w[16], c_w[16];
    for (int i = 0; i < 16; i++)
        a_w[i] = voleith_gf8_add_witness(c);
    for (int j = 0; j < 8; j++)
        pk_w[j] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        st_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        k_w[i] = voleith_gf8_add_witness(c);

    for (int i = 0; i < 16; i++) {
        gf8_wire_id nw =
            voleith_gf8_add_nibble(c, pk_w[i / 2], (unsigned)i % 2);
        c_w[i] = voleith_gf8_add_norm_embed(c, nw);
        gf8_wire_id a2 = voleith_gf8_add_square(c, a_w[i]);
        gf8_wire_id a4 = voleith_gf8_add_square(c, a2);
        gf8_wire_id a8 = voleith_gf8_add_square(c, a4);
        gf8_wire_id a16 = voleith_gf8_add_square(c, a8);
        voleith_gf8_assert_product3(c, c_w[i], a2, a16, a_w[i]);
    }
    voleith_gf8_assert_aes_norm_roundpair(c, a_w, c_w, st_w, k_w, 16, 0);

    check("norm roundpair: builder ok", voleith_gf8_circuit_ok(c));
    check("norm roundpair: qs_degree == 2",
          voleith_gf8_circuit_qs_degree(c) == 2);
    check("norm roundpair: zero mul gates (all free)",
          voleith_gf8_circuit_mul_count(c) == 0);

    /* Assemble the witness. */
    uint8_t wit[56];
    memcpy(wit + 0, a, 16);
    memcpy(wit + 16, packed, 8);
    memcpy(wit + 24, s_tilde, 16);
    memcpy(wit + 40, k0, 16);

    size_t nwires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wv = calloc(nwires, 1);
    check("norm roundpair: eval satisfied",
          wv != NULL && voleith_gf8_circuit_eval(c, wit, NULL, wv) == 1);
    free(wv);

    check("norm roundpair: honest accepts (128)",
          prove_verify(c, wit, 56, NULL, 0, 128, 0x9b000001u) == 1);
    check("norm roundpair: honest accepts (192)",
          prove_verify(c, wit, 56, NULL, 0, 192, 0x9b000002u) == 1);
    check("norm roundpair: honest accepts (256)",
          prove_verify(c, wit, 56, NULL, 0, 256, 0x9b000003u) == 1);

    /* Tamper the committed reset state: the paired relation breaks. */
    uint8_t bad_st[56];
    memcpy(bad_st, wit, 56);
    bad_st[24] ^= 0x01;
    check("norm roundpair: tampered s_tilde rejected",
          prove_verify(c, bad_st, 56, NULL, 0, 128, 0x9b000004u) != 1);

    /* Tamper a norm nibble: breaks PRODUCT3 and the paired relation. */
    uint8_t bad_n[56];
    memcpy(bad_n, wit, 56);
    bad_n[16] ^= 0x01;
    check("norm roundpair: tampered norm rejected",
          prove_verify(c, bad_n, 56, NULL, 0, 128, 0x9b000005u) != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Grostl norm round-pair gadget: one paired-round circuit (Grostl-256 P
 * geometry, nst=64, cols=8), honest round-trip + tamper rejection.  Exercises
 * voleith_gf8_assert_grostl_norm_roundpair end to end (prover + verifier
 * accumulate) without the full Grostl permutation.
 * ===================================================================== */
static void
test_grostl_norm_roundpair(void)
{
    enum { NST = 64, COLS = 8 };
    static const uint8_t shift[8] = {0, 1, 2, 3, 4, 5, 6, 7}; /* Grostl-256 P */
    const unsigned int odd_round = 1;

    uint8_t fwd[NST], inv[NST], rc[NST];
    grostl_norm_build_shift(COLS, shift, fwd, inv);
    grostl_norm_round_const(0, COLS, odd_round, rc);

    /* Even-round S-box input (= state with the public even AddRoundConstant
     * already folded in; arbitrary nonzero here). */
    uint8_t a[NST];
    for (int i = 0; i < NST; i++)
        a[i] = (uint8_t)(0x31 + 7 * i);

    /* Reference trace. */
    uint8_t nib[NST], packed[NST / 2];
    int norms_ok = 1;
    for (int i = 0; i < NST; i++) {
        nib[i] = norm_nibble_of(norm_of(a[i]));
        if (nib[i] == 0xff)
            norms_ok = 0;
    }
    check("grostl norm roundpair: all norms in GF(2^4)", norms_ok);
    for (int j = 0; j < NST / 2; j++)
        packed[j] = (uint8_t)(nib[2 * j] | (nib[2 * j + 1] << 4));

    uint8_t so[NST], sh[NST], u[NST], st0[NST], t[NST], s_tilde[NST];
    for (int i = 0; i < NST; i++)
        so[i] = rp_sbox(a[i]); /* even SubBytes */
    for (int i = 0; i < NST; i++)
        sh[i] = so[fwd[i]]; /* ShiftBytes */
    for (int col = 0; col < COLS; col++)
        for (int r = 0; r < 8; r++) {
            uint8_t acc = 0;
            for (int j = 0; j < 8; j++)
                acc ^= voleith_gf8_mul(GROSTL_NORM_MIX[r][j], sh[j + 8 * col]);
            u[r + 8 * col] = acc; /* MixBytes */
        }
    for (int i = 0; i < NST; i++)
        st0[i] =
            (uint8_t)(u[i] ^ rc[i]); /* odd AddRoundConstant => odd input */
    for (int i = 0; i < NST; i++)
        t[i] = rp_sbox(st0[i]); /* odd SubBytes output */
    for (int i = 0; i < NST; i++)
        s_tilde[i] = t[fwd[i]]; /* ShiftBytes => committed reset state */

    /* Build the circuit: witness order a[64], packed[32], s_tilde[64]. */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id a_w[NST], pk_w[NST / 2], st_w[NST], c_w[NST];
    for (int i = 0; i < NST; i++)
        a_w[i] = voleith_gf8_add_witness(c);
    for (int j = 0; j < NST / 2; j++)
        pk_w[j] = voleith_gf8_add_witness(c);
    for (int i = 0; i < NST; i++)
        st_w[i] = voleith_gf8_add_witness(c);

    for (int i = 0; i < NST; i++) {
        gf8_wire_id nw =
            voleith_gf8_add_nibble(c, pk_w[i / 2], (unsigned)i % 2);
        c_w[i] = voleith_gf8_add_norm_embed(c, nw);
        gf8_wire_id a2 = voleith_gf8_add_square(c, a_w[i]);
        gf8_wire_id a4 = voleith_gf8_add_square(c, a2);
        gf8_wire_id a8 = voleith_gf8_add_square(c, a4);
        gf8_wire_id a16 = voleith_gf8_add_square(c, a8);
        voleith_gf8_assert_product3(c, c_w[i], a2, a16, a_w[i]);
    }
    voleith_gf8_assert_grostl_norm_roundpair(c, a_w, c_w, st_w, NST, COLS,
                                             shift, 0, odd_round);

    check("grostl norm roundpair: builder ok", voleith_gf8_circuit_ok(c));
    check("grostl norm roundpair: qs_degree == 2",
          voleith_gf8_circuit_qs_degree(c) == 2);
    check("grostl norm roundpair: zero mul gates (all free)",
          voleith_gf8_circuit_mul_count(c) == 0);

    uint8_t wit[NST + NST / 2 + NST]; /* 160 */
    memcpy(wit + 0, a, NST);
    memcpy(wit + NST, packed, NST / 2);
    memcpy(wit + NST + NST / 2, s_tilde, NST);
    const size_t wlen = sizeof(wit);

    size_t nwires = voleith_gf8_circuit_wire_count(c);
    uint8_t *wv = calloc(nwires, 1);
    check("grostl norm roundpair: eval satisfied",
          wv != NULL && voleith_gf8_circuit_eval(c, wit, NULL, wv) == 1);
    free(wv);

    check("grostl norm roundpair: honest accepts (128)",
          prove_verify(c, wit, wlen, NULL, 0, 128, 0x6c000001u) == 1);
    check("grostl norm roundpair: honest accepts (192)",
          prove_verify(c, wit, wlen, NULL, 0, 192, 0x6c000002u) == 1);
    check("grostl norm roundpair: honest accepts (256)",
          prove_verify(c, wit, wlen, NULL, 0, 256, 0x6c000003u) == 1);

    uint8_t bad_st[NST + NST / 2 + NST];
    memcpy(bad_st, wit, wlen);
    bad_st[NST + NST / 2] ^= 0x01; /* first s_tilde byte */
    check("grostl norm roundpair: tampered s_tilde rejected",
          prove_verify(c, bad_st, wlen, NULL, 0, 128, 0x6c000004u) != 1);

    uint8_t bad_n[NST + NST / 2 + NST];
    memcpy(bad_n, wit, wlen);
    bad_n[NST] ^= 0x01; /* first packed norm nibble */
    check("grostl norm roundpair: tampered norm rejected",
          prove_verify(c, bad_n, wlen, NULL, 0, 128, 0x6c000005u) != 1);

    voleith_gf8_circuit_free(c);
}

/* =====================================================================
 * Full AES-128 norm circuit: honest round-trip + tamper rejection.
 * ===================================================================== */

static void
test_norm_aes128_roundtrip(void)
{
    static const uint8_t KEY[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t PT[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                   0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                   0xcc, 0xdd, 0xee, 0xff};

    uint8_t witness[AES128_NORM_GF8_WITNESS_BYTES];
    aes128_norm_gf8_build_witness(KEY, PT, witness, NULL);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id key[16], pt[16], out[16];
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt[i] = voleith_gf8_add_instance(c);
    aes128_norm_gf8_circuit(c, key, pt, out);

    check("norm aes128: honest accepts (128)",
          prove_verify(c, witness, AES128_NORM_GF8_WITNESS_BYTES, PT, 16, 128,
                       0xae000001u) == 1);
    check("norm aes128: honest accepts (192)",
          prove_verify(c, witness, AES128_NORM_GF8_WITNESS_BYTES, PT, 16, 192,
                       0xae000002u) == 1);
    check("norm aes128: honest accepts (256)",
          prove_verify(c, witness, AES128_NORM_GF8_WITNESS_BYTES, PT, 16, 256,
                       0xae000003u) == 1);

    /* Tamper a committed s_tilde byte in the first pair (witness offset 16+40+8
     * = first pair's s_tilde[0]). */
    uint8_t bad[AES128_NORM_GF8_WITNESS_BYTES];
    memcpy(bad, witness, sizeof(bad));
    bad[16 + 40 + 8] ^= 0x01;
    check("norm aes128: tampered state rejected",
          prove_verify(c, bad, AES128_NORM_GF8_WITNESS_BYTES, PT, 16, 128,
                       0xae000004u) != 1);

    /* Wrong instance (flip a plaintext byte the prover did not commit to). */
    uint8_t bad_pt[16];
    memcpy(bad_pt, PT, 16);
    bad_pt[0] ^= 0x01;
    check("norm aes128: wrong instance rejected",
          prove_verify(c, witness, AES128_NORM_GF8_WITNESS_BYTES, bad_pt, 16,
                       128, 0xae000005u) != 1);

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
    test_assert_product_soundness();
    test_assert_product_forgery();
    test_assert_zero();
    test_assert_equal();
    test_xor_const_linear_map();
    test_multiple_mul_gates();
    test_aes128_integration();
    test_lt_basic();
    test_lt_mixed_degree();
    test_lt_degree_accessor();
    test_lt_wide();
    test_product3_basic();
    test_product3_forgery();
    test_product3_norm();
    test_norm_packing();
    test_norm_roundpair();
    test_grostl_norm_roundpair();
    test_norm_aes128_roundtrip();

    printf("%d/%d tests passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
