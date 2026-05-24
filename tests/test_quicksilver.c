/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_quicksilver.c - Tests for the QuickSilver prover + verifier
 *
 * Tests:
 *   1:  ell / ellhat calculations
 *   2:  Prove + verify roundtrip - correct witnesses (lambda = 128, 192, 256)
 *   3:  Invalid witness - a0_tilde must not match
 *   4:  Tampered proof - a1_tilde flip causes mismatch
 *   5:  No-AND circuit - assert_zero only; valid and invalid witnesses
 *   6:  Invalid parameters rejected
 *   7:  NOT gate as AND input
 *   8:  CONST wires as AND inputs (CONST 0 and CONST 1)
 *   9:  Multiple AND gates - accumulation correctness
 *   10: Tampered d vector → verifier key mismatch
 *   11: All gate types in one circuit
 *   12: AES-128 integration - prove knowledge of key (NIST FIPS 197 vector)
 *
 * VOLE setup: for testing we synthesize the VOLE correlation directly.
 *   Choose random u (ellhat_bytes), random V rows (lambda x ellhat_bytes).
 *   The VOLE relation is Q[j] = V[j] XOR (delta_j ? u : 0)
 *   where delta_j = bit j of delta.  This is the standard VOLE equation
 *   col_i(Q) = col_i(V) XOR u_i * delta.
 */

#include "prover.h"
#include "verifier.h"
#include "aes_circuit.h"
#include "circuit.h"

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
 * Minimal deterministic PRNG (xorshift32) for test scaffolding.
 * NOT cryptographically random.
 * ===================================================================== */

static uint32_t g_prng = 0x12345678u;

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
 * Bit helpers
 * ===================================================================== */

static inline unsigned int
get_bit(const uint8_t *buf, size_t pos)
{
    return (buf[pos / 8] >> (pos % 8)) & 1u;
}

static void
set_bit(uint8_t *buf, size_t pos, uint8_t val)
{
    if (val & 1)
        buf[pos / 8] |= (uint8_t)(1u << (pos % 8));
    else
        buf[pos / 8] &= (uint8_t)~(1u << (pos % 8));
}

/* =====================================================================
 * VOLE scaffolding
 * ===================================================================== */

/*
 * Compute Q from V, u, delta via the VOLE relation:
 *   Q[j] = V[j] XOR (delta_j ? u : 0)    for each row j in 0..lambda-1
 * where delta_j = bit j of delta.
 */
static void
build_Q(uint8_t **Q_rows, const uint8_t **V_rows, const uint8_t *u,
        const uint8_t *delta, unsigned int lambda, size_t ellhat_bytes)
{
    for (unsigned int j = 0; j < lambda; j++) {
        uint8_t delta_j = (uint8_t)get_bit(delta, j);
        for (size_t k = 0; k < ellhat_bytes; k++)
            Q_rows[j][k] = V_rows[j][k] ^ (delta_j ? u[k] : 0u);
    }
}

/*
 * VOLE state: heap-allocated u, V, Q, delta, chall_2.
 * Fills with pseudo-random data and computes Q from the VOLE relation.
 */
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
    size_t nb;
} vole_state_t;

static int
vole_alloc(vole_state_t *vs, unsigned int lambda, size_t ellhat_bytes,
           uint32_t seed)
{
    unsigned int nb = lambda / 8;
    vs->lambda = lambda;
    vs->ellhat_bytes = ellhat_bytes;
    vs->nb = nb;

    vs->u = calloc(ellhat_bytes, 1);
    vs->V_rows = calloc(lambda, sizeof(uint8_t *));
    vs->Q_rows = calloc(lambda, sizeof(uint8_t *));
    vs->V_data = calloc(lambda * ellhat_bytes, 1);
    vs->Q_data = calloc(lambda * ellhat_bytes, 1);
    vs->delta = calloc(nb, 1);
    vs->chall_2 = calloc(3u * nb + 8u, 1);

    if (!vs->u || !vs->V_rows || !vs->Q_rows || !vs->V_data || !vs->Q_data ||
        !vs->delta || !vs->chall_2)
        return -1;

    for (unsigned int j = 0; j < lambda; j++) {
        vs->V_rows[j] = vs->V_data + j * ellhat_bytes;
        vs->Q_rows[j] = vs->Q_data + j * ellhat_bytes;
    }

    prng_reset(seed);
    prng_fill(vs->u, ellhat_bytes);
    prng_fill(vs->V_data, lambda * ellhat_bytes);
    prng_fill(vs->delta, nb);
    prng_fill(vs->chall_2, 3u * nb + 8u);
    build_Q(vs->Q_rows, (const uint8_t **)vs->V_rows, vs->u, vs->delta, lambda,
            ellhat_bytes);
    return 0;
}

static void
vole_free(vole_state_t *vs)
{
    free(vs->u);
    free(vs->V_rows);
    free(vs->Q_rows);
    free(vs->V_data);
    free(vs->Q_data);
    free(vs->delta);
    free(vs->chall_2);
}

/* =====================================================================
 * Test 1: ell / ellhat calculations
 * ===================================================================== */

static void
test_ell_ellhat(void)
{
    /* 3 witness wires + 1 AND gate → ell = 4 */
    voleith_circuit_t *c = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(c);
    wire_id wb = voleith_circuit_add_witness(c);
    (void)voleith_circuit_add_witness(c);
    (void)voleith_circuit_add_and(c, wa, wb);

    check("ell = witness_count + and_gate_count", voleith_qs_ell(c) == 4);
    check("ellhat (lambda=128) = ell + 3*128 + 16",
          voleith_qs_ellhat(c, 128) == 4u + 3u * 128u + 16u);
    check("ellhat (lambda=192) = ell + 3*192 + 16",
          voleith_qs_ellhat(c, 192) == 4u + 3u * 192u + 16u);
    check("ellhat (lambda=256) = ell + 3*256 + 16",
          voleith_qs_ellhat(c, 256) == 4u + 3u * 256u + 16u);

    voleith_circuit_free(c);
}

/* =====================================================================
 * Test 2: Prove + verify roundtrip - valid witnesses
 *
 * Circuit: (a AND b) XOR c == 0
 *   witness: a, b (private bits)
 *   instance: c (public bit, set to a AND b)
 *   AND gate: out = a AND b
 *   XOR gate: diff = out XOR c
 *   assert_zero(diff)
 * ===================================================================== */

static void
run_roundtrip(const char *label, unsigned int lambda, uint8_t a_bit,
              uint8_t b_bit)
{
    unsigned int nb = lambda / 8;

    /* Build circuit */
    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_instance(circuit);
    wire_id wand = voleith_circuit_add_and(circuit, wa, wb);
    wire_id diff = voleith_circuit_add_xor(circuit, wand, wc);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    /* Allocate VOLE state */
    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xDEAD0000u | lambda) != 0) {
        printf("  OOM in %s\n", label);
        voleith_circuit_free(circuit);
        return;
    }

    /* c = a AND b (correct witness) */
    uint8_t witness[1] = {0};
    uint8_t instance[1] = {0};
    set_bit(witness, 0, a_bit);
    set_bit(witness, 1, b_bit);
    set_bit(instance, 0, (uint8_t)(a_bit & b_bit));

    /* Allocate prover outputs */
    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in %s\n", label);
        goto cleanup;
    }

    /* Prove */
    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: prove returns 0", label);
        check(buf, r == 0);
    }
    if (r != 0)
        goto cleanup;

    /* Verify */
    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: verify returns 0", label);
        check(buf, r == 0);
    }
    if (r != 0)
        goto cleanup;

    /* a0_tilde must match */
    {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: a0_tilde matches (correct witness)",
                 label);
        check(buf, memcmp(a0_tilde, a0_out, nb) == 0);
    }

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

static void
test_roundtrip_valid(void)
{
    run_roundtrip("lambda=128 (1&1)", 128, 1, 1);
    run_roundtrip("lambda=128 (0&1)", 128, 0, 1);
    run_roundtrip("lambda=128 (0&0)", 128, 0, 0);
    run_roundtrip("lambda=128 (1&0)", 128, 1, 0);
    run_roundtrip("lambda=192 (1&1)", 192, 1, 1);
    run_roundtrip("lambda=256 (1&1)", 256, 1, 1);
}

/* =====================================================================
 * Test 3: Invalid witness - a0_tilde must NOT match
 *
 * Same circuit, but instance c != a AND b, so assert_zero(diff) fails.
 * The prover runs without error but produces a0_tilde that the verifier
 * cannot reconstruct.  With random delta this fails with probability
 * 1 - 2^{-lambda}, so the mismatch is effectively certain.
 * ===================================================================== */

static void
test_invalid_witness(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_instance(circuit);
    wire_id wand = voleith_circuit_add_and(circuit, wa, wb);
    wire_id diff = voleith_circuit_add_xor(circuit, wand, wc);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xBAD00001u) != 0) {
        printf("  OOM in test_invalid_witness\n");
        voleith_circuit_free(circuit);
        return;
    }

    /* Wrong: a=1, b=1, but c=0 (correct c would be 1) */
    uint8_t witness[1] = {0x03};  /* bits 0,1 set → a=1, b=1 */
    uint8_t instance[1] = {0x00}; /* c=0 (wrong) */

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_invalid_witness\n");
        goto cleanup;
    }

    /* X-10: voleith_qs_prove now rejects an invalid witness upfront
     * (matching the GF(2⁸) discipline) rather than publishing
     * coefficients that the verifier would later catch.  The
     * previous test shape - prove succeeds, then verify catches the
     * mismatch via a0_tilde - is no longer reachable because prove
     * returns non-zero first. */
    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("invalid witness (1&1 with c=0): prove rejects upfront", r != 0);

    /* Also test: a=0, b=1, c=1 (wrong: 0&1=0 ≠ 1) */
    memset(witness, 0, 1);
    memset(instance, 0, 1);
    set_bit(witness, 0, 0);
    set_bit(witness, 1, 1);
    set_bit(instance, 0, 1); /* wrong public value */

    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
    check("invalid witness (0&1 with c=1): prove rejects upfront", r != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 4: Tampered proof → a0_tilde mismatch
 *
 * Valid proof produced, then a1_tilde is bit-flipped.
 * The verifier's reconstructed a0_tilde must differ from the original.
 * ===================================================================== */

static void
test_tampered_proof(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_instance(circuit);
    wire_id wand = voleith_circuit_add_and(circuit, wa, wb);
    wire_id diff = voleith_circuit_add_xor(circuit, wand, wc);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xCAFEBABEu) != 0) {
        printf("  OOM in test_tampered_proof\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t witness[1] = {0x03};  /* a=1, b=1 */
    uint8_t instance[1] = {0x01}; /* c=1 (correct) */

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_tampered_proof\n");
        goto cleanup;
    }

    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    if (r != 0) {
        check("tampered: prove returned 0", 0);
        goto cleanup;
    }

    /* Tamper a1_tilde */
    a1_tilde[0] ^= 0xFFu;

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("tampered a1_tilde: verify returns 0", r == 0);
    check("tampered a1_tilde: a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

    /* Restore a1_tilde, tamper a2_tilde instead */
    a1_tilde[0] ^= 0xFFu; /* restore */
    a2_tilde[nb - 1] ^= 0x01u;

    memset(a0_out, 0, nb);
    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("tampered a2_tilde: a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 5: No-AND circuit (only witness wires + assert_zero)
 *
 * Circuit: a XOR b == 0  (i.e., a == b)
 *   ell = 2, no AND gate contribution to proof.
 * ===================================================================== */

static void
test_no_and_circuit(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id xab = voleith_circuit_add_xor(circuit, wa, wb);
    voleith_circuit_assert_zero(circuit, xab);
    (void)wa;
    (void)wb;

    check("no-AND: ell = 2", voleith_qs_ell(circuit) == 2);

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xABCD1234u) != 0) {
        printf("  OOM in test_no_and_circuit\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t empty_instance[1] = {0}; /* no instance wires in circuit */
    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_no_and_circuit\n");
        goto cleanup;
    }

    /* Valid witness: a=1, b=1 → a XOR b = 0 */
    uint8_t witness[1] = {0x03}; /* bits 0,1 both set */

    int r = voleith_qs_prove(circuit, witness, empty_instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("no-AND valid: prove returns 0", r == 0);

    r = voleith_qs_verify(circuit, empty_instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("no-AND valid: verify returns 0", r == 0);
    check("no-AND valid: a0_tilde matches (a=b=1)",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* Invalid witness: a=0, b=1 → a XOR b = 1 (fails assert_zero).
     * X-10: prove rejects upfront; the downstream verify path is
     * no longer reachable. */
    memset(witness, 0, 1);
    set_bit(witness, 1, 1); /* only b=1 */

    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    r = voleith_qs_prove(circuit, witness, empty_instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
    check("no-AND invalid: prove rejects upfront", r != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 6: Invalid parameters rejected
 * ===================================================================== */

static void
test_invalid_params(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    (void)voleith_circuit_add_and(circuit, wa, wb);

    size_t ellhat_bytes = (voleith_qs_ellhat(circuit, lambda) + 7) / 8;
    size_t ell_bytes = (voleith_qs_ell(circuit) + 7) / 8;

    uint8_t *u = calloc(ellhat_bytes, 1);
    uint8_t **V_rows = calloc(lambda, sizeof(uint8_t *));
    uint8_t *V_data = calloc(lambda * ellhat_bytes, 1);
    uint8_t *delta = calloc(nb, 1);
    uint8_t *chall_2 = calloc(3u * nb + 8u, 1);
    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0 = calloc(nb, 1);
    uint8_t *a1 = calloc(nb, 1);
    uint8_t *a2 = calloc(nb, 1);

    if (!u || !V_rows || !V_data || !delta || !chall_2 || !d_out || !a0 ||
        !a1 || !a2)
        goto cleanup;

    for (unsigned int j = 0; j < lambda; j++)
        V_rows[j] = V_data + j * ellhat_bytes;

    uint8_t witness[1] = {0};
    uint8_t instance[1] = {0};

    /* NULL circuit */
    int r =
        voleith_qs_prove(NULL, witness, instance, lambda, u,
                         (const uint8_t **)V_rows, chall_2, d_out, a0, a1, a2);
    check("prove: NULL circuit → -1", r == -1);

    /* Invalid lambda */
    r = voleith_qs_prove(circuit, witness, instance, 64u, u,
                         (const uint8_t **)V_rows, chall_2, d_out, a0, a1, a2);
    check("prove: lambda=64 → -1", r == -1);

    /* NULL witness */
    r = voleith_qs_prove(circuit, NULL, instance, lambda, u,
                         (const uint8_t **)V_rows, chall_2, d_out, a0, a1, a2);
    check("prove: NULL witness → -1", r == -1);

    /* Verifier NULL delta */
    r = voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)V_rows,
                          d_out, NULL, chall_2, a1, a2, a0);
    check("verify: NULL delta → -1", r == -1);

    /* Verifier invalid lambda */
    r = voleith_qs_verify(circuit, instance, 100u, (const uint8_t **)V_rows,
                          d_out, delta, chall_2, a1, a2, a0);
    check("verify: lambda=100 → -1", r == -1);

cleanup:
    free(u);
    free(V_rows);
    free(V_data);
    free(delta);
    free(chall_2);
    free(d_out);
    free(a0);
    free(a1);
    free(a2);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 7: NOT gate as AND input
 *
 * Circuit: NOT(a) AND b == c
 *   Key propagation rule under test: key[NOT(x)] = key[x] + delta
 *   (verifier side) vs tag[NOT(x)] = tag[x] (prover side).
 *
 * A bug in either would cause key[NOT(a)] to disagree, making the AND
 * gate contribution key[NOT(a)]*key[b] + key[and_out] wrong, which
 * the soundness check would catch via a0_tilde mismatch.
 * ===================================================================== */

static void
test_not_gate_in_and(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_instance(circuit);
    wire_id not_a = voleith_circuit_add_not(circuit, wa);
    wire_id wand = voleith_circuit_add_and(circuit, not_a, wb);
    wire_id diff = voleith_circuit_add_xor(circuit, wand, wc);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;

    check("NOT-AND circuit: 1 AND gate",
          voleith_circuit_and_gate_count(circuit) == 1);

    size_t ell = voleith_qs_ell(circuit); /* 2 witness + 1 AND = 3 */
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xF00D0001u) != 0) {
        printf("  OOM in test_not_gate_in_and\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_not_gate_in_and\n");
        goto cleanup;
    }

    /* a=0, b=1: NOT(0)=1, 1 AND 1 = 1 → c=1 */
    uint8_t witness[1] = {0x02};  /* bit0=0(a), bit1=1(b) */
    uint8_t instance[1] = {0x01}; /* c=1 */

    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("NOT-AND valid (a=0,b=1,c=1): prove returns 0", r == 0);

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("NOT-AND valid (a=0,b=1,c=1): verify returns 0", r == 0);
    check("NOT-AND valid (a=0,b=1,c=1): a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* a=1, b=1: NOT(1)=0, 0 AND 1 = 0 → c=0 */
    memset(witness, 0, 1);
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 1);
    memset(instance, 0, 1); /* c=0 */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    (void)r;
    check("NOT-AND valid (a=1,b=1,c=0): a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* Soundness: a=0,b=1 but wrong c=0 (NOT(a)&b=1, not 0) */
    memset(witness, 0, 1);
    set_bit(witness, 0, 0);
    set_bit(witness, 1, 1);
    memset(instance, 0, 1); /* wrong: c=0 */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("NOT-AND invalid (a=0,b=1,c=0 wrong): a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 8: CONST wires as AND inputs
 *
 * CONST(0) key = 0; CONST(1) key = delta (verifier) / 0 (prover tag).
 * A bug in const-1 handling would corrupt every AND gate that touches
 * a constant-1 input.
 *
 * Circuit A: a AND CONST(1) == a   (always true for any a)
 * Circuit B: a AND CONST(0) == 0   (always true for any a)
 * ===================================================================== */

static void
test_const_wires(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    /* --- Circuit A: a AND 1 == a --- */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id wa = voleith_circuit_add_witness(c);
        wire_id wc = voleith_circuit_add_instance(c);
        wire_id k1 = voleith_circuit_add_const(c, 1);
        wire_id wand = voleith_circuit_add_and(c, wa, k1);
        wire_id diff = voleith_circuit_add_xor(c, wand, wc);
        voleith_circuit_assert_zero(c, diff);
        (void)wa;
        (void)wc;
        (void)k1;

        size_t ell = voleith_qs_ell(c);
        size_t ellhat = voleith_qs_ellhat(c, lambda);
        size_t ell_bytes = (ell + 7) / 8;
        size_t ellhat_bytes = (ellhat + 7) / 8;

        vole_state_t vs;
        if (vole_alloc(&vs, lambda, ellhat_bytes, 0xC0051001u) != 0) {
            printf("  OOM in test_const_wires (circuit A)\n");
            voleith_circuit_free(c);
            goto circuit_b;
        }

        uint8_t *d_out = calloc(ell_bytes, 1);
        uint8_t *a0_tilde = calloc(nb, 1);
        uint8_t *a1_tilde = calloc(nb, 1);
        uint8_t *a2_tilde = calloc(nb, 1);
        uint8_t *a0_out = calloc(nb, 1);

        if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out)
            goto circuit_a_cleanup;

        /* a=1: 1 AND 1 = 1, c=1 */
        uint8_t witness[1] = {0x01};
        uint8_t instance[1] = {0x01};

        voleith_qs_prove(c, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
        voleith_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
                          d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde,
                          a0_out);
        check("CONST(1): a=1, AND(a,1)==1, c=1: a0_tilde matches",
              memcmp(a0_tilde, a0_out, nb) == 0);

        /* a=0: 0 AND 1 = 0, c=0 */
        memset(witness, 0, 1);
        memset(instance, 0, 1);
        memset(d_out, 0, ell_bytes);
        memset(a0_tilde, 0, nb);
        memset(a1_tilde, 0, nb);
        memset(a2_tilde, 0, nb);
        memset(a0_out, 0, nb);

        voleith_qs_prove(c, witness, instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
        voleith_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
                          d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde,
                          a0_out);
        check("CONST(1): a=0, AND(a,1)==0, c=0: a0_tilde matches",
              memcmp(a0_tilde, a0_out, nb) == 0);

    circuit_a_cleanup:
        free(d_out);
        free(a0_tilde);
        free(a1_tilde);
        free(a2_tilde);
        free(a0_out);
        vole_free(&vs);
        voleith_circuit_free(c);
    }

circuit_b:
    /* --- Circuit B: a AND 0 == 0 --- */
    {
        voleith_circuit_t *c = voleith_circuit_new();
        wire_id wa = voleith_circuit_add_witness(c);
        wire_id k0 = voleith_circuit_add_const(c, 0);
        wire_id wand = voleith_circuit_add_and(c, wa, k0);
        voleith_circuit_assert_zero(c, wand);
        (void)wa;
        (void)k0;

        size_t ell = voleith_qs_ell(c);
        size_t ellhat = voleith_qs_ellhat(c, lambda);
        size_t ell_bytes = (ell + 7) / 8;
        size_t ellhat_bytes = (ellhat + 7) / 8;

        vole_state_t vs;
        if (vole_alloc(&vs, lambda, ellhat_bytes, 0xC0050000u) != 0) {
            printf("  OOM in test_const_wires (circuit B)\n");
            voleith_circuit_free(c);
            return;
        }

        uint8_t *d_out = calloc(ell_bytes, 1);
        uint8_t *a0_tilde = calloc(nb, 1);
        uint8_t *a1_tilde = calloc(nb, 1);
        uint8_t *a2_tilde = calloc(nb, 1);
        uint8_t *a0_out = calloc(nb, 1);

        if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out)
            goto circuit_b_cleanup;

        uint8_t empty_instance[1] = {0};

        /* a=1: 1 AND 0 = 0 → assert_zero passes */
        uint8_t witness[1] = {0x01};
        voleith_qs_prove(c, witness, empty_instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
        voleith_qs_verify(c, empty_instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
        check("CONST(0): a=1, AND(a,0)==0: a0_tilde matches",
              memcmp(a0_tilde, a0_out, nb) == 0);

        /* a=0: 0 AND 0 = 0 → assert_zero passes */
        memset(witness, 0, 1);
        memset(d_out, 0, ell_bytes);
        memset(a0_tilde, 0, nb);
        memset(a1_tilde, 0, nb);
        memset(a2_tilde, 0, nb);
        memset(a0_out, 0, nb);

        voleith_qs_prove(c, witness, empty_instance, lambda, vs.u,
                         (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                         a0_tilde, a1_tilde, a2_tilde);
        voleith_qs_verify(c, empty_instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
        check("CONST(0): a=0, AND(a,0)==0: a0_tilde matches",
              memcmp(a0_tilde, a0_out, nb) == 0);

    circuit_b_cleanup:
        free(d_out);
        free(a0_tilde);
        free(a1_tilde);
        free(a2_tilde);
        free(a0_out);
        vole_free(&vs);
        voleith_circuit_free(c);
    }
}

/* =====================================================================
 * Test 9: Multiple AND gates - accumulation correctness
 *
 * Circuit: (a AND b) XOR (c AND d) == e
 *   4 witness bits (a,b,c,d), 1 instance (e)
 *   and1 = AND(a, b)
 *   and2 = AND(c, d)
 *   xout = XOR(and1, and2)
 *   diff = XOR(xout, e)
 *   assert_zero(diff)
 *
 * Tests zk_hash_3 accumulation across 2 AND gates with independent
 * VOLE slots (slot 4 = n_witness+0, slot 5 = n_witness+1).
 * ===================================================================== */

static void
test_multi_and(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_witness(circuit);
    wire_id wd = voleith_circuit_add_witness(circuit);
    wire_id we = voleith_circuit_add_instance(circuit);
    wire_id and1 = voleith_circuit_add_and(circuit, wa, wb);
    wire_id and2 = voleith_circuit_add_and(circuit, wc, wd);
    wire_id xout = voleith_circuit_add_xor(circuit, and1, and2);
    wire_id diff = voleith_circuit_add_xor(circuit, xout, we);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;
    (void)wd;
    (void)we;

    check("multi-AND: ell = 6 (4 witness + 2 AND)",
          voleith_qs_ell(circuit) == 6);

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xA110C8D0u) != 0) {
        printf("  OOM in test_multi_and\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_multi_and\n");
        goto cleanup;
    }

    /* (1&1) XOR (1&1) = 0 → e=0 */
    uint8_t witness[1] = {0x0F};  /* bits 0-3 all set: a=b=c=d=1 */
    uint8_t instance[1] = {0x00}; /* e=0 */

    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("multi-AND (1&1 XOR 1&1)=0: prove returns 0", r == 0);
    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("multi-AND (1&1 XOR 1&1)=0: verify returns 0", r == 0);
    check("multi-AND (1&1 XOR 1&1)=0: a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* (1&1) XOR (0&1) = 1 → e=1 */
    memset(witness, 0, 1);
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 1); /* a=1,b=1 */
    set_bit(witness, 2, 0);
    set_bit(witness, 3, 1); /* c=0,d=1 */
    memset(instance, 0, 1);
    set_bit(instance, 0, 1); /* e=1 */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("multi-AND (1&1 XOR 0&1)=1: a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* Soundness: (1&1) XOR (0&1) = 1, but claim e=0 (wrong) */
    memset(instance, 0, 1); /* e=0 (wrong) */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("multi-AND soundness: wrong e detected (a0_tilde mismatch)",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 10: Tampered d vector → verifier key mismatch
 *
 * The d vector is the VOLE correction: d[s] = bit[w] XOR u[s].
 * The verifier computes key[w] = col_s(Q) + delta * d[s].
 * Flipping a bit of d changes key[w] by delta, making the AND
 * gate contribution key[a]*key[b] + key[c] wrong.
 * ===================================================================== */

static void
test_tampered_d(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_instance(circuit);
    wire_id wand = voleith_circuit_add_and(circuit, wa, wb);
    wire_id diff = voleith_circuit_add_xor(circuit, wand, wc);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xD00DCAFEu) != 0) {
        printf("  OOM in test_tampered_d\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t witness[1] = {0x03};  /* a=1, b=1 */
    uint8_t instance[1] = {0x01}; /* c=1 */

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_tampered_d\n");
        goto cleanup;
    }

    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    if (r != 0) {
        check("tampered d: prove returned 0", 0);
        goto cleanup;
    }

    /* Tamper bit 0 of d (witness slot 0) */
    d_out[0] ^= 0x01u;

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("tampered d[0]: verify returns 0", r == 0);
    check("tampered d[0]: a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

    /* Restore bit 0, tamper bit 1 of d (witness slot 1) */
    d_out[0] ^= 0x01u;
    d_out[0] ^= 0x02u;
    memset(a0_out, 0, nb);

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("tampered d[1]: a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

    /* Restore bit 1, tamper bit 2 of d (AND gate slot) */
    d_out[0] ^= 0x02u;
    d_out[0] ^= 0x04u;
    memset(a0_out, 0, nb);

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    (void)r;
    check("tampered d[2] (AND slot): a0_tilde mismatch",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 11: All gate types in one circuit
 *
 * Exercises witness, instance, CONST(0), CONST(1), NOT, XOR, AND
 * together, including AND gates whose inputs include NOT and CONST.
 *
 * Circuit:
 *   wa, wb, wc: witness bits
 *   inst:       instance bit
 *   k1 = CONST(1)
 *   not_c = NOT(wc)                         # NOT(wc)
 *   and1  = AND(wa, k1)                     # AND with CONST(1) = wa
 *   and2  = AND(not_c, wb)                  # AND with NOT input
 *   xor1  = XOR(and1, and2)                 # (wa) XOR (NOT(wc) AND wb)
 *   diff  = XOR(xor1, inst)
 *   assert_zero(diff)
 *
 * Valid witness: wa=1, wb=1, wc=0, inst = 1 XOR (NOT(0) AND 1) = 1 XOR 1 = 0
 * ===================================================================== */

static void
test_all_gate_types(void)
{
    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    voleith_circuit_t *circuit = voleith_circuit_new();
    wire_id wa = voleith_circuit_add_witness(circuit);
    wire_id wb = voleith_circuit_add_witness(circuit);
    wire_id wc = voleith_circuit_add_witness(circuit);
    wire_id inst = voleith_circuit_add_instance(circuit);
    wire_id k1 = voleith_circuit_add_const(circuit, 1);
    wire_id not_c = voleith_circuit_add_not(circuit, wc);
    wire_id and1 = voleith_circuit_add_and(circuit, wa, k1);
    wire_id and2 = voleith_circuit_add_and(circuit, not_c, wb);
    wire_id xor1 = voleith_circuit_add_xor(circuit, and1, and2);
    wire_id diff = voleith_circuit_add_xor(circuit, xor1, inst);
    voleith_circuit_assert_zero(circuit, diff);
    (void)wa;
    (void)wb;
    (void)wc;
    (void)inst;
    (void)k1;
    (void)not_c;

    check("all-gate-types: 2 AND gates",
          voleith_circuit_and_gate_count(circuit) == 2);
    check("all-gate-types: ell = 5 (3 witness + 2 AND)",
          voleith_qs_ell(circuit) == 5);

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xA11EA7E5u) != 0) {
        printf("  OOM in test_all_gate_types\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_all_gate_types\n");
        goto cleanup;
    }

    /* wa=1, wb=1, wc=0: and1=1&1=1, and2=NOT(0)&1=1&1=1, xor1=1^1=0, inst=0 */
    uint8_t witness[1] = {0x03};  /* bits 0=1(wa), 1=1(wb), 2=0(wc) */
    uint8_t instance[1] = {0x00}; /* inst=0 */

    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("all-gate-types valid: prove returns 0", r == 0);
    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("all-gate-types valid: verify returns 0", r == 0);
    check("all-gate-types valid: a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* wa=0, wb=1, wc=1: and1=0&1=0, and2=NOT(1)&1=0&1=0, xor1=0^0=0, inst=0 */
    memset(witness, 0, 1);
    set_bit(witness, 0, 0);
    set_bit(witness, 1, 1);
    set_bit(witness, 2, 1);
    memset(instance, 0, 1); /* inst=0 */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("all-gate-types (wa=0,wb=1,wc=1 → result=0): a0_tilde matches",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* Soundness: wa=1,wb=1,wc=0 but wrong inst=1 (correct is 0) */
    memset(witness, 0, 1);
    set_bit(witness, 0, 1);
    set_bit(witness, 1, 1);
    set_bit(witness, 2, 0);
    memset(instance, 0, 1);
    set_bit(instance, 0, 1); /* wrong */
    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("all-gate-types soundness: wrong inst detected",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * Test 12: AES-128 integration - prove knowledge of key
 *
 * Circuit: key (128 witness bits) is the AES-128 key such that
 *   AES-128(key, plaintext) == ciphertext
 *   plaintext and ciphertext are instance (public) inputs.
 *
 * Uses NIST FIPS 197, Appendix B test vector:
 *   Key:        00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
 *   Plaintext:  00 11 22 33 44 55 66 77  88 99 aa bb cc dd ee ff
 *   Ciphertext: 69 c4 e0 d8 6a 7b 04 30  d8 cd b7 80 70 b4 c5 5a
 *
 * This exercises the full stack at realistic scale:
 *   ell = 128 witness + 7200 AND gates = 7328
 *   ellhat (lambda=128) = 7328 + 3*128 + 16 = 7728
 *   V/Q matrices: 128 rows × 966 bytes ≈ 121 KB each
 *
 * Correctness: correct key → a0_tilde matches.
 * Soundness: wrong key (1 bit flipped) → a0_tilde mismatch.
 * ===================================================================== */

static void
test_aes128_integration(void)
{
    static const uint8_t aes_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                        0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t aes_pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                       0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                       0xcc, 0xdd, 0xee, 0xff};
    static const uint8_t aes_ct[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                       0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                       0x70, 0xb4, 0xc5, 0x5a};

    unsigned int lambda = 128;
    unsigned int nb = lambda / 8;

    /* Build circuit */
    voleith_circuit_t *circuit = voleith_circuit_new();
    if (!circuit) {
        check("AES-128 integration: circuit_new", 0);
        return;
    }

    wire_id key_wires[128], pt_wires[128], ct_wires[128], out_wires[128];

    for (int i = 0; i < 128; i++)
        key_wires[i] = voleith_circuit_add_witness(circuit);
    for (int i = 0; i < 128; i++)
        pt_wires[i] = voleith_circuit_add_instance(circuit);
    for (int i = 0; i < 128; i++)
        ct_wires[i] = voleith_circuit_add_instance(circuit);

    aes128_circuit(circuit, key_wires, pt_wires, out_wires);

    for (int i = 0; i < 128; i++)
        voleith_circuit_assert_equal(circuit, out_wires[i], ct_wires[i]);

    check("AES-128 circuit: 7200 AND gates",
          voleith_circuit_and_gate_count(circuit) == 7200);
    check("AES-128 circuit: ell = 7328", voleith_qs_ell(circuit) == 7328);

    size_t ell = voleith_qs_ell(circuit);
    size_t ellhat = voleith_qs_ellhat(circuit, lambda);
    size_t ell_bytes = (ell + 7) / 8;
    size_t ellhat_bytes = (ellhat + 7) / 8;

    /* Bit-pack witness (key) and instance (plaintext || ciphertext).
     * The AES circuit uses bit 0 = LSB of each byte, so the byte arrays
     * map directly to the packed bit representation. */
    uint8_t witness[16];  /* 128 bits = 16 bytes */
    uint8_t instance[32]; /* 256 bits = 32 bytes (plaintext || ciphertext) */
    memcpy(witness, aes_key, 16);
    memcpy(instance, aes_pt, 16);
    memcpy(instance + 16, aes_ct, 16);

    /* Allocate synthetic VOLE */
    vole_state_t vs;
    if (vole_alloc(&vs, lambda, ellhat_bytes, 0xAE5128u) != 0) {
        printf("  OOM in test_aes128_integration\n");
        voleith_circuit_free(circuit);
        return;
    }

    uint8_t *d_out = calloc(ell_bytes, 1);
    uint8_t *a0_tilde = calloc(nb, 1);
    uint8_t *a1_tilde = calloc(nb, 1);
    uint8_t *a2_tilde = calloc(nb, 1);
    uint8_t *a0_out = calloc(nb, 1);

    if (!d_out || !a0_tilde || !a1_tilde || !a2_tilde || !a0_out) {
        printf("  OOM in test_aes128_integration\n");
        goto cleanup;
    }

    /* --- Correctness: correct key → a0_tilde matches --- */
    int r = voleith_qs_prove(circuit, witness, instance, lambda, vs.u,
                             (const uint8_t **)vs.V_rows, vs.chall_2, d_out,
                             a0_tilde, a1_tilde, a2_tilde);
    check("AES-128 integration: prove returns 0 (correct key)", r == 0);

    r = voleith_qs_verify(circuit, instance, lambda,
                          (const uint8_t **)vs.Q_rows, d_out, vs.delta,
                          vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("AES-128 integration: verify returns 0 (correct key)", r == 0);
    check("AES-128 integration: a0_tilde matches (correct key)",
          memcmp(a0_tilde, a0_out, nb) == 0);

    /* --- Soundness: wrong key (flip bit 0 of key byte 0) → mismatch --- */
    uint8_t wrong_witness[16];
    memcpy(wrong_witness, aes_key, 16);
    wrong_witness[0] ^= 0x01u; /* flip LSB of first key byte */

    memset(d_out, 0, ell_bytes);
    memset(a0_tilde, 0, nb);
    memset(a1_tilde, 0, nb);
    memset(a2_tilde, 0, nb);
    memset(a0_out, 0, nb);

    voleith_qs_prove(circuit, wrong_witness, instance, lambda, vs.u,
                     (const uint8_t **)vs.V_rows, vs.chall_2, d_out, a0_tilde,
                     a1_tilde, a2_tilde);
    voleith_qs_verify(circuit, instance, lambda, (const uint8_t **)vs.Q_rows,
                      d_out, vs.delta, vs.chall_2, a1_tilde, a2_tilde, a0_out);
    check("AES-128 integration: a0_tilde mismatch (wrong key)",
          memcmp(a0_tilde, a0_out, nb) != 0);

cleanup:
    free(d_out);
    free(a0_tilde);
    free(a1_tilde);
    free(a2_tilde);
    free(a0_out);
    vole_free(&vs);
    voleith_circuit_free(circuit);
}

/* =====================================================================
 * main
 * ===================================================================== */

int
main(void)
{
    printf("test_quicksilver: QuickSilver prover + verifier\n");

    test_ell_ellhat();
    test_roundtrip_valid();
    test_invalid_witness();
    test_tampered_proof();
    test_no_and_circuit();
    test_invalid_params();
    test_not_gate_in_and();
    test_const_wires();
    test_multi_and();
    test_tampered_d();
    test_all_gate_types();
    test_aes128_integration();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
