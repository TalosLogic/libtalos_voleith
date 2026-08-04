/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_syndrome_gf16.c - OP.SYNG step 3, GF(2^16) mirror of test_syndrome_gf8.
 *
 * Same validation layers as the gf8 twin: an INDEPENDENT schoolbook circulant
 * oracle cross-checks the circuit's clear-domain recompute; a QuickSilver
 * round-trip and a full two-phase proof exercise the degree-idx_bits
 * accumulators; and a real-parameter cross-check confirms the in-circuit
 * relation matches the production ichor gf2x helper at real dimensions.
 */

#include "gf16_circuit.h"
#include "gf16_prover.h"
#include "gf16_prover_internal.h" /* test-only unchecked prove seam */
#include "gf16_verifier.h"
#include "gf16_proof.h"   /* prove_v2 / verify_v2 (two-phase full proof) */
#include "proof.h"        /* voleith_params_*, voleith_proof_free */
#include "proof_header.h" /* VOLEITH_PROOF_HEADER_BYTES */
#include "qs_degree.h"    /* VOLEITH_QS_COEFFS_MAX */
#include "field16.h"
#include "../proof/rs_opener_argus_gf8.h"

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
        printf("  ok   %s\n", name);
    } else {
        printf("  FAIL %s\n", name);
    }
}

/* Independent oracle: dense circulant syndrome s = M0*e0 + ... + e_{n0-1}. */
static void
oracle_syndrome(uint8_t *s, uint32_t p, uint32_t n0, uint32_t t,
                const uint32_t *indices, const uint8_t *M)
{
    size_t block_bytes = ((size_t)p + 7u) / 8u;
    uint8_t *e = calloc((size_t)n0 * p, 1);
    for (uint32_t k = 0; k < t; k++)
        if (indices[k] < (uint32_t)n0 * p) /* out-of-range = no column */
            e[indices[k]] = 1;
    for (uint32_t j = 0; j < p; j++)
        s[j] = e[(size_t)(n0 - 1u) * p + j];
    for (uint32_t b = 0; b + 1u < n0; b++) {
        const uint8_t *mb = M + (size_t)b * block_bytes;
        for (uint32_t a = 0; a < p; a++)
            if ((mb[a >> 3] >> (a & 7u)) & 1u)
                for (uint32_t cpos = 0; cpos < p; cpos++)
                    s[(a + cpos) % p] ^= e[(size_t)b * p + cpos];
    }
    free(e);
}

/* Build a circuit + eval; returns check_constraints (1/0), -1 on error. */
static int
run_case(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
         const uint32_t *indices, const uint8_t *M, const uint8_t *s)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    size_t nib = (size_t)t * idx_bits;
    gf16_wire_id *idx_w = malloc(nib * sizeof(gf16_wire_id));
    gf16_wire_id *s_w = malloc((size_t)p * sizeof(gf16_wire_id));
    voleith_gf16_t *witness = malloc(nib * sizeof(voleith_gf16_t));
    voleith_gf16_t *instance = malloc((size_t)p * sizeof(voleith_gf16_t));
    voleith_gf16_t *wire_vals;
    int res;

    for (uint32_t k = 0; k < t; k++)
        for (uint32_t b = 0; b < idx_bits; b++) {
            idx_w[k * idx_bits + b] = voleith_gf16_add_witness(c);
            witness[k * idx_bits + b] =
                (voleith_gf16_t)((indices[k] >> (idx_bits - 1u - b)) & 1u);
        }
    for (uint32_t j = 0; j < p; j++) {
        s_w[j] = voleith_gf16_add_instance(c);
        instance[j] = (voleith_gf16_t)(s[j] & 1u);
    }
    voleith_gf16_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);

    wire_vals =
        malloc(voleith_gf16_circuit_wire_count(c) * sizeof(voleith_gf16_t));
    res = voleith_gf16_circuit_eval(c, witness, instance, wire_vals);
    if (res != 1 && res != 0)
        res = -1;

    free(idx_w);
    free(s_w);
    free(witness);
    free(instance);
    free(wire_vals);
    voleith_gf16_circuit_free(c);
    return res;
}

/* =====================================================================
 * QuickSilver-level prove + verify round-trip (synthesized VOLE).
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
prng_fill(uint8_t *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        b[i] = prng_byte();
}
static inline unsigned int
get_bit_t(const uint8_t *b, size_t pos)
{
    return (b[pos / 8] >> (pos % 8)) & 1u;
}

typedef struct {
    uint8_t *u, **V_rows, **Q_rows, *V_data, *Q_data, *delta, *chall_2;
    unsigned int lambda;
    size_t ellhat_bytes;
} vole_state_t;

static int
vole_alloc(vole_state_t *vs, unsigned int lambda, size_t ellhat)
{
    unsigned int nb = lambda / 8;
    vs->lambda = lambda;
    vs->ellhat_bytes = ellhat;
    vs->u = malloc(ellhat);
    vs->V_data = malloc((size_t)lambda * ellhat);
    vs->Q_data = malloc((size_t)lambda * ellhat);
    vs->V_rows = malloc(lambda * sizeof(uint8_t *));
    vs->Q_rows = malloc(lambda * sizeof(uint8_t *));
    vs->delta = malloc(nb);
    vs->chall_2 = malloc(3 * nb + 8);
    if (!vs->u || !vs->V_data || !vs->Q_data || !vs->V_rows || !vs->Q_rows ||
        !vs->delta || !vs->chall_2)
        return -1;
    for (unsigned int j = 0; j < lambda; j++) {
        vs->V_rows[j] = vs->V_data + (size_t)j * ellhat;
        vs->Q_rows[j] = vs->Q_data + (size_t)j * ellhat;
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

static voleith_gf16_circuit_t *
build_synd(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
           const uint32_t *indices, const uint8_t *M, const uint8_t *s,
           voleith_gf16_t **witness_out, voleith_gf16_t **instance_out)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    size_t nib = (size_t)t * idx_bits;
    gf16_wire_id *idx_w = malloc(nib * sizeof(gf16_wire_id));
    gf16_wire_id *s_w = malloc((size_t)p * sizeof(gf16_wire_id));
    voleith_gf16_t *witness = malloc(nib * sizeof(voleith_gf16_t));
    voleith_gf16_t *instance = malloc((size_t)p * sizeof(voleith_gf16_t));

    for (uint32_t k = 0; k < t; k++)
        for (uint32_t b = 0; b < idx_bits; b++) {
            idx_w[k * idx_bits + b] = voleith_gf16_add_witness(c);
            witness[k * idx_bits + b] =
                (voleith_gf16_t)((indices[k] >> (idx_bits - 1u - b)) & 1u);
        }
    for (uint32_t j = 0; j < p; j++) {
        s_w[j] = voleith_gf16_add_instance(c);
        instance[j] = (voleith_gf16_t)(s[j] & 1u);
    }
    voleith_gf16_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);
    free(idx_w);
    free(s_w);
    *witness_out = witness;
    *instance_out = instance;
    return c;
}

/*
 * Returns 1 if verify accepts (a0 matches), 0 if rejects, -2 on error.  If
 * tamper_top != 0, one byte of the opener-degree coefficient a_d is flipped
 * after prove and before verify (pins degree-d coefficient binding).
 */
static int
run_synd_proof_ex(voleith_gf16_circuit_t *c, const voleith_gf16_t *witness,
                  const voleith_gf16_t *instance, unsigned int lambda,
                  int use_unchecked, int tamper_top)
{
    size_t ell = voleith_gf16_qs_ell(c);
    size_t ellhat = voleith_gf16_qs_ellhat(c, lambda);
    unsigned int nb = lambda / 8;
    unsigned int d = voleith_gf16_circuit_qs_degree(c);
    vole_state_t vs;
    int rc = -2;

    if (vole_alloc(&vs, lambda, ellhat) < 0) {
        vole_free(&vs);
        return -2;
    }
    g_prng = 0x5117D0Eu;
    vole_fill(&vs);

    uint8_t *dcorr = calloc(2 * ell + 1, 1);
    if (!dcorr)
        goto done;
    {
        int cd =
            use_unchecked
                ? voleith_gf16_qs_compute_d_unchecked(c, witness, instance,
                                                      vs.u, dcorr)
                : voleith_gf16_qs_compute_d(c, witness, instance, vs.u, dcorr);
        if (cd < 0)
            goto done;
    }

    uint8_t a_buf[VOLEITH_QS_COEFFS_MAX][32];
    uint8_t *a_out[VOLEITH_QS_COEFFS_MAX];
    memset(a_buf, 0, sizeof(a_buf));
    for (unsigned int i = 0; i <= d; i++)
        a_out[i] = a_buf[i];

    {
        int pr =
            use_unchecked
                ? voleith_gf16_qs_prove_unchecked(
                      c, witness, instance, lambda, vs.u,
                      (const uint8_t **)vs.V_rows, vs.chall_2, dcorr, a_out)
                : voleith_gf16_qs_prove(c, witness, instance, lambda, vs.u,
                                        (const uint8_t **)vs.V_rows, vs.chall_2,
                                        dcorr, a_out);
        if (pr != 0)
            goto done;
    }

    if (tamper_top)
        a_buf[d][0] ^= 0x01u; /* flip the opener-degree coefficient a_d */

    const uint8_t *a_in[VOLEITH_QS_COEFFS_MAX];
    for (unsigned int i = 1; i <= d; i++)
        a_in[i] = a_buf[i];
    uint8_t a0v[32] = {0};
    if (voleith_gf16_qs_verify(c, instance, lambda, (const uint8_t **)vs.Q_rows,
                               dcorr, vs.delta, vs.chall_2, a_in, a0v) != 0)
        goto done;
    rc = (memcmp(a_buf[0], a0v, nb) == 0) ? 1 : 0;

done:
    free(dcorr);
    vole_free(&vs);
    return rc;
}

static int
run_synd_proof(voleith_gf16_circuit_t *c, const voleith_gf16_t *witness,
               const voleith_gf16_t *instance, unsigned int lambda,
               int use_unchecked)
{
    return run_synd_proof_ex(c, witness, instance, lambda, use_unchecked, 0);
}

/*
 * Well-formed syndrome circuit (GF(2^16) twin of the gf8 build_synd_wf):
 * build_synd plus the UNIFORM weight-t support well-formedness constraints
 * (strict-ascending LT chain over idx[k] < idx[k+1] = distinct + ascending +
 * canonical, and a range check idx[t-1] < n against a baked constant n).  Both
 * are zero-slot degree-(idx_bits+1) constraints batched into the syndrome
 * zk_hash.
 */
static voleith_gf16_circuit_t *
build_synd_wf(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
              const uint32_t *indices, const uint8_t *M, const uint8_t *s,
              voleith_gf16_t **witness_out, voleith_gf16_t **instance_out)
{
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    size_t nib = (size_t)t * idx_bits;
    gf16_wire_id *idx_w = malloc(nib * sizeof(gf16_wire_id));
    gf16_wire_id *s_w = malloc((size_t)p * sizeof(gf16_wire_id));
    gf16_wire_id *n_w = malloc((size_t)idx_bits * sizeof(gf16_wire_id));
    voleith_gf16_t *witness = malloc(nib * sizeof(voleith_gf16_t));
    voleith_gf16_t *instance = malloc((size_t)p * sizeof(voleith_gf16_t));
    uint32_t n = (uint32_t)n0 * p;

    for (uint32_t k = 0; k < t; k++)
        for (uint32_t b = 0; b < idx_bits; b++) {
            idx_w[k * idx_bits + b] = voleith_gf16_add_witness(c);
            witness[k * idx_bits + b] =
                (voleith_gf16_t)((indices[k] >> (idx_bits - 1u - b)) & 1u);
        }
    for (uint32_t j = 0; j < p; j++) {
        s_w[j] = voleith_gf16_add_instance(c);
        instance[j] = (voleith_gf16_t)(s[j] & 1u);
    }
    for (uint32_t b = 0; b < idx_bits; b++)
        n_w[b] = voleith_gf16_add_const(
            c, (voleith_gf16_t)((n >> (idx_bits - 1u - b)) & 1u));

    voleith_gf16_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);
    for (uint32_t k = 0; k + 1u < t; k++)
        voleith_gf16_assert_lt(c, idx_w + (size_t)k * idx_bits,
                               idx_w + (size_t)(k + 1u) * idx_bits, idx_bits);
    voleith_gf16_assert_lt(c, idx_w + (size_t)(t - 1u) * idx_bits, n_w,
                           idx_bits);

    free(idx_w);
    free(s_w);
    free(n_w);
    *witness_out = witness;
    *instance_out = instance;
    return c;
}

/* Verdict cross-check (option 1): collapsed (mode 0) vs reference (mode 1)
 * accumulator must give the same accept/reject over the same circuit / VOLE. */
static void
xcheck_ref_vs_collapsed(uint32_t p, uint32_t n0, uint32_t t, uint32_t idx_bits,
                        const uint32_t *indices, const uint8_t *M,
                        const uint8_t *s, int unchecked, unsigned int lambda,
                        const char *nm)
{
    voleith_gf16_t *wit, *inst;
    voleith_gf16_circuit_t *c =
        build_synd(p, n0, t, idx_bits, indices, M, s, &wit, &inst);
    voleith_gf16_syndrome_ref_mode = 0;
    int coll = run_synd_proof(c, wit, inst, lambda, unchecked);
    voleith_gf16_syndrome_ref_mode = 1;
    int ref = run_synd_proof(c, wit, inst, lambda, unchecked);
    voleith_gf16_syndrome_ref_mode = 0;
    char buf[96];
    snprintf(buf, sizeof(buf), "ref==collapsed verdict (%s)", nm);
    check(buf, coll >= 0 && coll == ref);
    free(wit);
    free(inst);
    voleith_gf16_circuit_free(c);
}

/* =====================================================================
 * Real-parameter cross-check against the production software syndrome helper.
 * ===================================================================== */
static void
fill_M_real(uint8_t *M, const voleith_rs_opener_argus_params_t *p)
{
    size_t nb = (size_t)(p->n0 - 1u) * p->block_bytes;
    unsigned padbits = (unsigned)(8u * p->block_bytes - p->p);
    uint8_t mask = padbits ? (uint8_t)(0xFFu >> padbits) : 0xFFu;
    for (size_t i = 0; i < nb; i++)
        M[i] = (uint8_t)(0x9eu * (unsigned)i + 0x37u);
    for (uint32_t b = 0; b + 1u < p->n0; b++)
        M[(size_t)(b + 1u) * p->block_bytes - 1u] &= mask;
}
static void
fill_indices_real(uint32_t *idx, const voleith_rs_opener_argus_params_t *p)
{
    uint32_t stride = p->n / p->t;
    for (uint32_t j = 0; j < p->t; j++)
        idx[j] = j * stride;
}

static void
test_real_param_xcheck(voleith_rs_opener_argus_set_t set, const char *label)
{
    const voleith_rs_opener_argus_params_t *pp =
        voleith_rs_opener_argus_params(set);
    char nm[96];
    if (!pp) {
        snprintf(nm, sizeof(nm), "params available: %s", label);
        check(nm, 0);
        return;
    }
    size_t mb = (size_t)(pp->n0 - 1u) * pp->block_bytes;
    uint8_t *M = malloc(mb ? mb : 1);
    uint32_t *idx = malloc((size_t)pp->t * sizeof(uint32_t));
    uint8_t *s_packed = malloc(pp->block_bytes);
    uint8_t *s_bits = malloc(pp->p);
    if (!M || !idx || !s_packed || !s_bits) {
        snprintf(nm, sizeof(nm), "alloc: %s", label);
        check(nm, 0);
        goto cleanup;
    }
    fill_M_real(M, pp);
    fill_indices_real(idx, pp);

    snprintf(nm, sizeof(nm), "production syndrome helper ok: %s", label);
    check(nm, voleith_rs_opener_argus_syndrome(pp, s_packed, M, idx) == 0);

    for (uint32_t j = 0; j < pp->p; j++)
        s_bits[j] = (uint8_t)((s_packed[j >> 3] >> (j & 7u)) & 1u);

    {
        uint8_t *s_oracle = malloc(pp->p);
        int eq = 1;
        if (s_oracle) {
            oracle_syndrome(s_oracle, pp->p, pp->n0, pp->t, idx, M);
            for (uint32_t j = 0; j < pp->p; j++)
                if ((s_oracle[j] & 1u) != s_bits[j]) {
                    eq = 0;
                    break;
                }
        }
        snprintf(nm, sizeof(nm), "schoolbook oracle == production helper s: %s",
                 label);
        check(nm, s_oracle && eq);
        free(s_oracle);
    }

    snprintf(nm, sizeof(nm), "circuit accepts production s: %s", label);
    check(nm,
          run_case(pp->p, pp->n0, pp->t, pp->idx_bits, idx, M, s_bits) == 1);

    s_bits[0] ^= 1u;
    snprintf(nm, sizeof(nm), "circuit rejects tampered production s: %s",
             label);
    check(nm,
          run_case(pp->p, pp->n0, pp->t, pp->idx_bits, idx, M, s_bits) == 0);

cleanup:
    free(M);
    free(idx);
    free(s_packed);
    free(s_bits);
}

/* =====================================================================
 * Full two-phase proof (prove_v2 -> verify_v2) over a syndrome circuit.
 * ===================================================================== */
static void
test_two_phase(const voleith_params_t *params, uint32_t p, uint32_t n0,
               uint32_t t, uint32_t idx_bits, const uint32_t *indices,
               const uint8_t *M, const char *label)
{
    printf("\n[two-phase syndrome full proof (gf16): %s]\n", label);
    uint8_t s[64];
    oracle_syndrome(s, p, n0, t, indices, M);

    voleith_gf16_t *witness, *instance;
    voleith_gf16_circuit_t *c =
        build_synd(p, n0, t, idx_bits, indices, M, s, &witness, &instance);
    size_t nwit = voleith_gf16_circuit_witness_count(c);
    uint8_t fs_seed[16];
    memset(fs_seed, 0x3b, sizeof(fs_seed));

    check("qs_degree == idx_bits (>2)",
          voleith_gf16_circuit_qs_degree(c) == idx_bits);

    voleith_proof_t proof;
    memset(&proof, 0, sizeof(proof));
    check("prove_v2 succeeds",
          voleith_gf16_prove_v2(&proof, params, c, witness, nwit, instance, p,
                                fs_seed, sizeof(fs_seed)) == 0);
    check("verify_v2 accepts valid d>2 proof",
          voleith_gf16_verify_v2(&proof, params, c, instance, p, fs_seed,
                                 sizeof(fs_seed)) == 0);
    check("proof_byte_size_circuit matches",
          voleith_gf16_proof_byte_size_circuit(params, c) == proof.len);

    if (proof.data && proof.len > VOLEITH_PROOF_HEADER_BYTES) {
        uint8_t saved = proof.data[proof.len - 1];
        proof.data[proof.len - 1] ^= 0x40u;
        check("verify_v2 rejects tampered proof",
              voleith_gf16_verify_v2(&proof, params, c, instance, p, fs_seed,
                                     sizeof(fs_seed)) != 0);
        proof.data[proof.len - 1] = saved;
    }

    instance[1] ^= 1u;
    check("verify_v2 rejects tampered public s",
          voleith_gf16_verify_v2(&proof, params, c, instance, p, fs_seed,
                                 sizeof(fs_seed)) != 0);
    instance[1] ^= 1u;

    voleith_proof_free(&proof);
    free(witness);
    free(instance);
    voleith_gf16_circuit_free(c);
}

int
main(void)
{
    const uint32_t p = 7, n0 = 2, t = 2, idx_bits = 4;
    uint8_t M[1] = {0x5a};
    uint32_t indices[2] = {2, 9};
    uint8_t s[7];

    printf("test_syndrome_gf16 (OP.SYNG step 3, gf16 mirror)\n");

    oracle_syndrome(s, p, n0, t, indices, M);

    check("valid support + s accepts",
          run_case(p, n0, t, idx_bits, indices, M, s) == 1);
    {
        uint8_t sbad[7];
        memcpy(sbad, s, 7);
        sbad[3] ^= 1u;
        check("tampered s bit rejects",
              run_case(p, n0, t, idx_bits, indices, M, sbad) == 0);
    }
    {
        uint32_t bad_idx[2] = {3, 9};
        check("wrong support index rejects",
              run_case(p, n0, t, idx_bits, bad_idx, M, s) == 0);
    }
    {
        voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
        gf16_wire_id idx_w[8], s_w[7];
        for (int i = 0; i < 8; i++)
            idx_w[i] = voleith_gf16_add_witness(c);
        for (int i = 0; i < 7; i++)
            s_w[i] = voleith_gf16_add_instance(c);
        voleith_gf16_assert_syndrome(c, idx_w, s_w, t, idx_bits, p, n0, M);
        check("qs_degree == idx_bits",
              voleith_gf16_circuit_qs_degree(c) == idx_bits);
        check("validate passes", voleith_gf16_circuit_validate(c) == 0);
        check("syndrome_count == 1",
              voleith_gf16_circuit_syndrome_count(c) == 1);
        voleith_gf16_circuit_free(c);
    }

    /* Real-parameter cross-check (release-gate sets). */
    test_real_param_xcheck(VOLEITH_RS_OPENER_ARGUS_SET_128_2, "128_2");
    test_real_param_xcheck(VOLEITH_RS_OPENER_ARGUS_SET_256_2, "256_2");

    /* QuickSilver round-trip at d = idx_bits. */
    {
        unsigned int lambdas[2] = {128, 256};
        for (int li = 0; li < 2; li++) {
            unsigned int lambda = lambdas[li];
            char nm[64];
            voleith_gf16_t *wit, *inst;
            voleith_gf16_circuit_t *c;

            c = build_synd(p, n0, t, idx_bits, indices, M, s, &wit, &inst);
            snprintf(nm, sizeof(nm), "roundtrip accept (lambda=%u)", lambda);
            check(nm, run_synd_proof(c, wit, inst, lambda, 0) == 1);
            free(wit);
            free(inst);
            voleith_gf16_circuit_free(c);

            {
                uint8_t sbad[7];
                memcpy(sbad, s, 7);
                sbad[2] ^= 1u;
                c = build_synd(p, n0, t, idx_bits, indices, M, sbad, &wit,
                               &inst);
                snprintf(nm, sizeof(nm), "roundtrip tampered-s rejects (%u)",
                         lambda);
                check(nm, run_synd_proof(c, wit, inst, lambda, 1) == 0);
                free(wit);
                free(inst);
                voleith_gf16_circuit_free(c);
            }
            {
                uint32_t bad_idx[2] = {5, 9};
                c = build_synd(p, n0, t, idx_bits, bad_idx, M, s, &wit, &inst);
                snprintf(nm, sizeof(nm), "roundtrip wrong-support rejects (%u)",
                         lambda);
                check(nm, run_synd_proof(c, wit, inst, lambda, 1) == 0);
                free(wit);
                free(inst);
                voleith_gf16_circuit_free(c);
            }
        }
    }

    /* Verdict cross-check: collapsed vs reference accumulator agree. */
    {
        unsigned int lambda = 128;
        uint32_t bad_idx[2] = {5, 9};
        uint8_t sbad[7];
        memcpy(sbad, s, 7);
        sbad[2] ^= 1u;
        xcheck_ref_vs_collapsed(p, n0, t, idx_bits, indices, M, s, 0, lambda,
                                "honest accept");
        xcheck_ref_vs_collapsed(p, n0, t, idx_bits, indices, M, sbad, 1, lambda,
                                "tampered s");
        xcheck_ref_vs_collapsed(p, n0, t, idx_bits, bad_idx, M, s, 1, lambda,
                                "wrong support");
    }

    /* Full two-phase proof at d>2. */
    {
        static const uint8_t M7[1] = {0x5a};
        static const uint32_t idx7[2] = {2, 9};
        test_two_phase(&voleith_params_em_128f, 7, 2, 2, 4, idx7, M7,
                       "em_128f p=7 (d=4)");
        static const uint8_t M13[2] = {0x2d, 0x0a};
        static const uint32_t idx13[3] = {3, 11, 19};
        test_two_phase(&voleith_params_em_256f, 13, 2, 3, 5, idx13, M13,
                       "em_256f p=13 (d=5)");
    }

    /* ===== OP.SYNG step 4: UNIFORM weight-t well-formedness =====
     * Each malformed shape is chosen so the syndrome equation accepts and only
     * the LT/range layer rejects (unchecked prover bypasses the upfront check). */
    {
        unsigned int lambdas[2] = {128, 256};
        for (int li = 0; li < 2; li++) {
            unsigned int lambda = lambdas[li];
            char nm[80];
            voleith_gf16_t *wit, *inst;
            voleith_gf16_circuit_t *c;

            c = build_synd_wf(p, n0, t, idx_bits, indices, M, s, &wit, &inst);
            snprintf(nm, sizeof(nm), "wf honest accepts (%u)", lambda);
            check(nm, run_synd_proof(c, wit, inst, lambda, 0) == 1);
            free(wit);
            free(inst);
            voleith_gf16_circuit_free(c);

            { /* duplicate: XOR cancels, commit s = 0; ascending LT rejects. */
                uint32_t dup[2] = {5, 5};
                uint8_t s0[7] = {0};
                c = build_synd_wf(p, n0, t, idx_bits, dup, M, s0, &wit, &inst);
                snprintf(nm, sizeof(nm), "wf duplicate rejects (%u)", lambda);
                check(nm, run_synd_proof(c, wit, inst, lambda, 1) == 0);
                free(wit);
                free(inst);
                voleith_gf16_circuit_free(c);
            }
            { /* descending: commutative XOR keeps honest s; LT rejects. */
                uint32_t desc[2] = {9, 2};
                c = build_synd_wf(p, n0, t, idx_bits, desc, M, s, &wit, &inst);
                snprintf(nm, sizeof(nm), "wf descending rejects (%u)", lambda);
                check(nm, run_synd_proof(c, wit, inst, lambda, 1) == 0);
                free(wit);
                free(inst);
                voleith_gf16_circuit_free(c);
            }
            { /* out-of-range: no column, s matches remainder; range LT rejects. */
                uint32_t oor[2] = {2, 14};
                uint8_t soor[7];
                oracle_syndrome(soor, p, n0, t, oor, M);
                c = build_synd_wf(p, n0, t, idx_bits, oor, M, soor, &wit,
                                  &inst);
                snprintf(nm, sizeof(nm), "wf out-of-range rejects (%u)",
                         lambda);
                check(nm, run_synd_proof(c, wit, inst, lambda, 1) == 0);
                free(wit);
                free(inst);
                voleith_gf16_circuit_free(c);
            }
            /* Opener-degree coefficient binding: tamper a_d, verify rejects. */
            c = build_synd_wf(p, n0, t, idx_bits, indices, M, s, &wit, &inst);
            snprintf(nm, sizeof(nm), "wf tampered a_d rejects (%u)", lambda);
            check(nm, run_synd_proof_ex(c, wit, inst, lambda, 0, 1) == 0);
            free(wit);
            free(inst);
            voleith_gf16_circuit_free(c);
        }
    }

    /* Slot count + opening degree: LT + range add ZERO VOLE slots and raise the
     * opening degree to idx_bits+1; t LT constraints (t-1 ascending + 1 range). */
    {
        voleith_gf16_t *wp, *ip, *ww, *iw;
        voleith_gf16_circuit_t *cp =
            build_synd(p, n0, t, idx_bits, indices, M, s, &wp, &ip);
        voleith_gf16_circuit_t *cw =
            build_synd_wf(p, n0, t, idx_bits, indices, M, s, &ww, &iw);
        check("wf adds zero VOLE slots",
              voleith_gf16_qs_ell(cw) == voleith_gf16_qs_ell(cp));
        check("wf qs_degree == idx_bits+1",
              voleith_gf16_circuit_qs_degree(cw) == idx_bits + 1u);
        check("wf validate passes", voleith_gf16_circuit_validate(cw) == 0);
        check("wf lt_count == t", voleith_gf16_circuit_lt_count(cw) == t);
        free(wp);
        free(ip);
        free(ww);
        free(iw);
        voleith_gf16_circuit_free(cp);
        voleith_gf16_circuit_free(cw);
    }

    printf("\n%d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
