/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_permutation_gf16_circuit.c - GF(2^16) AS-Waksman secret-permutation
 * gadget tests (P7 T7.5).
 *
 * Tests:
 *   1: switch-count formula matches known optimal AS-Waksman values, and the
 *      built circuit's mul-gate / witness counts agree.
 *   2: for random permutations over many sizes (incl. non-powers-of-two and the
 *      n=48 KAT grid), the routed control bits drive the circuit output to the
 *      plaintext permutation (eval).
 *   3: cross-check the gadget against the plaintext codec voleith_confrlnc
 *      permute on the n=48 grid.
 *   4: full prove + verify roundtrip with the output bound to a public instance.
 *   5: a tampered control bit is rejected (output no longer matches; prove
 *      fails), and booleanity rejects a non-{0,1} control value.
 */

#include "permutation_gf16_circuit.h"
#include "rlnc_confidential.h" /* plaintext permute oracle */
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

/* Deterministic splitmix-based PRNG for permutations and sample values. */
static uint64_t rng_state = UINT64_C(0x9E3779B97F4A7C15);

static uint64_t
rng_next(void)
{
    uint64_t z = (rng_state += UINT64_C(0x9E3779B97F4A7C15));
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

/* Uniform-ish Fisher-Yates permutation of [0, n). */
static void
random_perm(size_t *perm, size_t n)
{
    for (size_t i = 0; i < n; i++)
        perm[i] = i;
    for (size_t i = n; i-- > 1;) {
        size_t j = (size_t)(rng_next() % (uint64_t)(i + 1));
        size_t t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
    }
}

/* ===================================================================== */
static void
test_switch_counts(void)
{
    /* Known optimal AS-Waksman switch counts S(n) = ceil(n*log2 n - n + 1). */
    check("S(1) == 0", voleith_perm_gf16_n_switches(1) == 0);
    check("S(2) == 1", voleith_perm_gf16_n_switches(2) == 1);
    check("S(3) == 3", voleith_perm_gf16_n_switches(3) == 3);
    check("S(4) == 5", voleith_perm_gf16_n_switches(4) == 5);
    check("S(5) == 8", voleith_perm_gf16_n_switches(5) == 8);
    check("S(6) == 11", voleith_perm_gf16_n_switches(6) == 11);
    check("S(8) == 17", voleith_perm_gf16_n_switches(8) == 17);
    check("S(16) == 49", voleith_perm_gf16_n_switches(16) == 49);

    /* The built circuit has exactly S(n) mul gates and the caller supplies S(n)
     * control-bit witnesses. */
    size_t n = 13;
    size_t s = voleith_perm_gf16_n_switches(n);
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id *in = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *ctrl = calloc(s, sizeof(gf16_wire_id));
    gf16_wire_id *out = calloc(n, sizeof(gf16_wire_id));
    for (size_t i = 0; i < n; i++)
        in[i] = voleith_gf16_add_instance(c);
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);
    voleith_perm_gf16_circuit(c, in, ctrl, out, n);
    check("circuit builds ok", voleith_gf16_circuit_ok(c));
    check("n_mul == S(n)", voleith_gf16_circuit_mul_count(c) == s);
    check("n_witness == S(n)", voleith_gf16_circuit_witness_count(c) == s);
    free(in);
    free(ctrl);
    free(out);
    voleith_gf16_circuit_free(c);
}

/*
 * Build a circuit with inputs as instance wires and control bits as witnesses,
 * evaluate it for given values, and confirm the output wires carry the expected
 * permuted vector.  Returns 1 if eval passed AND outputs matched.
 */
static int
route_and_eval(const size_t *perm, size_t n)
{
    size_t s = voleith_perm_gf16_n_switches(n);
    uint16_t *bits = calloc(s ? s : 1, sizeof(uint16_t));
    if (voleith_perm_gf16_route(perm, n, bits) != 0) {
        free(bits);
        return 0;
    }

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id *in = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *ctrl = calloc(s ? s : 1, sizeof(gf16_wire_id));
    gf16_wire_id *out = calloc(n, sizeof(gf16_wire_id));
    for (size_t i = 0; i < n; i++)
        in[i] = voleith_gf16_add_instance(c);
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);
    voleith_perm_gf16_circuit(c, in, ctrl, out, n);

    /* instance = input values; witness = control bits. */
    voleith_gf16_t *in_vals = calloc(n, sizeof(voleith_gf16_t));
    voleith_gf16_t *wit = calloc(s ? s : 1, sizeof(voleith_gf16_t));
    for (size_t i = 0; i < n; i++)
        in_vals[i] = (voleith_gf16_t)(rng_next() & 0xffff);
    for (size_t i = 0; i < s; i++)
        wit[i] = bits[i];

    size_t nw = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));
    int ev = voleith_gf16_circuit_eval(c, wit, in_vals, vals);

    int ok = (ev == 1);
    for (size_t i = 0; i < n && ok; i++)
        if (vals[out[i]] != in_vals[perm[i]]) /* out[i] == in[perm[i]] */
            ok = 0;

    free(bits);
    free(in);
    free(ctrl);
    free(out);
    free(in_vals);
    free(wit);
    free(vals);
    voleith_gf16_circuit_free(c);
    return ok;
}

static void
test_route_eval(void)
{
    const size_t sizes[] = {2, 3, 4, 5, 6, 7, 8, 9, 13, 16, 31, 48, 64};
    int all = 1;
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        size_t *perm = calloc(n, sizeof(size_t));
        for (int trial = 0; trial < 8; trial++) {
            random_perm(perm, n);
            if (!route_and_eval(perm, n)) {
                printf("    (route/eval mismatch at n=%zu trial=%d)\n", n,
                       trial);
                all = 0;
                break;
            }
        }
        /* identity and reversal edge cases */
        for (size_t i = 0; i < n; i++)
            perm[i] = i;
        if (!route_and_eval(perm, n))
            all = 0;
        for (size_t i = 0; i < n; i++)
            perm[i] = n - 1 - i;
        if (!route_and_eval(perm, n))
            all = 0;
        free(perm);
    }
    check("routed circuit output == in[perm] over many sizes / perms", all);
}

/* Cross-check the gadget against the plaintext codec permute on the KAT grid. */
static void
test_codec_crosscheck(void)
{
    /* n = m*l*t = 4*6*2 = 48, the paper-figure grid. */
    voleith_confrlnc_params_t p = {VOLEITH_EC_FIELD_GF16, 2, 4, 6};
    size_t n = voleith_confrlnc_grid_size(&p);
    size_t s = voleith_perm_gf16_n_switches(n);

    size_t *perm = calloc(n, sizeof(size_t));
    random_perm(perm, n);
    uint16_t *bits = calloc(s, sizeof(uint16_t));
    int routed = (voleith_perm_gf16_route(perm, n, bits) == 0);
    check("route succeeds on n=48 grid", routed);

    /* Plaintext reference: codec permute on a random GF(2^16) grid. */
    uint16_t *in_vals = calloc(n, sizeof(uint16_t));
    uint16_t *ref = calloc(n, sizeof(uint16_t));
    for (size_t i = 0; i < n; i++)
        in_vals[i] = (uint16_t)(rng_next() & 0xffff);
    voleith_confrlnc_permute(&p, in_vals, perm, ref);

    /* Circuit output for the same inputs / control bits. */
    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id *in = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *ctrl = calloc(s, sizeof(gf16_wire_id));
    gf16_wire_id *out = calloc(n, sizeof(gf16_wire_id));
    for (size_t i = 0; i < n; i++)
        in[i] = voleith_gf16_add_instance(c);
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);
    voleith_perm_gf16_circuit(c, in, ctrl, out, n);

    voleith_gf16_t *ival = calloc(n, sizeof(voleith_gf16_t));
    voleith_gf16_t *wit = calloc(s, sizeof(voleith_gf16_t));
    for (size_t i = 0; i < n; i++)
        ival[i] = in_vals[i];
    for (size_t i = 0; i < s; i++)
        wit[i] = bits[i];
    size_t nw = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));
    int ev = voleith_gf16_circuit_eval(c, wit, ival, vals);

    int match = (ev == 1);
    for (size_t i = 0; i < n && match; i++)
        if (vals[out[i]] != ref[i])
            match = 0;
    check("gadget output == plaintext codec permute (n=48)", match);

    free(perm);
    free(bits);
    free(in_vals);
    free(ref);
    free(in);
    free(ctrl);
    free(out);
    free(ival);
    free(wit);
    free(vals);
    voleith_gf16_circuit_free(c);
}

/*
 * Build a prove/verify circuit binding the output to a public instance: in is
 * witness, expected-out is instance, control is witness, and out == exp is
 * asserted.  Returns the circuit and fills wire / value buffers (caller frees).
 */
static voleith_gf16_circuit_t *
build_bound_circuit(const size_t *perm, size_t n, const uint16_t *in_vals,
                    voleith_gf16_t **witness_out, voleith_gf16_t **instance_out,
                    size_t *n_wit, size_t *n_inst)
{
    size_t s = voleith_perm_gf16_n_switches(n);
    uint16_t *bits = calloc(s, sizeof(uint16_t));
    if (voleith_perm_gf16_route(perm, n, bits) != 0) {
        free(bits);
        return NULL;
    }

    voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
    gf16_wire_id *in = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *ctrl = calloc(s, sizeof(gf16_wire_id));
    gf16_wire_id *exp = calloc(n, sizeof(gf16_wire_id));
    gf16_wire_id *out = calloc(n, sizeof(gf16_wire_id));

    /* witness order: in (n) then ctrl (s); instance order: exp (n). */
    for (size_t i = 0; i < n; i++)
        in[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < s; i++)
        ctrl[i] = voleith_gf16_add_witness(c);
    for (size_t i = 0; i < n; i++)
        exp[i] = voleith_gf16_add_instance(c);

    voleith_perm_gf16_circuit(c, in, ctrl, out, n);
    for (size_t i = 0; i < n; i++)
        voleith_gf16_assert_equal(c, out[i], exp[i]);

    voleith_gf16_t *wit = calloc(n + s, sizeof(voleith_gf16_t));
    voleith_gf16_t *inst = calloc(n, sizeof(voleith_gf16_t));
    for (size_t i = 0; i < n; i++)
        wit[i] = in_vals[i];
    for (size_t i = 0; i < s; i++)
        wit[n + i] = bits[i];
    for (size_t i = 0; i < n; i++)
        inst[i] = in_vals[perm[i]]; /* expected out[i] = in[perm[i]] */

    *witness_out = wit;
    *instance_out = inst;
    *n_wit = n + s;
    *n_inst = n;

    free(bits);
    free(in);
    free(ctrl);
    free(exp);
    free(out);
    return c;
}

static void
test_prove_verify(void)
{
    const size_t sizes[] = {7, 12};
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        size_t *perm = calloc(n, sizeof(size_t));
        random_perm(perm, n);
        uint16_t *in_vals = calloc(n, sizeof(uint16_t));
        for (size_t i = 0; i < n; i++)
            in_vals[i] = (uint16_t)(rng_next() & 0xffff);

        voleith_gf16_t *wit = NULL, *inst = NULL;
        size_t nwit = 0, ninst = 0;
        voleith_gf16_circuit_t *c =
            build_bound_circuit(perm, n, in_vals, &wit, &inst, &nwit, &ninst);
        check("bound circuit builds", c && voleith_gf16_circuit_ok(c));

        uint8_t fs_seed[16];
        memset(fs_seed, 0x5a, sizeof(fs_seed));
        voleith_proof_t proof;
        int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, wit,
                                      inst, fs_seed, sizeof(fs_seed));
        check("prove succeeds", pret == 0);
        if (pret == 0) {
            int vret = voleith_gf16_verify(&proof, &voleith_params_em_128f, c,
                                           inst, fs_seed, sizeof(fs_seed));
            check("verify accepts a correct permutation proof", vret == 0);
            voleith_proof_free(&proof);
        }

        free(perm);
        free(in_vals);
        free(wit);
        free(inst);
        voleith_gf16_circuit_free(c);
    }
}

static void
test_tamper_and_booleanity(void)
{
    size_t n = 9;
    size_t s = voleith_perm_gf16_n_switches(n);
    size_t *perm = calloc(n, sizeof(size_t));
    random_perm(perm, n);
    uint16_t *in_vals = calloc(n, sizeof(uint16_t));
    for (size_t i = 0; i < n; i++)
        in_vals[i] = (uint16_t)(rng_next() & 0xffff);

    voleith_gf16_t *wit = NULL, *inst = NULL;
    size_t nwit = 0, ninst = 0;
    voleith_gf16_circuit_t *c =
        build_bound_circuit(perm, n, in_vals, &wit, &inst, &nwit, &ninst);

    /* Flip one control bit: output no longer matches the bound instance, so the
     * output-equality constraints fail (the network is still a permutation, but
     * the wrong one). */
    voleith_gf16_t saved = wit[n]; /* first control bit lives at index n */
    wit[n] ^= 0x0001;
    size_t nw = voleith_gf16_circuit_wire_count(c);
    voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));
    int ev = voleith_gf16_circuit_eval(c, wit, inst, vals);
    check("flipped control bit fails output binding", ev == 0);

    uint8_t fs_seed[16];
    memset(fs_seed, 0x33, sizeof(fs_seed));
    voleith_proof_t proof;
    int pret = voleith_gf16_prove(&proof, &voleith_params_em_128f, c, wit, inst,
                                  fs_seed, sizeof(fs_seed));
    check("prove rejects a flipped control bit", pret != 0);
    if (pret == 0)
        voleith_proof_free(&proof);
    wit[n] = saved;

    /* Non-{0,1} control value fails booleanity (assert_product(s,s,s)). */
    wit[n] = 0x0002;
    int ev2 = voleith_gf16_circuit_eval(c, wit, inst, vals);
    check("non-binary control value fails booleanity", ev2 == 0);
    wit[n] = saved;

    free(vals);
    free(perm);
    free(in_vals);
    free(wit);
    free(inst);
    voleith_gf16_circuit_free(c);
}

/*
 * Structural soundness: for ARBITRARY control bits (NOT produced by the router),
 * the network output must be a permutation of the input (every input value
 * appears exactly once).  This is the property that stops a cheating prover from
 * injecting or dropping a value; it must hold by construction (each switch
 * conserves its two values), independently of the routing algorithm.  Oracle:
 * multiset preservation with distinct inputs, checked here with random bits.
 */
static void
test_structural_permutation(void)
{
    const size_t sizes[] = {3, 4, 5, 8, 13, 48};
    int all = 1;
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        size_t s = voleith_perm_gf16_n_switches(n);

        voleith_gf16_circuit_t *c = voleith_gf16_circuit_new();
        gf16_wire_id *in = calloc(n, sizeof(gf16_wire_id));
        gf16_wire_id *ctrl = calloc(s ? s : 1, sizeof(gf16_wire_id));
        gf16_wire_id *out = calloc(n, sizeof(gf16_wire_id));
        for (size_t i = 0; i < n; i++)
            in[i] = voleith_gf16_add_instance(c);
        for (size_t i = 0; i < s; i++)
            ctrl[i] = voleith_gf16_add_witness(c);
        voleith_perm_gf16_circuit(c, in, ctrl, out, n);

        /* Distinct input values so "permutation" == "multiset preserved". */
        voleith_gf16_t *in_vals = calloc(n, sizeof(voleith_gf16_t));
        for (size_t i = 0; i < n; i++)
            in_vals[i] = (voleith_gf16_t)(i + 1); /* all distinct, nonzero */

        size_t nw = voleith_gf16_circuit_wire_count(c);
        voleith_gf16_t *vals = calloc(nw, sizeof(voleith_gf16_t));
        voleith_gf16_t *wit = calloc(s ? s : 1, sizeof(voleith_gf16_t));

        for (int trial = 0; trial < 16 && all; trial++) {
            /* RANDOM control bits, deliberately not the router's output. */
            for (size_t i = 0; i < s; i++)
                wit[i] = (voleith_gf16_t)(rng_next() & 1u);

            int ev = voleith_gf16_circuit_eval(c, wit, in_vals, vals);
            if (ev != 1) {
                all = 0;
                break;
            }
            /* Each input value 1..n must appear exactly once among outputs. */
            int *seen = calloc(n + 1, sizeof(int));
            for (size_t i = 0; i < n; i++) {
                voleith_gf16_t v = vals[out[i]];
                if (v < 1 || v > n || seen[v]) {
                    all = 0;
                    break;
                }
                seen[v] = 1;
            }
            free(seen);
        }

        free(in);
        free(ctrl);
        free(out);
        free(in_vals);
        free(vals);
        free(wit);
        voleith_gf16_circuit_free(c);
    }
    check("arbitrary control bits always yield a permutation (structural)",
          all);
}

/*
 * Software model of the AS-Waksman network: apply control bits to input values
 * exactly as build_block would, so we can validate a routing WITHOUT building
 * the ZK circuit (fast enough for exhaustive enumeration).  Switch semantics
 * mirror emit_switch: out0 = (s == 0) ? a : b; out1 = a XOR b XOR out0.
 */
static void
net_apply(const uint16_t *bits, size_t *k, const size_t *in, size_t *out,
          size_t n)
{
    if (n == 1) {
        out[0] = in[0];
        return;
    }
    if (n == 2) {
        uint16_t s = bits[(*k)++];
        size_t a = in[0], b = in[1];
        size_t o0 = s ? b : a;
        out[0] = o0;
        out[1] = a ^ b ^ o0;
        return;
    }

    size_t nin = n / 2, top_n = (n + 1) / 2, bot_n = n / 2;
    int odd = (int)(n & 1u);
    size_t *top_in = calloc(top_n, sizeof(size_t));
    size_t *bot_in = calloc(bot_n, sizeof(size_t));
    size_t *top_out = calloc(top_n, sizeof(size_t));
    size_t *bot_out = calloc(bot_n, sizeof(size_t));

    for (size_t p = 0; p < nin; p++) {
        uint16_t s = bits[(*k)++];
        size_t a = in[2 * p], b = in[2 * p + 1];
        size_t o0 = s ? b : a;
        top_in[p] = o0;
        bot_in[p] = a ^ b ^ o0;
    }
    if (odd)
        top_in[top_n - 1] = in[n - 1];

    net_apply(bits, k, top_in, top_out, top_n);
    net_apply(bits, k, bot_in, bot_out, bot_n);

    if (odd) {
        for (size_t q = 0; q < n / 2; q++) {
            uint16_t s = bits[(*k)++];
            size_t a = top_out[q], b = bot_out[q];
            size_t o0 = s ? b : a;
            out[2 * q] = o0;
            out[2 * q + 1] = a ^ b ^ o0;
        }
        out[n - 1] = top_out[top_n - 1];
    } else {
        out[0] = top_out[0];
        out[1] = bot_out[0];
        for (size_t q = 1; q < n / 2; q++) {
            uint16_t s = bits[(*k)++];
            size_t a = top_out[q], b = bot_out[q];
            size_t o0 = s ? b : a;
            out[2 * q] = o0;
            out[2 * q + 1] = a ^ b ^ o0;
        }
    }

    free(top_in);
    free(bot_in);
    free(top_out);
    free(bot_out);
}

/* Route perm (CT router, or reference oracle if use_reference), then apply the
 * bits through the software network on the identity vector.  Returns 1 iff all
 * S(n) bits are consumed and out[i] == perm[i] (i.e. out[i] == in[perm[i]]). */
static int
routes_ok(const size_t *perm, size_t n, int use_reference)
{
    size_t s = voleith_perm_gf16_n_switches(n);
    uint16_t *bits = calloc(s ? s : 1, sizeof(uint16_t));
    int rr = use_reference ? voleith_perm_gf16_route_reference(perm, n, bits)
                           : voleith_perm_gf16_route(perm, n, bits);
    if (rr != 0) {
        free(bits);
        return 0;
    }
    size_t *in = calloc(n, sizeof(size_t));
    size_t *out = calloc(n, sizeof(size_t));
    for (size_t i = 0; i < n; i++)
        in[i] = i;
    size_t k = 0;
    net_apply(bits, &k, in, out, n);
    int ok = (k == s);
    for (size_t i = 0; i < n && ok; i++)
        if (out[i] != perm[i])
            ok = 0;
    free(bits);
    free(in);
    free(out);
    return ok;
}

/* Recursively enumerate every permutation of perm[i..n-1]; return 0 on the
 * first routing that fails routes_ok (leaving perm in an arbitrary order). */
static int
enum_perms_ok(size_t *perm, size_t n, size_t i, int use_reference)
{
    if (i == n)
        return routes_ok(perm, n, use_reference);
    for (size_t j = i; j < n; j++) {
        size_t t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
        if (!enum_perms_ok(perm, n, i + 1, use_reference))
            return 0;
        t = perm[i];
        perm[i] = perm[j];
        perm[j] = t;
    }
    return 1;
}

/* Exhaustive: EVERY permutation of n = 2..8 routes correctly, for both the
 * constant-time router and the reference oracle.  This nails the odd/even
 * boundary logic (omitted switch, leftover wire) at the sizes where it lives. */
static void
test_route_exhaustive(void)
{
    int all_ct = 1, all_ref = 1;
    for (size_t n = 2; n <= 8; n++) {
        size_t *perm = calloc(n, sizeof(size_t));
        for (size_t i = 0; i < n; i++)
            perm[i] = i;
        if (!enum_perms_ok(perm, n, 0, 0))
            all_ct = 0;
        for (size_t i = 0; i < n; i++)
            perm[i] = i;
        if (!enum_perms_ok(perm, n, 0, 1))
            all_ref = 0;
        free(perm);
    }
    check("CT router: ALL permutations of n=2..8 route correctly", all_ct);
    check("reference router: ALL permutations of n=2..8 route correctly",
          all_ref);
}

/* Adversarial / degenerate perms across many sizes: identity, reversal,
 * rotation, a single long cycle (i+1 mod n), a constant shift, and a single
 * transposition.  Long cycles are the worst case for the coloring propagation. */
static void
test_route_adversarial(void)
{
    const size_t sizes[] = {2,  3,  4,  5,   7,   8,   15,  16,  17, 31,
                            48, 64, 65, 100, 127, 128, 129, 255, 256};
    int all = 1;
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        size_t *perm = calloc(n, sizeof(size_t));

        for (size_t i = 0; i < n; i++)
            perm[i] = i; /* identity */
        all &= routes_ok(perm, n, 0);

        for (size_t i = 0; i < n; i++)
            perm[i] = n - 1 - i; /* reversal */
        all &= routes_ok(perm, n, 0);

        for (size_t i = 0; i < n; i++)
            perm[i] = (i + 1) % n; /* single n-cycle */
        all &= routes_ok(perm, n, 0);

        for (size_t i = 0; i < n; i++)
            perm[i] = (i + n / 2) % n; /* constant shift */
        all &= routes_ok(perm, n, 0);

        for (size_t i = 0; i < n; i++)
            perm[i] = i;
        perm[0] = n - 1; /* single transposition */
        perm[n - 1] = 0;
        all &= routes_ok(perm, n, 0);

        free(perm);
    }
    check("CT router: adversarial permutations route correctly (many sizes)",
          all != 0);
}

/* Random cross-check up to n=256: both routers must independently produce a
 * routing that realizes the same permutation. */
static void
test_route_random_both(void)
{
    const size_t sizes[] = {9, 16, 31, 48, 64, 100, 128, 256};
    int all = 1;
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t n = sizes[si];
        size_t *perm = calloc(n, sizeof(size_t));
        for (int trial = 0; trial < 20; trial++) {
            random_perm(perm, n);
            all &= routes_ok(perm, n, 0); /* constant-time */
            all &= routes_ok(perm, n, 1); /* reference oracle */
        }
        free(perm);
    }
    check("CT and reference routers both realize random perms up to n=256",
          all != 0);
}

/* The oblivious input validator (F-1) must reject non-permutation tables:
 * an out-of-range entry and a duplicate entry, in addition to accepting a
 * valid one. */
static void
test_route_rejects_invalid(void)
{
    const size_t n = 8;
    size_t s = voleith_perm_gf16_n_switches(n);
    uint16_t *bits = calloc(s ? s : 1, sizeof(uint16_t));
    size_t *perm = calloc(n, sizeof(size_t));
    for (size_t i = 0; i < n; i++)
        perm[i] = i;

    check("route accepts a valid permutation",
          voleith_perm_gf16_route(perm, n, bits) == 0);

    size_t saved = perm[1];
    perm[1] = perm[0]; /* duplicate -> not a permutation */
    check("route rejects a duplicate entry",
          voleith_perm_gf16_route(perm, n, bits) != 0);
    perm[1] = saved;

    perm[1] = n; /* out of range (>= n) */
    check("route rejects an out-of-range entry",
          voleith_perm_gf16_route(perm, n, bits) != 0);

    free(perm);
    free(bits);
}

int
main(void)
{
    printf("=== GF(2^16) AS-Waksman permutation gadget (T7.5) ===\n");
    test_switch_counts();
    test_route_exhaustive();
    test_route_adversarial();
    test_route_rejects_invalid();
    test_route_random_both();
    test_route_eval();
    test_codec_crosscheck();
    test_prove_verify();
    test_tamper_and_booleanity();
    test_structural_permutation();
    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
