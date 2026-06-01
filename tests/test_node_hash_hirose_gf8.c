/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_node_hash_hirose_gf8.c - Tests for the Hirose iteration as a
 * GF(2^8) circuit.
 *
 * Tests:
 *   1: Structural gate accounting - one iteration costs exactly 500
 *      inv_in witness bytes and 1000 assert_product constraints,
 *      with zero mul gates and zero added instance wires (the
 *      iteration is pure AES-256 + linear glue).
 *   2: Witness-size accessor matches the #define.
 *   3: Circuit output equals the core/hirose.c software primitive
 *      for the (G, H, M, c) test triple - cross-checks that the
 *      KS-shared in-circuit emit produces the same bytes as the
 *      naive two-encrypt software form (the design's load-bearing
 *      equivalence).
 *   4: Chaining two iterations in-circuit produces the same
 *      (G2, H2) as chaining voleith_hirose_iteration twice - covers
 *      the inode shape (L as IV, R split across two iterations)
 *      without yet introducing the inode wrapper.
 *   5: Soundness smoke test - tampering one inv_in byte makes
 *      voleith_gf8_circuit_eval return 0 (constraint failure).
 *
 * Step 9.4 tests (vt-wrapper conformance):
 *   6: inv_in size accessors return the documented constants
 *      (fixed-32 leaf = 1000, inode = 1000, variable leaf =
 *      n_iter(len) x 500 for the {0, 1, 15, 16, 17, 32, 33, 64}
 *      table).
 *   7: Fixed-32 leaf circuit matches its software helper.
 *   8: Variable leaf circuit matches its software helper for a
 *      range of len values, including len=16 (aligned + always-pad).
 *   9: Inode circuit matches its software helper.
 *   10: Domain separation - the three constructions produce distinct
 *       outputs on equivalent inputs (fixed_leaf(x) != inode(x_lo,
 *       x_hi); variable_leaf(x) != inode(x_lo, x_hi);
 *       fixed_leaf(x) != variable_leaf(x)).
 *   11: Variable-leaf 10* always-pad - aligned input gets the extra
 *       block (n_iter(16) = 2; output differs from a hypothetical
 *       1-block hash); appending 0x80 to (n-1)-byte input matches
 *       n-byte input only if the n-byte input itself doesn't already
 *       end in 0x80 followed by all zeros (sanity check).
 *   12: vt instance fields agree with the documented values
 *       (node_bytes=32, cr_bits=128, name set, function pointers
 *       non-NULL).
 *   13: vt function pointers dispatch to the right implementation
 *       (calling through the vt produces the same bytes as calling
 *       the underlying functions directly).
 */

#include "../circuits/node_hash_hirose_gf8.h"
#include "../circuits/node_hash_vt.h"
#include "../core/hirose.h"
#include "../proof/gf8_circuit.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* Wraps a (possibly fallible) call so the function is ALWAYS evaluated,
 * even when NDEBUG elides assert().  `assert(fn(...) == 0)` would drop
 * the call entirely under -DNDEBUG (Release builds), leaving setup
 * outputs uninitialised. */
#define MUST_OK(expr)                                                          \
    do {                                                                       \
        int _rc_ = (expr);                                                     \
        (void)_rc_;                                                            \
        assert(_rc_ == 0);                                                     \
    } while (0)

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

/* Shared test inputs. */
static const uint8_t G_IN[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
                                 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
                                 0xcc, 0xdd, 0xee, 0xff};
static const uint8_t H_IN[16] = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
                                 0x32, 0x10, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
static const uint8_t M_IN[16] = {0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe,
                                 0xba, 0xbe, 0x01, 0x23, 0x45, 0x67,
                                 0x89, 0xab, 0xcd, 0xef};
static const uint8_t C_IN[16] = {'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
                                 'H', 'i', 'r', 'o', 's', 'e', '-', 'N'};

/* Build a circuit with all four 16-byte inputs declared as witness
 * wires, then emit one Hirose iteration.  Returns the circuit and the
 * output wire IDs. */
static voleith_gf8_circuit_t *
build_one_iter_circuit(gf8_wire_id G_w[16], gf8_wire_id H_w[16],
                       gf8_wire_id M_w[16], const uint8_t c_const[16],
                       gf8_wire_id G_out[16], gf8_wire_id H_out[16])
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        G_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        H_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        M_w[i] = voleith_gf8_add_witness(c);
    hirose_gf8_iteration_circuit(c, G_w, H_w, M_w, c_const, G_out, H_out);
    return c;
}

static void
test_structural_counts(void)
{
    gf8_wire_id G_w[16], H_w[16], M_w[16], G_out[16], H_out[16];
    voleith_gf8_circuit_t *c =
        build_one_iter_circuit(G_w, H_w, M_w, C_IN, G_out, H_out);

    /* 48 external (16 G + 16 H + 16 M) + 500 inv_in. */
    check("Hirose 1 iter: witness_count = 548",
          voleith_gf8_circuit_witness_count(c) == 48 + 500);
    /* All mul-bearing work goes through assert_product, never add_mul. */
    check("Hirose 1 iter: mul_count = 0",
          voleith_gf8_circuit_mul_count(c) == 0);
    /* 2 asserts per S-box, 500 S-boxes -> 1000. */
    check("Hirose 1 iter: assert_product_count = 1000",
          voleith_gf8_circuit_assert_product_count(c) == 1000);
    check("Hirose 1 iter: ell = 548", voleith_gf8_qs_ell(c) == 48 + 500);

    voleith_gf8_circuit_free(c);
}

static void
test_witness_bytes_accessor(void)
{
    check("hirose_gf8_iteration_witness_bytes() == 500",
          hirose_gf8_iteration_witness_bytes() ==
              HIROSE_GF8_ITERATION_WITNESS_BYTES);
    check("HIROSE_GF8_ITERATION_WITNESS_BYTES == 500",
          HIROSE_GF8_ITERATION_WITNESS_BYTES == 500);
}

static void
test_circuit_matches_software_oracle(void)
{
    gf8_wire_id G_w[16], H_w[16], M_w[16], G_out_w[16], H_out_w[16];
    voleith_gf8_circuit_t *c =
        build_one_iter_circuit(G_w, H_w, M_w, C_IN, G_out_w, H_out_w);

    /* Witness = G || H || M || iteration inv_in. */
    uint8_t witness[48 + 500];
    memcpy(witness + 0, G_IN, 16);
    memcpy(witness + 16, H_IN, 16);
    memcpy(witness + 32, M_IN, 16);
    hirose_gf8_iteration_build_witness(G_IN, H_IN, M_IN, C_IN, witness + 48,
                                       NULL, NULL);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("Hirose 1 iter: all constraints satisfied with valid witness",
          ok == 1);

    /* Read out circuit-computed outputs. */
    uint8_t G_circuit[16], H_circuit[16];
    for (int i = 0; i < 16; i++) {
        G_circuit[i] = vals[G_out_w[i]];
        H_circuit[i] = vals[H_out_w[i]];
    }

    /* Independent software oracle from core/hirose.c. */
    uint8_t G_sw[16], H_sw[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_sw, H_sw);

    check("Hirose 1 iter: G_out (KS-shared circuit) == G_out (naive sw)",
          memcmp(G_circuit, G_sw, 16) == 0);
    check("Hirose 1 iter: H_out (KS-shared circuit) == H_out (naive sw)",
          memcmp(H_circuit, H_sw, 16) == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* Two-iteration chain matches a software 2-iter chain - models the
 * inode shape without committing yet to the inode constants. */
static void
test_two_iter_chain(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    /* External wires: (G0, H0), then two M blocks (R0, R1). */
    gf8_wire_id G0[16], H0[16], R0[16], R1[16];
    for (int i = 0; i < 16; i++)
        G0[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        H0[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        R0[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        R1[i] = voleith_gf8_add_witness(c);

    gf8_wire_id G1[16], H1[16], G2_w[16], H2_w[16];
    hirose_gf8_iteration_circuit(c, G0, H0, R0, C_IN, G1, H1);
    hirose_gf8_iteration_circuit(c, G1, H1, R1, C_IN, G2_w, H2_w);

    /* Two iterations cost 2 * (48 + 500 wires)... no wait, only the
     * inv_in slots accumulate; (G1,H1) are derived from existing
     * wires, not new witnesses.  So external = 64, inv_in = 1000. */
    check("Hirose 2 iter chain: witness_count = 64 + 1000 = 1064",
          voleith_gf8_circuit_witness_count(c) == 64 + 1000);
    check("Hirose 2 iter chain: assert_product_count = 2000",
          voleith_gf8_circuit_assert_product_count(c) == 2000);

    /* Test inputs for the two-iter chain (re-use existing constants). */
    const uint8_t G_a[16] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
                             0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01};
    const uint8_t H_a[16] = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                             0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20};

    /* Witness layout: 64 external bytes, then iter-1's 500, then iter-2's 500. */
    uint8_t witness[64 + 1000];
    memcpy(witness + 0, G_a, 16);
    memcpy(witness + 16, H_a, 16);
    memcpy(witness + 32, G_IN, 16); /* re-use as R0 */
    memcpy(witness + 48, M_IN, 16); /* re-use as R1 */

    /* Iter 1: compute (G1, H1) and its inv_in. */
    uint8_t G1_b[16], H1_b[16];
    hirose_gf8_iteration_build_witness(G_a, H_a, G_IN, C_IN, witness + 64, G1_b,
                                       H1_b);
    /* Iter 2: compute its inv_in (and the expected final output). */
    uint8_t G2_b[16], H2_b[16];
    hirose_gf8_iteration_build_witness(G1_b, H1_b, M_IN, C_IN,
                                       witness + 64 + 500, G2_b, H2_b);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("Hirose 2 iter chain: constraints satisfied", ok == 1);

    /* Software reference: two voleith_hirose_iteration calls. */
    uint8_t G_sw1[16], H_sw1[16], G_sw2[16], H_sw2[16];
    voleith_hirose_iteration(G_a, H_a, G_IN, C_IN, G_sw1, H_sw1);
    voleith_hirose_iteration(G_sw1, H_sw1, M_IN, C_IN, G_sw2, H_sw2);

    uint8_t G_circuit[16], H_circuit[16];
    for (int i = 0; i < 16; i++) {
        G_circuit[i] = vals[G2_w[i]];
        H_circuit[i] = vals[H2_w[i]];
    }

    check("Hirose 2 iter chain: G2 matches sw oracle",
          memcmp(G_circuit, G_sw2, 16) == 0);
    check("Hirose 2 iter chain: H2 matches sw oracle",
          memcmp(H_circuit, H_sw2, 16) == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* The leaf/inode wrappers depend on hirose_gf8_iteration_circuit
 * supporting in-place chaining:
 *   hirose_gf8_iteration_circuit(c, G, H, M, k, G, H);
 * If aliasing G_out with G ever regresses, every wrapper's
 * software-vs-circuit equality test fails.  Lock that contract in
 * with its own regression case so a future refactor sees the
 * dependency explicitly rather than via the wrapper fallout. */
static void
test_iteration_in_place_aliasing(void)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id G[16], H[16], M[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        M[i] = voleith_gf8_add_witness(c);

    /* Snapshot the original input wire IDs so we can read them out
     * after the in-place call (which overwrites G and H). */
    gf8_wire_id G_in[16], H_in[16];
    for (int i = 0; i < 16; i++) {
        G_in[i] = G[i];
        H_in[i] = H[i];
    }

    /* Emit one iteration with G_out aliasing G and H_out aliasing H. */
    hirose_gf8_iteration_circuit(c, G, H, M, C_IN, G, H);

    uint8_t witness[48 + 500];
    memcpy(witness + 0, G_IN, 16);
    memcpy(witness + 16, H_IN, 16);
    memcpy(witness + 32, M_IN, 16);
    hirose_gf8_iteration_build_witness(G_IN, H_IN, M_IN, C_IN, witness + 48,
                                       NULL, NULL);

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("aliased iteration: constraints satisfied", ok == 1);

    uint8_t G_out[16], H_out[16];
    for (int i = 0; i < 16; i++) {
        G_out[i] = vals[G[i]];
        H_out[i] = vals[H[i]];
    }
    /* G and H array slots now hold the OUTPUT wire IDs.  Verify the
     * original input wires (snapshotted in G_in, H_in) still carry
     * the witness values - the in-place semantic is purely about
     * the wire-ID array, not about the wire-value array. */
    for (int i = 0; i < 16; i++) {
        if (vals[G_in[i]] != G_IN[i] || vals[H_in[i]] != H_IN[i]) {
            check("aliased iteration: input wires preserved", 0);
            goto done;
        }
    }
    check("aliased iteration: input wires preserved", 1);

    uint8_t G_sw[16], H_sw[16];
    voleith_hirose_iteration(G_IN, H_IN, M_IN, C_IN, G_sw, H_sw);
    check("aliased iteration: output matches software oracle",
          memcmp(G_out, G_sw, 16) == 0 && memcmp(H_out, H_sw, 16) == 0);

done:
    free(vals);
    voleith_gf8_circuit_free(c);
}

static void
test_tamper_breaks_constraints(void)
{
    gf8_wire_id G_w[16], H_w[16], M_w[16], G_out[16], H_out[16];
    voleith_gf8_circuit_t *c =
        build_one_iter_circuit(G_w, H_w, M_w, C_IN, G_out, H_out);

    uint8_t witness[48 + 500];
    memcpy(witness + 0, G_IN, 16);
    memcpy(witness + 16, H_IN, 16);
    memcpy(witness + 32, M_IN, 16);
    hirose_gf8_iteration_build_witness(G_IN, H_IN, M_IN, C_IN, witness + 48,
                                       NULL, NULL);

    /* Flip one bit in the first KS inv_in slot. */
    witness[48] ^= 0x01;

    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("Hirose 1 iter: tampered inv_in rejected by constraints", ok == 0);

    free(vals);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Step 9.4: vt-wrapper conformance tests
 * ================================================================ */

/* Evaluate a leaf or inode circuit and return the 32-byte node
 * output.  Witness is allocated/freed by the caller. */
static void
eval_node_circuit(voleith_gf8_circuit_t *c, const uint8_t *witness,
                  const gf8_wire_id out_w[32], uint8_t out[32])
{
    size_t n = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    check("circuit eval: constraints satisfied with valid witness", ok == 1);
    for (int i = 0; i < 32; i++)
        out[i] = vals[out_w[i]];
    free(vals);
}

static void
test_invin_size_accessors(void)
{
    check("fixed-32 leaf invin = 1000",
          merkle_hirose_gf8_fixed32_leaf_invin_bytes(32) == 1000);
    check("inode invin = 1000", merkle_hirose_gf8_inode_invin_bytes() == 1000);

    /* 10* always-pad: n_iter = (len + 16) / 16 */
    const struct {
        size_t len;
        size_t n_iter;
    } cases[] = {
        {0, 1}, {1, 1}, {15, 1}, {16, 2}, {17, 2}, {32, 3}, {33, 3}, {64, 5},
    };
    for (size_t k = 0; k < sizeof(cases) / sizeof(cases[0]); k++) {
        size_t want = cases[k].n_iter * 500;
        size_t got = merkle_hirose_gf8_variable_leaf_invin_bytes(cases[k].len);
        char name[64];
        snprintf(name, sizeof(name),
                 "variable leaf invin(len=%zu) = %zu (n_iter=%zu)",
                 cases[k].len, want, cases[k].n_iter);
        check(name, got == want);
    }
}

static void
test_fixed32_leaf_circuit_matches_software(void)
{
    const uint8_t LEAF[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id leaf_w[32], out_w[32];
    for (int i = 0; i < 32; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);
    merkle_hirose_gf8_fixed32_leaf_circuit(c, leaf_w, 32, out_w);

    /* witness = leaf data || 1000 inv_in */
    uint8_t witness[32 + 1000];
    memcpy(witness, LEAF, 32);
    MUST_OK(
        merkle_hirose_gf8_fixed32_leaf_build_witness(LEAF, 32, witness + 32));

    uint8_t circuit_out[32];
    eval_node_circuit(c, witness, out_w, circuit_out);

    uint8_t sw_out[32];
    MUST_OK(merkle_hirose_fixed32_leaf_hash(LEAF, 32, sw_out));
    check("fixed-32 leaf: circuit == software helper",
          memcmp(circuit_out, sw_out, 32) == 0);

    voleith_gf8_circuit_free(c);
}

static void
test_inode_circuit_matches_software(void)
{
    const uint8_t L[32] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff, 0x00, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
        0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    const uint8_t R[32] = {
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x23, 0x45,
        0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id L_w[32], R_w[32], out_w[32];
    for (int i = 0; i < 32; i++)
        L_w[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 32; i++)
        R_w[i] = voleith_gf8_add_witness(c);
    merkle_hirose_gf8_inode_circuit(c, L_w, R_w, out_w);

    uint8_t witness[64 + 1000];
    memcpy(witness + 0, L, 32);
    memcpy(witness + 32, R, 32);
    MUST_OK(merkle_hirose_gf8_inode_build_witness(L, R, witness + 64));

    uint8_t circuit_out[32];
    eval_node_circuit(c, witness, out_w, circuit_out);

    uint8_t sw_out[32];
    MUST_OK(merkle_hirose_inode_hash(L, R, sw_out));
    check("inode: circuit == software helper",
          memcmp(circuit_out, sw_out, 32) == 0);

    voleith_gf8_circuit_free(c);
}

/* Build a variable-leaf circuit on len bytes of data, evaluate, and
 * return the output. */
static void
eval_variable_leaf(const uint8_t *data, size_t len, uint8_t out[32])
{
    size_t n_iter = (len + 16) / 16;
    size_t invin_bytes = n_iter * 500;

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *leaf_w = NULL;
    if (len > 0) {
        leaf_w = malloc(len * sizeof(gf8_wire_id));
        for (size_t i = 0; i < len; i++)
            leaf_w[i] = voleith_gf8_add_witness(c);
    }
    gf8_wire_id out_w[32];
    merkle_hirose_gf8_variable_leaf_circuit(c, leaf_w, len, out_w);

    uint8_t *witness = malloc(len + invin_bytes);
    if (len > 0)
        memcpy(witness, data, len);
    MUST_OK(merkle_hirose_gf8_variable_leaf_build_witness(data, len,
                                                          witness + len));

    eval_node_circuit(c, witness, out_w, out);

    free(witness);
    free(leaf_w);
    voleith_gf8_circuit_free(c);
}

static void
test_variable_leaf_circuit_matches_software(void)
{
    const uint8_t DATA[64] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
        0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5,
        0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
        0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
        0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6,
        0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
    };
    const size_t lens[] = {0, 1, 15, 16, 17, 32, 33, 64};
    for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        uint8_t circuit_out[32], sw_out[32];
        eval_variable_leaf(DATA, lens[k], circuit_out);
        MUST_OK(merkle_hirose_variable_leaf_hash(DATA, lens[k], sw_out));
        char name[80];
        snprintf(name, sizeof(name),
                 "variable leaf (len=%zu): circuit == software helper",
                 lens[k]);
        check(name, memcmp(circuit_out, sw_out, 32) == 0);
    }
}

static void
test_domain_separation(void)
{
    /* Use a 32-byte buffer x; treat as a leaf input or as L||R split
     * for the inode. */
    const uint8_t X[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };

    /* For the inode comparison, use L = R = X.  An adversarial
     * inode input that maximizes the chance of accidental collision
     * with the leaf hashes (same bytes feeding both the chain and
     * the message); if even this distinguishes, distinct values
     * surely do. */
    uint8_t fixed_leaf_out[32], variable_leaf_out[32], inode_out[32];
    MUST_OK(merkle_hirose_fixed32_leaf_hash(X, 32, fixed_leaf_out));
    MUST_OK(merkle_hirose_variable_leaf_hash(X, 32, variable_leaf_out));
    MUST_OK(merkle_hirose_inode_hash(X, X, inode_out));

    check("domain sep: fixed32_leaf(x) != inode(x, x)",
          memcmp(fixed_leaf_out, inode_out, 32) != 0);
    check("domain sep: variable_leaf(x) != inode(x, x)",
          memcmp(variable_leaf_out, inode_out, 32) != 0);
    check("domain sep: fixed32_leaf(x) != variable_leaf(x)",
          memcmp(fixed_leaf_out, variable_leaf_out, 32) != 0);
}

static void
test_variable_leaf_always_pad(void)
{
    /* 16-byte aligned input must take 2 iterations and produce a
     * value distinct from any 1-iteration shortcut.  The cleanest
     * external check: variable_leaf(0-byte input) and
     * variable_leaf(16 zero bytes) both go through the always-pad
     * rule but at 1 and 2 iterations respectively, so they MUST
     * differ. */
    uint8_t out_empty[32], out_16zero[32];
    const uint8_t ZERO16[16] = {0};
    MUST_OK(merkle_hirose_variable_leaf_hash(NULL, 0, out_empty));
    MUST_OK(merkle_hirose_variable_leaf_hash(ZERO16, 16, out_16zero));
    check("variable leaf always-pad: hash() != hash(0x00 * 16)",
          memcmp(out_empty, out_16zero, 32) != 0);

    /* invin_bytes for len=16 confirms 2 iterations were allocated. */
    check("variable leaf always-pad: len=16 -> 2 iter (1000 invin)",
          merkle_hirose_gf8_variable_leaf_invin_bytes(16) == 1000);
}

static void
test_vt_instance_fields(void)
{
    /* fixed-32 vt */
    check("vt fixed32: name set",
          voleith_node_hash_hirose_fixed32.name != NULL);
    check("vt fixed32: node_bytes = 32",
          voleith_node_hash_hirose_fixed32.node_bytes == 32);
    check("vt fixed32: cr_bits = 128",
          voleith_node_hash_hirose_fixed32.cr_bits == 128);
    check("vt fixed32: function pointers non-NULL",
          voleith_node_hash_hirose_fixed32.leaf_invin_bytes != NULL &&
              voleith_node_hash_hirose_fixed32.inode_invin_bytes != NULL &&
              voleith_node_hash_hirose_fixed32.leaf_circuit != NULL &&
              voleith_node_hash_hirose_fixed32.inode_circuit != NULL &&
              voleith_node_hash_hirose_fixed32.leaf_build_witness != NULL &&
              voleith_node_hash_hirose_fixed32.inode_build_witness != NULL &&
              voleith_node_hash_hirose_fixed32.leaf_hash != NULL &&
              voleith_node_hash_hirose_fixed32.inode_hash != NULL);

    /* variable vt */
    check("vt variable: name set", voleith_node_hash_hirose.name != NULL);
    check("vt variable: node_bytes = 32",
          voleith_node_hash_hirose.node_bytes == 32);
    check("vt variable: cr_bits = 128",
          voleith_node_hash_hirose.cr_bits == 128);
    check("vt variable: function pointers non-NULL",
          voleith_node_hash_hirose.leaf_invin_bytes != NULL &&
              voleith_node_hash_hirose.inode_invin_bytes != NULL &&
              voleith_node_hash_hirose.leaf_circuit != NULL &&
              voleith_node_hash_hirose.inode_circuit != NULL &&
              voleith_node_hash_hirose.leaf_build_witness != NULL &&
              voleith_node_hash_hirose.inode_build_witness != NULL &&
              voleith_node_hash_hirose.leaf_hash != NULL &&
              voleith_node_hash_hirose.inode_hash != NULL);

    /* Shared inode dispatch: both vts must point inode_* at the
     * same implementation (no padding ambiguity at inode level). */
    check("vt: both vts share inode_circuit",
          voleith_node_hash_hirose.inode_circuit ==
              voleith_node_hash_hirose_fixed32.inode_circuit);
    check("vt: both vts share inode_build_witness",
          voleith_node_hash_hirose.inode_build_witness ==
              voleith_node_hash_hirose_fixed32.inode_build_witness);
    check("vt: both vts share inode_hash",
          voleith_node_hash_hirose.inode_hash ==
              voleith_node_hash_hirose_fixed32.inode_hash);

    /* Leaf dispatch must differ between the two vts. */
    check("vt: fixed32 and variable have distinct leaf_hash",
          voleith_node_hash_hirose.leaf_hash !=
              voleith_node_hash_hirose_fixed32.leaf_hash);
}

static void
test_vt_dispatch(void)
{
    const uint8_t LEAF[32] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                              0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                              0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                              0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    /* Calling through the vt must agree with the direct call. */
    uint8_t direct[32], via_vt[32];

    MUST_OK(merkle_hirose_fixed32_leaf_hash(LEAF, 32, direct));
    MUST_OK(voleith_node_hash_hirose_fixed32.leaf_hash(LEAF, 32, via_vt));
    check("vt dispatch: fixed32 leaf_hash matches direct call",
          memcmp(direct, via_vt, 32) == 0);

    MUST_OK(merkle_hirose_variable_leaf_hash(LEAF, 32, direct));
    MUST_OK(voleith_node_hash_hirose.leaf_hash(LEAF, 32, via_vt));
    check("vt dispatch: variable leaf_hash matches direct call",
          memcmp(direct, via_vt, 32) == 0);

    MUST_OK(merkle_hirose_inode_hash(LEAF, LEAF, direct));
    MUST_OK(voleith_node_hash_hirose.inode_hash(LEAF, LEAF, via_vt));
    check("vt dispatch: inode_hash matches direct call",
          memcmp(direct, via_vt, 32) == 0);
}

int
main(void)
{
    printf("test_node_hash_hirose_gf8: Hirose iteration GF(2^8) circuit\n");

    test_structural_counts();
    test_witness_bytes_accessor();
    test_circuit_matches_software_oracle();
    test_two_iter_chain();
    test_iteration_in_place_aliasing();
    test_tamper_breaks_constraints();

    /* Step 9.4 conformance. */
    test_invin_size_accessors();
    test_fixed32_leaf_circuit_matches_software();
    test_inode_circuit_matches_software();
    test_variable_leaf_circuit_matches_software();
    test_domain_separation();
    test_variable_leaf_always_pad();
    test_vt_instance_fields();
    test_vt_dispatch();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
