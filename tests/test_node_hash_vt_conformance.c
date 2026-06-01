/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_node_hash_vt_conformance.c - Branch D conformance suite.
 *
 * Parameterised suite that runs against EVERY voleith_node_hash_vt
 * uniformly (Hirose ×2, AES ×2, Grøstl ×4 = 8 vts).  Per
 * docs/HASH_AGNOSTIC_MERKLE_DESIGN.md §8.1, each vt must pass:
 *
 *   - node_bytes and cr_bits match documented values
 *   - all 8 function-pointer slots non-NULL
 *   - inode_invin_bytes() matches what inode_circuit emits
 *   - leaf_invin_bytes(N) matches what leaf_circuit emits, at
 *     representative N in {0, 1, 16, 32, 64, 128}
 *   - in-circuit leaf_circuit  ==  software leaf_hash
 *   - in-circuit inode_circuit ==  software inode_hash
 *   - domain separation: leaf_hash(x) != inode_hash(x_lo, x_hi)
 *   - depth-3 e2e via merkle_vt_gf8_path_circuit{,_secret_dir}
 *   - depth-3 e2e via merkle_vt_gf8_indexed_nonmember_circuit{,_secret_dir}
 *   - tamper: corrupt one leaf inv_in byte after path e2e -> rejected
 *   - secret-dir booleanity: a non-{0,1} direction wire is rejected
 *     by the in-circuit assert_product(dir, dir, dir)
 *
 * For the 6 wrapped families (AES + Grøstl) the equivalence harness
 * already proves vt + generic ≡ fixed-hash; the conformance suite
 * keeps that coverage but also closes the Hirose ⏳ rows of the
 * completeness matrix - Hirose has no fixed-hash entry to
 * equivalence-test against, but the conformance suite runs the same
 * generic-path / generic-indexed code over the Hirose vts.
 */

#include "merkle_vt_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "../proof/gf8_circuit.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define DEPTH 3
#define N_LEAVES (1u << DEPTH)
/*
 * 32-byte leaves chosen so the same value satisfies every vt's
 * contract uniformly:
 *   - voleith_node_hash_hirose_fixed32 REQUIRES leaf_data_bytes == 32
 *     (the circuit reads leaf_data[0..31] regardless of the passed-in
 *     size argument), so a 16-byte test input would dereference past
 *     a 16-element wire array.  32 is the only safe choice for that
 *     vt, and works fine for every other vt.
 *   - Every variable-leaf vt handles 32 bytes (1+ compression block).
 */
#define LEAF_DATA_BYTES 32u

static int total_tests = 0;
static int total_pass = 0;

static void
check(const char *what, int cond)
{
    total_tests++;
    if (cond) {
        total_pass++;
    } else {
        printf("    FAIL: %s\n", what);
    }
}

/* ================================================================
 * Vt table: every shipped vt + its documented attributes.
 * ================================================================ */

typedef struct {
    const char *label;
    const voleith_node_hash_vt *vt;
    size_t exp_node_bytes;
    size_t exp_cr_bits;
    /*
     * Per-vt list of valid leaf_data_bytes values for the
     * leaf_invin_bytes(N) sweep.  Most vts accept any non-negative N;
     * voleith_node_hash_hirose_fixed32 hard-requires N == 32 (the
     * circuit reads 32 bytes regardless), so its sweep is just {32}.
     */
    const size_t *valid_leaf_sizes;
    size_t n_valid_leaf_sizes;
    /*
     * Whether to run the indexed-non-member e2e check for this vt.
     * The indexed test uses a 3-byte leaf record (target_bytes=1,
     * index_bytes=1).  Fixed-leaf-size vts (only fixed32 today) can
     * not accept that, so we skip them - they're meant for naturally
     * fixed-size leaves (ledger transaction commitments), not the
     * structured leaf records the indexed Merkle protocol uses.  The
     * generic indexed circuit body itself is still exercised by the
     * 7 variable-leaf vts.
     */
    int supports_indexed;
} vt_case_t;

static const size_t LEAF_SIZES_VARIABLE[] = {0, 1, 16, 32, 64, 128};
static const size_t LEAF_SIZES_FIXED32[] = {32};
#define N_LEAF_SIZES_VARIABLE                                                  \
    (sizeof(LEAF_SIZES_VARIABLE) / sizeof(LEAF_SIZES_VARIABLE[0]))
#define N_LEAF_SIZES_FIXED32                                                   \
    (sizeof(LEAF_SIZES_FIXED32) / sizeof(LEAF_SIZES_FIXED32[0]))

static const vt_case_t CASES[] = {
    {"hirose-aes-256", &voleith_node_hash_hirose, 32, 128, LEAF_SIZES_VARIABLE,
     N_LEAF_SIZES_VARIABLE, 1},
    {"hirose-aes-256-fixed32", &voleith_node_hash_hirose_fixed32, 32, 128,
     LEAF_SIZES_FIXED32, N_LEAF_SIZES_FIXED32, 0},
    {"aes-dm", &voleith_node_hash_aes_dm, 16, 64, LEAF_SIZES_VARIABLE,
     N_LEAF_SIZES_VARIABLE, 1},
    {"aes-cmac128", &voleith_node_hash_aes_cmac128, 16, 64, LEAF_SIZES_VARIABLE,
     N_LEAF_SIZES_VARIABLE, 1},
    {"grostl256", &voleith_node_hash_grostl256, 32, 128, LEAF_SIZES_VARIABLE,
     N_LEAF_SIZES_VARIABLE, 1},
    {"grostl256_t27", &voleith_node_hash_grostl256_t27, 27, 108,
     LEAF_SIZES_VARIABLE, N_LEAF_SIZES_VARIABLE, 1},
    {"grostl512", &voleith_node_hash_grostl512, 64, 256, LEAF_SIZES_VARIABLE,
     N_LEAF_SIZES_VARIABLE, 1},
    {"grostl512_t59", &voleith_node_hash_grostl512_t59, 59, 236,
     LEAF_SIZES_VARIABLE, N_LEAF_SIZES_VARIABLE, 1},
};
#define N_CASES (sizeof(CASES) / sizeof(CASES[0]))

/* Widest node currently shipped (Grøstl-512). */
#define MAX_NODE_BYTES 64

/* ================================================================
 * 1. Attribute conformance.
 * ================================================================ */

static void
check_attributes(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    char name[128];

    snprintf(name, sizeof(name), "[%s] name set", cs->label);
    check(name, h->name != NULL);

    snprintf(name, sizeof(name), "[%s] node_bytes == %zu", cs->label,
             cs->exp_node_bytes);
    check(name, h->node_bytes == cs->exp_node_bytes);

    snprintf(name, sizeof(name), "[%s] cr_bits == %zu", cs->label,
             cs->exp_cr_bits);
    check(name, h->cr_bits == cs->exp_cr_bits);

    snprintf(name, sizeof(name), "[%s] all 8 fn ptrs non-NULL", cs->label);
    check(name, h->leaf_invin_bytes != NULL && h->inode_invin_bytes != NULL &&
                    h->leaf_circuit != NULL && h->inode_circuit != NULL &&
                    h->leaf_build_witness != NULL &&
                    h->inode_build_witness != NULL && h->leaf_hash != NULL &&
                    h->inode_hash != NULL);
}

/* ================================================================
 * 2. inode_invin_bytes / leaf_invin_bytes sizing matches what the
 * matching circuit emits.
 *
 * Build a circuit that consists of ONLY the leaf (or inode) circuit
 * over caller-declared external wires; the witness_count delta after
 * the call must equal the *_invin_bytes() accessor.  This is the
 * structural correctness invariant: the witness builder produces
 * exactly as many bytes as the circuit consumes.
 * ================================================================ */

static size_t
witness_delta_leaf(const voleith_node_hash_vt *h, size_t leaf_data_bytes)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id *leaf =
        leaf_data_bytes ? calloc(leaf_data_bytes, sizeof(gf8_wire_id)) : NULL;
    for (size_t i = 0; i < leaf_data_bytes; i++)
        leaf[i] = voleith_gf8_add_witness(c);
    size_t before = voleith_gf8_circuit_witness_count(c);

    gf8_wire_id out[MAX_NODE_BYTES];
    h->leaf_circuit(c, leaf, leaf_data_bytes, out);
    size_t after = voleith_gf8_circuit_witness_count(c);

    free(leaf);
    voleith_gf8_circuit_free(c);
    return after - before;
}

static size_t
witness_delta_inode(const voleith_node_hash_vt *h)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id left[MAX_NODE_BYTES], right[MAX_NODE_BYTES];
    for (size_t i = 0; i < h->node_bytes; i++) {
        left[i] = voleith_gf8_add_witness(c);
        right[i] = voleith_gf8_add_witness(c);
    }
    size_t before = voleith_gf8_circuit_witness_count(c);

    gf8_wire_id out[MAX_NODE_BYTES];
    h->inode_circuit(c, left, right, out);
    size_t after = voleith_gf8_circuit_witness_count(c);

    voleith_gf8_circuit_free(c);
    return after - before;
}

static void
check_invin_sizing(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    char name[160];

    /* inode_invin_bytes() == witness slots emitted by inode_circuit. */
    size_t inode_emitted = witness_delta_inode(h);
    snprintf(name, sizeof(name),
             "[%s] inode_invin_bytes()=%zu matches inode_circuit emit=%zu",
             cs->label, h->inode_invin_bytes(), inode_emitted);
    check(name, h->inode_invin_bytes() == inode_emitted);

    /* leaf_invin_bytes(N) sweep at the vt's valid N values. */
    for (size_t k = 0; k < cs->n_valid_leaf_sizes; k++) {
        size_t N = cs->valid_leaf_sizes[k];
        size_t reported = h->leaf_invin_bytes(N);
        size_t emitted = witness_delta_leaf(h, N);
        snprintf(
            name, sizeof(name),
            "[%s] leaf_invin_bytes(N=%zu)=%zu matches leaf_circuit emit=%zu",
            cs->label, N, reported, emitted);
        check(name, reported == emitted);
    }
}

/* ================================================================
 * 3. In-circuit leaf_circuit / inode_circuit equal the software
 * leaf_hash / inode_hash through the vt.
 * ================================================================ */

static void
eval_and_extract(voleith_gf8_circuit_t *c, const uint8_t *witness,
                 size_t witness_bytes, const gf8_wire_id *root_wires,
                 size_t root_count, uint8_t *root_out)
{
    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(nW > 0 ? nW : 1, 1);
    (void)witness_bytes;
    voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    for (size_t i = 0; i < root_count; i++)
        root_out[i] = wire_vals[root_wires[i]];
    free(wire_vals);
}

static void
check_leaf_circuit_matches_sw(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    uint8_t data[LEAF_DATA_BYTES];
    for (size_t i = 0; i < LEAF_DATA_BYTES; i++)
        data[i] = (uint8_t)(0xA0 + i);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id leaf_w[LEAF_DATA_BYTES];
    for (size_t i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);
    gf8_wire_id out_w[MAX_NODE_BYTES];
    h->leaf_circuit(c, leaf_w, LEAF_DATA_BYTES, out_w);

    size_t inv = h->leaf_invin_bytes(LEAF_DATA_BYTES);
    uint8_t *witness = calloc(LEAF_DATA_BYTES + inv, 1);
    memcpy(witness, data, LEAF_DATA_BYTES);
    MUST_OK(h->leaf_build_witness(data, LEAF_DATA_BYTES,
                                  witness + LEAF_DATA_BYTES));

    uint8_t circ_out[MAX_NODE_BYTES];
    eval_and_extract(c, witness, LEAF_DATA_BYTES + inv, out_w, h->node_bytes,
                     circ_out);

    uint8_t sw_out[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(data, LEAF_DATA_BYTES, sw_out));

    char name[160];
    snprintf(name, sizeof(name), "[%s] leaf: circuit == sw helper", cs->label);
    check(name, memcmp(circ_out, sw_out, h->node_bytes) == 0);

    free(witness);
    voleith_gf8_circuit_free(c);
}

static void
check_inode_circuit_matches_sw(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    size_t W = h->node_bytes;
    uint8_t L[MAX_NODE_BYTES], R[MAX_NODE_BYTES];
    for (size_t i = 0; i < W; i++) {
        L[i] = (uint8_t)(0x10 + i);
        R[i] = (uint8_t)(0xE0 - i);
    }

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    /*
     * Declare L first (W witnesses), then R (W witnesses).  Witness
     * order must match the order the witness array is populated below
     * (memcpy L, then memcpy R) - interleaving the two declarations
     * scrambles L and R as the circuit sees them.
     */
    gf8_wire_id L_w[MAX_NODE_BYTES], R_w[MAX_NODE_BYTES];
    for (size_t i = 0; i < W; i++)
        L_w[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < W; i++)
        R_w[i] = voleith_gf8_add_witness(c);
    gf8_wire_id out_w[MAX_NODE_BYTES];
    h->inode_circuit(c, L_w, R_w, out_w);

    size_t inv = h->inode_invin_bytes();
    uint8_t *witness = calloc(2 * W + inv, 1);
    memcpy(witness, L, W);
    memcpy(witness + W, R, W);
    MUST_OK(h->inode_build_witness(L, R, witness + 2 * W));

    uint8_t circ_out[MAX_NODE_BYTES];
    eval_and_extract(c, witness, 2 * W + inv, out_w, W, circ_out);

    uint8_t sw_out[MAX_NODE_BYTES];
    MUST_OK(h->inode_hash(L, R, sw_out));

    char name[160];
    snprintf(name, sizeof(name), "[%s] inode: circuit == sw helper", cs->label);
    check(name, memcmp(circ_out, sw_out, W) == 0);

    free(witness);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * 4. Domain separation: leaf_hash(x) != inode_hash(x_lo, x_hi).
 *
 * Use a (2 * node_bytes) sample; treat as either leaf input or as
 * L||R for the inode.  This is the strictest adversarial shape (same
 * bytes feeding both paths); distinct values would only widen any
 * gap.
 * ================================================================ */

static void
check_domain_separation(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    size_t W = h->node_bytes;
    uint8_t X[2 * MAX_NODE_BYTES];
    for (size_t i = 0; i < 2 * W; i++)
        X[i] = (uint8_t)((i * 0x9E + 0x37) & 0xFF);

    uint8_t leaf_out[MAX_NODE_BYTES];
    uint8_t inode_out[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(X, 2 * W, leaf_out));
    MUST_OK(h->inode_hash(X, X + W, inode_out));

    char name[160];
    snprintf(name, sizeof(name),
             "[%s] domain sep: leaf_hash(x) != inode_hash(x_lo, x_hi)",
             cs->label);
    check(name, memcmp(leaf_out, inode_out, W) != 0);
}

/* ================================================================
 * Software Merkle-tree helper (drives the vt's own *_hash routines).
 * ================================================================ */

static void
build_software_tree(const voleith_node_hash_vt *h, size_t target_leaf,
                    const uint8_t leaves[][LEAF_DATA_BYTES], uint8_t *root_out,
                    uint8_t *siblings_out, uint8_t *dirs_out)
{
    size_t W = h->node_bytes;
    uint8_t *layer[DEPTH + 1];
    for (size_t k = 0; k <= DEPTH; k++)
        layer[k] = calloc((N_LEAVES >> k) > 0 ? (N_LEAVES >> k) : 1, W);

    for (size_t i = 0; i < N_LEAVES; i++)
        MUST_OK(h->leaf_hash(leaves[i], LEAF_DATA_BYTES, layer[0] + i * W));

    for (size_t k = 0; k < DEPTH; k++) {
        size_t n_parents = N_LEAVES >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(h->inode_hash(layer[k] + (2 * j) * W,
                                  layer[k] + (2 * j + 1) * W,
                                  layer[k + 1] + j * W));
    }

    memcpy(root_out, layer[DEPTH], W);
    for (size_t k = 0; k < DEPTH; k++) {
        size_t cur = target_leaf >> k;
        dirs_out[k] = (uint8_t)(cur & 1u);
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }

    for (size_t k = 0; k <= DEPTH; k++)
        free(layer[k]);
}

/* ================================================================
 * 5. Depth-3 e2e via the generic merkle_vt_gf8_path_circuit
 * (public-dir) and *_secret_dir.  Closes the Hirose ⏳ rows uniformly.
 *
 * Inline tamper check: after the positive eval, flip one byte of the
 * leaf-side inv_in and require the circuit to reject.
 * ================================================================ */

static void
check_path_e2e(const vt_case_t *cs, int secret_dir)
{
    const voleith_node_hash_vt *h = cs->vt;
    size_t W = h->node_bytes;
    size_t target = 5;

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (size_t i = 0; i < N_LEAVES; i++)
        for (size_t j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 13 + j);

    uint8_t root_sw[MAX_NODE_BYTES];
    uint8_t *siblings = calloc(DEPTH, W);
    uint8_t dirs[DEPTH];
    build_software_tree(h, target, leaves, root_sw, siblings, dirs);

    /* Build circuit: leaf_data | path_nodes | [dirs] | (internals). */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();

    gf8_wire_id leaf_w[LEAF_DATA_BYTES];
    for (size_t i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *path_w = calloc(DEPTH * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < DEPTH * W; i++)
        path_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id dir_w[DEPTH];
    if (secret_dir)
        for (size_t k = 0; k < DEPTH; k++)
            dir_w[k] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[MAX_NODE_BYTES];
    int rc;
    if (secret_dir)
        rc = merkle_vt_gf8_path_circuit_secret_dir(
            c, h, leaf_w, LEAF_DATA_BYTES, path_w, dir_w, DEPTH, root_w);
    else
        rc = merkle_vt_gf8_path_circuit(c, h, leaf_w, LEAF_DATA_BYTES, path_w,
                                        dirs, DEPTH, root_w);
    (void)rc;
    assert(rc == 0);

    /* Witness assembly. */
    size_t wn = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(wn > 0 ? wn : 1, 1);
    uint8_t *wp = witness;
    memcpy(wp, leaves[target], LEAF_DATA_BYTES);
    wp += LEAF_DATA_BYTES;
    memcpy(wp, siblings, DEPTH * W);
    wp += DEPTH * W;
    if (secret_dir) {
        for (size_t k = 0; k < DEPTH; k++)
            wp[k] = dirs[k];
        wp += DEPTH;
    }
    MUST_OK(h->leaf_build_witness(leaves[target], LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(LEAF_DATA_BYTES);

    uint8_t current[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(leaves[target], LEAF_DATA_BYTES, current));
    for (size_t k = 0; k < DEPTH; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();
        uint8_t next[MAX_NODE_BYTES];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(nW > 0 ? nW : 1, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);

    char name[160];
    snprintf(name, sizeof(name), "[%s] %s path: witness satisfies", cs->label,
             secret_dir ? "secret-dir" : "public-dir");
    check(name, ok == 1);

    int root_eq = 1;
    for (size_t i = 0; i < W; i++)
        if (wire_vals[root_w[i]] != root_sw[i])
            root_eq = 0;
    snprintf(name, sizeof(name), "[%s] %s path: root matches software",
             cs->label, secret_dir ? "secret-dir" : "public-dir");
    check(name, root_eq);

    /* Tamper: flip the first leaf-side inv_in byte; circuit must reject. */
    size_t tamper_off = LEAF_DATA_BYTES + DEPTH * W + (secret_dir ? DEPTH : 0);
    if (tamper_off < wn) {
        witness[tamper_off] ^= 0x01;
        int bad = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
        snprintf(name, sizeof(name), "[%s] %s path: tampered inv_in rejected",
                 cs->label, secret_dir ? "secret-dir" : "public-dir");
        check(name, bad == 0);
        witness[tamper_off] ^= 0x01;
    }

    free(wire_vals);
    free(witness);
    free(path_w);
    free(siblings);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * 6. Depth-3 e2e via the generic indexed-non-member circuit.
 *
 * Small tree: leaf i has (value=10+10i, next_value=10+10*(i+1),
 * next_index=i+1).  Adjacent leaf for target=35 is leaf[2] (30, 40, 3).
 * Single-byte target/index keeps leaf_data short and uniform across
 * vts.
 * ================================================================ */

#define IDX_TARGET_BYTES 1
#define IDX_INDEX_BYTES 1
#define IDX_LEAF_DATA_BYTES (2 * IDX_TARGET_BYTES + IDX_INDEX_BYTES)
#define IDX_TARGET_VAL 35
#define IDX_ADJ_LEAF 2
#define IDX_LOW_VALUE 30
#define IDX_LOW_NEXT 40
#define IDX_NEXT_INDEX 3

static void
build_indexed_tree(const voleith_node_hash_vt *h, uint8_t *root_out,
                   uint8_t *siblings_out, uint8_t *dirs_out)
{
    uint8_t leaves[N_LEAVES][IDX_LEAF_DATA_BYTES];
    for (size_t i = 0; i < N_LEAVES; i++) {
        uint8_t value = (uint8_t)(10 + 10 * i);
        uint8_t next_value =
            (i == N_LEAVES - 1) ? 255 : (uint8_t)(10 + 10 * (i + 1));
        uint8_t next_index = (i == N_LEAVES - 1) ? 0 : (uint8_t)(i + 1);
        leaves[i][0] = value;
        leaves[i][1] = next_value;
        leaves[i][2] = next_index;
    }

    size_t W = h->node_bytes;
    uint8_t *layer[DEPTH + 1];
    for (size_t k = 0; k <= DEPTH; k++)
        layer[k] = calloc((N_LEAVES >> k) > 0 ? (N_LEAVES >> k) : 1, W);

    for (size_t i = 0; i < N_LEAVES; i++)
        MUST_OK(h->leaf_hash(leaves[i], IDX_LEAF_DATA_BYTES, layer[0] + i * W));
    for (size_t k = 0; k < DEPTH; k++) {
        size_t n_parents = N_LEAVES >> (k + 1);
        for (size_t j = 0; j < n_parents; j++)
            MUST_OK(h->inode_hash(layer[k] + (2 * j) * W,
                                  layer[k] + (2 * j + 1) * W,
                                  layer[k + 1] + j * W));
    }

    memcpy(root_out, layer[DEPTH], W);
    for (size_t k = 0; k < DEPTH; k++) {
        size_t cur = IDX_ADJ_LEAF >> k;
        dirs_out[k] = (uint8_t)(cur & 1u);
        memcpy(siblings_out + k * W, layer[k] + (cur ^ 1u) * W, W);
    }

    for (size_t k = 0; k <= DEPTH; k++)
        free(layer[k]);
}

static void
check_indexed_e2e(const vt_case_t *cs, int secret_dir)
{
    const voleith_node_hash_vt *h = cs->vt;
    size_t W = h->node_bytes;

    uint8_t root_sw[MAX_NODE_BYTES];
    uint8_t *siblings = calloc(DEPTH, W);
    uint8_t dirs[DEPTH];
    build_indexed_tree(h, root_sw, siblings, dirs);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id tgt[IDX_TARGET_BYTES], lv[IDX_TARGET_BYTES],
        ln[IDX_TARGET_BYTES], ni[IDX_INDEX_BYTES];
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        tgt[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        lv[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_TARGET_BYTES; i++)
        ln[i] = voleith_gf8_add_witness(c);
    for (size_t i = 0; i < IDX_INDEX_BYTES; i++)
        ni[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *path_w = calloc(DEPTH * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < DEPTH * W; i++)
        path_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id dir_w[DEPTH];
    if (secret_dir)
        for (size_t k = 0; k < DEPTH; k++)
            dir_w[k] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[MAX_NODE_BYTES];
    int rc;
    if (secret_dir)
        rc = merkle_vt_gf8_indexed_nonmember_circuit_secret_dir(
            c, h, tgt, IDX_TARGET_BYTES, lv, ln, ni, IDX_INDEX_BYTES, path_w,
            dir_w, DEPTH, root_w);
    else
        rc = merkle_vt_gf8_indexed_nonmember_circuit(
            c, h, tgt, IDX_TARGET_BYTES, lv, ln, ni, IDX_INDEX_BYTES, path_w,
            dirs, DEPTH, root_w);

    char name[160];
    snprintf(name, sizeof(name), "[%s] %s indexed: circuit built", cs->label,
             secret_dir ? "secret-dir" : "public-dir");
    check(name, rc == 0);

    /* Witness: target | lv | ln | ni | path_nodes | [dirs] | leaf inv_in | inode inv_in × D */
    size_t wn = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(wn > 0 ? wn : 1, 1);
    uint8_t *wp = witness;
    *wp++ = IDX_TARGET_VAL;
    *wp++ = IDX_LOW_VALUE;
    *wp++ = IDX_LOW_NEXT;
    *wp++ = IDX_NEXT_INDEX;
    memcpy(wp, siblings, DEPTH * W);
    wp += DEPTH * W;
    if (secret_dir) {
        for (size_t k = 0; k < DEPTH; k++)
            wp[k] = dirs[k];
        wp += DEPTH;
    }
    uint8_t leaf_data[IDX_LEAF_DATA_BYTES] = {IDX_LOW_VALUE, IDX_LOW_NEXT,
                                              IDX_NEXT_INDEX};
    MUST_OK(h->leaf_build_witness(leaf_data, IDX_LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(IDX_LEAF_DATA_BYTES);

    uint8_t current[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(leaf_data, IDX_LEAF_DATA_BYTES, current));
    for (size_t k = 0; k < DEPTH; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();
        uint8_t next[MAX_NODE_BYTES];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(nW > 0 ? nW : 1, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);

    snprintf(name, sizeof(name), "[%s] %s indexed: witness satisfies",
             cs->label, secret_dir ? "secret-dir" : "public-dir");
    check(name, ok == 1);

    int root_eq = 1;
    for (size_t i = 0; i < W; i++)
        if (wire_vals[root_w[i]] != root_sw[i])
            root_eq = 0;
    snprintf(name, sizeof(name), "[%s] %s indexed: root matches software",
             cs->label, secret_dir ? "secret-dir" : "public-dir");
    check(name, root_eq);

    /* Tamper: flip target to low_value (violates low_value < target). */
    uint8_t saved = witness[0];
    witness[0] = IDX_LOW_VALUE;
    int bad = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);
    snprintf(name, sizeof(name), "[%s] %s indexed: ordering violation rejected",
             cs->label, secret_dir ? "secret-dir" : "public-dir");
    check(name, bad == 0);
    witness[0] = saved;

    free(wire_vals);
    free(witness);
    free(path_w);
    free(siblings);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * 7. Secret-dir booleanity: a non-{0,1} direction wire must be
 * rejected by the in-circuit assert_product(dir, dir, dir).
 *
 * Sets dirs[1] = 0x02 in the witness while the circuit shape is
 * unchanged; the booleanity check must fire.
 * ================================================================ */

static void
check_secret_dir_booleanity(const vt_case_t *cs)
{
    const voleith_node_hash_vt *h = cs->vt;
    size_t W = h->node_bytes;
    size_t target = 5;

    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (size_t i = 0; i < N_LEAVES; i++)
        for (size_t j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i * 13 + j);

    uint8_t root_sw[MAX_NODE_BYTES];
    uint8_t *siblings = calloc(DEPTH, W);
    uint8_t dirs[DEPTH];
    build_software_tree(h, target, leaves, root_sw, siblings, dirs);

    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id leaf_w[LEAF_DATA_BYTES];
    for (size_t i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);
    gf8_wire_id *path_w = calloc(DEPTH * W, sizeof(gf8_wire_id));
    for (size_t i = 0; i < DEPTH * W; i++)
        path_w[i] = voleith_gf8_add_witness(c);
    gf8_wire_id dir_w[DEPTH];
    for (size_t k = 0; k < DEPTH; k++)
        dir_w[k] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[MAX_NODE_BYTES];
    int rc = merkle_vt_gf8_path_circuit_secret_dir(
        c, h, leaf_w, LEAF_DATA_BYTES, path_w, dir_w, DEPTH, root_w);
    (void)rc;
    assert(rc == 0);

    size_t wn = voleith_gf8_circuit_witness_count(c);
    uint8_t *witness = calloc(wn > 0 ? wn : 1, 1);
    uint8_t *wp = witness;
    memcpy(wp, leaves[target], LEAF_DATA_BYTES);
    wp += LEAF_DATA_BYTES;
    memcpy(wp, siblings, DEPTH * W);
    wp += DEPTH * W;
    /* Plant a non-bit direction at level 1. */
    uint8_t bad_dirs[DEPTH];
    memcpy(bad_dirs, dirs, DEPTH);
    bad_dirs[1] = 0x02;
    for (size_t k = 0; k < DEPTH; k++)
        wp[k] = bad_dirs[k];
    wp += DEPTH;
    MUST_OK(h->leaf_build_witness(leaves[target], LEAF_DATA_BYTES, wp));
    wp += h->leaf_invin_bytes(LEAF_DATA_BYTES);
    /*
     * For the inode inv_in we still walk the *correct* path; the
     * booleanity check fires on the bad dir wire regardless of what
     * the inode inv_in look like.  Build them consistently so any
     * rejection is necessarily from the assert_product, not from a
     * downstream S-box mismatch.
     */
    uint8_t current[MAX_NODE_BYTES];
    MUST_OK(h->leaf_hash(leaves[target], LEAF_DATA_BYTES, current));
    for (size_t k = 0; k < DEPTH; k++) {
        const uint8_t *sib = siblings + k * W;
        uint8_t dir = dirs[k];
        const uint8_t *L = dir ? sib : current;
        const uint8_t *R = dir ? current : sib;
        MUST_OK(h->inode_build_witness(L, R, wp));
        wp += h->inode_invin_bytes();
        uint8_t next[MAX_NODE_BYTES];
        MUST_OK(h->inode_hash(L, R, next));
        memcpy(current, next, W);
    }

    size_t nW = voleith_gf8_circuit_wire_count(c);
    uint8_t *wire_vals = calloc(nW > 0 ? nW : 1, 1);
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, wire_vals);

    char name[160];
    snprintf(name, sizeof(name),
             "[%s] secret-dir booleanity: dir=0x02 rejected", cs->label);
    check(name, ok == 0);

    free(wire_vals);
    free(witness);
    free(path_w);
    free(siblings);
    voleith_gf8_circuit_free(c);
}

/* ================================================================
 * Run all conformance checks per vt.
 * ================================================================ */

static void
run_vt_case(const vt_case_t *cs)
{
    printf("  %s\n", cs->label);
    check_attributes(cs);
    check_invin_sizing(cs);
    check_leaf_circuit_matches_sw(cs);
    check_inode_circuit_matches_sw(cs);
    check_domain_separation(cs);
    check_path_e2e(cs, /*secret_dir=*/0);
    check_path_e2e(cs, /*secret_dir=*/1);
    if (cs->supports_indexed) {
        check_indexed_e2e(cs, /*secret_dir=*/0);
        check_indexed_e2e(cs, /*secret_dir=*/1);
    }
    check_secret_dir_booleanity(cs);
}

int
main(void)
{
    printf("=== Node-hash vt conformance suite (Branch D) ===\n");
    for (size_t i = 0; i < N_CASES; i++)
        run_vt_case(&CASES[i]);

    printf("\n%d / %d tests passed\n", total_pass, total_tests);
    return (total_pass == total_tests) ? 0 : 1;
}
