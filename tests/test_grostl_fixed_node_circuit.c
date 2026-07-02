/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_grostl_fixed_node_circuit.c - Tests for the fixed-input
 * single-compression Grøstl node circuits (grostl{256,512}_gf8_node_*).
 *
 * Validates (T2.1 of the Grøstl fixed-input node hash plan):
 *   - Circuit-eval output equals the software oracle
 *     voleith_grostl{256,512}_compress_node (core/grostl.c), for both
 *     a leaf-shaped block (payload zero-padded) and an inode-shaped
 *     block (full block of children), and for distinct IVs.
 *   - The realized S-box / VOLE-slot count is 1,920 (256) / 5,376
 *     (512), with no add_mul gates (the Grøstl S-box uses Prop 6.4
 *     assert_product, so the cost lives in the witness count, matching
 *     test_grostl_gf8_circuit.c).
 *
 * Witness layout for one node circuit: the caller declares the block
 * input wires first (block_bytes of them), then grostl*_gf8_node_circuit
 * adds the inv_in wires internally.  So the full witness array is
 * [block bytes] followed by grostl*_gf8_node_build_witness output.
 */

#include "../circuits/grostl_gf8_circuit.h"
#include "../circuits/merkle_vt_gf8_circuit.h"
#include "../circuits/node_hash_vt.h"
#include "../core/grostl.h"
#include "../proof/gf8_circuit.h"
#include "../proof/gf8_proof.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-60s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

static void
hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* ================================================================
 * Build + evaluate one node circuit.  Returns the circuit-eval
 * constraint flag (1 ok, 0 violation, -1 alloc), the 32/64 output
 * bytes, and the realized S-box and add_mul counts.
 * ================================================================ */

static int
eval_node_256(const uint8_t iv[64], const uint8_t block[64], uint8_t out[32],
              size_t *n_sboxes, size_t *n_mul)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id block_wires[64];
    for (int i = 0; i < 64; i++)
        block_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id outw[32];
    grostl256_gf8_node_circuit(c, iv, block_wires, outw);

    size_t wbytes = 64 + grostl256_gf8_node_invin_bytes();
    uint8_t *witness = malloc(wbytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return -1;
    }
    memcpy(witness, block, 64);
    grostl256_gf8_node_build_witness(iv, block, witness + 64);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    if (!vals) {
        free(witness);
        voleith_gf8_circuit_free(c);
        return -1;
    }
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    for (int i = 0; i < 32; i++)
        out[i] = vals[outw[i]];

    if (n_sboxes)
        *n_sboxes = voleith_gf8_circuit_witness_count(c) - 64;
    if (n_mul)
        *n_mul = voleith_gf8_circuit_mul_count(c);

    free(vals);
    free(witness);
    voleith_gf8_circuit_free(c);
    return ok;
}

static int
eval_node_512(const uint8_t iv[128], const uint8_t block[128], uint8_t out[64],
              size_t *n_sboxes, size_t *n_mul)
{
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id block_wires[128];
    for (int i = 0; i < 128; i++)
        block_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id outw[64];
    grostl512_gf8_node_circuit(c, iv, block_wires, outw);

    size_t wbytes = 128 + grostl512_gf8_node_invin_bytes();
    uint8_t *witness = malloc(wbytes);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return -1;
    }
    memcpy(witness, block, 128);
    grostl512_gf8_node_build_witness(iv, block, witness + 128);

    size_t n_wires = voleith_gf8_circuit_wire_count(c);
    uint8_t *vals = calloc(n_wires, 1);
    if (!vals) {
        free(witness);
        voleith_gf8_circuit_free(c);
        return -1;
    }
    int ok = voleith_gf8_circuit_eval(c, witness, NULL, vals);
    for (int i = 0; i < 64; i++)
        out[i] = vals[outw[i]];

    if (n_sboxes)
        *n_sboxes = voleith_gf8_circuit_witness_count(c) - 128;
    if (n_mul)
        *n_mul = voleith_gf8_circuit_mul_count(c);

    free(vals);
    free(witness);
    voleith_gf8_circuit_free(c);
    return ok;
}

/* ================================================================
 * Circuit-vs-oracle.
 * ================================================================ */

static void
check_node_256(const uint8_t iv[64], const uint8_t block[64], const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "grostl256 node circuit vs oracle: %s", label);
    TEST(name);

    uint8_t got[32];
    size_t n_sboxes = 0, n_mul = 0;
    int ok = eval_node_256(iv, block, got, &n_sboxes, &n_mul);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d (constraint failure)\n", ok);
        return;
    }

    uint8_t want[32];
    if (voleith_grostl256_compress_node(iv, block, want) != 0) {
        FAIL("oracle returned nonzero");
        return;
    }

    if (memcmp(got, want, 32) == 0) {
        PASS();
    } else {
        printf("FAIL\n        circuit: ");
        hex_print(got, 32);
        printf("\n        oracle:  ");
        hex_print(want, 32);
        printf("\n");
    }
}

static void
check_node_512(const uint8_t iv[128], const uint8_t block[128],
               const char *label)
{
    char name[80];
    snprintf(name, sizeof(name), "grostl512 node circuit vs oracle: %s", label);
    TEST(name);

    uint8_t got[64];
    size_t n_sboxes = 0, n_mul = 0;
    int ok = eval_node_512(iv, block, got, &n_sboxes, &n_mul);
    if (ok != 1) {
        printf("FAIL: circuit_eval returned %d (constraint failure)\n", ok);
        return;
    }

    uint8_t want[64];
    if (voleith_grostl512_compress_node(iv, block, want) != 0) {
        FAIL("oracle returned nonzero");
        return;
    }

    if (memcmp(got, want, 64) == 0) {
        PASS();
    } else {
        printf("FAIL\n        circuit: ");
        hex_print(got, 64);
        printf("\n        oracle:  ");
        hex_print(want, 64);
        printf("\n");
    }
}

static void
test_circuit_vs_oracle_256(void)
{
    uint8_t iv_a[64], iv_b[64];
    for (int i = 0; i < 64; i++) {
        iv_a[i] = (uint8_t)(0x11 + i);
        iv_b[i] = (uint8_t)(iv_a[i] ^ 0x5a); /* distinct IV (domain sep) */
    }

    /* Leaf-shaped block: 32-byte payload zero-padded to the 64-byte
     * block (the leaf vt's layout). */
    uint8_t leaf_block[64];
    memset(leaf_block, 0, sizeof(leaf_block));
    for (int i = 0; i < 32; i++)
        leaf_block[i] = (uint8_t)(0xa0 + i);

    /* Inode-shaped block: full block of two 32-byte children. */
    uint8_t inode_block[64];
    for (int i = 0; i < 64; i++)
        inode_block[i] = (uint8_t)(0xff - i);

    check_node_256(iv_a, leaf_block, "leaf (zero-padded), iv_a");
    check_node_256(iv_a, inode_block, "inode (full block), iv_a");
    check_node_256(iv_b, inode_block, "inode (full block), iv_b");
}

static void
test_circuit_vs_oracle_512(void)
{
    uint8_t iv_a[128], iv_b[128];
    for (int i = 0; i < 128; i++) {
        iv_a[i] = (uint8_t)(0x11 + i);
        iv_b[i] = (uint8_t)(iv_a[i] ^ 0x5a);
    }

    uint8_t leaf_block[128];
    memset(leaf_block, 0, sizeof(leaf_block));
    for (int i = 0; i < 64; i++)
        leaf_block[i] = (uint8_t)(0xa0 + i);

    uint8_t inode_block[128];
    for (int i = 0; i < 128; i++)
        inode_block[i] = (uint8_t)(0xff - i);

    check_node_512(iv_a, leaf_block, "leaf (zero-padded), iv_a");
    check_node_512(iv_a, inode_block, "inode (full block), iv_a");
    check_node_512(iv_b, inode_block, "inode (full block), iv_b");
}

/* ================================================================
 * S-box / VOLE-slot counts.  One compression (P + Q) plus the output
 * transform's P, no padding block: 1,920 (256) / 5,376 (512).  No
 * add_mul gates (Prop 6.4 S-box gadget).
 * ================================================================ */

static void
test_sbox_count(void)
{
    uint8_t iv256[64], block256[64];
    for (int i = 0; i < 64; i++) {
        iv256[i] = (uint8_t)i;
        block256[i] = (uint8_t)(i * 3 + 1);
    }
    uint8_t out256[32];
    size_t sb256 = 0, mul256 = 0;

    TEST("grostl256 node: 1920 S-boxes, 0 add_mul");
    int ok = eval_node_256(iv256, block256, out256, &sb256, &mul256);
    if (ok == 1 && sb256 == 1920u && mul256 == 0u) {
        PASS();
    } else {
        printf("FAIL: ok=%d n_sboxes=%zu (want 1920) n_mul=%zu (want 0)\n", ok,
               sb256, mul256);
    }

    uint8_t iv512[128], block512[128];
    for (int i = 0; i < 128; i++) {
        iv512[i] = (uint8_t)i;
        block512[i] = (uint8_t)(i * 3 + 1);
    }
    uint8_t out512[64];
    size_t sb512 = 0, mul512 = 0;

    TEST("grostl512 node: 5376 S-boxes, 0 add_mul");
    ok = eval_node_512(iv512, block512, out512, &sb512, &mul512);
    if (ok == 1 && sb512 == 5376u && mul512 == 0u) {
        PASS();
    } else {
        printf("FAIL: ok=%d n_sboxes=%zu (want 5376) n_mul=%zu (want 0)\n", ok,
               sb512, mul512);
    }
}

/* invin_bytes accessors must agree with the realized counts. */
static void
test_invin_bytes(void)
{
    TEST("node_invin_bytes accessors: 1920 / 5376");
    if (grostl256_gf8_node_invin_bytes() == 1920u &&
        grostl512_gf8_node_invin_bytes() == 5376u) {
        PASS();
    } else {
        printf("FAIL: 256=%zu (want 1920) 512=%zu (want 5376)\n",
               grostl256_gf8_node_invin_bytes(),
               grostl512_gf8_node_invin_bytes());
    }
}

/* ================================================================
 * Depth-3 Merkle path: full prove + verify + tamper soundness,
 * through the vt-driven merkle_vt_gf8_path_circuit (T2.3).
 *
 * Drives the fixed-input vts (leaf width = node width: 32 for
 * grostl256_fixed, 64 for grostl512_fixed) end to end: build a tree in
 * software, build the path circuit with the root as a public instance,
 * generate the witness, then:
 *   - prove + verify the honest path (expect success),
 *   - verify the honest proof against a flipped root (expect reject),
 *   - prove with a tampered sibling byte (expect the prover to reject
 *     the invalid witness).
 * ================================================================ */

#define E2E_DEPTH 3
#define E2E_N_LEAVES (1u << E2E_DEPTH)
#define E2E_MAX_NODE 64

static void
test_path_e2e(const voleith_node_hash_vt *h, const char *label)
{
    size_t W = h->node_bytes;
    size_t lb = h->fixed_leaf_bytes; /* 32 (256) or 64 (512) */
    unsigned target = 5;

    /* Software tree over leaves[i] = {i*7, i*7+1, ...} (lb bytes). */
    uint8_t leaves[E2E_N_LEAVES][E2E_MAX_NODE];
    for (unsigned i = 0; i < E2E_N_LEAVES; i++)
        for (size_t j = 0; j < lb; j++)
            leaves[i][j] = (uint8_t)(i * 7 + j);

    uint8_t *layer[E2E_DEPTH + 1];
    for (unsigned k = 0; k <= E2E_DEPTH; k++)
        layer[k] = malloc(((size_t)E2E_N_LEAVES >> k) * W);
    for (unsigned i = 0; i < E2E_N_LEAVES; i++)
        h->leaf_hash(leaves[i], lb, layer[0] + (size_t)i * W);
    for (unsigned k = 0; k < E2E_DEPTH; k++) {
        unsigned np = E2E_N_LEAVES >> (k + 1);
        for (unsigned j = 0; j < np; j++)
            h->inode_hash(layer[k] + (size_t)(2 * j) * W,
                          layer[k] + (size_t)(2 * j + 1) * W,
                          layer[k + 1] + (size_t)j * W);
    }
    uint8_t root[E2E_MAX_NODE];
    memcpy(root, layer[E2E_DEPTH], W);

    uint8_t dirs[E2E_DEPTH];
    uint8_t siblings[E2E_DEPTH * E2E_MAX_NODE];
    for (unsigned k = 0; k < E2E_DEPTH; k++) {
        unsigned cur = target >> k;
        dirs[k] = (uint8_t)(cur & 1u);
        memcpy(siblings + (size_t)k * W, layer[k] + (size_t)(cur ^ 1u) * W, W);
    }

    /* Circuit: leaf wires | sibling wires | path circuit | root instance. */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    gf8_wire_id leaf_w[E2E_MAX_NODE];
    for (size_t i = 0; i < lb; i++)
        leaf_w[i] = voleith_gf8_add_witness(c);
    gf8_wire_id *node_w = malloc((size_t)E2E_DEPTH * W * sizeof(*node_w));
    for (size_t i = 0; i < (size_t)E2E_DEPTH * W; i++)
        node_w[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_w[E2E_MAX_NODE];
    int crc = merkle_vt_gf8_path_circuit(c, h, leaf_w, lb, node_w, dirs,
                                         E2E_DEPTH, root_w);
    for (size_t i = 0; i < W; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_w[i], ri);
    }

    /* Witness: leaf | siblings | leaf inv_in | per-level inode inv_in. */
    size_t leaf_invin = h->leaf_invin_bytes(lb);
    size_t inode_invin = h->inode_invin_bytes();
    size_t total = lb + (size_t)E2E_DEPTH * W + leaf_invin +
                   (size_t)E2E_DEPTH * inode_invin;
    uint8_t *witness = calloc(total, 1);
    size_t off = 0;
    memcpy(witness + off, leaves[target], lb);
    off += lb;
    memcpy(witness + off, siblings, (size_t)E2E_DEPTH * W);
    off += (size_t)E2E_DEPTH * W;
    h->leaf_build_witness(leaves[target], lb, witness + off);
    off += leaf_invin;
    uint8_t current[E2E_MAX_NODE];
    h->leaf_hash(leaves[target], lb, current);
    for (unsigned k = 0; k < E2E_DEPTH; k++) {
        const uint8_t *sib = siblings + (size_t)k * W;
        const uint8_t *L = dirs[k] ? sib : current;
        const uint8_t *R = dirs[k] ? current : sib;
        h->inode_build_witness(L, R, witness + off);
        off += inode_invin;
        uint8_t next[E2E_MAX_NODE];
        h->inode_hash(L, R, next);
        memcpy(current, next, W);
    }

    const voleith_params_t *params = &voleith_params_em_128f;
    const char *ds = "test_grostl_fixed_node:path-e2e";
    size_t inst_len = voleith_gf8_circuit_instance_byte_len(c);
    size_t wit_len = voleith_gf8_circuit_witness_byte_len(c);
    char name[96];

    /* Positive: honest prove + verify. */
    snprintf(name, sizeof(name), "%s depth-3 path: prove + verify", label);
    TEST(name);
    voleith_proof_t p = {0};
    int prc = -1, vrc = -1;
    if (crc != 0) {
        FAIL("path circuit build failed");
    } else {
        prc = voleith_gf8_prove_v2(&p, params, c, witness, wit_len, root,
                                   inst_len, ds, strlen(ds));
        if (prc == 0)
            vrc = voleith_gf8_verify_v2(&p, params, c, root, inst_len, ds,
                                        strlen(ds));
        if (prc == 0 && vrc == 0)
            PASS();
        else
            printf("FAIL: prove=%d verify=%d\n", prc, vrc);
    }

    /* Tamper 1: verify the honest proof against a flipped root. */
    snprintf(name, sizeof(name), "%s depth-3 path: wrong root rejected", label);
    TEST(name);
    if (prc == 0) {
        uint8_t bad_root[E2E_MAX_NODE];
        memcpy(bad_root, root, W);
        bad_root[0] ^= 0x01;
        int brc = voleith_gf8_verify_v2(&p, params, c, bad_root, inst_len, ds,
                                        strlen(ds));
        if (brc != 0)
            PASS();
        else
            FAIL("verify accepted wrong root");
    } else {
        FAIL("no valid proof to test against");
    }
    voleith_proof_free(&p);

    /* Tamper 2: corrupt the first sibling byte; the prover must reject
     * the now-inconsistent witness (inode inv_in no longer matches). */
    snprintf(name, sizeof(name), "%s depth-3 path: tampered sibling rejected",
             label);
    TEST(name);
    witness[lb] ^= 0x01;
    voleith_proof_t p2 = {0};
    int trc = voleith_gf8_prove_v2(&p2, params, c, witness, wit_len, root,
                                   inst_len, ds, strlen(ds));
    if (trc != 0) {
        PASS();
    } else {
        FAIL("prove accepted tampered witness");
        voleith_proof_free(&p2);
    }
    witness[lb] ^= 0x01;

    free(witness);
    free(node_w);
    for (unsigned k = 0; k <= E2E_DEPTH; k++)
        free(layer[k]);
    voleith_gf8_circuit_free(c);
}

/* A leaf preimage wider than the single-compression capacity
 * (leaf_block_bytes = 2*node_bytes: 64 for grostl256_fixed, 128 for
 * grostl512_fixed) must be rejected (-1), not clamped.  Exactly the
 * capacity succeeds. */
static void
test_leaf_rejects_oversize(const voleith_node_hash_vt *h, const char *label)
{
    size_t cap = h->leaf_block_bytes;
    uint8_t data[256];
    uint8_t out[64];
    uint8_t *inv = calloc(h->leaf_invin_bytes(cap), 1);
    char name[96];

    for (size_t i = 0; i < sizeof(data); i++)
        data[i] = (uint8_t)(0x20 + i);

    snprintf(name, sizeof(name), "%s leaf_hash: %zu (cap) bytes accepted",
             label, cap);
    TEST(name);
    if (h->leaf_hash(data, cap, out) == 0)
        PASS();
    else
        FAIL("expected 0");

    snprintf(name, sizeof(name), "%s leaf_hash: cap+1 bytes rejected", label);
    TEST(name);
    if (h->leaf_hash(data, cap + 1, out) == -1)
        PASS();
    else
        FAIL("expected -1");

    snprintf(name, sizeof(name), "%s leaf_build_witness: cap+1 bytes rejected",
             label);
    TEST(name);
    if (h->leaf_build_witness(data, cap + 1, inv) == -1)
        PASS();
    else
        FAIL("expected -1");

    free(inv);
}

int
main(void)
{
    printf("grostl_fixed_node_circuit tests\n");
    printf("===============================\n");

    printf("\n  S-box / VOLE-slot counts\n");
    test_invin_bytes();
    test_sbox_count();

    printf("\n  Grøstl-256 node: circuit vs oracle\n");
    test_circuit_vs_oracle_256();

    printf("\n  Grøstl-512 node: circuit vs oracle\n");
    test_circuit_vs_oracle_512();

    printf("\n  Depth-3 Merkle path: prove + verify + tamper\n");
    test_path_e2e(&voleith_node_hash_grostl256_fixed, "grostl256_fixed");
    test_path_e2e(&voleith_node_hash_grostl512_fixed, "grostl512_fixed");

    printf("\n  Oversize leaf preimage rejected (not clamped)\n");
    test_leaf_rejects_oversize(&voleith_node_hash_grostl256_fixed,
                               "grostl256_fixed");
    test_leaf_rejects_oversize(&voleith_node_hash_grostl512_fixed,
                               "grostl512_fixed");

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
