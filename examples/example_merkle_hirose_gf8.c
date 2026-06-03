/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_merkle_hirose_gf8.c - ZK proof of Merkle path membership using
 * the Hirose-AES-256 node-hash vt through the generic vt-driven Merkle
 * path circuit (circuits/merkle_vt_gf8_circuit + voleith_node_hash_hirose_fixed32).
 *
 * Counterpart to example_merkle_gf8.c (16-byte AES-DM nodes, 2^64 CR) and
 * example_merkle_grostl_gf8.c (wide-node Grøstl, 2^108 / 2^128 / 2^256 CR).
 * Run all three at the same depth on the same hardware to compare proof
 * size and prover/verifier time across the three node-hash families:
 *
 *   AES-DM        : 16-byte nodes, 2^64  CR,   ~200 S-boxes / inode
 *   Hirose-AES-256: 32-byte nodes, 2^128 CR, ~1,000 S-boxes / inode (this)
 *   Grøstl-256    : 32-byte nodes, 2^128 CR, ~3,200 S-boxes / inode
 *   Grøstl-256_T27: 27-byte nodes, 2^108 CR, ~1,920 S-boxes / inode
 *
 * Hirose is the 2^128-CR floor: same node width and same security as
 * Grøstl-256 at roughly one third of the per-inode S-box cost, because
 * each Merkle inode is two Hirose iterations sharing one AES-256 key
 * schedule (500 S-boxes / iteration; see docs/DESIGN.md "Hirose-AES-256").
 *
 * Hirose ships only as voleith_node_hash_vt instances - there is no
 * fixed-hash entry point for it - so this example doubles as the
 * canonical demonstration of how to drive any vt-based hash through the
 * generic merkle_vt_gf8_path_circuit body.  The fixed-32 leaf vt is
 * used here because the existing AES-DM and Grøstl examples also use
 * fixed leaves with no padding overhead, keeping the comparison
 * apples-to-apples.
 *
 * Tree: depth 5 (32 leaves), Hirose-AES-256 fixed-32 leaf, 32-byte
 * nodes (2^128 CR), public leaf index.
 *
 * Public  (instance): root R (32 bytes)
 * Private (witness):  leaf data + sibling hashes along the path +
 *                     Hirose iteration inv_in (leaf and inode).
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_vt_gf8_circuit.h"
#include "node_hash_vt.h"
#include "node_hash_hirose_gf8.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "bench_util.h"

#define DEPTH 5
#define N_LEAVES (1u << DEPTH) /* 32 */
#define NODE_BYTES 32          /* Hirose-AES-256 chain width */
#define LEAF_DATA_BYTES 32     /* fixed-32 leaf: exactly two iterations */
#define LEAF_INDEX 21 /* 0b10101 - a mixed-bit path (matches the other two) */

/* Benchmark iteration counts (tune as needed). */
#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25
#define BENCH_VERIFY_ITERS 100

int
main(void)
{
    const voleith_node_hash_vt *h = &voleith_node_hash_hirose_fixed32;

    printf("=== Merkle path ZK proof (vt-driven, Hirose-AES-256 fixed-32 leaf) "
           "===\n");
    printf("Statement: knowledge of leaf[%u] and path s.t. Merkle path → "
           "root\n",
           LEAF_INDEX);
    printf("Tree: %u leaves (depth %u), Hirose-AES-256 32-byte nodes "
           "(2^128 CR), public index\n",
           N_LEAVES, DEPTH);
    printf("vt: %s (node_bytes=%zu, cr_bits=%zu)\n\n", h->name, h->node_bytes,
           h->cr_bits);

    /* ================================================================
     * Build the depth-5 tree in software.
     *
     * leaf[i]      = a 32-byte record: {i, i+1, ..., i+31}
     * layer[0][i]  = Hirose-fixed32-leaf(leaf[i])
     * layer[k+1][j]= Hirose-inode(layer[k][2j], layer[k][2j+1])
     * root         = layer[DEPTH][0]
     * ================================================================ */
    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (unsigned i = 0; i < N_LEAVES; i++)
        for (unsigned j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i + j);

    /* layer[k] holds (N_LEAVES >> k) nodes of NODE_BYTES each. */
    uint8_t *layer[DEPTH + 1];
    for (unsigned k = 0; k <= DEPTH; k++)
        layer[k] = malloc(((size_t)N_LEAVES >> k) * NODE_BYTES);

    for (unsigned i = 0; i < N_LEAVES; i++)
        merkle_hirose_fixed32_leaf_hash(leaves[i], LEAF_DATA_BYTES,
                                        layer[0] + (size_t)i * NODE_BYTES);

    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned n_parents = N_LEAVES >> (k + 1);
        for (unsigned j = 0; j < n_parents; j++)
            merkle_hirose_inode_hash(layer[k] + (size_t)(2 * j) * NODE_BYTES,
                                     layer[k] +
                                         (size_t)(2 * j + 1) * NODE_BYTES,
                                     layer[k + 1] + (size_t)j * NODE_BYTES);
    }

    const uint8_t *root = layer[DEPTH]; /* layer[DEPTH][0] */

    /* Sibling and direction at each path level for LEAF_INDEX. */
    uint8_t path_dirs[DEPTH];
    uint8_t siblings[DEPTH * NODE_BYTES];
    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned cur = LEAF_INDEX >> k;
        path_dirs[k] = (uint8_t)(cur & 1u);
        memcpy(siblings + (size_t)k * NODE_BYTES,
               layer[k] + (size_t)(cur ^ 1u) * NODE_BYTES, NODE_BYTES);
    }

    /* ================================================================
     * Build the circuit.  Declaration order fixes the witness layout:
     *   (1) leaf data wires,
     *   (2) sibling wires,
     *   (3) merkle_vt_gf8_path_circuit, which appends
     *         leaf inv_in then per-level inode inv_in internally.
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id leaf_wires[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *node_wires =
        malloc((size_t)DEPTH * NODE_BYTES * sizeof(*node_wires));
    for (size_t i = 0; i < (size_t)DEPTH * NODE_BYTES; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_computed[NODE_BYTES];
    if (merkle_vt_gf8_path_circuit(c, h, leaf_wires, LEAF_DATA_BYTES,
                                   node_wires, path_dirs, DEPTH,
                                   root_computed) != 0) {
        fprintf(stderr, "merkle_vt_gf8_path_circuit failed\n");
        return 1;
    }

    /* Root: NODE_BYTES public instance wires; assert equal. */
    for (int i = 0; i < NODE_BYTES; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t leaf_invin = h->leaf_invin_bytes(LEAF_DATA_BYTES);
    size_t inode_invin = h->inode_invin_bytes();

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (S-box uses assert_product, not add_mul)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("    = %d leaf + %u siblings + %zu leaf inv_in + %u×%zu inode "
           "inv_in\n",
           LEAF_DATA_BYTES, (unsigned)(DEPTH * NODE_BYTES), leaf_invin, DEPTH,
           inode_invin);
    printf("  Instance wires:  %zu (root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Assemble the witness in declaration order.  merkle_vt_gf8_path_circuit
     * calls h->leaf_circuit before walking the path, so leaf inv_in
     * precedes the per-level inode inv_in.
     *
     * Layout: leaf data | siblings | leaf inv_in | per-level inode inv_in
     * ================================================================ */
    size_t total = LEAF_DATA_BYTES + (size_t)DEPTH * NODE_BYTES + leaf_invin +
                   (size_t)DEPTH * inode_invin;
    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    /* (1) leaf data */
    memcpy(witness + off, leaves[LEAF_INDEX], LEAF_DATA_BYTES);
    off += LEAF_DATA_BYTES;

    /* (2) siblings */
    memcpy(witness + off, siblings, (size_t)DEPTH * NODE_BYTES);
    off += (size_t)DEPTH * NODE_BYTES;

    /* (3) leaf inv_in */
    merkle_hirose_gf8_fixed32_leaf_build_witness(
        leaves[LEAF_INDEX], LEAF_DATA_BYTES, witness + off);
    off += leaf_invin;

    /* (4) per-level inode inv_in, walking the path from the leaf hash up */
    uint8_t current[NODE_BYTES];
    merkle_hirose_fixed32_leaf_hash(leaves[LEAF_INDEX], LEAF_DATA_BYTES,
                                    current);
    for (unsigned lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + (size_t)lvl * NODE_BYTES;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_hirose_gf8_inode_build_witness(L, R, witness + off);
        off += inode_invin;

        uint8_t next[NODE_BYTES];
        merkle_hirose_inode_hash(L, R, next);
        memcpy(current, next, NODE_BYTES);
    }

    /* Sanity: walked root must equal the tree root. */
    if (memcmp(current, root, NODE_BYTES) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        return 1;
    }

    const uint8_t *instance = root;
    const char *ds = "example_merkle_hirose_gf8:depth5-Hirose-fixed32-leaf21";

    /* ================================================================
     * Benchmark prove + verify.  The witness build above stays outside
     * the timed region, so this measures only the proof system.
     *
     * Prove is re-run each iteration (fresh proof - captures grinding-
     * loop variance, which is real prover cost).  Verify is run against
     * one fixed proof (pure verify timing; valid-proof verify cost does
     * not depend on which proof).  See bench_util.h for the min/median/
     * mean/max methodology and why we do not trim the fast tail.
     * ================================================================ */
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};

    /* Warmup: fill caches, settle frequency scaling; times discarded. */
    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf8_prove_v2(
                &p, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
                instance, voleith_gf8_circuit_instance_byte_len(c), ds,
                strlen(ds)) != 0) {
            fprintf(stderr, "voleith_gf8_prove_v2 failed (warmup)\n");
            return 1;
        }
        voleith_gf8_verify_v2(&p, params, c, instance,
                              voleith_gf8_circuit_instance_byte_len(c), ds,
                              strlen(ds));
        voleith_proof_free(&p);
    }

    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_prove_v2(
            &p, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
            instance, voleith_gf8_circuit_instance_byte_len(c), ds, strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
            return 1;
        }
        prove_ms[i] = (double)(t1 - t0) / 1e6;
        if (i == BENCH_PROVE_ITERS - 1)
            kept = p; /* keep the last proof for the verify loop */
        else
            voleith_proof_free(&p);
    }

    int verify_ok = 1;
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_verify_v2(&kept, params, c, instance,
                                       voleith_gf8_circuit_instance_byte_len(c),
                                       ds, strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0)
            verify_ok = 0;
        verify_ms[i] = (double)(t1 - t0) / 1e6;
    }

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);

    printf("Proof size:   %zu bytes\n", kept.len);
    printf("Verification: %s\n", verify_ok ? "PASS" : "FAIL");
    printf("Timing (%d prove / %d verify iters, %d warmup):\n",
           BENCH_PROVE_ITERS, BENCH_VERIFY_ITERS, BENCH_WARMUP);
    bench_print("prove", ps);
    bench_print("verify", vs);

    int rc = verify_ok ? 0 : 1;
    voleith_proof_free(&kept);
    voleith_gf8_circuit_free(c);
    free(witness);
    free(node_wires);
    for (unsigned k = 0; k <= DEPTH; k++)
        free(layer[k]);

    return (rc == 0) ? 0 : 1;
}
