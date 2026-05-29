/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_merkle_grostl_gf8.c - ZK proof of Merkle path membership using
 * the wide-node Grøstl Merkle circuit (circuits/merkle_grostl_gf8_circuit).
 *
 * Counterpart to example_merkle_gf8.c, which uses 16-byte AES-DM nodes
 * (2⁶⁴ collision resistance).  This example uses Grøstl-256 with 32-byte
 * nodes for full 2¹²⁸ collision resistance - the "proper" Merkle option
 * when 64-bit CR is not enough.  Switch GROSTL_VARIANT to
 * VOLEITH_MERKLE_GROSTL_512 for 64-byte nodes / 2²⁵⁶ CR.
 *
 * Tree: depth 5 (32 leaves), Grøstl-256, RFC-6962 domain separation
 * (0x00 leaf / 0x01 inode), public leaf index.  Membership is proven for
 * one chosen leaf.
 *
 * Public  (instance): root R (node_bytes)
 * Private (witness):  leaf data + all Grøstl S-box inv_in values + sibling
 *                     hashes along the path.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "grostl.h"
#include "merkle_grostl_gf8_circuit.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> /* needed for timing */
#include "bench_util.h"

#define GROSTL_VARIANT VOLEITH_MERKLE_GROSTL_256_T27
#define DEPTH 5
#define N_LEAVES (1u << DEPTH) /* 32 */
#define LEAF_DATA_BYTES 32
#define LEAF_INDEX 21 /* 0b10101 - a mixed-bit path */

/* Benchmark iteration counts (tune as needed). */
#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25
#define BENCH_VERIFY_ITERS 100

static const char *
variant_label(voleith_merkle_grostl_variant_t v)
{
    switch (v) {
    case VOLEITH_MERKLE_GROSTL_256:
        return "Grøstl-256, 32-byte nodes (2^128 CR, 2-block inode)";
    case VOLEITH_MERKLE_GROSTL_256_T27:
        return "Grøstl-256/T27, 27-byte nodes (2^108 CR, 1-block inode)";
    case VOLEITH_MERKLE_GROSTL_512:
        return "Grøstl-512, 64-byte nodes (2^256 CR, 2-block inode)";
    default:
        return "?";
    }
}

int
main(void)
{
    const voleith_merkle_grostl_variant_t variant = GROSTL_VARIANT;
    const size_t nb = merkle_grostl_node_bytes(variant);

    printf("=== Merkle path ZK proof (wide-node Grøstl Merkle circuit) ===\n");
    printf("Statement: knowledge of leaf[%u] and path s.t. Merkle path → "
           "root\n",
           LEAF_INDEX);
    printf("Tree: %u leaves (depth %u), %s, public index\n\n", N_LEAVES, DEPTH,
           variant_label(variant));

    /* ================================================================
     * Build the depth-5 tree in software.
     *
     * leaf[i]      = a 32-byte record: {i, i+1, ..., i+31}
     * layer[0][i]  = Grøstl(0x00 ‖ leaf[i])              (leaf hashes)
     * layer[k+1][j]= Grøstl(0x01 ‖ layer[k][2j] ‖ [2j+1]) (inode hashes)
     * root         = layer[DEPTH][0]
     * ================================================================ */
    uint8_t leaves[N_LEAVES][LEAF_DATA_BYTES];
    for (unsigned i = 0; i < N_LEAVES; i++)
        for (unsigned j = 0; j < LEAF_DATA_BYTES; j++)
            leaves[i][j] = (uint8_t)(i + j);

    /* layer[k] holds (N_LEAVES >> k) nodes of nb bytes each. */
    uint8_t *layer[DEPTH + 1];
    for (unsigned k = 0; k <= DEPTH; k++)
        layer[k] = malloc(((size_t)N_LEAVES >> k) * nb);

    for (unsigned i = 0; i < N_LEAVES; i++)
        merkle_grostl_leaf_hash(leaves[i], LEAF_DATA_BYTES, variant,
                                layer[0] + (size_t)i * nb);

    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned n_parents = N_LEAVES >> (k + 1);
        for (unsigned j = 0; j < n_parents; j++)
            merkle_grostl_inode_hash(layer[k] + (size_t)(2 * j) * nb,
                                     layer[k] + (size_t)(2 * j + 1) * nb,
                                     variant, layer[k + 1] + (size_t)j * nb);
    }

    const uint8_t *root = layer[DEPTH]; /* layer[DEPTH][0] */

    /* Sibling and direction at each path level for LEAF_INDEX. */
    uint8_t path_dirs[DEPTH];
    uint8_t siblings[DEPTH * 64]; /* nb <= 64 */
    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned cur = LEAF_INDEX >> k;
        path_dirs[k] = (uint8_t)(cur & 1u);
        memcpy(siblings + (size_t)k * nb, layer[k] + (size_t)(cur ^ 1u) * nb,
               nb);
    }

    /* ================================================================
     * Build the circuit.  Declaration order fixes the witness layout:
     *   (1) leaf data wires, (2) leaf hash (adds leaf inv_in),
     *   (3) sibling wires,   (4) path circuit (adds inode inv_in).
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id leaf_wires[LEAF_DATA_BYTES];
    for (int i = 0; i < LEAF_DATA_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id leaf_hash_wires[64];
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_wires, LEAF_DATA_BYTES, variant,
                                        leaf_hash_wires);

    gf8_wire_id *node_wires = malloc((size_t)DEPTH * nb * sizeof(*node_wires));
    for (size_t i = 0; i < (size_t)DEPTH * nb; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_computed[64];
    merkle_grostl_gf8_path_circuit(c, leaf_hash_wires, node_wires, path_dirs,
                                   DEPTH, variant, root_computed);

    /* Root: nb public instance wires; assert equal. */
    for (size_t i = 0; i < nb; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    size_t leaf_invin =
        merkle_grostl_gf8_leaf_invin_bytes(LEAF_DATA_BYTES, variant);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(variant);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (S-box uses assert_product, not add_mul)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("    = %d leaf + %zu leaf inv_in + %u siblings + %u×%zu inode "
           "inv_in\n",
           LEAF_DATA_BYTES, leaf_invin, (unsigned)(DEPTH * nb), DEPTH,
           inode_invin);
    printf("  Instance wires:  %zu (root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Assemble the witness in declaration order.
     * ================================================================ */
    size_t total = LEAF_DATA_BYTES + leaf_invin + (size_t)DEPTH * nb +
                   (size_t)DEPTH * inode_invin;
    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    /* (1) leaf data */
    memcpy(witness + off, leaves[LEAF_INDEX], LEAF_DATA_BYTES);
    off += LEAF_DATA_BYTES;

    /* (2) leaf hash inv_in */
    merkle_grostl_gf8_leaf_build_witness(leaves[LEAF_INDEX], LEAF_DATA_BYTES,
                                         variant, witness + off);
    off += leaf_invin;

    /* (3) siblings (must precede the path inv_in) */
    memcpy(witness + off, siblings, (size_t)DEPTH * nb);
    off += (size_t)DEPTH * nb;

    /* (4) per-level inode inv_in, walking the path from the leaf hash up */
    uint8_t current[64];
    merkle_grostl_leaf_hash(leaves[LEAF_INDEX], LEAF_DATA_BYTES, variant,
                            current);
    for (unsigned lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + (size_t)lvl * nb;
        const uint8_t *L = path_dirs[lvl] ? sib : current;
        const uint8_t *R = path_dirs[lvl] ? current : sib;

        merkle_grostl_gf8_inode_build_witness(L, R, variant, witness + off);
        off += inode_invin;

        uint8_t next[64];
        merkle_grostl_inode_hash(L, R, variant, next);
        memcpy(current, next, nb);
    }

    /* Sanity: walked root must equal the tree root. */
    if (memcmp(current, root, nb) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        return 1;
    }

    const uint8_t *instance = root;
    const char *ds = "example_merkle_grostl_gf8:depth5-G256-leaf21";

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
        if (voleith_gf8_prove(&p, params, c, witness, instance, ds,
                              strlen(ds)) != 0) {
            fprintf(stderr, "voleith_gf8_prove failed (warmup)\n");
            return 1;
        }
        voleith_gf8_verify(&p, params, c, instance, ds, strlen(ds));
        voleith_proof_free(&p);
    }

    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc =
            voleith_gf8_prove(&p, params, c, witness, instance, ds, strlen(ds));
        uint64_t t1 = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "voleith_gf8_prove failed\n");
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
        int rc = voleith_gf8_verify(&kept, params, c, instance, ds, strlen(ds));
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
