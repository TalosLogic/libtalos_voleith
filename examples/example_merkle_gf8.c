/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_merkle_gf8.c - ZK proof of Merkle path membership (GF(2^8) circuit)
 *
 * 16-byte (128-bit) nodes hashed with Davies-Meyer AES-128: a cheap,
 * compact Merkle tree with 2^64 collision resistance.  Counterpart to
 * example_merkle_grostl_gf8.c, which uses wide Grøstl nodes for full
 * 2^128 / 2^256 collision resistance - run both at the same depth to
 * compare proof size and prover/verifier time.
 *
 * Tree: depth 5 (32 leaves), Davies-Meyer AES-128, public leaf index.
 *
 * Public  (instance): root R (16 bytes)
 * Private (witness):  leaf data + AES S-box inv_in for every AES call +
 *                     sibling hashes along the path.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "bench_util.h"

#define DEPTH 5
#define N_LEAVES (1u << DEPTH) /* 32 */
#define NODE_BYTES 16
#define LEAF_INDEX 21 /* 0b10101 - a mixed-bit path (matches Grøstl example) */

/* Benchmark iteration counts (tune as needed). */
#define BENCH_WARMUP 2
#define BENCH_PROVE_ITERS 25
#define BENCH_VERIFY_ITERS 100

static const uint8_t LEAF_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4c, 0x65, 0x61, 0x66,
                                     0x00, 0x00, 0x00, 0x00};
static const uint8_t NODE_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4e, 0x6f, 0x64, 0x65,
                                     0x00, 0x00, 0x00, 0x00};

/* DM compress: AES_key(pt) XOR pt */
static void
dm_compress(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    for (int i = 0; i < 16; i++)
        out[i] ^= pt[i];
}

static void
leaf_hash_dm(const uint8_t leaf[16], uint8_t out[16])
{
    dm_compress(LEAF_DOM, leaf, out);
}

static void
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ NODE_DOM[i];
    dm_compress(L, P, out);
}

/*
 * get_aes_inv_in - compute the 200 inv_in bytes for AES_{key}(plaintext).
 * Calls aes128_gf8_build_witness and extracts witness[16..215].
 */
static void
get_aes_inv_in(const uint8_t key[16], const uint8_t pt[16], uint8_t inv_in[200])
{
    uint8_t tmp[216];
    aes128_gf8_build_witness(key, pt, tmp, NULL);
    memcpy(inv_in, tmp + 16, 200);
}

int
main(void)
{
    printf("=== Merkle path ZK proof (GF(2^8) circuit, AES-DM nodes) ===\n");
    printf("Statement: knowledge of leaf[%u] and path s.t. Merkle path → "
           "root\n",
           LEAF_INDEX);
    printf("Tree: %u leaves (depth %u), Davies-Meyer AES-128 16-byte nodes "
           "(2^64 CR), public index\n\n",
           N_LEAVES, DEPTH);

    /* ================================================================
     * Build the depth-5 tree in software.
     *
     * leaf[i]      = a 16-byte record: {i, i+1, ..., i+15}
     * layer[0][i]  = leaf_hash_dm(leaf[i])
     * layer[k+1][j]= inode_hash_dm(layer[k][2j], layer[k][2j+1])
     * root         = layer[DEPTH][0]
     * ================================================================ */
    uint8_t leaves[N_LEAVES][NODE_BYTES];
    for (unsigned i = 0; i < N_LEAVES; i++)
        for (unsigned j = 0; j < NODE_BYTES; j++)
            leaves[i][j] = (uint8_t)(i + j);

    /* layer[k] holds (N_LEAVES >> k) nodes of NODE_BYTES each. */
    uint8_t *layer[DEPTH + 1];
    for (unsigned k = 0; k <= DEPTH; k++)
        layer[k] = malloc(((size_t)N_LEAVES >> k) * NODE_BYTES);

    for (unsigned i = 0; i < N_LEAVES; i++)
        leaf_hash_dm(leaves[i], layer[0] + (size_t)i * NODE_BYTES);

    for (unsigned k = 0; k < DEPTH; k++) {
        unsigned n_parents = N_LEAVES >> (k + 1);
        for (unsigned j = 0; j < n_parents; j++)
            inode_hash_dm(layer[k] + (size_t)(2 * j) * NODE_BYTES,
                          layer[k] + (size_t)(2 * j + 1) * NODE_BYTES,
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
     *   (1) leaf data wires, (2) leaf hash (adds leaf inv_in),
     *   (3) sibling wires,   (4) path circuit (adds inode inv_in).
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id leaf_wires[NODE_BYTES];
    for (int i = 0; i < NODE_BYTES; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id leaf_hash_wires[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_wires, NODE_BYTES,
                                 VOLEITH_MERKLE_HASH_AES_DM, leaf_hash_wires);

    gf8_wire_id *node_wires =
        malloc((size_t)DEPTH * NODE_BYTES * sizeof(*node_wires));
    for (size_t i = 0; i < (size_t)DEPTH * NODE_BYTES; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id root_computed[16];
    merkle_gf8_path_circuit(c, leaf_hash_wires, node_wires, path_dirs, DEPTH,
                            VOLEITH_MERKLE_HASH_AES_DM, root_computed);

    /* Root: 16 public instance wires; assert equal. */
    for (int i = 0; i < NODE_BYTES; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (S-box uses assert_product, not add_mul)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("    = %d leaf + 200 leaf inv_in + %u siblings + %u×200 inode "
           "inv_in\n",
           NODE_BYTES, (unsigned)(DEPTH * NODE_BYTES), DEPTH);
    printf("  Instance wires:  %zu (root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Assemble the witness in declaration order.
     *
     * For DM inode at level k:
     *   dirs[k]=0 (current LEFT):  inv_in for AES_{current}(sibling XOR NODE_DOM)
     *   dirs[k]=1 (current RIGHT): inv_in for AES_{sibling}(current XOR NODE_DOM)
     * ================================================================ */
    size_t total =
        NODE_BYTES + 200 + (size_t)DEPTH * NODE_BYTES + (size_t)DEPTH * 200;
    uint8_t *witness = calloc(total, 1);
    size_t off = 0;

    /* (1) leaf data */
    memcpy(witness + off, leaves[LEAF_INDEX], NODE_BYTES);
    off += NODE_BYTES;

    /* (2) leaf hash inv_in */
    get_aes_inv_in(LEAF_DOM, leaves[LEAF_INDEX], witness + off);
    off += 200;

    /* (3) siblings (must precede the path inv_in) */
    memcpy(witness + off, siblings, (size_t)DEPTH * NODE_BYTES);
    off += (size_t)DEPTH * NODE_BYTES;

    /* (4) per-level inode inv_in, walking the path from the leaf hash up */
    uint8_t current[16];
    leaf_hash_dm(leaves[LEAF_INDEX], current);
    for (unsigned lvl = 0; lvl < DEPTH; lvl++) {
        const uint8_t *sib = siblings + (size_t)lvl * NODE_BYTES;
        uint8_t P[16];
        uint8_t next[16];

        if (path_dirs[lvl] == 0) {
            /* current LEFT: H(current, sibling) */
            for (int i = 0; i < 16; i++)
                P[i] = sib[i] ^ NODE_DOM[i];
            get_aes_inv_in(current, P, witness + off);
            dm_compress(current, P, next);
        } else {
            /* current RIGHT: H(sibling, current) */
            for (int i = 0; i < 16; i++)
                P[i] = current[i] ^ NODE_DOM[i];
            get_aes_inv_in(sib, P, witness + off);
            dm_compress(sib, P, next);
        }
        off += 200;
        memcpy(current, next, 16);
    }

    /* Sanity: walked root must equal the tree root. */
    if (memcmp(current, root, NODE_BYTES) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        return 1;
    }

    const uint8_t *instance = root;
    const char *ds = "example_merkle_gf8:depth5-DM-leaf21";

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
