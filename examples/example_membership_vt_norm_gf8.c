/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_membership_vt_norm_gf8.c - frozen vs norm node hashes in a real
 * Merkle membership proof, across the node-hash choices a deployment would
 * actually pick.
 *
 * A depth-10 ring-membership circuit (prove "I am a member of the tree with
 * root R" without revealing which leaf) is built on the node_hash_vt layer,
 * which lets the LEAF hash (owf_hash) and the internal-NODE hash (tree_hash)
 * be chosen independently.  Each configuration is proven once with the frozen
 * S-box and once with the FAEST paired-round norm S-box; the node output is
 * identical, so the Merkle root is the same, only the witness/circuit differ.
 * Run it to compare witness bytes, proof size, and prove/verify time per
 * configuration (bench_util.h documents the timing methodology).
 *
 * The four configurations, and why a deployment picks each:
 *
 *   1. pure Hirose (leaf + node): one AES-based primitive, 128-bit collision
 *      resistance, double-block-length.  Simplest single-primitive choice.
 *
 *   2. MIX: Grostl-256 leaf + Hirose node.  The leaf preimage can be wide
 *      (secret key || attributes), and Hirose charges per 16-byte message
 *      block: a 64-byte leaf is ~4 Hirose blocks (~2000 witness slots frozen),
 *      whereas Grostl-256 absorbs 64 bytes in a single compression (~1920
 *      slots).  But the Hirose *node* hashes a fixed two-child input and folds
 *      the left child into one block-half and the right into the other, so an
 *      inode stays ~2 blocks (~1000 slots) - cheaper than a Grostl-256 inode.
 *      So: Grostl-256 for the wide leaf, Hirose for the cheap fixed node.
 *      (The printed witness counts below are the authoritative figures; the
 *      slot numbers here are the design intuition.)
 *
 *   3. pure Grostl-256 (leaf + node): all-Grostl, 128-bit.  Chosen when a
 *      deployment wants to avoid Hirose entirely because its security margin
 *      against quantum (free-start) collision attacks is narrower under
 *      certain analyses (see the Hirose posture note in DESIGN.md); Grostl
 *      sidesteps that class of concern.
 *
 *   4. pure Grostl-512 (leaf + node): the only 256-bit-collision-resistant
 *      configuration here (64-byte nodes).  Heaviest to prove; use when
 *      256-bit security is required.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC (via bench_util.h) */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"
#include "rs_membership_gf8.h"
#include "rs_membership_gf8_circuit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench_util.h"

#define DEPTH 10
#define N_MEMBERS 8u /* real members; the rest of the 2^10 tree is sentinel. */
#define SIGNER 5u

/* Depth-10 proofs are heavier than the AES example, so fewer iterations. */
#define BENCH_WARMUP 1
#define BENCH_PROVE_ITERS 5
#define BENCH_VERIFY_ITERS 20

static int
bench_report(const char *label, voleith_gf8_circuit_t *c,
             const uint8_t *witness, const uint8_t *instance)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t ell = voleith_gf8_qs_ell(c);
    size_t wlen = voleith_gf8_circuit_witness_byte_len(c);
    size_t ilen = voleith_gf8_circuit_instance_byte_len(c);
    double prove_ms[BENCH_PROVE_ITERS];
    double verify_ms[BENCH_VERIFY_ITERS];
    voleith_proof_t kept = {0};
    int verify_ok = 1;

    printf("    [%s]\n", label);
    printf("      witness bytes: %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("      mul gates:     %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("      ell:           %zu\n", ell);
    printf("      proof bytes:   %zu\n",
           voleith_gf8_proof_byte_size(params, ell));

    for (int w = 0; w < BENCH_WARMUP; w++) {
        voleith_proof_t p = {0};
        if (voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance, ilen,
                                 label, strlen(label)) != 0) {
            fprintf(stderr, "prove failed (warmup)\n");
            return 1;
        }
        voleith_gf8_verify_v2(&p, params, c, instance, ilen, label,
                              strlen(label));
        voleith_proof_free(&p);
    }
    for (int i = 0; i < BENCH_PROVE_ITERS; i++) {
        voleith_proof_t p = {0};
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_prove_v2(&p, params, c, witness, wlen, instance,
                                      ilen, label, strlen(label));
        uint64_t t1 = bench_now_ns();
        if (rc != 0) {
            fprintf(stderr, "prove failed\n");
            return 1;
        }
        prove_ms[i] = (double)(t1 - t0) / 1e6;
        if (i == BENCH_PROVE_ITERS - 1)
            kept = p;
        else
            voleith_proof_free(&p);
    }
    for (int i = 0; i < BENCH_VERIFY_ITERS; i++) {
        uint64_t t0 = bench_now_ns();
        int rc = voleith_gf8_verify_v2(&kept, params, c, instance, ilen, label,
                                       strlen(label));
        uint64_t t1 = bench_now_ns();
        if (rc != 0)
            verify_ok = 0;
        verify_ms[i] = (double)(t1 - t0) / 1e6;
    }

    bench_stats_t ps = bench_compute(prove_ms, BENCH_PROVE_ITERS);
    bench_stats_t vs = bench_compute(verify_ms, BENCH_VERIFY_ITERS);
    printf("      proof size:    %zu bytes (verify %s)\n", kept.len,
           verify_ok ? "PASS" : "FAIL");
    bench_print("      prove", ps);
    bench_print("      verify", vs);
    printf("\n");

    voleith_proof_free(&kept);
    return verify_ok ? 0 : 1;
}

/* Build the depth-DEPTH membership circuit for (tree_vt, owf_vt) and bench it.
 * owf_vt == NULL means the leaf uses the node hash (a "pure" config). */
static int
run_config(const char *label, const voleith_node_hash_vt *tree_vt,
           const voleith_node_hash_vt *owf_vt, size_t sk_bytes)
{
    voleith_rs_membership_config_t cfg;
    voleith_rs_membership_layout_t layout;
    voleith_gf8_circuit_t *c = NULL;
    size_t W = tree_vt->node_bytes;
    uint8_t *sks = NULL, *root = NULL, *sib = NULL, *witness = NULL,
            *instance = NULL;
    voleith_rs_membership_path_t *paths = NULL;
    int rc = 1;

    cfg.tree_hash = tree_vt;
    cfg.owf_hash = owf_vt;
    cfg.sk_bytes = sk_bytes;
    cfg.depth_m = DEPTH;
    cfg.depth_r = 0;

    if (voleith_rs_membership_validate(&cfg) != 0) {
        fprintf(stderr, "%s: config rejected\n", label);
        return 1;
    }

    sks = calloc(N_MEMBERS * sk_bytes, 1);
    root = calloc(W, 1);
    paths = calloc(N_MEMBERS, sizeof(*paths));
    sib = calloc(N_MEMBERS * (size_t)DEPTH * W, 1);
    if (!sks || !root || !paths || !sib)
        goto done;
    for (size_t i = 0; i < N_MEMBERS; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    if (voleith_rsv1_ring_build(&cfg, sks, N_MEMBERS, root, paths, sib) != 0) {
        fprintf(stderr, "%s: ring_build failed\n", label);
        goto done;
    }

    c = voleith_gf8_circuit_new();
    if (c == NULL || voleith_rs_membership_build_circuit(c, &cfg, &layout) != 0)
        goto done;

    witness = calloc(layout.witness_bytes, 1);
    instance = calloc(layout.instance_bytes, 1);
    if (!witness || !instance)
        goto done;
    if (voleith_rs_membership_pack_witness(&cfg, &layout,
                                           sks + SIGNER * sk_bytes,
                                           &paths[SIGNER], NULL, witness) != 0)
        goto done;
    memcpy(instance + layout.inst_root_off, root, layout.inst_root_bytes);

    rc = bench_report(label, c, witness, instance);

done:
    if (c != NULL)
        voleith_gf8_circuit_free(c);
    free(sks);
    free(root);
    free(paths);
    free(sib);
    free(witness);
    free(instance);
    return rc;
}

int
main(void)
{
    int rc = 0;

    printf("=== Merkle membership: frozen vs norm node hashes (depth %d) ===\n",
           DEPTH);
    printf("Same root both ways; only the witness/circuit differ.\n\n");

    printf("1. pure Hirose (AES-256 double-block, 128-bit CR):\n");
    rc |= run_config("hirose-frozen", &voleith_node_hash_hirose, NULL, 32);
    rc |= run_config("hirose-norm", &voleith_node_hash_hirose_norm, NULL, 32);

    printf("2. MIX: Grostl-256 leaf + Hirose node (wide cheap leaf, cheap "
           "fixed node; 128-bit CR):\n");
    rc |= run_config("mix-frozen", &voleith_node_hash_hirose,
                     &voleith_node_hash_grostl256_fixed, 32);
    rc |= run_config("mix-norm", &voleith_node_hash_hirose_norm,
                     &voleith_node_hash_grostl256_fixed_norm, 32);

    printf("3. pure Grostl-256 (all-Grostl, 128-bit CR; avoids Hirose quantum "
           "posture):\n");
    rc |= run_config("grostl256-frozen", &voleith_node_hash_grostl256_fixed,
                     NULL, 32);
    rc |= run_config("grostl256-norm", &voleith_node_hash_grostl256_fixed_norm,
                     NULL, 32);

    printf("4. pure Grostl-512 (256-bit CR; the only 256-bit config here):\n");
    rc |= run_config("grostl512-frozen", &voleith_node_hash_grostl512_fixed,
                     NULL, 64);
    rc |= run_config("grostl512-norm", &voleith_node_hash_grostl512_fixed_norm,
                     NULL, 64);

    return rc ? 1 : 0;
}
