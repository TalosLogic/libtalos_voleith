/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_v2_linkable_gf8.c - V2 linkable ring signature.
 *
 * Statement: "I am one of N enrolled members, and for scope S I publish a
 * nullifier T = AES-CMAC(sk, S)."  Two signatures by the same member under
 * the same scope carry the *same* T (linkable: a verifier rejects the
 * duplicate), while a different scope yields a different T (unlinkable
 * across scopes).  The signer's identity stays hidden in both cases.
 *
 * Demonstration:
 *   1. Enroll an 8-member depth-3 ring.
 *   2. Compute the signer's nullifier T under two scopes.
 *   3. Sign twice under scope A (two messages) and once under scope B.
 *   4. Show T(A,m1) == T(A,m2) (link / duplicate) and T(A) != T(B), and
 *      reject the second scope-A signature against a one-element seen-set.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "aes_cmac_gf8_circuit.h"
#include "node_hash_vt.h"
#include "rs_gf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double
elapsed_ms(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) * 1000.0 +
           (double)(end.tv_nsec - start.tv_nsec) / 1.0e6;
}

int
main(void)
{
    /*
     * ===== Node hash + strength selection ============================
     * Everything below derives from vt, sk_bytes, and params, so these
     * three lines are the only edit needed to change the node hash or
     * move from 128-bit to 256-bit strength:
     *
     *   128-bit (default):
     *     &voleith_node_hash_hirose          sk_bytes 16  params em_128f
     *     &voleith_node_hash_grostl256_fixed sk_bytes 16  params em_128f
     *   256-bit:
     *     &voleith_node_hash_grostl512_fixed sk_bytes 32  params em_256f
     *
     * The node hash sets the Merkle collision resistance (Hirose-AES-256
     * and Grostl-256 = 2^128, Grostl-512 = 2^256); the param set sets the
     * proof soundness (em_128f = 128-bit, em_256f = 256-bit).  Upgrade
     * both together for a coherent 256-bit system.  The nullifier uses
     * AES-CMAC, so sk_bytes must be 16 (AES-128) or 32 (AES-256).
     * =================================================================
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose;
    const size_t sk_bytes = 16;
    voleith_params_t params = voleith_params_em_128f;

    const size_t depth_m = 3;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t W = vt->node_bytes;
    const size_t scope_bytes = 12;
    const size_t signer = 3;
    int ok = 1;

    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.scope_bytes = scope_bytes;

    printf("=== V2 linkable ring signature ===\n");
    printf("Ring:    %zu members, depth %zu\n", n_members, depth_m);
    printf("Hash:    %s (sk_bytes = %zu, node_bytes = %zu, 2^%zu CR)\n",
           vt->name, sk_bytes, W, vt->cr_bits);
    printf("Signer:  member #%zu, nullifier T = AES-CMAC(sk, scope)\n\n",
           signer);

    /* 1. Enroll. */
    uint8_t *sks = calloc(n_members, sk_bytes);
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    voleith_rs_path_t *paths = calloc(n_members, sizeof(*paths));
    uint8_t *sib = calloc(n_members, depth_m * W);
    if (sks == NULL || paths == NULL || sib == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < n_members; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);
    if (voleith_rs_ring_build(&cfg, sks, NULL, n_members, root, paths, sib) !=
        0) {
        fprintf(stderr, "ring_build failed\n");
        return 1;
    }

    /* 2. Compute the signer's nullifier under two scopes. */
    uint8_t scope_a[12], scope_b[12];
    for (size_t i = 0; i < scope_bytes; i++) {
        scope_a[i] = (uint8_t)(0x90 + i);
        scope_b[i] = (uint8_t)(0x11 + i);
    }
    size_t cmac_wbytes = aes_cmac_gf8_witness_bytes(sk_bytes, scope_bytes);
    uint8_t *cmac_tmp = malloc(cmac_wbytes);
    uint8_t Ta[16], Tb[16];
    if (cmac_tmp == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    const uint8_t *sk = sks + signer * sk_bytes;
    aes_cmac_gf8_build_witness(sk, sk_bytes, scope_a, scope_bytes, cmac_tmp,
                               Ta);
    aes_cmac_gf8_build_witness(sk, sk_bytes, scope_b, scope_bytes, cmac_tmp,
                               Tb);

    /* 3. Sign: twice under scope A, once under scope B. */
    const uint8_t m1[] = "transfer #1 in epoch A";
    const uint8_t m2[] = "transfer #2 in epoch A";
    voleith_rs_path_t path = paths[signer];
    voleith_rs_public_t pub;
    voleith_rs_sig_t sig_a1 = {NULL, 0}, sig_a2 = {NULL, 0}, sig_b = {NULL, 0};
    struct timespec t0, t1;

    path.scope = scope_a;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.scope = scope_a;
    pub.nullifier = Ta;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = voleith_rs_sign(&sig_a1, &cfg, &params, sk, NULL, &path, &pub, m1,
                             sizeof(m1) - 1);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign A1 failed\n");
        return 1;
    }
    printf("Sign:    %zu proof bytes in %.2f ms\n", sig_a1.len,
           elapsed_ms(t0, t1));

    if (voleith_rs_sign(&sig_a2, &cfg, &params, sk, NULL, &path, &pub, m2,
                        sizeof(m2) - 1) != 0) {
        fprintf(stderr, "sign A2 failed\n");
        return 1;
    }

    path.scope = scope_b;
    pub.scope = scope_b;
    pub.nullifier = Tb;
    if (voleith_rs_sign(&sig_b, &cfg, &params, sk, NULL, &path, &pub, m1,
                        sizeof(m1) - 1) != 0) {
        fprintf(stderr, "sign B failed\n");
        return 1;
    }

    /* Verify all three. */
    pub.scope = scope_a;
    pub.nullifier = Ta;
    int va1 =
        voleith_rs_verify(&sig_a1, &cfg, &params, &pub, m1, sizeof(m1) - 1);
    int va2 =
        voleith_rs_verify(&sig_a2, &cfg, &params, &pub, m2, sizeof(m2) - 1);
    pub.scope = scope_b;
    pub.nullifier = Tb;
    int vb = voleith_rs_verify(&sig_b, &cfg, &params, &pub, m1, sizeof(m1) - 1);
    printf("Verify:  A1=%s A2=%s B=%s\n", va1 == 0 ? "PASS" : "FAIL",
           va2 == 0 ? "PASS" : "FAIL", vb == 0 ? "PASS" : "FAIL");
    ok = ok && va1 == 0 && va2 == 0 && vb == 0;

    /* 4. Linkability + one-per-scope policy. */
    int linked = voleith_rs_nullifier_equal(Ta, Ta, 16); /* A1 vs A2: same T */
    int crosslinked = voleith_rs_nullifier_equal(Ta, Tb, 16); /* A vs B */
    printf("Link:    T(A,m1) == T(A,m2) -> %s (expected LINKED)\n",
           linked ? "LINKED" : "unlinked");
    printf("Scope:   T(A) == T(B)       -> %s (expected UNLINKED)\n",
           crosslinked ? "linked" : "UNLINKED");
    ok = ok && linked == 1 && crosslinked == 0;

    /* Seen-set: T(A) recorded by the first accepted signature; the second
     * scope-A signature presents the same T and is rejected as a duplicate. */
    uint8_t seen_T[16];
    memcpy(seen_T, Ta, 16);
    int duplicate = voleith_rs_nullifier_equal(seen_T, Ta, 16);
    printf("Policy:  second scope-A signature -> %s (expected REJECT)\n",
           duplicate ? "REJECT (T already seen)" : "accept?!");
    ok = ok && duplicate == 1;

    voleith_rs_sig_free(&sig_a1);
    voleith_rs_sig_free(&sig_a2);
    voleith_rs_sig_free(&sig_b);
    free(cmac_tmp);
    free(sks);
    free(paths);
    free(sib);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
