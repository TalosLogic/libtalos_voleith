/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_v4_claimable_gf8.c - V4 claimable ring signature.
 *
 * Statement: "I am one of N enrolled members, and I bind a hiding
 * commitment C = H(id || rand) into this signature."  Later the signer can
 * reveal the opening (id, rand) to claim authorship of *this* signature,
 * since C is bound into its Fiat-Shamir transcript.  Without the opening
 * (specifically without rand) the signature stays anonymous.
 *
 * Demonstration:
 *   1. Enroll an 8-member depth-3 ring.
 *   2. Sign as a member, binding C = H(id || rand).
 *   3. Produce a claim from (id, rand) and verify it against C.
 *   4. Show non-transferability: the claim does not open a different C.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

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
     * The node hash sets the commitment binding strength (Hirose-AES-256
     * and Grostl-256 = 2^128, Grostl-512 = 2^256); the param set sets the
     * proof soundness (em_128f = 128-bit, em_256f = 256-bit).  The
     * commitment handle id and blinding rand are sk_bytes wide (= lambda),
     * so they scale with the chosen strength.
     * =================================================================
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose;
    const size_t sk_bytes = 16;
    voleith_params_t params = voleith_params_em_128f;

    const size_t depth_m = 3;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t W = vt->node_bytes;
    const size_t commit_bytes = sk_bytes; /* id and rand width = lambda */
    const size_t signer = 6;
    int ok = 1;

    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = commit_bytes;
    cfg.commit_rand_bytes = commit_bytes;

    printf("=== V4 claimable ring signature ===\n");
    printf("Ring:    %zu members, depth %zu\n", n_members, depth_m);
    printf("Hash:    %s (C = H(id || rand), node_bytes = %zu, 2^%zu CR)\n",
           vt->name, W, vt->cr_bits);
    printf("Signer:  member #%zu binds C; can later claim authorship\n\n",
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

    /* The signer's commitment opening (id and rand are commit_bytes wide). */
    uint8_t id[MERKLE_VT_MAX_NODE_BYTES], rand[MERKLE_VT_MAX_NODE_BYTES];
    for (size_t i = 0; i < commit_bytes; i++) {
        id[i] = (uint8_t)(0xA0 + i);
        rand[i] = (uint8_t)(0x5C - i);
    }
    voleith_rs_claim_t claim;
    if (voleith_rs_claim_produce(&cfg, id, rand, &claim) != 0) {
        fprintf(stderr, "claim_produce failed\n");
        return 1;
    }
    const uint8_t *C = claim.commitment; /* the C the signer will bind */

    /* 2. Sign, binding C. */
    const uint8_t m[] = "V4 example: anonymous now, claimable later";
    size_t m_len = sizeof(m) - 1;
    const uint8_t *sk = sks + signer * sk_bytes;
    voleith_rs_path_t path = paths[signer];
    path.commit_id = id;
    path.commit_rand = rand;
    voleith_rs_public_t pub;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.commitment = C;

    voleith_rs_sig_t sig = {NULL, 0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc =
        voleith_rs_sign(&sig, &cfg, &params, sk, NULL, &path, &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    printf("Sign:    %zu proof bytes in %.2f ms\n", sig.len,
           elapsed_ms(t0, t1));
    int v = voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len);
    printf("Verify:  %s (commitment bound into transcript)\n",
           v == 0 ? "PASS" : "FAIL");
    ok = ok && v == 0;

    /* 3. Claim authorship: reveal (id, rand), check against the signature's
     * bound C (which the verifier already holds in pub.commitment). */
    int claimed = voleith_rs_claim_verify(&cfg, pub.commitment, id, rand);
    printf("Claim:   open (id, rand) against bound C -> %s (expected VALID)\n",
           claimed == 0 ? "VALID" : "invalid?!");
    ok = ok && claimed == 0;

    /* 4. Non-transferability: a different signature's C is not opened by the
     * same (id, rand). */
    uint8_t other_C[MERKLE_VT_MAX_NODE_BYTES];
    memcpy(other_C, C, W);
    other_C[0] ^= 0x01;
    int crossclaim = voleith_rs_claim_verify(&cfg, other_C, id, rand);
    printf("Bind:    claim against another signature's C -> %s "
           "(expected REJECT)\n",
           crossclaim == -1 ? "REJECT" : "accept?!");
    ok = ok && crossclaim == -1;

    voleith_rs_sig_free(&sig);
    free(sks);
    free(paths);
    free(sib);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
