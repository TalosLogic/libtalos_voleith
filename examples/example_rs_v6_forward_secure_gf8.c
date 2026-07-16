/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_v6_forward_secure_gf8.c - V6 forward-secure ring signature.
 *
 * Statement: "I am one of N enrolled members and I am signing in the
 * current epoch t, using a key that stops existing the moment I advance
 * past t."  Each identity carries a GGM epoch tree; its ring leaf is the
 * epoch-tree root, and signing at epoch t proves in-circuit that the
 * per-epoch seed sk_t hashes into that root at position t (the public
 * epoch directions are the bits of t).  Advancing the signer's state
 * zeroizes every seed that could reach a retired epoch, so a key captured
 * at epoch t cannot sign for any t' < t.
 *
 * Demonstration:
 *   1. Enroll an 8-member depth-3 ring; each leaf is one identity's epoch
 *      root (depth_e = 10, so 1024 epochs per identity).
 *   2. Sign as a member at epoch 0; verify.
 *   3. Advance the signer's state to epoch 5; sign at epoch 5; verify.
 *   4. Attempt to sign for epoch 0 after advancing: the API refuses (the
 *      seed for epoch 0 no longer exists in the state).
 *   5. Apply a verifier epoch-window policy: a signature whose epoch falls
 *      outside the application's accepted window is rejected before the
 *      cryptographic check even runs.
 *   6. Print circuit size (ell), proof size, and serialized state size.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "rs_epoch_gf8.h"
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

/*
 * Verifier epoch-window policy (design 8.4): the application, not the
 * library, decides which epochs it currently accepts.  A signature must
 * both fall inside [win_lo, win_hi] and pass voleith_rs_verify.  The window
 * check is public (pub->epoch is a public input), so it runs first and
 * rejects out-of-window epochs without spending a verification.
 */
static int
verify_in_window(const voleith_rs_sig_t *sig, const voleith_rs_config_t *cfg,
                 const voleith_params_t *params, const voleith_rs_public_t *pub,
                 const uint8_t *m, size_t m_len, uint64_t win_lo,
                 uint64_t win_hi)
{
    if (pub->epoch < win_lo || pub->epoch > win_hi)
        return -1; /* outside the accepted epoch window */
    return voleith_rs_verify(sig, cfg, params, pub, m, m_len);
}

int
main(void)
{
    /*
     * ===== Node hash + strength selection ============================
     * Everything below derives from vt, epoch_sk_bytes, and params.  To
     * move to 256-bit strength, upgrade all three together:
     *
     *   128-bit (default):
     *     &voleith_node_hash_hirose          epoch_sk 16  params em_128f
     *   256-bit:
     *     &voleith_node_hash_grostl512_fixed epoch_sk 32  params em_256f
     *
     * Under V6 the membership leaf IS the epoch-tree root, so
     * membership.sk_bytes is 0: the identity secret lives entirely in the
     * epoch key schedule, not in a static per-member key.
     * =================================================================
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose;
    const size_t epoch_sk_bytes = 16;
    voleith_params_t params = voleith_params_em_128f;

    const size_t depth_m = 3;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t depth_e = 10; /* 1024 epochs per identity (design Q6) */
    const size_t W = vt->node_bytes;
    const size_t signer = 2;
    int ok = 1;

    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = 0; /* V6: leaf = epoch root, no static sk */
    cfg.membership.depth_m = depth_m;
    cfg.depth_e = depth_e;
    cfg.epoch_sk_bytes = epoch_sk_bytes;

    printf("=== V6 forward-secure ring signature ===\n");
    printf("Ring:    %zu members, depth %zu\n", n_members, depth_m);
    printf("Epochs:  2^%zu = %llu per identity (leaf = epoch-tree root)\n",
           depth_e, (unsigned long long)1u << depth_e);
    printf("Hash:    %s (node_bytes = %zu, 2^%zu CR)\n", vt->name, W,
           vt->cr_bits);
    printf("Signer:  member #%zu\n\n", signer);

    /*
     * 1. Enroll.  Each member is an independent identity: keygen builds its
     * epoch tree and returns the root, which becomes the member's ring
     * leaf.  Only the signer's forward-secure state is retained; the other
     * seven states are cleared immediately (we keep just their public
     * roots).
     */
    uint8_t *leaves = calloc(n_members, W); /* epoch roots = ring leaves */
    uint8_t *msibs = calloc(depth_m, W);
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    voleith_rs_epoch_state_t signer_state;
    memset(&signer_state, 0, sizeof(signer_state));
    if (leaves == NULL || msibs == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    for (size_t i = 0; i < n_members; i++) {
        uint8_t master[VOLEITH_RS_EPOCH_SEED_MAX_BYTES];
        for (size_t j = 0; j < epoch_sk_bytes; j++)
            master[j] = (uint8_t)(i * 37u + j * 11u + 0x05u);

        if (i == signer) {
            if (voleith_rs_epoch_keygen(&cfg, master, NULL, &signer_state,
                                        leaves + i * W) != 0) {
                fprintf(stderr, "signer keygen failed\n");
                return 1;
            }
        } else {
            voleith_rs_epoch_state_t tmp;
            memset(&tmp, 0, sizeof(tmp));
            if (voleith_rs_epoch_keygen(&cfg, master, NULL, &tmp,
                                        leaves + i * W) != 0) {
                fprintf(stderr, "member %zu keygen failed\n", i);
                return 1;
            }
            voleith_rs_epoch_state_clear(&tmp); /* keep only the public root */
        }
    }

    /* Build the membership tree over the eight epoch roots. */
    if (voleith_merkle_vt_build(vt, leaves, n_members, root) != 0 ||
        voleith_merkle_vt_compute_path(vt, leaves, n_members, signer, msibs) !=
            0) {
        fprintf(stderr, "membership tree build failed\n");
        return 1;
    }

    voleith_rs_path_t path;
    memset(&path, 0, sizeof(path));
    path.membership.leaf_index = signer;
    path.membership.siblings = msibs;

    voleith_rs_public_t pub;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;

    const uint8_t m[] = "V6 example: forward-secure ring membership";
    size_t m_len = sizeof(m) - 1;

    /* 2. Sign at epoch 0. */
    pub.epoch = 0;
    voleith_rs_sig_t sig0 = {NULL, 0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = voleith_rs_epoch_sign(&sig0, &signer_state, &cfg, &params, NULL,
                                   &path, &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign@0 failed\n");
        return 1;
    }
    printf("Sign@0:  %zu proof bytes in %.2f ms\n", sig0.len,
           elapsed_ms(t0, t1));
    int v0 = voleith_rs_verify(&sig0, &cfg, &params, &pub, m, m_len);
    printf("Verify:  %s\n", v0 == 0 ? "PASS" : "FAIL");
    ok = ok && v0 == 0;

    /* 3. Advance the signer's state to epoch 5, then sign at epoch 5. */
    if (voleith_rs_epoch_state_advance(&signer_state, 5) != 0) {
        fprintf(stderr, "advance to epoch 5 failed\n");
        return 1;
    }
    pub.epoch = 5;
    voleith_rs_sig_t sig5 = {NULL, 0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = voleith_rs_epoch_sign(&sig5, &signer_state, &cfg, &params, NULL, &path,
                               &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign@5 failed\n");
        return 1;
    }
    printf("\nSign@5:  %zu proof bytes in %.2f ms (state advanced to t=5)\n",
           sig5.len, elapsed_ms(t0, t1));
    int v5 = voleith_rs_verify(&sig5, &cfg, &params, &pub, m, m_len);
    printf("Verify:  %s\n", v5 == 0 ? "PASS" : "FAIL");
    ok = ok && v5 == 0;

    /* 4. Forward security: signing for the retired epoch 0 is refused, the
     * seed sk_0 no longer exists in the advanced state. */
    voleith_rs_public_t pub_old = pub;
    pub_old.epoch = 0;
    voleith_rs_sig_t sig_old = {NULL, 0};
    rc = voleith_rs_epoch_sign(&sig_old, &signer_state, &cfg, &params, NULL,
                               &path, &pub_old, m, m_len);
    printf("\nForward: signing retired epoch 0 (state at t=5) -> %s "
           "(expected REFUSE)\n",
           rc == -1 ? "REFUSE (key erased)" : "produced a proof?!");
    ok = ok && rc == -1;

    /* 5. Verifier epoch-window policy.  The application accepts only epochs
     * [4, 8].  The epoch-5 signature is inside the window; if the verifier
     * instead ran with a window of [6, 8] the same valid proof would be
     * rejected up front for being out of window. */
    pub.epoch = 5;
    int win_ok = verify_in_window(&sig5, &cfg, &params, &pub, m, m_len, 4, 8);
    int win_reject =
        verify_in_window(&sig5, &cfg, &params, &pub, m, m_len, 6, 8);
    printf("\nWindow:  epoch 5 in [4,8]   -> %s (expected ACCEPT)\n",
           win_ok == 0 ? "ACCEPT" : "reject?!");
    printf("Window:  epoch 5 in [6,8]   -> %s (expected REJECT: out of "
           "window)\n",
           win_reject != 0 ? "REJECT" : "accepted?!");
    ok = ok && win_ok == 0 && win_reject != 0;

    /* 6. Sizes. */
    size_t state_len = voleith_rs_epoch_state_serialized_len(&signer_state);
    printf("\nSizes:   proof %zu bytes, serialized state %zu bytes\n", sig5.len,
           state_len);

    voleith_rs_sig_free(&sig0);
    voleith_rs_sig_free(&sig5);
    voleith_rs_sig_free(&sig_old);
    voleith_rs_epoch_state_clear(&signer_state);
    free(leaves);
    free(msibs);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
