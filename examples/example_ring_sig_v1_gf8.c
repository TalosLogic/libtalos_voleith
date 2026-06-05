/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_ring_sig_v1_gf8.c - RSv1 ring signature, no revocation.
 *
 * Statement: "I am one of N enrolled members in the ring whose root is R
 * (depth-d binary Merkle tree under the chosen node hash), and I am
 * binding the message m to this signature via Fiat-Shamir."
 *
 * vt / depth selection: edit the cfg struct at the top of main().  All
 * buffer sizes downstream are derived from `cfg.tree_hash->node_bytes`
 * and `cfg.depth_m`; swapping in any wrapped voleith_node_hash_vt
 * (`voleith_node_hash_aes_dm`, `voleith_node_hash_hirose`,
 * `voleith_node_hash_grostl256`, ...) and any depth in
 * [1, VOLEITH_RS_MEMBERSHIP_MAX_DEPTH] should "just work".  For
 * fixed-leaf vts (currently only hirose_fixed32) set cfg.sk_bytes ==
 * vt->fixed_leaf_bytes; variable-leaf vts accept any sk_bytes >= 1.
 *
 * Demonstration outline:
 *   1. Enroll N members with deterministic test sks; build the
 *      membership tree via voleith_rsv1_ring_build.
 *   2. Sign as the chosen signer over a message; report sizes and
 *      timings.
 *   3. Pack + unpack the on-the-wire signature via voleith_ring_sig_pack/
 *      voleith_ring_sig_unpack; verify on the unpacked sig.
 *   4. Tamper one byte of m; verify rejects (Fiat-Shamir non-malleability).
 *
 * Returns 0 on full success, nonzero on any unexpected failure.  Suitable
 * as a CI smoke test for the RSv1 layer.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"

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
     * Edit this cfg + signer index to swap node hash, ring shape, or
     * signing member.  Everything downstream derives from these.
     */
    voleith_rs_membership_config_t cfg = {
        .tree_hash = &voleith_node_hash_hirose_fixed32,
        .owf_hash = NULL,
        .sk_bytes = 32, /* matches hirose_fixed32 node_bytes */
        .depth_m = 5,
        .depth_r = 0,
    };
    voleith_params_t params = voleith_params_em_128f;
    const size_t signer = 5;

    /*
     * If the OWF vt is fixed-leaf (e.g. hirose_fixed32), its
     * fixed_leaf_bytes overrides cfg.sk_bytes so the example "just
     * works" when the user swaps the vt without updating sk_bytes.
     * Variable-leaf vts (fixed_leaf_bytes == 0) keep the cfg value.
     */
    {
        const voleith_node_hash_vt *owf_vt =
            cfg.owf_hash ? cfg.owf_hash : cfg.tree_hash;
        if (owf_vt->fixed_leaf_bytes != 0)
            cfg.sk_bytes = owf_vt->fixed_leaf_bytes;
    }

    const size_t W = cfg.tree_hash->node_bytes;
    const size_t sk_bytes = cfg.sk_bytes;
    const size_t depth_m = cfg.depth_m;
    const size_t n_members = (size_t)1u << depth_m;

    printf("=== RSv1 ring signature (no revocation) ===\n");
    printf("Ring:    %zu members, depth %zu (capacity 2^%zu = %zu)\n",
           n_members, depth_m, depth_m, n_members);
    printf("Hash:    %s (sk_bytes = %zu, node_bytes = %zu)\n",
           cfg.tree_hash->name, sk_bytes, W);
    printf("Signer:  member #%zu\n\n", signer);

    /* ------------------------------------------------------------------ */
    /* 1. Enroll members                                                    */
    /* ------------------------------------------------------------------ */
    uint8_t *sks = calloc(n_members, sk_bytes);
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    voleith_rs_membership_path_t *paths = calloc(n_members, sizeof(*paths));
    uint8_t *sib_storage = calloc(n_members, depth_m * W);
    if (sks == NULL || paths == NULL || sib_storage == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < n_members; i++)
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);

    if (voleith_rsv1_ring_build(&cfg, sks, n_members, root, paths,
                                sib_storage) != 0) {
        fprintf(stderr, "ring_build failed\n");
        return 1;
    }

    printf("Enrolled %zu members; membership root (%zu bytes): ", n_members, W);
    for (size_t i = 0; i < W; i++)
        printf("%02x", root[i]);
    printf("\n\n");

    /* ------------------------------------------------------------------ */
    /* 2. Sign as the chosen member                                         */
    /* ------------------------------------------------------------------ */
    const uint8_t m[] = "RSv1 example: signed over a fixed message.";
    size_t m_len = sizeof(m) - 1;
    voleith_ring_sig_t sig = {NULL, 0};
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = voleith_rsv1_sign(&sig, &cfg, &params, sks + signer * sk_bytes,
                               root, &paths[signer], NULL, NULL, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    printf("Sign:    %zu raw proof bytes in %.2f ms\n", sig.len,
           elapsed_ms(t0, t1));

    /* ------------------------------------------------------------------ */
    /* 3. Pack + unpack the on-the-wire envelope                            */
    /* ------------------------------------------------------------------ */
    size_t packed_len = voleith_ring_sig_packed_len(&sig);
    uint8_t *packed = malloc(packed_len);
    if (packed == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    if (voleith_ring_sig_pack(packed, packed_len, NULL, &sig, &cfg, &params) !=
        0) {
        fprintf(stderr, "ring_sig_pack failed\n");
        return 1;
    }
    printf("Pack:    %zu wire bytes (= %zu header + %zu proof)\n", packed_len,
           (size_t)VOLEITH_RING_SIG_HEADER_BYTES, sig.len);

    voleith_ring_sig_t unpacked = {NULL, 0};
    if (voleith_ring_sig_unpack(&unpacked, packed, packed_len, &cfg, &params) !=
        0) {
        fprintf(stderr, "ring_sig_unpack failed\n");
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 4. Verify the unpacked signature                                     */
    /* ------------------------------------------------------------------ */
    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = voleith_rsv1_verify(&unpacked, &cfg, &params, root, NULL, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Verify:  %s in %.2f ms\n", rc == 0 ? "PASS" : "FAIL",
           elapsed_ms(t0, t1));
    if (rc != 0) {
        voleith_ring_sig_free(&sig);
        voleith_ring_sig_free(&unpacked);
        free(packed);
        free(sks);
        free(paths);
        free(sib_storage);
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 5. Tamper detection: flip one bit of m, verify must reject           */
    /* ------------------------------------------------------------------ */
    uint8_t bad_m[sizeof(m)];
    memcpy(bad_m, m, m_len);
    bad_m[0] ^= 0x01;
    rc =
        voleith_rsv1_verify(&unpacked, &cfg, &params, root, NULL, bad_m, m_len);
    printf("Tamper:  verify on flipped m -> %s (expected REJECT)\n",
           rc == -1 ? "REJECT" : "ACCEPT?!");
    int tamper_ok = (rc == -1);

    voleith_ring_sig_free(&sig);
    voleith_ring_sig_free(&unpacked);
    free(packed);
    free(sks);
    free(paths);
    free(sib_storage);
    return tamper_ok ? 0 : 1;
}
