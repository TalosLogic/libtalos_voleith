/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_v3_attribute_gf8.c - V3 attribute ring signature.
 *
 * Statement: "I am one of N enrolled members, my leaf commits to a hidden
 * attribute `age`, and I prove age is in the public range [18, 120] without
 * revealing it."  The bounds are per-signature public inputs, so one ring
 * (fixed leaf format) supports many thresholds.
 *
 * Demonstration:
 *   1. Enroll an 8-member depth-3 ring; each member's leaf is
 *      OWF(sk || age).
 *   2. Sign as a member with age = 37, proving age in [18, 120].
 *   3. Verify; show that the same signer fails at sign time when the public
 *      range excludes the true age (predicate violation caught up front).
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
     * The node hash sets the Merkle collision resistance (Hirose-AES-256
     * and Grostl-256 = 2^128, Grostl-512 = 2^256); the param set sets the
     * proof soundness (em_128f = 128-bit, em_256f = 256-bit).  Upgrade
     * both together for a coherent 256-bit system.  The leaf preimage is
     * OWF(sk || age), so sk_bytes + attr_bytes must fit the hash's
     * single-compression block (Grostl-256 = 64, Grostl-512 = 128;
     * Hirose is variable-length).
     * =================================================================
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose;
    const size_t sk_bytes = 16;
    voleith_params_t params = voleith_params_em_128f;

    const size_t depth_m = 3;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t W = vt->node_bytes;
    const size_t signer = 2;
    const size_t attr_bytes = 4; /* one little-endian "age" field */
    int ok = 1;

    static const voleith_rs_attr_field_t fields[] = {
        {4, VOLEITH_RS_ATTR_PRED_RANGE},
    };
    voleith_rs_attr_schema_t schema = {fields, 1};
    voleith_rs_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.membership.tree_hash = vt;
    cfg.membership.sk_bytes = sk_bytes;
    cfg.membership.depth_m = depth_m;
    cfg.attr_schema = &schema;

    printf("=== V3 attribute ring signature ===\n");
    printf("Ring:    %zu members, depth %zu\n", n_members, depth_m);
    printf("Hash:    %s (leaf = OWF(sk || age), node_bytes = %zu, 2^%zu CR)\n",
           vt->name, W, vt->cr_bits);
    printf("Signer:  member #%zu, hidden age = 37, proving age in [18,120]\n\n",
           signer);

    /* 1. Enroll: member i has age 30 + i. */
    uint8_t *sks = calloc(n_members, sk_bytes);
    uint8_t *attrs = calloc(n_members, attr_bytes);
    uint8_t root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    voleith_rs_path_t *paths = calloc(n_members, sizeof(*paths));
    uint8_t *sib = calloc(n_members, depth_m * W);
    if (sks == NULL || attrs == NULL || paths == NULL || sib == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    for (size_t i = 0; i < n_members; i++) {
        for (size_t j = 0; j < sk_bytes; j++)
            sks[i * sk_bytes + j] = (uint8_t)(i * 31u + j * 7u + 0x11u);
        attrs[i * attr_bytes] = (uint8_t)(30 + i); /* age */
    }
    if (voleith_rs_ring_build(&cfg, sks, attrs, n_members, root, paths, sib) !=
        0) {
        fprintf(stderr, "ring_build failed\n");
        return 1;
    }

    const uint8_t *sk = sks + signer * sk_bytes;
    const uint8_t *attr = attrs + signer * attr_bytes;
    printf("(signer's true age = %u)\n\n", attr[0]);

    /* 2. Sign proving age in [18, 120]. */
    const uint8_t m[] = "V3 example: prove adult, hide exact age";
    size_t m_len = sizeof(m) - 1;
    uint8_t bounds_ok[8] = {18, 0, 0, 0, 120, 0, 0, 0};

    voleith_rs_path_t path = paths[signer];
    voleith_rs_public_t pub;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.bounds = bounds_ok;
    pub.bounds_len = sizeof(bounds_ok);

    voleith_rs_sig_t sig = {NULL, 0};
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc =
        voleith_rs_sign(&sig, &cfg, &params, sk, attr, &path, &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    printf("Sign:    %zu proof bytes in %.2f ms\n", sig.len,
           elapsed_ms(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int v = voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Verify:  %s in %.2f ms (age proven in range, value hidden)\n",
           v == 0 ? "PASS" : "FAIL", elapsed_ms(t0, t1));
    ok = ok && v == 0;
    voleith_rs_sig_free(&sig);

    /* 3. Predicate violation: a public range that excludes age 37 fails at
     * sign (the prover never produces a proof for a false statement). */
    uint8_t bounds_bad[8] = {40, 0, 0, 0, 120, 0, 0, 0};
    pub.bounds = bounds_bad;
    rc = voleith_rs_sign(&sig, &cfg, &params, sk, attr, &path, &pub, m, m_len);
    printf("Policy:  signing age in [40,120] -> %s (expected REJECT)\n",
           rc == -1 ? "REJECT at sign" : "produced a proof?!");
    ok = ok && rc == -1;
    voleith_rs_sig_free(&sig);

    free(sks);
    free(attrs);
    free(paths);
    free(sib);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
