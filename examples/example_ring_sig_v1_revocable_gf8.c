/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_ring_sig_v1_revocable_gf8.c - RSv1 with revocation IMT.
 *
 * Statement: "I am one of N enrolled members in the ring (root R), my
 * leaf node is NOT recorded in the revocation IMT (root V), and I am
 * binding the message m to this signature."
 *
 * vt / depth selection: edit the cfg struct at the top of main().  All
 * buffer sizes downstream are derived from `cfg.tree_hash->node_bytes`,
 * `cfg.depth_m`, and `cfg.depth_r`; swapping in any wrapped
 * voleith_node_hash_vt and any depths in
 * [1, VOLEITH_RS_MEMBERSHIP_MAX_DEPTH] should "just work".  For
 * fixed-leaf vts set cfg.sk_bytes == vt->fixed_leaf_bytes; variable-leaf
 * vts accept any sk_bytes >= 1.
 *
 * Demonstration outline:
 *   1. Build an N-member ring at depth depth_m (same baseline as the
 *      no-revocation example).
 *   2. Build the initial revocation IMT at depth depth_r with two
 *      synthetic sentinel records that do not include any member's
 *      leaf node.
 *   3. A chosen signer produces a non-membership proof against V and
 *      signs.
 *   4. "Revoke" that signer: add their leaf node to V and rebuild.
 *      Lookup of their leaf now returns -1 (target is a member of V);
 *      they cannot produce a witness.  Another, unrevoked member's
 *      leaf is still outside V and signs successfully against the new V.
 *
 * Returns 0 on full success, nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "indexed_merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "ring_sig_v1_gf8.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define INDEX_BYTES VOLEITH_RSV1_REV_INDEX_BYTES

/*
 * One IMT record.  Value buffers are sized to MERKLE_VT_MAX_NODE_BYTES
 * so the struct works for any vt; only the first `value_bytes` bytes
 * (= vt->node_bytes) are meaningful.
 */
typedef struct {
    uint8_t value[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next_value[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next_index[INDEX_BYTES];
} rev_record_t;

static double
elapsed_ms(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) * 1000.0 +
           (double)(end.tv_nsec - start.tv_nsec) / 1.0e6;
}

/*
 * Empty (no-revocations) IMT for n_recs records.  rec[0] spans the full
 * open range [0, MAX), all later records are degenerate "max" sentinels.
 * Any signer's leaf node (a random-looking OWF output) falls into
 * rec[0]'s interval with overwhelming probability (~1 - 2 * 2^-N) where
 * N = 8 * value_bytes; the negligible failure cases are leaf == all-zero
 * or leaf == all-0xFF.
 */
static void
fill_empty_revocation_set(rev_record_t *recs, size_t n_recs, size_t value_bytes)
{
    memset(recs[0].value, 0x00, value_bytes);
    memset(recs[0].next_value, 0xFF, value_bytes);
    memset(recs[0].next_index, 0, INDEX_BYTES);
    if (n_recs > 1)
        recs[0].next_index[0] = 1;

    for (size_t i = 1; i < n_recs; i++) {
        memset(recs[i].value, 0xFF, value_bytes);
        memset(recs[i].next_value, 0xFF, value_bytes);
        memset(recs[i].next_index, 0, INDEX_BYTES);
    }
}

/*
 * Revoke `leaf` by splitting rec[0] so the boundary value lands exactly
 * at leaf:
 *   rec[0]: [0x00.., leaf)
 *   rec[1]: [leaf,   0xFF..)
 * Any subsequent lookup of `leaf` finds rec[1].value == leaf and
 * rejects (membership).  Later records (if any) remain max-sentinels.
 */
static void
revoke_one_leaf(rev_record_t *recs, size_t n_recs, size_t value_bytes,
                const uint8_t *leaf)
{
    memset(recs[0].value, 0x00, value_bytes);
    memcpy(recs[0].next_value, leaf, value_bytes);
    memset(recs[0].next_index, 0, INDEX_BYTES);
    if (n_recs > 1)
        recs[0].next_index[0] = 1;

    if (n_recs >= 2) {
        memcpy(recs[1].value, leaf, value_bytes);
        memset(recs[1].next_value, 0xFF, value_bytes);
        memset(recs[1].next_index, 0, INDEX_BYTES);
    }
    for (size_t i = 2; i < n_recs; i++) {
        memset(recs[i].value, 0xFF, value_bytes);
        memset(recs[i].next_value, 0xFF, value_bytes);
        memset(recs[i].next_index, 0, INDEX_BYTES);
    }
}

static void
records_to_imt(const rev_record_t *recs, size_t n_recs,
               voleith_imt_record_t *imt)
{
    for (size_t i = 0; i < n_recs; i++) {
        imt[i].value = recs[i].value;
        imt[i].next_value = recs[i].next_value;
        imt[i].next_index = recs[i].next_index;
    }
}

/*
 * Build V from `recs`; look up the adjacent record straddling `target`;
 * produce the revocation path bundle the signer will hand to
 * voleith_rsv1_sign.  Returns 0 on success, -1 on lookup failure
 * (target is a member of V, no non-membership proof possible).
 *
 * On success, the rev_path's pointers alias buffers owned by `recs`
 * and `siblings_storage`.  Caller must keep both alive while signing.
 */
static int
build_rev_path(const voleith_node_hash_vt *vt, const rev_record_t *recs,
               size_t n_recs, size_t value_bytes, const uint8_t *target,
               uint8_t *v_root_out, uint8_t *siblings_storage,
               voleith_rs_membership_path_t *rev_path_out)
{
    voleith_imt_record_t *imt = calloc(n_recs, sizeof(*imt));
    size_t adj_idx;
    int rc;

    if (imt == NULL)
        return -1;
    records_to_imt(recs, n_recs, imt);

    if (voleith_imt_vt_build(vt, imt, n_recs, value_bytes, INDEX_BYTES,
                             v_root_out) != 0) {
        fprintf(stderr, "imt_vt_build failed\n");
        free(imt);
        return -1;
    }
    rc = voleith_imt_vt_lookup_nonmember(vt, imt, n_recs, value_bytes,
                                         INDEX_BYTES, target, &adj_idx,
                                         siblings_storage);
    free(imt);
    if (rc != 0)
        return -1;

    memset(rev_path_out, 0, sizeof(*rev_path_out));
    rev_path_out->rev_adj_leaf_index = adj_idx;
    rev_path_out->rev_siblings = siblings_storage;
    rev_path_out->rev_low_value = recs[adj_idx].value;
    rev_path_out->rev_low_next = recs[adj_idx].next_value;
    rev_path_out->rev_next_index = recs[adj_idx].next_index;
    return 0;
}

int
main(void)
{
    /*
     * Edit this cfg + signer indices to swap node hash, ring shape,
     * revocation depth, or signing members.  Everything downstream
     * derives from these.
     *
     * The node hash MUST be variable-leaf here: a revocation IMT record is
     * value || next_value || next_index = 2*node_bytes + 8 bytes, which
     * exceeds a single compression block, so a fixed-input vt (hirose_fixed32,
     * grostl*_fixed) would reject it.  Variable-leaf options: Hirose (2^128,
     * default), the full-hash Grostl vts (grostl256 2^128, grostl512 2^256),
     * or AES-DM / AES-CMAC (2^64).
     */
    voleith_rs_membership_config_t cfg = {
        .tree_hash = &voleith_node_hash_hirose,
        .owf_hash = NULL,
        .sk_bytes =
            32, /* Hirose leaf takes any sk width; 32 = 256-bit secret */
        .depth_m = 5,
        .depth_r = 5,
    };
    voleith_params_t params = voleith_params_em_128f;
    const size_t signer_revoked = 5;
    const size_t signer_unrevoked = 2;

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

    const voleith_node_hash_vt *vt = cfg.tree_hash;
    const size_t W = vt->node_bytes;
    const size_t sk_bytes = cfg.sk_bytes;
    const size_t depth_m = cfg.depth_m;
    const size_t depth_r = cfg.depth_r;
    const size_t n_members = (size_t)1u << depth_m;
    const size_t n_recs = (size_t)1u << depth_r;

    printf("=== RSv1 ring signature with revocation ===\n");
    printf("Ring:       %zu members, depth_m %zu\n", n_members, depth_m);
    printf("Revocation: IMT depth_r %zu (%zu records, %zu-byte values)\n",
           depth_r, n_recs, W);
    printf("Hash:       %s (sk_bytes = %zu, node_bytes = %zu)\n", vt->name,
           sk_bytes, W);

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
    printf("Enrolled %zu members; membership root: ", n_members);
    for (size_t i = 0; i < W; i++)
        printf("%02x", root[i]);
    printf("\n");

    /* Compute leaf nodes for the two signers we will exercise. */
    uint8_t leaf_revoked[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t leaf_unrevoked[MERKLE_VT_MAX_NODE_BYTES];
    if (vt->leaf_hash(sks + signer_revoked * sk_bytes, sk_bytes,
                      leaf_revoked) != 0 ||
        vt->leaf_hash(sks + signer_unrevoked * sk_bytes, sk_bytes,
                      leaf_unrevoked) != 0) {
        fprintf(stderr, "leaf_hash failed\n");
        return 1;
    }

    /* ------------------------------------------------------------------ */
    /* 2. Empty revocation set: signer_revoked signs successfully           */
    /* ------------------------------------------------------------------ */
    rev_record_t *recs = calloc(n_recs, sizeof(*recs));
    uint8_t v_root[MERKLE_VT_MAX_NODE_BYTES] = {0};
    uint8_t *rev_sib = calloc(depth_r, W);
    if (recs == NULL || rev_sib == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    fill_empty_revocation_set(recs, n_recs, W);

    voleith_rs_membership_path_t rev_path;
    if (build_rev_path(vt, recs, n_recs, W, leaf_revoked, v_root, rev_sib,
                       &rev_path) != 0) {
        fprintf(stderr,
                "lookup_nonmember failed for member #%zu against empty V\n",
                signer_revoked);
        return 1;
    }

    printf("\n--- Scenario A: empty V, member #%zu signs ---\n",
           signer_revoked);
    printf("Revocation root V: ");
    for (size_t i = 0; i < W; i++)
        printf("%02x", v_root[i]);
    printf("\n");

    const uint8_t m1[] = "scenario A: empty revocation set";
    size_t m1_len = sizeof(m1) - 1;
    voleith_ring_sig_t sigA = {NULL, 0};
    struct timespec t0, t1;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    int rc = voleith_rsv1_sign(
        &sigA, &cfg, &params, sks + signer_revoked * sk_bytes, root,
        &paths[signer_revoked], v_root, &rev_path, m1, m1_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign (member #%zu, empty V) failed\n", signer_revoked);
        return 1;
    }
    printf("Sign:    %zu bytes in %.2f ms\n", sigA.len, elapsed_ms(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = voleith_rsv1_verify(&sigA, &cfg, &params, root, v_root, m1, m1_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Verify:  %s in %.2f ms\n", rc == 0 ? "PASS" : "FAIL",
           elapsed_ms(t0, t1));
    if (rc != 0) {
        voleith_ring_sig_free(&sigA);
        free(recs);
        free(rev_sib);
        free(sks);
        free(paths);
        free(sib_storage);
        return 1;
    }
    voleith_ring_sig_free(&sigA);

    /* ------------------------------------------------------------------ */
    /* 3. Revoke signer_revoked: their leaf is now in V                     */
    /* ------------------------------------------------------------------ */
    revoke_one_leaf(recs, n_recs, W, leaf_revoked);

    printf("\n--- Scenario B: V revokes member #%zu ---\n", signer_revoked);

    /* Lookup against the new V must reject for the revoked signer
     * (target is a member of V's records). */
    {
        voleith_imt_record_t *imt_b = calloc(n_recs, sizeof(*imt_b));
        if (imt_b == NULL) {
            fprintf(stderr, "alloc failed\n");
            return 1;
        }
        records_to_imt(recs, n_recs, imt_b);

        uint8_t v_root_b[MERKLE_VT_MAX_NODE_BYTES] = {0};
        if (voleith_imt_vt_build(vt, imt_b, n_recs, W, INDEX_BYTES, v_root_b) !=
            0) {
            fprintf(stderr, "imt_vt_build (revoked) failed\n");
            free(imt_b);
            return 1;
        }
        size_t adj_idx;
        uint8_t *sib_b = calloc(depth_r, W);
        if (sib_b == NULL) {
            free(imt_b);
            return 1;
        }
        rc = voleith_imt_vt_lookup_nonmember(vt, imt_b, n_recs, W, INDEX_BYTES,
                                             leaf_revoked, &adj_idx, sib_b);
        printf("Lookup for revoked member #%zu: %s (expected REJECT)\n",
               signer_revoked, rc == -1 ? "REJECT" : "ACCEPT?!");
        free(sib_b);
        free(imt_b);
        if (rc != -1)
            return 1;
        memcpy(v_root, v_root_b, W);
    }

    /* ------------------------------------------------------------------ */
    /* 4. Unrevoked member signs against the new V                          */
    /* ------------------------------------------------------------------ */
    voleith_rs_membership_path_t rev_path2;
    if (build_rev_path(vt, recs, n_recs, W, leaf_unrevoked, v_root, rev_sib,
                       &rev_path2) != 0) {
        fprintf(stderr,
                "lookup_nonmember failed for member #%zu against new V\n",
                signer_unrevoked);
        return 1;
    }

    printf(
        "\n--- Scenario C: V revokes #%zu, unrevoked member #%zu signs ---\n",
        signer_revoked, signer_unrevoked);

    const uint8_t m2[] = "scenario C: post-revocation message";
    size_t m2_len = sizeof(m2) - 1;
    voleith_ring_sig_t sigC = {NULL, 0};

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = voleith_rsv1_sign(
        &sigC, &cfg, &params, sks + signer_unrevoked * sk_bytes, root,
        &paths[signer_unrevoked], v_root, &rev_path2, m2, m2_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (rc != 0) {
        fprintf(stderr, "sign (member #%zu, V revokes #%zu) failed\n",
                signer_unrevoked, signer_revoked);
        return 1;
    }
    printf("Sign:    %zu bytes in %.2f ms\n", sigC.len, elapsed_ms(t0, t1));

    clock_gettime(CLOCK_MONOTONIC, &t0);
    rc = voleith_rsv1_verify(&sigC, &cfg, &params, root, v_root, m2, m2_len);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("Verify:  %s in %.2f ms\n", rc == 0 ? "PASS" : "FAIL",
           elapsed_ms(t0, t1));
    int verify_ok = (rc == 0);

    voleith_ring_sig_free(&sigC);
    free(recs);
    free(rev_sib);
    free(sks);
    free(paths);
    free(sib_storage);
    return verify_ok ? 0 : 1;
}
