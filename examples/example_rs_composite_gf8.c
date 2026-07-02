/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_rs_composite_gf8.c - all modules in one ring signature.
 *
 * Combines every composable module in a single proof:
 *   - membership   : one of N enrolled members (depth-3 ring);
 *   - revocation   : the signer's leaf is NOT in the revocation IMT;
 *   - nullifier    : T = AES-CMAC(sk, scope) published (linkable per scope);
 *   - spent-set    : T is NOT in the spent-set IMT (one-time use in-proof);
 *   - attribute    : hidden age proven in [18, 120];
 *   - commitment   : claimable C = H(id || rand) bound into the transcript.
 *
 * Demonstration: enroll an 8-member ring, build the revocation and
 * spent-set indexed Merkle trees, sign as one member with all modules
 * active, verify, then flip one public field and show verify rejects.
 *
 * Returns 0 on full success; nonzero on any unexpected failure.
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "aes_cmac_gf8_circuit.h"
#include "indexed_merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "rs_gf8.h"
#include "rs_leaf_gf8_circuit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define INDEX_BYTES VOLEITH_RSV1_REV_INDEX_BYTES

static double
elapsed_ms(struct timespec start, struct timespec end)
{
    return (double)(end.tv_sec - start.tv_sec) * 1000.0 +
           (double)(end.tv_nsec - start.tv_nsec) / 1.0e6;
}

/*
 * One IMT record.  Value buffers are sized to MERKLE_VT_MAX_NODE_BYTES so
 * the struct works for any value width; only the first `value_bytes` bytes
 * are meaningful.  The revocation IMT uses value_bytes = node_bytes (the
 * leaf node), the spent-set IMT uses value_bytes = 16 (the nullifier T).
 */
typedef struct {
    uint8_t value[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next_value[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t next_index[INDEX_BYTES];
} imt_record_t;

/*
 * Build an empty (nothing-revoked / nothing-spent) IMT at `n_recs` records:
 * rec[0] spans the full open range [0, MAX), later records are degenerate
 * max-sentinels.  Any random-looking target (a hash output or CMAC tag)
 * falls into rec[0]'s interval with overwhelming probability, so the
 * non-membership proof exists.  Computes the root and the adjacent record
 * straddling `target`; siblings_storage must hold n_recs's depth * W bytes.
 * Returns 0 on success.
 */
static int
build_empty_imt_nonmember(const voleith_node_hash_vt *vt, imt_record_t *recs,
                          size_t n_recs, size_t value_bytes,
                          const uint8_t *target, uint8_t *root_out,
                          uint8_t *siblings_storage, size_t *adj_idx_out)
{
    voleith_imt_record_t *imt = calloc(n_recs, sizeof(*imt));
    int rc;

    if (imt == NULL)
        return -1;

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
    for (size_t i = 0; i < n_recs; i++) {
        imt[i].value = recs[i].value;
        imt[i].next_value = recs[i].next_value;
        imt[i].next_index = recs[i].next_index;
    }

    if (voleith_imt_vt_build(vt, imt, n_recs, value_bytes, INDEX_BYTES,
                             root_out) != 0) {
        free(imt);
        return -1;
    }
    rc = voleith_imt_vt_lookup_nonmember(vt, imt, n_recs, value_bytes,
                                         INDEX_BYTES, target, adj_idx_out,
                                         siblings_storage);
    free(imt);
    return rc;
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
     *     &voleith_node_hash_hirose   sk_bytes 16  params em_128f
     *   256-bit:
     *     &voleith_node_hash_grostl512 sk_bytes 32  params em_256f
     *
     * The node hash sets the Merkle / commitment collision resistance
     * (Hirose-AES-256 = 2^128, Grostl-512 = 2^256); the param set sets the
     * proof soundness (em_128f = 128-bit, em_256f = 256-bit).  Upgrade both
     * together for a coherent 256-bit system.  The nullifier uses AES-CMAC,
     * so sk_bytes must be 16 or 32.
     *
     * Composite-specific constraint: the revocation IMT proves
     * non-membership of the signer's leaf node, so its records are
     * value || next_value || next_index = 2*node_bytes + 8 bytes wide.
     * That exceeds a single compression block, so this example needs a
     * VARIABLE-leaf node hash (Hirose, or the full-hash Grostl vts).  The
     * fixed-input single-compression vts (hirose_fixed32, grostl256_fixed,
     * grostl512_fixed) deliberately REJECT an over-capacity leaf rather
     * than silently truncate it, so they suit the non-IMT V2/V3/V4
     * examples but not this wide revocation IMT.
     * =================================================================
     */
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose;
    const size_t sk_bytes = 16;
    voleith_params_t params = voleith_params_em_128f;

    const size_t depth_m = 3;
    const size_t depth_r = 2; /* revocation IMT depth */
    const size_t depth_s = 2; /* spent-set IMT depth */
    const size_t n_members = (size_t)1u << depth_m;
    const size_t n_rev = (size_t)1u << depth_r;
    const size_t n_spent = (size_t)1u << depth_s;
    const size_t W = vt->node_bytes;
    const size_t scope_bytes = 12;
    const size_t attr_bytes = 4;
    const size_t commit_bytes = sk_bytes;
    const size_t signer = 2;
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
    cfg.membership.depth_r = depth_r;
    cfg.attr_schema = &schema;
    cfg.scope_bytes = scope_bytes;
    cfg.depth_s = depth_s;
    cfg.enable_commitment = 1;
    cfg.commit_id_bytes = commit_bytes;
    cfg.commit_rand_bytes = commit_bytes;

    printf("=== Composite ring signature (all modules) ===\n");
    printf("Ring:    %zu members, depth %zu; rev depth %zu, spent depth %zu\n",
           n_members, depth_m, depth_r, depth_s);
    printf("Hash:    %s (node_bytes = %zu, 2^%zu CR); modules: membership"
           "+revocation+nullifier+spent+attribute+commitment\n",
           vt->name, W, vt->cr_bits);
    printf("Signer:  member #%zu, age 37 in [18,120]\n\n", signer);

    /* 1. Enroll. */
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
        attrs[i * attr_bytes] = (uint8_t)(35 + i); /* signer #2 -> age 37 */
    }
    if (voleith_rs_ring_build(&cfg, sks, attrs, n_members, root, paths, sib) !=
        0) {
        fprintf(stderr, "ring_build failed\n");
        return 1;
    }

    const uint8_t *sk = sks + signer * sk_bytes;
    const uint8_t *attr = attrs + signer * attr_bytes;

    /* Commitment opening (commit_bytes wide), scope, and nullifier T. */
    uint8_t id[MERKLE_VT_MAX_NODE_BYTES], rand[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t scope[12];
    for (size_t i = 0; i < commit_bytes; i++) {
        id[i] = (uint8_t)(0xA0 + i);
        rand[i] = (uint8_t)(0x5C - i);
    }
    for (size_t i = 0; i < scope_bytes; i++)
        scope[i] = (uint8_t)(0x90 + i);

    voleith_rs_claim_t claim;
    uint8_t Tbuf[16];
    size_t cmac_wbytes = aes_cmac_gf8_witness_bytes(sk_bytes, scope_bytes);
    uint8_t *cmac_tmp = malloc(cmac_wbytes);
    uint8_t leaf0[MERKLE_VT_MAX_NODE_BYTES];
    if (cmac_tmp == NULL ||
        voleith_rs_claim_produce(&cfg, id, rand, &claim) != 0 ||
        rs_leaf_gf8_hash(vt, sk, sk_bytes, attr, attr_bytes, leaf0) != 0) {
        fprintf(stderr, "setup failed\n");
        return 1;
    }
    aes_cmac_gf8_build_witness(sk, sk_bytes, scope, scope_bytes, cmac_tmp,
                               Tbuf);
    const uint8_t *C = claim.commitment;

    /* 2. Revocation IMT (signer leaf NOT revoked; value width = node_bytes)
     * and spent-set IMT (16-byte nullifier T NOT spent).  Siblings are tree
     * nodes (node_bytes each), so each storage buffer is depth * W. */
    imt_record_t *rev_recs = calloc(n_rev, sizeof(*rev_recs));
    imt_record_t *spent_recs = calloc(n_spent, sizeof(*spent_recs));
    uint8_t rev_root[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t spent_root[MERKLE_VT_MAX_NODE_BYTES];
    uint8_t *rev_sib = calloc(depth_r, W);
    uint8_t *spent_sib = calloc(depth_s, W);
    size_t rev_adj, spent_adj;
    if (rev_recs == NULL || spent_recs == NULL || rev_sib == NULL ||
        spent_sib == NULL) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }
    if (build_empty_imt_nonmember(vt, rev_recs, n_rev, W, leaf0, rev_root,
                                  rev_sib, &rev_adj) != 0 ||
        build_empty_imt_nonmember(vt, spent_recs, n_spent,
                                  VOLEITH_RS_NULLIFIER_BYTES, Tbuf, spent_root,
                                  spent_sib, &spent_adj) != 0) {
        fprintf(stderr, "IMT build failed\n");
        return 1;
    }

    /* 3. Assemble the prover path. */
    voleith_rs_path_t path = paths[signer];
    path.membership.rev_adj_leaf_index = rev_adj;
    path.membership.rev_siblings = rev_sib;
    path.membership.rev_low_value = rev_recs[rev_adj].value;
    path.membership.rev_low_next = rev_recs[rev_adj].next_value;
    path.membership.rev_next_index = rev_recs[rev_adj].next_index;
    path.scope = scope;
    path.commit_id = id;
    path.commit_rand = rand;
    path.spent_adj_leaf_index = spent_adj;
    path.spent_siblings = spent_sib;
    path.spent_low_value = spent_recs[spent_adj].value;
    path.spent_low_next = spent_recs[spent_adj].next_value;
    path.spent_next_index = spent_recs[spent_adj].next_index;

    uint8_t bounds[8] = {18, 0, 0, 0, 120, 0, 0, 0};
    voleith_rs_public_t pub;
    memset(&pub, 0, sizeof(pub));
    pub.membership_root = root;
    pub.revocation_root = rev_root;
    pub.commitment = C;
    pub.scope = scope;
    pub.nullifier = Tbuf;
    pub.spent_root = spent_root;
    pub.bounds = bounds;
    pub.bounds_len = sizeof(bounds);

    const uint8_t m[] = "Composite: one proof, every module active";
    size_t m_len = sizeof(m) - 1;
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
    printf("Verify:  %s in %.2f ms\n", v == 0 ? "PASS" : "FAIL",
           elapsed_ms(t0, t1));
    ok = ok && v == 0;

    /* 4. Tamper one public field (the spent root): verify must reject. */
    uint8_t bad_spent[MERKLE_VT_MAX_NODE_BYTES];
    memcpy(bad_spent, spent_root, W);
    bad_spent[0] ^= 0x01;
    pub.spent_root = bad_spent;
    int tampered = voleith_rs_verify(&sig, &cfg, &params, &pub, m, m_len);
    printf("Tamper:  flipped spent root -> %s (expected REJECT)\n",
           tampered == -1 ? "REJECT" : "ACCEPT?!");
    ok = ok && tampered == -1;
    pub.spent_root = spent_root;

    voleith_rs_sig_free(&sig);
    free(cmac_tmp);
    free(rev_recs);
    free(spent_recs);
    free(rev_sib);
    free(spent_sib);
    free(sks);
    free(attrs);
    free(paths);
    free(sib);

    printf("\n%s\n", ok ? "OK" : "FAILED");
    return ok ? 0 : 1;
}
