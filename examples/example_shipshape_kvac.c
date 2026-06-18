/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_shipshape_kvac.c - full KVAC credential LIFECYCLE demo expressed
 * through the Shipshape `.ship` format.
 *
 * A keyed-verification anonymous credential (KVAC) system is not just an
 * issue-and-show protocol: it needs lifecycle management.  Members are issued
 * credentials, prove membership anonymously, and must be revocable.  This demo
 * shows the full arc using BOTH crypto-v2 secret-direction constructions over
 * the hirose_fixed_32 node hash (32-byte nodes, 128-bit collision resistance):
 *
 *   merkle/path_secret[hirose_fixed_32]              (membership)
 *   indexed_merkle/nonmember_secret[hirose_fixed_32] (non-revocation)
 *
 * Phases:
 *   1. Membership:        the member proves they are a leaf of the group tree.
 *   2. Non-revocation:    the member proves their revocation value is NOT in
 *                         the public revocation indexed Merkle tree.
 *   3. Revoke:            the member's value is inserted into the revocation
 *                         IMT; the revocation root is updated.
 *   4. Post-revocation:   the same member can no longer produce an accepted
 *                         non-revocation proof.  No adjacent record straddles
 *                         their value anymore, and a STALE pre-revocation
 *                         witness no longer matches the new root.
 *
 * example_shipshape_anon_membership is the membership-only building block; this
 * example reuses its anon_membership_hirose.ship for Phase 1 and adds the
 * revocation half via kvac_revocation_hirose.ship.
 *
 * Critical parameter fact: for hirose_fixed_32 the indexed leaf record is
 * value(12) || next_value(12) || next_index(8) = 32 = the fixed leaf size, so
 * the revocation IMT uses value_bytes = 12 and index_bytes = 8 (node/sibling
 * width is still 32 bytes).
 *
 *   ./example_shipshape_kvac
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "indexed_merkle_vt_gf8_helpers.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "shipshape.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VOLEITH_SHIPSHAPE_DATA_DIR
#define VOLEITH_SHIPSHAPE_DATA_DIR "tests/data/shipshape"
#endif

/* Membership tree: depth 8 (256-leaf group); the member sits at index 100. */
#define MEM_DEPTH 8
#define MEM_N_LEAVES (1u << MEM_DEPTH)
#define MEMBER_INDEX 100u

/* Revocation indexed Merkle tree: depth 8 (256 records). */
#define REV_DEPTH 8
#define REV_N_RECS (1u << REV_DEPTH)

/*
 * Field widths FROZEN by hirose_fixed_32: the indexed leaf record is
 * value(12) || next_value(12) || next_index(8) = 32 = fixed_leaf_bytes.  The
 * node / sibling / root width is the full 32 bytes.
 */
#define VALUE_BYTES 12
#define INDEX_BYTES 8
#define NODE_BYTES 32

/* ext layouts. */
#define MEM_EXT_LEN (32 + MEM_DEPTH * 32 + MEM_DEPTH) /* 296 */
#define REV_EXT_LEN                                                            \
    (VALUE_BYTES + VALUE_BYTES + VALUE_BYTES + INDEX_BYTES +                   \
     REV_DEPTH * NODE_BYTES + REV_DEPTH) /* 308 */

/*
 * One revocation IMT record, adapted from the RSv1 revocable example to the
 * frozen hirose_fixed_32 widths (value_bytes = 12, index_bytes = 8).  Only the
 * meaningful prefix of each field is used.
 */
typedef struct {
    uint8_t value[VALUE_BYTES];
    uint8_t next_value[VALUE_BYTES];
    uint8_t next_index[INDEX_BYTES];
} rev_record_t;

/*
 * Empty (no-revocations) IMT: rec[0] spans the full open range [0, MAX), every
 * later record is a degenerate "max" sentinel.  A target strictly between the
 * bounds (not all 0x00, not all 0xFF) falls into rec[0]'s interval.
 */
static void
fill_empty_revocation_set(rev_record_t *recs, size_t n_recs)
{
    size_t i;

    memset(recs[0].value, 0x00, VALUE_BYTES);
    memset(recs[0].next_value, 0xFF, VALUE_BYTES);
    memset(recs[0].next_index, 0, INDEX_BYTES);
    if (n_recs > 1)
        recs[0].next_index[0] = 1;

    for (i = 1; i < n_recs; i++) {
        memset(recs[i].value, 0xFF, VALUE_BYTES);
        memset(recs[i].next_value, 0xFF, VALUE_BYTES);
        memset(recs[i].next_index, 0, INDEX_BYTES);
    }
}

/*
 * Revoke `target` by splitting rec[0] exactly at it:
 *   rec[0]: [0x00.., target)
 *   rec[1]: [target,  0xFF..)
 * A subsequent lookup of `target` finds rec[1].value == target and rejects
 * (membership).  Later records remain max-sentinels.
 */
static void
revoke_one_leaf(rev_record_t *recs, size_t n_recs, const uint8_t *target)
{
    size_t i;

    memset(recs[0].value, 0x00, VALUE_BYTES);
    memcpy(recs[0].next_value, target, VALUE_BYTES);
    memset(recs[0].next_index, 0, INDEX_BYTES);
    if (n_recs > 1)
        recs[0].next_index[0] = 1;

    if (n_recs >= 2) {
        memcpy(recs[1].value, target, VALUE_BYTES);
        memset(recs[1].next_value, 0xFF, VALUE_BYTES);
        memset(recs[1].next_index, 0, INDEX_BYTES);
    }
    for (i = 2; i < n_recs; i++) {
        memset(recs[i].value, 0xFF, VALUE_BYTES);
        memset(recs[i].next_value, 0xFF, VALUE_BYTES);
        memset(recs[i].next_index, 0, INDEX_BYTES);
    }
}

static void
records_to_imt(const rev_record_t *recs, size_t n_recs,
               voleith_imt_record_t *imt)
{
    size_t i;

    for (i = 0; i < n_recs; i++) {
        imt[i].value = recs[i].value;
        imt[i].next_value = recs[i].next_value;
        imt[i].next_index = recs[i].next_index;
    }
}

/*
 * Run one revocation (non-membership) proof against `rev_root` using the
 * pre-built ext_rev external witness.  Returns 1 if the proof verifies, 0 if it
 * is (correctly or incorrectly) rejected at any stage, -1 on a hard error.
 *
 * accept_out, when non-NULL, receives 1 iff a clean verify happened.  This lets
 * the caller distinguish "proof rejected" (the desired post-revocation result)
 * from "API error".
 */
static int
run_revocation_proof(const voleith_params_t *params,
                     voleith_shipshape_parsed_t *p, const uint8_t *ext_rev,
                     const uint8_t *rev_root, const uint8_t *fs_seed,
                     size_t fs_seed_len, int *accept_out)
{
    voleith_proof_t proof;
    uint8_t *witness = NULL;
    size_t witness_len = 0;
    int accept = 0;
    int r;

    if (accept_out != NULL)
        *accept_out = 0;

    r = voleith_shipshape_witness_gen(
        p, ext_rev, REV_EXT_LEN, rev_root, NODE_BYTES,
        VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &witness, &witness_len);
    if (r != 0) {
        /* Witness gen rejected the unsatisfiable instance: a clean reject. */
        return 0;
    }

    r = voleith_gf8_prove_v2(&proof, params, p->circuit, witness, witness_len,
                             rev_root, NODE_BYTES, fs_seed, fs_seed_len);
    if (r != 0) {
        /* Prover rejected the unsatisfied circuit: a clean reject. */
        voleith_secure_zero(witness, witness_len);
        free(witness);
        return 0;
    }

    r = voleith_gf8_verify_v2(&proof, params, p->circuit, rev_root, NODE_BYTES,
                              fs_seed, fs_seed_len);
    accept = (r == 0);
    if (accept_out != NULL)
        *accept_out = accept;

    voleith_proof_free(&proof);
    voleith_secure_zero(witness, witness_len);
    free(witness);
    return accept ? 1 : 0;
}

int
main(void)
{
    const char *mem_path =
        VOLEITH_SHIPSHAPE_DATA_DIR "/anon_membership_hirose.ship";
    const char *rev_path =
        VOLEITH_SHIPSHAPE_DATA_DIR "/kvac_revocation_hirose.ship";
    const voleith_params_t *params = &voleith_params_em_128f;
    const voleith_node_hash_vt *vt = &voleith_node_hash_hirose_fixed32;

    voleith_shipshape_parsed_t pmem = {0};
    voleith_shipshape_parsed_t prev = {0};
    int pmem_ok = 0, prev_ok = 0;

    /* Membership (Phase 1) buffers. */
    uint8_t member_cred[32];
    uint8_t leaf_secret[32];
    uint8_t *leaf_nodes = NULL;
    uint8_t mem_sib[MEM_DEPTH * 32];
    uint8_t mem_dirs[MEM_DEPTH];
    uint8_t mem_root[32];
    uint8_t mem_ext[MEM_EXT_LEN];
    uint8_t *mem_witness = NULL;
    size_t mem_witness_len = 0;
    voleith_proof_t mem_proof;
    int mem_proof_live = 0;

    /* Revocation (Phases 2-4) buffers. */
    rev_record_t *recs = NULL;
    voleith_imt_record_t *imt = NULL;
    uint8_t target[VALUE_BYTES];
    uint8_t rev_sib[REV_DEPTH * NODE_BYTES];
    uint8_t rev_dirs[REV_DEPTH];
    uint8_t rev_root[NODE_BYTES];  /* pre-revocation root */
    uint8_t rev_root2[NODE_BYTES]; /* post-revocation root */
    uint8_t ext_rev[REV_EXT_LEN];

    uint8_t fs_seed[16];
    size_t adj_idx;
    size_t i;

    /* Phase outcome flags (all must be set for overall success). */
    int membership_pass = 0;
    int prerevoke_pass = 0;
    int postlookup_pass = 0;
    int staleproof_pass = 0;

    int rc = 1;
    int r;

    printf("Shipshape KVAC credential lifecycle example\n");
    printf("  membership statement:   %s\n", mem_path);
    printf("  non-revocation:         %s\n\n", rev_path);

    /* Parse both .ship statements up front. */
    r = voleith_shipshape_parse_file(&pmem, mem_path, NULL);
    if (r != 0 || pmem.circuit == NULL) {
        fprintf(stderr, "membership parse failed (%d): %s\n", r, mem_path);
        goto out;
    }
    pmem_ok = 1;

    r = voleith_shipshape_parse_file(&prev, rev_path, NULL);
    if (r != 0 || prev.circuit == NULL) {
        fprintf(stderr, "revocation parse failed (%d): %s\n", r, rev_path);
        goto out;
    }
    prev_ok = 1;

    /* Confirm both circuits match the expected hirose_fixed_32 layouts. */
    if (voleith_shipshape_external_witness_len(&pmem) != MEM_EXT_LEN ||
        voleith_gf8_circuit_instance_count(pmem.circuit) != NODE_BYTES) {
        fprintf(stderr, "membership circuit layout mismatch\n");
        goto out;
    }
    if (voleith_shipshape_external_witness_len(&prev) != REV_EXT_LEN ||
        voleith_gf8_circuit_instance_count(prev.circuit) != NODE_BYTES) {
        fprintf(stderr, "revocation circuit layout mismatch\n");
        goto out;
    }

    /*
     * Register the W8 Tier 2a native hirose construction backends once.  Both
     * the membership and revocation constructions dispatch through these.  The
     * generic Tier 1 evaluator is the always-correct fallback.
     */
    voleith_shipshape_witgen_reset();
    if (voleith_shipshape_witgen_register_constructions() != 0) {
        fprintf(stderr, "register_constructions failed\n");
        goto out;
    }

    memset(fs_seed, 0x5A, sizeof(fs_seed));

    /* ============================================================ */
    /* PHASE 1: membership ("the member is in the group")           */
    /* ============================================================ */
    printf("--- Phase 1: membership ---\n");

    leaf_nodes = calloc(MEM_N_LEAVES, 32);
    if (leaf_nodes == NULL) {
        fprintf(stderr, "leaf_nodes alloc failed\n");
        goto out;
    }
    /* The member's raw 32-byte credential preimage. */
    memset(member_cred, 0xA5, sizeof(member_cred));
    for (i = 0; i < MEM_N_LEAVES; i++) {
        if (i == MEMBER_INDEX) {
            if (vt->leaf_hash(member_cred, 32, &leaf_nodes[i * 32]) != 0) {
                fprintf(stderr, "leaf_hash failed (member)\n");
                goto out;
            }
            continue;
        }
        /* Distinct per-leaf secret so the tree is non-trivial. */
        memset(leaf_secret, (uint8_t)(0x10 + (i & 0xff)), sizeof(leaf_secret));
        leaf_secret[0] = (uint8_t)(i & 0xff);
        leaf_secret[1] = (uint8_t)((i >> 8) & 0xff);
        if (vt->leaf_hash(leaf_secret, 32, &leaf_nodes[i * 32]) != 0) {
            fprintf(stderr, "leaf_hash failed (leaf %zu)\n", i);
            goto out;
        }
    }

    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, MEM_N_LEAVES,
                                       MEMBER_INDEX, mem_sib) != 0) {
        fprintf(stderr, "compute_path failed\n");
        goto out;
    }
    if (voleith_merkle_vt_build(vt, leaf_nodes, MEM_N_LEAVES, mem_root) != 0) {
        fprintf(stderr, "merkle build failed\n");
        goto out;
    }
    for (i = 0; i < MEM_DEPTH; i++)
        mem_dirs[i] = (uint8_t)((MEMBER_INDEX >> i) & 1);

    /* ext = leaf(32) | sib(256) | dirs(8) = 296. */
    memcpy(mem_ext + 0, member_cred, 32);
    memcpy(mem_ext + 32, mem_sib, MEM_DEPTH * 32);
    memcpy(mem_ext + 32 + MEM_DEPTH * 32, mem_dirs, MEM_DEPTH);

    r = voleith_shipshape_witness_gen(
        &pmem, mem_ext, sizeof(mem_ext), mem_root, NODE_BYTES,
        VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &mem_witness, &mem_witness_len);
    if (r != 0) {
        fprintf(stderr, "membership witness gen failed (%d)\n", r);
        goto out;
    }
    r = voleith_gf8_prove_v2(&mem_proof, params, pmem.circuit, mem_witness,
                             mem_witness_len, mem_root, NODE_BYTES, fs_seed,
                             sizeof(fs_seed));
    if (r != 0) {
        fprintf(stderr, "membership prove failed (%d)\n", r);
        goto out;
    }
    mem_proof_live = 1;
    r = voleith_gf8_verify_v2(&mem_proof, params, pmem.circuit, mem_root,
                              NODE_BYTES, fs_seed, sizeof(fs_seed));
    membership_pass = (r == 0);
    printf("Membership proof: %s\n\n", membership_pass ? "PASS" : "FAIL");

    /* ============================================================ */
    /* PHASE 2: non-revocation, pre-revocation ("not yet revoked")  */
    /* ============================================================ */
    printf("--- Phase 2: non-revocation (before revoke) ---\n");

    recs = calloc(REV_N_RECS, sizeof(*recs));
    imt = calloc(REV_N_RECS, sizeof(*imt));
    if (recs == NULL || imt == NULL) {
        fprintf(stderr, "revocation records alloc failed\n");
        goto out;
    }
    fill_empty_revocation_set(recs, REV_N_RECS);

    /*
     * The member's 12-byte revocation value.  In a real KVAC system this is
     * derived from the member's credential (e.g. a pseudonym tag); here it is a
     * fixed value strictly between the empty-set bounds (not all 0x00, not all
     * 0xFF), little-endian (byte 0 = LSB).
     */
    for (i = 0; i < VALUE_BYTES; i++)
        target[i] = (uint8_t)(0x01 + i); /* {0x01, 0x02, ..., 0x0C} */

    records_to_imt(recs, REV_N_RECS, imt);
    if (voleith_imt_vt_build(vt, imt, REV_N_RECS, VALUE_BYTES, INDEX_BYTES,
                             rev_root) != 0) {
        fprintf(stderr, "imt build (pre-revoke) failed\n");
        goto out;
    }
    r = voleith_imt_vt_lookup_nonmember(vt, imt, REV_N_RECS, VALUE_BYTES,
                                        INDEX_BYTES, target, &adj_idx, rev_sib);
    if (r != 0) {
        fprintf(stderr, "lookup_nonmember (pre-revoke) failed (%d)\n", r);
        goto out;
    }

    /*
     * Assemble the pre-revocation external witness.
     *   low  = records[adj_idx].value       (12 bytes)
     *   hi   = records[adj_idx].next_value   (12 bytes)
     *   nidx = records[adj_idx].next_index   (8 bytes, the STORED field)
     *   sib  = rev_sib from lookup_nonmember (depth * 32 bytes)
     *   dirs = bit k of adj_idx              (depth bytes)
     * ext_rev = target(12) | low(12) | hi(12) | nidx(8) | sib(256) | dirs(8)
     *         = 308 bytes.  root is an INSTANCE wire, NOT part of ext.
     */
    for (i = 0; i < REV_DEPTH; i++)
        rev_dirs[i] = (uint8_t)((adj_idx >> i) & 1);

    memcpy(ext_rev + 0, target, VALUE_BYTES);
    memcpy(ext_rev + 12, recs[adj_idx].value, VALUE_BYTES);
    memcpy(ext_rev + 24, recs[adj_idx].next_value, VALUE_BYTES);
    memcpy(ext_rev + 36, recs[adj_idx].next_index, INDEX_BYTES);
    memcpy(ext_rev + 44, rev_sib, REV_DEPTH * NODE_BYTES);
    memcpy(ext_rev + 44 + REV_DEPTH * NODE_BYTES, rev_dirs, REV_DEPTH);

    r = run_revocation_proof(params, &prev, ext_rev, rev_root, fs_seed,
                             sizeof(fs_seed), NULL);
    if (r < 0)
        goto out;
    prerevoke_pass = (r == 1);
    printf("Non-revocation proof (before revoke): %s\n\n",
           prerevoke_pass ? "PASS" : "FAIL");

    /* ============================================================ */
    /* PHASE 3: revoke ("revoke the member")                        */
    /* ============================================================ */
    printf("--- Phase 3: revoke the member ---\n");

    revoke_one_leaf(recs, REV_N_RECS, target);
    records_to_imt(recs, REV_N_RECS, imt);
    if (voleith_imt_vt_build(vt, imt, REV_N_RECS, VALUE_BYTES, INDEX_BYTES,
                             rev_root2) != 0) {
        fprintf(stderr, "imt build (post-revoke) failed\n");
        goto out;
    }
    printf("Member revoked; revocation root updated\n\n");

    /* ============================================================ */
    /* PHASE 4: non-revocation, post-revocation ("now revoked")     */
    /* ============================================================ */
    printf("--- Phase 4: non-revocation (after revoke) ---\n");

    /*
     * The target is now a record value (rec[1].value == target), so
     * lookup_nonmember must reject: no adjacent record strictly straddles it.
     */
    r = voleith_imt_vt_lookup_nonmember(vt, imt, REV_N_RECS, VALUE_BYTES,
                                        INDEX_BYTES, target, &adj_idx, rev_sib);
    postlookup_pass = (r == -1);
    printf("Post-revoke lookup (no non-membership witness exists): "
           "rc == -1 -> %s\n",
           postlookup_pass ? "PASS" : "FAIL");

    /*
     * Cryptographic enforcement: reuse the STALE pre-revocation witness
     * (ext_rev still holds low = 0x00.., hi = 0xFF.., the old sib, old dirs)
     * but prove against the NEW root rev_root2.  The stale adjacent record
     * [0, MAX) is no longer part of rev_root2, so witness gen, prove, or verify
     * MUST reject.  This mirrors the prove-or-verify-rejects idiom from
     * test_shipshape_crypto_v2_proof.c's tampered_sib test.
     */
    r = run_revocation_proof(params, &prev, ext_rev, rev_root2, fs_seed,
                             sizeof(fs_seed), NULL);
    if (r < 0)
        goto out;
    staleproof_pass = (r == 0); /* stale proof must NOT verify */
    printf("Stale non-revocation proof against new root rejected: %s\n\n",
           staleproof_pass ? "PASS" : "FAIL");

    /* Overall success: all four phase checks must pass. */
    rc = (membership_pass && prerevoke_pass && postlookup_pass &&
          staleproof_pass)
             ? 0
             : 1;
    printf("Lifecycle result: %s\n", rc == 0 ? "PASS" : "FAIL");

out:
    if (mem_proof_live)
        voleith_proof_free(&mem_proof);
    if (mem_witness != NULL) {
        voleith_secure_zero(mem_witness, mem_witness_len);
        free(mem_witness);
    }
    voleith_secure_zero(member_cred, sizeof(member_cred));
    voleith_secure_zero(leaf_secret, sizeof(leaf_secret));
    voleith_secure_zero(target, sizeof(target));
    voleith_secure_zero(ext_rev, sizeof(ext_rev));
    voleith_secure_zero(mem_ext, sizeof(mem_ext));
    free(leaf_nodes);
    free(recs);
    free(imt);
    voleith_shipshape_witgen_reset();
    if (pmem_ok)
        voleith_shipshape_parsed_free(&pmem);
    if (prev_ok)
        voleith_shipshape_parsed_free(&prev);
    return rc;
}
