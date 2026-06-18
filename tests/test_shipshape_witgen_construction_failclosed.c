/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_witgen_construction_failclosed.c - W8.6 fail-closed property
 * test for a crypto-v2 CONSTRUCTION witness backend.
 *
 * Mirrors test_shipshape_witgen_failclosed.c (the W8.4 FIXED-entry version),
 * but the vehicle is the hash-parametric construction ring_sig/v1[aes_dm] over
 * a REAL satisfiable depth-2 tree.  Under the W8.4 interleaved skip a registered
 * backend is AUTHORITATIVE: the generic forward pass no longer recomputes the
 * inverse for a dispatched slot, so a WRONG construction backend produces a
 * wrong witness.  The fail-closed guarantee (docs/CIRC_WITNESS_GEN.md §7.1, §7.5)
 * is that a wrong backend can only yield an INVALID proof, never a verifier
 * accept:
 *
 *   1. With SELF_CHECK, witness_gen rejects the corrupted witness at gen time.
 *   2. Without SELF_CHECK, witness_gen succeeds (bad witness) but the prover
 *      refuses the unsatisfied circuit (or, failing that, verify rejects).
 *   3. Control: the REAL backend reproduces the generic witness byte-for-byte,
 *      and that witness proves and verifies (the skip is transparent).
 *
 * The wrong backend produces a witness that is correct EXCEPT one flipped byte:
 * it cannot recompute the genuine span itself (the real construction handler is
 * internal), so the test first generates the genuine witness with the real
 * backends, stashes it in a file-scope pointer, and the wrong backend copies
 * the genuine region span into the full array and then flips one byte.  This
 * guarantees "correct except one byte", so prove / verify must reject precisely
 * because of the corruption, not because of unrelated garbage.
 */

#include "gf8_proof.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "shipshape.h"
#include "shipshape_witgen_construction.h"
#include "shipshape_witgen_dispatch.h"
#include "shipshape_witness.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* crypto-v2 header. */
#define HDR_V2                                                                 \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v2\n"

/* ring_sig/v1[aes_dm]: sk=16, depth=2, sib=32, root(inst)=16. */
static const char RING_SIG_SRC[] =
    HDR_V2 "WITNESS  -> %sk   : byte[16]\n"
           "WITNESS  -> %dirs : byte[2]\n"
           "WITNESS  -> %sib  : byte[32]\n"
           "INSTANCE -> %root : byte[16]\n"
           "stdlib/crypto/ring_sig/v1[aes_dm](%sk, %dirs, %sib, %root)\n";

/* The exact bracketed name the wrong backend registers under. */
#define RING_SIG_NAME "stdlib/crypto/ring_sig/v1[aes_dm]"

static const uint8_t FS_SEED[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                    0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                                    0xDD, 0xEE, 0xFF, 0x01};

/* Zero the secret witness buffer before releasing it. */
static void
zfree(uint8_t *buf, size_t len)
{
    if (buf != NULL && len > 0)
        voleith_secure_zero(buf, len);
    free(buf);
}

/*
 * Build a real two-leaf-level tree (n_leaves=4, depth=2, leaf_index=0 so
 * dirs={0,0}) with the aes_dm software oracles.  Copied verbatim from
 * test_shipshape_crypto_v2_proof.c.
 *
 * Input: sk (16 bytes) as the raw leaf secret.
 * Output: sib_out (32 bytes), root_out (16 bytes).
 * Returns 0 on success, -1 on vt or allocation failure.
 */
static int
build_tree(const uint8_t *sk, uint8_t *sib_out, uint8_t *root_out)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    size_t W = vt->node_bytes; /* 16 */

    static const uint8_t seed1[16] = {0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45,
                                      0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
                                      0x23, 0x45, 0x67, 0x89};
    static const uint8_t seed2[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                                      0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
                                      0xDD, 0xEE, 0xFF, 0x00};
    static const uint8_t seed3[16] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
                                      0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04,
                                      0x05, 0x06, 0x07, 0x08};

    uint8_t leaf_nodes[4 * 16];
    uint8_t *ln0 = leaf_nodes + 0 * W;
    uint8_t *ln1 = leaf_nodes + 1 * W;
    uint8_t *ln2 = leaf_nodes + 2 * W;
    uint8_t *ln3 = leaf_nodes + 3 * W;

    if (vt->leaf_hash(sk, 16, ln0) != 0 || vt->leaf_hash(seed1, 16, ln1) != 0 ||
        vt->leaf_hash(seed2, 16, ln2) != 0 ||
        vt->leaf_hash(seed3, 16, ln3) != 0)
        return -1;

    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, 4, 0, sib_out) != 0)
        return -1;
    if (voleith_merkle_vt_build(vt, leaf_nodes, 4, root_out) != 0)
        return -1;
    return 0;
}

/* Fixed witness inputs for the satisfiable tree. */
static const uint8_t SK[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                               0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C};
static const uint8_t DIRS[2] = {0x00, 0x00};

/*
 * File-scope handle to the genuine full witness, set before a witness_gen run
 * that uses the wrong backend.  The wrong backend reads the region span from
 * here so it can produce a witness that is "correct except one byte".
 */
static const uint8_t *g_genuine = NULL;
static size_t g_genuine_len = 0;

/*
 * Wrong construction backend: copy the genuine region span into `full`, then
 * flip exactly one byte.  Selected via the exact bracketed name, it must still
 * yield an invalid proof.
 */
static int
wrong_ring_backend(const voleith_shipshape_region_t *region, const uint8_t *ext,
                   size_t ext_len, uint8_t *full)
{
    size_t first = region->first_witness;
    size_t n = region->n_witness;

    if (ext == NULL || ext_len == 0 || n == 0)
        return -1;
    if (g_genuine == NULL || first + n > g_genuine_len)
        return -1;

    memcpy(full + first, g_genuine + first, n);
    full[first] ^= 0x01;
    return 0;
}

/*
 * Generate the genuine full witness with the REAL construction backends and
 * SELF_CHECK over the satisfiable tree.  On success *wit / *wit_len hold the
 * witness (caller zfrees) and *root holds the 16-byte instance root.
 *
 * Returns 0 on success, -1 on any failure.
 */
static int
gen_genuine(uint8_t *root_out, uint8_t **wit_out, size_t *wit_len_out)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t sib[32], root[16];
    uint8_t ext[16 + 2 + 32];
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    if (build_tree(SK, sib, root) != 0)
        return -1;

    memcpy(ext + 0, SK, 16);
    memcpy(ext + 16, DIRS, 2);
    memcpy(ext + 18, sib, 32);

    if (voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL) != 0 ||
        p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return -1;
    }

    voleith_shipshape_witgen_reset();
    if (voleith_shipshape_witgen_register_constructions() != 0) {
        voleith_shipshape_parsed_free(&p);
        return -1;
    }
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);

    if (r != 0 || wit == NULL)
        return -1;

    memcpy(root_out, root, 16);
    *wit_out = wit;
    *wit_len_out = wit_len;
    return 0;
}

static void
test_self_check_rejects_wrong_backend(const uint8_t *root)
{
    voleith_shipshape_parsed_t p = {0};
    uint8_t sib[32], rt[16];
    uint8_t ext[16 + 2 + 32];
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    (void)root;
    if (build_tree(SK, sib, rt) != 0) {
        check("self-check: tree build", 0);
        return;
    }
    memcpy(ext + 0, SK, 16);
    memcpy(ext + 16, DIRS, 2);
    memcpy(ext + 18, sib, 32);

    r = voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL);
    check("self-check: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    voleith_shipshape_witgen_reset();
    check("self-check: wrong backend registers",
          voleith_shipshape_witgen_register_construction(
              RING_SIG_NAME, wrong_ring_backend) == 0);

    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), rt, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    check("self-check: gen with SELF_CHECK rejects corrupted witness", r != 0);
    check("self-check: no buffer handed back on failure", wit == NULL);

    zfree(wit, wit_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

static void
test_prove_rejects_wrong_backend(const uint8_t *root)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p = {0};
    voleith_proof_t proof;
    uint8_t sib[32], rt[16];
    uint8_t ext[16 + 2 + 32];
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    (void)root;
    if (build_tree(SK, sib, rt) != 0) {
        check("prove-reject: tree build", 0);
        return;
    }
    memcpy(ext + 0, SK, 16);
    memcpy(ext + 16, DIRS, 2);
    memcpy(ext + 18, sib, 32);

    r = voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL);
    check("prove-reject: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    voleith_shipshape_witgen_reset();
    check("prove-reject: wrong backend registers",
          voleith_shipshape_witgen_register_construction(
              RING_SIG_NAME, wrong_ring_backend) == 0);

    /* No SELF_CHECK: a bad witness is produced without complaint. */
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), rt, 16, 0, &wit,
                                      &wit_len);
    check("prove-reject: gen without self-check succeeds (bad witness)",
          r == 0 && wit != NULL);

    if (r == 0 && wit != NULL) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, rt,
                                 16, FS_SEED, sizeof(FS_SEED));
        if (r != 0) {
            /* Prover refused the unsatisfied circuit: fail-closed. */
            check("prove-reject: prover refuses unsatisfied circuit", 1);
        } else {
            /* If prove unexpectedly succeeds, verify MUST reject. */
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, rt, 16,
                                      FS_SEED, sizeof(FS_SEED));
            check("prove-reject: verify rejects bad-witness proof", r != 0);
            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

static void
test_real_backend_transparent(const uint8_t *genuine, size_t genuine_len,
                              const uint8_t *root)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p = {0};
    voleith_proof_t proof;
    uint8_t sib[32], rt[16];
    uint8_t ext[16 + 2 + 32];
    uint8_t *dispatched = NULL;
    size_t dispatched_len = 0;
    int r;

    (void)root;
    if (build_tree(SK, sib, rt) != 0) {
        check("control: tree build", 0);
        return;
    }
    memcpy(ext + 0, SK, 16);
    memcpy(ext + 16, DIRS, 2);
    memcpy(ext + 18, sib, 32);

    r = voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL);
    check("control: parses", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /* Real construction backends registered. */
    voleith_shipshape_witgen_reset();
    check("control: real construction backends register",
          voleith_shipshape_witgen_register_constructions() == 0);
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), rt, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK,
                                      &dispatched, &dispatched_len);
    check("control: dispatched gen succeeds", r == 0 && dispatched != NULL);

    /* The real backend reproduces the genuine witness byte-for-byte. */
    check("control: dispatched witness equals genuine baseline",
          dispatched != NULL && genuine != NULL &&
              dispatched_len == genuine_len &&
              memcmp(dispatched, genuine, genuine_len) == 0);

    /* The dispatched (correct) witness proves and verifies. */
    if (dispatched != NULL) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, dispatched,
                                 dispatched_len, rt, 16, FS_SEED,
                                 sizeof(FS_SEED));
        check("control: correct witness proves", r == 0);
        if (r == 0) {
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, rt, 16,
                                      FS_SEED, sizeof(FS_SEED));
            check("control: proof verifies", r == 0);
            voleith_proof_free(&proof);
        }
    }

    zfree(dispatched, dispatched_len);
    voleith_shipshape_witgen_reset();
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    uint8_t *genuine = NULL;
    size_t genuine_len = 0;
    uint8_t root[16];

    printf("test_shipshape_witgen_construction_failclosed\n");

    /* Stage the genuine witness once; the wrong backend mirrors its span. */
    if (gen_genuine(root, &genuine, &genuine_len) != 0) {
        check("setup: genuine witness generated", 0);
        printf("%d/%d tests passed\n", pass_count, test_count);
        return 1;
    }
    check("setup: genuine witness generated", 1);
    g_genuine = genuine;
    g_genuine_len = genuine_len;

    test_self_check_rejects_wrong_backend(root);
    test_prove_rejects_wrong_backend(root);
    test_real_backend_transparent(genuine, genuine_len, root);

    g_genuine = NULL;
    g_genuine_len = 0;
    zfree(genuine, genuine_len);

    printf("%d/%d tests passed\n", pass_count, test_count);
    return pass_count == test_count ? 0 : 1;
}
