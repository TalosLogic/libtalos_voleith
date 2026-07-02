/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_crypto_v2_proof.c - prove / verify round-trip for a
 * hash-parametric registry entry (MR4 / 4b of
 * the crypto-v2 implementation plan).
 *
 * Uses ring_sig/v1[aes_dm] because it is an assertion-only entry (the
 * root is an INSTANCE wire), so a wrong Merkle path is unsatisfiable and
 * the prover must reject it before emitting a proof.  This closes the
 * loop: parse -> witness-gen -> prove -> verify, with no change to the
 * generic witness generator.
 *
 * Test plan:
 *
 *   valid_roundtrip:
 *     - Build a real two-leaf tree (n_leaves=4, leaf_index=0 so dirs={0,0})
 *       with the aes_dm software oracles.
 *     - Compute ext = sk||dirs||sib in .ship declaration order.
 *     - Compute inst = root[16] using leaf_hash then inode_hash in the
 *       direction matching the circuit convention (dir==0 means current is
 *       left, sibling is right: inode(current, sibling)).
 *     - Parse, witness-gen, prove, verify: must succeed.
 *     - Tamper proof byte 0: verify must reject.
 *
 *   tampered_sib_rejected:
 *     - Start from the same valid (ext, inst).
 *     - Flip one byte in the sib portion of ext.
 *     - Parse, attempt witness-gen + prove: must fail (prove rejects the
 *       unsatisfied circuit via the ASSERT_EQUAL constraints on root).
 *     - Positive control: un-flip and confirm prove still succeeds.
 *
 * Direction convention (from merkle_vt_gf8_circuit.h):
 *   path_dirs[k] = 0  -> accumulated hash is the LEFT child; inode(current, sibling)
 *   path_dirs[k] = 1  -> accumulated hash is the RIGHT child; inode(sibling, current)
 *
 * With dirs = {0, 0} (leaf_index = 0, both bits clear):
 *   Level 0: inode(leaf_node, sib[0..15])     -> n0
 *   Level 1: inode(n0, sib[16..31])           -> root
 * This matches exactly what voleith_merkle_vt_compute_path produces for
 * leaf_index=0 in a 4-leaf tree, and what the circuit computes when driven
 * with those witnesses.
 */

#include "gf8_proof.h"
#include "merkle_vt_gf8_helpers.h"
#include "node_hash_vt.h"
#include "shipshape.h"
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
 * Compute the Merkle root for a 4-leaf tree (n_leaves=4, depth=2) using
 * the aes_dm software oracles, for leaf_index=0 (dirs={0,0}).
 *
 * Input: sk (16 bytes) as the raw leaf secret; the leaf hash and all
 * inode hashes are computed by the aes_dm vt.
 *
 * Output:
 *   sib_out    - 32 bytes: sib[0..15]=level-0 sibling, sib[16..31]=level-1
 *   root_out   - 16 bytes: computed Merkle root
 *
 * Returns 0 on success, -1 on vt failure or allocation failure.
 *
 * The four leaf secrets are: sk, then three synthetic bytes (index-derived
 * so the tree is non-trivial).  We only need the path for leaf_index=0.
 *
 * Tree structure (leaf_index=0, dirs={0,0}):
 *   leaf_nodes[0] = leaf_hash(sk, 16)
 *   leaf_nodes[1] = leaf_hash(seed1, 16)
 *   leaf_nodes[2] = leaf_hash(seed2, 16)
 *   leaf_nodes[3] = leaf_hash(seed3, 16)
 *   inode[0] = inode_hash(leaf_nodes[0], leaf_nodes[1])  <- level 1 left
 *   inode[1] = inode_hash(leaf_nodes[2], leaf_nodes[3])  <- level 1 right
 *   root     = inode_hash(inode[0], inode[1])
 *
 * For leaf_index=0:
 *   sib[0..15] = leaf_nodes[1]     (level-0 sibling: index 0^1=1)
 *   sib[16..31]= inode[1]          (level-1 sibling: index 0^1=1 at level 1)
 */
static int
build_tree(const uint8_t *sk, uint8_t *sib_out, uint8_t *root_out)
{
    const voleith_node_hash_vt *vt = &voleith_node_hash_aes_dm;
    size_t W = vt->node_bytes; /* 16 */

    /* Four synthetic leaf secrets. */
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

    /* Use the tree helper to get sibling path for leaf_index=0. */
    if (voleith_merkle_vt_compute_path(vt, leaf_nodes, 4, 0, sib_out) != 0)
        return -1;
    if (voleith_merkle_vt_build(vt, leaf_nodes, 4, root_out) != 0)
        return -1;
    return 0;
}

/*
 * Valid roundtrip: parse ring_sig/v1[aes_dm], build a real witness, prove,
 * verify.  Also exercises tampered-proof detection.
 */
static void
test_valid_roundtrip(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    /*
     * Fixed sk.  dirs={0,0} (leaf_index=0; both path bits are 0, meaning
     * at each level the accumulated hash is the left child).
     */
    static const uint8_t sk[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE,
                                   0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
                                   0x09, 0xCF, 0x4F, 0x3C};
    static const uint8_t dirs[2] = {0x00, 0x00};
    uint8_t sib[32], root[16];

    /* ext layout (declaration order): sk[16] | dirs[2] | sib[32] */
    uint8_t ext[16 + 2 + 32];

    r = build_tree(sk, sib, root);
    check("valid_roundtrip: tree build ok", r == 0);
    if (r != 0)
        return;

    memcpy(ext + 0, sk, 16);
    memcpy(ext + 16, dirs, 2);
    memcpy(ext + 18, sib, 32);

    r = voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL);
    check("valid_roundtrip: parse ok", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    check("valid_roundtrip: witness gen ok", r == 0);

    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, root,
                                 16, FS_SEED, sizeof(FS_SEED));
        check("valid_roundtrip: prove ok", r == 0);

        if (r == 0) {
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, 16,
                                      FS_SEED, sizeof(FS_SEED));
            check("valid_roundtrip: verify accepts", r == 0);

            /* Tamper: flip proof byte 0; verify must reject. */
            proof.data[0] ^= 0xFF;
            r = voleith_gf8_verify_v2(&proof, params, p.circuit, root, 16,
                                      FS_SEED, sizeof(FS_SEED));
            check("valid_roundtrip: tampered proof rejected", r != 0);
            proof.data[0] ^= 0xFF;

            voleith_proof_free(&proof);
        }
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

/*
 * Tampered sibling rejected: flip one byte in the sib portion of ext, then
 * attempt witness-gen + prove.  The ASSERT_EQUAL constraints on the root
 * must cause the prover to reject.  A positive control (un-flip) must
 * prove.
 */
static void
test_tampered_sib_rejected(void)
{
    const voleith_params_t *params = &voleith_params_em_128f;
    voleith_shipshape_parsed_t p;
    voleith_proof_t proof;
    uint8_t *wit = NULL;
    size_t wit_len = 0;
    int r;

    static const uint8_t sk[16] = {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE,
                                   0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88,
                                   0x09, 0xCF, 0x4F, 0x3C};
    static const uint8_t dirs[2] = {0x00, 0x00};
    uint8_t sib[32], root[16];
    uint8_t ext[16 + 2 + 32];

    r = build_tree(sk, sib, root);
    check("tampered_sib: tree build ok", r == 0);
    if (r != 0)
        return;

    memcpy(ext + 0, sk, 16);
    memcpy(ext + 16, dirs, 2);
    memcpy(ext + 18, sib, 32);

    r = voleith_shipshape_parse_buffer(&p, RING_SIG_SRC, 0, NULL);
    check("tampered_sib: parse ok", r == 0 && p.circuit != NULL);
    if (r != 0 || p.circuit == NULL) {
        voleith_shipshape_parsed_free(&p);
        return;
    }

    /*
     * Corrupt one byte of the sibling block (byte 18 = first sib byte).
     * The generated witness will not satisfy the ASSERT_EQUAL constraints
     * on the root; the prover must return nonzero.
     */
    ext[18] ^= 0x01;
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    /*
     * Witness gen with WITGEN_SELF_CHECK may itself detect the violation
     * (r != 0) before prove is reached.  If it succeeds, prove must reject.
     */
    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, root,
                                 16, FS_SEED, sizeof(FS_SEED));
        check("tampered_sib: prove or witgen rejects corrupted path", r != 0);
        if (r == 0)
            voleith_proof_free(&proof);
    } else {
        check("tampered_sib: prove or witgen rejects corrupted path", 1);
    }
    zfree(wit, wit_len);
    wit = NULL;
    wit_len = 0;

    /* Positive control: un-flip the corrupted byte; prove must succeed. */
    ext[18] ^= 0x01;
    r = voleith_shipshape_witness_gen(&p, ext, sizeof(ext), root, 16,
                                      VOLEITH_SHIPSHAPE_WITGEN_SELF_CHECK, &wit,
                                      &wit_len);
    check("tampered_sib: correct path witness gen ok", r == 0);

    if (r == 0) {
        r = voleith_gf8_prove_v2(&proof, params, p.circuit, wit, wit_len, root,
                                 16, FS_SEED, sizeof(FS_SEED));
        check("tampered_sib: correct path proves", r == 0);
        if (r == 0)
            voleith_proof_free(&proof);
    }

    zfree(wit, wit_len);
    voleith_shipshape_parsed_free(&p);
}

int
main(void)
{
    printf("test_shipshape_crypto_v2_proof: starting\n");
    test_valid_roundtrip();
    test_tampered_sib_rejected();
    printf("test_shipshape_crypto_v2_proof: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
