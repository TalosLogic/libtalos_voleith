/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_merkle_gf8.c - ZK proof of Merkle path membership (GF(2^8) circuit)
 *
 * Same statement as example_merkle.c but using the GF(2^8) circuit.
 * Key differences from the bit-level variant:
 *   - path_dirs are plain uint8_t (NOT witness wires) - public leaf index,
 *     resolved at circuit-build time with zero mul-gate cost.
 *   - Witness is byte-oriented: leaf_data (16B) + leaf_AES_inv_in (200B) +
 *     depth x (sibling (16B) + path_AES_inv_in (200B)) = 864 bytes.
 *   - ell = 864 (vs 29,699 bit-level), much smaller proof.
 *
 * Public (instance): root R (16 bytes)
 * Private (witness): 864-byte witness (leaf + inv_in for all AES calls)
 *
 * Tree: depth=3, 8 leaves, Davies-Meyer AES-128, leaf index 5 = 0b101
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "merkle_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const uint8_t LEAF_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4c, 0x65, 0x61, 0x66,
                                     0x00, 0x00, 0x00, 0x00};
static const uint8_t NODE_DOM[16] = {0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74,
                                     0x48, 0x2d, 0x4e, 0x6f, 0x64, 0x65,
                                     0x00, 0x00, 0x00, 0x00};

/* DM compress: AES_key(pt) XOR pt */
static void
dm_compress(const uint8_t key[16], const uint8_t pt[16], uint8_t out[16])
{
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, out, pt);
    for (int i = 0; i < 16; i++)
        out[i] ^= pt[i];
}

static void
leaf_hash_dm(const uint8_t leaf[16], uint8_t out[16])
{
    dm_compress(LEAF_DOM, leaf, out);
}

static void
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ NODE_DOM[i];
    dm_compress(L, P, out);
}

/*
 * get_aes_inv_in - compute the 200 inv_in bytes for AES_{key}(plaintext).
 * Calls aes128_gf8_build_witness and extracts witness[16..215].
 */
static void
get_aes_inv_in(const uint8_t key[16], const uint8_t pt[16], uint8_t inv_in[200])
{
    uint8_t tmp[216];
    aes128_gf8_build_witness(key, pt, tmp, NULL);
    memcpy(inv_in, tmp + 16, 200);
}

int
main(void)
{
    printf("=== Merkle path ZK proof (GF(2^8) circuit) ===\n");
    printf(
        "Statement: knowledge of leaf[5] and path s.t. Merkle path → root\n");
    printf("Tree: 8 leaves (depth 3), Davies-Meyer AES-128, public leaf "
           "index\n\n");

    /* ================================================================
     * Build 8-leaf DM tree.  leaf[i] = {i,i,...,i} (16 bytes).
     * ================================================================ */
    uint8_t leaf[8][16];
    for (int i = 0; i < 8; i++)
        memset(leaf[i], i, 16);

    uint8_t lh[8][16];
    for (int i = 0; i < 8; i++)
        leaf_hash_dm(leaf[i], lh[i]);

    uint8_t L1[4][16];
    for (int i = 0; i < 4; i++)
        inode_hash_dm(lh[2 * i], lh[2 * i + 1], L1[i]);

    uint8_t L2[2][16];
    for (int i = 0; i < 2; i++)
        inode_hash_dm(L1[2 * i], L1[2 * i + 1], L2[i]);

    uint8_t root[16];
    inode_hash_dm(L2[0], L2[1], root);

    /* Path for leaf index 5 = 0b101: dirs[0]=1, dirs[1]=0, dirs[2]=1 */
    const uint8_t path_dirs[3] = {1, 0, 1};
    const uint8_t *siblings[3] = {lh[4], L1[3], L2[0]};

    /* ================================================================
     * Build circuit
     * path_dirs are plain uint8_t (public, resolved at build time).
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Leaf data: 16 private witness wires */
    gf8_wire_id leaf_wires[16];
    for (int i = 0; i < 16; i++)
        leaf_wires[i] = voleith_gf8_add_witness(c);

    /* Leaf hash (DM, 16-byte leaf → 200 inv_in witness wires added internally) */
    gf8_wire_id leaf_hash_wires[16];
    merkle_gf8_leaf_hash_circuit(c, leaf_wires, 16, VOLEITH_MERKLE_HASH_AES_DM,
                                 leaf_hash_wires);

    /* Path nodes: depth*16 private witness wires (one per byte) */
    gf8_wire_id node_wires[3 * 16];
    for (int i = 0; i < 3 * 16; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    /* Merkle path circuit (path_dirs are public uint8_t, NOT wire IDs) */
    gf8_wire_id root_computed[16];
    merkle_gf8_path_circuit(c, leaf_hash_wires, node_wires, path_dirs, 3,
                            VOLEITH_MERKLE_HASH_AES_DM, root_computed);

    /* Root: 16 public instance wires; assert equal */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu (16 leaf + 200 inv_in + 3x216)\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (864 bytes total).
     *
     * Slot order matches the order of voleith_gf8_add_witness calls:
     *   [0..15]:   leaf data        ← leaf_wires (declared before leaf_hash_circuit)
     *   [16..215]: leaf hash inv_in ← added inside merkle_gf8_leaf_hash_circuit
     *   [216..263]: siblings[0..2]  ← node_wires (declared after leaf_hash_circuit,
     *                                  before merkle_gf8_path_circuit)
     *   [264..463]: path level 0 inv_in ← added inside merkle_gf8_path_circuit
     *   [464..663]: path level 1 inv_in
     *   [664..863]: path level 2 inv_in
     *
     * For DM inode at level k:
     *   dirs[k]=0 (current LEFT):  inv_in for AES_{current}(sibling XOR NODE_DOM)
     *   dirs[k]=1 (current RIGHT): inv_in for AES_{sibling}(current XOR NODE_DOM)
     * ================================================================ */
    uint8_t witness[864];
    memset(witness, 0, sizeof(witness));

    /* [0..15]: leaf data */
    memcpy(witness, leaf[5], 16);

    /* [16..215]: leaf hash inv_in */
    get_aes_inv_in(LEAF_DOM, leaf[5], witness + 16);

    /* [216..263]: all siblings in order (must come before path inv_in) */
    for (int lvl = 0; lvl < 3; lvl++)
        memcpy(witness + 216 + lvl * 16, siblings[lvl], 16);

    /* [264..863]: path inv_in for each level */
    uint8_t current[16];
    memcpy(current, lh[5], 16);

    for (int lvl = 0; lvl < 3; lvl++) {
        const uint8_t *sibling = siblings[lvl];
        uint8_t P[16];

        if (path_dirs[lvl] == 0) {
            /* current LEFT: H(current, sibling) = AES_{current}(sibling^NODE_DOM) ^ ... */
            for (int i = 0; i < 16; i++)
                P[i] = sibling[i] ^ NODE_DOM[i];
            get_aes_inv_in(current, P, witness + 264 + lvl * 200);
            uint8_t next[16];
            dm_compress(current, P, next);
            memcpy(current, next, 16);
        } else {
            /* current RIGHT: H(sibling, current) = AES_{sibling}(current^NODE_DOM) ^ ... */
            for (int i = 0; i < 16; i++)
                P[i] = current[i] ^ NODE_DOM[i];
            get_aes_inv_in(sibling, P, witness + 264 + lvl * 200);
            uint8_t next[16];
            dm_compress(sibling, P, next);
            memcpy(current, next, 16);
        }
    }

    /* Sanity check: 'current' should now equal 'root' */
    if (memcmp(current, root, 16) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: root (16 bytes) */
    const uint8_t *instance = root;

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    int rc =
        voleith_gf8_prove(&proof, params, c, witness, instance,
                          "example_merkle_gf8:depth3-DM-leaf5",
                          sizeof("example_merkle_gf8:depth3-DM-leaf5") - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_gf8_verify(&proof, params, c, instance,
                            "example_merkle_gf8:depth3-DM-leaf5",
                            sizeof("example_merkle_gf8:depth3-DM-leaf5") - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
