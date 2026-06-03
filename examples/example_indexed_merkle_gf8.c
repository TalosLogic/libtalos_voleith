/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_indexed_merkle_gf8.c - ZK non-membership proof for indexed Merkle tree
 *                                (GF(2^8) element circuit)
 *
 * Same statement as example_indexed_merkle.c using the GF(2^8) circuit.
 *
 * Public (instance): target T (1 byte) || root R (16 bytes)
 * Private (witness): low_value, low_next, next_index (3 bytes) +
 *                    leaf AES inv_in (200 bytes for 3-byte leaf, DM) +
 *                    depth x (sibling (16 bytes) + path AES inv_in (200 bytes))
 *                    = 3 + 200 + 2*(16+200) = 635 bytes
 *
 * mul gate cost: 2 comparisons x 8 bits x 3 mul/bit = 48
 * ell = 635 + 48 = 683  (vs 22,186 bit-level)
 *
 * Tree: depth=2, 4 sorted leaves, DM hash.  Target T = 0x30.
 * Adjacent leaf: leaf[1] = (0x10, 0x50, 0x02), index=1=0b01.
 * path_dirs = [1, 0] - public uint8_t, zero mul-gate cost.
 */

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "indexed_merkle_gf8_circuit.h"
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
leaf_hash_dm_partial(const uint8_t *data, size_t len, uint8_t out[16])
{
    uint8_t padded[16] = {0};
    memcpy(padded, data, len);
    padded[len] = 0x80;
    dm_compress(LEAF_DOM, padded, out);
}

static void
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ NODE_DOM[i];
    dm_compress(L, P, out);
}

/* Get 200 inv_in bytes for AES_{key}(pt) */
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
    printf(
        "=== Indexed Merkle non-membership ZK proof (GF(2^8) circuit) ===\n");
    printf("Statement: 0x30 is not in {0x00, 0x10, 0x50, 0x80}\n");
    printf("Tree: 4 leaves (depth 2), Davies-Meyer AES-128, public leaf "
           "index\n\n");

    /* ================================================================
     * Build 4-leaf depth-2 indexed Merkle tree
     * ================================================================ */
    const uint8_t leaf_records[4][3] = {{0x00, 0x10, 0x01},
                                        {0x10, 0x50, 0x02},
                                        {0x50, 0x80, 0x03},
                                        {0x80, 0x00, 0x00}};

    uint8_t lh[4][16];
    for (int i = 0; i < 4; i++)
        leaf_hash_dm_partial(leaf_records[i], 3, lh[i]);

    uint8_t L1[2][16];
    for (int i = 0; i < 2; i++)
        inode_hash_dm(lh[2 * i], lh[2 * i + 1], L1[i]);

    uint8_t root[16];
    inode_hash_dm(L1[0], L1[1], root);

    const uint8_t TARGET = 0x30;
    const uint8_t LOW_VALUE = 0x10;
    const uint8_t LOW_NEXT = 0x50;
    const uint8_t NEXT_IDX = 0x02;
    /* Leaf index 1 = binary 01: path_dirs[0]=1 (right), path_dirs[1]=0 (left) */
    const uint8_t path_dirs[2] = {1, 0};
    /* Siblings: lh[0] (left sibling of lh[1]), L1[1] (right sibling of L1[0]) */
    const uint8_t *siblings[2] = {lh[0], L1[1]};

    /* ================================================================
     * Build circuit
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Target T: 1 public instance wire */
    gf8_wire_id target_wire = voleith_gf8_add_instance(c);

    /* Adjacent leaf fields: 3 private witness wires */
    gf8_wire_id low_val_wire = voleith_gf8_add_witness(c);
    gf8_wire_id low_next_wire = voleith_gf8_add_witness(c);
    gf8_wire_id next_idx_wire = voleith_gf8_add_witness(c);

    /* Path node bytes: depth*16 private witness wires */
    gf8_wire_id node_wires[2 * 16];
    for (int i = 0; i < 2 * 16; i++)
        node_wires[i] = voleith_gf8_add_witness(c);

    /* Indexed Merkle non-membership circuit
       (path_dirs are public uint8_t - zero mul-gate cost) */
    gf8_wire_id root_computed[16];
    if (indexed_merkle_gf8_nonmember_circuit(
            c, &target_wire, 1, /* target: 1 byte */
            &low_val_wire,      /* low_value */
            &low_next_wire,     /* low_next */
            &next_idx_wire, 1,  /* next_index: 1 byte */
            node_wires,         /* path nodes */
            path_dirs,          /* public direction bits */
            2,                  /* depth */
            VOLEITH_MERKLE_HASH_AES_DM, root_computed) != 0) {
        fprintf(stderr,
                "indexed_merkle_gf8_nonmember_circuit: leaf data exceeds "
                "stack-VLA bound\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Root: 16 public instance wires; assert equal */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id root_inst = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, root_computed[i], root_inst);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu (2 comparisons x 8 bits x 3)\n",
           voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu (1 target + 16 root)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (635 bytes):
     *   [0]:       low_value
     *   [1]:       low_next
     *   [2]:       next_index
     *   [3..18]:   sibling[0] = lh[0]       ← node_wires[0..15]
     *   [19..34]:  sibling[1] = L1[1]       ← node_wires[16..31]
     *   [35..234]: inv_in for AES_{LEAF_DOM}(padded 3-byte leaf)
     *   [235..434]: inv_in for DM compress at level 0
     *   [435..634]: inv_in for DM compress at level 1
     *
     * Slot order: externally-declared node_wires (3..34) always come
     * before inv_in wires added internally by the circuit function.
     * ================================================================ */
    uint8_t witness[635];
    memset(witness, 0, sizeof(witness));

    /* [0..2]: adjacent leaf fields */
    witness[0] = LOW_VALUE;
    witness[1] = LOW_NEXT;
    witness[2] = NEXT_IDX;

    /* [3..34]: path siblings (node_wires declared before circuit call) */
    memcpy(witness + 3, siblings[0], 16);
    memcpy(witness + 19, siblings[1], 16);

    /* [35..234]: leaf hash inv_in: AES_{LEAF_DOM}(padded_leaf) */
    uint8_t padded_leaf[16] = {0};
    padded_leaf[0] = LOW_VALUE;
    padded_leaf[1] = LOW_NEXT;
    padded_leaf[2] = NEXT_IDX;
    padded_leaf[3] = 0x80;
    get_aes_inv_in(LEAF_DOM, padded_leaf, witness + 35);

    /* [235..634]: path inv_in for each level */
    uint8_t current[16];
    memcpy(current, lh[1], 16); /* start at leaf[1] hash */

    for (int lvl = 0; lvl < 2; lvl++) {
        const uint8_t *sibling = siblings[lvl];
        uint8_t P[16];
        if (path_dirs[lvl] == 0) {
            /* current LEFT: AES_{current}(sibling XOR NODE_DOM) */
            for (int i = 0; i < 16; i++)
                P[i] = sibling[i] ^ NODE_DOM[i];
            get_aes_inv_in(current, P, witness + 235 + lvl * 200);
            uint8_t next[16];
            dm_compress(current, P, next);
            memcpy(current, next, 16);
        } else {
            /* current RIGHT: AES_{sibling}(current XOR NODE_DOM) */
            for (int i = 0; i < 16; i++)
                P[i] = current[i] ^ NODE_DOM[i];
            get_aes_inv_in(sibling, P, witness + 235 + lvl * 200);
            uint8_t next[16];
            dm_compress(sibling, P, next);
            memcpy(current, next, 16);
        }
    }

    if (memcmp(current, root, 16) != 0) {
        fprintf(stderr, "witness build: root mismatch\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Instance: target (1 byte) || root (16 bytes) */
    uint8_t instance[17];
    instance[0] = TARGET;
    memcpy(instance + 1, root, 16);

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    int rc = voleith_gf8_prove_v2(
        &proof, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
        instance, voleith_gf8_circuit_instance_byte_len(c),
        "example_indexed_merkle_gf8:T=0x30",
        sizeof("example_indexed_merkle_gf8:T=0x30") - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("Proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c),
                               "example_indexed_merkle_gf8:T=0x30",
                               sizeof("example_indexed_merkle_gf8:T=0x30") - 1);
    printf("Verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
