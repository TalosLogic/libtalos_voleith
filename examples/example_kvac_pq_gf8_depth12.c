/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kvac_pq_gf8_depth12.c - Signal KVAC PQ proof, depth-12 trees (GF(2^8))
 *
 * Production-scale version of example_kvac_pq_gf8.c.  Both the membership
 * and revocation trees are depth 12 (4096 leaf slots each), matching an
 * append-only tree that can hold ~1000 active members with typical churn
 * over the group lifetime.
 *
 * Each extra depth level vs. the depth-3 example adds 217 ell:
 *   Membership: +9 levels  → +1953 ell
 *   Revocation: +11 levels → +2387 ell
 *   Total ell = 3468 + 4340 = 7808
 *
 * Instance wires: 192 (mem nodes) + 16 (nonce) + 192 (rev nodes)
 *                 + 16+16+1 (low/next/idx) + 16+16+16 (roots/binding) = 481 bytes
 * Witness bytes: 16 (key) + 16 (uid) + 600 (KDF) + 12 (mem dirs)
 *                + 2400 (mem path) + 600 (binding) + 12 (rev dirs)
 *                + 600 (rev leaf) + 2400 (rev path) = 6656 bytes
 *
 * Build with the clmul_aesni variant for hardware-accelerated timing:
 *   cmake -DVOLEITH_AESNI=ON -DVOLEITH_CLMUL=ON ..
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "aes_gf8_circuit.h"
#include "aes_cmac_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "merkle_gf8_circuit.h"
#include "indexed_merkle_gf8_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define MEM_DEPTH 12
#define REV_DEPTH 12
#define MEM_MEMBER_IDX 2
#define MEM_N_LEAVES (1 << MEM_DEPTH) /* 4096 */
#define REV_N_LEAVES (1 << REV_DEPTH) /* 4096 */

#define WITNESS_BYTES 6656u
#define INSTANCE_BYTES 481u

/* ================================================================
 * Domain constants - must match merkle_gf8_circuit.c
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d,
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00};
static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d,
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00};

/* ================================================================
 * Software reference helpers
 * ================================================================ */

static double
now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec * 1e-6;
}

static void
print_hex16(const uint8_t h[16])
{
    for (int i = 0; i < 16; i++)
        printf("%02x", h[i]);
}

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
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ MERKLE_INODE_DOMAIN[i];
    dm_compress(L, P, out);
}

static void
dm_leaf_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);
    size_t n_blocks = (len + 15) / 16;
    if (n_blocks == 0)
        n_blocks = 1;
    int last_full = (len > 0) && (len % 16 == 0);
    for (size_t i = 0; i < n_blocks; i++) {
        uint8_t block[16] = {0};
        size_t off = i * 16;
        size_t chunk = (len > off) ? (len - off < 16 ? len - off : 16) : 0;
        if (chunk)
            memcpy(block, data + off, chunk);
        if (i == n_blocks - 1 && !last_full)
            block[chunk] = 0x80;
        dm_compress(state, block, state);
    }
    memcpy(out, state, 16);
}

static void
cmac128_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    static const uint8_t Rb = 0x87;
    uint8_t L[16] = {0};
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, L, L);
    for (int i = 0; i < 15; i++)
        k1[i] = (uint8_t)((L[i] << 1) | (L[i + 1] >> 7));
    k1[15] = (uint8_t)(L[15] << 1);
    if (L[0] & 0x80)
        k1[15] ^= Rb;
    for (int i = 0; i < 15; i++)
        k2[i] = (uint8_t)((k1[i] << 1) | (k1[i + 1] >> 7));
    k2[15] = (uint8_t)(k1[15] << 1);
    if (k1[0] & 0x80)
        k2[15] ^= Rb;
}

static void
cmac128(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t tag[16])
{
    uint8_t k1[16], k2[16];
    cmac128_subkeys(key, k1, k2);
    size_t n_blocks = (len + 15) / 16;
    if (n_blocks == 0)
        n_blocks = 1;
    int last_full = (len > 0) && (len % 16 == 0);
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    uint8_t state[16] = {0};
    for (size_t i = 0; i < n_blocks; i++) {
        uint8_t block[16] = {0};
        size_t off = i * 16;
        size_t chunk = (len > off) ? (len - off < 16 ? len - off : 16) : 0;
        if (chunk)
            memcpy(block, msg + off, chunk);
        if (i == n_blocks - 1) {
            if (last_full) {
                for (int j = 0; j < 16; j++)
                    block[j] ^= k1[j];
            } else {
                block[chunk] = 0x80;
                for (int j = 0; j < 16; j++)
                    block[j] ^= k2[j];
            }
        }
        for (int j = 0; j < 16; j++)
            state[j] ^= block[j];
        voleith_aes_encrypt(&ctx, state, state);
    }
    memcpy(tag, state, 16);
}

/*
 * get_dm_inode_inv_in - GF(2^8) witness (200 bytes) for one DM inode AES call.
 * H(L,R) = AES_L(R XOR C_inode) XOR (R XOR C_inode).
 */
static void
get_dm_inode_inv_in(const uint8_t L[16], const uint8_t R[16],
                    uint8_t inv_out[200], uint8_t next_out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ MERKLE_INODE_DOMAIN[i];
    uint8_t tmp[216], cipher[16];
    aes128_gf8_build_witness(L, P, tmp, cipher);
    memcpy(inv_out, tmp + 16, 200);
    if (next_out)
        for (int i = 0; i < 16; i++)
            next_out[i] = cipher[i] ^ P[i];
}

/* ================================================================
 * Tree helpers
 * ================================================================ */

/* Allocate level arrays for a complete binary tree of given depth. */
static uint8_t **
alloc_tree(int depth)
{
    uint8_t **t = malloc((size_t)(depth + 1) * sizeof(uint8_t *));
    if (!t) {
        fprintf(stderr, "OOM\n");
        exit(1);
    }
    for (int d = 0; d <= depth; d++) {
        t[d] = malloc((size_t)(1 << (depth - d)) * 16);
        if (!t[d]) {
            fprintf(stderr, "OOM\n");
            exit(1);
        }
    }
    return t;
}

static void
free_tree(uint8_t **t, int depth)
{
    for (int d = 0; d <= depth; d++)
        free(t[d]);
    free(t);
}

/* Build all internal nodes bottom-up from pre-filled leaf level. */
static void
build_tree_internals(uint8_t **tree, int depth)
{
    for (int d = 1; d <= depth; d++) {
        int n = 1 << (depth - d);
        for (int i = 0; i < n; i++)
            inode_hash_dm(tree[d - 1] + (2 * i) * 16,
                          tree[d - 1] + (2 * i + 1) * 16, tree[d] + i * 16);
    }
}

/*
 * Extract path from leaf_idx to root.
 * dirs[d]     = (leaf_idx >> d) & 1
 * siblings[d] = tree[d][sibling_index * 16 .. +16]
 */
static void
extract_path(uint8_t **tree, int depth, int leaf_idx, uint8_t *dirs,
             uint8_t *siblings)
{
    for (int d = 0; d < depth; d++) {
        int idx = leaf_idx >> d;
        dirs[d] = (uint8_t)(idx & 1);
        memcpy(siblings + d * 16, tree[d] + (idx ^ 1) * 16, 16);
    }
}

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    printf("=== Signal Hybrid KVAC - PQ proof, depth-12 trees (GF(2^8)) ===\n");
    printf("Config A: AES-128, NIST PQ Level 1 - element-level circuit\n");
#if defined(VOLEITH_HAVE_AES_NI) && defined(VOLEITH_HAVE_CLMUL)
    printf("Hardware: AES-NI + CLMUL\n");
#elif defined(VOLEITH_HAVE_AES_NI)
    printf("Hardware: AES-NI (no CLMUL)\n");
#elif defined(VOLEITH_HAVE_CLMUL)
    printf("Hardware: CLMUL (no AES-NI)\n");
#else
    printf("Hardware: software fallback\n");
#endif
    printf("Membership tree: depth=%d, %d leaf slots, member at index %d\n",
           MEM_DEPTH, MEM_N_LEAVES, MEM_MEMBER_IDX);
    printf("Revocation tree: depth=%d, %d leaf slots, 2 sentinels\n\n",
           REV_DEPTH, REV_N_LEAVES);

    /* ================================================================
     * Sample credentials (same as depth-3 example)
     * ================================================================ */
    static const uint8_t PQ_KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                       0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                       0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t UID[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t SESSION_NONCE[16] = {
        0xa5, 0x3d, 0x19, 0xc7, 0x82, 0xf0, 0x4b, 0x11,
        0xce, 0x77, 0x2e, 0x90, 0x01, 0x6a, 0xd4, 0x53};
    static const char MEMBERSHIP_TAG[] = "membership";
    static const char BINDING_TAG[] = "binding";

    /* ================================================================
     * Compute the member's KDF leaf
     * ================================================================ */
    uint8_t fi[26];
    memcpy(fi, UID, 16);
    memcpy(fi + 16, MEMBERSHIP_TAG, 10);

    uint8_t member_leaf[16];
    {
        uint8_t msg[30];
        msg[0] = 0;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 1;
        memcpy(msg + 4, fi, 26);
        cmac128(PQ_KEY, msg, 30, member_leaf);
    }
    printf("Member's KDF leaf: ");
    print_hex16(member_leaf);
    printf("\n\n");

    /* ================================================================
     * Build membership tree (depth=12, 4096 leaves, sparse)
     * Leaves: member at MEM_MEMBER_IDX; all others synthetic KDF values.
     * Synthetic key for index i: k[0]=i&0xFF, k[1]=(i>>8)&0xFF (unique for i<65536).
     * ================================================================ */
    double t0 = now_ms();

    uint8_t **mem_tree = alloc_tree(MEM_DEPTH);
    for (int i = 0; i < MEM_N_LEAVES; i++) {
        if (i == MEM_MEMBER_IDX) {
            memcpy(mem_tree[0] + i * 16, member_leaf, 16);
        } else {
            uint8_t k[16] = {0}, f[26], msg[30];
            k[0] = (uint8_t)(i & 0xFF);
            k[1] = (uint8_t)((i >> 8) & 0xFF);
            memcpy(f, k, 16);
            memcpy(f + 16, MEMBERSHIP_TAG, 10);
            msg[0] = 0;
            msg[1] = 0;
            msg[2] = 0;
            msg[3] = 1;
            memcpy(msg + 4, f, 26);
            cmac128(k, msg, 30, mem_tree[0] + i * 16);
        }
    }
    build_tree_internals(mem_tree, MEM_DEPTH);

    uint8_t mem_dirs[MEM_DEPTH];
    uint8_t mem_siblings[MEM_DEPTH * 16];
    extract_path(mem_tree, MEM_DEPTH, MEM_MEMBER_IDX, mem_dirs, mem_siblings);
    uint8_t *mem_root = mem_tree[MEM_DEPTH];

    double t_mem_tree = now_ms() - t0;

    printf("Membership tree (depth=%d, DM hash, %d leaves):\n", MEM_DEPTH,
           MEM_N_LEAVES);
    printf("  root:  ");
    print_hex16(mem_root);
    printf("\n");
    printf("  Path siblings (leaf-level first):\n");
    for (int d = 0; d < MEM_DEPTH; d++) {
        printf("    [%2d] dir=%d sibling=", d, mem_dirs[d]);
        print_hex16(mem_siblings + d * 16);
        printf("\n");
    }
    printf("  Build time: %.2f ms\n\n", t_mem_tree);

    /* ================================================================
     * Build revocation indexed Merkle tree (depth=12, 4096 slots).
     *   slot 0: min sentinel {0x00..00, 0xFF..FF, next_idx=1}
     *   slot 1: max sentinel {0xFF..FF, 0x00..00, next_idx=0}
     *   slots 2..4095: empty record {0x00 × 33}
     * Adjacent leaf for non-membership proof: slot 0 (dirs all 0).
     * ================================================================ */
    t0 = now_ms();

    static const uint8_t REV_MIN[16] = {0};
    static const uint8_t REV_MAX[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff};
    static const uint8_t REV_NEXT_IDX = 0x01;

    uint8_t rev_ld0[33];
    memcpy(rev_ld0, REV_MIN, 16);
    memcpy(rev_ld0 + 16, REV_MAX, 16);
    rev_ld0[32] = REV_NEXT_IDX;

    uint8_t rev_lh[2][16], rev_lh_empty[16];
    dm_leaf_hash(rev_ld0, 33, rev_lh[0]);
    {
        uint8_t ld1[33];
        memcpy(ld1, REV_MAX, 16);
        memcpy(ld1 + 16, REV_MIN, 16);
        ld1[32] = 0x00;
        dm_leaf_hash(ld1, 33, rev_lh[1]);
    }
    {
        uint8_t empty[33] = {0};
        dm_leaf_hash(empty, 33, rev_lh_empty);
    }

    uint8_t **rev_tree = alloc_tree(REV_DEPTH);
    memcpy(rev_tree[0] + 0 * 16, rev_lh[0], 16);
    memcpy(rev_tree[0] + 1 * 16, rev_lh[1], 16);
    for (int i = 2; i < REV_N_LEAVES; i++)
        memcpy(rev_tree[0] + i * 16, rev_lh_empty, 16);
    build_tree_internals(rev_tree, REV_DEPTH);

    /* Adjacent leaf at position 0: dirs all 0, siblings at index 1 each level. */
    uint8_t rev_dirs[REV_DEPTH];
    uint8_t rev_siblings[REV_DEPTH * 16];
    extract_path(rev_tree, REV_DEPTH, 0, rev_dirs, rev_siblings);
    uint8_t *rev_root = rev_tree[REV_DEPTH];

    double t_rev_tree = now_ms() - t0;

    printf("Revocation indexed Merkle tree (depth=%d, DM hash, %d slots):\n",
           REV_DEPTH, REV_N_LEAVES);
    printf("  root:  ");
    print_hex16(rev_root);
    printf("\n");
    printf("  leaf[0] (min sentinel): ");
    print_hex16(rev_lh[0]);
    printf("\n");
    printf("  leaf[1] (max sentinel): ");
    print_hex16(rev_lh[1]);
    printf("\n");
    printf("  Build time: %.2f ms\n\n", t_rev_tree);

    /* ================================================================
     * Binding: AES-CMAC(pq_key, session_nonce || "binding")
     * ================================================================ */
    uint8_t bm[23];
    memcpy(bm, SESSION_NONCE, 16);
    memcpy(bm + 16, BINDING_TAG, 7);
    uint8_t binding[16];
    cmac128(PQ_KEY, bm, 23, binding);

    /* ================================================================
     * Build GF(2^8) circuit
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* Private: pq_key, uid */
    gf8_wire_id pq_key_wires[16], uid_wires[16];
    for (int i = 0; i < 16; i++)
        pq_key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        uid_wires[i] = voleith_gf8_add_witness(c);

    /* Component 1: KDF-CTR leaf (3 AES calls → 600 inv_in) */
    gf8_wire_id fi_wires[26];
    for (int i = 0; i < 16; i++)
        fi_wires[i] = uid_wires[i];
    for (int i = 0; i < 10; i++)
        fi_wires[16 + i] = voleith_gf8_add_const(c, (uint8_t)MEMBERSHIP_TAG[i]);

    gf8_wire_id leaf_wires[16];
    if (kdf_ctr_cmac_gf8_circuit(c, pq_key_wires, 16, fi_wires, 26, leaf_wires,
                                 16) != 0) {
        fprintf(stderr, "kdf_ctr_cmac_gf8_circuit: stack-VLA bound exceeded\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Component 2: Membership path (depth=12, DM, secret dirs, 16 mul/level) */
    gf8_wire_id mem_node_wires[MEM_DEPTH * 16];
    for (int i = 0; i < MEM_DEPTH * 16; i++)
        mem_node_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id mem_dir_wires[MEM_DEPTH];
    for (int i = 0; i < MEM_DEPTH; i++)
        mem_dir_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id mem_root_computed[16];
    merkle_gf8_path_circuit_secret_dir(
        c, leaf_wires, mem_node_wires, mem_dir_wires, MEM_DEPTH,
        VOLEITH_MERKLE_HASH_AES_DM, mem_root_computed);

    /* Session nonce: public instance */
    gf8_wire_id nonce_wires[16];
    for (int i = 0; i < 16; i++)
        nonce_wires[i] = voleith_gf8_add_instance(c);

    /* Component 3: Binding CMAC (3 AES calls → 600 inv_in) */
    gf8_wire_id binding_msg_wires[23];
    for (int i = 0; i < 16; i++)
        binding_msg_wires[i] = nonce_wires[i];
    for (int i = 0; i < 7; i++)
        binding_msg_wires[16 + i] =
            voleith_gf8_add_const(c, (uint8_t)BINDING_TAG[i]);

    gf8_wire_id binding_computed[16];
    aes_cmac_gf8_circuit(c, pq_key_wires, 16, binding_msg_wires, 23,
                         binding_computed);

    /* Component 4: Revocation non-membership (depth=12, DM, secret dirs) */
    gf8_wire_id rev_node_wires[REV_DEPTH * 16];
    for (int i = 0; i < REV_DEPTH * 16; i++)
        rev_node_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id rev_dir_wires[REV_DEPTH];
    for (int i = 0; i < REV_DEPTH; i++)
        rev_dir_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id low_val_wires[16], low_next_wires[16], next_idx_wires[1];
    for (int i = 0; i < 16; i++)
        low_val_wires[i] = voleith_gf8_add_instance(c);
    for (int i = 0; i < 16; i++)
        low_next_wires[i] = voleith_gf8_add_instance(c);
    next_idx_wires[0] = voleith_gf8_add_instance(c);

    gf8_wire_id rev_root_computed[16];
    if (indexed_merkle_gf8_nonmember_circuit_secret_dir(
            c, leaf_wires, 16, low_val_wires, low_next_wires, next_idx_wires,
            1, rev_node_wires, rev_dir_wires, REV_DEPTH,
            VOLEITH_MERKLE_HASH_AES_DM, rev_root_computed) != 0) {
        fprintf(stderr,
                "indexed_merkle_gf8_nonmember_circuit_secret_dir: leaf data "
                "exceeds stack-VLA bound\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* Assert computed roots and binding match public instances */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id w = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, mem_root_computed[i], w);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id w = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, binding_computed[i], w);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id w = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, rev_root_computed[i], w);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:      %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:  %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires: %zu\n", voleith_gf8_circuit_instance_count(c));
    printf("  ell:            %zu  (vs 3468 at depth=3; +%zu)\n", ell,
           ell - 3468);
    printf("  Expected proof: %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (6656 bytes)
     * Slot order mirrors add_witness call order in circuit above.
     * ================================================================ */
    uint8_t *witness = calloc(WITNESS_BYTES, 1);
    if (!witness) {
        voleith_gf8_circuit_free(c);
        return 1;
    }
    uint8_t *wp = witness;

    /* [0..15]: pq_key */
    memcpy(wp, PQ_KEY, 16);
    wp += 16;

    /* [16..31]: uid */
    memcpy(wp, UID, 16);
    wp += 16;

    /* [32..631]: KDF-CTR inv_in (3 AES × 200 = 600 bytes) */
    {
        size_t n = kdf_ctr_cmac_gf8_witness_bytes(16, 16, 26);
        uint8_t *tmp = malloc(n);
        if (!tmp) {
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        uint8_t check[16];
        kdf_ctr_cmac_gf8_build_witness(PQ_KEY, 16, fi, 26, 16, tmp, check);
        if (memcmp(check, member_leaf, 16) != 0) {
            fprintf(stderr, "KDF witness mismatch\n");
            free(tmp);
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        memcpy(wp, tmp + 16, n - 16);
        wp += n - 16;
        free(tmp);
    }

    /* [632..643]: membership path_dirs (12 bytes) */
    memcpy(wp, mem_dirs, MEM_DEPTH);
    wp += MEM_DEPTH;

    /* [644..3043]: membership path inv_in (12 levels × 200 = 2400 bytes) */
    {
        uint8_t current[16];
        memcpy(current, member_leaf, 16);
        for (int lvl = 0; lvl < MEM_DEPTH; lvl++) {
            uint8_t dir = mem_dirs[lvl];
            const uint8_t *sib = mem_siblings + lvl * 16;
            const uint8_t *L = dir ? sib : current;
            const uint8_t *R = dir ? current : sib;
            uint8_t next[16];
            get_dm_inode_inv_in(L, R, wp, next);
            wp += 200;
            memcpy(current, next, 16);
        }
        if (memcmp(current, mem_root, 16) != 0) {
            fprintf(stderr, "membership path witness: root mismatch\n");
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
    }

    /* [3044..3643]: binding CMAC inv_in (3 AES × 200 = 600 bytes) */
    {
        size_t n = aes_cmac_gf8_witness_bytes(16, 23);
        uint8_t *tmp = malloc(n);
        if (!tmp) {
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        uint8_t check[16];
        aes_cmac_gf8_build_witness(PQ_KEY, 16, bm, 23, tmp, check);
        if (memcmp(check, binding, 16) != 0) {
            fprintf(stderr, "binding witness mismatch\n");
            free(tmp);
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        memcpy(wp, tmp + 16, n - 16);
        wp += n - 16;
        free(tmp);
    }

    /* [3644..3655]: revocation path_dirs (12 bytes, all 0) */
    memcpy(wp, rev_dirs, REV_DEPTH);
    wp += REV_DEPTH;

    /* [3656..4255]: revocation adjacent leaf hash inv_in (3 DM AES × 200 = 600 bytes).
     * DM chain: state_0=LEAF_DOMAIN, then compress block by block with ISO padding.
     * rev_ld0 = 33 bytes: 2 full blocks + 1-byte remainder → 3 blocks (with padding). */
    {
        uint8_t state[16];
        memcpy(state, MERKLE_LEAF_DOMAIN, 16);
        /* Block 0: rev_ld0[0..15] */
        uint8_t tmp[216], cipher[16];
        aes128_gf8_build_witness(state, rev_ld0, tmp, cipher);
        memcpy(wp, tmp + 16, 200);
        wp += 200;
        for (int i = 0; i < 16; i++)
            state[i] = cipher[i] ^ rev_ld0[i];
        /* Block 1: rev_ld0[16..31] */
        aes128_gf8_build_witness(state, rev_ld0 + 16, tmp, cipher);
        memcpy(wp, tmp + 16, 200);
        wp += 200;
        for (int i = 0; i < 16; i++)
            state[i] = cipher[i] ^ rev_ld0[16 + i];
        /* Block 2 (padded): [rev_ld0[32]=next_idx, 0x80, 0x00..] */
        uint8_t blk[16] = {0};
        blk[0] = rev_ld0[32];
        blk[1] = 0x80;
        aes128_gf8_build_witness(state, blk, tmp, cipher);
        memcpy(wp, tmp + 16, 200);
        wp += 200;
        uint8_t check[16];
        for (int i = 0; i < 16; i++)
            check[i] = cipher[i] ^ blk[i];
        if (memcmp(check, rev_lh[0], 16) != 0) {
            fprintf(stderr, "rev leaf hash witness mismatch\n");
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
    }

    /* [4256..6655]: revocation path inv_in (12 DM inode AES × 200 = 2400 bytes) */
    {
        uint8_t current[16];
        memcpy(current, rev_lh[0], 16);
        for (int lvl = 0; lvl < REV_DEPTH; lvl++) {
            uint8_t dir = rev_dirs[lvl]; /* always 0 */
            const uint8_t *sib = rev_siblings + lvl * 16;
            const uint8_t *L = dir ? sib : current;
            const uint8_t *R = dir ? current : sib;
            uint8_t next[16];
            get_dm_inode_inv_in(L, R, wp, next);
            wp += 200;
            memcpy(current, next, 16);
        }
        if (memcmp(current, rev_root, 16) != 0) {
            fprintf(stderr, "revocation path witness: root mismatch\n");
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
    }

    if ((size_t)(wp - witness) != WITNESS_BYTES) {
        fprintf(stderr, "witness size error: got %zu expected %zu\n",
                (size_t)(wp - witness), WITNESS_BYTES);
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ================================================================
     * Build instance (481 bytes)
     * Order matches add_instance call order in circuit above.
     * ================================================================ */
    uint8_t instance[INSTANCE_BYTES];
    memset(instance, 0, sizeof(instance));
    uint8_t *ip = instance;

    /* [0..191]: membership path siblings (12×16) */
    memcpy(ip, mem_siblings, MEM_DEPTH * 16);
    ip += MEM_DEPTH * 16;

    /* [192..207]: session nonce */
    memcpy(ip, SESSION_NONCE, 16);
    ip += 16;

    /* [208..399]: revocation path siblings (12×16) */
    memcpy(ip, rev_siblings, REV_DEPTH * 16);
    ip += REV_DEPTH * 16;

    /* [400..415]: low_value */
    memcpy(ip, REV_MIN, 16);
    ip += 16;

    /* [416..431]: low_next */
    memcpy(ip, REV_MAX, 16);
    ip += 16;

    /* [432]: next_idx */
    *ip++ = REV_NEXT_IDX;

    /* [433..448]: membership root */
    memcpy(ip, mem_root, 16);
    ip += 16;

    /* [449..464]: binding */
    memcpy(ip, binding, 16);
    ip += 16;

    /* [465..480]: revocation root */
    memcpy(ip, rev_root, 16);
    ip += 16;

    if ((size_t)(ip - instance) != INSTANCE_BYTES) {
        fprintf(stderr, "instance size error: got %zu expected %zu\n",
                (size_t)(ip - instance), INSTANCE_BYTES);
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ================================================================
     * Prove
     * ================================================================ */
    static const char FS_SEED[] =
        "kvac-pq-gf8:mem-depth12-rev-depth12-config-a";

    voleith_proof_t proof = {0};
    t0 = now_ms();
    int rc = voleith_gf8_prove(&proof, params, c, witness, instance, FS_SEED,
                               sizeof(FS_SEED) - 1);
    double t_prove = now_ms() - t0;
    free(witness);

    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove failed\n");
        voleith_gf8_circuit_free(c);
        free_tree(mem_tree, MEM_DEPTH);
        free_tree(rev_tree, REV_DEPTH);
        return 1;
    }
    printf("Proof generated: %zu bytes  (prove: %.1f ms)\n", proof.len,
           t_prove);

    /* ================================================================
     * Verify
     * ================================================================ */
    t0 = now_ms();
    rc = voleith_gf8_verify(&proof, params, c, instance, FS_SEED,
                            sizeof(FS_SEED) - 1);
    double t_verify = now_ms() - t0;

    printf("Verification: %s  (verify: %.1f ms)\n\n",
           (rc == 0) ? "PASS" : "FAIL", t_verify);

    printf("Timing summary:\n");
    printf("  Tree build (mem): %.2f ms\n", t_mem_tree);
    printf("  Tree build (rev): %.2f ms\n", t_rev_tree);
    printf("  Prove:            %.1f ms\n", t_prove);
    printf("  Verify:           %.1f ms\n", t_verify);

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    free_tree(mem_tree, MEM_DEPTH);
    free_tree(rev_tree, REV_DEPTH);
    return (rc == 0) ? 0 : 1;
}
