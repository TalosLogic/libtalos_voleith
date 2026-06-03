/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kvac_pq_grostl_gf8_depth12.c - Signal KVAC PQ proof, depth-12
 * trees, with wide-node Grøstl-256 Merkle hashing (GF(2^8) circuit).
 *
 * Production-scale Grøstl variant of example_kvac_pq_grostl_gf8.c: both
 * the membership and revocation trees are depth 12 (4096 leaf slots),
 * matching a tree holding ~1000 active members with churn.  See that
 * file for the statement and the rationale for Grøstl nodes (collision
 * resistance at the security level under an adversarial prover, vs. 2^64
 * for the 16-byte AES-DM nodes of example_kvac_pq_gf8_depth12.c).
 *
 * Uses the Grøstl-256 _T27 variant (27-byte nodes, 2^108 CR, single-block
 * inodes) for ~37% smaller proofs than the full 32-byte / 2^128
 * GROSTL_256 variant; swap the VARIANT constant below to trade proof size
 * for the full 2^128.  Both trees use the secret-dir circuits so the leaf
 * index stays private.  The 16-byte KDF leaf is hashed to a node
 * (leaf node = Grøstl(0x00 || KDF leaf)) before the membership path.
 *
 * Build with the clmul_aesni variant for hardware-accelerated timing:
 *   cmake -DVOLEITH_AES_NI=ON -DVOLEITH_CLMUL=ON ..
 */

/* POSIX.1b for clock_gettime / CLOCK_MONOTONIC */
#define _POSIX_C_SOURCE 199309L

#include "gf8_circuit.h"
#include "gf8_proof.h"
#include "aes_cmac_gf8_circuit.h"
#include "kdf_ctr_cmac_gf8_circuit.h"
#include "merkle_grostl_gf8_circuit.h"
#include "indexed_merkle_grostl_gf8_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MEM_DEPTH 12
#define REV_DEPTH 12
#define MEM_MEMBER_IDX 2
#define MEM_N_LEAVES (1 << MEM_DEPTH)
#define REV_N_LEAVES (1 << REV_DEPTH)

static const voleith_merkle_grostl_variant_t VARIANT =
    VOLEITH_MERKLE_GROSTL_256_T27;

static double
now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1000.0 + (double)t.tv_nsec / 1.0e6;
}

/* ================================================================
 * Software AES-CMAC (RFC 4493) for the KDF leaf, binding, and the
 * synthetic membership leaves.
 * ================================================================ */

static void
cmac128_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    uint8_t L[16] = {0};
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, L, L);
    for (int i = 0; i < 15; i++)
        k1[i] = (uint8_t)((L[i] << 1) | (L[i + 1] >> 7));
    k1[15] = (uint8_t)(L[15] << 1);
    if (L[0] & 0x80)
        k1[15] ^= 0x87;
    for (int i = 0; i < 15; i++)
        k2[i] = (uint8_t)((k1[i] << 1) | (k1[i + 1] >> 7));
    k2[15] = (uint8_t)(k1[15] << 1);
    if (k1[0] & 0x80)
        k2[15] ^= 0x87;
}

static void
cmac128(const uint8_t key[16], const uint8_t *msg, size_t len, uint8_t tag[16])
{
    uint8_t k1[16], k2[16];
    cmac128_subkeys(key, k1, k2);
    size_t n_blocks = (len + 15) / 16;
    if (!n_blocks)
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

static void
kdf_leaf(const uint8_t key[16], const uint8_t uid[16], uint8_t out[16])
{
    uint8_t msg[30];
    msg[0] = 0;
    msg[1] = 0;
    msg[2] = 0;
    msg[3] = 1;
    memcpy(msg + 4, uid, 16);
    memcpy(msg + 20, "membership", 10);
    cmac128(key, msg, 30, out);
}

static void
print_hex(const uint8_t *h, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", h[i]);
}

/* ================================================================
 * Grøstl Merkle tree over nb-byte nodes (complete binary tree).
 * ================================================================ */

static uint8_t **
alloc_tree(int depth, size_t nb)
{
    uint8_t **t = malloc((size_t)(depth + 1) * sizeof(*t));
    for (int d = 0; d <= depth; d++)
        t[d] = malloc((size_t)(1 << (depth - d)) * nb);
    return t;
}

static void
free_tree(uint8_t **t, int depth)
{
    for (int d = 0; d <= depth; d++)
        free(t[d]);
    free(t);
}

static void
build_tree_internals(uint8_t **tree, int depth, size_t nb)
{
    for (int d = 1; d <= depth; d++) {
        int n = 1 << (depth - d);
        for (int i = 0; i < n; i++)
            merkle_grostl_inode_hash(tree[d - 1] + (2 * i) * nb,
                                     tree[d - 1] + (2 * i + 1) * nb, VARIANT,
                                     tree[d] + i * nb);
    }
}

static void
extract_path(uint8_t **tree, int depth, size_t nb, int leaf_idx, uint8_t *dirs,
             uint8_t *siblings)
{
    int idx = leaf_idx;
    for (int d = 0; d < depth; d++) {
        dirs[d] = (uint8_t)(idx & 1);
        memcpy(siblings + (size_t)d * nb, tree[d] + (size_t)(idx ^ 1) * nb, nb);
        idx >>= 1;
    }
}

int
main(void)
{
    const size_t nb = merkle_grostl_node_bytes(VARIANT);

    printf("=== Signal Hybrid KVAC - PQ proof, depth-12 Grøstl-256 trees "
           "(GF(2^8)) ===\n");
    printf("Membership: depth=%d, %d leaves, member at index %d\n", MEM_DEPTH,
           MEM_N_LEAVES, MEM_MEMBER_IDX);
    printf("Revocation: depth=%d, %d slots (2 sentinels + empties)\n",
           REV_DEPTH, REV_N_LEAVES);
    printf("Node hash: Grøstl-256 T27 (27-byte nodes, 2^108 CR), secret "
           "leaf index\n\n");

    static const uint8_t PQ_KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                       0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                       0x09, 0xcf, 0x4f, 0x3c};
    static const uint8_t UID[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t SESSION_NONCE[16] = {
        0xa5, 0x3d, 0x19, 0xc7, 0x82, 0xf0, 0x4b, 0x11,
        0xce, 0x77, 0x2e, 0x90, 0x01, 0x6a, 0xd4, 0x53};

    uint8_t member_leaf[16];
    kdf_leaf(PQ_KEY, UID, member_leaf);
    printf("Member's KDF leaf: ");
    print_hex(member_leaf, 16);
    printf("\n");

    /* ----- membership tree (4096 leaves) ----- */
    double t0 = now_ms();
    uint8_t **mem_tree = alloc_tree(MEM_DEPTH, nb);
    for (int i = 0; i < MEM_N_LEAVES; i++) {
        uint8_t kdf_out[16];
        if (i == MEM_MEMBER_IDX) {
            memcpy(kdf_out, member_leaf, 16);
        } else {
            uint8_t k[16], u[16];
            k[0] = (uint8_t)(i & 0xff);
            k[1] = (uint8_t)((i >> 8) & 0xff);
            memset(k + 2, 0, 14);
            memcpy(u, k, 16);
            kdf_leaf(k, u, kdf_out);
        }
        merkle_grostl_leaf_hash(kdf_out, 16, VARIANT,
                                mem_tree[0] + (size_t)i * nb);
    }
    build_tree_internals(mem_tree, MEM_DEPTH, nb);

    uint8_t *mem_root = malloc(nb);
    memcpy(mem_root, mem_tree[MEM_DEPTH], nb);

    uint8_t mem_dirs[MEM_DEPTH];
    uint8_t *mem_siblings = malloc((size_t)MEM_DEPTH * nb);
    extract_path(mem_tree, MEM_DEPTH, nb, MEM_MEMBER_IDX, mem_dirs,
                 mem_siblings);
    printf("Membership tree built in %.1f ms (root ", now_ms() - t0);
    print_hex(mem_root, 8);
    printf("...)\n");

    /* ----- revocation tree (4096 slots: 2 sentinels + empties) ----- */
    static const uint8_t REV_MIN[16] = {0};
    static const uint8_t REV_MAX[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff};
    static const uint8_t REV_NEXT_IDX = 0x01;

    uint8_t rev_ld0[33]; /* adjacent leaf: {REV_MIN, REV_MAX, 1} */
    memcpy(rev_ld0, REV_MIN, 16);
    memcpy(rev_ld0 + 16, REV_MAX, 16);
    rev_ld0[32] = REV_NEXT_IDX;

    t0 = now_ms();
    uint8_t **rev_tree = alloc_tree(REV_DEPTH, nb);
    {
        uint8_t ld1[33], empty[33] = {0}, node1[64], node_empty[64];
        memcpy(ld1, REV_MAX, 16);
        memcpy(ld1 + 16, REV_MIN, 16);
        ld1[32] = 0x00;
        merkle_grostl_leaf_hash(rev_ld0, 33, VARIANT, rev_tree[0] + 0 * nb);
        merkle_grostl_leaf_hash(ld1, 33, VARIANT, node1);
        merkle_grostl_leaf_hash(empty, 33, VARIANT, node_empty);
        memcpy(rev_tree[0] + 1 * nb, node1, nb);
        for (int i = 2; i < REV_N_LEAVES; i++)
            memcpy(rev_tree[0] + (size_t)i * nb, node_empty, nb);
    }
    build_tree_internals(rev_tree, REV_DEPTH, nb);

    uint8_t *rev_root = malloc(nb);
    memcpy(rev_root, rev_tree[REV_DEPTH], nb);

    /* Adjacent leaf at slot 0: dirs all 0. */
    uint8_t rev_dirs[REV_DEPTH];
    uint8_t *rev_siblings = malloc((size_t)REV_DEPTH * nb);
    extract_path(rev_tree, REV_DEPTH, nb, 0, rev_dirs, rev_siblings);
    printf("Revocation tree built in %.1f ms (root ", now_ms() - t0);
    print_hex(rev_root, 8);
    printf("...)\n\n");

    /* ----- binding ----- */
    uint8_t bm[23];
    memcpy(bm, SESSION_NONCE, 16);
    memcpy(bm + 16, "binding", 7);
    uint8_t binding[16];
    cmac128(PQ_KEY, bm, 23, binding);

    /* ================================================================
     * Build the circuit.
     * ================================================================ */
    voleith_gf8_circuit_t *c = voleith_gf8_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    gf8_wire_id pq_key_wires[16], uid_wires[16];
    for (int i = 0; i < 16; i++)
        pq_key_wires[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        uid_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id fi_wires[26];
    for (int i = 0; i < 16; i++)
        fi_wires[i] = uid_wires[i];
    for (int i = 0; i < 10; i++)
        fi_wires[16 + i] = voleith_gf8_add_const(c, (uint8_t) "membership"[i]);

    gf8_wire_id leaf_wires[16];
    if (kdf_ctr_cmac_gf8_circuit(c, pq_key_wires, 16, fi_wires, 26, leaf_wires,
                                 16) != 0) {
        fprintf(stderr, "kdf_ctr_cmac_gf8_circuit failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    gf8_wire_id *leaf_hash_wires = malloc(nb * sizeof(*leaf_hash_wires));
    merkle_grostl_gf8_leaf_hash_circuit(c, leaf_wires, 16, VARIANT,
                                        leaf_hash_wires);

    gf8_wire_id *mem_node_wires =
        malloc((size_t)MEM_DEPTH * nb * sizeof(*mem_node_wires));
    for (size_t i = 0; i < (size_t)MEM_DEPTH * nb; i++)
        mem_node_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id mem_dir_wires[MEM_DEPTH];
    for (int i = 0; i < MEM_DEPTH; i++)
        mem_dir_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id *mem_root_computed = malloc(nb * sizeof(*mem_root_computed));
    merkle_grostl_gf8_path_circuit_secret_dir(
        c, leaf_hash_wires, mem_node_wires, mem_dir_wires, MEM_DEPTH, VARIANT,
        mem_root_computed);

    gf8_wire_id nonce_wires[16];
    for (int i = 0; i < 16; i++)
        nonce_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id binding_msg_wires[23];
    for (int i = 0; i < 16; i++)
        binding_msg_wires[i] = nonce_wires[i];
    for (int i = 0; i < 7; i++)
        binding_msg_wires[16 + i] =
            voleith_gf8_add_const(c, (uint8_t) "binding"[i]);

    gf8_wire_id binding_computed[16];
    aes_cmac_gf8_circuit(c, pq_key_wires, 16, binding_msg_wires, 23,
                         binding_computed);

    gf8_wire_id *rev_node_wires =
        malloc((size_t)REV_DEPTH * nb * sizeof(*rev_node_wires));
    for (size_t i = 0; i < (size_t)REV_DEPTH * nb; i++)
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

    gf8_wire_id *rev_root_computed = malloc(nb * sizeof(*rev_root_computed));
    if (indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir(
            c, leaf_wires, 16, low_val_wires, low_next_wires, next_idx_wires, 1,
            rev_node_wires, rev_dir_wires, REV_DEPTH, VARIANT,
            rev_root_computed) != 0) {
        fprintf(stderr,
                "indexed_merkle_grostl_gf8_nonmember_circuit_secret_dir "
                "failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    for (size_t i = 0; i < nb; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, mem_root_computed[i], ri);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id bi = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, binding_computed[i], bi);
    }
    for (size_t i = 0; i < nb; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, rev_root_computed[i], ri);
    }

    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu\n", voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu\n", voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n",
           voleith_gf8_proof_byte_size(params, ell));

    /* ================================================================
     * Build the witness (add_witness declaration order).
     * ================================================================ */
    size_t mem_leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(16, VARIANT);
    size_t inode_invin = merkle_grostl_gf8_inode_invin_bytes(VARIANT);
    size_t rev_leaf_invin = merkle_grostl_gf8_leaf_invin_bytes(33, VARIANT);
    size_t kdf_w_bytes = kdf_ctr_cmac_gf8_witness_bytes(16, 16, 26);
    size_t bind_w_bytes = aes_cmac_gf8_witness_bytes(16, 23);

    size_t witness_bytes = 16 + 16 + (kdf_w_bytes - 16) + mem_leaf_invin +
                           MEM_DEPTH + (size_t)MEM_DEPTH * inode_invin +
                           (bind_w_bytes - 16) + REV_DEPTH + rev_leaf_invin +
                           (size_t)REV_DEPTH * inode_invin;

    if (witness_bytes != voleith_gf8_circuit_witness_count(c)) {
        fprintf(stderr, "witness layout mismatch: %zu vs circuit %zu\n",
                witness_bytes, voleith_gf8_circuit_witness_count(c));
        voleith_gf8_circuit_free(c);
        return 1;
    }

    uint8_t *witness = calloc(witness_bytes, 1);
    uint8_t *wp = witness;
    int ok = 1;

    memcpy(wp, PQ_KEY, 16);
    wp += 16;
    memcpy(wp, UID, 16);
    wp += 16;

    {
        uint8_t fi[26], leaf_check[16];
        memcpy(fi, UID, 16);
        memcpy(fi + 16, "membership", 10);
        uint8_t *kdf_w = malloc(kdf_w_bytes);
        kdf_ctr_cmac_gf8_build_witness(PQ_KEY, 16, fi, 26, 16, kdf_w,
                                       leaf_check);
        ok &= (memcmp(leaf_check, member_leaf, 16) == 0);
        memcpy(wp, kdf_w + 16, kdf_w_bytes - 16);
        wp += kdf_w_bytes - 16;
        free(kdf_w);
    }

    merkle_grostl_gf8_leaf_build_witness(member_leaf, 16, VARIANT, wp);
    wp += mem_leaf_invin;

    memcpy(wp, mem_dirs, MEM_DEPTH);
    wp += MEM_DEPTH;

    {
        uint8_t current[64], next[64];
        merkle_grostl_leaf_hash(member_leaf, 16, VARIANT, current);
        for (int lvl = 0; lvl < MEM_DEPTH; lvl++) {
            const uint8_t *sib = mem_siblings + (size_t)lvl * nb;
            const uint8_t *L = mem_dirs[lvl] ? sib : current;
            const uint8_t *R = mem_dirs[lvl] ? current : sib;
            merkle_grostl_gf8_inode_build_witness(L, R, VARIANT, wp);
            wp += inode_invin;
            merkle_grostl_inode_hash(L, R, VARIANT, next);
            memcpy(current, next, nb);
        }
        ok &= (memcmp(current, mem_root, nb) == 0);
    }

    {
        uint8_t bind_check[16];
        uint8_t *bind_w = malloc(bind_w_bytes);
        aes_cmac_gf8_build_witness(PQ_KEY, 16, bm, 23, bind_w, bind_check);
        ok &= (memcmp(bind_check, binding, 16) == 0);
        memcpy(wp, bind_w + 16, bind_w_bytes - 16);
        wp += bind_w_bytes - 16;
        free(bind_w);
    }

    memcpy(wp, rev_dirs, REV_DEPTH);
    wp += REV_DEPTH;

    merkle_grostl_gf8_leaf_build_witness(rev_ld0, 33, VARIANT, wp);
    wp += rev_leaf_invin;

    {
        uint8_t current[64], next[64];
        merkle_grostl_leaf_hash(rev_ld0, 33, VARIANT, current);
        for (int lvl = 0; lvl < REV_DEPTH; lvl++) {
            const uint8_t *sib = rev_siblings + (size_t)lvl * nb;
            const uint8_t *L = rev_dirs[lvl] ? sib : current;
            const uint8_t *R = rev_dirs[lvl] ? current : sib;
            merkle_grostl_gf8_inode_build_witness(L, R, VARIANT, wp);
            wp += inode_invin;
            merkle_grostl_inode_hash(L, R, VARIANT, next);
            memcpy(current, next, nb);
        }
        ok &= (memcmp(current, rev_root, nb) == 0);
    }

    if (!ok || (size_t)(wp - witness) != witness_bytes) {
        fprintf(stderr, "witness build error (ok=%d, size=%zu/%zu)\n", ok,
                (size_t)(wp - witness), witness_bytes);
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ================================================================
     * Build the instance (add_instance declaration order).
     * ================================================================ */
    size_t instance_bytes = (size_t)MEM_DEPTH * nb + 16 +
                            (size_t)REV_DEPTH * nb + 16 + 16 + 1 + nb + 16 + nb;
    uint8_t *instance = calloc(instance_bytes, 1);
    uint8_t *ip = instance;

    memcpy(ip, mem_siblings, (size_t)MEM_DEPTH * nb);
    ip += (size_t)MEM_DEPTH * nb;
    memcpy(ip, SESSION_NONCE, 16);
    ip += 16;
    memcpy(ip, rev_siblings, (size_t)REV_DEPTH * nb);
    ip += (size_t)REV_DEPTH * nb;
    memcpy(ip, REV_MIN, 16);
    ip += 16;
    memcpy(ip, REV_MAX, 16);
    ip += 16;
    *ip++ = REV_NEXT_IDX;
    memcpy(ip, mem_root, nb);
    ip += nb;
    memcpy(ip, binding, 16);
    ip += 16;
    memcpy(ip, rev_root, nb);
    ip += nb;

    /* ================================================================
     * Prove and verify (timed).
     * ================================================================ */
    static const char FS_SEED[] = "kvac-pq-grostl-gf8:mem-d12-rev-d12";

    voleith_proof_t proof = {0};
    t0 = now_ms();
    int rc = voleith_gf8_prove_v2(
        &proof, params, c, witness, voleith_gf8_circuit_witness_byte_len(c),
        instance, voleith_gf8_circuit_instance_byte_len(c), FS_SEED,
        sizeof(FS_SEED) - 1);
    double t_prove = now_ms() - t0;
    free(witness);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove_v2 failed\n");
        free(instance);
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("PQ proof generated: %zu bytes in %.1f ms\n", proof.len, t_prove);

    t0 = now_ms();
    rc = voleith_gf8_verify_v2(&proof, params, c, instance,
                               voleith_gf8_circuit_instance_byte_len(c),
                               FS_SEED, sizeof(FS_SEED) - 1);
    double t_verify = now_ms() - t0;
    printf("PQ proof verification: %s (%.1f ms)\n", (rc == 0) ? "PASS" : "FAIL",
           t_verify);

    voleith_proof_free(&proof);
    free(instance);
    free(mem_root);
    free(mem_siblings);
    free(rev_root);
    free(rev_siblings);
    free(leaf_hash_wires);
    free(mem_node_wires);
    free(mem_root_computed);
    free(rev_node_wires);
    free(rev_root_computed);
    free_tree(mem_tree, MEM_DEPTH);
    free_tree(rev_tree, REV_DEPTH);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
