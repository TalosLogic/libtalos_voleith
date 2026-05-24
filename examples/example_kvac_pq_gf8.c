/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kvac_pq_gf8.c - PQ side of Signal hybrid KVAC group authentication
 *                          (GF(2^8) element-level circuit)
 *
 * GF(2^8) version of example_kvac_pq.c. The proof statement is identical:
 *
 *   "I know (pq_key, uid) such that:
 *    - leaf = KDF-CTR(AES-CMAC, pq_key, uid || 'membership') is in the
 *      membership Merkle tree at root R1
 *    - leaf is NOT in the revocation indexed Merkle tree at root R2
 *    - binding = AES-CMAC(pq_key, session_nonce || 'binding') is correct"
 *
 * The GF(2^8) element circuit reduces ell from ~95,140 (bit-level) to ~3,468,
 * a ~27x reduction. Each wire carries one GF(2^8) byte; the S-box inversions
 * in each AES call become single mul slots rather than 36 AND gate cascades.
 *
 * Wire privacy (same as the bit-level version per the KVAC spec Section 3.8):
 *   PRIVATE (witness): pq_key (16 B), uid (16 B),
 *                      membership path_dirs (3 B), revocation path_dir (1 B)
 *   PUBLIC  (instance): membership path_nodes (3×16 B), membership_root (16 B),
 *                       session_nonce (16 B), binding (16 B),
 *                       revocation path_node (16 B),
 *                       low_value (16 B), low_next (16 B), next_idx (1 B),
 *                       revocation_root (16 B)
 *
 * Membership path_dirs are private (witness) to prevent the server from
 * correlating the leaf position with the enrollment record and deanonymizing
 * the authenticating member. The secret-dir Merkle path circuits add 16 mul
 * gates per level (one MUX per output byte) - negligible compared to the
 * 200 inv_in witness slots per AES call already required.
 *
 * Witness layout (slot order = add_witness call order, 2636 bytes total):
 *   [0..15]     pq_key (16 B)
 *   [16..31]    uid (16 B)
 *   [32..631]   KDF-CTR inv_in (3 AES calls × 200 B = 600 B)
 *   [632..634]  membership path_dirs (3 B)
 *   [635..1234] membership path inv_in (3 levels × 200 B = 600 B)
 *   [1235..1834] binding CMAC inv_in (3 AES calls × 200 B = 600 B)
 *   [1835]      revocation path_dir (1 B)
 *   [1836..2435] revocation leaf hash inv_in (3 AES calls × 200 B = 600 B)
 *   [2436..2635] revocation path inv_in (1 level × 200 B = 200 B)
 *
 * Instance layout (161 bytes total):
 *   [0..47]    membership path nodes (3×16 B siblings)
 *   [48..63]   session nonce (16 B)
 *   [64..79]   revocation path node (depth=1 sibling, 16 B)
 *   [80..95]   low_value of adjacent revocation leaf (16 B)
 *   [96..111]  low_next of adjacent revocation leaf (16 B)
 *   [112]      next_idx of adjacent revocation leaf (1 B)
 *   [113..128] membership root (16 B, from assert_equal)
 *   [129..144] binding (16 B, from assert_equal)
 *   [145..160] revocation root (16 B, from assert_equal)
 *
 * Simplified parameters (same tree dimensions as the bit-level example):
 *   Membership tree:  depth=3, 8 leaves, DM hash, member at leaf index 2
 *   Revocation tree:  depth=1, 2 sentinel leaves (no revocations)
 */

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

/* ================================================================
 * Domain constants - must match merkle_gf8_circuit.c internals
 * ================================================================ */

static const uint8_t MERKLE_LEAF_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4c, 0x65, 0x61, 0x66, 0x00, 0x00, 0x00, 0x00  /* "Leaf\0\0\0\0" */
};
static const uint8_t MERKLE_INODE_DOMAIN[16] = {
    0x56, 0x4f, 0x4c, 0x45, 0x69, 0x74, 0x48, 0x2d, /* "VOLEitH-" */
    0x4e, 0x6f, 0x64, 0x65, 0x00, 0x00, 0x00, 0x00  /* "Node\0\0\0\0" */
};

/* ================================================================
 * Software reference helpers (same values as bit-level example)
 * ================================================================ */

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

/* DM inode: H(L,R) = AES_L(R XOR INODE_DOM) XOR (R XOR INODE_DOM) */
static void
inode_hash_dm(const uint8_t L[16], const uint8_t R[16], uint8_t out[16])
{
    uint8_t P[16];
    for (int i = 0; i < 16; i++)
        P[i] = R[i] ^ MERKLE_INODE_DOMAIN[i];
    dm_compress(L, P, out);
}

/* DM leaf hash - Merkle-Damgård with ISO 7816-4 padding */
static void
dm_leaf_hash(const uint8_t *data, size_t len, uint8_t out[16])
{
    size_t full = len / 16;
    size_t last = len % 16;
    int needs_pad = (len == 0) || (last != 0);

    uint8_t state[16];
    memcpy(state, MERKLE_LEAF_DOMAIN, 16);

    size_t n_inner = needs_pad ? full : (full > 0 ? full - 1 : 0);
    for (size_t i = 0; i < n_inner; i++) {
        uint8_t tmp[16];
        dm_compress(state, data + i * 16, tmp);
        memcpy(state, tmp, 16);
    }

    uint8_t padded[16] = {0};
    if (!needs_pad) {
        memcpy(padded, data + (full - 1) * 16, 16);
    } else {
        if (last)
            memcpy(padded, data + full * 16, last);
        padded[last] = 0x80;
    }
    dm_compress(state, padded, out);
}

/* AES-CMAC subkeys (RFC 4493) */
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

/* AES-128-CMAC */
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

/*
 * get_dm_inode_inv_in - compute 200 inv_in bytes for one DM inode compression.
 *
 * H(L,R) = AES_L(R XOR NODE_DOM) XOR (R XOR NODE_DOM).
 * Writes the 200 inv_in bytes to inv_out and, if next_out is non-NULL,
 * the 16-byte hash result.
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

static void
print_hex16(const uint8_t h[16])
{
    for (int i = 0; i < 16; i++)
        printf("%02x", h[i]);
}

int
main(void)
{
    printf(
        "=== Signal Hybrid KVAC - PQ membership proof (GF(2^8) VOLEitH) ===\n");
    printf("Config A: AES-128, NIST PQ Level 1 - element-level circuit\n");
    printf("Proves knowledge of (pq_key, uid) such that:\n");
    printf("  leaf = KDF-CTR(pq_key, uid||\"membership\") is in membership "
           "tree\n");
    printf("  leaf is NOT in revocation tree\n");
    printf("  binding = AES-CMAC(pq_key, nonce||\"binding\") is correct\n\n");

    /* ================================================================
     * Sample credentials
     * ================================================================ */
    static const uint8_t PQ_KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                       0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                       0x09, 0xcf, 0x4f, 0x3c};
    /* Simplified to 16 bytes; production uid is a 255-bit Ristretto255 scalar. */
    static const uint8_t UID[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    static const uint8_t SESSION_NONCE[16] = {
        0xa5, 0x3d, 0x19, 0xc7, 0x82, 0xf0, 0x4b, 0x11,
        0xce, 0x77, 0x2e, 0x90, 0x01, 0x6a, 0xd4, 0x53};

    /* ================================================================
     * Compute the member's Merkle leaf.
     *   leaf = KDF-CTR(AES-CMAC, pq_key, uid || "membership")
     * ================================================================ */
    static const char MEMBERSHIP_TAG[] = "membership";
    uint8_t fi[26];
    memcpy(fi, UID, 16);
    memcpy(fi + 16, MEMBERSHIP_TAG, 10);

    uint8_t member_leaf[16];
    {
        /* KDF-CTR(AES-CMAC): K(1) = CMAC(pq_key, [1]_32be || fi) */
        uint8_t msg[30];
        msg[0] = 0;
        msg[1] = 0;
        msg[2] = 0;
        msg[3] = 1;
        memcpy(msg + 4, fi, 26);
        cmac128(PQ_KEY, msg, 30, member_leaf);
    }

    printf("Member's KDF leaf: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", member_leaf[i]);
    printf("\n\n");

    /* ================================================================
     * Build 8-leaf membership tree (depth=3, DM hash).
     * Member is at index 2 = binary 010 (LSB-first: dirs = {0, 1, 0}).
     * ================================================================ */
    uint8_t leaf[8][16];
    for (int i = 0; i < 8; i++) {
        if (i == 2) {
            memcpy(leaf[i], member_leaf, 16);
        } else {
            uint8_t k[16], u[16], f[26], msg[30];
            memset(k, (uint8_t)i, 16);
            memset(u, (uint8_t)i, 16);
            memcpy(f, u, 16);
            memcpy(f + 16, MEMBERSHIP_TAG, 10);
            msg[0] = 0;
            msg[1] = 0;
            msg[2] = 0;
            msg[3] = 1;
            memcpy(msg + 4, f, 26);
            cmac128(k, msg, 30, leaf[i]);
        }
    }

    uint8_t L1[4][16], L2[2][16], mem_root[16];
    for (int i = 0; i < 4; i++)
        inode_hash_dm(leaf[2 * i], leaf[2 * i + 1], L1[i]);
    for (int i = 0; i < 2; i++)
        inode_hash_dm(L1[2 * i], L1[2 * i + 1], L2[i]);
    inode_hash_dm(L2[0], L2[1], mem_root);

    printf("Membership tree (depth=3, DM hash, 8 leaves):\n");
    printf("  root:     ");
    print_hex16(mem_root);
    printf("\n");
    printf("  L2[0]:    ");
    print_hex16(L2[0]);
    printf("\n");
    printf("  L2[1]:    ");
    print_hex16(L2[1]);
    printf("\n");
    for (int i = 0; i < 4; i++) {
        printf("  L1[%d]:    ", i);
        print_hex16(L1[i]);
        printf("\n");
    }
    for (int i = 0; i < 8; i++) {
        printf("  leaf[%d]:  ", i);
        print_hex16(leaf[i]);
        printf("%s\n", (i == 2) ? "  <- member (index 2)" : "");
    }
    printf("  Path dirs: {0,1,0}  siblings: [0]=leaf[3], [1]=L1[0], "
           "[2]=L2[1]\n\n");

    /*
     * Path for member at index 2 = 0b010 (bit 0=0, bit 1=1, bit 2=0):
     *   dir[0]=0: leaf[2] is LEFT child  → sibling = leaf[3]
     *   dir[1]=1: L1[1]  is RIGHT child  → sibling = L1[0]
     *   dir[2]=0: L2[0]  is LEFT child   → sibling = L2[1]
     */
    static const uint8_t MEM_DIRS[3] = {0, 1, 0};
    const uint8_t *mem_siblings[3] = {leaf[3], L1[0], L2[1]};

    /* ================================================================
     * Build 2-sentinel revocation indexed Merkle tree (depth=1).
     *   REV_MIN sentinel: {value=0x00..00, next=0xFF..FF, next_idx=1}
     *   REV_MAX sentinel: {value=0xFF..FF, next=0x00..00, next_idx=0}
     * Any leaf strictly between 0 and 2^128-1 is provably not revoked.
     * ================================================================ */
    static const uint8_t REV_MIN[16] = {0};
    static const uint8_t REV_MAX[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff};
    static const uint8_t REV_NEXT_IDX = 0x01;

    /* Rev leaf data = value(16B) || next_value(16B) || next_index(1B) = 33 bytes */
    uint8_t rev_ld0[33];
    memcpy(rev_ld0, REV_MIN, 16);
    memcpy(rev_ld0 + 16, REV_MAX, 16);
    rev_ld0[32] = REV_NEXT_IDX;

    uint8_t rev_lh[2][16];
    dm_leaf_hash(rev_ld0, 33, rev_lh[0]);
    { /* sentinel 1: {0xFF..FF, 0x00..00, 0x00} */
        uint8_t ld1[33];
        memcpy(ld1, REV_MAX, 16);
        memcpy(ld1 + 16, REV_MIN, 16);
        ld1[32] = 0x00;
        dm_leaf_hash(ld1, 33, rev_lh[1]);
    }
    uint8_t rev_root[16];
    inode_hash_dm(rev_lh[0], rev_lh[1], rev_root);

    printf("Revocation indexed Merkle tree (depth=1, DM hash, 2 sentinels):\n");
    printf("  root:     ");
    print_hex16(rev_root);
    printf("\n");
    printf("  leaf[0]:  ");
    print_hex16(rev_lh[0]);
    printf("  (min sentinel: value=0x00..00)\n");
    printf("  leaf[1]:  ");
    print_hex16(rev_lh[1]);
    printf("  (max sentinel: value=0xff..ff)\n");
    printf("  Non-membership path: target between leaf[0] and leaf[1] - not "
           "revoked\n\n");

    /* Non-membership proof for member_leaf via sentinel[0] (left child).
     *   dir[0]=0: sentinel[0] is LEFT child  → sibling = rev_lh[1]
     */
    static const uint8_t REV_DIRS[1] = {0};

    /* ================================================================
     * Binding: binding = AES-CMAC(pq_key, session_nonce || "binding")
     * ================================================================ */
    static const char BINDING_TAG[] = "binding";
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

    /* --- Private witnesses: pq_key and uid --- */
    gf8_wire_id pq_key_wires[16];
    for (int i = 0; i < 16; i++)
        pq_key_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id uid_wires[16];
    for (int i = 0; i < 16; i++)
        uid_wires[i] = voleith_gf8_add_witness(c);

    /* --- Component 1: KDF-CTR(AES-CMAC) leaf ---
     * fixed_input = uid_wires (private, 16 bytes) || "membership" (constant, 10 bytes)
     * KDF message = [1]_32be (4B const) || fixed_input (26B) = 30 bytes per iteration
     * aes_cmac_gf8_n_aes_calls(30) = 3 → 600 inv_in witness bytes added internally. */
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

    /* --- Component 2: Membership Merkle path (depth=3, DM, secret dirs) ---
     * path_nodes: PUBLIC instance (sibling hashes reveal position, not identity).
     * path_dirs:  PRIVATE witness (direction bits encode leaf index position).
     * 16 mul gates per level × 3 = 48 mul gates total.
     * 3 DM inode AES calls × 200 inv_in = 600 witness bytes added internally. */
    gf8_wire_id mem_node_wires[3 * 16];
    for (int i = 0; i < 3 * 16; i++)
        mem_node_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id mem_dir_wires[3];
    for (int i = 0; i < 3; i++)
        mem_dir_wires[i] = voleith_gf8_add_witness(c);

    gf8_wire_id mem_root_computed[16];
    merkle_gf8_path_circuit_secret_dir(
        c, leaf_wires, mem_node_wires, mem_dir_wires, 3,
        VOLEITH_MERKLE_HASH_AES_DM, mem_root_computed);

    /* --- Session nonce: PUBLIC instance (server-issued, prevents replay) --- */
    gf8_wire_id nonce_wires[16];
    for (int i = 0; i < 16; i++)
        nonce_wires[i] = voleith_gf8_add_instance(c);

    /* --- Component 3: Binding AES-CMAC ---
     * binding = AES-CMAC(pq_key, session_nonce || "binding")
     * Reuses pq_key_wires (already declared as witnesses, slot reuse is free).
     * 3 AES calls × 200 inv_in = 600 witness bytes added internally. */
    gf8_wire_id binding_msg_wires[23];
    for (int i = 0; i < 16; i++)
        binding_msg_wires[i] = nonce_wires[i];
    for (int i = 0; i < 7; i++)
        binding_msg_wires[16 + i] =
            voleith_gf8_add_const(c, (uint8_t)BINDING_TAG[i]);

    gf8_wire_id binding_computed[16];
    aes_cmac_gf8_circuit(c, pq_key_wires, 16, binding_msg_wires, 23,
                         binding_computed);

    /* --- Component 4: Revocation non-membership (depth=1, DM, secret dir) ---
     * Target T = leaf_wires (the computed KDF leaf - already private).
     * Adjacent leaf: sentinel[0] with low_value < T < low_next.
     * path_dirs:  PRIVATE witness (hides which gap in the sorted tree).
     * path_nodes: PUBLIC instance (no identity information in sibling hashes).
     * 16 mul gates (1 level × 16 MUX) + 768 mul gates (ordering comparison).
     * Internally adds 3 × 200 (leaf hash) + 200 (path) = 800 inv_in bytes. */
    gf8_wire_id rev_node_wires[16];
    for (int i = 0; i < 16; i++)
        rev_node_wires[i] = voleith_gf8_add_instance(c);

    gf8_wire_id rev_dir_wires[1];
    rev_dir_wires[0] = voleith_gf8_add_witness(c);

    gf8_wire_id low_val_wires[16], low_next_wires[16], next_idx_wires[1];
    for (int i = 0; i < 16; i++)
        low_val_wires[i] = voleith_gf8_add_instance(c);
    for (int i = 0; i < 16; i++)
        low_next_wires[i] = voleith_gf8_add_instance(c);
    next_idx_wires[0] = voleith_gf8_add_instance(c);

    gf8_wire_id rev_root_computed[16];
    if (indexed_merkle_gf8_nonmember_circuit_secret_dir(
            c, leaf_wires, 16, /* T = computed leaf (from KDF above) */
            low_val_wires, low_next_wires, next_idx_wires, 1, rev_node_wires,
            rev_dir_wires, 1, VOLEITH_MERKLE_HASH_AES_DM,
            rev_root_computed) != 0) {
        fprintf(stderr,
                "indexed_merkle_gf8_nonmember_circuit_secret_dir: leaf data "
                "exceeds stack-VLA bound\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* --- Assert computed roots and binding match public instances --- */
    for (int i = 0; i < 16; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, mem_root_computed[i], ri);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id bi = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, binding_computed[i], bi);
    }
    for (int i = 0; i < 16; i++) {
        gf8_wire_id ri = voleith_gf8_add_instance(c);
        voleith_gf8_assert_equal(c, rev_root_computed[i], ri);
    }

    /* ================================================================
     * Print circuit statistics
     * ================================================================ */
    size_t ell = voleith_gf8_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_gf8_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  mul gates:       %zu\n", voleith_gf8_circuit_mul_count(c));
    printf("  Witness wires:   %zu  (pq_key[16] + uid[16] + dirs[4] + "
           "inv_in[2600])\n",
           voleith_gf8_circuit_witness_count(c));
    printf("  Instance wires:  %zu  (nodes + roots + nonce + binding + "
           "low/next)\n",
           voleith_gf8_circuit_instance_count(c));
    printf("  ell:             %zu  (vs ~95,140 bit-level; ~27x reduction)\n",
           ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (2636 bytes)
     * ================================================================ */
    static const size_t WITNESS_BYTES = 2636;
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

    /* [32..631]: KDF-CTR inv_in (600 bytes).
     * kdf_ctr_cmac_gf8_build_witness outputs key_bytes + n_aes * 200.
     * Skip the first 16 bytes (key) to get just the inv_in portion. */
    {
        size_t kdf_w_bytes = kdf_ctr_cmac_gf8_witness_bytes(16, 16, 26);
        uint8_t *kdf_w = malloc(kdf_w_bytes);
        if (!kdf_w) {
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }

        uint8_t leaf_check[16];
        kdf_ctr_cmac_gf8_build_witness(PQ_KEY, 16, fi, 26, 16, kdf_w,
                                       leaf_check);

        if (memcmp(leaf_check, member_leaf, 16) != 0) {
            fprintf(stderr, "KDF witness build: leaf mismatch\n");
            free(kdf_w);
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        memcpy(wp, kdf_w + 16, kdf_w_bytes - 16);
        wp += kdf_w_bytes - 16;
        free(kdf_w);
    }

    /* [632..634]: membership path_dirs */
    for (int i = 0; i < 3; i++)
        *wp++ = MEM_DIRS[i];

    /* [635..1234]: membership path inv_in (3 DM inode AES calls × 200 bytes).
     * Traverses the path from member_leaf up to the root, filling 200 inv_in
     * bytes per level. */
    {
        uint8_t current[16];
        memcpy(current, member_leaf, 16);
        for (int lvl = 0; lvl < 3; lvl++) {
            uint8_t dir = MEM_DIRS[lvl];
            const uint8_t *sibling = mem_siblings[lvl];
            const uint8_t *L = dir ? sibling : current;
            const uint8_t *R = dir ? current : sibling;
            uint8_t next[16];
            get_dm_inode_inv_in(L, R, wp, next);
            wp += 200;
            memcpy(current, next, 16);
        }
        /* Verify path ends at expected root */
        if (memcmp(current, mem_root, 16) != 0) {
            fprintf(stderr, "membership path witness: root mismatch\n");
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
    }

    /* [1235..1834]: binding CMAC inv_in (600 bytes).
     * Skip the first 16 bytes (key) from aes_cmac_gf8_build_witness output. */
    {
        size_t bind_w_bytes = aes_cmac_gf8_witness_bytes(16, 23);
        uint8_t *bind_w = malloc(bind_w_bytes);
        if (!bind_w) {
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }

        uint8_t bind_check[16];
        aes_cmac_gf8_build_witness(PQ_KEY, 16, bm, 23, bind_w, bind_check);

        if (memcmp(bind_check, binding, 16) != 0) {
            fprintf(stderr, "binding witness build: tag mismatch\n");
            free(bind_w);
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
        memcpy(wp, bind_w + 16, bind_w_bytes - 16);
        wp += bind_w_bytes - 16;
        free(bind_w);
    }

    /* [1835]: revocation path_dir */
    *wp++ = REV_DIRS[0];

    /* [1836..2435]: revocation adjacent leaf hash inv_in (3 DM AES calls).
     * DM hash of 33-byte leaf_data = REV_MIN || REV_MAX || next_idx.
     * 33 bytes: full_blocks=2, last=1, needs_padding=true → 3 AES calls. */
    {
        uint8_t state[16];
        memcpy(state, MERKLE_LEAF_DOMAIN, 16);

        /* Inner block 0: rev_ld0[0..15] */
        uint8_t tmp0[216];
        uint8_t cipher0[16];
        aes128_gf8_build_witness(state, rev_ld0 + 0, tmp0, cipher0);
        memcpy(wp, tmp0 + 16, 200);
        wp += 200;
        for (int i = 0; i < 16; i++)
            state[i] = cipher0[i] ^ rev_ld0[i];

        /* Inner block 1: rev_ld0[16..31] */
        uint8_t tmp1[216];
        uint8_t cipher1[16];
        aes128_gf8_build_witness(state, rev_ld0 + 16, tmp1, cipher1);
        memcpy(wp, tmp1 + 16, 200);
        wp += 200;
        for (int i = 0; i < 16; i++)
            state[i] = cipher1[i] ^ rev_ld0[16 + i];

        /* Last block (padded): [rev_ld0[32]=next_idx, 0x80, 0x00..0x00] */
        uint8_t padded[16] = {0};
        padded[0] = rev_ld0[32];
        padded[1] = 0x80;
        uint8_t tmp2[216];
        uint8_t cipher2[16];
        aes128_gf8_build_witness(state, padded, tmp2, cipher2);
        memcpy(wp, tmp2 + 16, 200);
        wp += 200;

        /* Verify computed rev_lh[0] matches what dm_leaf_hash produced */
        uint8_t check[16];
        for (int i = 0; i < 16; i++)
            check[i] = cipher2[i] ^ padded[i];
        if (memcmp(check, rev_lh[0], 16) != 0) {
            fprintf(stderr, "rev leaf hash witness: mismatch\n");
            free(witness);
            voleith_gf8_circuit_free(c);
            return 1;
        }
    }

    /* [2436..2635]: revocation path inv_in (1 DM inode AES call × 200 bytes).
     * dir[0]=0: adjacent leaf is LEFT child → L=rev_lh[0], R=rev_lh[1]. */
    {
        get_dm_inode_inv_in(rev_lh[0], rev_lh[1], wp, NULL);
        wp += 200;
    }

    if ((size_t)(wp - witness) != WITNESS_BYTES) {
        fprintf(stderr, "witness size error: %zu expected %zu\n",
                (size_t)(wp - witness), WITNESS_BYTES);
        free(witness);
        voleith_gf8_circuit_free(c);
        return 1;
    }

    /* ================================================================
     * Build instance (161 bytes):
     *   [0..47]    membership path nodes (3×16)
     *   [48..63]   session nonce (16)
     *   [64..79]   revocation path node (depth=1 sibling = rev_lh[1])
     *   [80..95]   low_value  (REV_MIN)
     *   [96..111]  low_next   (REV_MAX)
     *   [112]      next_idx   (1)
     *   [113..128] membership root (16, assert_equal wires)
     *   [129..144] binding    (16, assert_equal wires)
     *   [145..160] revocation root (16, assert_equal wires)
     * ================================================================ */
    uint8_t instance[161];
    memset(instance, 0, sizeof(instance));

    memcpy(instance + 0, mem_siblings[0], 16);  /* leaf[3]  */
    memcpy(instance + 16, mem_siblings[1], 16); /* L1[0]   */
    memcpy(instance + 32, mem_siblings[2], 16); /* L2[1]   */
    memcpy(instance + 48, SESSION_NONCE, 16);
    memcpy(instance + 64, rev_lh[1], 16); /* depth=1 sibling */
    memcpy(instance + 80, REV_MIN, 16);   /* low_value  */
    memcpy(instance + 96, REV_MAX, 16);   /* low_next   */
    instance[112] = REV_NEXT_IDX;
    memcpy(instance + 113, mem_root, 16);
    memcpy(instance + 129, binding, 16);
    memcpy(instance + 145, rev_root, 16);

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    static const char FS_SEED[] = "kvac-pq-gf8:mem-depth3-rev-depth1-config-a";

    int rc = voleith_gf8_prove(&proof, params, c, witness, instance, FS_SEED,
                               sizeof(FS_SEED) - 1);
    free(witness);
    if (rc != 0) {
        fprintf(stderr, "voleith_gf8_prove failed\n");
        voleith_gf8_circuit_free(c);
        return 1;
    }
    printf("PQ proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_gf8_verify(&proof, params, c, instance, FS_SEED,
                            sizeof(FS_SEED) - 1);
    printf("PQ proof verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_gf8_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
