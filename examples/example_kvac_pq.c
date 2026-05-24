/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * example_kvac_pq.c - PQ side of Signal hybrid KVAC group authentication
 *
 * Implements the VOLEitH proof component of the PQ Hybrid KVAC Protocol
 * (see docs/specs/PQ_Hybrid_KVAC_Protocol_Specification.md, Section 3.4
 * "Step 2: PQ Presentation").
 *
 * The prover demonstrates knowledge of (pq_key, uid) such that:
 *   (1) leaf = KDF-CTR(AES-CMAC, pq_key, uid || "membership") is in the
 *       membership Merkle tree at root R1
 *   (2) leaf is NOT in the revocation indexed Merkle tree at root R2
 *   (3) binding = AES-CMAC(pq_key, session_nonce || "binding") is correct
 *
 * The classical Schnorr NIZK side (MAC_GGM / Ristretto255) is out of scope
 * for this library.  This example is the PQ half only.
 *
 * Config A (AES-128, NIST Level 1):
 *   pq_key     128-bit AES key     - PRIVATE witness
 *   uid        128-bit identity    - PRIVATE witness
 *                                    (production: 255-bit Ristretto255 scalar)
 *   path_dirs  direction bits      - PRIVATE witness
 *                                    (reveal leaf position → deanonymization)
 *   path_nodes sibling hashes      - PUBLIC instance
 *                                    (position only, not identity)
 *   low_value, low_next, next_idx  - PUBLIC instance
 *   session_nonce, binding, roots  - PUBLIC instance
 *
 * AND gate breakdown (simplified parameters):
 *   KDF-CTR leaf    (1 iter, 30-byte CMAC msg): 3 × 7,200 = 21,600
 *   Membership path (depth=3, DM, MUX per level): 3 × 7,328 = 21,984
 *   Binding CMAC    (23-byte msg): 3 × 7,200 = 21,600
 *   Revocation      (depth=1, leaf hash 3 blocks, ordering): ~29,696
 *   Total: ~94,880   ell = 260 + 94,880 = ~95,140
 *
 * Simplified parameters:
 *   Membership tree:  depth=3, 8 leaves, DM hash, member at index 2
 *   Revocation tree:  depth=1, 2 sentinel leaves (no revocations)
 */

#include "circuit.h"
#include "proof.h"
#include "prover.h"
#include "aes_cmac_circuit.h"
#include "kdf_ctr_cmac_circuit.h"
#include "merkle_circuit.h"
#include "indexed_merkle_circuit.h"
#include "aes.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ================================================================
 * Domain constants - must match merkle_circuit.c internals
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
 * Software reference helpers
 * ================================================================ */

static void
xor16(const uint8_t a[16], const uint8_t b[16], uint8_t out[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] ^ b[i];
}

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

/*
 * dm_leaf_hash - Merkle-Damgård DM chain with IV = MERKLE_LEAF_DOMAIN.
 * ISO 7816-4 padding: complete blocks get no padding; partial or empty
 * last block gets 0x80 appended then zero-filled to 16 bytes.
 */
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
        size_t offset = i * 16;
        size_t chunk =
            (len > offset) ? (len - offset < 16 ? len - offset : 16) : 0;
        if (chunk)
            memcpy(block, data + offset, chunk);
        if (i == n_blocks - 1 && !last_full)
            block[chunk] = 0x80;
        dm_compress(state, block, state);
    }
    memcpy(out, state, 16);
}

/* AES-128-CMAC subkey generation (RFC 4493 Section 2.3) */
static void
cmac128_subkeys(const uint8_t key[16], uint8_t k1[16], uint8_t k2[16])
{
    static const uint8_t Rb = 0x87;
    uint8_t L[16] = {0};
    voleith_aes_ctx_t ctx;
    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, L, L);

    /* K1 = L << 1; if MSB(L)=1 then K1 ^= 0^120 || Rb */
    for (int i = 0; i < 15; i++)
        k1[i] = (uint8_t)((L[i] << 1) | (L[i + 1] >> 7));
    k1[15] = (uint8_t)(L[15] << 1);
    if (L[0] & 0x80)
        k1[15] ^= Rb;

    /* K2 = K1 << 1; if MSB(K1)=1 then K2 ^= 0^120 || Rb */
    for (int i = 0; i < 15; i++)
        k2[i] = (uint8_t)((k1[i] << 1) | (k1[i + 1] >> 7));
    k2[15] = (uint8_t)(k1[15] << 1);
    if (k1[0] & 0x80)
        k2[15] ^= Rb;
}

/* AES-128-CMAC (RFC 4493) */
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
        size_t offset = i * 16;
        size_t chunk =
            (len > offset) ? (len - offset < 16 ? len - offset : 16) : 0;
        if (chunk)
            memcpy(block, msg + offset, chunk);
        if (i == n_blocks - 1) {
            if (last_full)
                xor16(block, k1, block);
            else {
                block[chunk] = 0x80;
                xor16(block, k2, block);
            }
        }
        xor16(state, block, state);
        voleith_aes_encrypt(&ctx, state, state);
    }
    memcpy(tag, state, 16);
}

/*
 * KDF-CTR(AES-128-CMAC), single iteration → 16-byte output.
 * K(1) = CMAC(key, [0x00000001]_32be || fixed_input)
 */
static void
kdf_ctr_1iter(const uint8_t key[16], const uint8_t *fixed_input, size_t fi_len,
              uint8_t out[16])
{
    uint8_t msg[4 + 64];
    msg[0] = 0x00;
    msg[1] = 0x00;
    msg[2] = 0x00;
    msg[3] = 0x01;
    memcpy(msg + 4, fixed_input, fi_len);
    cmac128(key, msg, 4 + fi_len, out);
}

static void
print_hex16(const uint8_t h[16])
{
    for (int i = 0; i < 16; i++)
        printf("%02x", h[i]);
}

/* Set a single bit in a bit-packed byte array (LSB-first per byte). */
static void
set_bit(uint8_t *buf, size_t pos, uint8_t val)
{
    if (val)
        buf[pos / 8] |= (uint8_t)(1u << (pos % 8));
}

int
main(void)
{
    printf("=== Signal Hybrid KVAC - PQ membership proof (VOLEitH) ===\n");
    printf("Config A: AES-128, NIST PQ Level 1\n");
    printf("Proves knowledge of (pq_key, uid) such that:\n");
    printf("  leaf = KDF-CTR(pq_key, uid||\"membership\") is in membership "
           "tree\n");
    printf("  leaf is NOT in revocation tree\n");
    printf("  binding = AES-CMAC(pq_key, nonce||\"binding\") is correct\n\n");

    /* ================================================================
     * Sample credentials (Config A)
     * ================================================================ */
    static const uint8_t PQ_KEY[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae,
                                       0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88,
                                       0x09, 0xcf, 0x4f, 0x3c};
    /* Production uid is a 255-bit Ristretto255 scalar.  Simplified to 16 bytes here. */
    static const uint8_t UID[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};
    /* Server-issued session nonce (prevents replay). */
    static const uint8_t SESSION_NONCE[16] = {
        0xa5, 0x3d, 0x19, 0xc7, 0x82, 0xf0, 0x4b, 0x11,
        0xce, 0x77, 0x2e, 0x90, 0x01, 0x6a, 0xd4, 0x53};

    /* ================================================================
     * Compute the member's Merkle leaf.
     *   leaf = KDF-CTR(AES-CMAC, pq_key, uid || "membership")
     * ================================================================ */
    uint8_t fi[26];
    memcpy(fi, UID, 16);
    memcpy(fi + 16, "membership", 10);
    uint8_t member_leaf[16];
    kdf_ctr_1iter(PQ_KEY, fi, 26, member_leaf);

    printf("Member's KDF leaf: ");
    for (int i = 0; i < 16; i++)
        printf("%02x", member_leaf[i]);
    printf("\n\n");

    /* ================================================================
     * Build 8-leaf membership tree (depth=3, DM hash).
     *   Member is at index 2 = binary 010.
     *   Other leaves use synthetic pq_key_i={i,i,...} / uid_i={i,i,...}.
     * ================================================================ */
    uint8_t leaf[8][16];
    for (int i = 0; i < 8; i++) {
        if (i == 2) {
            memcpy(leaf[i], member_leaf, 16);
        } else {
            uint8_t k[16], u[16], f[26];
            memset(k, (uint8_t)i, 16);
            memset(u, (uint8_t)i, 16);
            memcpy(f, u, 16);
            memcpy(f + 16, "membership", 10);
            kdf_ctr_1iter(k, f, 26, leaf[i]);
        }
    }

    uint8_t L1[4][16];
    for (int i = 0; i < 4; i++)
        inode_hash_dm(leaf[2 * i], leaf[2 * i + 1], L1[i]);

    uint8_t L2[2][16];
    for (int i = 0; i < 2; i++)
        inode_hash_dm(L1[2 * i], L1[2 * i + 1], L2[i]);

    uint8_t mem_root[16];
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
     * Path for member at index 2 = 0b010 (LSB first):
     *   dirs[0]=0: leaf[2] is LEFT child  → sibling = leaf[3]
     *   dirs[1]=1: L1[1] is RIGHT child   → sibling = L1[0]
     *   dirs[2]=0: L2[0] is LEFT child    → sibling = L2[1]
     */
    static const uint8_t MEM_DIRS[3] = {0, 1, 0};
    const uint8_t *mem_nodes[3] = {leaf[3], L1[0], L2[1]};

    /* ================================================================
     * Build revocation indexed Merkle tree (depth=1, 2 sentinel leaves).
     *   Two sentinel leaves bracket all possible leaf values:
     *     leaf[0]: {value=0x00*16, next=0xFF*16, next_idx=1}  (min sentinel)
     *     leaf[1]: {value=0xFF*16, next=0x00*16, next_idx=0}  (max sentinel)
     *   Any leaf value strictly between 0 and 2^128-1 is provably not revoked.
     * ================================================================ */
    static const uint8_t REV_MIN[16] = {0};
    static const uint8_t REV_MAX[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff};
    static const uint8_t REV_NEXT_IDX = 0x01;

    /* leaf_data = value(16B) || next_value(16B) || next_index(1B) = 33 bytes */
    uint8_t rev_ld0[33], rev_ld1[33];
    memcpy(rev_ld0, REV_MIN, 16);
    memcpy(rev_ld0 + 16, REV_MAX, 16);
    rev_ld0[32] = 0x01;
    memcpy(rev_ld1, REV_MAX, 16);
    memcpy(rev_ld1 + 16, REV_MIN, 16);
    rev_ld1[32] = 0x00;

    uint8_t rev_lh[2][16];
    dm_leaf_hash(rev_ld0, 33, rev_lh[0]);
    dm_leaf_hash(rev_ld1, 33, rev_lh[1]);

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

    /*
     * Non-membership proof: adjacent leaf = sentinel[0].
     *   dirs[0]=0 (sentinel[0] is LEFT child) → sibling = rev_lh[1]
     */
    static const uint8_t REV_DIRS[1] = {0};
    const uint8_t *rev_nodes[1] = {rev_lh[1]};

    /* ================================================================
     * Compute binding.
     *   binding = AES-CMAC(pq_key, session_nonce || "binding")
     * ================================================================ */
    uint8_t bm[23];
    memcpy(bm, SESSION_NONCE, 16);
    memcpy(bm + 16, "binding", 7);
    uint8_t binding[16];
    cmac128(PQ_KEY, bm, 23, binding);

    /* ================================================================
     * Build circuit.
     *
     * Wire privacy per Signal KVAC spec (Section 3.8):
     *   PRIVATE (witness): pq_key, uid, membership path_dirs, revocation path_dirs
     *   PUBLIC (instance): membership path_nodes, membership_root,
     *                      session_nonce, binding_commitment,
     *                      revocation path_node, low_value, low_next,
     *                      next_idx, revocation_root
     *
     * Instance declaration order (determines bit-packing layout):
     *   [0..47]:   mem_node_wires  (3 × 128 bits = 48 bytes)
     *   [48..63]:  membership_root (16 bytes)
     *   [64..79]:  session_nonce   (16 bytes)
     *   [80..95]:  binding         (16 bytes)
     *   [96..111]: rev_node_wires  (1 × 128 bits = 16 bytes)
     *   [112..127]: low_value      (16 bytes)
     *   [128..143]: low_next       (16 bytes)
     *   [144]:      next_idx       (1 byte)
     *   [145..160]: revocation_root (16 bytes)
     * ================================================================ */
    voleith_circuit_t *c = voleith_circuit_new();
    if (!c) {
        fprintf(stderr, "circuit_new failed\n");
        return 1;
    }

    /* --- Private: pq_key and uid --- */
    wire_id pq_key_wires[128];
    for (int i = 0; i < 128; i++)
        pq_key_wires[i] = voleith_circuit_add_witness(c);

    wire_id uid_wires[128];
    for (int i = 0; i < 128; i++)
        uid_wires[i] = voleith_circuit_add_witness(c);

    /* --- Component 1: KDF-CTR leaf ---
     * fixed_input = uid (private) || "membership" (constant, 10 bytes).
     * kdf_ctr_cmac_circuit prepends [1]_32be internally per NIST SP 800-108.
     * CMAC message = 4 + 26 = 30 bytes → 2 blocks → 3 AES = 21,600 AND gates. */
    static const uint8_t MEMBERSHIP_STR[10] = "membership";
    wire_id membership_wires[80];
    for (int b = 0; b < 10; b++)
        for (int bit = 0; bit < 8; bit++)
            membership_wires[b * 8 + bit] =
                voleith_circuit_add_const(c, (MEMBERSHIP_STR[b] >> bit) & 1);

    wire_id fixed_input_wires[208];
    for (int i = 0; i < 128; i++)
        fixed_input_wires[i] = uid_wires[i];
    for (int i = 0; i < 80; i++)
        fixed_input_wires[128 + i] = membership_wires[i];

    wire_id leaf_wires[128];
    kdf_ctr_cmac_circuit(c, pq_key_wires, 128, fixed_input_wires, 208,
                         leaf_wires, 128);

    /* --- Component 2: Membership Merkle path (depth=3, DM hash) ---
     * path_nodes: PUBLIC instance - sibling hashes don't reveal which leaf.
     * path_dirs:  PRIVATE witness - direction bits encode leaf index position. */
    wire_id mem_node_wires[3 * 128];
    for (int i = 0; i < 3 * 128; i++)
        mem_node_wires[i] = voleith_circuit_add_instance(c);

    wire_id mem_dir_wires[3];
    for (int i = 0; i < 3; i++)
        mem_dir_wires[i] = voleith_circuit_add_witness(c);

    wire_id mem_root_computed[128];
    merkle_path_circuit(c, leaf_wires, mem_node_wires, mem_dir_wires, 3,
                        VOLEITH_MERKLE_HASH_AES_DM, mem_root_computed);

    for (int i = 0; i < 128; i++) {
        wire_id ri = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, mem_root_computed[i], ri);
    }

    /* --- Component 3: Binding CMAC ---
     * binding = AES-CMAC(pq_key, session_nonce || "binding")
     * session_nonce: PUBLIC (server-issued, verifier knows it).
     * "binding": 7-byte constant string.
     * CMAC message = 23 bytes → 2 blocks → 3 AES = 21,600 AND gates. */
    wire_id nonce_wires[128];
    for (int i = 0; i < 128; i++)
        nonce_wires[i] = voleith_circuit_add_instance(c);

    static const uint8_t BINDING_STR[7] = "binding";
    wire_id binding_str_wires[56];
    for (int b = 0; b < 7; b++)
        for (int bit = 0; bit < 8; bit++)
            binding_str_wires[b * 8 + bit] =
                voleith_circuit_add_const(c, (BINDING_STR[b] >> bit) & 1);

    wire_id binding_msg_wires[184];
    for (int i = 0; i < 128; i++)
        binding_msg_wires[i] = nonce_wires[i];
    for (int i = 0; i < 56; i++)
        binding_msg_wires[128 + i] = binding_str_wires[i];

    wire_id binding_computed[128];
    aes_cmac_circuit(c, pq_key_wires, 128, binding_msg_wires, 184,
                     binding_computed);

    for (int i = 0; i < 128; i++) {
        wire_id bi = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, binding_computed[i], bi);
    }

    /* --- Component 4: Revocation non-membership (depth=1, DM hash) ---
     * Target T = leaf_wires (the computed KDF leaf, implicitly private).
     * path_nodes:  PUBLIC instance.
     * path_dirs:   PRIVATE witness (hides which gap in the sorted tree).
     * low_value, low_next, next_idx: PUBLIC instance.
     * Ordering check internally asserts: low_value < T < low_next. */
    wire_id rev_node_wires[128];
    for (int i = 0; i < 128; i++)
        rev_node_wires[i] = voleith_circuit_add_instance(c);

    wire_id rev_dir_wires[1];
    rev_dir_wires[0] = voleith_circuit_add_witness(c);

    wire_id low_val_wires[128], low_next_wires[128], next_idx_wires[8];
    for (int i = 0; i < 128; i++)
        low_val_wires[i] = voleith_circuit_add_instance(c);
    for (int i = 0; i < 128; i++)
        low_next_wires[i] = voleith_circuit_add_instance(c);
    for (int i = 0; i < 8; i++)
        next_idx_wires[i] = voleith_circuit_add_instance(c);

    wire_id rev_root_computed[128];
    indexed_merkle_nonmember_circuit(
        c, leaf_wires, 128, /* T = computed leaf (private, from KDF) */
        low_val_wires, low_next_wires, next_idx_wires, 8, rev_node_wires,
        rev_dir_wires, 1, VOLEITH_MERKLE_HASH_AES_DM, rev_root_computed);

    for (int i = 0; i < 128; i++) {
        wire_id ri = voleith_circuit_add_instance(c);
        voleith_circuit_assert_equal(c, rev_root_computed[i], ri);
    }

    /* ================================================================
     * Print circuit statistics
     * ================================================================ */
    size_t ell = voleith_qs_ell(c);
    const voleith_params_t *params = &voleith_params_em_128f;
    size_t proof_bytes = voleith_proof_byte_size(params, ell);

    printf("Circuit statistics:\n");
    printf("  AND gates:       %zu\n", voleith_circuit_and_gate_count(c));
    printf("  Witness wires:   %zu  (pq_key[128] + uid[128] + dirs[4])\n",
           voleith_circuit_witness_count(c));
    printf("  Instance wires:  %zu  (nodes + roots + nonce + binding + "
           "low/next)\n",
           voleith_circuit_instance_count(c));
    printf("  ell:             %zu\n", ell);
    printf("  Expected proof:  %zu bytes\n\n", proof_bytes);

    /* ================================================================
     * Build witness (bit-packed, ceil(260/8) = 33 bytes).
     *
     * Slot order (determined by add_witness call order above):
     *   bits   0..127: pq_key
     *   bits 128..255: uid
     *   bit       256: mem_dirs[0] = 0
     *   bit       257: mem_dirs[1] = 1
     *   bit       258: mem_dirs[2] = 0
     *   bit       259: rev_dirs[0] = 0
     * ================================================================ */
    uint8_t witness[33];
    memset(witness, 0, sizeof(witness));

    memcpy(witness, PQ_KEY, 16);
    memcpy(witness + 16, UID, 16);

    size_t dir_base = 256; /* bits 0..255 used by pq_key + uid */
    for (int i = 0; i < 3; i++)
        set_bit(witness, dir_base + (size_t)i, MEM_DIRS[i]);
    set_bit(witness, dir_base + 3, REV_DIRS[0]);

    /* ================================================================
     * Build instance (bit-packed, 161 bytes).
     * ================================================================ */
    uint8_t instance[161];
    memset(instance, 0, sizeof(instance));

    /* [0..47]   membership path nodes: level-0 sibling, level-1, level-2 */
    memcpy(instance, mem_nodes[0], 16);      /* leaf[3]  */
    memcpy(instance + 16, mem_nodes[1], 16); /* L1[0]   */
    memcpy(instance + 32, mem_nodes[2], 16); /* L2[1]   */

    /* [48..63]  membership root */
    memcpy(instance + 48, mem_root, 16);

    /* [64..79]  session nonce */
    memcpy(instance + 64, SESSION_NONCE, 16);

    /* [80..95]  binding commitment */
    memcpy(instance + 80, binding, 16);

    /* [96..111] revocation path node (depth=1: one sibling = rev_lh[1]) */
    memcpy(instance + 96, rev_nodes[0], 16);

    /* [112..127] low_value (min sentinel) */
    memcpy(instance + 112, REV_MIN, 16);

    /* [128..143] low_next (max sentinel) */
    memcpy(instance + 128, REV_MAX, 16);

    /* [144]      next_idx = 1 */
    instance[144] = REV_NEXT_IDX;

    /* [145..160] revocation root */
    memcpy(instance + 145, rev_root, 16);

    /* ================================================================
     * Prove
     * ================================================================ */
    voleith_proof_t proof = {0};
    int rc =
        voleith_prove(&proof, params, c, witness, instance,
                      "kvac-pq:mem-depth3-rev-depth1-config-a",
                      sizeof("kvac-pq:mem-depth3-rev-depth1-config-a") - 1);
    if (rc != 0) {
        fprintf(stderr, "voleith_prove failed\n");
        voleith_circuit_free(c);
        return 1;
    }
    printf("PQ proof generated: %zu bytes\n", proof.len);

    /* ================================================================
     * Verify
     * ================================================================ */
    rc = voleith_verify(&proof, params, c, instance,
                        "kvac-pq:mem-depth3-rev-depth1-config-a",
                        sizeof("kvac-pq:mem-depth3-rev-depth1-config-a") - 1);
    printf("PQ proof verification: %s\n", (rc == 0) ? "PASS" : "FAIL");

    voleith_proof_free(&proof);
    voleith_circuit_free(c);
    return (rc == 0) ? 0 : 1;
}
