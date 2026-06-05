/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * node_hash_hirose_gf8.c - one Hirose iteration as a GF(2^8) circuit.
 *
 * Optimization: every linear operation is a free wire-graph
 * construction (add_xor / add_xor_const).  The only VOLE-slot
 * consumers are AES-256 S-boxes, and the key-schedule sharing across
 * the two same-key encryptions is structural (one expand_key, two
 * encrypt_rk).  See the header for the per-iteration gate accounting
 * derivation.
 *
 * The leaf/inode wrappers, voleith_node_hash_vt instances, and
 * HIROSE_IV_LEAF / HIROSE_C_LEAF_* / HIROSE_C_INODE constants are
 * deferred to step 9.4 (see docs/HIROSE_MERKLE_DESIGN.md).
 */

#include "node_hash_hirose_gf8.h"
#include "node_hash_vt.h"
#include "aes_gf8_circuit.h"
#include "../core/hirose.h"
#include "../core/util.h"
#include <string.h>

size_t
hirose_gf8_iteration_witness_bytes(void)
{
    return HIROSE_GF8_ITERATION_WITNESS_BYTES;
}

void
hirose_gf8_iteration_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id G[16],
                             const gf8_wire_id H[16], const gf8_wire_id M[16],
                             const uint8_t c_const[16], gf8_wire_id G_out[16],
                             gf8_wire_id H_out[16])
{
    /* Snapshot the input G wire IDs.  G is read three times during
     * emission (once by encrypt_rk to build the AES gates, once by
     * the G_out feed-forward XOR, and once by the Gxc XOR-with-c).
     * If G_out aliases G (the natural shape for chaining iterations
     * in-place), the second read overwrites G[i] with the new G_out
     * wire ID, and the third read picks up the wrong wire.  The
     * snapshot decouples reads from writes so any aliasing of
     * G_out / H_out with G / H / M is safe.  H and M are each read
     * exactly once (into key_wires below) before any output writes,
     * so they need no snapshot. */
    gf8_wire_id G_in[16];
    for (int i = 0; i < 16; i++)
        G_in[i] = G[i];

    /* K = H || M as a 32-wire array.  Pure wire-graph reshape: no
     * gates emitted. */
    gf8_wire_id key_wires[32];
    for (int i = 0; i < 16; i++)
        key_wires[i] = H[i];
    for (int i = 0; i < 16; i++)
        key_wires[16 + i] = M[i];

    /* Expand the AES-256 key schedule ONCE.  This is the shared
     * structure that gives Hirose its 1000-S-box-per-inode cost
     * vs. 1104 for two independent aes256_gf8_circuit calls. */
    gf8_wire_id rk[15][16];
    aes256_gf8_expand_key(c, key_wires, rk);

    /* G_out = AES_K(G) XOR G. */
    gf8_wire_id ct_G[16];
    aes256_gf8_encrypt_rk(c, rk, G_in, ct_G);
    for (int i = 0; i < 16; i++)
        G_out[i] = voleith_gf8_add_xor(c, ct_G[i], G_in[i]);

    /* Gxc = G XOR c_const (free xor-with-constant). */
    gf8_wire_id Gxc[16];
    for (int i = 0; i < 16; i++)
        Gxc[i] = voleith_gf8_add_xor_const(c, G_in[i], c_const[i]);

    /* H_out = AES_K(Gxc) XOR Gxc.  Reuses rk - second encrypt_rk emit
     * under the same schedule. */
    gf8_wire_id ct_Gxc[16];
    aes256_gf8_encrypt_rk(c, rk, Gxc, ct_Gxc);
    for (int i = 0; i < 16; i++)
        H_out[i] = voleith_gf8_add_xor(c, ct_Gxc[i], Gxc[i]);
}

void
hirose_gf8_iteration_build_witness(
    const uint8_t G[16], const uint8_t H[16], const uint8_t M[16],
    const uint8_t c_const[16],
    uint8_t inv_out[HIROSE_GF8_ITERATION_WITNESS_BYTES], uint8_t G_out[16],
    uint8_t H_out[16])
{
    /* Mirror the circuit's emission order exactly:
     *   [ 0 ..  51]  expand_key
     *   [52 .. 275]  encrypt_rk for AES_K(G)
     *   [276..499]   encrypt_rk for AES_K(G ^ c) */
    uint8_t key[32];
    memcpy(key, H, 16);
    memcpy(key + 16, M, 16);

    uint8_t rk[15][16];
    uint8_t ct_G[16];
    uint8_t Gxc[16];
    uint8_t ct_Gxc[16];

    aes256_gf8_expand_key_witness(key, inv_out, rk);

    /* AES_K(G) inv_in chunk + ciphertext. */
    aes256_gf8_encrypt_rk_witness(rk, G, inv_out + AES256_GF8_KS_INVIN_BYTES,
                                  ct_G);

    /* Gxc = G ^ c (out-of-circuit). */
    for (int i = 0; i < 16; i++)
        Gxc[i] = G[i] ^ c_const[i];

    /* AES_K(Gxc) inv_in chunk + ciphertext. */
    aes256_gf8_encrypt_rk_witness(rk, Gxc,
                                  inv_out + AES256_GF8_KS_INVIN_BYTES +
                                      AES256_GF8_ENC_INVIN_BYTES,
                                  ct_Gxc);

    /* Feed-forward XORs. */
    if (G_out != NULL) {
        for (int i = 0; i < 16; i++)
            G_out[i] = ct_G[i] ^ G[i];
    }
    if (H_out != NULL) {
        for (int i = 0; i < 16; i++)
            H_out[i] = ct_Gxc[i] ^ Gxc[i];
    }

    /* CIR-11: clear everything that touched key material or message-
     * derived intermediates.  The aes256_gf8_*_witness routines
     * already clear their own scratch; rk and key are ours. */
    voleith_secure_zero(key, sizeof(key));
    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(ct_G, sizeof(ct_G));
    voleith_secure_zero(Gxc, sizeof(Gxc));
    voleith_secure_zero(ct_Gxc, sizeof(ct_Gxc));
}

/* ================================================================
 * Step 9.4: domain-separation constants
 *
 * IV_LEAF is the 2n-bit chaining IV for both leaf vts (32 bytes
 * because it occupies the full (G, H) chaining state).  The c
 * constants are n-bit half-block tweaks (16 bytes), nonzero and
 * pairwise distinct, that gate the inner f's two encryptions
 * against each other AND realize leaf-vs-inode and fixed-vs-variable
 * domain separation (see docs/HIROSE_MERKLE_DESIGN.md §2.4 and
 * docs/HASH_AGNOSTIC_MERKLE_DESIGN.md §5.2).
 *
 * Concrete values (sized to land exactly at 16 / 32 bytes - no
 * padding decisions to second-guess later):
 *
 *   HIROSE_IV_LEAF        : "VOLEitH-Hirose-IV" (17 B) + zero-pad to 32
 *   HIROSE_C_LEAF_FIXED32 : "VOLEitH-Hirose-L"  (exactly 16 B)
 *   HIROSE_C_LEAF_VAR     : "VOLEitH-Hirose-V"  (exactly 16 B)
 *   HIROSE_C_INODE        : "VOLEitH-Hirose-N"  (exactly 16 B)
 *
 * Distinctness:
 *   c_leaf_fixed32 != c_leaf_var  (cross-vt leaf-collision prevention)
 *   c_leaf_* != c_inode          (leaf vs inode type-confusion safety)
 *   all are nonzero              (Hirose requires c != 0)
 * ================================================================ */

static const uint8_t HIROSE_IV_LEAF[32] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-', 'H', 'i', 'r',
    'o', 's', 'e', '-', 'I', 'V', 0,   0,   0,   0,   0,
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
};
static const uint8_t HIROSE_C_LEAF_FIXED32[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'L',
};
static const uint8_t HIROSE_C_LEAF_VAR[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'V',
};
static const uint8_t HIROSE_C_INODE[16] = {
    'V', 'O', 'L', 'E', 'i', 'T', 'H', '-',
    'H', 'i', 'r', 'o', 's', 'e', '-', 'N',
};

/* ================================================================
 * inv_in byte-size accessors
 * ================================================================ */

size_t
merkle_hirose_gf8_fixed32_leaf_invin_bytes(size_t leaf_data_bytes)
{
    /* fixed-32 vt's contract: caller must pass leaf_data_bytes == 32.
     * Returning the constant regardless makes the function a pure
     * size accessor without a branch on the (uninspected) input. */
    (void)leaf_data_bytes;
    return 2 * HIROSE_GF8_ITERATION_WITNESS_BYTES; /* 1000 */
}

size_t
merkle_hirose_gf8_variable_leaf_invin_bytes(size_t leaf_data_bytes)
{
    /* 10* always-pad: n_iter = ceil((len + 1) / 16) = (len + 16) / 16.
     * Holds for len = 0 too (n_iter = 1, padded block = 0x80 || 0x00*15). */
    size_t n_iter = (leaf_data_bytes + 16) / 16;
    return n_iter * HIROSE_GF8_ITERATION_WITNESS_BYTES;
}

size_t
merkle_hirose_gf8_inode_invin_bytes(void)
{
    return 2 * HIROSE_GF8_ITERATION_WITNESS_BYTES; /* 1000 */
}

/* ================================================================
 * Software helpers - independent oracles using core/hirose.c.
 * Used by the witness builders' final outputs and by tests.
 * ================================================================ */

int
merkle_hirose_fixed32_leaf_hash(const uint8_t *leaf_data,
                                size_t leaf_data_bytes, uint8_t *out)
{
    /* Contract: leaf_data_bytes must be 32.  Silently consume only
     * the first 32 bytes if the caller violates the contract; this
     * keeps the vt's signature pure and matches the no-padding
     * semantics of the fixed-32 vt. */
    (void)leaf_data_bytes;

    uint8_t G[16], H[16];
    memcpy(G, HIROSE_IV_LEAF + 0, 16);
    memcpy(H, HIROSE_IV_LEAF + 16, 16);
    voleith_hirose_iteration(G, H, leaf_data + 0, HIROSE_C_LEAF_FIXED32, G, H);
    voleith_hirose_iteration(G, H, leaf_data + 16, HIROSE_C_LEAF_FIXED32, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

int
merkle_hirose_variable_leaf_hash(const uint8_t *leaf_data,
                                 size_t leaf_data_bytes, uint8_t *out)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;

    uint8_t G[16], H[16];
    memcpy(G, HIROSE_IV_LEAF + 0, 16);
    memcpy(H, HIROSE_IV_LEAF + 16, 16);

    for (size_t k = 0; k < n_iter; k++) {
        uint8_t M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = 0x80;
            else
                M[i] = 0x00;
        }
        voleith_hirose_iteration(G, H, M, HIROSE_C_LEAF_VAR, G, H);
        voleith_secure_zero(M, sizeof(M));
    }

    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

int
merkle_hirose_inode_hash(const uint8_t *left, const uint8_t *right,
                         uint8_t *out)
{
    uint8_t G[16], H[16];
    memcpy(G, left + 0, 16);  /* L_G as initial chaining G */
    memcpy(H, left + 16, 16); /* L_H as initial chaining H */
    voleith_hirose_iteration(G, H, right + 0, HIROSE_C_INODE, G, H);
    voleith_hirose_iteration(G, H, right + 16, HIROSE_C_INODE, G, H);
    memcpy(out + 0, G, 16);
    memcpy(out + 16, H, 16);
    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

/* ================================================================
 * Witness builders - mirror the in-circuit emission order so the
 * inv_in chunks land where each iteration's circuit reads from.
 * ================================================================ */

int
merkle_hirose_gf8_fixed32_leaf_build_witness(const uint8_t *leaf_data,
                                             size_t leaf_data_bytes,
                                             uint8_t *inv_out)
{
    (void)leaf_data_bytes; /* caller must pass 32 */

    uint8_t G[16], H[16];
    memcpy(G, HIROSE_IV_LEAF + 0, 16);
    memcpy(H, HIROSE_IV_LEAF + 16, 16);

    hirose_gf8_iteration_build_witness(G, H, leaf_data + 0,
                                       HIROSE_C_LEAF_FIXED32, inv_out, G, H);
    hirose_gf8_iteration_build_witness(
        G, H, leaf_data + 16, HIROSE_C_LEAF_FIXED32,
        inv_out + HIROSE_GF8_ITERATION_WITNESS_BYTES, G, H);

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

int
merkle_hirose_gf8_variable_leaf_build_witness(const uint8_t *leaf_data,
                                              size_t leaf_data_bytes,
                                              uint8_t *inv_out)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;

    uint8_t G[16], H[16];
    memcpy(G, HIROSE_IV_LEAF + 0, 16);
    memcpy(H, HIROSE_IV_LEAF + 16, 16);

    for (size_t k = 0; k < n_iter; k++) {
        uint8_t M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = 0x80;
            else
                M[i] = 0x00;
        }
        hirose_gf8_iteration_build_witness(
            G, H, M, HIROSE_C_LEAF_VAR,
            inv_out + k * HIROSE_GF8_ITERATION_WITNESS_BYTES, G, H);
        voleith_secure_zero(M, sizeof(M));
    }

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

int
merkle_hirose_gf8_inode_build_witness(const uint8_t *left, const uint8_t *right,
                                      uint8_t *inv_out)
{
    uint8_t G[16], H[16];
    memcpy(G, left + 0, 16);
    memcpy(H, left + 16, 16);

    hirose_gf8_iteration_build_witness(G, H, right + 0, HIROSE_C_INODE, inv_out,
                                       G, H);
    hirose_gf8_iteration_build_witness(
        G, H, right + 16, HIROSE_C_INODE,
        inv_out + HIROSE_GF8_ITERATION_WITNESS_BYTES, G, H);

    voleith_secure_zero(G, sizeof(G));
    voleith_secure_zero(H, sizeof(H));
    return 0;
}

/* ================================================================
 * In-circuit emission
 *
 * IV_LEAF bytes enter the circuit as add_const wires (free).  Padding
 * bytes for the variable-leaf vt likewise become add_const wires.
 * Caller passes leaf_data / left / right as already-declared wires
 * (witness or instance - the circuit is layout-agnostic about that).
 * ================================================================ */

void
merkle_hirose_gf8_fixed32_leaf_circuit(voleith_gf8_circuit_t *c,
                                       const gf8_wire_id *leaf_data,
                                       size_t leaf_data_bytes,
                                       gf8_wire_id *out_node)
{
    (void)leaf_data_bytes; /* caller must pass 32 */

    /* IV_LEAF as 32 constant wires (free). */
    gf8_wire_id G[16], H[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_const(c, HIROSE_IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_const(c, HIROSE_IV_LEAF[16 + i]);

    /* 2 iterations: M0 = data[0..15], M1 = data[16..31]. */
    hirose_gf8_iteration_circuit(c, G, H, &leaf_data[0], HIROSE_C_LEAF_FIXED32,
                                 G, H);
    hirose_gf8_iteration_circuit(c, G, H, &leaf_data[16], HIROSE_C_LEAF_FIXED32,
                                 G, H);

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

void
merkle_hirose_gf8_variable_leaf_circuit(voleith_gf8_circuit_t *c,
                                        const gf8_wire_id *leaf_data,
                                        size_t leaf_data_bytes,
                                        gf8_wire_id *out_node)
{
    size_t n_iter = (leaf_data_bytes + 16) / 16;

    /* IV_LEAF as 32 constant wires (free). */
    gf8_wire_id G[16], H[16];
    for (int i = 0; i < 16; i++)
        G[i] = voleith_gf8_add_const(c, HIROSE_IV_LEAF[i]);
    for (int i = 0; i < 16; i++)
        H[i] = voleith_gf8_add_const(c, HIROSE_IV_LEAF[16 + i]);

    /* Reuse two padding-byte constants across all blocks (cheaper on
     * circuit-build memory; identical VOLE-slot cost since constants
     * are free either way). */
    gf8_wire_id c80 = voleith_gf8_add_const(c, 0x80);
    gf8_wire_id c00 = voleith_gf8_add_const(c, 0x00);

    for (size_t k = 0; k < n_iter; k++) {
        gf8_wire_id M[16];
        for (int i = 0; i < 16; i++) {
            size_t pos = k * 16 + (size_t)i;
            if (pos < leaf_data_bytes)
                M[i] = leaf_data[pos];
            else if (pos == leaf_data_bytes)
                M[i] = c80;
            else
                M[i] = c00;
        }
        hirose_gf8_iteration_circuit(c, G, H, M, HIROSE_C_LEAF_VAR, G, H);
    }

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

void
merkle_hirose_gf8_inode_circuit(voleith_gf8_circuit_t *c,
                                const gf8_wire_id *left,
                                const gf8_wire_id *right, gf8_wire_id *out_node)
{
    /* L = (left[0..15], left[16..31]) feeds the iter-1 chaining slots
     * directly; no constant wires needed (the IV slot is occupied by
     * a witness/instance value, the inode's defining trick). */
    gf8_wire_id G[16], H[16];
    hirose_gf8_iteration_circuit(c, &left[0], &left[16], &right[0],
                                 HIROSE_C_INODE, G, H);
    hirose_gf8_iteration_circuit(c, G, H, &right[16], HIROSE_C_INODE, G, H);

    for (int i = 0; i < 16; i++) {
        out_node[i] = G[i];
        out_node[16 + i] = H[i];
    }
}

/* ================================================================
 * vt instances
 *
 * Both vts have:
 *   node_bytes = 32   (Hirose state is 256 bits)
 *   cr_bits    = 128  (Hirose FSE 2006 ideal-cipher bound, optimal
 *                      for a 2n-bit output)
 *   inode_*   = the shared inode hash (no padding ambiguity at the
 *               inode level - both children are always 32 B)
 *
 * They differ only in the leaf_* fields, gated by their distinct
 * c_leaf constants (HIROSE_C_LEAF_FIXED32 vs HIROSE_C_LEAF_VAR).
 * ================================================================ */

/* Compile-time bound check.  See MERKLE_VT_MAX_NODE_BYTES in node_hash_vt.h. */
_Static_assert(32 <= MERKLE_VT_MAX_NODE_BYTES,
               "hirose node_bytes exceeds MERKLE_VT_MAX_NODE_BYTES");

const voleith_node_hash_vt voleith_node_hash_hirose_fixed32 = {
    .name = "hirose-aes-256-fixed32",
    .node_bytes = 32,
    .cr_bits = 128,
    .fixed_leaf_bytes = 32,
    .leaf_invin_bytes = merkle_hirose_gf8_fixed32_leaf_invin_bytes,
    .inode_invin_bytes = merkle_hirose_gf8_inode_invin_bytes,
    .leaf_circuit = merkle_hirose_gf8_fixed32_leaf_circuit,
    .inode_circuit = merkle_hirose_gf8_inode_circuit,
    .leaf_build_witness = merkle_hirose_gf8_fixed32_leaf_build_witness,
    .inode_build_witness = merkle_hirose_gf8_inode_build_witness,
    .leaf_hash = merkle_hirose_fixed32_leaf_hash,
    .inode_hash = merkle_hirose_inode_hash,
};

const voleith_node_hash_vt voleith_node_hash_hirose = {
    .name = "hirose-aes-256",
    .node_bytes = 32,
    .cr_bits = 128,
    .leaf_invin_bytes = merkle_hirose_gf8_variable_leaf_invin_bytes,
    .inode_invin_bytes = merkle_hirose_gf8_inode_invin_bytes,
    .leaf_circuit = merkle_hirose_gf8_variable_leaf_circuit,
    .inode_circuit = merkle_hirose_gf8_inode_circuit,
    .leaf_build_witness = merkle_hirose_gf8_variable_leaf_build_witness,
    .inode_build_witness = merkle_hirose_gf8_inode_build_witness,
    .leaf_hash = merkle_hirose_variable_leaf_hash,
    .inode_hash = merkle_hirose_inode_hash,
};
