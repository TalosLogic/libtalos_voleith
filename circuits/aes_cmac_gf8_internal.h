/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_gf8_internal.h - shared AES-CMAC orchestration (RFC 4493).
 *
 * The CMAC structure (subkey generation, CBC-MAC chaining, last-block
 * padding, witness layout) is identical whether the inner block cipher is the
 * frozen 8-bit-inverse AES circuit or the FAEST paired-round norm AES circuit:
 * CMAC is a mode, and the two only differ in how each AES call commits its
 * S-box witnesses.  Both translation units (aes_cmac_gf8_circuit.c and
 * aes_cmac_norm_gf8_circuit.c) drive the same skeletons here with a `norm`
 * flag, so there is a single source of truth and the frozen and norm MACs
 * cannot drift on the mode logic they must agree on.
 *
 * The flag selects the AES block call at the two sites where it matters; every
 * other operation (shift_xor_rb, block XOR, padding) is GF(2)-linear and byte
 * identical.  For norm = 0 the skeletons emit exactly the gates the frozen
 * circuit emitted before this header existed, so the frozen circuit's output,
 * fingerprints and RFC 4493 KATs are unchanged.
 */

#ifndef VOLEITH_AES_CMAC_GF8_INTERNAL_H
#define VOLEITH_AES_CMAC_GF8_INTERNAL_H

#include "../proof/gf8_circuit.h"
#include "aes_gf8_circuit.h"      /* frozen AES block cipher + witness */
#include "aes_norm_gf8_circuit.h" /* norm AES block cipher + witness */
#include "../core/util.h"         /* voleith_secure_zero */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* inv_in bytes committed per AES call (the per-call witness minus the key
 * prefix): frozen 200/276, norm 160/220 (75% of frozen). */
static inline size_t
cmac_gf8_inv_per_call(size_t key_bytes, int norm)
{
    if (norm)
        return (key_bytes == 16) ? (AES128_NORM_GF8_WITNESS_BYTES - 16u)
                                 : (AES256_NORM_GF8_WITNESS_BYTES - 32u);
    return (key_bytes == 16) ? 200u : 276u;
}

/* ================================================================
 * Wire-level helpers (free GF(2)-linear; no mul gates).
 * ================================================================ */

/*
 * cmac_shift_xor_rb_gf8 - (in << 1) XOR (MSB(in) ? Rb : 0) at byte level.
 * See the former in-file definition for the M_lo / M_hi / M_msb derivation;
 * Rb = 0x87 (RFC 4493).
 */
static inline void
cmac_shift_xor_rb_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id in[16],
                      gf8_wire_id out[16])
{
    static const uint8_t M_lo[8] = {0x00, 0x01, 0x02, 0x04,
                                    0x08, 0x10, 0x20, 0x40};
    static const uint8_t M_hi[8] = {0x80, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00};
    static const uint8_t M_msb[8] = {0x80, 0x80, 0x80, 0x00,
                                     0x00, 0x00, 0x00, 0x80};

    for (int k = 0; k < 15; k++) {
        gf8_wire_id lo = voleith_gf8_add_linear_map(c, in[k], M_lo);
        gf8_wire_id hi = voleith_gf8_add_linear_map(c, in[k + 1], M_hi);
        out[k] = voleith_gf8_add_xor(c, lo, hi);
    }
    gf8_wire_id lo15 = voleith_gf8_add_linear_map(c, in[15], M_lo);
    gf8_wire_id msb15 = voleith_gf8_add_linear_map(c, in[0], M_msb);
    out[15] = voleith_gf8_add_xor(c, lo15, msb15);
}

static inline void
cmac_xor_blocks_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id a[16],
                    const gf8_wire_id b[16], gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_xor(c, a[k], b[k]);
}

static inline void
cmac_aes_block_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                   size_t key_bytes, const gf8_wire_id in[16],
                   gf8_wire_id out[16], int norm)
{
    if (norm) {
        if (key_bytes == 16)
            aes128_norm_gf8_circuit(c, key, in, out);
        else
            aes256_norm_gf8_circuit(c, key, in, out);
    } else {
        if (key_bytes == 16)
            aes128_gf8_circuit(c, key, in, out);
        else
            aes256_gf8_circuit(c, key, in, out);
    }
}

/* ================================================================
 * Circuit skeleton.
 * ================================================================ */

static inline void
cmac_circuit_skeleton(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                      size_t key_bytes, const gf8_wire_id *message,
                      size_t message_bytes, gf8_wire_id tag[16], int norm)
{
    /* Subkey generation: L = AES(key, 0^16), K1 = shift_xor_rb(L),
     * K2 = shift_xor_rb(K1). */
    gf8_wire_id zero[16];
    for (int k = 0; k < 16; k++)
        zero[k] = voleith_gf8_add_const(c, 0x00);

    gf8_wire_id L[16];
    cmac_aes_block_gf8(c, key, key_bytes, zero, L, norm);

    gf8_wire_id K1[16], K2[16];
    cmac_shift_xor_rb_gf8(c, L, K1);
    cmac_shift_xor_rb_gf8(c, K1, K2);

    size_t n_full_blocks = message_bytes / 16;
    size_t last_bytes = message_bytes % 16;
    int needs_padding = (message_bytes == 0) || (last_bytes != 0);

    /* CBC-MAC: X0 = 0^16.  Process complete blocks except the last. */
    gf8_wire_id X[16];
    for (int k = 0; k < 16; k++)
        X[k] = voleith_gf8_add_const(c, 0x00);

    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        gf8_wire_id inp[16];
        cmac_xor_blocks_gf8(c, X, message + blk * 16, inp);
        cmac_aes_block_gf8(c, key, key_bytes, inp, X, norm);
    }

    /* Last block: M_last XOR chaining value. */
    gf8_wire_id last_inp[16];
    if (!needs_padding) {
        gf8_wire_id m_xor_k[16];
        cmac_xor_blocks_gf8(c, message + (n_full_blocks - 1) * 16, K1, m_xor_k);
        cmac_xor_blocks_gf8(c, X, m_xor_k, last_inp);
    } else {
        gf8_wire_id padded[16];
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = message[n_full_blocks * 16 + b];
        padded[last_bytes] = voleith_gf8_add_const(c, 0x80);
        for (size_t b = last_bytes + 1; b < 16; b++)
            padded[b] = voleith_gf8_add_const(c, 0x00);

        gf8_wire_id m_xor_k[16];
        cmac_xor_blocks_gf8(c, padded, K2, m_xor_k);
        cmac_xor_blocks_gf8(c, X, m_xor_k, last_inp);
    }

    /* Final AES call: T = AES(key, last_inp). */
    cmac_aes_block_gf8(c, key, key_bytes, last_inp, tag, norm);
}

/* ================================================================
 * Witness skeleton.
 * ================================================================ */

static inline void
cmac_shift_xor_rb_bytes(const uint8_t in[16], uint8_t out[16])
{
    uint8_t msb = (in[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)((in[15] << 1) ^ (msb ? 0x87u : 0u));
}

/* Run one AES call for the witness: fill ct_out with ciphertext and append the
 * per-call inv_in bytes at *inv_ptr, advancing it. */
static inline void
cmac_do_aes_witness(const uint8_t *key, size_t key_bytes, const uint8_t pt[16],
                    uint8_t ct_out[16], uint8_t **inv_ptr, int norm)
{
    uint8_t w_temp[308];

    if (norm) {
        if (key_bytes == 16)
            aes128_norm_gf8_build_witness(key, pt, w_temp, ct_out);
        else
            aes256_norm_gf8_build_witness(key, pt, w_temp, ct_out);
    } else {
        if (key_bytes == 16)
            aes128_gf8_build_witness(key, pt, w_temp, ct_out);
        else
            aes256_gf8_build_witness(key, pt, w_temp, ct_out);
    }

    size_t inv_per_call = cmac_gf8_inv_per_call(key_bytes, norm);
    memcpy(*inv_ptr, w_temp + key_bytes, inv_per_call);
    *inv_ptr += inv_per_call;
    /* w_temp held the full per-call AES witness (key prefix + S-box inv_in),
     * both secret. */
    voleith_secure_zero(w_temp, sizeof(w_temp));
}

static inline void
cmac_witness_skeleton(const uint8_t *key, size_t key_bytes,
                      const uint8_t *message, size_t message_bytes,
                      uint8_t *witness_out, uint8_t tag_out[16], int norm)
{
    /* Witness layout: [key_bytes key] [inv_per_call per AES call, in order]. */
    memcpy(witness_out, key, key_bytes);
    uint8_t *inv_ptr = witness_out + key_bytes;

    /* Subkey generation: L = AES(key, 0^16). */
    uint8_t zero[16] = {0};
    uint8_t L[16];
    cmac_do_aes_witness(key, key_bytes, zero, L, &inv_ptr, norm);

    uint8_t K1[16], K2[16];
    cmac_shift_xor_rb_bytes(L, K1);
    cmac_shift_xor_rb_bytes(K1, K2);

    size_t n_full_blocks = message_bytes / 16;
    size_t last_bytes = message_bytes % 16;
    int needs_padding = (message_bytes == 0) || (last_bytes != 0);

    /* CBC-MAC: X0 = 0^16. */
    uint8_t X[16] = {0};
    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        uint8_t inp[16];
        for (int i = 0; i < 16; i++)
            inp[i] = X[i] ^ message[blk * 16 + i];
        cmac_do_aes_witness(key, key_bytes, inp, X, &inv_ptr, norm);
    }

    /* Last block. */
    uint8_t last_inp[16];
    if (!needs_padding) {
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ message[(n_full_blocks - 1) * 16 + i] ^ K1[i];
    } else {
        uint8_t padded[16] = {0};
        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = message[n_full_blocks * 16 + b];
        padded[last_bytes] = 0x80;
        for (int i = 0; i < 16; i++)
            last_inp[i] = X[i] ^ padded[i] ^ K2[i];
    }

    uint8_t ct[16];
    cmac_do_aes_witness(key, key_bytes, last_inp, ct, &inv_ptr, norm);

    if (tag_out)
        memcpy(tag_out, ct, 16);

    /* Zero all per-call CMAC working buffers (subkeys, CBC state, final
     * block plaintext/ciphertext).  w_temp is zeroed in cmac_do_aes_witness. */
    voleith_secure_zero(L, sizeof(L));
    voleith_secure_zero(K1, sizeof(K1));
    voleith_secure_zero(K2, sizeof(K2));
    voleith_secure_zero(X, sizeof(X));
    voleith_secure_zero(last_inp, sizeof(last_inp));
    voleith_secure_zero(ct, sizeof(ct));
}

#endif /* VOLEITH_AES_CMAC_GF8_INTERNAL_H */
