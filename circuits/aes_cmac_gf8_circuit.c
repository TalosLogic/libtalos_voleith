/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_gf8_circuit.c - AES-CMAC as a GF(2⁸) element circuit (RFC 4493)
 *
 * Element-level port of aes_cmac_circuit.c. Each wire carries one GF(2⁸)
 * element (one byte) instead of one bit. The shift_xor_rb operation is
 * implemented via per-byte GF(2) linear maps - no mul gates required.
 * All VOLE cost comes from the AES calls inside (200 or 276 witness slots each).
 */

#include "aes_cmac_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "../core/util.h"
#include <string.h>

/* ================================================================
 * Internal helpers
 * ================================================================ */

/*
 * shift_xor_rb_gf8 - compute (in << 1) XOR (MSB(in) ? Rb : 0) at byte level.
 *
 * The 128-bit block left-shift operates on in[0..15] as a big-endian integer:
 * byte 0 holds the most-significant bits; MSB = bit 7 of in[0].
 *
 * At the GF(2⁸) element level, each output byte is a GF(2)-linear function
 * of the input bytes. Three matrices encode the per-byte dependencies:
 *
 *   M_lo  - shifts bits 0..6 of a byte up by one (out_bit_b = in_bit_{b-1} for
 *            b=1..7; out_bit_0 = 0). Represents the "left-shift within byte"
 *            contribution of in[k] to out[k].
 *
 *   M_hi  - extracts bit 7 of a byte and places it at bit 0 of the output
 *            (out_bit_0 = in_bit_7). Represents the carry from in[k+1]→out[k].
 *
 *   M_msb - for byte 15: encodes the conditional Rb XOR. Rb = 0x87 is XOR'd
 *            into out[15] when MSB(in[0]) = bit 7 of in[0] is 1. Since this
 *            is GF(2)-linear in in[0], M_msb captures it:
 *              out_bit_i ^= M_msb[i][7] * in[0]_bit_7
 *            0x87 has bits {0,1,2,7} set, so M_msb rows 0,1,2,7 = 0x80
 *            (select bit 7 of in[0]).
 *
 * For bytes 0..14:
 *   out[k] = M_lo · in[k]  XOR  M_hi · in[k+1]
 *
 * For byte 15:
 *   out[15] = M_lo · in[15]  XOR  M_msb · in[0]
 *   (M_lo produces the shifted value with bit 0 = 0; M_msb adds the conditional
 *    Rb = 0x87 XOR based on the block MSB, which lives in in[0].)
 */
static void
shift_xor_rb_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id in[16],
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
    /* Byte 15: shift left (M_lo) then XOR conditional Rb from in[0] (M_msb). */
    gf8_wire_id lo15 = voleith_gf8_add_linear_map(c, in[15], M_lo);
    gf8_wire_id msb15 = voleith_gf8_add_linear_map(c, in[0], M_msb);
    out[15] = voleith_gf8_add_xor(c, lo15, msb15);
}

static void
aes_gf8_call(voleith_gf8_circuit_t *c, const gf8_wire_id *key, size_t key_bytes,
             const gf8_wire_id inp[16], gf8_wire_id outp[16])
{
    if (key_bytes == 16)
        aes128_gf8_circuit(c, key, inp, outp);
    else
        aes256_gf8_circuit(c, key, inp, outp);
}

static void
xor_blocks_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id a[16],
               const gf8_wire_id b[16], gf8_wire_id out[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = voleith_gf8_add_xor(c, a[k], b[k]);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
aes_cmac_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *key,
                     size_t key_bytes, const gf8_wire_id *message,
                     size_t message_bytes, gf8_wire_id tag[16])
{
    /* ------------------------------------------------------------------
     * Subkey generation: L = AES(key, 0^16), K1 = shift_xor_rb(L),
     *                    K2 = shift_xor_rb(K1).
     * ------------------------------------------------------------------ */
    gf8_wire_id zero[16];
    for (int k = 0; k < 16; k++)
        zero[k] = voleith_gf8_add_const(c, 0x00);

    gf8_wire_id L[16];
    aes_gf8_call(c, key, key_bytes, zero, L);

    gf8_wire_id K1[16], K2[16];
    shift_xor_rb_gf8(c, L, K1);
    shift_xor_rb_gf8(c, K1, K2);

    /* ------------------------------------------------------------------
     * Block structure.
     * ------------------------------------------------------------------ */
    size_t n_full_blocks = message_bytes / 16;
    size_t last_bytes = message_bytes % 16;
    int needs_padding = (message_bytes == 0) || (last_bytes != 0);

    /* ------------------------------------------------------------------
     * CBC-MAC: X0 = 0^16.
     * Process complete blocks except the last.
     * ------------------------------------------------------------------ */
    gf8_wire_id X[16];
    for (int k = 0; k < 16; k++)
        X[k] = voleith_gf8_add_const(c, 0x00);

    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        gf8_wire_id inp[16];
        xor_blocks_gf8(c, X, message + blk * 16, inp);
        aes_gf8_call(c, key, key_bytes, inp, X);
    }

    /* ------------------------------------------------------------------
     * Last block: M_last XOR chaining value.
     * ------------------------------------------------------------------ */
    gf8_wire_id last_inp[16];

    if (!needs_padding) {
        /* M_last = M[n_full_blocks-1] XOR K1 */
        gf8_wire_id m_xor_k[16];
        xor_blocks_gf8(c, message + (n_full_blocks - 1) * 16, K1, m_xor_k);
        xor_blocks_gf8(c, X, m_xor_k, last_inp);
    } else {
        /*
         * Padded last block:
         *   bytes 0..(last_bytes-1): message wires
         *   byte last_bytes:         0x80 (constant)
         *   bytes (last_bytes+1)..15: 0x00 (constants)
         * Then XOR with K2 and chaining value X.
         */
        gf8_wire_id padded[16];

        for (size_t b = 0; b < last_bytes; b++)
            padded[b] = message[n_full_blocks * 16 + b];

        padded[last_bytes] = voleith_gf8_add_const(c, 0x80);

        for (size_t b = last_bytes + 1; b < 16; b++)
            padded[b] = voleith_gf8_add_const(c, 0x00);

        gf8_wire_id m_xor_k[16];
        xor_blocks_gf8(c, padded, K2, m_xor_k);
        xor_blocks_gf8(c, X, m_xor_k, last_inp);
    }

    /* ------------------------------------------------------------------
     * Final AES call: T = AES(key, last_inp).
     * ------------------------------------------------------------------ */
    aes_gf8_call(c, key, key_bytes, last_inp, tag);
}

/* ================================================================
 * Witness builder
 * ================================================================ */

/* Software shift_xor_rb for byte-level witness computation. */
static void
shift_xor_rb_bytes(const uint8_t in[16], uint8_t out[16])
{
    uint8_t msb = (in[0] >> 7) & 1;
    for (int i = 0; i < 15; i++)
        out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (uint8_t)((in[15] << 1) ^ (msb ? 0x87u : 0u));
}

/*
 * Run one AES call for the witness: fills ct_out with ciphertext and
 * advances *inv_ptr by inv_per_call bytes (the S-box inv_in values).
 */
static void
do_aes_witness(const uint8_t *key, size_t key_bytes, const uint8_t pt[16],
               uint8_t ct_out[16], uint8_t **inv_ptr)
{
    uint8_t w_temp[308];

    if (key_bytes == 16)
        aes128_gf8_build_witness(key, pt, w_temp, ct_out);
    else
        aes256_gf8_build_witness(key, pt, w_temp, ct_out);

    size_t inv_per_call = (key_bytes == 16) ? 200u : 276u;
    memcpy(*inv_ptr, w_temp + key_bytes, inv_per_call);
    *inv_ptr += inv_per_call;
    /* CIR-11: w_temp held the full per-call AES witness, including the
     * key prefix and the S-box inv_in values.  Both are secret. */
    voleith_secure_zero(w_temp, sizeof(w_temp));
}

void
aes_cmac_gf8_build_witness(const uint8_t *key, size_t key_bytes,
                           const uint8_t *message, size_t message_bytes,
                           uint8_t *witness_out, uint8_t tag_out[16])
{
    /* Witness layout: [key_bytes key] [inv_per_call per AES call, in order]. */
    memcpy(witness_out, key, key_bytes);
    uint8_t *inv_ptr = witness_out + key_bytes;

    /* Subkey generation: L = AES(key, 0^16). */
    uint8_t zero[16] = {0};
    uint8_t L[16];
    do_aes_witness(key, key_bytes, zero, L, &inv_ptr);

    /* K1, K2 from L (software computation). */
    uint8_t K1[16], K2[16];
    shift_xor_rb_bytes(L, K1);
    shift_xor_rb_bytes(K1, K2);

    /* Block structure. */
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
        do_aes_witness(key, key_bytes, inp, X, &inv_ptr);
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
    do_aes_witness(key, key_bytes, last_inp, ct, &inv_ptr);

    if (tag_out)
        memcpy(tag_out, ct, 16);

    /* CIR-11: zero all per-call CMAC working buffers.
     *   L, K1, K2: CMAC subkeys derived from the master key.
     *   X: CBC-MAC running state across blocks under that key.
     *   last_inp, ct: final block's plaintext and ciphertext.
     * Note: w_temp inside do_aes_witness is zeroed there. */
    voleith_secure_zero(L, sizeof(L));
    voleith_secure_zero(K1, sizeof(K1));
    voleith_secure_zero(K2, sizeof(K2));
    voleith_secure_zero(X, sizeof(X));
    voleith_secure_zero(last_inp, sizeof(last_inp));
    voleith_secure_zero(ct, sizeof(ct));
}
