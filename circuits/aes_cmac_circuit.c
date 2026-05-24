/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_cmac_circuit.c - AES-CMAC as a Boolean circuit (RFC 4493)
 *
 * Algorithm (RFC 4493 Section 2.4):
 *   Subkey generation:
 *     L  = AES(key, 0^128)
 *     K1 = (L  << 1) XOR (MSB(L)  ? Rb : 0)
 *     K2 = (K1 << 1) XOR (MSB(K1) ? Rb : 0)
 *     Rb = 0x00000000000000000000000000000087
 *
 *   CBC-MAC:
 *     X0 = 0^128
 *     Xi = AES(key, X_{i-1} XOR Mi)  for i = 1 .. n-1
 *     T  = AES(key, X_{n-1} XOR M_last)
 *     M_last = M_n XOR K1  (no padding needed)
 *            = pad(M_n) XOR K2  (padding needed)
 *     pad(x) = x || 1 || 0...0 to 128 bits
 */

#include "aes_cmac_circuit.h"
#include "aes_circuit.h"

/* ================================================================
 * Internal helpers
 * ================================================================ */

/*
 * shift_xor_rb - compute (in << 1) XOR (MSB(in) ? Rb : 0).
 *
 * "Shift left" is in the big-endian bit sense: the MSB of the 128-bit block
 * (bit 7 of byte 0 in our LSB-first wire ordering = wire[7]) shifts out, and
 * bit 127 (wire[120], LSB of byte 15) becomes 0.
 *
 * Wire index mapping for our convention (bit b of byte k = wire[8k+b],
 * bit 0 = LSB, bit 7 = MSB):
 *   Big-endian bit j <-> wire[8*(j/8) + (7 - j%8)]
 *
 * Shift formula (derived from big-endian bit shift mapped to wire indices):
 *   byte k (0..14), bit b (1..7): out[8k+b] = in[8k+(b-1)]
 *   byte k (0..14), bit 0:        out[8k]   = in[8(k+1)+7]   (MSB of next byte)
 *   byte 15,        bit b (1..7): out[120+b] = in[120+(b-1)]
 *   byte 15,        bit 0:        out[120]  = const 0
 *
 * This is pure rewiring - no AND gates.
 *
 * Rb = 0x87 at byte 15 (= 10000111b; in LSB-first ordering: bits {7,2,1,0}
 * are set, corresponding to wires 127, 122, 121, 120 of the block).
 * The conditional XOR uses only XOR gates - no AND gates.
 */
static void
shift_xor_rb(voleith_circuit_t *c, const wire_id in[128], wire_id out[128])
{
    wire_id msb = in[7]; /* MSB of block = bit 7 of byte 0 */

    wire_id shifted[128];
    for (int k = 0; k < 15; k++) {
        for (int b = 1; b < 8; b++)
            shifted[8 * k + b] = in[8 * k + b - 1];
        shifted[8 * k] = in[8 * (k + 1) + 7];
    }
    for (int b = 1; b < 8; b++)
        shifted[120 + b] = in[120 + b - 1];
    shifted[120] = voleith_circuit_add_const(c, 0);

    for (int i = 0; i < 128; i++)
        out[i] = shifted[i];

    /* Conditionally XOR with Rb (wires 120, 121, 122, 127 of block). */
    out[120] = voleith_circuit_add_xor(c, shifted[120], msb);
    out[121] = voleith_circuit_add_xor(c, shifted[121], msb);
    out[122] = voleith_circuit_add_xor(c, shifted[122], msb);
    out[127] = voleith_circuit_add_xor(c, shifted[127], msb);
}

static void
aes_call(voleith_circuit_t *c, const wire_id *key, size_t key_bits,
         const wire_id inp[128], wire_id outp[128])
{
    if (key_bits == 128)
        aes128_circuit(c, key, inp, outp);
    else
        aes256_circuit(c, key, inp, outp);
}

static void
xor_blocks(voleith_circuit_t *c, const wire_id a[128], const wire_id b[128],
           wire_id out[128])
{
    for (int i = 0; i < 128; i++)
        out[i] = voleith_circuit_add_xor(c, a[i], b[i]);
}

/* ================================================================
 * Public API
 * ================================================================ */

void
aes_cmac_circuit(voleith_circuit_t *c, const wire_id *key, size_t key_bits,
                 const wire_id *message, size_t message_bits, wire_id tag[128])
{
    /* ------------------------------------------------------------------
     * Subkey generation.
     * ------------------------------------------------------------------ */
    wire_id zero[128];
    for (int i = 0; i < 128; i++)
        zero[i] = voleith_circuit_add_const(c, 0);

    wire_id L[128];
    aes_call(c, key, key_bits, zero, L);

    wire_id K1[128], K2[128];
    shift_xor_rb(c, L, K1);
    shift_xor_rb(c, K1, K2);

    /* ------------------------------------------------------------------
     * Block structure.
     * ------------------------------------------------------------------ */
    size_t n_full_bytes = message_bits / 8;
    size_t n_full_blocks = n_full_bytes / 16;
    size_t last_bytes = n_full_bytes % 16;
    int needs_padding = (message_bits == 0) || (last_bytes != 0);

    /* ------------------------------------------------------------------
     * CBC-MAC: X0 = 0^128.
     * Process complete blocks except the last one.
     * ------------------------------------------------------------------ */
    wire_id X[128];
    for (int i = 0; i < 128; i++)
        X[i] = voleith_circuit_add_const(c, 0);

    size_t n_inner = needs_padding
                         ? n_full_blocks
                         : (n_full_blocks > 0 ? n_full_blocks - 1 : 0);
    for (size_t blk = 0; blk < n_inner; blk++) {
        wire_id inp[128];
        xor_blocks(c, X, message + blk * 128, inp);
        aes_call(c, key, key_bits, inp, X);
    }

    /* ------------------------------------------------------------------
     * Last block: M_last XOR chaining value.
     * ------------------------------------------------------------------ */
    wire_id last_inp[128];

    if (!needs_padding) {
        /* M_last = M[n_full_blocks-1] XOR K1 */
        wire_id m_xor_k[128];
        xor_blocks(c, message + (n_full_blocks - 1) * 128, K1, m_xor_k);
        xor_blocks(c, X, m_xor_k, last_inp);
    } else {
        /*
         * Padded last block:
         *   Bytes 0..(last_bytes-1): message wires
         *   Byte last_bytes:         bit 7 = 1, bits 0..6 = 0  (= 0x80)
         *   Bytes (last_bytes+1)..15: 0x00
         * Then XOR with K2 and the chaining value X.
         */
        wire_id padded[128];

        for (size_t b = 0; b < last_bytes; b++)
            for (int bit = 0; bit < 8; bit++)
                padded[b * 8 + bit] =
                    message[n_full_blocks * 128 + b * 8 + bit];

        /* 0x80 in byte ordering: MSB (bit 7) = 1, rest = 0. */
        padded[last_bytes * 8 + 7] = voleith_circuit_add_const(c, 1);
        for (int bit = 0; bit < 7; bit++)
            padded[last_bytes * 8 + bit] = voleith_circuit_add_const(c, 0);

        for (size_t b = last_bytes + 1; b < 16; b++)
            for (int bit = 0; bit < 8; bit++)
                padded[b * 8 + bit] = voleith_circuit_add_const(c, 0);

        wire_id m_xor_k[128];
        xor_blocks(c, padded, K2, m_xor_k);
        xor_blocks(c, X, m_xor_k, last_inp);
    }

    /* ------------------------------------------------------------------
     * Final AES call: T = AES(key, last_inp).
     * ------------------------------------------------------------------ */
    aes_call(c, key, key_bits, last_inp, tag);
}
