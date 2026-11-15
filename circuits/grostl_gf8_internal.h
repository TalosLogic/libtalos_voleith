/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_gf8_internal.h - shared Grostl linear-layer and byte-level helpers.
 *
 * These are the structural pieces of Grostl that are identical whether the
 * S-box data path is expressed with the frozen 8-bit inverse (grostl_gf8_circuit
 * .c) or the FAEST paired-round norm (grostl_norm_gf8_circuit.c): the MixBytes
 * MDS (wire and byte level), the byte-level ShiftBytes / S-box / padding, the
 * spec constants, and the IV injection.  Both translation units include this
 * header so there is a single source of truth and the two circuits cannot drift
 * on the linear layer they must agree on.  The helper names are unchanged from
 * their former in-file definitions, so the frozen circuit's call sites are
 * untouched.
 *
 * Moving these definitions here is behavior-preserving: they emit the same gates
 * / compute the same bytes as before, so the frozen circuit's output,
 * fingerprints and KATs are unchanged (those depend on the emitted circuit, not
 * on where a C helper is defined).
 *
 * Grostl-specific pieces that are NOT shared stay in their own .c: ShiftBytes at
 * the wire level and the inv_in-capturing SubBytes/permute/compress traces are
 * frozen-only; the norm circuit has its own norm-form data path and witness
 * capture.  AddRoundConstant is shared through grostl_norm_round_const in
 * proof/gf8_grostl_norm_const.h.
 */

#ifndef VOLEITH_GROSTL_GF8_INTERNAL_H
#define VOLEITH_GROSTL_GF8_INTERNAL_H

#include "../proof/gf8_circuit.h"
#include "aes_gf8_circuit.h" /* AES_GF8_AFFINE_MATRIX */
#include "../core/field.h"   /* voleith_gf8_inv */
#include <stddef.h>
#include <stdint.h>

/* ================================================================
 * Spec constants - matched against core/grostl.c.
 * ================================================================ */

#define ROWS 8
#define COLS_256 8
#define COLS_512 16
#define STATE_BYTES_256 (ROWS * COLS_256) /* 64  */
#define STATE_BYTES_512 (ROWS * COLS_512) /* 128 */
#define ROUNDS_256 10
#define ROUNDS_512 14

/* ShiftBytes (spec §3.4.4 + Round3Mods §2). */
static const uint8_t SHIFT_P512[ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};
static const uint8_t SHIFT_Q512[ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};
static const uint8_t SHIFT_P1024[ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};
static const uint8_t SHIFT_Q1024[ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* ================================================================
 * MixBytes constants as 8x8 GF(2) linear maps.  Row i of M is the byte
 * whose bit j is set iff input bit j contributes to output bit i.
 * ================================================================ */

/* Multiply by 0x02 (xtime). */
static const uint8_t MUL2_MATRIX[8] = {
    0x80, 0x81, 0x02, 0x84, 0x88, 0x10, 0x20, 0x40,
};
/* Multiply by 0x03 = xtime(a) XOR a = MUL2 XOR I. */
static const uint8_t MUL3_MATRIX[8] = {
    0x81, 0x83, 0x06, 0x8c, 0x98, 0x30, 0x60, 0xc0,
};
/* Multiply by 0x04 = xtime(xtime(a)). */
static const uint8_t MUL4_MATRIX[8] = {
    0x40, 0xc0, 0x81, 0x42, 0xc4, 0x88, 0x10, 0x20,
};
/* Multiply by 0x05 = MUL4 XOR I. */
static const uint8_t MUL5_MATRIX[8] = {
    0x41, 0xc2, 0x85, 0x4a, 0xd4, 0xa8, 0x50, 0xa0,
};
/* Multiply by 0x07 = MUL4 XOR MUL2 XOR I. */
static const uint8_t MUL7_MATRIX[8] = {
    0xc1, 0x43, 0x87, 0xce, 0x5c, 0xb8, 0x70, 0xe0,
};

/* ================================================================
 * Wire-level helpers.  State is flat column-major: byte (r + ROWS*c) is
 * row r, column c.
 * ================================================================ */

/* MixBytes column: new = B * col where B's row 0 = [2,2,3,4,5,3,5,7] and
 * each subsequent row is the row above right-rotated by one. */
static inline void
mix_bytes_column_wires(voleith_gf8_circuit_t *c, const gf8_wire_id in[ROWS],
                       gf8_wire_id out[ROWS])
{
    gf8_wire_id a = in[0], b = in[1], cc = in[2], d = in[3];
    gf8_wire_id e = in[4], f = in[5], g = in[6], h = in[7];

    gf8_wire_id m2[ROWS], m3[ROWS], m4[ROWS], m5[ROWS], m7[ROWS];
    const gf8_wire_id ins[ROWS] = {a, b, cc, d, e, f, g, h};
    for (int i = 0; i < ROWS; i++) {
        m2[i] = voleith_gf8_add_linear_map(c, ins[i], MUL2_MATRIX);
        m3[i] = voleith_gf8_add_linear_map(c, ins[i], MUL3_MATRIX);
        m4[i] = voleith_gf8_add_linear_map(c, ins[i], MUL4_MATRIX);
        m5[i] = voleith_gf8_add_linear_map(c, ins[i], MUL5_MATRIX);
        m7[i] = voleith_gf8_add_linear_map(c, ins[i], MUL7_MATRIX);
    }

    gf8_wire_id t;

    t = voleith_gf8_add_xor(c, m2[0], m2[1]);
    t = voleith_gf8_add_xor(c, t, m3[2]);
    t = voleith_gf8_add_xor(c, t, m4[3]);
    t = voleith_gf8_add_xor(c, t, m5[4]);
    t = voleith_gf8_add_xor(c, t, m3[5]);
    t = voleith_gf8_add_xor(c, t, m5[6]);
    out[0] = voleith_gf8_add_xor(c, t, m7[7]);

    t = voleith_gf8_add_xor(c, m7[0], m2[1]);
    t = voleith_gf8_add_xor(c, t, m2[2]);
    t = voleith_gf8_add_xor(c, t, m3[3]);
    t = voleith_gf8_add_xor(c, t, m4[4]);
    t = voleith_gf8_add_xor(c, t, m5[5]);
    t = voleith_gf8_add_xor(c, t, m3[6]);
    out[1] = voleith_gf8_add_xor(c, t, m5[7]);

    t = voleith_gf8_add_xor(c, m5[0], m7[1]);
    t = voleith_gf8_add_xor(c, t, m2[2]);
    t = voleith_gf8_add_xor(c, t, m2[3]);
    t = voleith_gf8_add_xor(c, t, m3[4]);
    t = voleith_gf8_add_xor(c, t, m4[5]);
    t = voleith_gf8_add_xor(c, t, m5[6]);
    out[2] = voleith_gf8_add_xor(c, t, m3[7]);

    t = voleith_gf8_add_xor(c, m3[0], m5[1]);
    t = voleith_gf8_add_xor(c, t, m7[2]);
    t = voleith_gf8_add_xor(c, t, m2[3]);
    t = voleith_gf8_add_xor(c, t, m2[4]);
    t = voleith_gf8_add_xor(c, t, m3[5]);
    t = voleith_gf8_add_xor(c, t, m4[6]);
    out[3] = voleith_gf8_add_xor(c, t, m5[7]);

    t = voleith_gf8_add_xor(c, m5[0], m3[1]);
    t = voleith_gf8_add_xor(c, t, m5[2]);
    t = voleith_gf8_add_xor(c, t, m7[3]);
    t = voleith_gf8_add_xor(c, t, m2[4]);
    t = voleith_gf8_add_xor(c, t, m2[5]);
    t = voleith_gf8_add_xor(c, t, m3[6]);
    out[4] = voleith_gf8_add_xor(c, t, m4[7]);

    t = voleith_gf8_add_xor(c, m4[0], m5[1]);
    t = voleith_gf8_add_xor(c, t, m3[2]);
    t = voleith_gf8_add_xor(c, t, m5[3]);
    t = voleith_gf8_add_xor(c, t, m7[4]);
    t = voleith_gf8_add_xor(c, t, m2[5]);
    t = voleith_gf8_add_xor(c, t, m2[6]);
    out[5] = voleith_gf8_add_xor(c, t, m3[7]);

    t = voleith_gf8_add_xor(c, m3[0], m4[1]);
    t = voleith_gf8_add_xor(c, t, m5[2]);
    t = voleith_gf8_add_xor(c, t, m3[3]);
    t = voleith_gf8_add_xor(c, t, m5[4]);
    t = voleith_gf8_add_xor(c, t, m7[5]);
    t = voleith_gf8_add_xor(c, t, m2[6]);
    out[6] = voleith_gf8_add_xor(c, t, m2[7]);

    t = voleith_gf8_add_xor(c, m2[0], m3[1]);
    t = voleith_gf8_add_xor(c, t, m4[2]);
    t = voleith_gf8_add_xor(c, t, m5[3]);
    t = voleith_gf8_add_xor(c, t, m3[4]);
    t = voleith_gf8_add_xor(c, t, m5[5]);
    t = voleith_gf8_add_xor(c, t, m7[6]);
    out[7] = voleith_gf8_add_xor(c, t, m2[7]);
}

static inline void
mix_bytes_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state, int columns)
{
    gf8_wire_id col_in[ROWS], col_out[ROWS];
    for (int col = 0; col < columns; col++) {
        for (int r = 0; r < ROWS; r++)
            col_in[r] = state[r + ROWS * col];
        mix_bytes_column_wires(c, col_in, col_out);
        for (int r = 0; r < ROWS; r++)
            state[r + ROWS * col] = col_out[r];
    }
}

/* ================================================================
 * Padded message construction.
 * ================================================================ */

static inline size_t
n_blocks_for(size_t msg_bytes, size_t block_size)
{
    return (msg_bytes + 9 + block_size - 1) / block_size;
}

static inline void
build_padded_block(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                   size_t msg_bytes, size_t block_index, size_t n_blocks,
                   size_t block_size, gf8_wire_id *block_out)
{
    uint64_t total_blocks = (uint64_t)n_blocks;
    size_t padded_len = n_blocks * block_size;
    size_t base = block_index * block_size;

    for (size_t k = 0; k < block_size; k++) {
        size_t pos = base + k;
        if (pos < msg_bytes) {
            block_out[k] = msg[pos];
        } else if (pos == msg_bytes) {
            block_out[k] = voleith_gf8_add_const(c, 0x80);
        } else if (pos < padded_len - 8) {
            block_out[k] = voleith_gf8_add_const(c, 0x00);
        } else {
            int byte_in_count = (int)(pos - (padded_len - 8));
            uint8_t v = (uint8_t)(total_blocks >> (8 * (7 - byte_in_count)));
            block_out[k] = voleith_gf8_add_const(c, v);
        }
    }
}

/* IV per spec §3.5: ℓ-bit big-endian representation of n. */
static inline void
init_iv_256_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h)
{
    for (size_t i = 0; i < STATE_BYTES_256; i++)
        h[i] = voleith_gf8_add_const(c, (i == 62) ? 0x01 : 0x00);
}

static inline void
init_iv_512_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h)
{
    for (size_t i = 0; i < STATE_BYTES_512; i++)
        h[i] = voleith_gf8_add_const(c, (i == 126) ? 0x02 : 0x00);
}

/* ================================================================
 * Byte-level helpers (for the witness builders).
 * ================================================================ */

/* AES S-box byte via the constant-time Fermat inverse. */
static inline uint8_t
aes_sbox_byte(uint8_t x)
{
    uint8_t t = voleith_gf8_inv(x);
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t masked = (uint8_t)(AES_GF8_AFFINE_MATRIX[i] & t);
        masked ^= (uint8_t)(masked >> 4);
        masked ^= (uint8_t)(masked >> 2);
        masked ^= (uint8_t)(masked >> 1);
        result |= (uint8_t)((masked & 1u) << i);
    }
    return (uint8_t)(result ^ 0x63);
}

static inline uint8_t
gf_xtime(uint8_t b)
{
    uint8_t carry = (uint8_t)(0u - (uint32_t)(b >> 7));
    return (uint8_t)((b << 1) ^ (carry & 0x1b));
}
static inline uint8_t
mul2_byte(uint8_t b)
{
    return gf_xtime(b);
}
static inline uint8_t
mul3_byte(uint8_t b)
{
    return (uint8_t)(gf_xtime(b) ^ b);
}
static inline uint8_t
mul4_byte(uint8_t b)
{
    return gf_xtime(gf_xtime(b));
}
static inline uint8_t
mul5_byte(uint8_t b)
{
    return (uint8_t)(mul4_byte(b) ^ b);
}
static inline uint8_t
mul7_byte(uint8_t b)
{
    return (uint8_t)(mul4_byte(b) ^ gf_xtime(b) ^ b);
}

static inline void
shift_bytes_bytes(uint8_t *state, int columns, const uint8_t shift[ROWS])
{
    uint8_t row[COLS_512];
    for (int r = 0; r < ROWS; r++) {
        uint8_t s = shift[r];
        for (int col = 0; col < columns; col++)
            row[col] = state[r + ROWS * ((col + s) % columns)];
        for (int col = 0; col < columns; col++)
            state[r + ROWS * col] = row[col];
    }
}

static inline void
mix_bytes_column_bytes(const uint8_t in[ROWS], uint8_t out[ROWS])
{
    uint8_t a = in[0], b = in[1], cc = in[2], d = in[3];
    uint8_t e = in[4], f = in[5], g = in[6], h = in[7];
    out[0] =
        (uint8_t)(mul2_byte(a) ^ mul2_byte(b) ^ mul3_byte(cc) ^ mul4_byte(d) ^
                  mul5_byte(e) ^ mul3_byte(f) ^ mul5_byte(g) ^ mul7_byte(h));
    out[1] =
        (uint8_t)(mul7_byte(a) ^ mul2_byte(b) ^ mul2_byte(cc) ^ mul3_byte(d) ^
                  mul4_byte(e) ^ mul5_byte(f) ^ mul3_byte(g) ^ mul5_byte(h));
    out[2] =
        (uint8_t)(mul5_byte(a) ^ mul7_byte(b) ^ mul2_byte(cc) ^ mul2_byte(d) ^
                  mul3_byte(e) ^ mul4_byte(f) ^ mul5_byte(g) ^ mul3_byte(h));
    out[3] =
        (uint8_t)(mul3_byte(a) ^ mul5_byte(b) ^ mul7_byte(cc) ^ mul2_byte(d) ^
                  mul2_byte(e) ^ mul3_byte(f) ^ mul4_byte(g) ^ mul5_byte(h));
    out[4] =
        (uint8_t)(mul5_byte(a) ^ mul3_byte(b) ^ mul5_byte(cc) ^ mul7_byte(d) ^
                  mul2_byte(e) ^ mul2_byte(f) ^ mul3_byte(g) ^ mul4_byte(h));
    out[5] =
        (uint8_t)(mul4_byte(a) ^ mul5_byte(b) ^ mul3_byte(cc) ^ mul5_byte(d) ^
                  mul7_byte(e) ^ mul2_byte(f) ^ mul2_byte(g) ^ mul3_byte(h));
    out[6] =
        (uint8_t)(mul3_byte(a) ^ mul4_byte(b) ^ mul5_byte(cc) ^ mul3_byte(d) ^
                  mul5_byte(e) ^ mul7_byte(f) ^ mul2_byte(g) ^ mul2_byte(h));
    out[7] =
        (uint8_t)(mul2_byte(a) ^ mul3_byte(b) ^ mul4_byte(cc) ^ mul5_byte(d) ^
                  mul3_byte(e) ^ mul5_byte(f) ^ mul7_byte(g) ^ mul2_byte(h));
}

static inline void
mix_bytes_bytes(uint8_t *state, int columns)
{
    uint8_t in[ROWS], out[ROWS];
    for (int col = 0; col < columns; col++) {
        for (int r = 0; r < ROWS; r++)
            in[r] = state[r + ROWS * col];
        mix_bytes_column_bytes(in, out);
        for (int r = 0; r < ROWS; r++)
            state[r + ROWS * col] = out[r];
    }
}

static inline void
build_padded_block_bytes(const uint8_t *msg, size_t msg_bytes,
                         size_t block_index, size_t n_blocks, size_t block_size,
                         uint8_t *block_out)
{
    uint64_t total_blocks = (uint64_t)n_blocks;
    size_t padded_len = n_blocks * block_size;
    size_t base = block_index * block_size;

    for (size_t k = 0; k < block_size; k++) {
        size_t pos = base + k;
        if (pos < msg_bytes) {
            block_out[k] = msg[pos];
        } else if (pos == msg_bytes) {
            block_out[k] = 0x80;
        } else if (pos < padded_len - 8) {
            block_out[k] = 0x00;
        } else {
            int byte_in_count = (int)(pos - (padded_len - 8));
            block_out[k] = (uint8_t)(total_blocks >> (8 * (7 - byte_in_count)));
        }
    }
}

#endif /* VOLEITH_GROSTL_GF8_INTERNAL_H */
