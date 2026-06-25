/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_gf8_circuit.c - Grøstl-256 and Grøstl-512 as GF(2⁸) element circuits.
 *
 * Mirrors the byte-level structure of core/grostl.c (which is the
 * NIST-KAT-validated reference) but emitting wire IDs instead of
 * computing on bytes.  SubBytes reuses aes_gf8_sbox (Prop. 6.4 from
 * FAEST §6.2); everything else is GF(2)-linear and costs zero VOLE
 * slots.
 *
 * Witness builder runs the byte-level Grøstl and records the
 * inv_in (= GF(2⁸) inverse of each S-box input) in circuit-evaluation
 * order so the prover can supply the corresponding witness slot
 * values.
 */

#include "grostl_gf8_circuit.h"
#include "../core/field.h"
#include "../core/util.h"
#include "aes_gf8_circuit.h"
#include <stdint.h>
#include <string.h>

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
 * MixBytes constants as 8x8 GF(2) linear maps.
 *
 * MixBytes (§3.4.5) multiplies each column by the circulant
 * B = circ(02, 02, 03, 04, 05, 03, 05, 07).  Each multiplication by
 * a fixed GF(2⁸) constant is a fixed GF(2)-linear map on bit
 * positions, expressible as an 8x8 matrix over GF(2).  Encoded
 * row-major: row i of M is the byte whose bit j is set iff input
 * bit j contributes to output bit i.  See voleith_gf8_add_linear_map.
 *
 * Derivation: M[i] = sum over j of (1 << j) * [bit i of (mul_c(1<<j))],
 * where mul_c(x) = c * x mod (x^8 + x^4 + x^3 + x + 1).  Sanity:
 * MUL_K applied to 0x01 should yield K, i.e. the column-0 bit pattern
 * of MUL_K equals K.
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
 * Wire-side helpers.
 *
 * State is always stored flat (column-major) per the spec mapping:
 * byte (r + ROWS*c) is row r, column c.
 * ================================================================ */

static void
add_round_constant_p_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state,
                           int columns, uint8_t round)
{
    /* Only row 0 column c gets (c<<4) XOR round; other bytes
     * unchanged.  Constant XOR is free. */
    for (int col = 0; col < columns; col++) {
        uint8_t k = (uint8_t)((col << 4) ^ round);
        state[0 + ROWS * col] =
            voleith_gf8_add_xor_const(c, state[0 + ROWS * col], k);
    }
}

static void
add_round_constant_q_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state,
                           int columns, uint8_t round)
{
    /* Rows 0..6 XOR with 0xff (i.e. bit-invert); row 7 column c XOR
     * with (0xff XOR (c<<4) XOR round). */
    for (int col = 0; col < columns; col++) {
        for (int r = 0; r < ROWS - 1; r++) {
            state[r + ROWS * col] =
                voleith_gf8_add_xor_const(c, state[r + ROWS * col], 0xff);
        }
        uint8_t k = (uint8_t)(0xff ^ (col << 4) ^ round);
        state[(ROWS - 1) + ROWS * col] =
            voleith_gf8_add_xor_const(c, state[(ROWS - 1) + ROWS * col], k);
    }
}

static void
sub_bytes_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state, size_t n)
{
    /* One aes_gf8_sbox call per state byte; each consumes one VOLE
     * slot (the inv_in witness) plus two assert_product constraints. */
    for (size_t k = 0; k < n; k++)
        state[k] = aes_gf8_sbox(c, state[k]);
}

static void
shift_bytes_wires(gf8_wire_id *state, int columns, const uint8_t shift[ROWS])
{
    /* Free: just permute wire IDs in place.  new[r][c] = old[r][(c+s) mod v]. */
    gf8_wire_id row[COLS_512];
    for (int r = 0; r < ROWS; r++) {
        uint8_t s = shift[r];
        for (int col = 0; col < columns; col++)
            row[col] = state[r + ROWS * ((col + s) % columns)];
        for (int col = 0; col < columns; col++)
            state[r + ROWS * col] = row[col];
    }
}

/* MixBytes column: new = B * col where B's row 0 = [2,2,3,4,5,3,5,7]
 * and each subsequent row is the row above right-rotated by one.
 * Per spec §3.4.5.
 *
 * out[0] = 2*a ^ 2*b ^ 3*c ^ 4*d ^ 5*e ^ 3*f ^ 5*g ^ 7*h
 * out[1] = 7*a ^ 2*b ^ 2*c ^ 3*d ^ 4*e ^ 5*f ^ 3*g ^ 5*h
 * out[2] = 5*a ^ 7*b ^ 2*c ^ 2*d ^ 3*e ^ 4*f ^ 5*g ^ 3*h
 * out[3] = 3*a ^ 5*b ^ 7*c ^ 2*d ^ 2*e ^ 3*f ^ 4*g ^ 5*h
 * out[4] = 5*a ^ 3*b ^ 5*c ^ 7*d ^ 2*e ^ 2*f ^ 3*g ^ 4*h
 * out[5] = 4*a ^ 5*b ^ 3*c ^ 5*d ^ 7*e ^ 2*f ^ 2*g ^ 3*h
 * out[6] = 3*a ^ 4*b ^ 5*c ^ 3*d ^ 5*e ^ 7*f ^ 2*g ^ 2*h
 * out[7] = 2*a ^ 3*b ^ 4*c ^ 5*d ^ 3*e ^ 5*f ^ 7*g ^ 2*h
 *
 * All linear maps + XORs - free. */
static void
mix_bytes_column_wires(voleith_gf8_circuit_t *c, const gf8_wire_id in[ROWS],
                       gf8_wire_id out[ROWS])
{
    gf8_wire_id a = in[0], b = in[1], cc = in[2], d = in[3];
    gf8_wire_id e = in[4], f = in[5], g = in[6], h = in[7];

    /* Precompute the unique scaled inputs to avoid recomputing the
     * same linear map.  Each input byte contributes at multiplier
     * 2, 3, 4, 5, and 7 across the eight output rows. */
    gf8_wire_id m2[ROWS], m3[ROWS], m4[ROWS], m5[ROWS], m7[ROWS];
    const gf8_wire_id ins[ROWS] = {a, b, cc, d, e, f, g, h};
    for (int i = 0; i < ROWS; i++) {
        m2[i] = voleith_gf8_add_linear_map(c, ins[i], MUL2_MATRIX);
        m3[i] = voleith_gf8_add_linear_map(c, ins[i], MUL3_MATRIX);
        m4[i] = voleith_gf8_add_linear_map(c, ins[i], MUL4_MATRIX);
        m5[i] = voleith_gf8_add_linear_map(c, ins[i], MUL5_MATRIX);
        m7[i] = voleith_gf8_add_linear_map(c, ins[i], MUL7_MATRIX);
    }

    /* Each row sums 8 scaled inputs via a chain of XORs (all free
     * - GF(2)-linear operations cost zero VOLE slots).  The
     * MixBytes B matrix is circulant with first row
     * [2, 2, 3, 4, 5, 3, 5, 7], so row i pulls multipliers
     * cyclically shifted right by i. */
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

static void
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
 * Permutations P and Q at the wire level.
 *
 * Round = AddRoundConstant -> SubBytes -> ShiftBytes -> MixBytes
 * (spec §3.4, strict order, load-bearing for prover/verifier
 * determinism).
 * ================================================================ */

static void
permute_p_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state, int columns,
                int rounds, const uint8_t shift[ROWS])
{
    size_t state_bytes = (size_t)(ROWS * columns);
    for (int r = 0; r < rounds; r++) {
        add_round_constant_p_wires(c, state, columns, (uint8_t)r);
        sub_bytes_wires(c, state, state_bytes);
        shift_bytes_wires(state, columns, shift);
        mix_bytes_wires(c, state, columns);
    }
}

static void
permute_q_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state, int columns,
                int rounds, const uint8_t shift[ROWS])
{
    size_t state_bytes = (size_t)(ROWS * columns);
    for (int r = 0; r < rounds; r++) {
        add_round_constant_q_wires(c, state, columns, (uint8_t)r);
        sub_bytes_wires(c, state, state_bytes);
        shift_bytes_wires(state, columns, shift);
        mix_bytes_wires(c, state, columns);
    }
}

/* ================================================================
 * Compression and output transform.
 *
 * f(h, m) = P(h XOR m) XOR Q(m) XOR h   (spec §3.2)
 * Omega(h) = trunc_n(P(h) XOR h)         (spec §3.3)
 * ================================================================ */

static void
compress_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h, const gf8_wire_id *m,
               int columns, int rounds, const uint8_t shift_p[ROWS],
               const uint8_t shift_q[ROWS])
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id p_in[STATE_BYTES_512];
    gf8_wire_id q_in[STATE_BYTES_512];

    for (size_t i = 0; i < n; i++) {
        p_in[i] = voleith_gf8_add_xor(c, h[i], m[i]);
        q_in[i] = m[i];
    }

    permute_p_wires(c, p_in, columns, rounds, shift_p);
    permute_q_wires(c, q_in, columns, rounds, shift_q);

    for (size_t i = 0; i < n; i++) {
        gf8_wire_id pq = voleith_gf8_add_xor(c, p_in[i], q_in[i]);
        h[i] = voleith_gf8_add_xor(c, h[i], pq);
    }
}

static void
output_transform_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h, int columns,
                       int rounds, const uint8_t shift_p[ROWS])
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id temp[STATE_BYTES_512];

    for (size_t i = 0; i < n; i++)
        temp[i] = h[i];

    permute_p_wires(c, temp, columns, rounds, shift_p);

    for (size_t i = 0; i < n; i++)
        h[i] = voleith_gf8_add_xor(c, h[i], temp[i]);
}

/* ================================================================
 * Padded message construction.
 *
 * For block_index in [0, n_blocks), produce the block's
 * (ROWS * columns) wire IDs by interleaving the caller's msg wires
 * and the public padding constants (0x80 marker, zero pad, 64-bit
 * big-endian block count at the end of the last block).
 * ================================================================ */

static size_t
n_blocks_for(size_t msg_bytes, size_t block_size)
{
    /* Pad: append 0x80, zero-pad, then 8-byte big-endian count.
     * Need padded_length to be a multiple of block_size and at least
     * msg_bytes + 1 (for 0x80) + 8 (for count) bytes. */
    return (msg_bytes + 9 + block_size - 1) / block_size;
}

/* Position of byte i within the padded message (0-indexed across
 * the full padded sequence): is it a message byte, the 0x80 marker,
 * a zero pad byte, or a length-field byte? */
static void
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
            /* Caller-supplied message byte. */
            block_out[k] = msg[pos];
        } else if (pos == msg_bytes) {
            /* The 0x80 padding marker - structural, public, constant. */
            block_out[k] = voleith_gf8_add_const(c, 0x80);
        } else if (pos < padded_len - 8) {
            /* Zero pad byte. */
            block_out[k] = voleith_gf8_add_const(c, 0x00);
        } else {
            /* Last 8 bytes: 64-bit big-endian block count. */
            int byte_in_count = (int)(pos - (padded_len - 8));
            uint8_t v = (uint8_t)(total_blocks >> (8 * (7 - byte_in_count)));
            block_out[k] = voleith_gf8_add_const(c, v);
        }
    }
}

/* ================================================================
 * Public API: circuit builders.
 *
 * IV per spec §3.5: ℓ-bit big-endian representation of n.  For
 * Grøstl-256 (ℓ=512, n=256), bytes 0..61 are zero, bytes 62..63
 * encode 256 (= 0x0100) big-endian -> state[62] = 0x01.
 * Grøstl-512 (ℓ=1024, n=512): state[126] = 0x02 (= 0x0200).
 * ================================================================ */

static void
init_iv_256_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h)
{
    for (size_t i = 0; i < STATE_BYTES_256; i++)
        h[i] = voleith_gf8_add_const(c, (i == 62) ? 0x01 : 0x00);
}

static void
init_iv_512_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h)
{
    for (size_t i = 0; i < STATE_BYTES_512; i++)
        h[i] = voleith_gf8_add_const(c, (i == 126) ? 0x02 : 0x00);
}

void
grostl256_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                      size_t msg_bytes, gf8_wire_id out[32])
{
    gf8_wire_id h[STATE_BYTES_256];
    init_iv_256_wires(c, h);

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    gf8_wire_id block[STATE_BYTES_256];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block(c, msg, msg_bytes, bi, n_blocks, STATE_BYTES_256,
                           block);
        compress_wires(c, h, block, COLS_256, ROUNDS_256, SHIFT_P512,
                       SHIFT_Q512);
    }

    output_transform_wires(c, h, COLS_256, ROUNDS_256, SHIFT_P512);

    /* trunc_256: last 32 bytes of the 64-byte state. */
    for (size_t i = 0; i < 32; i++)
        out[i] = h[STATE_BYTES_256 - 32 + i];
}

void
grostl512_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                      size_t msg_bytes, gf8_wire_id out[64])
{
    gf8_wire_id h[STATE_BYTES_512];
    init_iv_512_wires(c, h);

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    gf8_wire_id block[STATE_BYTES_512];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block(c, msg, msg_bytes, bi, n_blocks, STATE_BYTES_512,
                           block);
        compress_wires(c, h, block, COLS_512, ROUNDS_512, SHIFT_P1024,
                       SHIFT_Q1024);
    }

    output_transform_wires(c, h, COLS_512, ROUNDS_512, SHIFT_P1024);

    /* trunc_512: last 64 bytes of the 128-byte state. */
    for (size_t i = 0; i < 64; i++)
        out[i] = h[STATE_BYTES_512 - 64 + i];
}

/* ================================================================
 * Fixed-input single-compression node circuits.
 *
 * H = Omega(f(iv, block)): inject iv as constant wires, run ONE
 * compression (no padding), then the output transform, truncate to the
 * node width.  Sibling of grostl{256,512}_gf8_circuit, reusing
 * compress_wires / output_transform_wires; the full-hash path is
 * untouched.  See grostl_gf8_circuit.h for the contract.
 * ================================================================ */

static void
grostl_node_circuit_impl(voleith_gf8_circuit_t *c, const uint8_t *iv,
                         const gf8_wire_id *block, int columns, int rounds,
                         const uint8_t shift_p[ROWS],
                         const uint8_t shift_q[ROWS], size_t out_bytes,
                         gf8_wire_id *out)
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id h[STATE_BYTES_512];

    /* iv is public structural data: constant wires, zero VOLE slots. */
    for (size_t i = 0; i < n; i++)
        h[i] = voleith_gf8_add_const(c, iv[i]);

    compress_wires(c, h, block, columns, rounds, shift_p, shift_q);
    output_transform_wires(c, h, columns, rounds, shift_p);

    /* trunc_n: last out_bytes of the state (matches core/grostl.c). */
    for (size_t i = 0; i < out_bytes; i++)
        out[i] = h[n - out_bytes + i];
}

void
grostl256_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                           const gf8_wire_id block[64], gf8_wire_id out[32])
{
    grostl_node_circuit_impl(c, iv, block, COLS_256, ROUNDS_256, SHIFT_P512,
                             SHIFT_Q512, 32, out);
}

void
grostl512_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[128],
                           const gf8_wire_id block[128], gf8_wire_id out[64])
{
    grostl_node_circuit_impl(c, iv, block, COLS_512, ROUNDS_512, SHIFT_P1024,
                             SHIFT_Q1024, 64, out);
}

/* ================================================================
 * Witness builder.
 *
 * Runs the byte-level Grøstl in lockstep with the circuit and
 * records the inv_in (GF(2⁸) inverse of each S-box input, or 0 when
 * the input is 0) in the same order that the circuit's aes_gf8_sbox
 * calls add inv_in witnesses.
 *
 * Witness layout:
 *   [0 .. msg_bytes - 1]   : caller's message bytes
 *   [msg_bytes ..]         : inv_in for every S-box, in
 *                            circuit-evaluation order
 * ================================================================ */

/* AES S-box: affine(inv(x)) XOR 0x63.  Same formulation as in
 * circuits/aes_gf8_circuit.c, but using the constant-time Fermat
 * inverse exposed by core/field.h (a^254 via a fixed addition chain
 * of 7 squarings + 6 multiplications - ~20x faster than the
 * brute-force scan it replaces, identical output, still
 * constant-time). */
static uint8_t
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

static uint8_t
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

static void
add_round_constant_p_bytes(uint8_t *state, int columns, uint8_t round)
{
    for (int col = 0; col < columns; col++)
        state[0 + ROWS * col] ^= (uint8_t)((col << 4) ^ round);
}

static void
add_round_constant_q_bytes(uint8_t *state, int columns, uint8_t round)
{
    for (int col = 0; col < columns; col++) {
        for (int r = 0; r < ROWS - 1; r++)
            state[r + ROWS * col] ^= 0xff;
        state[(ROWS - 1) + ROWS * col] ^= (uint8_t)(0xff ^ (col << 4) ^ round);
    }
}

/* SubBytes byte-trace that ALSO writes inv_in for each S-box into
 * *inv_out_p (advancing the pointer). */
static void
sub_bytes_bytes_capture(uint8_t *state, size_t n, uint8_t **inv_out_p)
{
    for (size_t k = 0; k < n; k++) {
        **inv_out_p = voleith_gf8_inv(state[k]);
        (*inv_out_p)++;
        state[k] = aes_sbox_byte(state[k]);
    }
}

static void
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

static void
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

static void
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

static void
permute_p_bytes_capture(uint8_t *state, int columns, int rounds,
                        const uint8_t shift[ROWS], uint8_t **inv_out_p)
{
    size_t n = (size_t)(ROWS * columns);
    for (int r = 0; r < rounds; r++) {
        add_round_constant_p_bytes(state, columns, (uint8_t)r);
        sub_bytes_bytes_capture(state, n, inv_out_p);
        shift_bytes_bytes(state, columns, shift);
        mix_bytes_bytes(state, columns);
    }
}

static void
permute_q_bytes_capture(uint8_t *state, int columns, int rounds,
                        const uint8_t shift[ROWS], uint8_t **inv_out_p)
{
    size_t n = (size_t)(ROWS * columns);
    for (int r = 0; r < rounds; r++) {
        add_round_constant_q_bytes(state, columns, (uint8_t)r);
        sub_bytes_bytes_capture(state, n, inv_out_p);
        shift_bytes_bytes(state, columns, shift);
        mix_bytes_bytes(state, columns);
    }
}

static void
compress_bytes_capture(uint8_t *h, const uint8_t *m, int columns, int rounds,
                       const uint8_t shift_p[ROWS], const uint8_t shift_q[ROWS],
                       uint8_t **inv_out_p)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t p_in[STATE_BYTES_512];
    uint8_t q_in[STATE_BYTES_512];
    for (size_t i = 0; i < n; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }
    /* Circuit emits P-permutation S-boxes first, then Q's, per
     * compress_wires.  Match that order here. */
    permute_p_bytes_capture(p_in, columns, rounds, shift_p, inv_out_p);
    permute_q_bytes_capture(q_in, columns, rounds, shift_q, inv_out_p);
    for (size_t i = 0; i < n; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    voleith_secure_zero(p_in, sizeof(p_in));
    voleith_secure_zero(q_in, sizeof(q_in));
}

static void
output_transform_bytes_capture(uint8_t *h, int columns, int rounds,
                               const uint8_t shift_p[ROWS], uint8_t **inv_out_p)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t temp[STATE_BYTES_512];
    memcpy(temp, h, n);
    permute_p_bytes_capture(temp, columns, rounds, shift_p, inv_out_p);
    for (size_t i = 0; i < n; i++)
        h[i] ^= temp[i];
    voleith_secure_zero(temp, sizeof(temp));
}

/* Build a padded message block in flat-byte form.  Mirrors
 * build_padded_block at the wire level. */
static void
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

size_t
grostl256_gf8_witness_bytes(size_t msg_bytes)
{
    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    /* Per compression: 1,280 S-boxes (P + Q).  Output transform:
     * 640 (P only). */
    return msg_bytes + n_blocks * 1280u + 640u;
}

size_t
grostl512_gf8_witness_bytes(size_t msg_bytes)
{
    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    /* Per compression: 14 rounds * 128 boxes * 2 = 3,584.  Output
     * transform: 1,792. */
    return msg_bytes + n_blocks * 3584u + 1792u;
}

void
grostl256_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                            uint8_t *witness)
{
    /* Front of witness: message bytes (matching the caller's
     * voleith_gf8_add_witness declaration order). */
    if (msg_bytes > 0)
        memcpy(witness, msg, msg_bytes);

    uint8_t *inv_out = witness + msg_bytes;

    /* IV. */
    uint8_t h[STATE_BYTES_256];
    memset(h, 0, sizeof(h));
    h[62] = 0x01;

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    uint8_t block[STATE_BYTES_256];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block_bytes(msg, msg_bytes, bi, n_blocks, STATE_BYTES_256,
                                 block);
        compress_bytes_capture(h, block, COLS_256, ROUNDS_256, SHIFT_P512,
                               SHIFT_Q512, &inv_out);
    }

    output_transform_bytes_capture(h, COLS_256, ROUNDS_256, SHIFT_P512,
                                   &inv_out);

    voleith_secure_zero(h, sizeof(h));
    voleith_secure_zero(block, sizeof(block));
}

void
grostl512_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                            uint8_t *witness)
{
    if (msg_bytes > 0)
        memcpy(witness, msg, msg_bytes);

    uint8_t *inv_out = witness + msg_bytes;

    uint8_t h[STATE_BYTES_512];
    memset(h, 0, sizeof(h));
    h[126] = 0x02;

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    uint8_t block[STATE_BYTES_512];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block_bytes(msg, msg_bytes, bi, n_blocks, STATE_BYTES_512,
                                 block);
        compress_bytes_capture(h, block, COLS_512, ROUNDS_512, SHIFT_P1024,
                               SHIFT_Q1024, &inv_out);
    }

    output_transform_bytes_capture(h, COLS_512, ROUNDS_512, SHIFT_P1024,
                                   &inv_out);

    voleith_secure_zero(h, sizeof(h));
    voleith_secure_zero(block, sizeof(block));
}

/* ================================================================
 * Node-circuit witness builders.
 *
 * One compression + output transform over (iv, block), capturing the
 * inv_in in the same P-then-Q, then output-transform-P order the node
 * circuit emits.  Excludes block bytes (caller-declared).
 * ================================================================ */

size_t
grostl256_gf8_node_invin_bytes(void)
{
    /* One compression (P + Q = 1,280) + output transform P (640). */
    return 1280u + 640u;
}

size_t
grostl512_gf8_node_invin_bytes(void)
{
    /* One compression (14 * 128 * 2 = 3,584) + output transform P (1,792). */
    return 3584u + 1792u;
}

void
grostl256_gf8_node_build_witness(const uint8_t iv[64], const uint8_t block[64],
                                 uint8_t *inv_out)
{
    uint8_t h[STATE_BYTES_256];
    memcpy(h, iv, STATE_BYTES_256);

    compress_bytes_capture(h, block, COLS_256, ROUNDS_256, SHIFT_P512,
                           SHIFT_Q512, &inv_out);
    output_transform_bytes_capture(h, COLS_256, ROUNDS_256, SHIFT_P512,
                                   &inv_out);

    voleith_secure_zero(h, sizeof(h));
}

void
grostl512_gf8_node_build_witness(const uint8_t iv[128],
                                 const uint8_t block[128], uint8_t *inv_out)
{
    uint8_t h[STATE_BYTES_512];
    memcpy(h, iv, STATE_BYTES_512);

    compress_bytes_capture(h, block, COLS_512, ROUNDS_512, SHIFT_P1024,
                           SHIFT_Q1024, &inv_out);
    output_transform_bytes_capture(h, COLS_512, ROUNDS_512, SHIFT_P1024,
                                   &inv_out);

    voleith_secure_zero(h, sizeof(h));
}
