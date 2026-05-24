/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_gf8_circuit.c - AES S-box and AES-128/256 as GF(2⁸) element circuits
 *
 * Each wire represents one byte (GF(2⁸) element).  The S-box inversion uses
 * Proposition 6.4 from the FAEST spec (Section 6.2): two assert_product
 * degree-3 checks prove y = x⁻¹ without any add_mul gate, costing just one
 * witness slot for inv_in.  All other AES operations (ShiftRows, MixColumns,
 * AddRoundKey, the affine transform) are GF(2)-linear and cost zero VOLE slots.
 */

#include "aes_gf8_circuit.h"
#include "../core/field.h"
#include "../core/util.h"
#include <string.h>
#include <stdint.h>

/* ================================================================
 * Constants
 * ================================================================ */

/*
 * AES affine transform matrix (row-major 8×8 GF(2)).
 * Row i: output bit i = XOR of input bits j where bit j of matrix[i] is set.
 * From FIPS 197 Section 4.2.1:
 *   out_i = a_i ⊕ a_{i+4 mod 8} ⊕ a_{i+5 mod 8} ⊕ a_{i+6 mod 8} ⊕ a_{i+7 mod 8}
 */
const uint8_t AES_GF8_AFFINE_MATRIX[8] = {
    0xF1, /* row 0: bits {0,4,5,6,7} */
    0xE3, /* row 1: bits {0,1,5,6,7} */
    0xC7, /* row 2: bits {0,1,2,6,7} */
    0x8F, /* row 3: bits {0,1,2,3,7} */
    0x1F, /* row 4: bits {0,1,2,3,4} */
    0x3E, /* row 5: bits {1,2,3,4,5} */
    0x7C, /* row 6: bits {2,3,4,5,6} */
    0xF8, /* row 7: bits {3,4,5,6,7} */
};

/*
 * Multiply-by-2 (xtime) in GF(2⁸) with P_8 = x^8+x^4+x^3+x+1.
 * Implemented as an 8×8 GF(2) linear map.
 * out_i = a_{i-1}  for i in {2,5,6,7}
 *       = a_7       for i = 0  (reduction bit 0)
 *       = a_0 ⊕ a_7 for i = 1  (reduction bits 0 and 1)
 *       = a_2 ⊕ a_7 for i = 3  (reduction)
 *       = a_3 ⊕ a_7 for i = 4  (reduction)
 */
static const uint8_t XTIME_MATRIX[8] = {
    0x80, /* row 0: bit {7} */
    0x81, /* row 1: bits {0,7} */
    0x02, /* row 2: bit {1} */
    0x84, /* row 3: bits {2,7} */
    0x88, /* row 4: bits {3,7} */
    0x10, /* row 5: bit {4} */
    0x20, /* row 6: bit {5} */
    0x40, /* row 7: bit {6} */
};

/*
 * AES-128 round constants for key schedule (FIPS 197 Table 5).
 */
static const uint8_t RCON128[10] = {0x01, 0x02, 0x04, 0x08, 0x10,
                                    0x20, 0x40, 0x80, 0x1b, 0x36};

/*
 * AES-256 round constants for key schedule.
 */
static const uint8_t RCON256[7] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40};

/*
 * ShiftRows permutation: new_state[k] = old_state[SHIFTROWS_PERM[k]].
 * Derived from: row r=k%4 shifts left by r in column space.
 * Source column for output at (row r, col c): (c + r) % 4.
 * Source byte index: r + 4 * ((c + r) % 4).
 */
static const int SHIFTROWS_PERM[16] = {
    0,  5,  10, 15, /* output column 0 */
    4,  9,  14, 3,  /* output column 1 */
    8,  13, 2,  7,  /* output column 2 */
    12, 1,  6,  11, /* output column 3 */
};

/* ================================================================
 * AES S-box at element level
 * ================================================================ */

gf8_wire_id
aes_gf8_sbox(voleith_gf8_circuit_t *c, gf8_wire_id in)
{
    /* Prover supplies the inverse of `in` (or 0 if in = 0) as a new witness.
     * This consumes exactly 1 VOLE slot. */
    gf8_wire_id inv_in = voleith_gf8_add_witness(c);

    /* Frobenius squarings: x² is GF(2)-linear, costs zero VOLE slots. */
    gf8_wire_id in_sq = voleith_gf8_add_square(c, in);
    gf8_wire_id inv_in_sq = voleith_gf8_add_square(c, inv_in);

    /* Inversion constraints (Proposition 6.4, FAEST spec Section 6.2).
     * These check existing wires - zero new VOLE slots. */
    voleith_gf8_assert_product(c, in_sq, inv_in,
                               in); /* in² · inv_in = in     */
    voleith_gf8_assert_product(c, in, inv_in_sq,
                               inv_in); /* in · inv_in² = inv_in */

    /* AES affine transform: 8×8 GF(2) linear map - free. */
    gf8_wire_id after_affine =
        voleith_gf8_add_linear_map(c, inv_in, AES_GF8_AFFINE_MATRIX);
    /* XOR constant 0x63 - free. */
    return voleith_gf8_add_xor_const(c, after_affine, 0x63);
}

/* ================================================================
 * AES building blocks at element level
 * ================================================================ */

/* AES state: 16 element wires in column-major byte order.
 * state[k] = wire for byte k, where byte k = state[row=k%4][col=k/4]. */
typedef gf8_wire_id aes_gf8_state[16];

/* SubBytes: apply S-box to each of the 16 state bytes. */
static void
sub_bytes_gf8(voleith_gf8_circuit_t *c, aes_gf8_state s)
{
    for (int k = 0; k < 16; k++)
        s[k] = aes_gf8_sbox(c, s[k]);
}

/* ShiftRows: permute state bytes (free - no gates, just wire remapping). */
static void
shift_rows_gf8(aes_gf8_state s)
{
    aes_gf8_state tmp;
    for (int k = 0; k < 16; k++)
        tmp[k] = s[SHIFTROWS_PERM[k]];
    for (int k = 0; k < 16; k++)
        s[k] = tmp[k];
}

/*
 * mix_column_gf8 - AES MixColumns for one column - free (all linear maps + XOR).
 *
 * [b0]   [2 3 1 1] [a0]
 * [b1] = [1 2 3 1] [a1]
 * [b2]   [1 1 2 3] [a2]
 * [b3]   [3 1 1 2] [a3]
 *
 * Multiplication by 2 (xtime) is the XTIME_MATRIX linear map.
 * Multiplication by 3 = xtime(a) XOR a, i.e., xtime result XOR original.
 */
static void
mix_column_gf8(voleith_gf8_circuit_t *c, gf8_wire_id a0, gf8_wire_id a1,
               gf8_wire_id a2, gf8_wire_id a3, gf8_wire_id *b0, gf8_wire_id *b1,
               gf8_wire_id *b2, gf8_wire_id *b3)
{
    /* x0 = 2*a0, x1 = 2*a1, x2 = 2*a2, x3 = 2*a3 (free linear maps) */
    gf8_wire_id x0 = voleith_gf8_add_linear_map(c, a0, XTIME_MATRIX);
    gf8_wire_id x1 = voleith_gf8_add_linear_map(c, a1, XTIME_MATRIX);
    gf8_wire_id x2 = voleith_gf8_add_linear_map(c, a2, XTIME_MATRIX);
    gf8_wire_id x3 = voleith_gf8_add_linear_map(c, a3, XTIME_MATRIX);

    /* t0 = 3*a0 = xtime(a0) XOR a0, etc. */
    gf8_wire_id t0 = voleith_gf8_add_xor(c, x0, a0);
    gf8_wire_id t1 = voleith_gf8_add_xor(c, x1, a1);
    gf8_wire_id t2 = voleith_gf8_add_xor(c, x2, a2);
    gf8_wire_id t3 = voleith_gf8_add_xor(c, x3, a3);

    /* b0 = 2*a0 XOR 3*a1 XOR a2 XOR a3 */
    gf8_wire_id tmp;
    tmp = voleith_gf8_add_xor(c, x0, t1);
    tmp = voleith_gf8_add_xor(c, tmp, a2);
    *b0 = voleith_gf8_add_xor(c, tmp, a3);

    /* b1 = a0 XOR 2*a1 XOR 3*a2 XOR a3 */
    tmp = voleith_gf8_add_xor(c, a0, x1);
    tmp = voleith_gf8_add_xor(c, tmp, t2);
    *b1 = voleith_gf8_add_xor(c, tmp, a3);

    /* b2 = a0 XOR a1 XOR 2*a2 XOR 3*a3 */
    tmp = voleith_gf8_add_xor(c, a0, a1);
    tmp = voleith_gf8_add_xor(c, tmp, x2);
    *b2 = voleith_gf8_add_xor(c, tmp, t3);

    /* b3 = 3*a0 XOR a1 XOR a2 XOR 2*a3 */
    tmp = voleith_gf8_add_xor(c, t0, a1);
    tmp = voleith_gf8_add_xor(c, tmp, a2);
    *b3 = voleith_gf8_add_xor(c, tmp, x3);
}

/* MixColumns: apply mix_column_gf8 to each of the 4 state columns - free. */
static void
mix_columns_gf8(voleith_gf8_circuit_t *c, aes_gf8_state s)
{
    for (int col = 0; col < 4; col++) {
        gf8_wire_id b0, b1, b2, b3;
        mix_column_gf8(c, s[4 * col + 0], s[4 * col + 1], s[4 * col + 2],
                       s[4 * col + 3], &b0, &b1, &b2, &b3);
        s[4 * col + 0] = b0;
        s[4 * col + 1] = b1;
        s[4 * col + 2] = b2;
        s[4 * col + 3] = b3;
    }
}

/* AddRoundKey: XOR each state byte with the corresponding round key byte - free. */
static void
add_round_key_gf8(voleith_gf8_circuit_t *c, aes_gf8_state s,
                  const gf8_wire_id rk[16])
{
    for (int k = 0; k < 16; k++)
        s[k] = voleith_gf8_add_xor(c, s[k], rk[k]);
}

/*
 * sub_word_gf8 - apply S-box to each of 4 bytes in a word.
 * in[4], out[4]: one wire per byte.
 */
static void
sub_word_gf8(voleith_gf8_circuit_t *c, const gf8_wire_id in[4],
             gf8_wire_id out[4])
{
    for (int b = 0; b < 4; b++)
        out[b] = aes_gf8_sbox(c, in[b]);
}

/*
 * rot_word_gf8 - rotate a 4-byte word left by 1 byte - free (wire permutation).
 * (b0,b1,b2,b3) → (b1,b2,b3,b0)
 */
static void
rot_word_gf8(const gf8_wire_id in[4], gf8_wire_id out[4])
{
    out[0] = in[1];
    out[1] = in[2];
    out[2] = in[3];
    out[3] = in[0];
}

/* ================================================================
 * AES-128 key schedule
 * ================================================================ */

static void
aes128_gf8_key_schedule(voleith_gf8_circuit_t *c, const gf8_wire_id key[16],
                        gf8_wire_id rk[11][16])
{
    /* Round 0: original key. */
    for (int k = 0; k < 16; k++)
        rk[0][k] = key[k];

    /* Working words (4 words × 4 bytes each). */
    gf8_wire_id w[4][4];
    for (int word = 0; word < 4; word++)
        for (int b = 0; b < 4; b++)
            w[word][b] = key[4 * word + b];

    for (int round = 1; round <= 10; round++) {
        /* temp = RotWord(w[3]) */
        gf8_wire_id rot[4];
        rot_word_gf8(w[3], rot);

        /* temp = SubWord(temp) - adds 4 witness slots + 8 assert_products */
        gf8_wire_id sw[4];
        sub_word_gf8(c, rot, sw);

        /* XOR round constant into byte 0 of sw - free */
        sw[0] = voleith_gf8_add_xor_const(c, sw[0], RCON128[round - 1]);

        /* Expand words: w[i] = w[i] XOR w[i-1] (or sw for i=0) */
        gf8_wire_id new_w[4][4];
        for (int b = 0; b < 4; b++)
            new_w[0][b] = voleith_gf8_add_xor(c, w[0][b], sw[b]);
        for (int word = 1; word < 4; word++)
            for (int b = 0; b < 4; b++)
                new_w[word][b] =
                    voleith_gf8_add_xor(c, w[word][b], new_w[word - 1][b]);

        /* Pack round key and advance words. */
        for (int word = 0; word < 4; word++) {
            for (int b = 0; b < 4; b++) {
                rk[round][4 * word + b] = new_w[word][b];
                w[word][b] = new_w[word][b];
            }
        }
    }
}

/* ================================================================
 * Public API: AES-128 circuit
 * ================================================================ */

void
aes128_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[16],
                   const gf8_wire_id plaintext[16], gf8_wire_id output[16])
{
    /* Build key schedule: adds 40 S-box witnesses (key schedule). */
    gf8_wire_id rk[11][16];
    aes128_gf8_key_schedule(c, key, rk);

    /* Initialize state from plaintext. */
    aes_gf8_state state;
    for (int k = 0; k < 16; k++)
        state[k] = plaintext[k];

    /* Round 0: AddRoundKey. */
    add_round_key_gf8(c, state, rk[0]);

    /* Rounds 1–9: SubBytes + ShiftRows + MixColumns + AddRoundKey.
     * Each SubBytes adds 16 S-box witnesses. */
    for (int round = 1; round <= 9; round++) {
        sub_bytes_gf8(c, state);
        shift_rows_gf8(state);
        mix_columns_gf8(c, state);
        add_round_key_gf8(c, state, rk[round]);
    }

    /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns). */
    sub_bytes_gf8(c, state);
    shift_rows_gf8(state);
    add_round_key_gf8(c, state, rk[10]);

    for (int k = 0; k < 16; k++)
        output[k] = state[k];
}

/* ================================================================
 * AES-256 key schedule
 * ================================================================ */

static void
aes256_gf8_key_schedule(voleith_gf8_circuit_t *c, const gf8_wire_id key[32],
                        gf8_wire_id rk[15][16])
{
    /* Store all 60 key-schedule words. */
    gf8_wire_id w[60][4];

    /* w[0..7] from the key. */
    for (int word = 0; word < 8; word++)
        for (int b = 0; b < 4; b++)
            w[word][b] = key[4 * word + b];

    /* Generate w[8..59]. */
    for (int i = 8; i < 60; i++) {
        gf8_wire_id temp[4];
        for (int b = 0; b < 4; b++)
            temp[b] = w[i - 1][b];

        if (i % 8 == 0) {
            /* RotWord + SubWord + Rcon XOR */
            gf8_wire_id rot[4];
            rot_word_gf8(temp, rot);
            gf8_wire_id sw[4];
            sub_word_gf8(c, rot, sw);
            sw[0] = voleith_gf8_add_xor_const(c, sw[0], RCON256[i / 8 - 1]);
            for (int b = 0; b < 4; b++)
                temp[b] = sw[b];
        } else if (i % 8 == 4) {
            /* SubWord only */
            gf8_wire_id sw[4];
            sub_word_gf8(c, temp, sw);
            for (int b = 0; b < 4; b++)
                temp[b] = sw[b];
        }

        for (int b = 0; b < 4; b++)
            w[i][b] = voleith_gf8_add_xor(c, w[i - 8][b], temp[b]);
    }

    /* Extract 15 round keys from the 60 words. */
    for (int n = 0; n < 15; n++)
        for (int word = 0; word < 4; word++)
            for (int b = 0; b < 4; b++)
                rk[n][4 * word + b] = w[4 * n + word][b];
}

/* ================================================================
 * Public API: AES-256 circuit
 * ================================================================ */

void
aes256_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[32],
                   const gf8_wire_id plaintext[16], gf8_wire_id output[16])
{
    gf8_wire_id rk[15][16];
    aes256_gf8_key_schedule(c, key, rk);

    aes_gf8_state state;
    for (int k = 0; k < 16; k++)
        state[k] = plaintext[k];

    add_round_key_gf8(c, state, rk[0]);

    for (int round = 1; round <= 13; round++) {
        sub_bytes_gf8(c, state);
        shift_rows_gf8(state);
        mix_columns_gf8(c, state);
        add_round_key_gf8(c, state, rk[round]);
    }

    /* Round 14: no MixColumns. */
    sub_bytes_gf8(c, state);
    shift_rows_gf8(state);
    add_round_key_gf8(c, state, rk[14]);

    for (int k = 0; k < 16; k++)
        output[k] = state[k];
}

/* ================================================================
 * Witness builders - byte-level AES trace to produce inv_in values
 * ================================================================ */

/* Compute GF(2⁸) inverse: brute-force scan (acceptable for setup, not hot path). */
static uint8_t
gf8_inv_byte(uint8_t x)
{
    if (x == 0)
        return 0;
    for (int y = 1; y < 256; y++) {
        if (voleith_gf8_mul(x, (uint8_t)y) == 1)
            return (uint8_t)y;
    }
    return 0; /* unreachable for nonzero x in GF(2⁸) */
}

/* AES S-box byte computation: affine(inv(x)) XOR 0x63. */
static uint8_t
aes_sbox_byte(uint8_t x)
{
    uint8_t t = gf8_inv_byte(x);
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t masked = AES_GF8_AFFINE_MATRIX[i] & t;
        masked ^= masked >> 4;
        masked ^= masked >> 2;
        masked ^= masked >> 1;
        result |= (uint8_t)((masked & 1u) << i);
    }
    return result ^ 0x63;
}

/* xtime: multiply byte by 2 in GF(2⁸). */
static uint8_t
xtime_byte(uint8_t a)
{
    return (uint8_t)((a << 1) ^ (a & 0x80 ? 0x1B : 0));
}

/* MixColumns for one column at byte level. */
static void
mix_column_bytes(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3, uint8_t *b0,
                 uint8_t *b1, uint8_t *b2, uint8_t *b3)
{
    uint8_t x0 = xtime_byte(a0), x1 = xtime_byte(a1);
    uint8_t x2 = xtime_byte(a2), x3 = xtime_byte(a3);
    *b0 = x0 ^ (x1 ^ a1) ^ a2 ^ a3;
    *b1 = a0 ^ x1 ^ (x2 ^ a2) ^ a3;
    *b2 = a0 ^ a1 ^ x2 ^ (x3 ^ a3);
    *b3 = (x0 ^ a0) ^ a1 ^ a2 ^ x3;
}

/* ShiftRows for byte array state[16]. */
static void
shift_rows_bytes(uint8_t state[16])
{
    uint8_t tmp[16];
    for (int k = 0; k < 16; k++)
        tmp[k] = state[SHIFTROWS_PERM[k]];
    memcpy(state, tmp, 16);
}

/* MixColumns for byte array state[16]. */
static void
mix_columns_bytes(uint8_t state[16])
{
    for (int col = 0; col < 4; col++) {
        uint8_t b0, b1, b2, b3;
        mix_column_bytes(state[4 * col + 0], state[4 * col + 1],
                         state[4 * col + 2], state[4 * col + 3], &b0, &b1, &b2,
                         &b3);
        state[4 * col + 0] = b0;
        state[4 * col + 1] = b1;
        state[4 * col + 2] = b2;
        state[4 * col + 3] = b3;
    }
}

void
aes128_gf8_build_witness(const uint8_t key[16], const uint8_t plaintext[16],
                         uint8_t witness[216], uint8_t ciphertext[16])
{
    /* witness[0..15] = key bytes */
    memcpy(witness, key, 16);
    uint8_t *inv_slot = witness + 16;

    /* Byte-level key schedule: track w[0..3] as 4×4 bytes. */
    uint8_t w[4][4];
    for (int word = 0; word < 4; word++)
        memcpy(w[word], key + 4 * word, 4);

    /* Round keys (for data path trace). */
    uint8_t rk[11][16];
    memcpy(rk[0], key, 16);

    for (int round = 1; round <= 10; round++) {
        /* RotWord(w[3]) */
        uint8_t rot[4] = {w[3][1], w[3][2], w[3][3], w[3][0]};

        /* SubWord: record inv_in in circuit evaluation order (b=0,1,2,3). */
        uint8_t sw[4];
        for (int b = 0; b < 4; b++) {
            *inv_slot++ = gf8_inv_byte(rot[b]);
            sw[b] = aes_sbox_byte(rot[b]);
        }

        /* XOR Rcon into byte 0. */
        sw[0] ^= RCON128[round - 1];

        /* Expand words. */
        uint8_t new_w[4][4];
        for (int b = 0; b < 4; b++)
            new_w[0][b] = w[0][b] ^ sw[b];
        for (int word = 1; word < 4; word++)
            for (int b = 0; b < 4; b++)
                new_w[word][b] = w[word][b] ^ new_w[word - 1][b];

        for (int word = 0; word < 4; word++) {
            memcpy(w[word], new_w[word], 4);
            memcpy(rk[round] + 4 * word, new_w[word], 4);
        }
    }

    /* Data path: trace state, recording inv_in for each S-box in order. */
    uint8_t state[16];
    for (int k = 0; k < 16; k++)
        state[k] = plaintext[k] ^ rk[0][k];

    for (int round = 1; round <= 9; round++) {
        /* SubBytes: record inv_in for k=0..15 in order. */
        for (int k = 0; k < 16; k++) {
            *inv_slot++ = gf8_inv_byte(state[k]);
            state[k] = aes_sbox_byte(state[k]);
        }
        shift_rows_bytes(state);
        mix_columns_bytes(state);
        for (int k = 0; k < 16; k++)
            state[k] ^= rk[round][k];
    }

    /* Round 10: SubBytes + ShiftRows + AddRoundKey (no MixColumns). */
    for (int k = 0; k < 16; k++) {
        *inv_slot++ = gf8_inv_byte(state[k]);
        state[k] = aes_sbox_byte(state[k]);
    }
    shift_rows_bytes(state);
    for (int k = 0; k < 16; k++)
        state[k] ^= rk[10][k];

    if (ciphertext)
        memcpy(ciphertext, state, 16);

    /* CIR-11: clear key-schedule working state and per-block running
     * state.  `w` holds expanded key-schedule words; `rk` is the full
     * round-key table; `state` is the AES data path mid-encrypt. */
    voleith_secure_zero(w, sizeof(w));
    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(state, sizeof(state));
}

void
aes256_gf8_build_witness(const uint8_t key[32], const uint8_t plaintext[16],
                         uint8_t witness[308], uint8_t ciphertext[16])
{
    /* witness[0..31] = key bytes */
    memcpy(witness, key, 32);
    uint8_t *inv_slot = witness + 32;

    /* All 60 key-schedule words. */
    uint8_t w[60][4];
    for (int word = 0; word < 8; word++)
        memcpy(w[word], key + 4 * word, 4);

    uint8_t rk[15][16];

    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, w[i - 1], 4);

        if (i % 8 == 0) {
            uint8_t rot[4] = {temp[1], temp[2], temp[3], temp[0]};
            uint8_t sw[4];
            for (int b = 0; b < 4; b++) {
                *inv_slot++ = gf8_inv_byte(rot[b]);
                sw[b] = aes_sbox_byte(rot[b]);
            }
            sw[0] ^= RCON256[i / 8 - 1];
            memcpy(temp, sw, 4);
        } else if (i % 8 == 4) {
            uint8_t sw[4];
            for (int b = 0; b < 4; b++) {
                *inv_slot++ = gf8_inv_byte(temp[b]);
                sw[b] = aes_sbox_byte(temp[b]);
            }
            memcpy(temp, sw, 4);
        }

        for (int b = 0; b < 4; b++)
            w[i][b] = w[i - 8][b] ^ temp[b];
    }

    /* Build round key table from w. */
    for (int n = 0; n < 15; n++)
        for (int word = 0; word < 4; word++)
            memcpy(rk[n] + 4 * word, w[4 * n + word], 4);

    /* Data path. */
    uint8_t state[16];
    for (int k = 0; k < 16; k++)
        state[k] = plaintext[k] ^ rk[0][k];

    for (int round = 1; round <= 13; round++) {
        for (int k = 0; k < 16; k++) {
            *inv_slot++ = gf8_inv_byte(state[k]);
            state[k] = aes_sbox_byte(state[k]);
        }
        shift_rows_bytes(state);
        mix_columns_bytes(state);
        for (int k = 0; k < 16; k++)
            state[k] ^= rk[round][k];
    }

    /* Round 14: no MixColumns. */
    for (int k = 0; k < 16; k++) {
        *inv_slot++ = gf8_inv_byte(state[k]);
        state[k] = aes_sbox_byte(state[k]);
    }
    shift_rows_bytes(state);
    for (int k = 0; k < 16; k++)
        state[k] ^= rk[14][k];

    if (ciphertext)
        memcpy(ciphertext, state, 16);

    /* CIR-11: same cleanup as the AES-128 variant. */
    voleith_secure_zero(w, sizeof(w));
    voleith_secure_zero(rk, sizeof(rk));
    voleith_secure_zero(state, sizeof(state));
}
