/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_norm_gf8_circuit.c - AES-128/256 GF(2^8) element circuits with the FAEST
 * paired-round norm S-box.  See aes_norm_gf8_circuit.h.
 */

#include "aes_norm_gf8_circuit.h"

#include "aes_gf8_circuit.h" /* frozen key schedule + AES_GF8_AFFINE_MATRIX */
#include "../core/field.h"
#include "../core/util.h"

#include <string.h>

/* ================================================================
 * Shared constants / free linear helpers (wire level)
 * ================================================================ */

/* xtime (multiply by 0x02) as an 8x8 GF(2) matrix, row-major. */
static const uint8_t NORM_XTIME[8] = {0x80, 0x81, 0x02, 0x84,
                                      0x88, 0x10, 0x20, 0x40};

/* ShiftRows: new[k] = old[SRP[k]] (column-major state). */
static const unsigned int NORM_SRP[16] = {0, 5,  10, 15, 4,  9, 14, 3,
                                          8, 13, 2,  7,  12, 1, 6,  11};

/* MixColumns on 16 state wires (free: linear maps + XOR), matching
 * aes_gf8_circuit.c::mix_columns_gf8. */
static void
norm_mix_columns(voleith_gf8_circuit_t *c, gf8_wire_id s[16])
{
    for (int col = 0; col < 4; col++) {
        gf8_wire_id a0 = s[4 * col], a1 = s[4 * col + 1], a2 = s[4 * col + 2],
                    a3 = s[4 * col + 3];
        gf8_wire_id x0 = voleith_gf8_add_linear_map(c, a0, NORM_XTIME);
        gf8_wire_id x1 = voleith_gf8_add_linear_map(c, a1, NORM_XTIME);
        gf8_wire_id x2 = voleith_gf8_add_linear_map(c, a2, NORM_XTIME);
        gf8_wire_id x3 = voleith_gf8_add_linear_map(c, a3, NORM_XTIME);
        gf8_wire_id t0 = voleith_gf8_add_xor(c, x0, a0); /* 3*a0 */
        gf8_wire_id t1 = voleith_gf8_add_xor(c, x1, a1);
        gf8_wire_id t2 = voleith_gf8_add_xor(c, x2, a2);
        gf8_wire_id t3 = voleith_gf8_add_xor(c, x3, a3);
        gf8_wire_id tmp;
        tmp = voleith_gf8_add_xor(c, x0, t1);
        tmp = voleith_gf8_add_xor(c, tmp, a2);
        s[4 * col + 0] = voleith_gf8_add_xor(c, tmp, a3);
        tmp = voleith_gf8_add_xor(c, a0, x1);
        tmp = voleith_gf8_add_xor(c, tmp, t2);
        s[4 * col + 1] = voleith_gf8_add_xor(c, tmp, a3);
        tmp = voleith_gf8_add_xor(c, a0, a1);
        tmp = voleith_gf8_add_xor(c, tmp, x2);
        s[4 * col + 2] = voleith_gf8_add_xor(c, tmp, t3);
        tmp = voleith_gf8_add_xor(c, t0, a1);
        tmp = voleith_gf8_add_xor(c, tmp, a2);
        s[4 * col + 3] = voleith_gf8_add_xor(c, tmp, x3);
    }
}

/* ================================================================
 * Shared circuit core: norm data path over npairs round-pairs
 * ================================================================ */

static void
norm_encrypt(voleith_gf8_circuit_t *c, const gf8_wire_id (*rk)[16],
             unsigned int npairs, const gf8_wire_id plaintext[16],
             gf8_wire_id output[16])
{
    gf8_wire_id state[16];
    for (int i = 0; i < 16; i++)
        state[i] = voleith_gf8_add_xor(c, plaintext[i], rk[0][i]); /* +rk[0] */

    for (unsigned int r = 0; r < npairs; r++) {
        /* Commit 8 packed norm bytes, extract/embed 16 norms, PRODUCT3. */
        gf8_wire_id packed[8], cw[16];
        for (int j = 0; j < 8; j++)
            packed[j] = voleith_gf8_add_witness(c);
        for (int i = 0; i < 16; i++) {
            gf8_wire_id nib =
                voleith_gf8_add_nibble(c, packed[i / 2], (unsigned)i % 2);
            cw[i] = voleith_gf8_add_norm_embed(c, nib);
            gf8_wire_id a2 = voleith_gf8_add_square(c, state[i]);
            gf8_wire_id a4 = voleith_gf8_add_square(c, a2);
            gf8_wire_id a8 = voleith_gf8_add_square(c, a4);
            gf8_wire_id a16 = voleith_gf8_add_square(c, a8);
            voleith_gf8_assert_product3(c, cw[i], a2, a16, state[i]);
        }
        /* Commit the odd-round reset state s_tilde. */
        gf8_wire_id st[16];
        for (int i = 0; i < 16; i++)
            st[i] = voleith_gf8_add_witness(c);

        int last = (r == npairs - 1);
        voleith_gf8_assert_aes_norm_roundpair(c, state, cw, st, rk[2 * r + 1],
                                              16, last);

        if (!last) {
            /* next state = MixColumns(s_tilde) XOR rk[2r+2]. */
            gf8_wire_id mc[16];
            for (int i = 0; i < 16; i++)
                mc[i] = st[i];
            norm_mix_columns(c, mc);
            for (int i = 0; i < 16; i++)
                state[i] = voleith_gf8_add_xor(c, mc[i], rk[2 * r + 2][i]);
        } else {
            /* ciphertext = s_tilde XOR rk[2*npairs] (last round, no MixCols). */
            for (int i = 0; i < 16; i++)
                output[i] = voleith_gf8_add_xor(c, st[i], rk[2 * npairs][i]);
        }
    }
}

void
aes128_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[16],
                        const gf8_wire_id plaintext[16], gf8_wire_id output[16])
{
    gf8_wire_id rk[11][16];
    aes128_gf8_expand_key(c, key, rk); /* frozen 8-bit key schedule */
    norm_encrypt(c, rk, 5, plaintext, output);
}

void
aes256_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id key[32],
                        const gf8_wire_id plaintext[16], gf8_wire_id output[16])
{
    gf8_wire_id rk[15][16];
    aes256_gf8_expand_key(c, key, rk); /* frozen 8-bit key schedule */
    norm_encrypt(c, rk, 7, plaintext, output);
}

void
aes128_norm_gf8_encrypt_rk(voleith_gf8_circuit_t *c,
                           const gf8_wire_id rk[11][16],
                           const gf8_wire_id plaintext[16],
                           gf8_wire_id output[16])
{
    norm_encrypt(c, rk, 5, plaintext, output);
}

void
aes256_norm_gf8_encrypt_rk(voleith_gf8_circuit_t *c,
                           const gf8_wire_id rk[15][16],
                           const gf8_wire_id plaintext[16],
                           gf8_wire_id output[16])
{
    norm_encrypt(c, rk, 7, plaintext, output);
}

/* ================================================================
 * Byte-level reference (for the witness builder)
 * ================================================================ */

static uint8_t
nb_inv(uint8_t a)
{
    uint8_t r = 1;
    if (a == 0)
        return 0;
    for (int i = 0; i < 254; i++)
        r = voleith_gf8_mul(r, a);
    return r;
}

static uint8_t
nb_aff_lin(uint8_t z)
{
    uint8_t o = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t m = (uint8_t)(AES_GF8_AFFINE_MATRIX[i] & z);
        int p = 0;
        for (int j = 0; j < 8; j++)
            p ^= (m >> j) & 1;
        o |= (uint8_t)((p & 1) << i);
    }
    return o;
}

static uint8_t
nb_sbox(uint8_t a)
{
    return (uint8_t)(nb_aff_lin(nb_inv(a)) ^ 0x63);
}

/* norm nibble: 4-bit code of a^-17 in the GF(2^4) basis {0x01,0x50,0xb0,0x0c}. */
static uint8_t
nb_norm_nibble(uint8_t a)
{
    static const uint8_t B[4] = {0x01, 0x50, 0xb0, 0x0c};
    uint8_t c = nb_inv(a); /* a^-1 */
    uint8_t cc = c;
    for (int i = 0; i < 4; i++) /* c^17 = c * c^16 */
        cc = voleith_gf8_mul(cc, cc);
    cc = voleith_gf8_mul(cc, c); /* (a^-1)^17 = a^-17 */
    for (unsigned int n = 0; n < 16; n++) {
        uint8_t v = 0;
        for (int k = 0; k < 4; k++)
            if (n & (1u << k))
                v ^= B[k];
        if (v == cc)
            return (uint8_t)n;
    }
    return 0; /* a == 0: norm 0 */
}

static void
nb_shiftrows(uint8_t out[16], const uint8_t in[16])
{
    for (int k = 0; k < 16; k++)
        out[k] = in[NORM_SRP[k]];
}

static void
nb_mixcolumns(uint8_t s[16])
{
    for (int col = 0; col < 4; col++) {
        uint8_t a0 = s[4 * col], a1 = s[4 * col + 1], a2 = s[4 * col + 2],
                a3 = s[4 * col + 3];
        s[4 * col] = (uint8_t)(voleith_gf8_mul(2, a0) ^ voleith_gf8_mul(3, a1) ^
                               a2 ^ a3);
        s[4 * col + 1] = (uint8_t)(a0 ^ voleith_gf8_mul(2, a1) ^
                                   voleith_gf8_mul(3, a2) ^ a3);
        s[4 * col + 2] = (uint8_t)(a0 ^ a1 ^ voleith_gf8_mul(2, a2) ^
                                   voleith_gf8_mul(3, a3));
        s[4 * col + 3] = (uint8_t)(voleith_gf8_mul(3, a0) ^ a1 ^ a2 ^
                                   voleith_gf8_mul(2, a3));
    }
}

/* Trace the norm data path, writing per-pair [8 packed norms || 16 s_tilde]
 * into w_out and (optionally) the ciphertext. */
static void
norm_witness(const uint8_t (*rk)[16], unsigned int npairs,
             const uint8_t plaintext[16], uint8_t *w_out,
             uint8_t ciphertext[16])
{
    uint8_t state[16];
    for (int i = 0; i < 16; i++)
        state[i] = (uint8_t)(plaintext[i] ^ rk[0][i]);

    for (unsigned int r = 0; r < npairs; r++) {
        uint8_t nib[16], so[16], sr[16], even_out[16], so2[16], s_tilde[16];
        for (int i = 0; i < 16; i++)
            nib[i] = nb_norm_nibble(state[i]);
        for (int j = 0; j < 8; j++)
            *w_out++ = (uint8_t)(nib[2 * j] | (nib[2 * j + 1] << 4));

        for (int i = 0; i < 16; i++)
            so[i] = nb_sbox(state[i]);
        nb_shiftrows(sr, so);
        nb_mixcolumns(sr);
        for (int i = 0; i < 16; i++)
            even_out[i] = (uint8_t)(sr[i] ^ rk[2 * r + 1][i]);

        for (int i = 0; i < 16; i++)
            so2[i] = nb_sbox(even_out[i]);
        nb_shiftrows(s_tilde, so2);
        memcpy(w_out, s_tilde, 16);
        w_out += 16;

        if (r + 1 < npairs) {
            uint8_t mc[16];
            memcpy(mc, s_tilde, 16);
            nb_mixcolumns(mc);
            for (int i = 0; i < 16; i++)
                state[i] = (uint8_t)(mc[i] ^ rk[2 * r + 2][i]);
        } else if (ciphertext) {
            for (int i = 0; i < 16; i++)
                ciphertext[i] = (uint8_t)(s_tilde[i] ^ rk[2 * npairs][i]);
        }
    }
    voleith_secure_zero(state, sizeof(state));
}

void
aes_norm_gf8_solve_pair(const uint8_t state_in[16], const uint8_t k0[16],
                        uint8_t packed_out[8], uint8_t s_tilde_out[16])
{
    uint8_t so[16], sr[16], even_out[16], so2[16];
    int i;

    /* Packed norms of the even-round input state. */
    for (i = 0; i < 8; i++)
        packed_out[i] = (uint8_t)(nb_norm_nibble(state_in[2 * i]) |
                                  (nb_norm_nibble(state_in[2 * i + 1]) << 4));

    /* Even round: SubBytes, ShiftRows, MixColumns, AddRoundKey(k0). */
    for (i = 0; i < 16; i++)
        so[i] = nb_sbox(state_in[i]);
    nb_shiftrows(sr, so);
    nb_mixcolumns(sr);
    for (i = 0; i < 16; i++)
        even_out[i] = (uint8_t)(sr[i] ^ k0[i]);

    /* Odd round: SubBytes, ShiftRows => committed reset state s_tilde. */
    for (i = 0; i < 16; i++)
        so2[i] = nb_sbox(even_out[i]);
    nb_shiftrows(s_tilde_out, so2);
}

void
aes128_norm_gf8_build_witness(const uint8_t key[16],
                              const uint8_t plaintext[16],
                              uint8_t witness[AES128_NORM_GF8_WITNESS_BYTES],
                              uint8_t ciphertext[16])
{
    uint8_t rk[11][16];
    memcpy(witness, key, 16);
    aes128_gf8_expand_key_witness(key, witness + 16, rk);
    norm_witness((const uint8_t(*)[16])rk, 5, plaintext,
                 witness + 16 + AES128_GF8_KS_INVIN_BYTES, ciphertext);
    voleith_secure_zero(rk, sizeof(rk));
}

void
aes256_norm_gf8_build_witness(const uint8_t key[32],
                              const uint8_t plaintext[16],
                              uint8_t witness[AES256_NORM_GF8_WITNESS_BYTES],
                              uint8_t ciphertext[16])
{
    uint8_t rk[15][16];
    memcpy(witness, key, 32);
    aes256_gf8_expand_key_witness(key, witness + 32, rk);
    norm_witness((const uint8_t(*)[16])rk, 7, plaintext,
                 witness + 32 + AES256_GF8_KS_INVIN_BYTES, ciphertext);
    voleith_secure_zero(rk, sizeof(rk));
}

void
aes128_norm_gf8_encrypt_rk_witness(
    const uint8_t rk[11][16], const uint8_t plaintext[16],
    uint8_t inv_out[AES128_NORM_GF8_ENC_INVIN_BYTES], uint8_t ciphertext[16])
{
    norm_witness(rk, 5, plaintext, inv_out, ciphertext);
}

void
aes256_norm_gf8_encrypt_rk_witness(
    const uint8_t rk[15][16], const uint8_t plaintext[16],
    uint8_t inv_out[AES256_NORM_GF8_ENC_INVIN_BYTES], uint8_t ciphertext[16])
{
    norm_witness(rk, 7, plaintext, inv_out, ciphertext);
}
