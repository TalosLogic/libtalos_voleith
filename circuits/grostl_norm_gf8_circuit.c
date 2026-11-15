/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl_norm_gf8_circuit.c - Grostl-256 and Grostl-512 as GF(2^8) element
 * circuits with the FAEST paired-round norm S-box.  See
 * grostl_norm_gf8_circuit.h.
 *
 * Each permutation round is ARC -> SubBytes -> ShiftBytes -> MixBytes (spec
 * §3.4).  The norm form groups the rounds in pairs: the even round commits
 * packed 4-bit subfield norms (c = a^-17) for its SubBytes input, the odd
 * round commits the full post-SubBytes/ShiftBytes reset state s_tilde (which
 * resets the constraint degree), and one
 * voleith_gf8_assert_grostl_norm_roundpair handles the two inversions plus the
 * ShiftBytes/MixBytes/odd-ARC between them.  The even-round AddRoundConstant
 * folds in as a free XOR before the gadget; the odd-round MixBytes closes the
 * pair afterward and feeds the next pair.  Every pair, including the last, is
 * followed by MixBytes: Grostl permutations always end with a full round, so
 * there is no AES-style last-round special case.
 *
 * The linear layer and all byte-level structural helpers are shared verbatim
 * with the frozen circuit through grostl_gf8_internal.h.  Only the norm nibble
 * (the sole genuinely norm-specific byte helper) is local, mirroring how the
 * AES norm circuit keeps its own byte reference trace.
 */

#include "grostl_norm_gf8_circuit.h"

#include "grostl_gf8_internal.h" /* shared Grostl constants + linear layer */
#include "../proof/gf8_grostl_norm_const.h" /* grostl_norm_round_const, MAX_STATE */
#include "../core/field.h"
#include "../core/util.h"

#include <string.h>

/* Round pairs per permutation: 10 rounds -> 5 (Grostl-256), 14 -> 7 (-512). */
#define NPAIRS_256 (ROUNDS_256 / 2)
#define NPAIRS_512 (ROUNDS_512 / 2)

/* ================================================================
 * Wire-side norm data path.
 * ================================================================ */

/* One permutation (P or Q) in norm form over `npairs` round-pairs. */
static void
permute_norm_wires(voleith_gf8_circuit_t *c, gf8_wire_id *state, int columns,
                   int npairs, const uint8_t shift[ROWS], int is_q)
{
    unsigned int nst = (unsigned int)(ROWS * columns);

    for (int k = 0; k < npairs; k++) {
        uint8_t rc[GROSTL_NORM_MAX_STATE];
        gf8_wire_id a[GROSTL_NORM_MAX_STATE];
        gf8_wire_id packed[GROSTL_NORM_MAX_STATE / 2];
        gf8_wire_id cw[GROSTL_NORM_MAX_STATE];
        gf8_wire_id st[GROSTL_NORM_MAX_STATE];

        /* Even-round AddRoundConstant folds in as a free XOR. */
        grostl_norm_round_const(is_q, (unsigned int)columns, (uint8_t)(2 * k),
                                rc);
        for (unsigned int i = 0; i < nst; i++)
            a[i] = rc[i] ? voleith_gf8_add_xor_const(c, state[i], rc[i])
                         : state[i];

        /* Commit packed norms and the per-byte relation c * a^2 * a^16 = a. */
        for (unsigned int j = 0; j < nst / 2; j++)
            packed[j] = voleith_gf8_add_witness(c);
        for (unsigned int i = 0; i < nst; i++) {
            gf8_wire_id nib = voleith_gf8_add_nibble(c, packed[i / 2], i % 2);
            cw[i] = voleith_gf8_add_norm_embed(c, nib);
            gf8_wire_id a2 = voleith_gf8_add_square(c, a[i]);
            gf8_wire_id a4 = voleith_gf8_add_square(c, a2);
            gf8_wire_id a8 = voleith_gf8_add_square(c, a4);
            gf8_wire_id a16 = voleith_gf8_add_square(c, a8);
            voleith_gf8_assert_product3(c, cw[i], a2, a16, a[i]);
        }

        /* Commit the odd-round reset state s_tilde. */
        for (unsigned int i = 0; i < nst; i++)
            st[i] = voleith_gf8_add_witness(c);

        voleith_gf8_assert_grostl_norm_roundpair(
            c, a, cw, st, nst, (unsigned int)columns, shift, is_q,
            (unsigned int)(2 * k + 1));

        /* Odd-round MixBytes closes the pair; its output is the next state. */
        for (unsigned int i = 0; i < nst; i++)
            state[i] = st[i];
        mix_bytes_wires(c, state, columns);
    }
}

/* ================================================================
 * Compression and output transform (same shape as the frozen circuit).
 *
 * f(h, m) = P(h XOR m) XOR Q(m) XOR h   (spec §3.2)
 * Omega(h) = trunc_n(P(h) XOR h)         (spec §3.3)
 * ================================================================ */

static void
compress_norm_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h,
                    const gf8_wire_id *m, int columns, int npairs,
                    const uint8_t shift_p[ROWS], const uint8_t shift_q[ROWS])
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id p_in[STATE_BYTES_512];
    gf8_wire_id q_in[STATE_BYTES_512];

    for (size_t i = 0; i < n; i++) {
        p_in[i] = voleith_gf8_add_xor(c, h[i], m[i]);
        q_in[i] = m[i];
    }

    permute_norm_wires(c, p_in, columns, npairs, shift_p, 0);
    permute_norm_wires(c, q_in, columns, npairs, shift_q, 1);

    for (size_t i = 0; i < n; i++) {
        gf8_wire_id pq = voleith_gf8_add_xor(c, p_in[i], q_in[i]);
        h[i] = voleith_gf8_add_xor(c, h[i], pq);
    }
}

static void
output_transform_norm_wires(voleith_gf8_circuit_t *c, gf8_wire_id *h,
                            int columns, int npairs,
                            const uint8_t shift_p[ROWS])
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id temp[STATE_BYTES_512];

    for (size_t i = 0; i < n; i++)
        temp[i] = h[i];

    permute_norm_wires(c, temp, columns, npairs, shift_p, 0);

    for (size_t i = 0; i < n; i++)
        h[i] = voleith_gf8_add_xor(c, h[i], temp[i]);
}

/* ================================================================
 * Public API: full-hash circuit builders.
 * ================================================================ */

void
grostl256_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                           size_t msg_bytes, gf8_wire_id out[32])
{
    gf8_wire_id h[STATE_BYTES_256];
    init_iv_256_wires(c, h);

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    gf8_wire_id block[STATE_BYTES_256];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block(c, msg, msg_bytes, bi, n_blocks, STATE_BYTES_256,
                           block);
        compress_norm_wires(c, h, block, COLS_256, NPAIRS_256, SHIFT_P512,
                            SHIFT_Q512);
    }

    output_transform_norm_wires(c, h, COLS_256, NPAIRS_256, SHIFT_P512);

    for (size_t i = 0; i < 32; i++)
        out[i] = h[STATE_BYTES_256 - 32 + i];
}

void
grostl512_norm_gf8_circuit(voleith_gf8_circuit_t *c, const gf8_wire_id *msg,
                           size_t msg_bytes, gf8_wire_id out[64])
{
    gf8_wire_id h[STATE_BYTES_512];
    init_iv_512_wires(c, h);

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    gf8_wire_id block[STATE_BYTES_512];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block(c, msg, msg_bytes, bi, n_blocks, STATE_BYTES_512,
                           block);
        compress_norm_wires(c, h, block, COLS_512, NPAIRS_512, SHIFT_P1024,
                            SHIFT_Q1024);
    }

    output_transform_norm_wires(c, h, COLS_512, NPAIRS_512, SHIFT_P1024);

    for (size_t i = 0; i < 64; i++)
        out[i] = h[STATE_BYTES_512 - 64 + i];
}

/* ================================================================
 * Fixed-input node circuits (single- and multi-block).  Same structure as
 * the frozen node circuits, with the norm compression / output transform.
 * ================================================================ */

static void
grostl_norm_node_impl(voleith_gf8_circuit_t *c, const uint8_t *iv,
                      const gf8_wire_id *blocks, size_t n_blocks, int columns,
                      int npairs, const uint8_t shift_p[ROWS],
                      const uint8_t shift_q[ROWS], size_t out_bytes,
                      gf8_wire_id *out)
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id h[STATE_BYTES_512];

    /* iv is public structural data: constant wires, zero VOLE slots. */
    for (size_t i = 0; i < n; i++)
        h[i] = voleith_gf8_add_const(c, iv[i]);

    for (size_t bi = 0; bi < n_blocks; bi++)
        compress_norm_wires(c, h, blocks + bi * n, columns, npairs, shift_p,
                            shift_q);

    output_transform_norm_wires(c, h, columns, npairs, shift_p);

    for (size_t i = 0; i < out_bytes; i++)
        out[i] = h[n - out_bytes + i];
}

void
grostl256_norm_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                                const gf8_wire_id block[64],
                                gf8_wire_id out[32])
{
    grostl_norm_node_impl(c, iv, block, 1, COLS_256, NPAIRS_256, SHIFT_P512,
                          SHIFT_Q512, 32, out);
}

void
grostl512_norm_gf8_node_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[128],
                                const gf8_wire_id block[128],
                                gf8_wire_id out[64])
{
    grostl_norm_node_impl(c, iv, block, 1, COLS_512, NPAIRS_512, SHIFT_P1024,
                          SHIFT_Q1024, 64, out);
}

void
grostl256_norm_gf8_node2_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                                 const gf8_wire_id block[128],
                                 gf8_wire_id out[32])
{
    grostl_norm_node_impl(c, iv, block, 2, COLS_256, NPAIRS_256, SHIFT_P512,
                          SHIFT_Q512, 32, out);
}

void
grostl512_norm_gf8_node2_circuit(voleith_gf8_circuit_t *c,
                                 const uint8_t iv[128],
                                 const gf8_wire_id block[256],
                                 gf8_wire_id out[64])
{
    grostl_norm_node_impl(c, iv, block, 2, COLS_512, NPAIRS_512, SHIFT_P1024,
                          SHIFT_Q1024, 64, out);
}

void
grostl256_norm_gf8_nodeN_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                                 const gf8_wire_id *blocks, size_t n_blocks,
                                 gf8_wire_id out[32])
{
    grostl_norm_node_impl(c, iv, blocks, n_blocks, COLS_256, NPAIRS_256,
                          SHIFT_P512, SHIFT_Q512, 32, out);
}

/* ================================================================
 * Byte-level reference trace (for the witness builders).  Reuses the shared
 * byte helpers (aes_sbox_byte, shift_bytes_bytes, mix_bytes_bytes) from
 * grostl_gf8_internal.h; only the norm nibble is norm-specific.
 * ================================================================ */

/* 4-bit code of a^-17 in the GF(2^4) norm basis {0x01,0x50,0xb0,0x0c}
 * (matching voleith_gf8_add_norm_embed; a == 0 maps to nibble 0). */
static uint8_t
norm_nibble_byte(uint8_t a)
{
    static const uint8_t B[4] = {0x01, 0x50, 0xb0, 0x0c};
    uint8_t cc = voleith_gf8_inv(a); /* a^-1 (0 if a == 0) */
    uint8_t c17 = cc;
    for (int i = 0; i < 4; i++) /* c^16 */
        c17 = voleith_gf8_mul(c17, c17);
    c17 = voleith_gf8_mul(c17, cc); /* (a^-1)^17 = a^-17 */
    for (unsigned int n = 0; n < 16; n++) {
        uint8_t v = 0;
        for (int k = 0; k < 4; k++)
            if (n & (1u << k))
                v ^= B[k];
        if (v == c17)
            return (uint8_t)n;
    }
    return 0;
}

/* One permutation (P or Q) traced over `npairs` round-pairs, appending the
 * per-pair [nst/2 packed norms || nst s_tilde] bytes to *w. */
static void
permute_norm_bytes_capture(uint8_t *state, int columns, int npairs,
                           const uint8_t shift[ROWS], int is_q, uint8_t **w)
{
    unsigned int nst = (unsigned int)(ROWS * columns);

    for (int k = 0; k < npairs; k++) {
        uint8_t rc[GROSTL_NORM_MAX_STATE];
        uint8_t a[GROSTL_NORM_MAX_STATE];
        uint8_t tmp[GROSTL_NORM_MAX_STATE];

        /* Even-round AddRoundConstant => even SubBytes input. */
        grostl_norm_round_const(is_q, (unsigned int)columns, (uint8_t)(2 * k),
                                rc);
        for (unsigned int i = 0; i < nst; i++)
            a[i] = (uint8_t)(state[i] ^ rc[i]);

        /* Packed norms of the even-round input. */
        for (unsigned int j = 0; j < nst / 2; j++)
            *(*w)++ = (uint8_t)(norm_nibble_byte(a[2 * j]) |
                                (norm_nibble_byte(a[2 * j + 1]) << 4));

        /* Even round: SubBytes, ShiftBytes, MixBytes. */
        for (unsigned int i = 0; i < nst; i++)
            tmp[i] = aes_sbox_byte(a[i]);
        shift_bytes_bytes(tmp, columns, shift);
        mix_bytes_bytes(tmp, columns);

        /* Odd-round AddRoundConstant => odd SubBytes input. */
        grostl_norm_round_const(is_q, (unsigned int)columns,
                                (uint8_t)(2 * k + 1), rc);
        for (unsigned int i = 0; i < nst; i++)
            tmp[i] = (uint8_t)(tmp[i] ^ rc[i]);

        /* Odd round: SubBytes, ShiftBytes => committed reset state s_tilde. */
        for (unsigned int i = 0; i < nst; i++)
            tmp[i] = aes_sbox_byte(tmp[i]);
        shift_bytes_bytes(tmp, columns, shift);
        memcpy(*w, tmp, nst);
        *w += nst;

        /* Odd-round MixBytes closes the pair -> next state. */
        mix_bytes_bytes(tmp, columns);
        memcpy(state, tmp, nst);

        voleith_secure_zero(a, sizeof(a));
    }
}

void
grostl_norm_gf8_solve_pair(const uint8_t *state_in, unsigned int nst,
                           unsigned int cols, const uint8_t shift[ROWS],
                           int is_q, unsigned int odd_round,
                           uint8_t *packed_out, uint8_t *s_tilde_out)
{
    uint8_t rc[GROSTL_NORM_MAX_STATE];
    uint8_t tmp[GROSTL_NORM_MAX_STATE];
    unsigned int i, j;

    /* state_in is the even-round SubBytes input (state XOR even ARC), i.e. the
     * gadget's state_in pool wires; packed norms are taken directly from it. */
    for (j = 0; j < nst / 2; j++)
        packed_out[j] = (uint8_t)(norm_nibble_byte(state_in[2 * j]) |
                                  (norm_nibble_byte(state_in[2 * j + 1]) << 4));

    /* Even round: SubBytes, ShiftBytes, MixBytes. */
    for (i = 0; i < nst; i++)
        tmp[i] = aes_sbox_byte(state_in[i]);
    shift_bytes_bytes(tmp, (int)cols, shift);
    mix_bytes_bytes(tmp, (int)cols);

    /* Odd-round AddRoundConstant => odd SubBytes input. */
    grostl_norm_round_const(is_q, cols, (uint8_t)odd_round, rc);
    for (i = 0; i < nst; i++)
        tmp[i] = (uint8_t)(tmp[i] ^ rc[i]);

    /* Odd round: SubBytes, ShiftBytes => committed reset state s_tilde. */
    for (i = 0; i < nst; i++)
        tmp[i] = aes_sbox_byte(tmp[i]);
    shift_bytes_bytes(tmp, (int)cols, shift);
    memcpy(s_tilde_out, tmp, nst);
}

static void
compress_norm_bytes_capture(uint8_t *h, const uint8_t *m, int columns,
                            int npairs, const uint8_t shift_p[ROWS],
                            const uint8_t shift_q[ROWS], uint8_t **w)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t p_in[STATE_BYTES_512];
    uint8_t q_in[STATE_BYTES_512];

    for (size_t i = 0; i < n; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }
    permute_norm_bytes_capture(p_in, columns, npairs, shift_p, 0, w);
    permute_norm_bytes_capture(q_in, columns, npairs, shift_q, 1, w);
    for (size_t i = 0; i < n; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    voleith_secure_zero(p_in, sizeof(p_in));
    voleith_secure_zero(q_in, sizeof(q_in));
}

static void
output_transform_norm_bytes_capture(uint8_t *h, int columns, int npairs,
                                    const uint8_t shift_p[ROWS], uint8_t **w)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t temp[STATE_BYTES_512];

    memcpy(temp, h, n);
    permute_norm_bytes_capture(temp, columns, npairs, shift_p, 0, w);
    for (size_t i = 0; i < n; i++)
        h[i] ^= temp[i];

    voleith_secure_zero(temp, sizeof(temp));
}

/* ================================================================
 * Full-hash witness sizes and builders.
 *
 * Per compression (P + Q): 2 * npairs * (nst/2 + nst) bytes.  Grostl-256:
 * 2 * 5 * (32 + 64) = 960.  Grostl-512: 2 * 7 * (64 + 128) = 2688.  Output
 * transform (P only) is half the compression figure: 480 and 1344.
 * ================================================================ */

size_t
grostl256_norm_gf8_witness_bytes(size_t msg_bytes)
{
    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    return msg_bytes + n_blocks * 960u + 480u;
}

size_t
grostl512_norm_gf8_witness_bytes(size_t msg_bytes)
{
    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    return msg_bytes + n_blocks * 2688u + 1344u;
}

void
grostl256_norm_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                 uint8_t *witness)
{
    if (msg_bytes > 0)
        memcpy(witness, msg, msg_bytes);

    uint8_t *w = witness + msg_bytes;

    uint8_t h[STATE_BYTES_256];
    memset(h, 0, sizeof(h));
    h[62] = 0x01;

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_256);
    uint8_t block[STATE_BYTES_256];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block_bytes(msg, msg_bytes, bi, n_blocks, STATE_BYTES_256,
                                 block);
        compress_norm_bytes_capture(h, block, COLS_256, NPAIRS_256, SHIFT_P512,
                                    SHIFT_Q512, &w);
    }

    output_transform_norm_bytes_capture(h, COLS_256, NPAIRS_256, SHIFT_P512,
                                        &w);

    voleith_secure_zero(h, sizeof(h));
    voleith_secure_zero(block, sizeof(block));
}

void
grostl512_norm_gf8_build_witness(const uint8_t *msg, size_t msg_bytes,
                                 uint8_t *witness)
{
    if (msg_bytes > 0)
        memcpy(witness, msg, msg_bytes);

    uint8_t *w = witness + msg_bytes;

    uint8_t h[STATE_BYTES_512];
    memset(h, 0, sizeof(h));
    h[126] = 0x02;

    size_t n_blocks = n_blocks_for(msg_bytes, STATE_BYTES_512);
    uint8_t block[STATE_BYTES_512];
    for (size_t bi = 0; bi < n_blocks; bi++) {
        build_padded_block_bytes(msg, msg_bytes, bi, n_blocks, STATE_BYTES_512,
                                 block);
        compress_norm_bytes_capture(h, block, COLS_512, NPAIRS_512, SHIFT_P1024,
                                    SHIFT_Q1024, &w);
    }

    output_transform_norm_bytes_capture(h, COLS_512, NPAIRS_512, SHIFT_P1024,
                                        &w);

    voleith_secure_zero(h, sizeof(h));
    voleith_secure_zero(block, sizeof(block));
}

/* ================================================================
 * Node-circuit witness sizes and builders.  One compression per block
 * (chained through h, no output transform between them) then one output
 * transform; capture order is (P then Q) per block, then the output
 * transform's P.  Block bytes are caller-declared and excluded.
 * ================================================================ */

static void
grostl_norm_node_build_witness_impl(const uint8_t *iv, const uint8_t *blocks,
                                    size_t n_blocks, int columns, int npairs,
                                    const uint8_t shift_p[ROWS],
                                    const uint8_t shift_q[ROWS],
                                    uint8_t *inv_out)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t h[STATE_BYTES_512];
    memcpy(h, iv, n);

    for (size_t bi = 0; bi < n_blocks; bi++)
        compress_norm_bytes_capture(h, blocks + bi * n, columns, npairs,
                                    shift_p, shift_q, &inv_out);
    output_transform_norm_bytes_capture(h, columns, npairs, shift_p, &inv_out);

    voleith_secure_zero(h, sizeof(h));
}

size_t
grostl256_norm_gf8_node_invin_bytes(void)
{
    return 960u + 480u; /* 1440 */
}

size_t
grostl512_norm_gf8_node_invin_bytes(void)
{
    return 2688u + 1344u; /* 4032 */
}

size_t
grostl256_norm_gf8_node2_invin_bytes(void)
{
    return 2u * 960u + 480u; /* 2400 */
}

size_t
grostl512_norm_gf8_node2_invin_bytes(void)
{
    return 2u * 2688u + 1344u; /* 6720 */
}

size_t
grostl256_norm_gf8_nodeN_invin_bytes(size_t n_blocks)
{
    return n_blocks * 960u + 480u;
}

void
grostl256_norm_gf8_node_build_witness(const uint8_t iv[64],
                                      const uint8_t block[64], uint8_t *inv_out)
{
    grostl_norm_node_build_witness_impl(iv, block, 1, COLS_256, NPAIRS_256,
                                        SHIFT_P512, SHIFT_Q512, inv_out);
}

void
grostl512_norm_gf8_node_build_witness(const uint8_t iv[128],
                                      const uint8_t block[128],
                                      uint8_t *inv_out)
{
    grostl_norm_node_build_witness_impl(iv, block, 1, COLS_512, NPAIRS_512,
                                        SHIFT_P1024, SHIFT_Q1024, inv_out);
}

void
grostl256_norm_gf8_node2_build_witness(const uint8_t iv[64],
                                       const uint8_t block[128],
                                       uint8_t *inv_out)
{
    grostl_norm_node_build_witness_impl(iv, block, 2, COLS_256, NPAIRS_256,
                                        SHIFT_P512, SHIFT_Q512, inv_out);
}

void
grostl512_norm_gf8_node2_build_witness(const uint8_t iv[128],
                                       const uint8_t block[256],
                                       uint8_t *inv_out)
{
    grostl_norm_node_build_witness_impl(iv, block, 2, COLS_512, NPAIRS_512,
                                        SHIFT_P1024, SHIFT_Q1024, inv_out);
}

void
grostl256_norm_gf8_nodeN_build_witness(const uint8_t iv[64],
                                       const uint8_t *blocks, size_t n_blocks,
                                       uint8_t *inv_out)
{
    grostl_norm_node_build_witness_impl(iv, blocks, n_blocks, COLS_256,
                                        NPAIRS_256, SHIFT_P512, SHIFT_Q512,
                                        inv_out);
}
