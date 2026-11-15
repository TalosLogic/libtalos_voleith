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
#include "grostl_gf8_internal.h" /* shared Grostl constants + linear layer */
#include "../core/field.h"
#include "../core/util.h"
#include "aes_gf8_circuit.h"
#include <stdint.h>
#include <string.h>

/* Spec constants (ROWS/COLS/STATE/ROUNDS), the ShiftBytes row shifts
 * (SHIFT_P512/Q512/P1024/Q1024) and the MixBytes GF(2) bit matrices
 * (MUL2..7_MATRIX) now live in grostl_gf8_internal.h, shared with the norm
 * circuit. */

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

/* mix_bytes_column_wires / mix_bytes_wires now live in
 * grostl_gf8_internal.h, shared with the norm circuit. */

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

/* n_blocks_for / build_padded_block now live in grostl_gf8_internal.h,
 * shared with the norm circuit. */

/* ================================================================
 * Public API: circuit builders.
 *
 * IV per spec §3.5: ℓ-bit big-endian representation of n.  For
 * Grøstl-256 (ℓ=512, n=256), bytes 0..61 are zero, bytes 62..63
 * encode 256 (= 0x0100) big-endian -> state[62] = 0x01.
 * Grøstl-512 (ℓ=1024, n=512): state[126] = 0x02 (= 0x0200).
 * ================================================================ */

/* init_iv_256_wires / init_iv_512_wires now live in grostl_gf8_internal.h,
 * shared with the norm circuit. */

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
 * Fixed-input multi-block node circuits.
 *
 * H = Omega(f(... f(f(iv, block0), block1) ..., block_{k-1})): inject
 * iv as constant wires, run n_blocks raw compressions (chaining the
 * wire-valued state h across blocks, NO output transform between
 * them), then a single output transform and truncation.  This is the
 * standard Grøstl MD chain with the IV carrying domain separation and
 * NO Merkle-Damgård length/marker padding (the input is a fixed number
 * of full-width blocks).  Reuses compress_wires / output_transform_wires
 * exactly as the single-block node circuit does; the single-block
 * path (grostl_node_circuit_impl) is untouched and byte-identical.
 * ================================================================ */

static void
grostl_node_multiblock_impl(voleith_gf8_circuit_t *c, const uint8_t *iv,
                            const gf8_wire_id *blocks, size_t n_blocks,
                            int columns, int rounds,
                            const uint8_t shift_p[ROWS],
                            const uint8_t shift_q[ROWS], size_t out_bytes,
                            gf8_wire_id *out)
{
    size_t n = (size_t)(ROWS * columns);
    gf8_wire_id h[STATE_BYTES_512];

    /* iv is public structural data: constant wires, zero VOLE slots. */
    for (size_t i = 0; i < n; i++)
        h[i] = voleith_gf8_add_const(c, iv[i]);

    /* One raw compression per block; Omega only after the last. */
    for (size_t bi = 0; bi < n_blocks; bi++)
        compress_wires(c, h, blocks + bi * n, columns, rounds, shift_p,
                       shift_q);

    output_transform_wires(c, h, columns, rounds, shift_p);

    for (size_t i = 0; i < out_bytes; i++)
        out[i] = h[n - out_bytes + i];
}

void
grostl256_gf8_node2_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                            const gf8_wire_id block[128], gf8_wire_id out[32])
{
    grostl_node_multiblock_impl(c, iv, block, 2, COLS_256, ROUNDS_256,
                                SHIFT_P512, SHIFT_Q512, 32, out);
}

void
grostl512_gf8_node2_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[128],
                            const gf8_wire_id block[256], gf8_wire_id out[64])
{
    grostl_node_multiblock_impl(c, iv, block, 2, COLS_512, ROUNDS_512,
                                SHIFT_P1024, SHIFT_Q1024, 64, out);
}

void
grostl256_gf8_nodeN_circuit(voleith_gf8_circuit_t *c, const uint8_t iv[64],
                            const gf8_wire_id *blocks, size_t n_blocks,
                            gf8_wire_id out[32])
{
    grostl_node_multiblock_impl(c, iv, blocks, n_blocks, COLS_256, ROUNDS_256,
                                SHIFT_P512, SHIFT_Q512, 32, out);
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

/* aes_sbox_byte, gf_xtime and mul{2,3,4,5,7}_byte now live in
 * grostl_gf8_internal.h, shared with the norm circuit. */

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

/* shift_bytes_bytes, mix_bytes_column_bytes and mix_bytes_bytes now live in
 * grostl_gf8_internal.h, shared with the norm circuit. */

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

/* build_padded_block_bytes now lives in grostl_gf8_internal.h, shared with
 * the norm circuit. */

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

/* ================================================================
 * Multi-block node-circuit witness builders.  Mirror the multi-block
 * node circuit: n_blocks compressions chained through h, then one
 * output transform.  inv_in order = (P then Q) per block, then the
 * output transform's P.  Excludes block bytes (caller-declared).
 * ================================================================ */

static void
grostl_node_multiblock_build_witness_impl(
    const uint8_t *iv, const uint8_t *blocks, size_t n_blocks, int columns,
    int rounds, const uint8_t shift_p[ROWS], const uint8_t shift_q[ROWS],
    uint8_t *inv_out)
{
    size_t n = (size_t)(ROWS * columns);
    uint8_t h[STATE_BYTES_512];
    memcpy(h, iv, n);

    for (size_t bi = 0; bi < n_blocks; bi++)
        compress_bytes_capture(h, blocks + bi * n, columns, rounds, shift_p,
                               shift_q, &inv_out);
    output_transform_bytes_capture(h, columns, rounds, shift_p, &inv_out);

    voleith_secure_zero(h, sizeof(h));
}

size_t
grostl256_gf8_node2_invin_bytes(void)
{
    /* Two compressions (2 * 1,280) + output transform P (640). */
    return 2u * 1280u + 640u; /* 3200 */
}

size_t
grostl512_gf8_node2_invin_bytes(void)
{
    /* Two compressions (2 * 3,584) + output transform P (1,792). */
    return 2u * 3584u + 1792u; /* 8960 */
}

void
grostl256_gf8_node2_build_witness(const uint8_t iv[64],
                                  const uint8_t block[128], uint8_t *inv_out)
{
    grostl_node_multiblock_build_witness_impl(
        iv, block, 2, COLS_256, ROUNDS_256, SHIFT_P512, SHIFT_Q512, inv_out);
}

void
grostl512_gf8_node2_build_witness(const uint8_t iv[128],
                                  const uint8_t block[256], uint8_t *inv_out)
{
    grostl_node_multiblock_build_witness_impl(
        iv, block, 2, COLS_512, ROUNDS_512, SHIFT_P1024, SHIFT_Q1024, inv_out);
}

size_t
grostl256_gf8_nodeN_invin_bytes(size_t n_blocks)
{
    /* n compressions (n * 1,280) + one output transform P (640). */
    return n_blocks * 1280u + 640u;
}

void
grostl256_gf8_nodeN_build_witness(const uint8_t iv[64], const uint8_t *blocks,
                                  size_t n_blocks, uint8_t *inv_out)
{
    grostl_node_multiblock_build_witness_impl(iv, blocks, n_blocks, COLS_256,
                                              ROUNDS_256, SHIFT_P512,
                                              SHIFT_Q512, inv_out);
}
