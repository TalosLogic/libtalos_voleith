/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_ct64.c - Bitsliced AES-128/192/256 (constant-time, portable).
 *
 * Backend selected when no hardware AES (AES-NI on x86_64, ARMv8
 * Cryptography Extension on aarch64) is available.  Processes four
 * AES blocks in parallel using a uint64_t bit-plane representation.
 *
 * Block-major packing: bit k of byte i of block b lives at bit
 * position (16 * b + i) of q[k].  See docs/BITSLICED_AES_DESIGN.md
 * for the full convention and derivation.
 *
 * Constant-time by construction: every operation in the encrypt and
 * key-expansion paths is a fixed sequence of XOR / AND / NOT / shift
 * with constant shift amounts.  No data-dependent branches; no
 * secret-indexed memory accesses.
 *
 * The S-box is the Canright (2005) tower-field decomposition lifted
 * from circuits/aes_circuit.c (already validated against NIST CAVP
 * and faest-ref).  The lift is a mechanical 1:1 substitution of
 * wire_id -> uint64_t and add_xor/add_and -> ^/&.
 */

#include "aes_ct64.h"
#include "util.h"
#include <string.h>

/* ================================================================
 * Endianness gate.  Block-major packing assumes little-endian
 * uint64_t interpretation of 8-byte chunks; explicitly fail on
 * big-endian targets rather than silently miscompile.
 * ================================================================ */

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "aes_ct64.c assumes a little-endian target."
#endif

/* ================================================================
 * Byte-level load / store helpers (avoid alignment assumptions).
 * ================================================================ */

static inline uint64_t
load_le64(const uint8_t *p)
{
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static inline void
store_le64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static inline uint32_t
load_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void
store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ================================================================
 * 8x8 bit-matrix transpose on a single uint64_t.
 *
 * Input: a uint64_t holding 8 bytes laid out as rows of a bit matrix
 *        (byte 0 in bits 0..7 = row 0; byte 7 in bits 56..63 = row 7).
 * Output: transpose of that matrix.  After transpose, byte k of the
 *         result holds bit k of each input byte (bit k of row 0 in
 *         the LSB, bit k of row 7 in the MSB).
 *
 * Hacker's-Delight / Eklundh-style three-step butterfly.
 * ================================================================ */

static inline uint64_t
bit_transpose_8x8(uint64_t x)
{
    uint64_t y;

    y = (x ^ (x >> 7)) & 0x00AA00AA00AA00AAULL;
    x = x ^ y ^ (y << 7);

    y = (x ^ (x >> 14)) & 0x0000CCCC0000CCCCULL;
    x = x ^ y ^ (y << 14);

    y = (x ^ (x >> 28)) & 0x00000000F0F0F0F0ULL;
    x = x ^ y ^ (y << 28);

    return x;
}

/* ================================================================
 * Orthogonalize / un-orthogonalize.
 *
 * orthogonalize(): 64 input bytes (four 16-byte blocks) -> 8 bit-plane
 * registers q[0..7].  bit k of input byte i (i in 0..63) lives at
 * bit position i of q[k].
 *
 * un_orthogonalize() is the inverse.
 * ================================================================ */

static void
orthogonalize(uint64_t q[8], const uint8_t in[64])
{
    uint64_t t[8];
    int chunk, k;

    /* Per-chunk transpose: byte k of t[chunk] = bit k of input
     * bytes 8*chunk .. 8*chunk+7. */
    for (chunk = 0; chunk < 8; chunk++)
        t[chunk] = bit_transpose_8x8(load_le64(in + 8 * chunk));

    /* Gather byte k of every chunk into q[k] at position 8*chunk. */
    for (k = 0; k < 8; k++) {
        uint64_t v = 0;
        for (chunk = 0; chunk < 8; chunk++)
            v |= ((t[chunk] >> (8 * k)) & 0xFFULL) << (8 * chunk);
        q[k] = v;
    }
}

static void
un_orthogonalize(uint8_t out[64], const uint64_t q[8])
{
    uint64_t t[8];
    int chunk, k;

    /* Scatter: byte chunk of q[k] -> byte k of t[chunk]. */
    for (chunk = 0; chunk < 8; chunk++) {
        uint64_t v = 0;
        for (k = 0; k < 8; k++)
            v |= ((q[k] >> (8 * chunk)) & 0xFFULL) << (8 * k);
        t[chunk] = v;
    }

    /* Per-chunk transpose is its own inverse. */
    for (chunk = 0; chunk < 8; chunk++)
        store_le64(out + 8 * chunk, bit_transpose_8x8(t[chunk]));
}

/* ================================================================
 * Bitsliced GF(2^n) helpers - direct 1:1 lift of the tower-field
 * code from circuits/aes_circuit.c.  Each wire_id becomes a uint64_t
 * (one bit per byte slot, 64 byte slots = 4 blocks * 16 bytes).
 * ================================================================ */

/* GF(2^2) element: high (xi coeff) and low (constant). */
typedef struct {
    uint64_t h, l;
} gf2_bs;

/* GF(2^4) element: high (eta coeff) and low. */
typedef struct {
    gf2_bs H, L;
} gf4_bs;

/* GF(2^8) element: high (theta coeff) and low. */
typedef struct {
    gf4_bs H, L;
} gf8_bs;

static inline gf2_bs
gf2_add(gf2_bs a, gf2_bs b)
{
    return (gf2_bs){a.h ^ b.h, a.l ^ b.l};
}

static inline gf2_bs
gf2_sq(gf2_bs a)
{
    return (gf2_bs){a.h, a.h ^ a.l};
}

static inline gf2_bs
gf2_inv(gf2_bs a)
{
    return gf2_sq(a);
}

static inline gf2_bs
gf2_mul_xi(gf2_bs a)
{
    return (gf2_bs){a.h ^ a.l, a.h};
}

static inline gf2_bs
gf2_mul_xi1(gf2_bs a)
{
    return (gf2_bs){a.l, a.h ^ a.l};
}

static inline gf2_bs
gf2_mul(gf2_bs a, gf2_bs b)
{
    uint64_t ah_xl = a.h ^ a.l;
    uint64_t bh_xl = b.h ^ b.l;
    uint64_t p1 = a.h & b.h;
    uint64_t p2 = a.l & b.l;
    uint64_t p3 = ah_xl & bh_xl;
    return (gf2_bs){p3 ^ p2, p1 ^ p2};
}

static inline gf4_bs
gf4_add(gf4_bs a, gf4_bs b)
{
    return (gf4_bs){gf2_add(a.H, b.H), gf2_add(a.L, b.L)};
}

static inline gf4_bs
gf4_sq(gf4_bs a)
{
    gf2_bs sq_H = gf2_sq(a.H);
    gf2_bs sq_L = gf2_sq(a.L);
    return (gf4_bs){sq_H, gf2_add(gf2_mul_xi(sq_H), sq_L)};
}

static inline gf4_bs
gf4_mul_phi(gf4_bs a)
{
    gf2_bs sum = gf2_add(a.H, a.L);
    return (gf4_bs){gf2_mul_xi(sum), gf2_mul_xi1(a.H)};
}

static inline gf4_bs
gf4_mul(gf4_bs a, gf4_bs b)
{
    gf2_bs P1 = gf2_mul(a.H, b.H);
    gf2_bs P2 = gf2_mul(a.L, b.L);
    gf2_bs aHL = gf2_add(a.H, a.L);
    gf2_bs bHL = gf2_add(b.H, b.L);
    gf2_bs P3 = gf2_mul(aHL, bHL);
    return (gf4_bs){
        gf2_add(P3, P2),
        gf2_add(gf2_mul_xi(P1), P2),
    };
}

static inline gf4_bs
gf4_inv(gf4_bs a)
{
    gf2_bs sq_H = gf2_sq(a.H);
    gf2_bs sq_L = gf2_sq(a.L);
    gf2_bs prod = gf2_mul(a.H, a.L);
    gf2_bs N4 = gf2_add(gf2_mul_xi(sq_H), gf2_add(prod, sq_L));
    gf2_bs N4_inv = gf2_inv(N4);
    gf2_bs sumHL = gf2_add(a.L, a.H);
    return (gf4_bs){
        gf2_mul(a.H, N4_inv),
        gf2_mul(sumHL, N4_inv),
    };
}

static inline gf8_bs
gf8_inv(gf8_bs a)
{
    gf4_bs sq_H = gf4_sq(a.H);
    gf4_bs sq_L = gf4_sq(a.L);
    gf4_bs prod = gf4_mul(a.H, a.L);
    gf4_bs N = gf4_add(gf4_mul_phi(sq_H), gf4_add(prod, sq_L));
    gf4_bs N_inv = gf4_inv(N);
    gf4_bs sumHL = gf4_add(a.H, a.L);
    return (gf8_bs){
        gf4_mul(a.H, N_inv),
        gf4_mul(sumHL, N_inv),
    };
}

/* ================================================================
 * Change-of-basis matrices.  Identical to the constants in
 * circuits/aes_circuit.c (same Canright tower-field parameters).
 *
 *   B     : AES polynomial basis -> tower basis.
 *   B_INV : tower basis -> AES polynomial basis.
 * ================================================================ */

static const uint8_t B[8] = {
    0x73, 0x38, 0x42, 0xc8, 0x70, 0x0c, 0xde, 0xa0,
};

static const uint8_t B_INV[8] = {
    0xe1, 0xf0, 0xc6, 0xe6, 0x7e, 0x9a, 0xf4, 0x1a,
};

/* Apply an 8x8 GF(2) matrix M to 8 bit-plane registers.
 * out[i] = XOR of in[j] for each j with bit j of M[i] set. */
static void
apply_linear8(const uint8_t M[8], const uint64_t in[8], uint64_t out[8])
{
    int i, j;

    for (i = 0; i < 8; i++) {
        uint8_t row = M[i];
        uint64_t acc = 0;
        for (j = 0; j < 8; j++) {
            if ((row >> j) & 1)
                acc ^= in[j];
        }
        out[i] = acc;
    }
}

/* AES affine transform (post-inversion).
 *   out[i] = in[i] ^ in[(i+4)%8] ^ in[(i+5)%8] ^ in[(i+6)%8]
 *            ^ in[(i+7)%8] ^ const_bit[i]
 * where const = 0x63 (bits 0, 1, 5, 6 set).
 *
 * The constant-1 bit-plane is "all ones at every byte slot" =
 * ~(uint64_t)0; XORing with it flips every byte's bit i. */
static void
aes_affine(const uint64_t in[8], uint64_t out[8])
{
    static const uint8_t C = 0x63;
    static const uint64_t ALL_ONES = ~(uint64_t)0;
    int i;

    for (i = 0; i < 8; i++) {
        uint64_t acc = in[i];
        acc ^= in[(i + 4) % 8];
        acc ^= in[(i + 5) % 8];
        acc ^= in[(i + 6) % 8];
        acc ^= in[(i + 7) % 8];
        if ((C >> i) & 1)
            acc ^= ALL_ONES;
        out[i] = acc;
    }
}

/* AES S-box on all 64 byte slots in parallel.
 *
 * Six steps, mirroring aes_sbox_circuit() in circuits/aes_circuit.c:
 *   1. Change basis AES poly -> tower (apply B).
 *   2. Pack into gf8_bs (bit layout per Canright decomposition).
 *   3. Invert in GF(2^8) via tower field (36 ANDs).
 *   4. Unpack to flat bit array.
 *   5. Change basis tower -> AES poly (apply B_INV).
 *   6. AES affine transform. */
static void
sbox(const uint64_t in[8], uint64_t out[8])
{
    uint64_t tower_in[8];
    uint64_t tower_out[8];
    uint64_t aes_inv[8];

    apply_linear8(B, in, tower_in);

    gf8_bs a = {
        .H =
            {
                .H = {tower_in[7], tower_in[6]},
                .L = {tower_in[5], tower_in[4]},
            },
        .L =
            {
                .H = {tower_in[3], tower_in[2]},
                .L = {tower_in[1], tower_in[0]},
            },
    };

    gf8_bs inv = gf8_inv(a);

    tower_out[0] = inv.L.L.l;
    tower_out[1] = inv.L.L.h;
    tower_out[2] = inv.L.H.l;
    tower_out[3] = inv.L.H.h;
    tower_out[4] = inv.H.L.l;
    tower_out[5] = inv.H.L.h;
    tower_out[6] = inv.H.H.l;
    tower_out[7] = inv.H.H.h;

    apply_linear8(B_INV, tower_out, aes_inv);
    aes_affine(aes_inv, out);
}

/* ================================================================
 * Round constants for the bit-plane operations.
 *
 * R0/R1/R2/R3 select bytes at row r (within each block's 16-byte
 * subfield) - namely byte positions {0,4,8,12}, {1,5,9,13},
 * {2,6,10,14}, {3,7,11,15}.  Replicated to all four blocks of a
 * uint64_t.
 * ================================================================ */

#define R0 0x1111111111111111ULL
#define R1 0x2222222222222222ULL
#define R2 0x4444444444444444ULL
#define R3 0x8888888888888888ULL
#define R_NOT3 (R0 | R1 | R2)

/*
 * Per-row ShiftRows masks split into "no-wrap" and "wrap" output
 * positions.  Splitting is necessary because the rotation we want
 * lives entirely within each 16-bit block subfield, but the shift
 * operations on a 64-bit register naturally cross block boundaries.
 *
 * Row 1 (cycle by 1 column):
 *   no-wrap output positions {1, 5, 9} per block (source at +4) -> (s >> 4)
 *   wrap output position {13} per block (source at -12)         -> (s << 12)
 *
 * Row 2 (cycle by 2 columns):
 *   no-wrap output positions {2, 6}    per block (source at +8) -> (s >> 8)
 *   wrap output positions   {10, 14}   per block (source at -8) -> (s << 8)
 *
 * Row 3 (cycle by 3 columns):
 *   no-wrap output positions {7, 11, 15} per block (source at -4)  -> (s << 4)
 *   wrap output position    {3}         per block (source at +12) -> (s >> 12)
 */
#define R1_LO 0x0222022202220222ULL
#define R1_HI 0x2000200020002000ULL
#define R2_LO 0x0044004400440044ULL
#define R2_HI 0x4400440044004400ULL
#define R3_LO 0x0008000800080008ULL
#define R3_HI 0x8880888088808880ULL

/* xtime applied to every byte slot in parallel.
 * Equations from FIPS 197 / circuits/aes_circuit.c:362-377. */
static inline void
xtime_state(const uint64_t in[8], uint64_t out[8])
{
    uint64_t b7 = in[7];
    out[0] = b7;
    out[1] = in[0] ^ b7;
    out[2] = in[1];
    out[3] = in[2] ^ b7;
    out[4] = in[3] ^ b7;
    out[5] = in[4];
    out[6] = in[5];
    out[7] = in[6];
}

/* ShiftRows on the bit-plane state.
 *
 * Per row r, each output position takes its source from one of two
 * shift operations on q[k] (no-wrap shift or within-block-wrap
 * shift); the split masks R{r}_LO / R{r}_HI route the contributions
 * to the correct output positions and discard any cross-block
 * spill.  See the mask comments above for the routing table.
 *
 * Per row r, the same shift is applied to every block in parallel
 * because the rotations stay within each 16-bit block subfield. */
static void
shift_rows(uint64_t q[8])
{
    int k;

    for (k = 0; k < 8; k++) {
        uint64_t s = q[k];
        q[k] = (s & R0) | ((s >> 4) & R1_LO) | ((s << 12) & R1_HI) |
               ((s >> 8) & R2_LO) | ((s << 8) & R2_HI) | ((s << 4) & R3_HI) |
               ((s >> 12) & R3_LO);
    }
}

/* SubBytes - S-box on the whole state in place. */
static inline void
sub_bytes(uint64_t q[8])
{
    uint64_t out[8];
    sbox(q, out);
    memcpy(q, out, sizeof(out));
}

/* AddRoundKey - XOR the bit-plane round key into the state. */
static inline void
add_round_key(uint64_t q[8], const uint64_t rk[8])
{
    int k;
    for (k = 0; k < 8; k++)
        q[k] ^= rk[k];
}

/* MixColumns on the bit-plane state.
 *
 * Per FIPS 197 §5.1.3, for each column c:
 *   s_xor = a_0 ^ a_1 ^ a_2 ^ a_3
 *   b_r   = a_r ^ s_xor ^ xtime(a_r ^ a_{(r+1) mod 4})
 *
 * Bit-plane implementation:
 *   1. Compute s_xor[k] for each bit-plane (XOR of column bytes,
 *      broadcast across all four row positions per column).
 *   2. Compute pair[k] = a_r ^ a_{r+1 mod 4} at each row r position
 *      via a per-row "next-row" shift.
 *   3. b[k] = a[k] ^ s_xor[k] ^ xtime(pair)[k].
 */
static void
mix_columns(uint64_t q[8])
{
    uint64_t s_xor[8];
    uint64_t pair[8];
    uint64_t xt_pair[8];
    int k;

    /* Step 1: per-column XOR, broadcast to all row positions. */
    for (k = 0; k < 8; k++) {
        uint64_t a = q[k];
        uint64_t r0_at_row0 = a & R0;
        uint64_t r1_at_row0 = (a & R1) >> 1;
        uint64_t r2_at_row0 = (a & R2) >> 2;
        uint64_t r3_at_row0 = (a & R3) >> 3;
        uint64_t col_at_row0 =
            r0_at_row0 ^ r1_at_row0 ^ r2_at_row0 ^ r3_at_row0;
        s_xor[k] = col_at_row0 | (col_at_row0 << 1) | (col_at_row0 << 2) |
                   (col_at_row0 << 3);
    }

    /* Step 2: pair[k] at row r position = q[k] at row r XOR q[k] at
     * row (r+1) mod 4 of the same column.  Build a "shifted" register
     * holding row (r+1)'s value at row r's position:
     *   rows 0,1,2 -> read from p+1 (q >> 1)
     *   row 3      -> wrap to row 0 of same column (q << 3)
     * Masks ensure no cross-block spill. */
    for (k = 0; k < 8; k++) {
        uint64_t a = q[k];
        uint64_t shifted = ((a >> 1) & R_NOT3) | ((a << 3) & R3);
        pair[k] = a ^ shifted;
    }

    /* Step 3: xtime(pair) and final assembly. */
    xtime_state(pair, xt_pair);
    for (k = 0; k < 8; k++)
        q[k] ^= s_xor[k] ^ xt_pair[k];
}

/* ================================================================
 * Full AES encrypt on bit-plane state (10 / 12 / 14 rounds).
 * ================================================================ */

static void
encrypt_state(uint64_t q[8], const aes_ct64_ctx_t *ctx)
{
    int r;

    add_round_key(q, ctx->rk[0]);
    for (r = 1; r < ctx->nr; r++) {
        sub_bytes(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, ctx->rk[r]);
    }
    sub_bytes(q);
    shift_rows(q);
    add_round_key(q, ctx->rk[ctx->nr]);
}

/* ================================================================
 * Round-key packing.
 *
 * pack_round_key() converts 16 bytes of a round key into bit-plane
 * form, replicated across all four 16-bit block subfields so that
 * AddRoundKey applies the same key to every parallel block.
 * ================================================================ */

static void
pack_round_key(uint64_t rk_out[8], const uint8_t key_bytes[16])
{
    int k, i;

    for (k = 0; k < 8; k++) {
        uint64_t v = 0;
        for (i = 0; i < 16; i++)
            v |= (uint64_t)((key_bytes[i] >> k) & 1) << i;
        /* Replicate the 16-bit value across all 4 blocks. */
        rk_out[k] = v | (v << 16) | (v << 32) | (v << 48);
    }
}

/* ================================================================
 * Constant-time SubWord for key expansion.
 *
 * Packs the 4 input bytes into the low 4 bit positions of 8
 * bit-plane registers, runs the bitsliced S-box, and unpacks.
 * Bytes at unused slots (4..63) are zero on input; their S-box
 * outputs are discarded.  Constant-time: no branches on key data,
 * shifts are by compile-time constants.
 * ================================================================ */

static uint32_t
sub_word(uint32_t w)
{
    uint64_t bp[8];
    uint64_t out[8];
    uint32_t res;
    int k;
    uint8_t b0 = (uint8_t)(w >> 24);
    uint8_t b1 = (uint8_t)(w >> 16);
    uint8_t b2 = (uint8_t)(w >> 8);
    uint8_t b3 = (uint8_t)w;

    /* SubWord acts on the bytes in big-endian order: byte 0 is the
     * most-significant byte of w.  Pack into bp[k] bit positions
     * 0..3. */
    for (k = 0; k < 8; k++) {
        bp[k] = (uint64_t)((b0 >> k) & 1) << 0 |
                (uint64_t)((b1 >> k) & 1) << 1 |
                (uint64_t)((b2 >> k) & 1) << 2 | (uint64_t)((b3 >> k) & 1) << 3;
    }

    sbox(bp, out);

    res = 0;
    for (k = 0; k < 8; k++) {
        res |= (uint32_t)((out[k] >> 0) & 1) << (24 + k);
        res |= (uint32_t)((out[k] >> 1) & 1) << (16 + k);
        res |= (uint32_t)((out[k] >> 2) & 1) << (8 + k);
        res |= (uint32_t)((out[k] >> 3) & 1) << k;
    }
    return res;
}

static inline uint32_t
rot_word(uint32_t w)
{
    return (w << 8) | (w >> 24);
}

/* ================================================================
 * Key expansion (FIPS 197 §5.2).
 *
 * Generates Nk * (Nr + 1) 32-bit words, packs each consecutive run
 * of four words into a 16-byte round key, then converts to
 * bit-plane form via pack_round_key().
 *
 * Constant-time: every operation on key data is XOR, shift by
 * constant amount, or the bitsliced sub_word(); no branches and no
 * table lookups indexed by key bits.
 * ================================================================ */

int
aes_ct64_key_expand(aes_ct64_ctx_t *ctx, const uint8_t *key, int key_bits)
{
    /* Rcon[i] = {x^(i-1), 00, 00, 00} in AES GF(2^8).  Only the
     * top byte (most-significant in big-endian word) is non-zero. */
    static const uint8_t RCON[16] = {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    };
    uint32_t w[60]; /* AES-256 worst case: Nb*(Nr+1) = 4*15 = 60 words */
    uint8_t round_bytes[16];
    int nk, nr, i, r;

    switch (key_bits) {
    case 128:
        nk = 4;
        nr = 10;
        break;
    case 192:
        nk = 6;
        nr = 12;
        break;
    case 256:
        nk = 8;
        nr = 14;
        break;
    default:
        return -1;
    }

    /* w[0..nk-1] = key bytes packed as big-endian 32-bit words. */
    for (i = 0; i < nk; i++)
        w[i] = load_be32(key + 4 * i);

    /* w[i] for i >= nk. */
    for (i = nk; i < 4 * (nr + 1); i++) {
        uint32_t temp = w[i - 1];
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)RCON[i / nk] << 24);
        } else if (nk == 8 && i % nk == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - nk] ^ temp;
    }

    ctx->nr = nr;
    for (r = 0; r <= nr; r++) {
        store_be32(round_bytes + 0, w[4 * r + 0]);
        store_be32(round_bytes + 4, w[4 * r + 1]);
        store_be32(round_bytes + 8, w[4 * r + 2]);
        store_be32(round_bytes + 12, w[4 * r + 3]);
        pack_round_key(ctx->rk[r], round_bytes);
    }

    voleith_secure_zero(w, sizeof(w));
    voleith_secure_zero(round_bytes, sizeof(round_bytes));
    return 0;
}

/* ================================================================
 * Public encrypt entry points.
 * ================================================================ */

void
aes_ct64_encrypt_x4(const aes_ct64_ctx_t *ctx, uint8_t out[64],
                    const uint8_t in[64])
{
    uint64_t q[8];

    orthogonalize(q, in);
    encrypt_state(q, ctx);
    un_orthogonalize(out, q);
    voleith_secure_zero(q, sizeof(q));
}

void
aes_ct64_encrypt(const aes_ct64_ctx_t *ctx, uint8_t out[16],
                 const uint8_t in[16])
{
    uint8_t buf[64];

    memcpy(buf, in, 16);
    memset(buf + 16, 0, 48);
    aes_ct64_encrypt_x4(ctx, buf, buf);
    memcpy(out, buf, 16);
    voleith_secure_zero(buf, sizeof(buf));
}

void
aes_ct64_ctx_clear(aes_ct64_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}
