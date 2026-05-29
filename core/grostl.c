/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.c - Grøstl-256 and Grøstl-512.
 *
 * Clean-room implementation from the Grøstl specification
 * (third_party/Groestl/Supporting_Documentation/Groestl.pdf §3) with
 * the round-3 modifications applied (Round3Mods.pdf §2: tweaked Q
 * shift values and full-width AddRoundConstant).  No code is copied
 * from the reference implementation.
 *
 * State representation:
 *   The state is stored as a flat byte array using the column-major
 *   mapping defined in the spec §3.4.1: the linear byte sequence
 *   00 01 02 .. (statesize-1) maps to the state matrix such that
 *   byte (r + ROWS*c) lives at row r, column c.  ROWS = 8 always;
 *   the number of columns is 8 (Grøstl-256) or 16 (Grøstl-512).
 *   This matches the byte order of all input/output and lets us use
 *   the bitsliced AES S-box directly on flat 64-byte chunks.
 *
 * SubBytes:
 *   Grøstl reuses the AES S-box (spec §3.4.3 + Appendix B).  Three
 *   backends, selected at compile time:
 *     VOLEITH_HAVE_AES_NI       - x86 AES-NI via _mm_aesenclast_si128.
 *     VOLEITH_HAVE_ARMV8_AES    - ARMv8 Cryptography Extension via vaeseq_u8.
 *     (none of the above)       - bitsliced fallback via
 *                                 aes_ct64_sbox_inplace_4blocks.
 *   All three are constant-time.  The hardware paths use AES's own
 *   round instruction with a zero round key and undo the ShiftRows
 *   that the instruction additionally performs - see the inline
 *   comments at each hardware helper for the derivation.
 *
 * Constant-time:
 *   No table lookups indexed by secret state; all branches in this
 *   file are on public values (round number, byte index, etc.).  The
 *   "carry" in xtime() is computed via arithmetic rather than a
 *   branch.
 */

#include "grostl.h"
#include "aes_ct64.h"
#include "util.h"
#include <string.h>

#if defined(VOLEITH_HAVE_AES_NI)
#include <tmmintrin.h> /* SSSE3 _mm_shuffle_epi8 (pshufb) */
#include <wmmintrin.h> /* AES-NI _mm_aesenclast_si128 */
#elif defined(VOLEITH_HAVE_ARMV8_AES)
#include <arm_neon.h>
#endif

#define GROSTL_ROWS 8
#define GROSTL_COLS_256 8
#define GROSTL_COLS_512 16
#define GROSTL_STATE_BYTES_256 (GROSTL_ROWS * GROSTL_COLS_256) /* 64 */
#define GROSTL_STATE_BYTES_512 (GROSTL_ROWS * GROSTL_COLS_512) /* 128 */
#define GROSTL_ROUNDS_256 10
#define GROSTL_ROUNDS_512 14

/* ================================================================
 * ShiftBytes vectors (spec §3.4.4 + Round3Mods §2.1.1 / §2.2.1).
 *
 * Each row r is cyclically shifted left by SHIFT_*[r] positions.
 * Indexing: ROW r of the state, after the shift, equals row r of
 * the input rotated so that byte at column c reads from column
 * (c + SHIFT[r]) mod v.
 * ================================================================ */

/* P_512: identity-style. */
static const uint8_t SHIFT_P512[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 7};

/* Q_512: tweaked shifts (Round3Mods §2.1.1). */
static const uint8_t SHIFT_Q512[GROSTL_ROWS] = {1, 3, 5, 7, 0, 2, 4, 6};

/* P_1024: row 7 has the extra "11" shift (only valid for v=16). */
static const uint8_t SHIFT_P1024[GROSTL_ROWS] = {0, 1, 2, 3, 4, 5, 6, 11};

/* Q_1024: tweaked shifts (Round3Mods §2.2.1). */
static const uint8_t SHIFT_Q1024[GROSTL_ROWS] = {1, 3, 5, 11, 0, 2, 4, 6};

/* ================================================================
 * Constant-time GF(2^8) multiplication by small constants.
 *
 * Field: F_256 with reduction polynomial x^8 + x^4 + x^3 + x + 1
 * (= 0x11b), same as AES/Rijndael (spec §3.4.5).
 *
 * xtime(b) = b * x:
 *   carry = high bit of b, broadcast to all 8 bits as 0xff or 0x00.
 *   result = (b << 1) ^ (carry & 0x1b).
 *
 * Branchless: the "if high bit" decision is computed by arithmetic
 * (0u - (b >> 7) is 0xff..ff if bit 7 is set, else 0), which masks
 * the reduction constant 0x1b on or off without conditional control
 * flow.  Constant-time on every reasonable compiler/CPU.
 * ================================================================ */

static inline uint8_t
gf_xtime(uint8_t b)
{
    /* 0xff when b's high bit is set, 0x00 otherwise. */
    uint8_t carry_mask = (uint8_t)(0u - (uint32_t)(b >> 7));
    return (uint8_t)((b << 1) ^ (carry_mask & 0x1b));
}

static inline uint8_t
gf_mul2(uint8_t b)
{
    return gf_xtime(b);
}

static inline uint8_t
gf_mul3(uint8_t b)
{
    return (uint8_t)(gf_xtime(b) ^ b);
}

static inline uint8_t
gf_mul4(uint8_t b)
{
    return gf_xtime(gf_xtime(b));
}

static inline uint8_t
gf_mul5(uint8_t b)
{
    return (uint8_t)(gf_mul4(b) ^ b);
}

static inline uint8_t
gf_mul7(uint8_t b)
{
    return (uint8_t)(gf_mul4(b) ^ gf_xtime(b) ^ b);
}

/* ================================================================
 * AddRoundConstant.
 *
 * P: only row 0 is altered; column c contributes (c<<4) ^ round.
 *    Round3Mods Eq. P_512:C[i] / P_1024:C[i].
 *
 * Q: all bytes in rows 0..6 are XORed with 0xff (i.e. inverted), and
 *    row 7 column c is XORed with (0xff ^ (c<<4) ^ round).
 *    Round3Mods Eq. Q_512:C[i] / Q_1024:C[i].
 *
 * In flat column-major layout, byte (r + 8*c) is row r of column c.
 * ================================================================ */

static void
add_round_constant_p(uint8_t *state, int columns, uint8_t round)
{
    for (int c = 0; c < columns; c++)
        state[0 + GROSTL_ROWS * c] ^= (uint8_t)((c << 4) ^ round);
}

static void
add_round_constant_q(uint8_t *state, int columns, uint8_t round)
{
    for (int c = 0; c < columns; c++) {
        for (int r = 0; r < GROSTL_ROWS - 1; r++)
            state[r + GROSTL_ROWS * c] ^= 0xff;
        state[(GROSTL_ROWS - 1) + GROSTL_ROWS * c] ^=
            (uint8_t)(0xff ^ (c << 4) ^ round);
    }
}

/* ================================================================
 * ShiftBytes (spec §3.4.4 + Round3Mods).
 *
 * Cyclically rotate row r to the left by shift[r] positions over v
 * columns.  After the rotation, new[r][c] = old[r][(c + shift[r]) mod v].
 *
 * Implementation: read out the full row into a scratch buffer with
 * the rotated indices, then write back.  No data-dependent indexing
 * - shift[r] is a public per-row constant, and the (c + shift[r])
 * mod v computation depends only on public column index c.
 * ================================================================ */

static void
shift_bytes(uint8_t *state, int columns, const uint8_t shift[GROSTL_ROWS])
{
    uint8_t row[GROSTL_COLS_512];

    for (int r = 0; r < GROSTL_ROWS; r++) {
        uint8_t s = shift[r];
        for (int c = 0; c < columns; c++)
            row[c] = state[r + GROSTL_ROWS * ((c + s) % columns)];
        for (int c = 0; c < columns; c++)
            state[r + GROSTL_ROWS * c] = row[c];
    }
}

/* ================================================================
 * MixBytes (spec §3.4.5).
 *
 * Each column of the state matrix is left-multiplied by the
 * circulant 8x8 GF(2^8) matrix B = circ(02, 02, 03, 04, 05, 03, 05,
 * 07).  Row r of B is the first row right-rotated by r positions:
 *
 *   B[0] = [02, 02, 03, 04, 05, 03, 05, 07]
 *   B[1] = [07, 02, 02, 03, 04, 05, 03, 05]
 *   B[2] = [05, 07, 02, 02, 03, 04, 05, 03]
 *   B[3] = [03, 05, 07, 02, 02, 03, 04, 05]
 *   B[4] = [05, 03, 05, 07, 02, 02, 03, 04]
 *   B[5] = [04, 05, 03, 05, 07, 02, 02, 03]
 *   B[6] = [03, 04, 05, 03, 05, 07, 02, 02]
 *   B[7] = [02, 03, 04, 05, 03, 05, 07, 02]
 *
 * Constant-time: no data-dependent control flow; the mul* helpers
 * unfold each GF(2^8) multiply into a fixed XOR / shift sequence.
 * ================================================================ */

static void
mix_bytes_column(const uint8_t in[GROSTL_ROWS], uint8_t out[GROSTL_ROWS])
{
    uint8_t a = in[0];
    uint8_t b = in[1];
    uint8_t c = in[2];
    uint8_t d = in[3];
    uint8_t e = in[4];
    uint8_t f = in[5];
    uint8_t g = in[6];
    uint8_t h = in[7];

    out[0] = (uint8_t)(gf_mul2(a) ^ gf_mul2(b) ^ gf_mul3(c) ^ gf_mul4(d) ^
                       gf_mul5(e) ^ gf_mul3(f) ^ gf_mul5(g) ^ gf_mul7(h));
    out[1] = (uint8_t)(gf_mul7(a) ^ gf_mul2(b) ^ gf_mul2(c) ^ gf_mul3(d) ^
                       gf_mul4(e) ^ gf_mul5(f) ^ gf_mul3(g) ^ gf_mul5(h));
    out[2] = (uint8_t)(gf_mul5(a) ^ gf_mul7(b) ^ gf_mul2(c) ^ gf_mul2(d) ^
                       gf_mul3(e) ^ gf_mul4(f) ^ gf_mul5(g) ^ gf_mul3(h));
    out[3] = (uint8_t)(gf_mul3(a) ^ gf_mul5(b) ^ gf_mul7(c) ^ gf_mul2(d) ^
                       gf_mul2(e) ^ gf_mul3(f) ^ gf_mul4(g) ^ gf_mul5(h));
    out[4] = (uint8_t)(gf_mul5(a) ^ gf_mul3(b) ^ gf_mul5(c) ^ gf_mul7(d) ^
                       gf_mul2(e) ^ gf_mul2(f) ^ gf_mul3(g) ^ gf_mul4(h));
    out[5] = (uint8_t)(gf_mul4(a) ^ gf_mul5(b) ^ gf_mul3(c) ^ gf_mul5(d) ^
                       gf_mul7(e) ^ gf_mul2(f) ^ gf_mul2(g) ^ gf_mul3(h));
    out[6] = (uint8_t)(gf_mul3(a) ^ gf_mul4(b) ^ gf_mul5(c) ^ gf_mul3(d) ^
                       gf_mul5(e) ^ gf_mul7(f) ^ gf_mul2(g) ^ gf_mul2(h));
    out[7] = (uint8_t)(gf_mul2(a) ^ gf_mul3(b) ^ gf_mul4(c) ^ gf_mul5(d) ^
                       gf_mul3(e) ^ gf_mul5(f) ^ gf_mul7(g) ^ gf_mul2(h));
}

static void
mix_bytes(uint8_t *state, int columns)
{
    uint8_t in[GROSTL_ROWS];
    uint8_t out[GROSTL_ROWS];

    for (int c = 0; c < columns; c++) {
        for (int r = 0; r < GROSTL_ROWS; r++)
            in[r] = state[r + GROSTL_ROWS * c];
        mix_bytes_column(in, out);
        for (int r = 0; r < GROSTL_ROWS; r++)
            state[r + GROSTL_ROWS * c] = out[r];
    }
}

/* ================================================================
 * SubBytes - hardware-accelerated paths plus bitsliced fallback.
 *
 * Grøstl SubBytes is the AES S-box applied byte-wise to all state
 * bytes (§3.4.3).  AES round instructions on x86 and ARM apply that
 * exact S-box as part of a larger AES round; we use the round
 * instruction with a zero round key and reverse the ShiftRows
 * component that the instruction additionally performs.
 *
 * AES ShiftRows in the standard 4x4 column-major layout sends the
 * byte at (row r, col c) to (row r, col (c - r) mod 4), i.e. the
 * permutation
 *
 *   sigma = [0, 13, 10, 7,  4, 1, 14, 11,  8, 5, 2, 15,  12, 9, 6, 3]
 *
 * mapping input position i to output position sigma(i).
 *
 * To undo ShiftRows after the AES round instruction we need a pshufb
 * (resp. vqtbl1q) mask M such that out[j] = result[M[j]] = S(in[j]).
 * Because the round instruction moves S(in[i]) to position sigma(i),
 * recovering S(in[j]) means reading from position sigma(j) of the
 * result.  So the mask is sigma itself, not sigma^-1.  The variable
 * name SHIFT_ROWS_MASK reflects the value (forward sigma); its role
 * is to undo the ShiftRows.
 *
 * The byte positions inside each 16-byte chunk of the Grøstl state
 * have no AES meaning - they're just 16 arbitrary Grøstl bytes -
 * so the AES ShiftRows permutation has no Grøstl significance.  All
 * we need is the byte-wise S-box applied without any permutation,
 * which the post-shuffle delivers.
 *
 * Both hardware paths are constant-time by ISA specification (the
 * AES round instructions don't index any cache lines on their
 * input).  The bitsliced fallback is constant-time by construction
 * (see core/aes_ct64.c).
 * ================================================================ */

#if defined(VOLEITH_HAVE_AES_NI) || defined(VOLEITH_HAVE_ARMV8_AES)
/* Forward AES ShiftRows sigma.  Used as a pshufb / vqtbl1q lookup
 * mask to undo the ShiftRows that the AES round instruction
 * inserts: out[j] = result[SHIFT_ROWS_MASK[j]] recovers S(input[j]). */
static const uint8_t SHIFT_ROWS_MASK[16] = {
    0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
};
#endif

#if defined(VOLEITH_HAVE_AES_NI)

/* _mm_aesenclast_si128(state, key) = AddRoundKey(ShiftRows(SubBytes(state)), key)
 * With key = 0, the XOR is a no-op, so the result is
 * ShiftRows(SubBytes(state)).  Post-applying pshufb with the forward
 * ShiftRows permutation sigma reads S(input[j]) back from position
 * sigma(j), recovering pure SubBytes(state). */
static inline __m128i
grostl_sbox_block_aesni(__m128i x, __m128i shift_rows_mask)
{
    __m128i sub_then_shift = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return _mm_shuffle_epi8(sub_then_shift, shift_rows_mask);
}

static void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    __m128i mask = _mm_loadu_si128((const __m128i *)SHIFT_ROWS_MASK);
    __m128i b0 = _mm_loadu_si128((const __m128i *)(state + 0));
    __m128i b1 = _mm_loadu_si128((const __m128i *)(state + 16));
    __m128i b2 = _mm_loadu_si128((const __m128i *)(state + 32));
    __m128i b3 = _mm_loadu_si128((const __m128i *)(state + 48));
    b0 = grostl_sbox_block_aesni(b0, mask);
    b1 = grostl_sbox_block_aesni(b1, mask);
    b2 = grostl_sbox_block_aesni(b2, mask);
    b3 = grostl_sbox_block_aesni(b3, mask);
    _mm_storeu_si128((__m128i *)(state + 0), b0);
    _mm_storeu_si128((__m128i *)(state + 16), b1);
    _mm_storeu_si128((__m128i *)(state + 32), b2);
    _mm_storeu_si128((__m128i *)(state + 48), b3);
}

#elif defined(VOLEITH_HAVE_ARMV8_AES)

/* vaeseq_u8(state, key) = ShiftRows(SubBytes(state XOR key)).
 * With key = 0, the XOR is identity, so the result is
 * ShiftRows(SubBytes(state)).  Post-applying vqtbl1q_u8 with the
 * forward ShiftRows permutation sigma recovers pure SubBytes(state)
 * by reading S(input[j]) back from position sigma(j). */
static inline uint8x16_t
grostl_sbox_block_armv8(uint8x16_t x, uint8x16_t shift_rows_mask)
{
    uint8x16_t sub_then_shift = vaeseq_u8(x, vdupq_n_u8(0));
    return vqtbl1q_u8(sub_then_shift, shift_rows_mask);
}

static void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    uint8x16_t mask = vld1q_u8(SHIFT_ROWS_MASK);
    uint8x16_t b0 = vld1q_u8(state + 0);
    uint8x16_t b1 = vld1q_u8(state + 16);
    uint8x16_t b2 = vld1q_u8(state + 32);
    uint8x16_t b3 = vld1q_u8(state + 48);
    b0 = grostl_sbox_block_armv8(b0, mask);
    b1 = grostl_sbox_block_armv8(b1, mask);
    b2 = grostl_sbox_block_armv8(b2, mask);
    b3 = grostl_sbox_block_armv8(b3, mask);
    vst1q_u8(state + 0, b0);
    vst1q_u8(state + 16, b1);
    vst1q_u8(state + 32, b2);
    vst1q_u8(state + 48, b3);
}

#else /* no hardware AES; fall back to the bitsliced engine */

static inline void
grostl_sbox_inplace_64bytes(uint8_t state[GROSTL_STATE_BYTES_256])
{
    aes_ct64_sbox_inplace_4blocks(state);
}

#endif

static void
sub_bytes_512(uint8_t state[GROSTL_STATE_BYTES_256])
{
    grostl_sbox_inplace_64bytes(state);
}

static void
sub_bytes_1024(uint8_t state[GROSTL_STATE_BYTES_512])
{
    grostl_sbox_inplace_64bytes(state);
    grostl_sbox_inplace_64bytes(state + GROSTL_STATE_BYTES_256);
}

/* ================================================================
 * Permutations.
 *
 * R = MixBytes ∘ ShiftBytes ∘ SubBytes ∘ AddRoundConstant
 *
 * Spec §3.4.6: 10 rounds for the 512-bit permutations, 14 rounds
 * for the 1024-bit permutations.  The variant ({P,Q}_{512,1024})
 * differs only in the ShiftBytes vector and the AddRoundConstant
 * pattern; SubBytes and MixBytes are identical across all four.
 * ================================================================ */

static void
permute_p512(uint8_t state[GROSTL_STATE_BYTES_256])
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_p(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_P512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
permute_q512(uint8_t state[GROSTL_STATE_BYTES_256])
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_256; r++) {
        add_round_constant_q(state, GROSTL_COLS_256, r);
        sub_bytes_512(state);
        shift_bytes(state, GROSTL_COLS_256, SHIFT_Q512);
        mix_bytes(state, GROSTL_COLS_256);
    }
}

static void
permute_p1024(uint8_t state[GROSTL_STATE_BYTES_512])
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_p(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_P1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

static void
permute_q1024(uint8_t state[GROSTL_STATE_BYTES_512])
{
    for (uint8_t r = 0; r < GROSTL_ROUNDS_512; r++) {
        add_round_constant_q(state, GROSTL_COLS_512, r);
        sub_bytes_1024(state);
        shift_bytes(state, GROSTL_COLS_512, SHIFT_Q1024);
        mix_bytes(state, GROSTL_COLS_512);
    }
}

/* ================================================================
 * Compression function f(h, m) = P(h ⊕ m) ⊕ Q(m) ⊕ h  (spec §3.2).
 * ================================================================ */

static void
compress_512(uint8_t h[GROSTL_STATE_BYTES_256],
             const uint8_t m[GROSTL_STATE_BYTES_256])
{
    uint8_t p_in[GROSTL_STATE_BYTES_256];
    uint8_t q_in[GROSTL_STATE_BYTES_256];

    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }

    permute_p512(p_in);
    permute_q512(q_in);

    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    voleith_secure_zero(p_in, sizeof(p_in));
    voleith_secure_zero(q_in, sizeof(q_in));
}

static void
compress_1024(uint8_t h[GROSTL_STATE_BYTES_512],
              const uint8_t m[GROSTL_STATE_BYTES_512])
{
    uint8_t p_in[GROSTL_STATE_BYTES_512];
    uint8_t q_in[GROSTL_STATE_BYTES_512];

    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++) {
        p_in[i] = (uint8_t)(h[i] ^ m[i]);
        q_in[i] = m[i];
    }

    permute_p1024(p_in);
    permute_q1024(q_in);

    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    voleith_secure_zero(p_in, sizeof(p_in));
    voleith_secure_zero(q_in, sizeof(q_in));
}

/* ================================================================
 * Output transformation Ω(x) = trunc_n(P(x) ⊕ x)  (spec §3.3).
 *
 * The truncation takes the trailing n bits of the linear byte
 * representation - i.e. the last n/8 bytes of the state buffer.
 * ================================================================ */

static void
output_transform_256(uint8_t state[GROSTL_STATE_BYTES_256])
{
    uint8_t temp[GROSTL_STATE_BYTES_256];

    memcpy(temp, state, GROSTL_STATE_BYTES_256);
    permute_p512(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++)
        state[i] ^= temp[i];

    voleith_secure_zero(temp, sizeof(temp));
}

static void
output_transform_512(uint8_t state[GROSTL_STATE_BYTES_512])
{
    uint8_t temp[GROSTL_STATE_BYTES_512];

    memcpy(temp, state, GROSTL_STATE_BYTES_512);
    permute_p1024(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        state[i] ^= temp[i];

    voleith_secure_zero(temp, sizeof(temp));
}

/* ================================================================
 * Compression dispatch.  Selects 512- or 1024-bit compression based
 * on the context's state_bytes field.
 * ================================================================ */

static void
compress_block(voleith_grostl_ctx_t *ctx, const uint8_t *block)
{
    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        compress_512(ctx->state, block);
    else
        compress_1024(ctx->state, block);
}

/* ================================================================
 * Public API: init.
 *
 * IV per spec §3.5: the ℓ-bit big-endian representation of the
 * output bit length n.  For Grøstl-256 (ℓ=512, n=256), this is 56
 * zero bytes followed by the 8-byte big-endian encoding of 256
 * (= 0x00..00 01 00; byte 62 holds the 0x01).  For Grøstl-512
 * (ℓ=1024, n=512), 120 zero bytes followed by 0x00..00 02 00.
 * ================================================================ */

void
voleith_grostl256_init(voleith_grostl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_256;
    ctx->output_bytes = 32;
    ctx->rounds = GROSTL_ROUNDS_256;
    ctx->columns = GROSTL_COLS_256;
    /* IV: the 512-bit (= 64-byte) big-endian representation of n=256.
     * Bytes 0..61 are zero; bytes 62..63 = 0x01 0x00 give the
     * big-endian value 0x0100 = 256.  This sits in row 6 / row 7 of
     * column 7 in the state matrix (column-major). */
    ctx->state[62] = 0x01;
}

void
voleith_grostl512_init(voleith_grostl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_512;
    ctx->output_bytes = 64;
    ctx->rounds = GROSTL_ROUNDS_512;
    ctx->columns = GROSTL_COLS_512;
    /* IV: the 1024-bit (= 128-byte) big-endian representation of n=512.
     * Bytes 0..125 are zero; bytes 126..127 = 0x02 0x00 give the
     * big-endian value 0x0200 = 512. */
    ctx->state[126] = 0x02;
}

/* ================================================================
 * Public API: absorb.
 * ================================================================ */

void
voleith_grostl_absorb(voleith_grostl_ctx_t *ctx, const uint8_t *data,
                      size_t len)
{
    size_t block_size = ctx->state_bytes;
    size_t offset = 0;

    /* Fill any pending partial block first. */
    if (ctx->buf_len > 0) {
        size_t space = block_size - ctx->buf_len;
        size_t take = (len < space) ? len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        offset += take;
        if (ctx->buf_len == block_size) {
            compress_block(ctx, ctx->buf);
            ctx->block_count++;
            ctx->buf_len = 0;
        }
    }

    /* Process whole blocks straight from the caller's buffer. */
    while (len - offset >= block_size) {
        compress_block(ctx, data + offset);
        ctx->block_count++;
        offset += block_size;
    }

    /* Hold the remainder for the next call or finalize. */
    if (offset < len) {
        size_t rem = len - offset;
        memcpy(ctx->buf, data + offset, rem);
        ctx->buf_len = rem;
    }
}

/* ================================================================
 * Public API: finalize.
 *
 * Padding (spec §3.6): append the bit '1' (= 0x80 in byte-aligned
 * input), then enough zero bits to leave exactly 64 bits free, then
 * a 64-bit big-endian count of the total number of blocks in the
 * padded message.
 *
 * When the buffer already contains so much data that the bit '1'
 * plus the 64-bit length wouldn't fit in the current block, the
 * padding spans two blocks: the current block is filled with zeros
 * after the 0x80 and compressed, then a final block holding only
 * the length field is compressed.
 * ================================================================ */

void
voleith_grostl_finalize(voleith_grostl_ctx_t *ctx, uint8_t *out)
{
    size_t block_size = ctx->state_bytes;
    uint64_t total_blocks;

    /* Append the 0x80 byte (a '1' bit followed by seven '0' bits;
     * input is byte-aligned, so the partial-bit branch from the
     * spec is never taken here). */
    ctx->buf[ctx->buf_len++] = 0x80;

    /* If we can't fit the 8-byte length field in the current block,
     * zero-pad and compress, then start a fresh padding block. */
    if (ctx->buf_len > block_size - 8) {
        while (ctx->buf_len < block_size)
            ctx->buf[ctx->buf_len++] = 0x00;
        compress_block(ctx, ctx->buf);
        ctx->block_count++;
        ctx->buf_len = 0;
    }

    /* Zero-pad to the length-field position. */
    while (ctx->buf_len < block_size - 8)
        ctx->buf[ctx->buf_len++] = 0x00;

    /* Block count for the final, padded message includes this last
     * block we are about to compress. */
    total_blocks = ctx->block_count + 1;

    /* 64-bit big-endian length field. */
    for (int i = 0; i < 8; i++)
        ctx->buf[block_size - 1 - i] = (uint8_t)(total_blocks >> (8 * i));

    compress_block(ctx, ctx->buf);
    ctx->block_count++;

    /* Output transform Ω(h) = trunc_n(P(h) ⊕ h). */
    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        output_transform_256(ctx->state);
    else
        output_transform_512(ctx->state);

    /* Truncation: emit the trailing output_bytes bytes of the state. */
    memcpy(out, ctx->state + (ctx->state_bytes - ctx->output_bytes),
           ctx->output_bytes);
}

/* ================================================================
 * Public API: secure cleanup and one-shot wrappers.
 * ================================================================ */

void
voleith_grostl_clear(voleith_grostl_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}

void
voleith_grostl256(uint8_t out[32], const uint8_t *msg, size_t msg_len)
{
    voleith_grostl_ctx_t ctx;

    voleith_grostl256_init(&ctx);
    if (msg_len > 0)
        voleith_grostl_absorb(&ctx, msg, msg_len);
    voleith_grostl_finalize(&ctx, out);
    voleith_grostl_clear(&ctx);
}

void
voleith_grostl512(uint8_t out[64], const uint8_t *msg, size_t msg_len)
{
    voleith_grostl_ctx_t ctx;

    voleith_grostl512_init(&ctx);
    if (msg_len > 0)
        voleith_grostl_absorb(&ctx, msg, msg_len);
    voleith_grostl_finalize(&ctx, out);
    voleith_grostl_clear(&ctx);
}
