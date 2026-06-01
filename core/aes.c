/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.c - AES-128/192/256 encrypt with backend dispatch.
 *
 * Backend priority (compile-time, by macro):
 *   VOLEITH_HAVE_AES_NI    : Intel AES-NI intrinsics.
 *   VOLEITH_HAVE_ARMV8_AES : ARMv8 Cryptography Extension intrinsics.
 *   (none of the above)    : Bitsliced (core/aes_ct64.c), the
 *                            unconditional portable fallback.
 *
 * All backends are constant-time.
 */

#include "aes.h"
#include "util.h"
#include <string.h>

/* When no hardware AES backend is selected, the bitsliced backend
 * services every voleith_aes_* call. */
#if !defined(VOLEITH_HAVE_AES_NI) && !defined(VOLEITH_HAVE_ARMV8_AES)
#include "aes_ct64.h"
#endif

/*
 * CI-detectable single-line build-time notice when no hardware AES
 * backend is active.  Greppable by build pipelines via the literal
 * prefix "voleith:".  Uses #pragma message rather than #warning so
 * it does not break -Werror builds on platforms where the bitsliced
 * fallback is the correct production choice (RISC-V, etc.).
 */
#if !defined(VOLEITH_HAVE_AES_NI) && !defined(VOLEITH_HAVE_ARMV8_AES)
#if defined(__GNUC__) || defined(__clang__)
#pragma message("voleith: AES backend = bitsliced software fallback "          \
                "(no AES-NI / ARMv8 Crypto Extension detected). "              \
                "Constant-time but ~30-50x slower than hardware AES. "         \
                "If targeting x86_64 or aarch64 with HW AES, verify "          \
                "the appropriate compile flags are set.")
#endif
#endif

/* ========================================================================
 * AES-NI implementation
 * ======================================================================== */

#ifdef VOLEITH_HAVE_AES_NI

#include <wmmintrin.h>
#include <smmintrin.h>

/* Helper: AES-128 key expansion assist */
static inline __m128i
aesni_key_expand_128(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xff);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static void
key_expand_128_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    __m128i *rk = (__m128i *)ctx->rk;
    __m128i k = _mm_loadu_si128((const __m128i *)key);
    rk[0] = k;

#define EXPAND128(i, rcon)                                                     \
    k = aesni_key_expand_128(k, _mm_aeskeygenassist_si128(k, rcon));           \
    rk[i] = k;

    EXPAND128(1, 0x01);
    EXPAND128(2, 0x02);
    EXPAND128(3, 0x04);
    EXPAND128(4, 0x08);
    EXPAND128(5, 0x10);
    EXPAND128(6, 0x20);
    EXPAND128(7, 0x40);
    EXPAND128(8, 0x80);
    EXPAND128(9, 0x1b);
    EXPAND128(10, 0x36);

#undef EXPAND128
}

/* Helper: AES-192 key expansion - processes 2 rounds at a time */
static inline void
aesni_key_expand_192(__m128i *k1, __m128i *k2, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0x55);
    __m128i t = _mm_slli_si128(*k1, 4);
    *k1 = _mm_xor_si128(*k1, t);
    t = _mm_slli_si128(t, 4);
    *k1 = _mm_xor_si128(*k1, t);
    t = _mm_slli_si128(t, 4);
    *k1 = _mm_xor_si128(*k1, t);
    *k1 = _mm_xor_si128(*k1, keygen);

    keygen = _mm_shuffle_epi32(*k1, 0xff);
    t = _mm_slli_si128(*k2, 4);
    *k2 = _mm_xor_si128(*k2, t);
    *k2 = _mm_xor_si128(*k2, keygen);
}

static void
key_expand_192_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    /*
     * AES-192 key schedule produces 13 round keys (52 words).
     * Key is 24 bytes = 6 words. We process 6 words at a time
     * (k1 = first 4 words, k2 = last 2 words in low 64 bits).
     */
    __m128i k1 = _mm_loadu_si128((const __m128i *)key);
    __m128i k2 = _mm_set_epi64x(0, *(const uint64_t *)(key + 16));

    /* Store into rk as a flat byte array - round keys overlap __m128i boundaries */
    /* We store 52 words = 208 bytes */
    uint8_t *rk = ctx->rk;
    _mm_storeu_si128((__m128i *)(rk + 0), k1);
    _mm_storel_epi64((__m128i *)(rk + 16), k2);

#define EXPAND192(rcon, offset)                                                \
    do {                                                                       \
        aesni_key_expand_192(&k1, &k2, _mm_aeskeygenassist_si128(k2, rcon));   \
        _mm_storeu_si128((__m128i *)(rk + (offset)), k1);                      \
        _mm_storel_epi64((__m128i *)(rk + (offset) + 16), k2);                 \
    } while (0)

    EXPAND192(0x01, 24);
    EXPAND192(0x02, 48);
    EXPAND192(0x04, 72);
    EXPAND192(0x08, 96);
    EXPAND192(0x10, 120);
    EXPAND192(0x20, 144);
    EXPAND192(0x40, 168);
    EXPAND192(0x80, 192);

#undef EXPAND192
}

/* Helper: AES-256 key expansion */
static inline __m128i
aesni_key_expand_256_a(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xff);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static inline __m128i
aesni_key_expand_256_b(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xaa);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static void
key_expand_256_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    __m128i *rk = (__m128i *)ctx->rk;
    __m128i k1 = _mm_loadu_si128((const __m128i *)key);
    __m128i k2 = _mm_loadu_si128((const __m128i *)(key + 16));
    rk[0] = k1;
    rk[1] = k2;

#define EXPAND256(i, rcon)                                                     \
    do {                                                                       \
        k1 = aesni_key_expand_256_a(k1, _mm_aeskeygenassist_si128(k2, rcon));  \
        rk[2 * (i)] = k1;                                                      \
        k2 = aesni_key_expand_256_b(k2, _mm_aeskeygenassist_si128(k1, 0));     \
        rk[2 * (i) + 1] = k2;                                                  \
    } while (0)

    EXPAND256(1, 0x01);
    EXPAND256(2, 0x02);
    EXPAND256(3, 0x04);
    EXPAND256(4, 0x08);
    EXPAND256(5, 0x10);
    EXPAND256(6, 0x20);

    /* Final round: only the first half */
    k1 = aesni_key_expand_256_a(k1, _mm_aeskeygenassist_si128(k2, 0x40));
    rk[14] = k1;

#undef EXPAND256
}

static void
encrypt_ni(const voleith_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    const __m128i *rk = (const __m128i *)ctx->rk;
    __m128i state = _mm_loadu_si128((const __m128i *)in);

    state = _mm_xor_si128(state, _mm_loadu_si128(&rk[0]));

    for (int i = 1; i < ctx->nr; i++)
        state = _mm_aesenc_si128(state, _mm_loadu_si128(&rk[i]));

    state = _mm_aesenclast_si128(state, _mm_loadu_si128(&rk[ctx->nr]));

    _mm_storeu_si128((__m128i *)out, state);
}

#endif /* VOLEITH_HAVE_AES_NI */

/* ========================================================================
 * ARMv8 Crypto Extension implementation
 * ======================================================================== */

#ifdef VOLEITH_HAVE_ARMV8_AES

#include <arm_neon.h>

/*
 * Constant-time SubWord for key expansion.
 *
 * Places the 4 input bytes in AES state column 0, applies AESE with a zero
 * round key (which performs SubBytes then ShiftRows), then extracts the
 * substituted bytes from their post-ShiftRows positions:
 *
 *   (row 0, col 0) → stays at index 0
 *   (row 1, col 0) → moves to (row 1, col 3) → index 1 + 4*3 = 13
 *   (row 2, col 0) → moves to (row 2, col 2) → index 2 + 4*2 = 10
 *   (row 3, col 0) → moves to (row 3, col 1) → index 3 + 4*1 = 7
 *
 * This is constant-time because AESE uses hardware S-box logic with no
 * cache-indexed table lookups.
 */
static inline void
armv8_subword(uint8_t out[4], const uint8_t in[4])
{
    uint8x16_t state = vdupq_n_u8(0);
    state = vsetq_lane_u8(in[0], state, 0);
    state = vsetq_lane_u8(in[1], state, 1);
    state = vsetq_lane_u8(in[2], state, 2);
    state = vsetq_lane_u8(in[3], state, 3);
    state = vaeseq_u8(state, vdupq_n_u8(0));
    out[0] = vgetq_lane_u8(state, 0);
    out[1] = vgetq_lane_u8(state, 13);
    out[2] = vgetq_lane_u8(state, 10);
    out[3] = vgetq_lane_u8(state, 7);
}

/* Round constants (FIPS 197 Table 5) - public values, not secret. */
static const uint8_t ARMV8_RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

static void
key_expand_128_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->rk[4 * (i - 1)], 4);
        if (i % 4 == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            /* SubWord (constant-time via AESE) */
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 4];
        }
        ctx->rk[4 * i + 0] = ctx->rk[4 * (i - 4) + 0] ^ temp[0];
        ctx->rk[4 * i + 1] = ctx->rk[4 * (i - 4) + 1] ^ temp[1];
        ctx->rk[4 * i + 2] = ctx->rk[4 * (i - 4) + 2] ^ temp[2];
        ctx->rk[4 * i + 3] = ctx->rk[4 * (i - 4) + 3] ^ temp[3];
    }
    ctx->nr = 10;
}

static void
key_expand_192_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->rk, key, 24);
    for (int i = 6; i < 52; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->rk[4 * (i - 1)], 4);
        if (i % 6 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 6];
        }
        ctx->rk[4 * i + 0] = ctx->rk[4 * (i - 6) + 0] ^ temp[0];
        ctx->rk[4 * i + 1] = ctx->rk[4 * (i - 6) + 1] ^ temp[1];
        ctx->rk[4 * i + 2] = ctx->rk[4 * (i - 6) + 2] ^ temp[2];
        ctx->rk[4 * i + 3] = ctx->rk[4 * (i - 6) + 3] ^ temp[3];
    }
    ctx->nr = 12;
}

static void
key_expand_256_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->rk, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->rk[4 * (i - 1)], 4);
        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 8];
        } else if (i % 8 == 4) {
            /* AES-256 extra SubWord (no RotWord, no Rcon) */
            armv8_subword(temp, temp);
        }
        ctx->rk[4 * i + 0] = ctx->rk[4 * (i - 8) + 0] ^ temp[0];
        ctx->rk[4 * i + 1] = ctx->rk[4 * (i - 8) + 1] ^ temp[1];
        ctx->rk[4 * i + 2] = ctx->rk[4 * (i - 8) + 2] ^ temp[2];
        ctx->rk[4 * i + 3] = ctx->rk[4 * (i - 8) + 3] ^ temp[3];
    }
    ctx->nr = 14;
}

/*
 * Single-block encrypt.
 *
 * The ARM Crypto Extension AESE instruction computes:
 *   ShiftRows(SubBytes(state XOR round_key))
 * followed by AESMC for MixColumns.  This means the round key is consumed
 * at the START of each iteration, matching the "equivalent cipher"
 * representation: rounds 0..nr-2 are AESMC(AESE(s, rk[i])) and the final
 * round is AESE(s, rk[nr-1]) XOR rk[nr].  The standard FIPS 197 key
 * schedule byte array is used without modification.
 */
static void
encrypt_armv8(const voleith_aes_ctx_t *ctx, uint8_t out[16],
              const uint8_t in[16])
{
    const uint8_t *rk = ctx->rk;
    uint8x16_t s = vld1q_u8(in);

    for (int i = 0; i < ctx->nr - 1; i++) {
        uint8x16_t k = vld1q_u8(rk + 16 * i);
        s = vaesmcq_u8(vaeseq_u8(s, k));
    }
    s = vaeseq_u8(s, vld1q_u8(rk + 16 * (ctx->nr - 1)));
    s = veorq_u8(s, vld1q_u8(rk + 16 * ctx->nr));

    vst1q_u8(out, s);
}

/*
 * 4-block interleaved encrypt.
 *
 * Interleaving four independent encryption streams lets the CPU issue
 * AESE/AESMC pairs for all four blocks simultaneously, hiding the 2-3
 * cycle latency of each instruction behind the others.  Throughput for
 * AES-CTR mode (used by the PRG) increases roughly 4x over four serial
 * single-block calls.
 */
static void
encrypt_x4_armv8(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                 const uint8_t in[64])
{
    const uint8_t *rk = ctx->rk;
    uint8x16_t s0 = vld1q_u8(in + 0);
    uint8x16_t s1 = vld1q_u8(in + 16);
    uint8x16_t s2 = vld1q_u8(in + 32);
    uint8x16_t s3 = vld1q_u8(in + 48);

    for (int i = 0; i < ctx->nr - 1; i++) {
        uint8x16_t k = vld1q_u8(rk + 16 * i);
        s0 = vaesmcq_u8(vaeseq_u8(s0, k));
        s1 = vaesmcq_u8(vaeseq_u8(s1, k));
        s2 = vaesmcq_u8(vaeseq_u8(s2, k));
        s3 = vaesmcq_u8(vaeseq_u8(s3, k));
    }
    uint8x16_t kp = vld1q_u8(rk + 16 * (ctx->nr - 1));
    uint8x16_t kl = vld1q_u8(rk + 16 * ctx->nr);
    vst1q_u8(out + 0, veorq_u8(vaeseq_u8(s0, kp), kl));
    vst1q_u8(out + 16, veorq_u8(vaeseq_u8(s1, kp), kl));
    vst1q_u8(out + 32, veorq_u8(vaeseq_u8(s2, kp), kl));
    vst1q_u8(out + 48, veorq_u8(vaeseq_u8(s3, kp), kl));
}

#endif /* VOLEITH_HAVE_ARMV8_AES */

/* ========================================================================
 * Public API
 * ======================================================================== */

int
voleith_aes_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
#if defined(VOLEITH_HAVE_AES_NI)
    int nr;
    switch (key_bits) {
    case 128:
        nr = 10;
        break;
    case 192:
        nr = 12;
        break;
    case 256:
        nr = 14;
        break;
    default:
        return -1;
    }
    ctx->nr = nr;
    switch (key_bits) {
    case 128:
        key_expand_128_ni(ctx, key);
        break;
    case 192:
        key_expand_192_ni(ctx, key);
        break;
    case 256:
        key_expand_256_ni(ctx, key);
        break;
    }
    return 0;
#elif defined(VOLEITH_HAVE_ARMV8_AES)
    switch (key_bits) {
    case 128:
        key_expand_128_armv8(ctx, key);
        break;
    case 192:
        key_expand_192_armv8(ctx, key);
        break;
    case 256:
        key_expand_256_armv8(ctx, key);
        break;
    default:
        return -1;
    }
    return 0;
#else
    return aes_ct64_key_expand(ctx, key, key_bits);
#endif
}

void
voleith_aes_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
                    const uint8_t in[16])
{
#if defined(VOLEITH_HAVE_AES_NI)
    encrypt_ni(ctx, out, in);
#elif defined(VOLEITH_HAVE_ARMV8_AES)
    encrypt_armv8(ctx, out, in);
#else
    aes_ct64_encrypt(ctx, out, in);
#endif
}

/*
 * 4-block batched encrypt.
 *
 * Bitsliced: one engine invocation processes all four blocks in
 * parallel; the speed win over four single-block calls is roughly
 * 4x and the primary reason voleith_aes_encrypt_x4 exists.
 *
 * AES-NI: chain four single-block encrypts.  No speed benefit, but
 * a uniform public API lets the PRG amortize its per-call overhead
 * uniformly.
 */
void
voleith_aes_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                       const uint8_t in[64])
{
#if defined(VOLEITH_HAVE_ARMV8_AES)
    encrypt_x4_armv8(ctx, out, in);
#elif defined(VOLEITH_HAVE_AES_NI)
    voleith_aes_encrypt(ctx, out + 0, in + 0);
    voleith_aes_encrypt(ctx, out + 16, in + 16);
    voleith_aes_encrypt(ctx, out + 32, in + 32);
    voleith_aes_encrypt(ctx, out + 48, in + 48);
#else
    aes_ct64_encrypt_x4(ctx, out, in);
#endif
}

void
voleith_aes_ctx_clear(voleith_aes_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}

voleith_aes_backend_t
voleith_aes_backend(void)
{
#if defined(VOLEITH_HAVE_AES_NI)
    return VOLEITH_AES_BACKEND_AESNI;
#elif defined(VOLEITH_HAVE_ARMV8_AES)
    return VOLEITH_AES_BACKEND_ARMV8;
#else
    return VOLEITH_AES_BACKEND_BITSLICED;
#endif
}

const char *
voleith_aes_backend_name(void)
{
    switch (voleith_aes_backend()) {
    case VOLEITH_AES_BACKEND_AESNI:
        return "AES-NI (x86_64 hardware)";
    case VOLEITH_AES_BACKEND_ARMV8:
        return "ARMv8 Cryptography Extension (aarch64 hardware)";
    case VOLEITH_AES_BACKEND_BITSLICED:
        return "bitsliced (portable constant-time software)";
    }
    return "unknown";
}
