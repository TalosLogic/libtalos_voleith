/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.c - AES-128/192/256 encrypt with backend dispatch.
 *
 * Backend priority (compile-time, by macro):
 *   VOLEITH_HAVE_AES_NI            : Intel AES-NI intrinsics.
 *   VOLEITH_ALLOW_VARIABLE_TIME_AES: FIPS 197 table-lookup software.
 *                                     Off by default; test/debug only.
 *   (none of the above)            : Bitsliced (core/aes_ct64.c), the
 *                                     unconditional portable fallback.
 *
 * See docs/AES_MIGRATION_PLAN.md for the rationale and migration
 * order, and docs/SECURITY_REVIEW.md C-1 for why the variable-time
 * path is now gated off (cache-timing side channel on secret keys).
 */

#include "aes.h"
#include "util.h"
#include <string.h>

/* When neither hardware AES nor the variable-time path is selected,
 * the bitsliced backend services every voleith_aes_* call. */
#if !defined(VOLEITH_HAVE_AES_NI) && !defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
#include "aes_ct64.h"
#endif

/*
 * CI-detectable single-line build-time notice when no hardware AES
 * backend is active.  Greppable by build pipelines via the literal
 * prefix "voleith:".  Uses #pragma message rather than #warning so
 * it does not break -Werror builds on platforms where the bitsliced
 * fallback is the correct production choice (ARM without crypto
 * extension, RISC-V, etc.).
 *
 * The variable-time path triggers its own loud CMake warning when
 * VOLEITH_ALLOW_VARIABLE_TIME_AES is set; no separate compile-time
 * notice needed here.
 */
#if !defined(VOLEITH_HAVE_AES_NI) && !defined(VOLEITH_HAVE_ARMV8_AES) &&       \
    !defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
#if defined(__GNUC__) || defined(__clang__)
#pragma message("voleith: AES backend = bitsliced software fallback "          \
                "(no AES-NI / ARMv8 Crypto Extension detected). "              \
                "Constant-time but ~30-50x slower than hardware AES. "         \
                "If targeting x86_64 or aarch64 with HW AES, verify "          \
                "the appropriate compile flags are set.")
#endif
#endif

#if defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)

/* ========================================================================
 * Variable-time software path - FIPS 197 table-lookup AES.
 *
 * This entire path is gated off by default because the SBOX[] lookups
 * are indexed by secret state/key bytes, creating a cache-timing side
 * channel.  Enable VOLEITH_ALLOW_VARIABLE_TIME_AES only for differential
 * testing or NIST-spec-reference inspection - never for production.
 * ======================================================================== */

/* AES S-box (FIPS 197 Table 4) */
static const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

/* Round constants (FIPS 197 Table 5) - Rcon[i] = {x^(i-1), 00, 00, 00} */
static const uint8_t RCON[11] = {
    0x00, /* unused index 0 */
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* ========================================================================
 * Software helpers
 * ======================================================================== */

/* xtime: multiply by x (i.e., {02}) in GF(2^8) with modulus m(x) */
static inline uint8_t
xtime(uint8_t b)
{
    return (uint8_t)((b << 1) ^ (((b >> 7) & 1) * 0x1b));
}

/* Multiply two bytes in GF(2^8) - used only in MixColumns with small constants */
static inline uint8_t
gf_mul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    uint8_t t = a;
    for (int i = 0; i < 8; i++) {
        if (b & 1)
            r ^= t;
        t = xtime(t);
        b >>= 1;
    }
    return r;
}

/* ========================================================================
 * Software key expansion (FIPS 197 Algorithm 2)
 * ======================================================================== */

static void
key_expand_soft(voleith_aes_ctx_t *ctx, const uint8_t *key, int nk, int nr)
{
    int total_words = 4 * (nr + 1);

    /* w[i] stored as bytes: w[i] = rk[4*i .. 4*i+3] */
    /* First Nk words are the key itself */
    memcpy(ctx->rk, key, (size_t)(4 * nk));

    for (int i = nk; i < total_words; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->rk[4 * (i - 1)], 4);

        if (i % nk == 0) {
            /* RotWord + SubWord + Rcon */
            uint8_t t0 = temp[0];
            temp[0] = SBOX[temp[1]] ^ RCON[i / nk];
            temp[1] = SBOX[temp[2]];
            temp[2] = SBOX[temp[3]];
            temp[3] = SBOX[t0];
        } else if (nk > 6 && i % nk == 4) {
            /* AES-256 extra SubWord */
            temp[0] = SBOX[temp[0]];
            temp[1] = SBOX[temp[1]];
            temp[2] = SBOX[temp[2]];
            temp[3] = SBOX[temp[3]];
        }

        ctx->rk[4 * i + 0] = ctx->rk[4 * (i - nk) + 0] ^ temp[0];
        ctx->rk[4 * i + 1] = ctx->rk[4 * (i - nk) + 1] ^ temp[1];
        ctx->rk[4 * i + 2] = ctx->rk[4 * (i - nk) + 2] ^ temp[2];
        ctx->rk[4 * i + 3] = ctx->rk[4 * (i - nk) + 3] ^ temp[3];
    }
}

/* ========================================================================
 * Software encrypt (FIPS 197 Algorithm 1)
 * ======================================================================== */

static void
encrypt_soft(const voleith_aes_ctx_t *ctx, uint8_t out[16],
             const uint8_t in[16])
{
    uint8_t s[16];
    memcpy(s, in, 16);

    /* Initial AddRoundKey */
    for (int i = 0; i < 16; i++)
        s[i] ^= ctx->rk[i];

    for (int round = 1; round <= ctx->nr; round++) {
        const uint8_t *rk = &ctx->rk[round * 16];
        uint8_t t[16];

        /* SubBytes + ShiftRows combined */
        t[0] = SBOX[s[0]];
        t[1] = SBOX[s[5]];
        t[2] = SBOX[s[10]];
        t[3] = SBOX[s[15]];
        t[4] = SBOX[s[4]];
        t[5] = SBOX[s[9]];
        t[6] = SBOX[s[14]];
        t[7] = SBOX[s[3]];
        t[8] = SBOX[s[8]];
        t[9] = SBOX[s[13]];
        t[10] = SBOX[s[2]];
        t[11] = SBOX[s[7]];
        t[12] = SBOX[s[12]];
        t[13] = SBOX[s[1]];
        t[14] = SBOX[s[6]];
        t[15] = SBOX[s[11]];

        if (round < ctx->nr) {
            /* MixColumns (FIPS 197 Eq 5.8) + AddRoundKey */
            for (int c = 0; c < 4; c++) {
                uint8_t b0 = t[4 * c + 0], b1 = t[4 * c + 1];
                uint8_t b2 = t[4 * c + 2], b3 = t[4 * c + 3];
                s[4 * c + 0] = gf_mul(0x02, b0) ^ gf_mul(0x03, b1) ^ b2 ^ b3 ^
                               rk[4 * c + 0];
                s[4 * c + 1] = b0 ^ gf_mul(0x02, b1) ^ gf_mul(0x03, b2) ^ b3 ^
                               rk[4 * c + 1];
                s[4 * c + 2] = b0 ^ b1 ^ gf_mul(0x02, b2) ^ gf_mul(0x03, b3) ^
                               rk[4 * c + 2];
                s[4 * c + 3] = gf_mul(0x03, b0) ^ b1 ^ b2 ^ gf_mul(0x02, b3) ^
                               rk[4 * c + 3];
            }
        } else {
            /* Final round: no MixColumns, just AddRoundKey */
            for (int i = 0; i < 16; i++)
                s[i] = t[i] ^ rk[i];
        }
    }

    memcpy(out, s, 16);
}

#endif /* VOLEITH_ALLOW_VARIABLE_TIME_AES */

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
#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    int nk, nr;

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
    ctx->nr = nr;
    key_expand_soft(ctx, key, nk, nr);
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
#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    encrypt_soft(ctx, out, in);
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
 * AES-NI / variable-time: chain four single-block encrypts.  No
 * speed benefit, but a uniform public API lets the PRG amortize
 * its per-call overhead uniformly.
 */
void
voleith_aes_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                       const uint8_t in[64])
{
#if !defined(VOLEITH_HAVE_AES_NI) && !defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    aes_ct64_encrypt_x4(ctx, out, in);
#else
    voleith_aes_encrypt(ctx, out + 0, in + 0);
    voleith_aes_encrypt(ctx, out + 16, in + 16);
    voleith_aes_encrypt(ctx, out + 32, in + 32);
    voleith_aes_encrypt(ctx, out + 48, in + 48);
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
#elif defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    return VOLEITH_AES_BACKEND_VARIABLE_TIME;
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
    case VOLEITH_AES_BACKEND_VARIABLE_TIME:
        return "variable-time table-lookup "
               "(TEST/DEBUG only - cache-timing side channel)";
    }
    return "unknown";
}
