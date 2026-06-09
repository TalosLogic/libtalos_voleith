/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_aesni.c - AES-128/192/256 using Intel AES-NI intrinsics.
 *
 * Compiled only when VOLEITH_HAVE_AES_NI is defined.  This TU is
 * always listed in VOLEITH_CORE_SOURCES but its entire content is
 * guarded so it compiles to an empty object when AES-NI is absent.
 *
 * Public entry points use the aes_aesni_ prefix and are declared in
 * aes_aesni.h.
 */

#ifdef VOLEITH_HAVE_AES_NI

#include "aes_aesni.h"
#include "aes_dispatch.h"

#include <smmintrin.h>
#include <wmmintrin.h>

/* Static helper prototypes. */
static __m128i aesni_key_expand_128(__m128i, __m128i);
static void aesni_key_expand_192(__m128i *, __m128i *, __m128i);
static __m128i aesni_key_expand_256_a(__m128i, __m128i);
static __m128i aesni_key_expand_256_b(__m128i, __m128i);
static void key_expand_128_ni(voleith_aes_ctx_t *, const uint8_t *);
static void key_expand_192_ni(voleith_aes_ctx_t *, const uint8_t *);
static void key_expand_256_ni(voleith_aes_ctx_t *, const uint8_t *);
static void encrypt_ni(const voleith_aes_ctx_t *, uint8_t[16],
                       const uint8_t[16]);

/* ========================================================================
 * Key expansion helpers
 * ======================================================================== */

/* AES-128 key expansion assist. */
static inline __m128i
aesni_key_expand_128(__m128i key, __m128i keygen)
{
    keygen = _mm_shuffle_epi32(keygen, 0xff);
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

/* AES-192 key expansion - processes 2 rounds at a time. */
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

/* AES-256 key expansion helpers (two halves). */
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

/* ========================================================================
 * Per-key-size expansion
 * ======================================================================== */

static void
key_expand_128_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    __m128i *rk = (__m128i *)ctx->storage;
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

static void
key_expand_192_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    /*
     * AES-192 key schedule produces 13 round keys (52 words).
     * Key is 24 bytes = 6 words; processed 6 words at a time
     * (k1 = first 4 words, k2 = last 2 words in low 64 bits).
     * Round keys are stored as a flat byte array because they
     * overlap __m128i boundaries.
     */
    __m128i k1 = _mm_loadu_si128((const __m128i *)key);
    __m128i k2 = _mm_set_epi64x(0, *(const uint64_t *)(key + 16));

    uint8_t *rk = ctx->storage;
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

static void
key_expand_256_ni(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    __m128i *rk = (__m128i *)ctx->storage;
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

    /* Final round: only the first half. */
    k1 = aesni_key_expand_256_a(k1, _mm_aeskeygenassist_si128(k2, 0x40));
    rk[14] = k1;

#undef EXPAND256
}

/* ========================================================================
 * Single-block encrypt
 * ======================================================================== */

static void
encrypt_ni(const voleith_aes_ctx_t *ctx, uint8_t out[16], const uint8_t in[16])
{
    const __m128i *rk = (const __m128i *)ctx->storage;
    __m128i state = _mm_loadu_si128((const __m128i *)in);

    state = _mm_xor_si128(state, _mm_loadu_si128(&rk[0]));

    for (int i = 1; i < ctx->nr; i++)
        state = _mm_aesenc_si128(state, _mm_loadu_si128(&rk[i]));

    state = _mm_aesenclast_si128(state, _mm_loadu_si128(&rk[ctx->nr]));

    _mm_storeu_si128((__m128i *)out, state);
}

/* ========================================================================
 * Public entry points
 * ======================================================================== */

int
aes_aesni_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
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
    ctx->backend_tag = VOLEITH_AES_BACKEND_AESNI;
    return 0;
}

void
aes_aesni_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
                  const uint8_t in[16])
{
    encrypt_ni(ctx, out, in);
}

/*
 * 4-block batched encrypt.
 *
 * AES-NI does not have a native 4-block parallel path; chain four
 * single-block calls.  The uniform voleith_aes_encrypt_x4 API allows
 * the PRG to amortize its per-call overhead uniformly across backends.
 */
void
aes_aesni_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                     const uint8_t in[64])
{
    encrypt_ni(ctx, out + 0, in + 0);
    encrypt_ni(ctx, out + 16, in + 16);
    encrypt_ni(ctx, out + 32, in + 32);
    encrypt_ni(ctx, out + 48, in + 48);
}

const voleith_aes_ops_t voleith_aes_ops_aesni = {
    .key_expand = aes_aesni_key_expand,
    .encrypt = aes_aesni_encrypt,
    .encrypt_x4 = aes_aesni_encrypt_x4,
    .backend_tag = VOLEITH_AES_BACKEND_AESNI,
    .name = "aesni",
};

#endif /* VOLEITH_HAVE_AES_NI */
