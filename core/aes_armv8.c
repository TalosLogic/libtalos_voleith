/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_armv8.c - AES-128/192/256 using the ARMv8 Cryptography Extension.
 *
 * Compiled only when VOLEITH_HAVE_ARMV8_AES is defined.  This TU is
 * always listed in VOLEITH_CORE_SOURCES but its entire content is
 * guarded so it compiles to an empty object when ARMv8 AES is absent.
 *
 * Public entry points use the aes_armv8_ prefix and are declared in
 * aes_armv8.h.
 */

#ifdef VOLEITH_HAVE_ARMV8_AES

#include "aes_armv8.h"
#include "aes_dispatch.h"

#include <arm_neon.h>
#include <string.h>

/* Static helper prototypes. */
static void armv8_subword(uint8_t[4], const uint8_t[4]);
static void key_expand_128_armv8(voleith_aes_ctx_t *, const uint8_t *);
static void key_expand_192_armv8(voleith_aes_ctx_t *, const uint8_t *);
static void key_expand_256_armv8(voleith_aes_ctx_t *, const uint8_t *);

/* ========================================================================
 * Key expansion helpers
 * ======================================================================== */

/*
 * Constant-time SubWord for key expansion.
 *
 * Places the 4 input bytes in AES state column 0, applies AESE with a zero
 * round key (which performs SubBytes then ShiftRows), then extracts the
 * substituted bytes from their post-ShiftRows positions:
 *
 *   (row 0, col 0) stays at index 0
 *   (row 1, col 0) moves to (row 1, col 3) = index 1 + 4*3 = 13
 *   (row 2, col 0) moves to (row 2, col 2) = index 2 + 4*2 = 10
 *   (row 3, col 0) moves to (row 3, col 1) = index 3 + 4*1 = 7
 *
 * Constant-time because AESE uses hardware S-box logic with no
 * cache-indexed table lookups.
 */
static void
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

/* ========================================================================
 * Per-key-size expansion
 * ======================================================================== */

static void
key_expand_128_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->storage, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->storage[4 * (i - 1)], 4);
        if (i % 4 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 4];
        }
        ctx->storage[4 * i + 0] = ctx->storage[4 * (i - 4) + 0] ^ temp[0];
        ctx->storage[4 * i + 1] = ctx->storage[4 * (i - 4) + 1] ^ temp[1];
        ctx->storage[4 * i + 2] = ctx->storage[4 * (i - 4) + 2] ^ temp[2];
        ctx->storage[4 * i + 3] = ctx->storage[4 * (i - 4) + 3] ^ temp[3];
    }
    ctx->nr = 10;
}

static void
key_expand_192_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->storage, key, 24);
    for (int i = 6; i < 52; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->storage[4 * (i - 1)], 4);
        if (i % 6 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 6];
        }
        ctx->storage[4 * i + 0] = ctx->storage[4 * (i - 6) + 0] ^ temp[0];
        ctx->storage[4 * i + 1] = ctx->storage[4 * (i - 6) + 1] ^ temp[1];
        ctx->storage[4 * i + 2] = ctx->storage[4 * (i - 6) + 2] ^ temp[2];
        ctx->storage[4 * i + 3] = ctx->storage[4 * (i - 6) + 3] ^ temp[3];
    }
    ctx->nr = 12;
}

static void
key_expand_256_armv8(voleith_aes_ctx_t *ctx, const uint8_t *key)
{
    memcpy(ctx->storage, key, 32);
    for (int i = 8; i < 60; i++) {
        uint8_t temp[4];
        memcpy(temp, &ctx->storage[4 * (i - 1)], 4);
        if (i % 8 == 0) {
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            armv8_subword(temp, temp);
            temp[0] ^= ARMV8_RCON[i / 8];
        } else if (i % 8 == 4) {
            /* AES-256 extra SubWord (no RotWord, no Rcon). */
            armv8_subword(temp, temp);
        }
        ctx->storage[4 * i + 0] = ctx->storage[4 * (i - 8) + 0] ^ temp[0];
        ctx->storage[4 * i + 1] = ctx->storage[4 * (i - 8) + 1] ^ temp[1];
        ctx->storage[4 * i + 2] = ctx->storage[4 * (i - 8) + 2] ^ temp[2];
        ctx->storage[4 * i + 3] = ctx->storage[4 * (i - 8) + 3] ^ temp[3];
    }
    ctx->nr = 14;
}

/* ========================================================================
 * Public entry points
 * ======================================================================== */

int
aes_armv8_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key, int key_bits)
{
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
    ctx->backend_tag = VOLEITH_AES_BACKEND_ARMV8;
    return 0;
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
void
aes_armv8_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
                  const uint8_t in[16])
{
    const uint8_t *rk = ctx->storage;
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
void
aes_armv8_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                     const uint8_t in[64])
{
    const uint8_t *rk = ctx->storage;
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

const voleith_aes_ops_t voleith_aes_ops_armv8 = {
    .key_expand = aes_armv8_key_expand,
    .encrypt = aes_armv8_encrypt,
    .encrypt_x4 = aes_armv8_encrypt_x4,
    .backend_tag = VOLEITH_AES_BACKEND_ARMV8,
    .name = "armv8",
};

#endif /* VOLEITH_HAVE_ARMV8_AES */
