/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * prg.c - Tweakable PRG from AES-CTR (FAEST spec Figure 3.6)
 *
 * PRG(sd, iv, twk; m):
 *   1. key_bar = AES-lambda.KeyExpansion(sd)
 *   2. iv' = AddToUpperWord(iv, twk)
 *   3. for i in [0..h):
 *        s_i = AES-lambda.Encrypt(key_bar, AddToLowerWord(iv', i))
 *   4. return s_0 || ... || s_{h-2} || s_{h-1}[0..rem-1]
 *
 * where h = floor(m/128), rem = m - 128*h.
 * If rem > 0, one extra block s_h is generated and truncated to rem bits.
 *
 * AddToUpperWord: adds twk to iv[12..15] (upper 32 bits, little-endian)
 * AddToLowerWord: adds counter i to iv[0..3] (lower 32 bits, little-endian)
 */

#include "prg.h"
#include "util.h"
#include "ichor_compat.h" /* compile-time guard on the vendored ichor version */
#include <string.h>

int
voleith_prg_init(voleith_prg_ctx_t *ctx, const uint8_t *seed, int lambda)
{
    ctx->lambda = lambda;
    return voleith_aes_key_expand(&ctx->aes, seed, lambda);
}

/* Load 32-bit little-endian from buffer */
static inline uint32_t
load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

/* Store 32-bit little-endian to buffer */
static inline void
store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

/*
 * Build count consecutive CTR-mode input blocks into in_w, using the supplied
 * iv' template and the absolute counter value (lower_base + i + b) for each
 * block.  count is at most VOLEITH_AES_WIDE_MAX.
 */
static void
build_ctr_wide(uint8_t *in_w, const uint8_t iv_tweaked[16], uint32_t lower_base,
               size_t i, unsigned count)
{
    for (unsigned b = 0; b < count; b++) {
        uint8_t *blk = in_w + 16 * b;
        memcpy(blk, iv_tweaked, 16);
        store_le32(blk, (uint32_t)(lower_base + (uint32_t)(i + (size_t)b)));
    }
}

void
voleith_prg_gen(const voleith_prg_ctx_t *ctx, uint8_t *out,
                const uint8_t iv[16], uint32_t twk, size_t m)
{
    if (m == 0)
        return;

    /* Compute iv' = AddToUpperWord(iv, twk) */
    uint8_t iv_tweaked[16];
    memcpy(iv_tweaked, iv, 16);
    uint32_t upper = load_le32(iv_tweaked + 12);
    upper = (upper + twk) & 0xFFFFFFFF;
    store_le32(iv_tweaked + 12, upper);

    /* Number of full 128-bit blocks and remaining bits */
    size_t full_blocks = m / 128;
    size_t rem_bits = m % 128;

    /* Base lower 32 bits for counter */
    uint32_t lower_base = load_le32(iv_tweaked);

    /*
     * Generate the full blocks in batches of up to VOLEITH_AES_WIDE_MAX via the
     * width-agnostic batch entry point.  The active backend chooses how to
     * service each batch: the VAES backend runs several YMM dependency chains
     * in flight, the bitsliced backend shares one engine pass across four
     * blocks, and the serial hardware paths run exactly as many single-block
     * encrypts as the batch holds.  The final (possibly partial) batch simply
     * passes a smaller count.
     */
    uint8_t in_w[16 * VOLEITH_AES_WIDE_MAX];
    uint8_t out_w[16 * VOLEITH_AES_WIDE_MAX];
    size_t i = 0;
    while (i < full_blocks) {
        size_t avail = full_blocks - i;
        unsigned n = (avail < VOLEITH_AES_WIDE_MAX)
                         ? (unsigned)avail
                         : (unsigned)VOLEITH_AES_WIDE_MAX;

        build_ctr_wide(in_w, iv_tweaked, lower_base, i, n);
        voleith_aes_encrypt_wide(&ctx->aes, out_w, in_w, n);
        memcpy(out + i * 16, out_w, (size_t)n * 16);

        voleith_secure_zero(in_w, (size_t)n * 16);
        voleith_secure_zero(out_w, (size_t)n * 16);
        i += n;
    }

    /*
     * Optional partial last block: encrypt one full counter block and copy
     * only the requested bytes, masking the unused high bits of the final byte.
     */
    if (rem_bits > 0) {
        uint8_t ctr_block[16];
        memcpy(ctr_block, iv_tweaked, 16);
        store_le32(ctr_block,
                   (lower_base + (uint32_t)full_blocks) & 0xFFFFFFFF);

        uint8_t block[16];
        voleith_aes_encrypt(&ctx->aes, block, ctr_block);

        size_t rem_bytes = (rem_bits + 7) / 8;
        memcpy(out + full_blocks * 16, block, rem_bytes);
        if (rem_bits % 8 != 0) {
            uint8_t mask = (uint8_t)((1u << (rem_bits % 8)) - 1);
            out[full_blocks * 16 + rem_bytes - 1] &= mask;
        }
        voleith_secure_zero(block, sizeof(block));
    }
    voleith_secure_zero(iv_tweaked, sizeof(iv_tweaked));
}

void
voleith_prg_clear(voleith_prg_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}
