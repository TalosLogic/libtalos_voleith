/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.c - Groestl-256 and Groestl-512: dispatch coordinator and public API.
 *
 * Clean-room implementation from the Groestl specification
 * (third_party/Groestl/Supporting_Documentation/Groestl.pdf SS3) with the
 * round-3 modifications applied (Round3Mods.pdf SS2).  No code is copied
 * from the reference implementation.
 *
 * State representation:
 *   Flat byte array in column-major order: byte (r + ROWS*c) lives at row r,
 *   column c.  ROWS = 8 always; columns = 8 (Groestl-256) or 16 (Groestl-512).
 *
 * Dispatch:
 *   The four permutations (P512, Q512, P1024, Q1024) differ only in their
 *   SubBytes implementation.  Each backend TU (grostl_aesni.c, grostl_armv8.c,
 *   grostl_soft.c) defines a complete set of four permutation functions and an
 *   ops table.  voleith_grostl_ops is selected on first use via a CAS guard
 *   inside compress_block, which is always reached before output_transform_*.
 *
 * Constant-time:
 *   No table lookups indexed by secret state in any path.  The dispatch
 *   decision is on public CPU-feature bits only.
 */

#include "grostl.h"
#include "grostl_dispatch.h"
#include "cpu.h"
#include "util.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 * Dispatch: one-shot CAS init.  Priority: AES-NI > ARMv8 > soft.
 * ================================================================ */

_Atomic(const voleith_grostl_ops_t *) voleith_grostl_ops = NULL;

static atomic_flag s_grostl_warn_once = ATOMIC_FLAG_INIT;

void
voleith_grostl_dispatch_init(void)
{
    if (atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire) != NULL)
        return;

    unsigned feat = voleith_cpu_features();
    const voleith_grostl_ops_t *pick = NULL;

#ifdef VOLEITH_HAVE_AES_NI
    if (pick == NULL && (feat & VOLEITH_CPU_AES_NI))
        pick = &voleith_grostl_ops_aesni;
#endif
#ifdef VOLEITH_HAVE_ARMV8_AES
    if (pick == NULL && (feat & VOLEITH_CPU_ARMV8_AES))
        pick = &voleith_grostl_ops_armv8;
#endif
    if (pick == NULL)
        pick = &voleith_grostl_ops_soft;

#ifndef VOLEITH_HAVE_AES_NI
    if ((feat & VOLEITH_CPU_AES_NI) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_grostl_warn_once))
        fputs("voleith: notice: host CPU has AES-NI but the grostl-aesni"
              " backend was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_AES_NI=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif
#ifndef VOLEITH_HAVE_ARMV8_AES
    if ((feat & VOLEITH_CPU_ARMV8_AES) && getenv("VOLEITH_QUIET") == NULL &&
        !atomic_flag_test_and_set(&s_grostl_warn_once))
        fputs("voleith: notice: host CPU has ARMv8 AES but the grostl-armv8"
              " backend was not compiled in; running on software fallback."
              " Rebuild with -DVOLEITH_ARMV8_AES=ON."
              " Suppress with VOLEITH_QUIET=1.\n",
              stderr);
#endif

    const voleith_grostl_ops_t *expected = NULL;
    atomic_compare_exchange_strong_explicit(&voleith_grostl_ops, &expected,
                                            pick, memory_order_release,
                                            memory_order_acquire);
}

void
voleith_grostl_dispatch_reset(void)
{
    atomic_store_explicit(&voleith_grostl_ops, NULL, memory_order_release);
}

const char *
voleith_grostl_backend_name(void)
{
    if (atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire) == NULL)
        voleith_grostl_dispatch_init();
    return atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire)
        ->name;
}

/* ================================================================
 * Compression function f(h, m) = P(h XOR m) XOR Q(m) XOR h (spec SS3.2).
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

    voleith_grostl_ops->p512(p_in);
    voleith_grostl_ops->q512(q_in);

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

    voleith_grostl_ops->p1024(p_in);
    voleith_grostl_ops->q1024(q_in);

    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        h[i] ^= (uint8_t)(p_in[i] ^ q_in[i]);

    voleith_secure_zero(p_in, sizeof(p_in));
    voleith_secure_zero(q_in, sizeof(q_in));
}

static void
compress_block(voleith_grostl_ctx_t *ctx, const uint8_t *block)
{
    if (atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire) == NULL)
        voleith_grostl_dispatch_init();

    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        compress_512(ctx->state, block);
    else
        compress_1024(ctx->state, block);
}

/* ================================================================
 * Output transformation Omega(x) = trunc_n(P(x) XOR x) (spec SS3.3).
 *
 * Dispatch is already initialized by compress_block, which is always
 * called in voleith_grostl_finalize before output_transform_*.
 * ================================================================ */

static void
output_transform_256(uint8_t state[GROSTL_STATE_BYTES_256])
{
    uint8_t temp[GROSTL_STATE_BYTES_256];

    memcpy(temp, state, GROSTL_STATE_BYTES_256);
    voleith_grostl_ops->p512(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_256; i++)
        state[i] ^= temp[i];

    voleith_secure_zero(temp, sizeof(temp));
}

static void
output_transform_512(uint8_t state[GROSTL_STATE_BYTES_512])
{
    uint8_t temp[GROSTL_STATE_BYTES_512];

    memcpy(temp, state, GROSTL_STATE_BYTES_512);
    voleith_grostl_ops->p1024(temp);
    for (size_t i = 0; i < GROSTL_STATE_BYTES_512; i++)
        state[i] ^= temp[i];

    voleith_secure_zero(temp, sizeof(temp));
}

/* ================================================================
 * Public API: init.
 *
 * IV per spec SS3.5: the l-bit big-endian representation of n.
 * Groestl-256 (l=512, n=256): 56 zero bytes then 0x01 0x00 at bytes 62-63.
 * Groestl-512 (l=1024, n=512): 120 zero bytes then 0x02 0x00 at bytes 126-127.
 * ================================================================ */

void
voleith_grostl256_init(voleith_grostl_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->state_bytes = GROSTL_STATE_BYTES_256;
    ctx->output_bytes = 32;
    ctx->rounds = GROSTL_ROUNDS_256;
    ctx->columns = GROSTL_COLS_256;
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

    while (len - offset >= block_size) {
        compress_block(ctx, data + offset);
        ctx->block_count++;
        offset += block_size;
    }

    if (offset < len) {
        size_t rem = len - offset;
        memcpy(ctx->buf, data + offset, rem);
        ctx->buf_len = rem;
    }
}

/* ================================================================
 * Public API: finalize.
 *
 * Padding (spec SS3.6): append 0x80, zero-pad to block_size - 8,
 * then a 64-bit big-endian count of total padded-message blocks.
 * When the 0x80 byte plus length field does not fit in the current
 * partial block, padding spans two blocks.
 * ================================================================ */

void
voleith_grostl_finalize(voleith_grostl_ctx_t *ctx, uint8_t *out)
{
    size_t block_size = ctx->state_bytes;
    uint64_t total_blocks;

    ctx->buf[ctx->buf_len++] = 0x80;

    if (ctx->buf_len > block_size - 8) {
        while (ctx->buf_len < block_size)
            ctx->buf[ctx->buf_len++] = 0x00;
        compress_block(ctx, ctx->buf);
        ctx->block_count++;
        ctx->buf_len = 0;
    }

    while (ctx->buf_len < block_size - 8)
        ctx->buf[ctx->buf_len++] = 0x00;

    total_blocks = ctx->block_count + 1;

    for (int i = 0; i < 8; i++)
        ctx->buf[block_size - 1 - i] = (uint8_t)(total_blocks >> (8 * i));

    compress_block(ctx, ctx->buf);
    ctx->block_count++;

    if (ctx->state_bytes == GROSTL_STATE_BYTES_256)
        output_transform_256(ctx->state);
    else
        output_transform_512(ctx->state);

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

/* ================================================================
 * Public API: fixed-input single-compression node hashes.
 *
 * H = Omega(f(iv, block)): one compression under the caller-supplied
 * chaining value iv, then the output transformation, truncated to the
 * node width (the low n bytes, matching voleith_grostl_finalize).  No
 * padding: the input is exactly one fixed-width block.  Dispatch is
 * initialized here because compress_512 / output_transform_256
 * dereference voleith_grostl_ops directly (compress_block, which
 * normally performs the CAS init, is bypassed).
 * ================================================================ */

int
voleith_grostl256_compress_node(const uint8_t iv[64], const uint8_t block[64],
                                uint8_t out[32])
{
    uint8_t state[GROSTL_STATE_BYTES_256];

    if (iv == NULL || block == NULL || out == NULL)
        return -1;

    if (atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire) == NULL)
        voleith_grostl_dispatch_init();

    memcpy(state, iv, GROSTL_STATE_BYTES_256);
    compress_512(state, block);
    output_transform_256(state);
    memcpy(out, state + (GROSTL_STATE_BYTES_256 - 32), 32);

    voleith_secure_zero(state, sizeof(state));
    return 0;
}

int
voleith_grostl512_compress_node(const uint8_t iv[128], const uint8_t block[128],
                                uint8_t out[64])
{
    uint8_t state[GROSTL_STATE_BYTES_512];

    if (iv == NULL || block == NULL || out == NULL)
        return -1;

    if (atomic_load_explicit(&voleith_grostl_ops, memory_order_acquire) == NULL)
        voleith_grostl_dispatch_init();

    memcpy(state, iv, GROSTL_STATE_BYTES_512);
    compress_1024(state, block);
    output_transform_512(state);
    memcpy(out, state + (GROSTL_STATE_BYTES_512 - 64), 64);

    voleith_secure_zero(state, sizeof(state));
    return 0;
}
