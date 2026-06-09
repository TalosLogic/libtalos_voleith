/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_ct64_ops.c - Bitsliced AES ops table for runtime dispatch.
 *
 * Wraps the aes_ct64_* functions (which take aes_ct64_ctx_t *) for
 * the voleith_aes_ctx_t * interface used by the dispatch table.
 *
 * The cast from voleith_aes_ctx_t * to aes_ct64_ctx_t * is valid:
 * both types place their round-key data at offset 0 (960 bytes) and
 * int nr at offset 960.  The _Alignas(16) on voleith_aes_ctx_t.storage
 * satisfies the uint64_t alignment requirement of the bitsliced engine.
 */

#include "aes_dispatch.h"
#include "aes_ct64.h"

static int
ct64_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key, int bits)
{
    int rc = aes_ct64_key_expand((aes_ct64_ctx_t *)ctx, key, bits);
    if (rc == 0)
        ctx->backend_tag = VOLEITH_AES_BACKEND_BITSLICED;
    return rc;
}

static void
ct64_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
             const uint8_t in[16])
{
    aes_ct64_encrypt((const aes_ct64_ctx_t *)ctx, out, in);
}

static void
ct64_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                const uint8_t in[64])
{
    aes_ct64_encrypt_x4((const aes_ct64_ctx_t *)ctx, out, in);
}

const voleith_aes_ops_t voleith_aes_ops_bitsliced = {
    .key_expand = ct64_key_expand,
    .encrypt = ct64_encrypt,
    .encrypt_x4 = ct64_encrypt_x4,
    .backend_tag = VOLEITH_AES_BACKEND_BITSLICED,
    .name = "bitsliced",
};
