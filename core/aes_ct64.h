/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_ct64.h - Bitsliced AES-128/192/256 (constant-time, portable).
 *
 * Internal backend used by core/aes.c when neither AES-NI nor the
 * ARMv8 Cryptography Extension is available.  Constant-time by
 * construction: no secret-dependent branches and no secret-indexed
 * memory access in any encrypt/key-expansion code path.
 *
 * Processes four AES blocks in parallel using a uint64_t bit-plane
 * representation.  See docs/BITSLICED_AES_DESIGN.md for the packing
 * convention, S-box reuse rationale, and validation plan.
 */

#ifndef VOLEITH_AES_CT64_H
#define VOLEITH_AES_CT64_H

#include <stdint.h>

/*
 * Bit-plane round-key context.
 *
 * rk[round][k] holds bit k of the 16 round-key bytes for `round`,
 * replicated across all four 16-bit block subfields of the uint64_t
 * (so the same key is applied to all four parallel blocks).  Sized
 * for AES-256 worst case (Nr + 1 = 15 round keys).
 *
 * nr is the number of rounds: 10 (AES-128), 12 (AES-192), 14 (AES-256).
 */
typedef struct {
    uint64_t rk[15][8];
    int nr;
} aes_ct64_ctx_t;

/*
 * Expand a cipher key into bit-plane round keys.
 *
 * key:      pointer to 16, 24, or 32 key bytes.
 * key_bits: 128, 192, or 256.
 *
 * Returns 0 on success, -1 on invalid key_bits.
 */
int aes_ct64_key_expand(aes_ct64_ctx_t *ctx, const uint8_t *key, int key_bits);

/*
 * Encrypt a single 16-byte block.  Single-block wrapper around the
 * four-block engine; the three companion slots are zero-padded.
 * out and in may alias.
 */
void aes_ct64_encrypt(const aes_ct64_ctx_t *ctx, uint8_t out[16],
                      const uint8_t in[16]);

/*
 * Encrypt four 16-byte blocks in parallel.
 *
 * out[0..63] and in[0..63] hold four consecutive 16-byte blocks.
 * out and in may alias.
 */
void aes_ct64_encrypt_x4(const aes_ct64_ctx_t *ctx, uint8_t out[64],
                         const uint8_t in[64]);

/*
 * Securely zero all key material in ctx.  Call after the last use of
 * a context holding a secret key.
 */
void aes_ct64_ctx_clear(aes_ct64_ctx_t *ctx);

#endif /* VOLEITH_AES_CT64_H */
