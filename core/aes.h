/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes.h - AES-128/192/256 block cipher (encrypt only).
 *
 * Implements the forward cipher and key expansion from FIPS 197.
 * Only encryption is provided - decryption is not needed for the
 * VOLEitH protocol (PRG uses AES-CTR which only needs encrypt).
 *
 * Backend selection happens at compile time, in this priority:
 *   1. AES-NI         (x86_64; VOLEITH_HAVE_AES_NI defined).
 *   2. ARMv8 Crypto   (aarch64; VOLEITH_HAVE_ARMV8_AES defined).
 *   3. Variable-time  (test/debug only; VOLEITH_ALLOW_VARIABLE_TIME_AES).
 *   4. Bitsliced      (portable constant-time; default fallback).
 *
 * The bitsliced backend (core/aes_ct64.c) is the universal fallback
 * and is always compiled in.  The variable-time path is gated off
 * by default because it has a cache-timing side channel and is
 * unsafe on any host with secret-bearing AES keys.
 */

#ifndef VOLEITH_AES_H
#define VOLEITH_AES_H

#include <stdint.h>
#include <stddef.h>

#define VOLEITH_AES_MAX_RK_BYTES (15 * 16)

/*
 * AES key context.
 *
 * Layout depends on the selected backend:
 *   - AES-NI / variable-time: 240-byte expanded round-key table.
 *   - Bitsliced: bit-plane round keys (uint64_t[15][8]).
 *
 * The two layouts are deliberately not interchangeable; downstream
 * code that peeks at ctx.rk[] (e.g., FIPS 197 Appendix A round-key
 * inspection in test_aes.c) only applies to the byte-rep backends.
 */
#if defined(VOLEITH_HAVE_AES_NI) || defined(VOLEITH_HAVE_ARMV8_AES) ||         \
    defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)

/*
 * The AES-NI key-expand and encrypt paths cast ctx->rk to (__m128i *)
 * and dereference it as rk[i], which compilers emit as MOVDQA
 * (aligned-only).  Without an explicit alignment the struct's natural
 * alignment is _Alignof(int) = 4 and a stack-local instance can land
 * on an offset that #GP-faults the aligned store/load.  Forcing
 * 16-byte alignment on rk also bumps the struct's alignment so
 * embeddings (heap, stack, or as a member of a larger struct) carry
 * the requirement through.
 */
typedef struct {
    _Alignas(16) uint8_t rk[VOLEITH_AES_MAX_RK_BYTES];
    int nr;
} voleith_aes_ctx_t;

#else

#include "aes_ct64.h"
typedef aes_ct64_ctx_t voleith_aes_ctx_t;

#endif

/*
 * Expands the cipher key into round keys.
 *
 * key:      pointer to the cipher key (16, 24, or 32 bytes).
 * key_bits: 128, 192, or 256.
 *
 * Returns 0 on success, -1 if key_bits is invalid.
 */
int voleith_aes_key_expand(voleith_aes_ctx_t *ctx, const uint8_t *key,
                           int key_bits);

/*
 * Encrypts a single 16-byte block using the expanded key schedule.
 * out and in may alias.
 */
void voleith_aes_encrypt(const voleith_aes_ctx_t *ctx, uint8_t out[16],
                         const uint8_t in[16]);

/*
 * Encrypts four consecutive 16-byte blocks under the same key.
 *
 * out[0..63] and in[0..63] are four consecutive blocks (block b
 * occupies bytes 16*b .. 16*b+15).  out and in may alias.
 *
 * The bitsliced backend services this with a single 4-block engine
 * call (4x faster than four single-block encrypts); the AES-NI and
 * variable-time backends fall back to four chained single-block
 * encrypts.
 */
void voleith_aes_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                            const uint8_t in[64]);

/*
 * Securely zero all key material in ctx.  Call after the last use
 * of a context holding a secret key.
 */
void voleith_aes_ctx_clear(voleith_aes_ctx_t *ctx);

/*
 * Identifies the AES backend compiled into the library (selected
 * at build time via the dispatch macros documented at the top of
 * this header).  Applications can call voleith_aes_backend_name()
 * during startup logging to make the active backend visible in
 * operational logs.
 */
typedef enum {
    VOLEITH_AES_BACKEND_AESNI = 1,
    VOLEITH_AES_BACKEND_ARMV8 = 2,
    VOLEITH_AES_BACKEND_BITSLICED = 3,
    VOLEITH_AES_BACKEND_VARIABLE_TIME = 4,
} voleith_aes_backend_t;

voleith_aes_backend_t voleith_aes_backend(void);

/*
 * Returns a static human-readable description of the active
 * backend.  Caller does not free.
 */
const char *voleith_aes_backend_name(void);

#endif /* VOLEITH_AES_H */
