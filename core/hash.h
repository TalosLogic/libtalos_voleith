/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hash.h - SHA-3-256, SHAKE-128, SHAKE-256 (FIPS 202)
 *
 * Implements the Keccak-based hash functions needed by the VOLEitH protocol:
 *   - SHA3-256:  fixed 32-byte digest
 *   - SHAKE-128: extendable-output function, 128-bit security
 *   - SHAKE-256: extendable-output function, 256-bit security
 *
 * All functions use the Keccak-f[1600] permutation (24 rounds) with the
 * sponge construction from FIPS 202.
 *
 * Incremental API (init/absorb/squeeze) is provided for SHAKE, which is
 * needed for Fiat-Shamir transcript construction. SHA3-256 has both
 * incremental and one-shot interfaces.
 */

#ifndef VOLEITH_HASH_H
#define VOLEITH_HASH_H

#include <stdint.h>
#include <stddef.h>

/* Keccak sponge context - shared by all SHA-3/SHAKE variants */
typedef struct {
    uint64_t state[25]; /* 1600-bit Keccak state as 25 lanes */
    size_t
        rate; /* rate in bytes (168 for SHAKE-128, 136 for SHAKE-256/SHA3-256) */
    size_t absorbed; /* bytes absorbed in current block (0..rate-1) */
    uint8_t
        suffix; /* domain separation + first pad bit (0x06 for SHA-3, 0x1f for SHAKE) */
    int finalized; /* nonzero after finalize/squeeze has been called */
} voleith_hash_ctx_t;

/*
 * SHA3-256: one-shot interface
 *
 * out:  32-byte output buffer for the digest
 * data: input data
 * len:  input length in bytes
 */
void voleith_sha3_256(uint8_t out[32], const uint8_t *data, size_t len);

/*
 * SHA3-256: incremental interface
 */
void voleith_sha3_256_init(voleith_hash_ctx_t *ctx);
void voleith_sha3_256_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                             size_t len);
void voleith_sha3_256_finalize(voleith_hash_ctx_t *ctx, uint8_t out[32]);

/*
 * SHAKE-128: incremental interface
 *
 * Call init, then absorb (one or more times), then squeeze (one or more times).
 * Once squeeze is called, no further absorb calls are allowed.
 */
void voleith_shake128_init(voleith_hash_ctx_t *ctx);
void voleith_shake128_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                             size_t len);
void voleith_shake128_squeeze(voleith_hash_ctx_t *ctx, uint8_t *out,
                              size_t len);

/*
 * SHAKE-256: incremental interface
 *
 * Same usage pattern as SHAKE-128.
 */
void voleith_shake256_init(voleith_hash_ctx_t *ctx);
void voleith_shake256_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                             size_t len);
void voleith_shake256_squeeze(voleith_hash_ctx_t *ctx, uint8_t *out,
                              size_t len);

/*
 * Securely zero all state in ctx.
 *
 * Call after the final squeeze when the context has absorbed secret data
 * (e.g. VOLE keys, commitment seeds) so that the sponge state is not
 * left in memory.
 */
void voleith_hash_ctx_clear(voleith_hash_ctx_t *ctx);

#endif /* VOLEITH_HASH_H */
