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
 * Backend selection happens at runtime via a function-pointer dispatch
 * table populated on first use from voleith_cpu_features().  Priority:
 *   1. AES-NI         (x86_64; VOLEITH_HAVE_AES_NI compiled in).
 *   2. ARMv8 Crypto   (aarch64; VOLEITH_HAVE_ARMV8_AES compiled in).
 *   3. Bitsliced      (portable constant-time; always compiled in).
 *
 * All three backends are constant-time.  VOLEITH_FORCE_BACKEND (env
 * var) can pin a specific backend for testing; see core/cpu.h.
 */

#ifndef VOLEITH_AES_H
#define VOLEITH_AES_H

#include <stdint.h>
#include <stddef.h>

/*
 * Size of the round-key storage array in voleith_aes_ctx_t.
 *
 * Must be large enough for every compiled-in backend:
 *   AES-NI / ARMv8:  15 round keys * 16 bytes = 240 bytes.
 *   Bitsliced:       15 rounds * 8 bit-planes * 8 bytes = 960 bytes.
 *
 * 960 bytes is the union-of-max.  AES-NI and ARMv8 backends use only
 * the first 240 bytes; the remaining 720 bytes are unused in those
 * paths.  At most a handful of contexts exist per proof session so the
 * overhead (~2 KB total) is invisible against the working-set size.
 */
#define VOLEITH_AES_CTX_STORAGE_BYTES 960

/*
 * AES key context.
 *
 * A single layout used by all backends.  The interpretation of
 * storage[] is backend-specific:
 *   AES-NI / ARMv8: storage[0..239] holds the expanded round-key table
 *                   (up to 15 * 16 bytes of uint8_t round keys).
 *   Bitsliced:      storage[0..959] holds uint64_t[15][8] bit-plane
 *                   round keys.
 *
 * The backend_tag field records which backend last called key_expand
 * on this context.  Useful for round-key inspection in tests.
 *
 * The _Alignas(16) ensures that AES-NI backends can cast storage to
 * __m128i * and use aligned MOVDQA loads/stores without faulting.
 * It also satisfies the uint64_t alignment requirement for the
 * bitsliced backend.
 */
typedef struct {
    _Alignas(16) uint8_t storage[VOLEITH_AES_CTX_STORAGE_BYTES];
    int nr;
    uint8_t backend_tag; /* VOLEITH_AES_BACKEND_* value */
} voleith_aes_ctx_t;

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
 * call (4x faster than four single-block encrypts); the AES-NI
 * backend falls back to four chained single-block encrypts.
 */
void voleith_aes_encrypt_x4(const voleith_aes_ctx_t *ctx, uint8_t out[64],
                            const uint8_t in[64]);

/*
 * Securely zero all key material in ctx.  Call after the last use
 * of a context holding a secret key.
 */
void voleith_aes_ctx_clear(voleith_aes_ctx_t *ctx);

/*
 * Identifies the AES backend currently selected by the dispatch table.
 * On the first call, triggers dispatch initialization (reads
 * voleith_cpu_features()).
 */
typedef enum {
    VOLEITH_AES_BACKEND_AESNI = 1,
    VOLEITH_AES_BACKEND_ARMV8 = 2,
    VOLEITH_AES_BACKEND_BITSLICED = 3,
} voleith_aes_backend_t;

voleith_aes_backend_t voleith_aes_backend(void);

/*
 * Returns a static human-readable description of the active
 * backend.  Caller does not free.
 */
const char *voleith_aes_backend_name(void);

/*
 * Initialise the AES dispatch table if it has not been set yet.
 * Selects the highest-priority compiled-in backend whose required
 * feature bits are present in voleith_cpu_features().  Also emits
 * the lean-build notice when applicable.  Called lazily by every
 * public forwarder; may be called explicitly by tests.
 *
 * DO NOT call this in production code.
 */
void voleith_aes_dispatch_init(void);

/*
 * Reset the AES dispatch table to NULL so the next forwarder call
 * re-runs voleith_aes_dispatch_init().  Used by the test suite to
 * cycle through backends via voleith_cpu_features_override().
 *
 * DO NOT call this in production code.
 */
void voleith_aes_dispatch_reset(void);

#endif /* VOLEITH_AES_H */
