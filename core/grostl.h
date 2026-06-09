/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.h - Grøstl-256 and Grøstl-512 hash functions.
 *
 * Clean-room implementation from the Grøstl specification
 * (third_party/Groestl/Supporting_Documentation/Groestl.pdf, with the
 * round-3 modifications in Round3Mods.pdf).  No code is taken from
 * the reference implementation.
 *
 * Grøstl-256:
 *   internal state    : 8 x 8 byte matrix (512 bits)
 *   output            : 32 bytes (256 bits)
 *   block size        : 64 bytes
 *   rounds            : 10 per permutation
 *
 * Grøstl-512:
 *   internal state    : 8 x 16 byte matrix (1024 bits)
 *   output            : 64 bytes (512 bits)
 *   block size        : 128 bytes
 *   rounds            : 14 per permutation
 *
 * Constant-time by construction: the SubBytes step uses the bitsliced
 * AES S-box exposed by core/aes_ct64.h (no table lookups indexed by
 * secret state); MixBytes is straight-line GF(2^8) arithmetic with no
 * tables; ShiftBytes, AddRoundConstant, and padding are
 * data-independent permutations and constants.
 */

#ifndef VOLEITH_GROSTL_H
#define VOLEITH_GROSTL_H

#include <stdint.h>
#include <stddef.h>

/*
 * Incremental hashing context.  Holds the chaining state, an
 * accumulating message-block buffer, and metadata identifying which
 * Grøstl variant is in use.
 *
 * Fields beyond the public read of state_bytes / output_bytes /
 * rounds / columns are implementation detail; do not depend on the
 * layout in caller code.
 *
 * Single context type for both variants, matching the SHAKE
 * convention in core/hash.h.  Discriminated by state_bytes (64 for
 * Grøstl-256, 128 for Grøstl-512); set by the corresponding init
 * function and never changed thereafter.
 */
typedef struct voleith_grostl_ctx {
    uint8_t state[128];   /* chaining variable (column-major) */
    uint8_t buf[128];     /* accumulating message-block buffer */
    uint64_t block_count; /* full message blocks compressed so far */
    size_t state_bytes;   /* 64 (Grøstl-256) or 128 (Grøstl-512) */
    size_t output_bytes;  /* 32 (Grøstl-256) or 64 (Grøstl-512) */
    size_t buf_len;       /* bytes currently held in buf */
    int rounds;           /* 10 (Grøstl-256) or 14 (Grøstl-512) */
    int columns;          /* 8 (Grøstl-256) or 16 (Grøstl-512) */
} voleith_grostl_ctx_t;

/*
 * One-shot Grøstl-256: hash msg_len bytes of input into a 32-byte
 * digest.  msg may be NULL when msg_len == 0.  Equivalent to init +
 * absorb + finalize, with secure cleanup on return.
 */
void voleith_grostl256(uint8_t out[32], const uint8_t *msg, size_t msg_len);

/*
 * One-shot Grøstl-512: hash msg_len bytes of input into a 64-byte
 * digest.  msg may be NULL when msg_len == 0.
 */
void voleith_grostl512(uint8_t out[64], const uint8_t *msg, size_t msg_len);

/*
 * Initialize an incremental Grøstl-256 context.  Sets the chaining
 * value to the standard 256-bit IV (the 512-bit big-endian
 * representation of the output bit length, 256).
 */
void voleith_grostl256_init(voleith_grostl_ctx_t *ctx);

/*
 * Initialize an incremental Grøstl-512 context.  Sets the chaining
 * value to the standard 512-bit IV (the 1024-bit big-endian
 * representation of the output bit length, 512).
 */
void voleith_grostl512_init(voleith_grostl_ctx_t *ctx);

/*
 * Absorb len bytes of message data into the context.  May be called
 * any number of times before finalize; equivalent to absorbing a
 * single concatenation of all absorbed buffers.  data may be NULL
 * when len == 0.
 */
void voleith_grostl_absorb(voleith_grostl_ctx_t *ctx, const uint8_t *data,
                           size_t len);

/*
 * Finalize the hash.  Applies Grøstl padding, runs the final
 * compression, runs the output transformation, and writes
 * ctx->output_bytes bytes to out.  The context is left in a
 * terminated state and must not be absorbed into again; reset by
 * calling voleith_grostl_clear followed by another init.
 */
void voleith_grostl_finalize(voleith_grostl_ctx_t *ctx, uint8_t *out);

/*
 * Securely zero all data in the context.  Call after the last use of
 * a context that has absorbed secret material.  Safe to call at any
 * point in the absorb / finalize sequence.
 */
void voleith_grostl_clear(voleith_grostl_ctx_t *ctx);

/*
 * Return a short string naming the active SubBytes backend: "aesni",
 * "armv8", or "soft".  Triggers dispatch initialization if not yet done.
 */
const char *voleith_grostl_backend_name(void);

/*
 * Reset the dispatch table to uninitialized, forcing reselection on the
 * next Groestl call.  Use only in tests, in combination with
 * voleith_cpu_features_override(), to cycle through backends.
 */
void voleith_grostl_dispatch_reset(void);

#endif /* VOLEITH_GROSTL_H */
