/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * prg.h - Tweakable PRG from AES-CTR (FAEST spec Section 3.3, Figure 3.6)
 *
 * PRG(sd, iv, twk; m):
 *   - sd:  seed of lambda bits (16, 24, or 32 bytes for lambda=128,192,256)
 *   - iv:  128-bit initialization vector
 *   - twk: 32-bit tweak (added to upper 32 bits of IV)
 *   - m:   output length in bits
 *
 * Internally: expand sd as AES-lambda key, encrypt counter blocks where
 * the lower 32 bits of IV are incremented, and the upper 32 bits carry the
 * tweak. Output m bits of keystream.
 */

#ifndef VOLEITH_PRG_H
#define VOLEITH_PRG_H

#include <stdint.h>
#include <stddef.h>
#include "aes.h"

/*
 * PRG context - holds the expanded AES key to allow multiple calls
 * with different IVs/tweaks using the same seed.
 */
typedef struct {
    voleith_aes_ctx_t aes;
    int lambda; /* security parameter: 128, 192, or 256 */
} voleith_prg_ctx_t;

/*
 * Initialize PRG context from a seed.
 *
 * seed:      pointer to seed bytes (lambda/8 bytes)
 * lambda:    security parameter (128, 192, or 256)
 *
 * Returns 0 on success, -1 on invalid lambda.
 */
int voleith_prg_init(voleith_prg_ctx_t *ctx, const uint8_t *seed, int lambda);

/*
 * Generate pseudorandom output.
 *
 * ctx:   initialized PRG context
 * out:   output buffer (must hold at least (m + 7) / 8 bytes)
 * iv:    128-bit initialization vector (16 bytes, little-endian)
 * twk:   32-bit tweak value
 * m:     number of output bits
 *
 * The output is written to out[0..ceil(m/8)-1]. If m is not a multiple
 * of 8, the unused high bits of the last byte are zero.
 */
void voleith_prg_gen(const voleith_prg_ctx_t *ctx, uint8_t *out,
                     const uint8_t iv[16], uint32_t twk, size_t m);

/*
 * Securely zero the PRG context (expanded key schedule and lambda).
 *
 * Call after the last voleith_prg_gen() invocation when the context was
 * initialized from a secret seed (e.g. a GGM-tree node seed), so that
 * the AES round keys derived from the seed are not left in memory.
 */
void voleith_prg_clear(voleith_prg_ctx_t *ctx);

#endif /* VOLEITH_PRG_H */
