/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * hash.c - SHA-3-256, SHAKE-128, SHAKE-256 (FIPS 202)
 *
 * Clean-room implementation of Keccak-f[1600] and the sponge construction
 * from NIST FIPS 202 (August 2015).
 *
 * State representation: 25 uint64_t lanes in little-endian byte order.
 * Lane(x, y) is stored at state[x + 5*y], matching the FIPS 202 convention
 * A[x, y, z] = S[64*(5y + x) + z].
 */

#include "hash.h"
#include "util.h"
#include <string.h>

/* ---- Little-endian helpers ---- */

static inline uint64_t
rotl64(uint64_t x, unsigned int n)
{
    /*
     * Rotation-by-variable with no UB for n == 0.  C11 6.5.7p3 makes
     * shifting a 64-bit value by 64 undefined; the naive
     * (x << n) | (x >> (64 - n)) form hits that when n == 0 (which
     * happens for Keccak lane (0, 0) whose ROT offset is 0).
     * The (-n) & 63 idiom keeps both shift amounts in [0, 63] for any
     * n in [0, 63], and compilers emit a single ROR/ROL instruction.
     */
    n &= 63;
    return (x << n) | (x >> ((-n) & 63));
}

/* ---- Keccak-f[1600] round constants (FIPS 202 Section 3.2.5) ---- */

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
    0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

/*
 * Rotation offsets for ρ (FIPS 202 Table 2), indexed as ROT[x + 5*y] mod 64.
 */
static const unsigned int ROT[25] = {
    0,  1,  62, 28, 27, /* y=0: x=0..4 */
    36, 44, 6,  55, 20, /* y=1: x=0..4 */
    3,  10, 43, 25, 39, /* y=2: x=0..4 */
    41, 45, 15, 21, 8,  /* y=3: x=0..4 */
    18, 2,  61, 56, 14, /* y=4: x=0..4 */
};

/*
 * Keccak-f[1600] permutation - 24 rounds of θ, ρ, π, χ, ι.
 * FIPS 202 Sections 3.2.1–3.2.5, Algorithm 7 with n_r=24.
 */
static void
keccak_f1600(uint64_t state[25])
{
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];

        /* θ - FIPS 202 Algorithm 1 */
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^
                   state[x + 20];

        for (int x = 0; x < 5; x++)
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);

        for (int i = 0; i < 25; i++)
            state[i] ^= D[i % 5];

        /* ρ and π combined - FIPS 202 Algorithms 2 and 3
         * π: A'[x, y] = A[(x + 3y) mod 5, x]
         * In our flat indexing with dest = (y, (2x+3y) mod 5):
         *   B[y + 5*((2x + 3y) % 5)] = rotl64(state[x + 5*y], ROT[x + 5*y])
         */
        for (int y = 0; y < 5; y++)
            for (int x = 0; x < 5; x++)
                B[y + 5 * ((2 * x + 3 * y) % 5)] =
                    rotl64(state[x + 5 * y], ROT[x + 5 * y]);

        /* χ - FIPS 202 Algorithm 4 */
        for (int y = 0; y < 5; y++) {
            int base = 5 * y;
            for (int x = 0; x < 5; x++)
                state[base + x] = B[base + x] ^ (~B[base + (x + 1) % 5] &
                                                 B[base + (x + 2) % 5]);
        }

        /* ι - FIPS 202 Algorithm 6 */
        state[0] ^= RC[round];
    }
}

/* ---- Sponge byte-level state access ---- */

/*
 * XOR data into state starting at a byte offset within the state.
 */
static void
xor_into_state(uint64_t state[25], size_t offset, const uint8_t *data,
               size_t len)
{
    for (size_t i = 0; i < len; i++) {
        size_t pos = offset + i;
        state[pos / 8] ^= (uint64_t)data[i] << (8 * (pos % 8));
    }
}

/*
 * Extract bytes from state starting at a byte offset.
 */
static void
extract_from_state(const uint64_t state[25], size_t offset, uint8_t *out,
                   size_t len)
{
    for (size_t i = 0; i < len; i++) {
        size_t pos = offset + i;
        out[i] = (uint8_t)(state[pos / 8] >> (8 * (pos % 8)));
    }
}

/* ---- Generic sponge init/absorb/finalize/squeeze ---- */

static void
sponge_init(voleith_hash_ctx_t *ctx, size_t rate, uint8_t suffix)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate = rate;
    ctx->absorbed = 0;
    ctx->suffix = suffix;
    ctx->finalized = 0;
}

static void
sponge_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t rate = ctx->rate;

    while (len > 0) {
        size_t space = rate - ctx->absorbed;
        size_t chunk = len < space ? len : space;

        xor_into_state(ctx->state, ctx->absorbed, data, chunk);
        ctx->absorbed += chunk;
        data += chunk;
        len -= chunk;

        if (ctx->absorbed == rate) {
            keccak_f1600(ctx->state);
            ctx->absorbed = 0;
        }
    }
}

static void
sponge_finalize(voleith_hash_ctx_t *ctx)
{
    if (ctx->finalized)
        return;

    size_t rate = ctx->rate;

    /* Apply domain separation suffix and pad10*1 padding.
     * For byte-aligned messages (FIPS 202 Table 6):
     *   - XOR suffix byte at current absorbed position
     *   - XOR 0x80 at last byte of rate block (pad10*1 final bit)
     */
    size_t pos = ctx->absorbed;
    ctx->state[pos / 8] ^= (uint64_t)ctx->suffix << (8 * (pos % 8));

    size_t last = rate - 1;
    ctx->state[last / 8] ^= (uint64_t)0x80 << (8 * (last % 8));

    keccak_f1600(ctx->state);
    ctx->absorbed = 0;
    ctx->finalized = 1;
}

static void
sponge_squeeze(voleith_hash_ctx_t *ctx, uint8_t *out, size_t len)
{
    if (!ctx->finalized)
        sponge_finalize(ctx);

    size_t rate = ctx->rate;

    while (len > 0) {
        size_t avail = rate - ctx->absorbed;
        size_t chunk = len < avail ? len : avail;

        extract_from_state(ctx->state, ctx->absorbed, out, chunk);
        ctx->absorbed += chunk;
        out += chunk;
        len -= chunk;

        if (len > 0 && ctx->absorbed == rate) {
            keccak_f1600(ctx->state);
            ctx->absorbed = 0;
        }
    }
}

/* ---- SHA3-256 ---- */

/* SHA3-256: rate = (1600 - 2*256) / 8 = 136 bytes, suffix = 0x06 */
#define SHA3_256_RATE 136

void
voleith_sha3_256_init(voleith_hash_ctx_t *ctx)
{
    sponge_init(ctx, SHA3_256_RATE, 0x06);
}

void
voleith_sha3_256_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                        size_t len)
{
    sponge_absorb(ctx, data, len);
}

void
voleith_sha3_256_finalize(voleith_hash_ctx_t *ctx, uint8_t out[32])
{
    sponge_squeeze(ctx, out, 32);
}

void
voleith_sha3_256(uint8_t out[32], const uint8_t *data, size_t len)
{
    voleith_hash_ctx_t ctx;
    voleith_sha3_256_init(&ctx);
    voleith_sha3_256_absorb(&ctx, data, len);
    voleith_sha3_256_finalize(&ctx, out);
}

/* ---- SHAKE-128 ---- */

/* SHAKE-128: rate = (1600 - 2*128) / 8 = 168 bytes, suffix = 0x1f */
#define SHAKE128_RATE 168

void
voleith_shake128_init(voleith_hash_ctx_t *ctx)
{
    sponge_init(ctx, SHAKE128_RATE, 0x1f);
}

void
voleith_shake128_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                        size_t len)
{
    sponge_absorb(ctx, data, len);
}

void
voleith_shake128_absorb_u32_le(voleith_hash_ctx_t *ctx, uint32_t v)
{
    uint8_t buf[4];

    buf[0] = (uint8_t)(v & 0xff);
    buf[1] = (uint8_t)((v >> 8) & 0xff);
    buf[2] = (uint8_t)((v >> 16) & 0xff);
    buf[3] = (uint8_t)((v >> 24) & 0xff);
    sponge_absorb(ctx, buf, sizeof(buf));
}

void
voleith_shake128_squeeze(voleith_hash_ctx_t *ctx, uint8_t *out, size_t len)
{
    sponge_squeeze(ctx, out, len);
}

/* ---- SHAKE-256 ---- */

/* SHAKE-256: rate = (1600 - 2*256) / 8 = 136 bytes, suffix = 0x1f */
#define SHAKE256_RATE 136

void
voleith_shake256_init(voleith_hash_ctx_t *ctx)
{
    sponge_init(ctx, SHAKE256_RATE, 0x1f);
}

void
voleith_shake256_absorb(voleith_hash_ctx_t *ctx, const uint8_t *data,
                        size_t len)
{
    sponge_absorb(ctx, data, len);
}

void
voleith_shake256_squeeze(voleith_hash_ctx_t *ctx, uint8_t *out, size_t len)
{
    sponge_squeeze(ctx, out, len);
}

void
voleith_hash_ctx_clear(voleith_hash_ctx_t *ctx)
{
    voleith_secure_zero(ctx, sizeof(*ctx));
}
