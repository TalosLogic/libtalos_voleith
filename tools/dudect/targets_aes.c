/* Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Bitsliced AES targets.  These exercise core/aes_ct64.c, which is
 * the constant-time AES backend that ships when no hardware-AES
 * extension (AES-NI on x86_64, Crypto Extension on ARMv8) is
 * available.  Hardware-AES backends are constant-time by ISA
 * specification and are not in scope for dudect validation.
 *
 * For each function under test we run two target descriptors:
 *
 *   _key  -- key bits vary across classes (all-zero vs all-one),
 *            plaintext fixed.  Catches leaks in the key schedule
 *            or any S-box state that depends on key bits.
 *   _pt   -- plaintext bits vary across classes, key fixed.
 *            Catches leaks on the data path separately from the
 *            key schedule.
 */
#include "dudect_target.h"

#include "aes_ct64.h"

#include <stdint.h>
#include <string.h>

typedef struct {
    aes_ct64_ctx_t ctx;
    uint8_t in[64]; /* 64 bytes covers both single-block and x4 paths */
} aes_state_t;

static volatile uint8_t aes_target_sink;

/* ----- key-bit pair -------------------------------------------------- */

static void
aes_key_setup(int cls, void *state)
{
    aes_state_t *s = (aes_state_t *)state;
    uint8_t key[16];
    memset(key, cls ? 0xFF : 0x00, sizeof(key));
    aes_ct64_key_expand(&s->ctx, key, 128);
    /* Fixed plaintext so the only varying input across classes is key. */
    memset(s->in, 0x55, sizeof(s->in));
}

static void
aes_encrypt_key_run(const void *state)
{
    const aes_state_t *s = (const aes_state_t *)state;
    uint8_t out[16];
    aes_ct64_encrypt(&s->ctx, out, s->in);
    aes_target_sink ^= out[0] ^ out[15];
}

static void
aes_encrypt_x4_key_run(const void *state)
{
    const aes_state_t *s = (const aes_state_t *)state;
    uint8_t out[64];
    aes_ct64_encrypt_x4(&s->ctx, out, s->in);
    aes_target_sink ^= out[0] ^ out[63];
}

const dudect_target_t target_aes_ct64_encrypt_key = {
    .name = "aes_ct64_encrypt_key",
    .setup_class = aes_key_setup,
    .run = aes_encrypt_key_run,
    .state_size = sizeof(aes_state_t),
    .reps_per_trial = 200,
};

const dudect_target_t target_aes_ct64_encrypt_x4_key = {
    .name = "aes_ct64_encrypt_x4_key",
    .setup_class = aes_key_setup,
    .run = aes_encrypt_x4_key_run,
    .state_size = sizeof(aes_state_t),
    .reps_per_trial = 200,
};

/* ----- plaintext-bit pair -------------------------------------------- */

static void
aes_pt_setup(int cls, void *state)
{
    aes_state_t *s = (aes_state_t *)state;
    /* Fixed key so the only varying input across classes is plaintext. */
    static const uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    aes_ct64_key_expand(&s->ctx, key, 128);
    memset(s->in, cls ? 0xFF : 0x00, sizeof(s->in));
}

static void
aes_encrypt_pt_run(const void *state)
{
    const aes_state_t *s = (const aes_state_t *)state;
    uint8_t out[16];
    aes_ct64_encrypt(&s->ctx, out, s->in);
    aes_target_sink ^= out[0] ^ out[15];
}

static void
aes_encrypt_x4_pt_run(const void *state)
{
    const aes_state_t *s = (const aes_state_t *)state;
    uint8_t out[64];
    aes_ct64_encrypt_x4(&s->ctx, out, s->in);
    aes_target_sink ^= out[0] ^ out[63];
}

const dudect_target_t target_aes_ct64_encrypt_pt = {
    .name = "aes_ct64_encrypt_pt",
    .setup_class = aes_pt_setup,
    .run = aes_encrypt_pt_run,
    .state_size = sizeof(aes_state_t),
    .reps_per_trial = 200,
};

const dudect_target_t target_aes_ct64_encrypt_x4_pt = {
    .name = "aes_ct64_encrypt_x4_pt",
    .setup_class = aes_pt_setup,
    .run = aes_encrypt_x4_pt_run,
    .state_size = sizeof(aes_state_t),
    .reps_per_trial = 200,
};
