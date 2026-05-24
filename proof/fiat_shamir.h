/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fiat_shamir.h - Fiat-Shamir transcript and challenge derivation
 *
 * Implements the hash functions H_i and H_2^j from the FAEST spec Section 3.3,
 * instantiated using SHAKE128 (λ=128) or SHAKE256 (λ ∈ {192, 256}).
 *
 * Domain separation (FAEST spec Section 3.3):
 *   H_i(m; ℓ)   := SHAKE(m || i,     ℓ),  for i ∈ {0, 1, 3, 4}
 *   H_2^j(m; ℓ) := SHAKE(m || (8+j), ℓ),  for j ∈ {0, 1, 2, 3}
 *
 * The domain separator is a single byte appended to the message BEFORE
 * squeezing.  Different protocol steps use different domain separators so
 * that hash outputs at one step cannot be confused with those at another.
 *
 * The transcript API provides an incremental absorb/squeeze interface:
 *   1. voleith_transcript_init   - select SHAKE variant and domain separator
 *   2. voleith_transcript_absorb - feed data (may be called repeatedly)
 *   3. voleith_transcript_squeeze - append domain sep byte, finalize, squeeze
 *      (may be called repeatedly; outputs are concatenated XOF-style)
 *
 * Usage:
 *   voleith_transcript_t t;
 *   voleith_transcript_init(&t, 128, VOLEITH_FS_H2_1);
 *   voleith_transcript_absorb(&t, chall1, chall1_len);
 *   voleith_transcript_absorb(&t, u_tilde, u_len);
 *   voleith_transcript_squeeze(&t, chall2, 3*16+8);   // 3λ/8+8 bytes
 */

#ifndef VOLEITH_FIAT_SHAMIR_H
#define VOLEITH_FIAT_SHAMIR_H

#include <stdint.h>
#include <stddef.h>
#include "hash.h"

/* ================================================================
 * Domain separator constants (FAEST spec Section 3.3)
 * ================================================================ */

#define VOLEITH_FS_H0 ((uint8_t)0)    /* H_0:   commitment key hash */
#define VOLEITH_FS_H1 ((uint8_t)1)    /* H_1:   vector commitment hash */
#define VOLEITH_FS_H2_0 ((uint8_t)8)  /* H_2^0: message / public-key hash */
#define VOLEITH_FS_H2_1 ((uint8_t)9)  /* H_2^1: first Fiat-Shamir challenge */
#define VOLEITH_FS_H2_2 ((uint8_t)10) /* H_2^2: second Fiat-Shamir challenge */
#define VOLEITH_FS_H2_3 ((uint8_t)11) /* H_2^3: third Fiat-Shamir challenge */
#define VOLEITH_FS_H3 ((uint8_t)3)    /* H_3:   secret randomness derivation */
#define VOLEITH_FS_H4 ((uint8_t)4)    /* H_4:   IV derivation */

/* ================================================================
 * Transcript object
 * ================================================================ */

/*
 * An incremental Fiat-Shamir transcript.
 *
 * Wraps a SHAKE context with a domain separator byte that is absorbed
 * automatically on the first squeeze call, following the FAEST spec.
 */
typedef struct {
    voleith_hash_ctx_t ctx; /* underlying SHAKE-128 or SHAKE-256 context */
    unsigned int lambda;    /* security parameter: 128, 192, or 256 */
    uint8_t domain_sep;     /* byte appended before first squeeze */
    int squeezed;           /* nonzero once squeeze has been called */
} voleith_transcript_t;

/*
 * Initialize a transcript.
 *
 * lambda:     security parameter (128, 192, or 256).
 *             Selects SHAKE128 when lambda==128, SHAKE256 otherwise.
 * domain_sep: domain separator byte appended before squeezing.
 *             Use VOLEITH_FS_* constants.
 */
void voleith_transcript_init(voleith_transcript_t *t, unsigned int lambda,
                             uint8_t domain_sep);

/*
 * Absorb data into the transcript.
 *
 * May be called any number of times before the first squeeze.
 * Must NOT be called after voleith_transcript_squeeze.
 */
void voleith_transcript_absorb(voleith_transcript_t *t, const uint8_t *data,
                               size_t len);

/*
 * Squeeze output from the transcript (XOF-style).
 *
 * First call: absorbs the domain separator byte, finalizes the SHAKE state,
 * then writes `len` bytes to `out`.
 * Subsequent calls: continue squeezing from the same state.
 * Outputs from successive squeeze calls are the same as one large squeeze.
 */
void voleith_transcript_squeeze(voleith_transcript_t *t, uint8_t *out,
                                size_t len);

/* ================================================================
 * One-shot convenience function
 * ================================================================ */

/*
 * Securely zero all state in the transcript.
 *
 * Call after the final squeeze when the transcript has absorbed secret
 * data (commitment seeds, VOLE vectors, witness-encoding values) so that
 * the sponge state is not retained in memory.
 */
void voleith_transcript_clear(voleith_transcript_t *t);

/*
 * One-shot hash: SHAKE(data || domain_sep; out_len bytes).
 *
 * Equivalent to init + absorb(data) + squeeze(out, out_len).
 *
 * lambda:     128, 192, or 256
 * domain_sep: see VOLEITH_FS_* constants
 * data:       input bytes (may be NULL when len == 0)
 * len:        input length
 * out:        output buffer
 * out_len:    number of output bytes to produce
 */
void voleith_fs_hash(unsigned int lambda, uint8_t domain_sep,
                     const uint8_t *data, size_t len, uint8_t *out,
                     size_t out_len);

#endif /* VOLEITH_FIAT_SHAMIR_H */
