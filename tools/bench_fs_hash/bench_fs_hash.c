/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * bench_fs_hash.c - microbenchmark FS-hash candidates over realistic
 * transcript sizes to inform the Grøstl-FS vs SHAKE selection
 * (docs/FS_TRANSFORM_SWITCHING_DESIGN.md).
 *
 * One source, six binaries.  The hash kind is selected at compile
 * time via VOLEITH_BENCH_HASH (one of GROSTL256, GROSTL512, SHAKE128,
 * SHAKE256).  HW vs SW for Grøstl is determined by which voleith_core
 * library the binary links against: the production lib (with
 * VOLEITH_HAVE_AES_NI / VOLEITH_HAVE_ARMV8_AES) gives the HW path,
 * the no-flags private lib gives the bitsliced SW path.  SHAKE has no
 * HW/SW split on the platforms we care about (no SHA-3 ISA on x86,
 * present on ARMv8.4-A but not exposed in core/hash.c yet).
 *
 * For SHAKE we use the native incremental absorb+squeeze.  For Grøstl
 * we implement the counter-mode XOF described in
 * FS_TRANSFORM_SWITCHING_DESIGN.md §"XOF expansion" (strategy (a):
 * buffer transcript, hash over buf || dom || ctr_be32 once per output
 * block).  That is what a real Grøstl-FS backend would pay; benching
 * just one-shot Grøstl over fixed input would understate the cost.
 *
 * Methodology: per (transcript_size, output_size) cell, run one warmup
 * burst, then NUM_SAMPLES timed bursts of INNER_REPS calls each.  Per-op
 * latency is sample_ns / INNER_REPS.  INNER_REPS is autotuned so each
 * sample lasts ~TARGET_SAMPLE_MS, keeping clock_gettime overhead
 * negligible relative to the measured op.
 *
 * Output is a fixed-column text table; pipe to a file for analysis.
 */

#define _POSIX_C_SOURCE 199309L

#include "bench_util.h"
#include "grostl.h"
#include "hash.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- compile-time hash selection ----------------------------------- */

#define BENCH_HASH_GROSTL256 1
#define BENCH_HASH_GROSTL512 2
#define BENCH_HASH_SHAKE128 3
#define BENCH_HASH_SHAKE256 4

#ifndef VOLEITH_BENCH_HASH
#error                                                                         \
    "VOLEITH_BENCH_HASH must be defined to GROSTL256, GROSTL512, SHAKE128, or SHAKE256"
#endif

#define BENCH_CONCAT_(a, b) a##b
#define BENCH_HASH_ID(x) BENCH_CONCAT_(BENCH_HASH_, x)
#define BENCH_SELECTED_HASH BENCH_HASH_ID(VOLEITH_BENCH_HASH)

#if BENCH_SELECTED_HASH == BENCH_HASH_GROSTL256
#define BENCH_LABEL_BASE "grostl-256"
#define BENCH_GROSTL_OUTPUT_BYTES 32
#elif BENCH_SELECTED_HASH == BENCH_HASH_GROSTL512
#define BENCH_LABEL_BASE "grostl-512"
#define BENCH_GROSTL_OUTPUT_BYTES 64
#elif BENCH_SELECTED_HASH == BENCH_HASH_SHAKE128
#define BENCH_LABEL_BASE "shake-128"
#elif BENCH_SELECTED_HASH == BENCH_HASH_SHAKE256
#define BENCH_LABEL_BASE "shake-256"
#else
#error "VOLEITH_BENCH_HASH must be GROSTL256, GROSTL512, SHAKE128, or SHAKE256"
#endif

/* HW vs SW label is determined by the linked library's compile flags. */
#if BENCH_SELECTED_HASH == BENCH_HASH_GROSTL256 ||                             \
    BENCH_SELECTED_HASH == BENCH_HASH_GROSTL512
#if defined(VOLEITH_HAVE_AES_NI)
#define BENCH_LABEL_BACKEND " (hw / AES-NI)"
#elif defined(VOLEITH_HAVE_ARMV8_AES)
#define BENCH_LABEL_BACKEND " (hw / ARMv8 AES)"
#else
#define BENCH_LABEL_BACKEND " (sw / bitsliced)"
#endif
#else
#define BENCH_LABEL_BACKEND ""
#endif

#define BENCH_LABEL BENCH_LABEL_BASE BENCH_LABEL_BACKEND

/* ---- workload --------------------------------------------------------- */

/* Domain separator byte mirrors what fiat_shamir.c uses on a real
 * absorb-then-squeeze cycle.  The exact value is irrelevant for timing;
 * we just want one byte appended before the squeeze. */
#define BENCH_DOMAIN_BYTE 0x01u

/* Transcript sizes (bytes) sweep range covering realistic FS absorbs.
 * 64-256B: chall intermediates / small protocol elements.
 * 1024B:   one VOLE row's worth.
 * 4096B:   several proof segments.
 * 16384B:  approaches whole-proof transcript at λ=128. */
static const size_t TRANSCRIPT_SIZES[] = {64, 256, 1024, 4096, 16384};
#define NUM_TRANSCRIPT_SIZES                                                   \
    (sizeof(TRANSCRIPT_SIZES) / sizeof(TRANSCRIPT_SIZES[0]))

/* Output sizes (bytes) cover realistic FS challenge lengths:
 * 16: chall_3 at λ=128 (= λ/8)
 * 32: chall_3 at λ=256 / native Grøstl-256 / SHA3-256
 * 88: chall_1 at λ=128 (= 5λ/8 + 8)
 * 168: chall_1 at λ=256 (= 5λ/8 + 8) */
static const size_t OUTPUT_SIZES[] = {16, 32, 88, 168};
#define NUM_OUTPUT_SIZES (sizeof(OUTPUT_SIZES) / sizeof(OUTPUT_SIZES[0]))

#define NUM_SAMPLES 64
#define WARMUP_REPS 8
#define TARGET_SAMPLE_MS 2.0
#define MIN_INNER_REPS 4
#define MAX_INNER_REPS (1u << 24)

/* ---- per-hash op() implementations ----------------------------------- */

#if BENCH_SELECTED_HASH == BENCH_HASH_GROSTL256 ||                             \
    BENCH_SELECTED_HASH == BENCH_HASH_GROSTL512

/* Grøstl XOF expansion (FS_TRANSFORM_SWITCHING_DESIGN.md §"XOF expansion",
 * strategy (a)): for each output block i, hash (transcript || dom ||
 * ctr_be32(i)) with native Grøstl and concatenate.  Real backend would
 * hold the transcript in a growing buffer.  Caller already owns
 * `transcript`; we just simulate the per-squeeze cost. */

#if BENCH_SELECTED_HASH == BENCH_HASH_GROSTL256
static inline void
bench_grostl_block(uint8_t *out, const uint8_t *msg, size_t msg_len)
{
    voleith_grostl256(out, msg, msg_len);
}
#else /* GROSTL512 */
static inline void
bench_grostl_block(uint8_t *out, const uint8_t *msg, size_t msg_len)
{
    voleith_grostl512(out, msg, msg_len);
}
#endif

static void
bench_op(uint8_t *scratch, size_t scratch_cap, const uint8_t *transcript,
         size_t transcript_len, uint8_t *out, size_t out_len)
{
    /* Build (transcript || dom || ctr_be32) in scratch.  Re-used across
     * counter iterations; only the last 4 bytes mutate. */
    if (transcript_len + 5 > scratch_cap)
        abort();
    memcpy(scratch, transcript, transcript_len);
    scratch[transcript_len] = (uint8_t)BENCH_DOMAIN_BYTE;
    size_t msg_len = transcript_len + 5;

    uint8_t block[BENCH_GROSTL_OUTPUT_BYTES];
    uint32_t ctr = 0;
    size_t written = 0;
    while (written < out_len) {
        scratch[transcript_len + 1] = (uint8_t)(ctr >> 24);
        scratch[transcript_len + 2] = (uint8_t)(ctr >> 16);
        scratch[transcript_len + 3] = (uint8_t)(ctr >> 8);
        scratch[transcript_len + 4] = (uint8_t)ctr;
        bench_grostl_block(block, scratch, msg_len);
        size_t take = out_len - written;
        if (take > BENCH_GROSTL_OUTPUT_BYTES)
            take = BENCH_GROSTL_OUTPUT_BYTES;
        memcpy(out + written, block, take);
        written += take;
        ctr++;
    }
}

#else /* SHAKE128 / SHAKE256 */

#if BENCH_SELECTED_HASH == BENCH_HASH_SHAKE128
#define BENCH_SHAKE_INIT voleith_shake128_init
#define BENCH_SHAKE_ABSORB voleith_shake128_absorb
#define BENCH_SHAKE_SQUEEZE voleith_shake128_squeeze
#else
#define BENCH_SHAKE_INIT voleith_shake256_init
#define BENCH_SHAKE_ABSORB voleith_shake256_absorb
#define BENCH_SHAKE_SQUEEZE voleith_shake256_squeeze
#endif

static void
bench_op(uint8_t *scratch, size_t scratch_cap, const uint8_t *transcript,
         size_t transcript_len, uint8_t *out, size_t out_len)
{
    (void)scratch;
    (void)scratch_cap;
    voleith_hash_ctx_t ctx;
    BENCH_SHAKE_INIT(&ctx);
    BENCH_SHAKE_ABSORB(&ctx, transcript, transcript_len);
    uint8_t dom = (uint8_t)BENCH_DOMAIN_BYTE;
    BENCH_SHAKE_ABSORB(&ctx, &dom, 1);
    BENCH_SHAKE_SQUEEZE(&ctx, out, out_len);
    voleith_hash_ctx_clear(&ctx);
}

#endif

/* ---- driver ---------------------------------------------------------- */

static size_t
autotune_inner_reps(uint8_t *scratch, size_t scratch_cap,
                    const uint8_t *transcript, size_t transcript_len,
                    uint8_t *out, size_t out_len)
{
    size_t reps = MIN_INNER_REPS;
    for (;;) {
        uint64_t t0 = bench_now_ns();
        for (size_t i = 0; i < reps; i++)
            bench_op(scratch, scratch_cap, transcript, transcript_len, out,
                     out_len);
        uint64_t t1 = bench_now_ns();
        double ms = (double)(t1 - t0) / 1.0e6;
        if (ms >= TARGET_SAMPLE_MS || reps >= MAX_INNER_REPS)
            return reps;
        /* Scale toward target, with 2x floor so we don't dawdle. */
        double scale = (TARGET_SAMPLE_MS / (ms > 1e-6 ? ms : 1e-6)) * 1.25;
        if (scale < 2.0)
            scale = 2.0;
        size_t next = (size_t)((double)reps * scale);
        if (next <= reps)
            next = reps * 2;
        if (next > MAX_INNER_REPS)
            next = MAX_INNER_REPS;
        reps = next;
    }
}

static void
run_cell(size_t transcript_len, size_t out_len, uint8_t *transcript,
         uint8_t *scratch, size_t scratch_cap, uint8_t *out)
{
    /* Fill transcript with a deterministic but non-trivial pattern so
     * the SHAKE rate-byte absorb and Grøstl block compression both see
     * varying input.  Pattern, not RNG, so re-runs are comparable. */
    for (size_t i = 0; i < transcript_len; i++)
        transcript[i] = (uint8_t)(i * 31u + 7u);

    /* Warmup */
    for (size_t i = 0; i < WARMUP_REPS; i++)
        bench_op(scratch, scratch_cap, transcript, transcript_len, out,
                 out_len);

    size_t reps = autotune_inner_reps(scratch, scratch_cap, transcript,
                                      transcript_len, out, out_len);

    double samples_us[NUM_SAMPLES];
    for (size_t s = 0; s < NUM_SAMPLES; s++) {
        uint64_t t0 = bench_now_ns();
        for (size_t i = 0; i < reps; i++)
            bench_op(scratch, scratch_cap, transcript, transcript_len, out,
                     out_len);
        uint64_t t1 = bench_now_ns();
        double per_op_ns = (double)(t1 - t0) / (double)reps;
        samples_us[s] = per_op_ns / 1000.0;
    }

    bench_stats_t st;
    {
        /* Reuse bench_compute (works on doubles, no unit assumption). */
        st = bench_compute(samples_us, NUM_SAMPLES);
    }

    printf("  %6zu  %5zu  %10zu  %10.4f  %10.4f  %10.4f  %10.4f\n",
           transcript_len, out_len, reps, st.min, st.median, st.mean, st.max);
}

int
main(void)
{
    printf("=== FS-hash microbenchmark: %s ===\n", BENCH_LABEL);
    printf("samples=%d  warmup=%d  target_sample=%.2fms  per-op stats in "
           "microseconds\n\n",
           NUM_SAMPLES, WARMUP_REPS, TARGET_SAMPLE_MS);
    printf("  T_size  out  inner_reps         min      median        mean      "
           "   max\n");

    /* Largest transcript + dom + ctr_be32 = max scratch needed for Grøstl. */
    size_t max_T = 0;
    for (size_t i = 0; i < NUM_TRANSCRIPT_SIZES; i++)
        if (TRANSCRIPT_SIZES[i] > max_T)
            max_T = TRANSCRIPT_SIZES[i];

    size_t max_out = 0;
    for (size_t i = 0; i < NUM_OUTPUT_SIZES; i++)
        if (OUTPUT_SIZES[i] > max_out)
            max_out = OUTPUT_SIZES[i];

    size_t scratch_cap = max_T + 16;
    uint8_t *transcript = (uint8_t *)malloc(max_T);
    uint8_t *scratch = (uint8_t *)malloc(scratch_cap);
    uint8_t *out = (uint8_t *)malloc(max_out);
    if (!transcript || !scratch || !out) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    for (size_t ti = 0; ti < NUM_TRANSCRIPT_SIZES; ti++) {
        for (size_t oi = 0; oi < NUM_OUTPUT_SIZES; oi++) {
            run_cell(TRANSCRIPT_SIZES[ti], OUTPUT_SIZES[oi], transcript,
                     scratch, scratch_cap, out);
        }
    }

    free(transcript);
    free(scratch);
    free(out);
    return 0;
}
