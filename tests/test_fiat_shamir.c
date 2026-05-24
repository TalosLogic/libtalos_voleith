/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_fiat_shamir.c - Tests for the Fiat-Shamir transcript API
 *
 * Tests:
 *   1: Determinism - same input + domain_sep produces same output
 *   2: Domain separation - different domain_sep bytes produce different output
 *   3: SHAKE variant selection - λ=128 (SHAKE128) vs λ=192 (SHAKE256) differ
 *   4: Incremental absorb equals one-shot absorb
 *   5: Squeeze chunking - partial squeezes concatenate to full squeeze
 *   6: Empty input - squeeze with no absorb calls
 *   7: One-shot voleith_fs_hash matches incremental transcript
 *   8: All VOLEITH_FS_* domain separators are mutually distinct
 *   9: H_2^0 through H_2^3 domain seps are 8+j (spec correctness)
 *  10: Large output - squeeze produces consistent long XOF output
 */

#include "fiat_shamir.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int test_count = 0;
static int pass_count = 0;

static void
check(const char *name, int cond)
{
    test_count++;
    if (cond) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
    }
}

/* ================================================================
 * Test 1: Determinism
 * ================================================================ */
static void
test_determinism(void)
{
    static const uint8_t input[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    uint8_t out1[32], out2[32];

    /* Two independent transcripts, same inputs - must produce same output */
    voleith_transcript_t t1, t2;
    voleith_transcript_init(&t1, 128, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t1, input, sizeof(input));
    voleith_transcript_squeeze(&t1, out1, sizeof(out1));

    voleith_transcript_init(&t2, 128, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t2, input, sizeof(input));
    voleith_transcript_squeeze(&t2, out2, sizeof(out2));

    check("determinism: same input same output (λ=128)",
          memcmp(out1, out2, 32) == 0);

    /* Same for λ=256 */
    voleith_transcript_init(&t1, 256, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t1, input, sizeof(input));
    voleith_transcript_squeeze(&t1, out1, sizeof(out1));

    voleith_transcript_init(&t2, 256, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t2, input, sizeof(input));
    voleith_transcript_squeeze(&t2, out2, sizeof(out2));

    check("determinism: same input same output (λ=256)",
          memcmp(out1, out2, 32) == 0);
}

/* ================================================================
 * Test 2: Domain separation
 * ================================================================ */
static void
test_domain_separation(void)
{
    static const uint8_t input[] = {0xAB, 0xCD, 0xEF};
    uint8_t out_h0[32], out_h1[32], out_h21[32], out_h22[32], out_h23[32];

    voleith_transcript_t t;

    voleith_transcript_init(&t, 128, VOLEITH_FS_H0);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_h0, 32);

    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_h1, 32);

    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_h21, 32);

    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_h22, 32);

    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_3);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_h23, 32);

    check("domain sep: H_0 != H_1", memcmp(out_h0, out_h1, 32) != 0);
    check("domain sep: H_0 != H_2^1", memcmp(out_h0, out_h21, 32) != 0);
    check("domain sep: H_1 != H_2^1", memcmp(out_h1, out_h21, 32) != 0);
    check("domain sep: H_2^1 != H_2^2", memcmp(out_h21, out_h22, 32) != 0);
    check("domain sep: H_2^2 != H_2^3", memcmp(out_h22, out_h23, 32) != 0);
}

/* ================================================================
 * Test 3: SHAKE variant selection by lambda
 * ================================================================ */
static void
test_shake_variant(void)
{
    static const uint8_t input[] = {0x11, 0x22, 0x33};
    uint8_t out128[32], out192[32], out256[32];

    voleith_transcript_t t;

    /* λ=128 uses SHAKE128 */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out128, 32);

    /* λ=192 uses SHAKE256 */
    voleith_transcript_init(&t, 192, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out192, 32);

    /* λ=256 uses SHAKE256 */
    voleith_transcript_init(&t, 256, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out256, 32);

    check("SHAKE variant: λ=128 (SHAKE128) != λ=192 (SHAKE256)",
          memcmp(out128, out192, 32) != 0);
    check("SHAKE variant: λ=192 == λ=256 (both SHAKE256)",
          memcmp(out192, out256, 32) == 0);
}

/* ================================================================
 * Test 4: Incremental absorb == one-shot absorb
 * ================================================================ */
static void
test_incremental_absorb(void)
{
    static const uint8_t data[] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
                                   0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
                                   0xD0, 0xE0, 0xF0, 0x00};
    uint8_t out_one[32], out_chunked[32];

    voleith_transcript_t t;

    /* One-shot: absorb all 16 bytes at once */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, data, 16);
    voleith_transcript_squeeze(&t, out_one, 32);

    /* Chunked: absorb 1 + 5 + 10 bytes */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, data, 1);
    voleith_transcript_absorb(&t, data + 1, 5);
    voleith_transcript_absorb(&t, data + 6, 10);
    voleith_transcript_squeeze(&t, out_chunked, 32);

    check("incremental absorb == one-shot absorb (λ=128)",
          memcmp(out_one, out_chunked, 32) == 0);

    /* Same for λ=256 */
    voleith_transcript_init(&t, 256, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, data, 16);
    voleith_transcript_squeeze(&t, out_one, 32);

    voleith_transcript_init(&t, 256, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, data, 4);
    voleith_transcript_absorb(&t, data + 4, 12);
    voleith_transcript_squeeze(&t, out_chunked, 32);

    check("incremental absorb == one-shot absorb (λ=256)",
          memcmp(out_one, out_chunked, 32) == 0);
}

/* ================================================================
 * Test 5: Squeeze chunking - outputs concatenate correctly
 * ================================================================ */
static void
test_squeeze_chunking(void)
{
    static const uint8_t input[] = {0xCA, 0xFE, 0xBA, 0xBE};
    uint8_t out_full[64];
    uint8_t out_chunked[64];

    voleith_transcript_t t;

    /* Full 64-byte squeeze in one call */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_full, 64);

    /* Same but squeeze 3 + 17 + 44 bytes */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_chunked, 3);
    voleith_transcript_squeeze(&t, out_chunked + 3, 17);
    voleith_transcript_squeeze(&t, out_chunked + 20, 44);

    check("squeeze chunking == full squeeze (λ=128)",
          memcmp(out_full, out_chunked, 64) == 0);

    /* Same for λ=256 */
    voleith_transcript_init(&t, 256, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_full, 64);

    voleith_transcript_init(&t, 256, VOLEITH_FS_H2_2);
    voleith_transcript_absorb(&t, input, sizeof(input));
    voleith_transcript_squeeze(&t, out_chunked, 16);
    voleith_transcript_squeeze(&t, out_chunked + 16, 48);

    check("squeeze chunking == full squeeze (λ=256)",
          memcmp(out_full, out_chunked, 64) == 0);
}

/* ================================================================
 * Test 6: Empty input
 * ================================================================ */
static void
test_empty_input(void)
{
    uint8_t out1[16], out2[16];

    /* Squeeze with no absorb calls - just domain sep byte */
    voleith_transcript_t t1, t2;
    voleith_transcript_init(&t1, 128, VOLEITH_FS_H0);
    voleith_transcript_squeeze(&t1, out1, 16);

    voleith_transcript_init(&t2, 128, VOLEITH_FS_H0);
    voleith_transcript_squeeze(&t2, out2, 16);

    check("empty input: deterministic", memcmp(out1, out2, 16) == 0);

    /* Empty input with H_0 vs H_1 must still differ */
    uint8_t out_h0[16], out_h1[16];
    voleith_transcript_t t;
    voleith_transcript_init(&t, 128, VOLEITH_FS_H0);
    voleith_transcript_squeeze(&t, out_h0, 16);
    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_squeeze(&t, out_h1, 16);

    check("empty input: H_0 != H_1", memcmp(out_h0, out_h1, 16) != 0);
}

/* ================================================================
 * Test 7: One-shot voleith_fs_hash matches incremental transcript
 * ================================================================ */
static void
test_oneshot_matches_incremental(void)
{
    static const uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x23, 0x45};
    uint8_t out_incremental[32], out_oneshot[32];

    voleith_transcript_t t;

    /* Incremental */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H2_3);
    voleith_transcript_absorb(&t, data, sizeof(data));
    voleith_transcript_squeeze(&t, out_incremental, 32);

    /* One-shot */
    voleith_fs_hash(128, VOLEITH_FS_H2_3, data, sizeof(data), out_oneshot, 32);

    check("one-shot matches incremental (λ=128)",
          memcmp(out_incremental, out_oneshot, 32) == 0);

    /* λ=192 */
    voleith_transcript_init(&t, 192, VOLEITH_FS_H3);
    voleith_transcript_absorb(&t, data, sizeof(data));
    voleith_transcript_squeeze(&t, out_incremental, 32);

    voleith_fs_hash(192, VOLEITH_FS_H3, data, sizeof(data), out_oneshot, 32);

    check("one-shot matches incremental (λ=192)",
          memcmp(out_incremental, out_oneshot, 32) == 0);

    /* Empty input: fs_hash with len=0 */
    voleith_transcript_init(&t, 128, VOLEITH_FS_H4);
    voleith_transcript_squeeze(&t, out_incremental, 16);

    voleith_fs_hash(128, VOLEITH_FS_H4, NULL, 0, out_oneshot, 16);

    check("one-shot empty input matches incremental",
          memcmp(out_incremental, out_oneshot, 16) == 0);
}

/* ================================================================
 * Test 8: All VOLEITH_FS_* domain separators produce distinct outputs
 * ================================================================ */
static void
test_all_domain_seps_distinct(void)
{
    static const uint8_t input[] = {0x55, 0xAA};

    static const uint8_t domain_seps[] = {
        VOLEITH_FS_H0,   VOLEITH_FS_H1,   VOLEITH_FS_H2_0, VOLEITH_FS_H2_1,
        VOLEITH_FS_H2_2, VOLEITH_FS_H2_3, VOLEITH_FS_H3,   VOLEITH_FS_H4,
    };
    static const size_t N = sizeof(domain_seps) / sizeof(domain_seps[0]);

    uint8_t outputs[8][16];
    voleith_transcript_t t;

    for (size_t i = 0; i < N; i++) {
        voleith_transcript_init(&t, 128, domain_seps[i]);
        voleith_transcript_absorb(&t, input, sizeof(input));
        voleith_transcript_squeeze(&t, outputs[i], 16);
    }

    int all_distinct = 1;
    for (size_t i = 0; i < N; i++) {
        for (size_t j = i + 1; j < N; j++) {
            if (memcmp(outputs[i], outputs[j], 16) == 0) {
                all_distinct = 0;
            }
        }
    }
    check("all 8 VOLEITH_FS_* domain separators produce distinct outputs",
          all_distinct);
}

/* ================================================================
 * Test 9: H_2^j domain seps are 8+j (spec correctness)
 * ================================================================ */
static void
test_h2j_domain_sep_values(void)
{
    check("H_2^0 domain sep == 8", VOLEITH_FS_H2_0 == 8);
    check("H_2^1 domain sep == 9", VOLEITH_FS_H2_1 == 9);
    check("H_2^2 domain sep == 10", VOLEITH_FS_H2_2 == 10);
    check("H_2^3 domain sep == 11", VOLEITH_FS_H2_3 == 11);
    check("H_0 domain sep == 0", VOLEITH_FS_H0 == 0);
    check("H_1 domain sep == 1", VOLEITH_FS_H1 == 1);
    check("H_3 domain sep == 3", VOLEITH_FS_H3 == 3);
    check("H_4 domain sep == 4", VOLEITH_FS_H4 == 4);
}

/* ================================================================
 * Test 10: Large output - XOF produces consistent long output
 * ================================================================ */
static void
test_large_output(void)
{
    static const uint8_t input[] = {0x01};
    /* 512 bytes - larger than one SHAKE128 block (168 bytes) and one SHAKE256
     * block (136 bytes), so multiple Keccak permutations are exercised */
    uint8_t out_full[512];
    uint8_t out_chunked[512];

    voleith_transcript_t t;

    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, input, 1);
    voleith_transcript_squeeze(&t, out_full, 512);

    voleith_transcript_init(&t, 128, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, input, 1);
    /* Squeeze in 100-byte chunks */
    for (int i = 0; i < 5; i++)
        voleith_transcript_squeeze(&t, out_chunked + i * 100, 100);
    voleith_transcript_squeeze(&t, out_chunked + 500, 12);

    check("large output: 512-byte squeeze == 100+100+...+12 bytes (λ=128)",
          memcmp(out_full, out_chunked, 512) == 0);

    /* λ=256 */
    voleith_transcript_init(&t, 256, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, input, 1);
    voleith_transcript_squeeze(&t, out_full, 512);

    voleith_transcript_init(&t, 256, VOLEITH_FS_H1);
    voleith_transcript_absorb(&t, input, 1);
    for (int i = 0; i < 5; i++)
        voleith_transcript_squeeze(&t, out_chunked + i * 100, 100);
    voleith_transcript_squeeze(&t, out_chunked + 500, 12);

    check("large output: 512-byte squeeze == chunks (λ=256)",
          memcmp(out_full, out_chunked, 512) == 0);
}

int
main(void)
{
    printf("test_fiat_shamir: Fiat-Shamir transcript API\n");

    test_determinism();
    test_domain_separation();
    test_shake_variant();
    test_incremental_absorb();
    test_squeeze_chunking();
    test_empty_input();
    test_oneshot_matches_incremental();
    test_all_domain_seps_distinct();
    test_h2j_domain_sep_values();
    test_large_output();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
