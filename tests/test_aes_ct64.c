/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes_ct64.c - Tests for the bitsliced (constant-time,
 * portable) AES backend.
 *
 * NIST known-answer vectors are exercised via the shared
 * aes_kat_run_all() runner - same vector set as test_aes.  Tests
 * unique to this backend (packing-layout sentinel, x4 consistency,
 * differential vs voleith_aes) live in this file.
 *
 * Per docs/BITSLICED_AES_DESIGN.md "Test plan":
 *   - All KAT vectors via the shared runner.
 *   - Byte-order sentinel and S-box-via-encrypt cross-check
 *     against voleith_aes.
 *   - aes_ct64_encrypt_x4 vs four serial single-block encrypts.
 *   - Differential vs voleith_aes over random inputs.
 *
 * Item (13), constant-time disassembly review, is performed
 * out-of-band against build/core/aes_ct64.o.  Item (14), dudect-style
 * timing, is required pre-production and staged separately.
 */

#include "aes_ct64.h"
#include "aes.h"
#include "aes_kat_runner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-58s ", tests_run, name);                             \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("PASS\n");                                                      \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("FAIL: %s\n", msg);                                             \
    } while (0)

static void
hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* Deterministic LCG for reproducible "random" inputs.  Not for any
 * cryptographic purpose; just stable test data. */
static uint64_t lcg_state = 0xC0FFEE1234567890ULL;

static uint8_t
lcg_byte(void)
{
    lcg_state = lcg_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (uint8_t)(lcg_state >> 56);
}

static void
fill_random(uint8_t *buf, size_t n)
{
    for (size_t i = 0; i < n; i++)
        buf[i] = lcg_byte();
}

/* ================================================================
 * KAT-runner adapter for the aes_ct64 backend.
 * ================================================================ */

static int
aes_ct64_kat_adapter(int key_bits, const uint8_t *key, uint8_t out[16],
                     const uint8_t in[16])
{
    aes_ct64_ctx_t ctx;
    if (aes_ct64_key_expand(&ctx, key, key_bits) != 0)
        return -1;
    aes_ct64_encrypt(&ctx, out, in);
    aes_ct64_ctx_clear(&ctx);
    return 0;
}

/* ================================================================
 * Byte-order sentinel: pt[i] = i under zero key, compared against
 * the voleith_aes backend.  A pure permutation bug in the
 * bit-plane layout shows up here distinctly because the sentinel
 * is not symmetric.
 * ================================================================ */

static void
test_packing_sentinel(void)
{
    TEST("byte-order sentinel (pt[i] = i, zero key)");

    aes_ct64_ctx_t ctx_bs;
    voleith_aes_ctx_t ctx_ref;
    uint8_t key[16] = {0};
    uint8_t pt[16];
    uint8_t ct_bs[16];
    uint8_t ct_ref[16];

    for (int i = 0; i < 16; i++)
        pt[i] = (uint8_t)i;

    if (aes_ct64_key_expand(&ctx_bs, key, 128) != 0) {
        FAIL("key expand");
        return;
    }
    voleith_aes_key_expand(&ctx_ref, key, 128);

    aes_ct64_encrypt(&ctx_bs, ct_bs, pt);
    voleith_aes_encrypt(&ctx_ref, ct_ref, pt);

    aes_ct64_ctx_clear(&ctx_bs);
    voleith_aes_ctx_clear(&ctx_ref);

    if (memcmp(ct_bs, ct_ref, 16) != 0) {
        printf("\n    bs =");
        hex_print(ct_bs, 16);
        printf("\n    ref=");
        hex_print(ct_ref, 16);
        FAIL("layout mismatch");
    } else {
        PASS();
    }
}

/* ================================================================
 * S-box stress: encrypt 256 distinct plaintexts under the zero key
 * with byte 0 walking through 0..255, compare against voleith_aes
 * each time.  A faulty S-box bit-plane (e.g., a wrong gate in the
 * Canright tower) tends to break only a small fraction of inputs -
 * exhaustive coverage of byte 0 catches it where 64 random trials
 * might not.
 * ================================================================ */

static void
test_sbox_through_full_encrypt(void)
{
    TEST("S-box stress (256 inputs via full AES-128 encrypt)");

    aes_ct64_ctx_t ctx_bs;
    voleith_aes_ctx_t ctx_ref;
    uint8_t key[16] = {0};
    int fail = 0;

    if (aes_ct64_key_expand(&ctx_bs, key, 128) != 0) {
        FAIL("aes_ct64_key_expand returned -1");
        return;
    }
    voleith_aes_key_expand(&ctx_ref, key, 128);

    for (int b = 0; b < 256; b++) {
        uint8_t pt[16] = {0};
        uint8_t ct_bs[16];
        uint8_t ct_ref[16];
        pt[0] = (uint8_t)b;
        aes_ct64_encrypt(&ctx_bs, ct_bs, pt);
        voleith_aes_encrypt(&ctx_ref, ct_ref, pt);
        if (memcmp(ct_bs, ct_ref, 16) != 0) {
            fail = 1;
            printf("\n    input byte 0x%02x: bs=", b);
            hex_print(ct_bs, 16);
            printf("  ref=");
            hex_print(ct_ref, 16);
            break;
        }
    }

    aes_ct64_ctx_clear(&ctx_bs);
    voleith_aes_ctx_clear(&ctx_ref);

    if (fail)
        FAIL("ciphertext mismatch");
    else
        PASS();
}

/* ================================================================
 * Differential vs voleith_aes_* over random inputs.  The KAT
 * runner covers fixed NIST vectors; this catches anything the
 * fixed vectors might miss in the wider random space.
 * ================================================================ */

static void
differential_one(int key_bits, int trials, const char *name)
{
    TEST(name);

    int key_bytes = key_bits / 8;
    int fail = 0;

    for (int t = 0; t < trials && !fail; t++) {
        uint8_t key[32];
        uint8_t pt[16];
        uint8_t ct_bs[16];
        uint8_t ct_ref[16];
        aes_ct64_ctx_t ctx_bs;
        voleith_aes_ctx_t ctx_ref;

        fill_random(key, key_bytes);
        fill_random(pt, 16);

        if (aes_ct64_key_expand(&ctx_bs, key, key_bits) != 0) {
            FAIL("key expand");
            return;
        }
        voleith_aes_key_expand(&ctx_ref, key, key_bits);

        aes_ct64_encrypt(&ctx_bs, ct_bs, pt);
        voleith_aes_encrypt(&ctx_ref, ct_ref, pt);

        if (memcmp(ct_bs, ct_ref, 16) != 0) {
            fail = 1;
            printf("\n    trial %d: key=", t);
            hex_print(key, key_bytes);
            printf("\n              pt =");
            hex_print(pt, 16);
            printf("\n              bs =");
            hex_print(ct_bs, 16);
            printf("\n              ref=");
            hex_print(ct_ref, 16);
        }

        aes_ct64_ctx_clear(&ctx_bs);
        voleith_aes_ctx_clear(&ctx_ref);
    }

    if (fail)
        FAIL("differential mismatch");
    else
        PASS();
}

/* ================================================================
 * _x4 vs four serial single-block encrypts.  Designed to catch
 * cross-block leakage in the bit-plane state (e.g., a missing mask
 * in ShiftRows or MixColumns).
 * ================================================================ */

static void
test_x4_consistency(void)
{
    TEST("aes_ct64_encrypt_x4 vs four serial encrypts (128 trials)");

    int fail = 0;
    for (int t = 0; t < 128 && !fail; t++) {
        uint8_t key[16];
        uint8_t in[64];
        uint8_t out_x4[64];
        uint8_t out_serial[64];
        aes_ct64_ctx_t ctx;

        fill_random(key, 16);
        fill_random(in, 64);

        if (aes_ct64_key_expand(&ctx, key, 128) != 0) {
            FAIL("key expand");
            return;
        }
        aes_ct64_encrypt_x4(&ctx, out_x4, in);
        for (int b = 0; b < 4; b++)
            aes_ct64_encrypt(&ctx, out_serial + 16 * b, in + 16 * b);
        aes_ct64_ctx_clear(&ctx);

        if (memcmp(out_x4, out_serial, 64) != 0) {
            fail = 1;
            for (int b = 0; b < 4; b++) {
                if (memcmp(out_x4 + 16 * b, out_serial + 16 * b, 16) != 0) {
                    printf("\n    trial %d block %d differs", t, b);
                }
            }
        }
    }

    if (fail)
        FAIL("x4 / serial mismatch");
    else
        PASS();
}

int
main(void)
{
    int failures = 0;

    printf("aes_ct64 tests\n");
    printf("==============\n");
    printf("voleith_aes active backend: %s\n", voleith_aes_backend_name());

    /* Backend-specific tests. */
    printf("\n  Backend-specific\n");
    test_packing_sentinel();
    test_sbox_through_full_encrypt();
    differential_one(128, 64,
                     "AES-128 differential vs voleith_aes (64 trials)");
    differential_one(192, 64,
                     "AES-192 differential vs voleith_aes (64 trials)");
    differential_one(256, 64,
                     "AES-256 differential vs voleith_aes (64 trials)");
    test_x4_consistency();

    /* Full NIST KAT suite via shared runner. */
    failures += aes_kat_run_all("aes_ct64", aes_ct64_kat_adapter, &tests_run,
                                &tests_passed);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run && failures == 0) ? 0 : 1;
}
