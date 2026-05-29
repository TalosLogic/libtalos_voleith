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

/* ================================================================
 * Public bit-plane primitives - validates the exports added for
 * core/grostl.c (and any other future consumer that shares the
 * bitsliced S-box without paying for a full AES round).
 *
 *   aes_ct64_bitslice_pack / _unpack must be inverses.
 *   aes_ct64_sbox_inplace_4blocks must reproduce the NIST AES S-box.
 *   aes_ct64_sbox_bitslice must match the convenience wrapper when
 *     composed manually with pack/unpack.
 * ================================================================ */

/* AES S-box (FIPS 197 §5.1.1).  Local copy for cross-validation
 * against the bitsliced implementation.  The production AES path
 * never instantiates this table - it computes S-box outputs via
 * the constant-time tower-field decomposition in aes_ct64.c. */
static const uint8_t NIST_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
};

static void
test_bitslice_pack_roundtrip(void)
{
    TEST("aes_ct64_bitslice_pack/unpack round-trip (64 trials)");

    int fail = 0;
    for (int t = 0; t < 64 && !fail; t++) {
        uint8_t in[64];
        uint8_t out[64];
        uint64_t q[8];

        fill_random(in, 64);
        aes_ct64_bitslice_pack(q, in);
        aes_ct64_bitslice_unpack(out, q);

        if (memcmp(in, out, 64) != 0) {
            fail = 1;
            printf("\n    trial %d: pack/unpack not identity", t);
        }
    }

    if (fail)
        FAIL("pack/unpack not identity");
    else
        PASS();
}

static void
test_sbox_inplace_against_nist(void)
{
    TEST("aes_ct64_sbox_inplace_4blocks vs NIST S-box (all 256 inputs)");

    /* Cover all 256 S-box inputs in four calls of 64 bytes each. */
    uint8_t state[64];
    uint8_t expected[64];
    int fail = 0;

    for (int chunk = 0; chunk < 4 && !fail; chunk++) {
        for (int i = 0; i < 64; i++) {
            state[i] = (uint8_t)(chunk * 64 + i);
            expected[i] = NIST_SBOX[chunk * 64 + i];
        }
        aes_ct64_sbox_inplace_4blocks(state);
        if (memcmp(state, expected, 64) != 0) {
            fail = 1;
            printf("\n    chunk %d (inputs %d..%d) mismatch", chunk, chunk * 64,
                   chunk * 64 + 63);
        }
    }

    if (fail)
        FAIL("S-box output != NIST table");
    else
        PASS();
}

static void
test_sbox_bitslice_consistency(void)
{
    TEST("aes_ct64_sbox_bitslice matches sbox_inplace_4blocks (64 trials)");

    int fail = 0;
    for (int t = 0; t < 64 && !fail; t++) {
        uint8_t in[64];
        uint8_t out_hi[64];
        uint8_t out_lo[64];
        uint64_t q[8];

        fill_random(in, 64);

        /* Path A: convenience wrapper. */
        memcpy(out_hi, in, 64);
        aes_ct64_sbox_inplace_4blocks(out_hi);

        /* Path B: bit-plane primitives composed manually. */
        aes_ct64_bitslice_pack(q, in);
        aes_ct64_sbox_bitslice(q);
        aes_ct64_bitslice_unpack(out_lo, q);

        if (memcmp(out_hi, out_lo, 64) != 0) {
            fail = 1;
            printf("\n    trial %d: convenience vs composed differ", t);
        }
    }

    if (fail)
        FAIL("low-level vs high-level mismatch");
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

    /* Public bit-plane primitives (exported for core/grostl.c). */
    printf("\n  Public bit-plane primitives\n");
    test_bitslice_pack_roundtrip();
    test_sbox_inplace_against_nist();
    test_sbox_bitslice_consistency();

    /* Full NIST KAT suite via shared runner. */
    failures += aes_kat_run_all("aes_ct64", aes_ct64_kat_adapter, &tests_run,
                                &tests_passed);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run && failures == 0) ? 0 : 1;
}
