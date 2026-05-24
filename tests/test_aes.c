/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_aes.c - Tests for the voleith_aes backend (AES-NI or
 * table-lookup software, depending on build flags).
 *
 * NIST known-answer vectors are exercised via the shared
 * aes_kat_run_all() runner - same vector set as test_aes_ct64.
 * This file also covers the backend-specific tests that the runner
 * does not handle: FIPS 197 Appendix A round-key inspection,
 * in-place (aliased in==out) encryption, and rejection of invalid
 * key sizes.
 */

#include "aes.h"
#include "aes_kat_runner.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;

static void
hex_print(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  [%2d] %-50s ", tests_run, name);                             \
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

/* ================================================================
 * KAT-runner adapter for the voleith_aes backend.
 * ================================================================ */

static int
voleith_aes_kat_adapter(int key_bits, const uint8_t *key, uint8_t out[16],
                        const uint8_t in[16])
{
    voleith_aes_ctx_t ctx;
    if (voleith_aes_key_expand(&ctx, key, key_bits) != 0)
        return -1;
    voleith_aes_encrypt(&ctx, out, in);
    voleith_aes_ctx_clear(&ctx);
    return 0;
}

/* ================================================================
 * FIPS 197 Appendix A - round-key inspection.
 *
 * The KAT runner validates that the final ciphertext is correct;
 * these tests verify intermediate state (the last round key) to
 * catch a class of key-schedule bug where the first and last bytes
 * land correctly but middle bytes are wrong.  Backend-specific
 * because they peek at the ctx.rk byte layout - only the AES-NI
 * and variable-time backends carry round keys in that layout; the
 * bitsliced backend uses a bit-plane representation that this test
 * cannot inspect directly.  Bitsliced correctness for key schedule
 * is established by the KAT runner.
 * ================================================================ */

#if defined(VOLEITH_HAVE_AES_NI) || defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)

static void
test_aes128_key_expansion(void)
{
    TEST("AES-128 key expansion (FIPS 197 A.1)");

    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    const uint8_t last_rk[16] = {0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee,
                                 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8,
                                 0xb6, 0x63, 0x0c, 0xa6};
    voleith_aes_ctx_t ctx;

    voleith_aes_key_expand(&ctx, key, 128);

    if (memcmp(&ctx.rk[160], last_rk, 16) != 0) {
        printf("FAIL\n    expected last rk: ");
        hex_print(last_rk, 16);
        printf("\n    got:               ");
        hex_print(&ctx.rk[160], 16);
        printf("\n");
        return;
    }
    PASS();
}

static void
test_aes256_key_expansion(void)
{
    TEST("AES-256 key expansion (FIPS 197 A.3)");

    const uint8_t key[32] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                             0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                             0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                             0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
    const uint8_t last_rk[16] = {0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18,
                                 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44,
                                 0x70, 0x6c, 0x63, 0x1e};
    voleith_aes_ctx_t ctx;

    voleith_aes_key_expand(&ctx, key, 256);

    if (memcmp(&ctx.rk[224], last_rk, 16) != 0) {
        printf("FAIL\n    expected last rk: ");
        hex_print(last_rk, 16);
        printf("\n    got:               ");
        hex_print(&ctx.rk[224], 16);
        printf("\n");
        return;
    }
    PASS();
}

#endif /* VOLEITH_HAVE_AES_NI || VOLEITH_ALLOW_VARIABLE_TIME_AES */

/* ================================================================
 * In-place (aliased in == out) encrypt.
 * ================================================================ */

static void
test_aes128_inplace(void)
{
    TEST("AES-128 in-place encryption");

    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t buf[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                       0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    const uint8_t expected[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                  0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                  0x19, 0x6a, 0x0b, 0x32};
    voleith_aes_ctx_t ctx;

    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt(&ctx, buf, buf);

    if (memcmp(buf, expected, 16) != 0) {
        printf("FAIL\n    expected: ");
        hex_print(expected, 16);
        printf("\n    got:      ");
        hex_print(buf, 16);
        printf("\n");
        return;
    }
    PASS();
}

/* ================================================================
 * voleith_aes_encrypt_x4 vs four serial single-block encrypts.
 *
 * The default implementation chains four single-block calls, so
 * this test mainly guards against future backend-specific overrides
 * (e.g., dispatch to aes_ct64_encrypt_x4) introducing a divergence.
 * Also exercises aliasing of in/out, which the public API allows.
 * ================================================================ */

static void
test_aes128_encrypt_x4(void)
{
    TEST("AES-128 voleith_aes_encrypt_x4 vs four serial encrypts");

    const uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    /* Four distinct plaintexts to exercise per-block routing. */
    const uint8_t in[64] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e,
        0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03,
        0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, 0x30,
        0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19,
        0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b,
        0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10};
    uint8_t out_x4[64];
    uint8_t out_serial[64];
    voleith_aes_ctx_t ctx;

    voleith_aes_key_expand(&ctx, key, 128);
    voleith_aes_encrypt_x4(&ctx, out_x4, in);
    for (int b = 0; b < 4; b++)
        voleith_aes_encrypt(&ctx, out_serial + 16 * b, in + 16 * b);

    if (memcmp(out_x4, out_serial, 64) != 0) {
        printf("FAIL\n");
        for (int b = 0; b < 4; b++) {
            if (memcmp(out_x4 + 16 * b, out_serial + 16 * b, 16) != 0) {
                printf("    block %d x4:    ", b);
                hex_print(out_x4 + 16 * b, 16);
                printf("\n    block %d serial:", b);
                hex_print(out_serial + 16 * b, 16);
                printf("\n");
            }
        }
        voleith_aes_ctx_clear(&ctx);
        return;
    }

    /* Aliased in/out: scratch buffer encrypted in place. */
    uint8_t buf[64];
    memcpy(buf, in, 64);
    voleith_aes_encrypt_x4(&ctx, buf, buf);
    if (memcmp(buf, out_serial, 64) != 0) {
        printf("FAIL (aliased in==out)\n");
        voleith_aes_ctx_clear(&ctx);
        return;
    }

    voleith_aes_ctx_clear(&ctx);
    PASS();
}

/* ================================================================
 * Invalid key-size rejection.
 * ================================================================ */

static void
test_invalid_key_size(void)
{
    TEST("AES invalid key size returns error");

    voleith_aes_ctx_t ctx;
    uint8_t key[16] = {0};

    if (voleith_aes_key_expand(&ctx, key, 64) == -1 &&
        voleith_aes_key_expand(&ctx, key, 0) == -1 &&
        voleith_aes_key_expand(&ctx, key, 512) == -1) {
        PASS();
    } else {
        FAIL("should return -1 for invalid key sizes");
    }
}

/* ================================================================
 * Main
 * ================================================================ */

int
main(void)
{
    int failures = 0;

    printf("AES tests (voleith_aes backend)\n");
    printf("================================\n");
    printf("active backend: %s\n", voleith_aes_backend_name());

    /* Backend-specific tests. */
    printf("\n  Backend-specific\n");
#if defined(VOLEITH_HAVE_AES_NI) || defined(VOLEITH_ALLOW_VARIABLE_TIME_AES)
    test_aes128_key_expansion();
    test_aes256_key_expansion();
#endif
    test_aes128_inplace();
    test_aes128_encrypt_x4();
    test_invalid_key_size();

    /* Full NIST KAT suite via shared runner. */
    failures += aes_kat_run_all("voleith_aes", voleith_aes_kat_adapter,
                                &tests_run, &tests_passed);

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run && failures == 0) ? 0 : 1;
}
