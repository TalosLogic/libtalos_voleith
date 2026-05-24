/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_prg.c - PRG tests
 *
 * Tests the tweakable PRG (AES-CTR) from FAEST spec Figure 3.6.
 * Since the PRG is AES-CTR, we can verify against known AES outputs
 * by constructing the expected counter blocks manually.
 */

#include "prg.h"
#include "aes.h"
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

/* ========================================================================
 * PRG consistency: verify that PRG output matches manual AES-CTR
 *
 * We manually construct what the PRG should output:
 *   key = AES-128.KeyExpand(seed)
 *   iv' = AddToUpperWord(iv, twk)
 *   block_i = AES-128.Encrypt(key, AddToLowerWord(iv', i))
 * ======================================================================== */

static void
test_prg128_consistency(void)
{
    TEST("PRG-128 consistency with manual AES-CTR");

    /* Arbitrary seed, IV, tweak */
    const uint8_t seed[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    const uint8_t iv[16] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    uint32_t twk = 5;

    /* Compute expected output manually */
    voleith_aes_ctx_t aes;
    voleith_aes_key_expand(&aes, seed, 128);

    /* iv' = AddToUpperWord(iv, twk) */
    uint8_t iv_tweaked[16];
    memcpy(iv_tweaked, iv, 16);
    uint32_t upper =
        (uint32_t)iv_tweaked[12] | ((uint32_t)iv_tweaked[13] << 8) |
        ((uint32_t)iv_tweaked[14] << 16) | ((uint32_t)iv_tweaked[15] << 24);
    upper += twk;
    iv_tweaked[12] = (uint8_t)(upper);
    iv_tweaked[13] = (uint8_t)(upper >> 8);
    iv_tweaked[14] = (uint8_t)(upper >> 16);
    iv_tweaked[15] = (uint8_t)(upper >> 24);

    /* Generate 3 blocks manually = 48 bytes = 384 bits */
    uint8_t expected[48];
    for (int i = 0; i < 3; i++) {
        uint8_t ctr_block[16];
        memcpy(ctr_block, iv_tweaked, 16);
        uint32_t lower =
            (uint32_t)ctr_block[0] | ((uint32_t)ctr_block[1] << 8) |
            ((uint32_t)ctr_block[2] << 16) | ((uint32_t)ctr_block[3] << 24);
        lower += (uint32_t)i;
        ctr_block[0] = (uint8_t)(lower);
        ctr_block[1] = (uint8_t)(lower >> 8);
        ctr_block[2] = (uint8_t)(lower >> 16);
        ctr_block[3] = (uint8_t)(lower >> 24);

        voleith_aes_encrypt(&aes, expected + i * 16, ctr_block);
    }

    /* Generate using PRG */
    uint8_t prg_out[48];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 128);
    voleith_prg_gen(&prg, prg_out, iv, twk, 384);

    if (memcmp(prg_out, expected, 48) != 0) {
        printf("FAIL\n    expected: ");
        hex_print(expected, 48);
        printf("\n    got:      ");
        hex_print(prg_out, 48);
        printf("\n");
        return;
    }
    PASS();
}

/* ========================================================================
 * PRG with tweak=0: verify the basic case
 * ======================================================================== */

static void
test_prg128_no_tweak(void)
{
    TEST("PRG-128 with twk=0 (no tweak)");

    const uint8_t seed[16] = {0};
    const uint8_t iv[16] = {0};

    /* Block 0: AES-128(0, 0) = known value */
    voleith_aes_ctx_t aes;
    voleith_aes_key_expand(&aes, seed, 128);

    uint8_t expected[16];
    uint8_t zero_iv[16] = {0};
    voleith_aes_encrypt(&aes, expected, zero_iv);

    uint8_t prg_out[16];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 128);
    voleith_prg_gen(&prg, prg_out, iv, 0, 128);

    if (memcmp(prg_out, expected, 16) != 0) {
        printf("FAIL\n    expected: ");
        hex_print(expected, 16);
        printf("\n    got:      ");
        hex_print(prg_out, 16);
        printf("\n");
        return;
    }
    PASS();
}

/* ========================================================================
 * PRG partial block: m not a multiple of 128
 * ======================================================================== */

static void
test_prg128_partial(void)
{
    TEST("PRG-128 partial block (200 bits)");

    const uint8_t seed[16] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
                              0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    const uint8_t iv[16] = {0};

    /* 200 bits = 1 full block (128) + 72 bits (9 bytes) */
    /* Generate expected: encrypt block 0 and block 1 */
    voleith_aes_ctx_t aes;
    voleith_aes_key_expand(&aes, seed, 128);

    uint8_t block0_in[16] = {0}, block1_in[16] = {0};
    block1_in[0] = 1;     /* AddToLowerWord(iv, 1) */
    uint8_t expected[25]; /* ceil(200/8) = 25 bytes */
    voleith_aes_encrypt(&aes, expected, block0_in);
    uint8_t block1_out[16];
    voleith_aes_encrypt(&aes, block1_out, block1_in);
    memcpy(expected + 16, block1_out, 9);

    /* PRG output */
    uint8_t prg_out[25];
    memset(prg_out, 0xff, 25); /* fill to detect over-write */
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 128);
    voleith_prg_gen(&prg, prg_out, iv, 0, 200);

    /* First 24 bytes should match exactly */
    if (memcmp(prg_out, expected, 24) != 0) {
        printf("FAIL (first 24 bytes)\n    expected: ");
        hex_print(expected, 24);
        printf("\n    got:      ");
        hex_print(prg_out, 24);
        printf("\n");
        return;
    }

    /* Last byte: only low 8 bits are valid (200 - 192 = 8 bits, all valid) */
    if (prg_out[24] != expected[24]) {
        printf("FAIL (byte 24): expected %02x got %02x\n", expected[24],
               prg_out[24]);
        return;
    }
    PASS();
}

/* ========================================================================
 * PRG-192 consistency
 * ======================================================================== */

static void
test_prg192_consistency(void)
{
    TEST("PRG-192 consistency with manual AES-CTR");

    const uint8_t seed[24] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const uint8_t iv[16] = {0};
    uint32_t twk = 0;

    voleith_aes_ctx_t aes;
    voleith_aes_key_expand(&aes, seed, 192);

    uint8_t expected[32];
    uint8_t ctr0[16] = {0}, ctr1[16] = {0};
    ctr1[0] = 1;
    voleith_aes_encrypt(&aes, expected, ctr0);
    voleith_aes_encrypt(&aes, expected + 16, ctr1);

    uint8_t prg_out[32];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 192);
    voleith_prg_gen(&prg, prg_out, iv, twk, 256);

    if (memcmp(prg_out, expected, 32) != 0) {
        printf("FAIL\n    expected: ");
        hex_print(expected, 32);
        printf("\n    got:      ");
        hex_print(prg_out, 32);
        printf("\n");
        return;
    }
    PASS();
}

/* ========================================================================
 * PRG-256 consistency
 * ======================================================================== */

static void
test_prg256_consistency(void)
{
    TEST("PRG-256 consistency with manual AES-CTR");

    const uint8_t seed[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    const uint8_t iv[16] = {0};
    uint32_t twk = 42;

    voleith_aes_ctx_t aes;
    voleith_aes_key_expand(&aes, seed, 256);

    /* iv' = AddToUpperWord(0, 42) => upper 32 bits = 42 */
    uint8_t iv_tweaked[16] = {0};
    iv_tweaked[12] = 42;

    uint8_t expected[32];
    uint8_t ctr0[16], ctr1[16];
    memcpy(ctr0, iv_tweaked, 16);
    memcpy(ctr1, iv_tweaked, 16);
    ctr1[0] = 1;
    voleith_aes_encrypt(&aes, expected, ctr0);
    voleith_aes_encrypt(&aes, expected + 16, ctr1);

    uint8_t prg_out[32];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 256);
    voleith_prg_gen(&prg, prg_out, iv, twk, 256);

    if (memcmp(prg_out, expected, 32) != 0) {
        printf("FAIL\n    expected: ");
        hex_print(expected, 32);
        printf("\n    got:      ");
        hex_print(prg_out, 32);
        printf("\n");
        return;
    }
    PASS();
}

/* ========================================================================
 * faest-ref known-answer test vectors (from prg_tvs.hpp)
 * ======================================================================== */

static void
test_prg128_faest_ref(void)
{
    TEST("PRG-128 faest-ref known-answer vector");

    const uint8_t key[16] = {
        0xe1, 0x52, 0x3a, 0x89, 0x80, 0xc1, 0x62, 0x83,
        0xcb, 0xc8, 0x5e, 0x71, 0x70, 0x3a, 0x04, 0xd1,
    };
    const uint8_t iv[16] = {
        0xd2, 0x33, 0x1c, 0x8b, 0xd9, 0x1b, 0x1e, 0x01,
        0x56, 0x59, 0x09, 0x44, 0x47, 0x2d, 0x2d, 0xd3,
    };
    uint32_t twk = 1180718807u;

    const uint8_t expected[232] = {
        0x94, 0xc4, 0xa8, 0xf5, 0x92, 0xd2, 0x43, 0x1c, 0x94, 0x62, 0xb8, 0x81,
        0xed, 0x17, 0x91, 0xdb, 0x1a, 0x91, 0xf4, 0x82, 0xf0, 0xe0, 0xa0, 0x77,
        0x30, 0xad, 0xa8, 0xd9, 0xb4, 0x90, 0x87, 0xfb, 0x4d, 0x55, 0x65, 0xc2,
        0x80, 0xdf, 0x8b, 0x56, 0x1d, 0x98, 0xa3, 0x04, 0xf4, 0xa7, 0x13, 0xe7,
        0x1b, 0xa1, 0xae, 0x37, 0xfa, 0xc5, 0x91, 0x2d, 0x7c, 0x7d, 0xf3, 0x13,
        0xd8, 0x12, 0xa1, 0xa1, 0x71, 0x58, 0xaa, 0xa4, 0x57, 0x83, 0x3e, 0x4d,
        0xbc, 0x86, 0x73, 0x79, 0xc4, 0x44, 0xb2, 0xe6, 0xa2, 0x70, 0xc0, 0x45,
        0x4f, 0x06, 0xb6, 0x76, 0x5e, 0x06, 0x27, 0x23, 0x36, 0x78, 0x3f, 0x89,
        0x7c, 0x35, 0xd8, 0x2f, 0x81, 0xe7, 0xd9, 0xc1, 0x92, 0x95, 0xeb, 0xdc,
        0xed, 0x0f, 0xdb, 0x19, 0x8d, 0xc4, 0x4d, 0x57, 0xbf, 0xa4, 0x29, 0x6d,
        0x80, 0xda, 0x88, 0x27, 0x6c, 0xe4, 0x46, 0xa4, 0x7a, 0xee, 0xce, 0x14,
        0x5f, 0x58, 0x14, 0x2c, 0x5a, 0xfe, 0x0e, 0xc5, 0x54, 0xc7, 0x13, 0xac,
        0x70, 0x7c, 0x7f, 0x37, 0xb1, 0xf6, 0xe3, 0x6c, 0x72, 0x8b, 0x4d, 0xa4,
        0x14, 0xa6, 0x25, 0xbf, 0xcb, 0x11, 0xda, 0x53, 0x10, 0xad, 0x14, 0xd0,
        0xf6, 0xf9, 0x3b, 0x7e, 0x4b, 0x5a, 0xbd, 0xd0, 0x0a, 0xd8, 0xd4, 0x6f,
        0x45, 0xc8, 0x92, 0x2c, 0x27, 0x30, 0x58, 0x07, 0x11, 0x4b, 0x0b, 0xd6,
        0xd4, 0xcc, 0xe5, 0x56, 0x2b, 0x0a, 0x93, 0x34, 0x7b, 0x87, 0x36, 0xca,
        0x48, 0x96, 0xa4, 0x6b, 0x63, 0x66, 0xeb, 0xbc, 0xf8, 0xf7, 0xef, 0x50,
        0x38, 0x15, 0x3f, 0x59, 0x05, 0x95, 0xc5, 0x6f, 0xba, 0x3b, 0xa7, 0x5f,
        0xfe, 0xf8, 0x26, 0xf7,
    };

    uint8_t prg_out[232];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, key, 128);
    voleith_prg_gen(&prg, prg_out, iv, twk, 232 * 8);

    if (memcmp(prg_out, expected, 232) != 0) {
        printf("FAIL\n    expected first 16: ");
        hex_print(expected, 16);
        printf("\n    got first 16:      ");
        hex_print(prg_out, 16);
        printf("\n");
        return;
    }
    PASS();
}

static void
test_prg192_faest_ref(void)
{
    TEST("PRG-192 faest-ref known-answer vector");

    const uint8_t key[24] = {
        0x2c, 0x15, 0x0b, 0x96, 0xcb, 0x0e, 0xc4, 0x07, 0x1a, 0x05, 0x46, 0x74,
        0xcd, 0x35, 0x2e, 0xd4, 0xda, 0x35, 0x33, 0x8b, 0xea, 0x59, 0xad, 0x66,
    };
    const uint8_t iv[16] = {
        0x06, 0x08, 0xc1, 0x2f, 0x86, 0xe8, 0xeb, 0x59,
        0x47, 0x75, 0xa7, 0x31, 0xdf, 0x92, 0x8c, 0x81,
    };
    uint32_t twk = 2615172839u;

    const uint8_t expected[232] = {
        0x0e, 0x58, 0x96, 0xbe, 0x5b, 0x55, 0x7e, 0xc3, 0x38, 0xa7, 0x90, 0x1b,
        0x47, 0xd8, 0x37, 0xe5, 0x9a, 0x6a, 0x31, 0xbb, 0xf7, 0xa4, 0x8f, 0x2a,
        0x6a, 0x66, 0x8c, 0x54, 0x16, 0xdb, 0x91, 0xae, 0xee, 0xac, 0x13, 0x50,
        0x7b, 0x8f, 0xf9, 0x23, 0x7a, 0x77, 0x4a, 0xd1, 0x99, 0x95, 0xa7, 0x96,
        0x47, 0x0d, 0x6e, 0x1f, 0x43, 0x88, 0x0e, 0x83, 0xef, 0x8c, 0x1c, 0xf3,
        0x4f, 0xd4, 0x1a, 0x31, 0xa9, 0x33, 0x35, 0x5c, 0x65, 0x53, 0x2c, 0x7c,
        0x64, 0x4d, 0xdd, 0xf8, 0xc2, 0x8d, 0x9f, 0xf5, 0x81, 0x81, 0xe8, 0x4d,
        0x82, 0xbc, 0x13, 0xd2, 0x7c, 0x16, 0xe7, 0x21, 0xab, 0xde, 0x71, 0x7d,
        0x60, 0x42, 0xb2, 0x6e, 0xaf, 0x34, 0xd7, 0xf1, 0x01, 0x33, 0xc3, 0x37,
        0xe0, 0x09, 0x34, 0xb3, 0x5c, 0xcf, 0xf6, 0x5b, 0xec, 0x3a, 0x97, 0x14,
        0x0e, 0xb5, 0x36, 0xb0, 0x8a, 0x0a, 0x68, 0x18, 0xda, 0x75, 0x68, 0xed,
        0x37, 0x07, 0x27, 0x86, 0x82, 0xf6, 0x58, 0xc6, 0xe0, 0x81, 0x0e, 0x3b,
        0x59, 0x0b, 0x59, 0xd1, 0x9d, 0xe0, 0xde, 0xb2, 0xdf, 0x90, 0xea, 0x74,
        0x4b, 0xcb, 0x00, 0xb9, 0x14, 0x93, 0xe7, 0x65, 0x9b, 0xab, 0x45, 0x3c,
        0x6e, 0xbd, 0xa6, 0x68, 0xf5, 0x6b, 0x8e, 0x48, 0x71, 0xbd, 0x43, 0x44,
        0x01, 0xb8, 0xb7, 0x53, 0x70, 0x29, 0x9e, 0xf0, 0xaa, 0x8c, 0x6e, 0x2f,
        0x38, 0x67, 0x23, 0xd1, 0xd1, 0x34, 0x4c, 0xae, 0x82, 0x75, 0x11, 0x07,
        0xd7, 0x50, 0x8e, 0x23, 0x81, 0x88, 0x08, 0x1c, 0xd3, 0x41, 0x58, 0xed,
        0x6d, 0xca, 0x04, 0x09, 0xd7, 0xca, 0x21, 0x1c, 0x69, 0x77, 0x19, 0x39,
        0x1d, 0xab, 0x81, 0xb6,
    };

    uint8_t prg_out[232];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, key, 192);
    voleith_prg_gen(&prg, prg_out, iv, twk, 232 * 8);

    if (memcmp(prg_out, expected, 232) != 0) {
        printf("FAIL\n    expected first 16: ");
        hex_print(expected, 16);
        printf("\n    got first 16:      ");
        hex_print(prg_out, 16);
        printf("\n");
        return;
    }
    PASS();
}

static void
test_prg256_faest_ref(void)
{
    TEST("PRG-256 faest-ref known-answer vector");

    const uint8_t key[32] = {
        0x2d, 0x2a, 0xe2, 0xd8, 0x95, 0x9c, 0x2a, 0x52, 0xca, 0x6f, 0x92,
        0xb7, 0xb1, 0x8e, 0x4c, 0x58, 0x01, 0xda, 0x83, 0xd0, 0x6d, 0x44,
        0x1a, 0x84, 0x89, 0xec, 0xb9, 0xb9, 0xe0, 0xb0, 0xd2, 0xe1,
    };
    const uint8_t iv[16] = {
        0x15, 0x79, 0x77, 0x10, 0x74, 0xf1, 0xab, 0x33,
        0x81, 0x46, 0x57, 0xc2, 0xb4, 0x39, 0x53, 0x43,
    };
    uint32_t twk = 4046638322u;

    const uint8_t expected[232] = {
        0x59, 0x4a, 0x97, 0x85, 0xc6, 0x88, 0xae, 0x2a, 0x1f, 0x53, 0x5b, 0x2d,
        0x33, 0xe8, 0x98, 0xe9, 0xae, 0x3b, 0x00, 0x66, 0x52, 0xe5, 0x62, 0x7f,
        0xfe, 0xf9, 0x67, 0x6f, 0xe4, 0x79, 0x8f, 0x4b, 0xbb, 0x2d, 0x7d, 0x96,
        0xb3, 0x5a, 0x22, 0xcd, 0xdb, 0xcf, 0x9e, 0xa8, 0x8d, 0x2a, 0x67, 0x4f,
        0x55, 0x29, 0x0c, 0x9c, 0xdd, 0x8d, 0x7a, 0x25, 0xc8, 0x6b, 0xbb, 0x23,
        0x11, 0xe3, 0x84, 0xe3, 0xbf, 0x91, 0x48, 0x40, 0x5c, 0xc3, 0x85, 0x9b,
        0x59, 0xb8, 0x82, 0xf9, 0x5c, 0x59, 0xf7, 0x14, 0x3c, 0xb0, 0xfb, 0xc0,
        0xb4, 0x7d, 0xb9, 0xb3, 0x0e, 0xf2, 0xd8, 0x86, 0xfe, 0xcd, 0x3e, 0xad,
        0xd1, 0x4d, 0xbd, 0x16, 0x2b, 0xa5, 0xd9, 0xcb, 0x2c, 0xaa, 0xbd, 0xea,
        0xd3, 0x90, 0x13, 0x81, 0x8b, 0x21, 0xa1, 0xa3, 0xc4, 0xa6, 0x4d, 0x48,
        0xa2, 0x04, 0xf1, 0x0e, 0x8a, 0xd3, 0x4a, 0xe8, 0xcd, 0xaf, 0x6b, 0xea,
        0x49, 0x80, 0x61, 0xd8, 0xf0, 0x2c, 0x6f, 0x77, 0x7d, 0xc5, 0x5f, 0x42,
        0x0d, 0xae, 0xd4, 0xb4, 0xbe, 0xb0, 0x14, 0x40, 0x33, 0x5b, 0xa6, 0xc3,
        0x2b, 0x9f, 0x28, 0x16, 0xcb, 0xcc, 0x15, 0x0c, 0xd6, 0x75, 0x7b, 0xf7,
        0xa9, 0x79, 0x21, 0xae, 0x02, 0x68, 0x9f, 0x90, 0x04, 0xea, 0x46, 0x7a,
        0x71, 0x52, 0x01, 0x11, 0xf0, 0xa8, 0x10, 0xf7, 0xfe, 0x98, 0x7a, 0x43,
        0xe2, 0x93, 0x3c, 0xbe, 0x2d, 0x81, 0x3a, 0x0b, 0xeb, 0x45, 0x5a, 0x03,
        0x95, 0x4a, 0x92, 0x11, 0x41, 0x62, 0xa9, 0x89, 0xce, 0x78, 0xf9, 0xdd,
        0xdc, 0xc7, 0xf3, 0x93, 0xbd, 0x47, 0xb5, 0x89, 0x65, 0x5b, 0xb1, 0x7a,
        0xbf, 0xee, 0x1c, 0x45,
    };

    uint8_t prg_out[232];
    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, key, 256);
    voleith_prg_gen(&prg, prg_out, iv, twk, 232 * 8);

    if (memcmp(prg_out, expected, 232) != 0) {
        printf("FAIL\n    expected first 16: ");
        hex_print(expected, 16);
        printf("\n    got first 16:      ");
        hex_print(prg_out, 16);
        printf("\n");
        return;
    }
    PASS();
}

/* ========================================================================
 * PRG different tweaks produce different output
 * ======================================================================== */

static void
test_prg_different_tweaks(void)
{
    TEST("PRG different tweaks produce different output");

    const uint8_t seed[16] = {0x42};
    const uint8_t iv[16] = {0};

    voleith_prg_ctx_t prg;
    voleith_prg_init(&prg, seed, 128);

    uint8_t out1[16], out2[16];
    voleith_prg_gen(&prg, out1, iv, 0, 128);
    voleith_prg_gen(&prg, out2, iv, 1, 128);

    if (memcmp(out1, out2, 16) == 0) {
        FAIL("different tweaks produced same output");
        return;
    }
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int
main(void)
{
    printf("PRG tests\n");
    printf("=========\n\n");

    test_prg128_consistency();
    test_prg128_no_tweak();
    test_prg128_partial();
    test_prg192_consistency();
    test_prg256_consistency();
    test_prg128_faest_ref();
    test_prg192_faest_ref();
    test_prg256_faest_ref();
    test_prg_different_tweaks();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
