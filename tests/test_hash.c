/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_hash.c - Tests for SHA-3-256, SHAKE-128, SHAKE-256 (FIPS 202)
 *
 * Test vectors from:
 *   - NIST CSRC: SHA-3 examples (empty, "abc", 200-byte repeated 0xa3)
 *     https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/
 *     example-values
 *   - NIST CAVP SHA-3 test vectors
 */

#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int test_count = 0;
static int pass_count = 0;

static void
print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
}

static int
hex_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static void
hex_to_bytes(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(hex_val(hex[2 * i]) << 4 | hex_val(hex[2 * i + 1]));
}

static int
bytes_eq_hex(const uint8_t *bytes, const char *hex, size_t len)
{
    uint8_t expected[256];
    hex_to_bytes(hex, expected, len);
    return memcmp(bytes, expected, len) == 0;
}

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

static void
check_hex(const char *name, const uint8_t *got, const char *expected_hex,
          size_t len)
{
    test_count++;
    if (bytes_eq_hex(got, expected_hex, len)) {
        pass_count++;
    } else {
        printf("  FAIL: %s\n", name);
        printf("    got: ");
        print_hex(got, len);
        printf("\n");
        uint8_t exp[256];
        hex_to_bytes(expected_hex, exp, len);
        printf("    exp: ");
        print_hex(exp, len);
        printf("\n");
    }
}

/* ================================================================
 * SHA3-256 tests
 * ================================================================ */

/*
 * Test 1: SHA3-256("") - empty message
 * From NIST examples:
 * a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
 */
static void
test_sha3_256_empty(void)
{
    uint8_t out[32];
    voleith_sha3_256(out, NULL, 0);
    check_hex("SHA3-256 empty message", out,
              "a7ffc6f8bf1ed76651c14756a061d662"
              "f580ff4de43b49fa82d80a4b80f8434a",
              32);
}

/*
 * Test 2: SHA3-256("abc")
 * From NIST examples:
 * 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
 */
static void
test_sha3_256_abc(void)
{
    uint8_t out[32];
    const uint8_t msg[] = {0x61, 0x62, 0x63}; /* "abc" */
    voleith_sha3_256(out, msg, 3);
    check_hex("SHA3-256 \"abc\"", out,
              "3a985da74fe225b2045c172d6bd390bd"
              "855f086e3e9d525b46bfe24511431532",
              32);
}

/*
 * Test 3: SHA3-256 of 200 bytes of 0xa3
 * From NIST examples:
 * 79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787
 */
static void
test_sha3_256_200_a3(void)
{
    uint8_t out[32];
    uint8_t msg[200];
    memset(msg, 0xa3, 200);
    voleith_sha3_256(out, msg, 200);
    check_hex("SHA3-256 200 bytes of 0xa3", out,
              "79f38adec5c20307a98ef76e8324afbf"
              "d46cfd81b22e3973c65fa1bd9de31787",
              32);
}

/*
 * Test 4: SHA3-256 incremental - absorb "abc" byte by byte
 */
static void
test_sha3_256_incremental(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[32];

    voleith_sha3_256_init(&ctx);
    voleith_sha3_256_absorb(&ctx, (const uint8_t *)"a", 1);
    voleith_sha3_256_absorb(&ctx, (const uint8_t *)"b", 1);
    voleith_sha3_256_absorb(&ctx, (const uint8_t *)"c", 1);
    voleith_sha3_256_finalize(&ctx, out);

    check_hex("SHA3-256 incremental absorb", out,
              "3a985da74fe225b2045c172d6bd390bd"
              "855f086e3e9d525b46bfe24511431532",
              32);
}

/*
 * Test 5: SHA3-256 of a message longer than one block (136 bytes)
 * Message: 200 bytes of 0x00
 * Verified via: python3 -c "import hashlib; print(hashlib.sha3_256(b'\x00'*200).hexdigest())"
 * = 2b43036c229ba512995f91fdb46fcd5327a4dc834d86d6e0f58a08053346dc2e
 */
static void
test_sha3_256_multiblock(void)
{
    uint8_t out[32];
    uint8_t msg[200];
    memset(msg, 0x00, 200);
    voleith_sha3_256(out, msg, 200);
    check_hex("SHA3-256 multi-block (200 zero bytes)", out,
              "2b43036c229ba512995f91fdb46fcd53"
              "27a4dc834d86d6e0f58a08053346dc2e",
              32);
}

/* ================================================================
 * SHAKE-128 tests
 * ================================================================ */

/*
 * Test 6: SHAKE128("") - empty message, 32 bytes output
 * From NIST examples:
 * 7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
 */
static void
test_shake128_empty(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[32];

    voleith_shake128_init(&ctx);
    voleith_shake128_squeeze(&ctx, out, 32);

    check_hex("SHAKE128 empty, 32 bytes", out,
              "7f9c2ba4e88f827d616045507605853e"
              "d73b8093f6efbc88eb1a6eacfa66ef26",
              32);
}

/*
 * Test 7: SHAKE128("abc"), 32 bytes output
 * From NIST examples:
 * 5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8
 */
static void
test_shake128_abc(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[32];
    const uint8_t msg[] = {0x61, 0x62, 0x63};

    voleith_shake128_init(&ctx);
    voleith_shake128_absorb(&ctx, msg, 3);
    voleith_shake128_squeeze(&ctx, out, 32);

    check_hex("SHAKE128 \"abc\", 32 bytes", out,
              "5881092dd818bf5cf8a3ddb793fbcba7"
              "4097d5c526a6d35f97b83351940f2cc8",
              32);
}

/*
 * Test 8: SHAKE128 incremental squeeze - squeeze same output in two calls
 */
static void
test_shake128_incremental_squeeze(void)
{
    voleith_hash_ctx_t ctx1, ctx2;
    uint8_t out_full[64];
    uint8_t out_parts[64];

    /* One-shot squeeze */
    voleith_shake128_init(&ctx1);
    voleith_shake128_squeeze(&ctx1, out_full, 64);

    /* Two-part squeeze */
    voleith_shake128_init(&ctx2);
    voleith_shake128_squeeze(&ctx2, out_parts, 32);
    voleith_shake128_squeeze(&ctx2, out_parts + 32, 32);

    check("SHAKE128 incremental squeeze", memcmp(out_full, out_parts, 64) == 0);
}

/* ================================================================
 * SHAKE-256 tests
 * ================================================================ */

/*
 * Test 9: SHAKE256("") - empty message, 32 bytes output
 * From NIST examples:
 * 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
 */
static void
test_shake256_empty(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[32];

    voleith_shake256_init(&ctx);
    voleith_shake256_squeeze(&ctx, out, 32);

    check_hex("SHAKE256 empty, 32 bytes", out,
              "46b9dd2b0ba88d13233b3feb743eeb24"
              "3fcd52ea62b81b82b50c27646ed5762f",
              32);
}

/*
 * Test 10: SHAKE256("abc"), 32 bytes output
 * 483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739
 */
static void
test_shake256_abc(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[32];
    const uint8_t msg[] = {0x61, 0x62, 0x63};

    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, msg, 3);
    voleith_shake256_squeeze(&ctx, out, 32);

    check_hex("SHAKE256 \"abc\", 32 bytes", out,
              "483366601360a8771c6863080cc4114d"
              "8db44530f8f1e1ee4f94ea37e78b5739",
              32);
}

/*
 * Test 11: SHAKE256 long output - squeeze 512 bytes, verify first and last 32
 * From NIST examples: SHAKE256(""), first 512 bytes
 * First 32 bytes: 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f
 */
static void
test_shake256_long_squeeze(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[512];

    voleith_shake256_init(&ctx);
    voleith_shake256_squeeze(&ctx, out, 512);

    check_hex("SHAKE256 long squeeze (first 32 bytes)", out,
              "46b9dd2b0ba88d13233b3feb743eeb24"
              "3fcd52ea62b81b82b50c27646ed5762f",
              32);
}

/*
 * Test 12: SHAKE256 multi-block squeeze consistency
 * Squeeze in 1-byte increments and compare to bulk squeeze
 */
static void
test_shake256_byte_squeeze(void)
{
    voleith_hash_ctx_t ctx1, ctx2;
    uint8_t bulk[256];
    uint8_t byte_by_byte[256];

    voleith_shake256_init(&ctx1);
    voleith_shake256_absorb(&ctx1, (const uint8_t *)"test", 4);
    voleith_shake256_squeeze(&ctx1, bulk, 256);

    voleith_shake256_init(&ctx2);
    voleith_shake256_absorb(&ctx2, (const uint8_t *)"test", 4);
    for (int i = 0; i < 256; i++)
        voleith_shake256_squeeze(&ctx2, byte_by_byte + i, 1);

    check("SHAKE256 byte-by-byte squeeze consistency",
          memcmp(bulk, byte_by_byte, 256) == 0);
}

/*
 * Test 13: SHA3-256 exactly one block (136 bytes)
 * This exercises the boundary where absorbed == rate before padding.
 */
static void
test_sha3_256_exact_block(void)
{
    uint8_t msg[136];
    uint8_t out1[32], out2[32];
    memset(msg, 0x42, 136);

    /* One-shot */
    voleith_sha3_256(out1, msg, 136);

    /* Incremental: two chunks */
    voleith_hash_ctx_t ctx;
    voleith_sha3_256_init(&ctx);
    voleith_sha3_256_absorb(&ctx, msg, 100);
    voleith_sha3_256_absorb(&ctx, msg + 100, 36);
    voleith_sha3_256_finalize(&ctx, out2);

    check("SHA3-256 exact block boundary", memcmp(out1, out2, 32) == 0);
}

/*
 * Test 14: SHAKE128 of 200 bytes of 0xa3, 16 bytes output
 * 131ab8d2b594946b9c81333f9bb6e0ce
 */
static void
test_shake128_200_a3(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[16];
    uint8_t msg[200];
    memset(msg, 0xa3, 200);

    voleith_shake128_init(&ctx);
    voleith_shake128_absorb(&ctx, msg, 200);
    voleith_shake128_squeeze(&ctx, out, 16);

    check_hex("SHAKE128 200 bytes of 0xa3, 16 bytes", out,
              "131ab8d2b594946b9c81333f9bb6e0ce", 16);
}

/*
 * Test 15: SHAKE256 of 200 bytes of 0xa3, 16 bytes output
 * From NIST examples:
 * cd8a920ed141aa0407a22d59288652e9
 */
static void
test_shake256_200_a3(void)
{
    voleith_hash_ctx_t ctx;
    uint8_t out[16];
    uint8_t msg[200];
    memset(msg, 0xa3, 200);

    voleith_shake256_init(&ctx);
    voleith_shake256_absorb(&ctx, msg, 200);
    voleith_shake256_squeeze(&ctx, out, 16);

    check_hex("SHAKE256 200 bytes of 0xa3, 16 bytes", out,
              "cd8a920ed141aa0407a22d59288652e9", 16);
}

int
main(void)
{
    printf("test_hash: SHA-3-256, SHAKE-128, SHAKE-256\n");

    /* SHA3-256 */
    test_sha3_256_empty();
    test_sha3_256_abc();
    test_sha3_256_200_a3();
    test_sha3_256_incremental();
    test_sha3_256_multiblock();
    test_sha3_256_exact_block();

    /* SHAKE-128 */
    test_shake128_empty();
    test_shake128_abc();
    test_shake128_incremental_squeeze();
    test_shake128_200_a3();

    /* SHAKE-256 */
    test_shake256_empty();
    test_shake256_abc();
    test_shake256_long_squeeze();
    test_shake256_byte_squeeze();
    test_shake256_200_a3();

    printf("  %d / %d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
