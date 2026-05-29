/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_grostl.c - Initial correctness tests for core/grostl.
 *
 * Validates the software Grøstl-256 and Grøstl-512 implementations
 * against a small hand-picked subset of the NIST round-3 KAT vectors
 * shipped in third_party/Groestl/KAT_MCT/.  A full KAT file parser
 * comes later (see GROSTL_PRIMITIVE_DESIGN.md testing section); this
 * file is meant to catch top-level bugs (state layout, padding, IV,
 * permutation correctness) before the larger test suite is wired up.
 *
 * Vectors covered:
 *   - Grøstl-256, empty input (0-byte message).
 *   - Grøstl-256, 3-byte message (sub-block, exercises padding).
 *   - Grøstl-256, 64-byte message (exactly one block, exercises the
 *     two-block padding branch).
 *   - Grøstl-256, 128-byte message (two blocks).
 *   - Grøstl-512, same vectors at the larger block size.
 *   - Incremental absorb byte-by-byte gives the same result as the
 *     one-shot API.
 */

#include "grostl.h"
#include "aes.h"
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

static int
hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode a hex string into a fresh byte buffer.  Returns the byte
 * length on success, -1 on malformed input.  Caller must free *out. */
static int
hex_decode(const char *s, uint8_t **out)
{
    size_t len = strlen(s);
    if (len % 2 != 0)
        return -1;
    size_t n = len / 2;
    uint8_t *buf = malloc(n > 0 ? n : 1);
    if (!buf)
        return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_nibble(s[2 * i]);
        int lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out = buf;
    return (int)n;
}

static void
hex_print(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

/* ================================================================
 * NIST KAT vectors hand-extracted from
 * third_party/Groestl/KAT_MCT/ShortMsgKAT_{256,512}.txt.
 * ================================================================ */

/* Grøstl-256, empty message. */
static const char *KAT256_EMPTY_MD =
    "1A52D11D550039BE16107F9C58DB9EBCC417F16F736ADB2502567119F0083467";

/* Grøstl-256, Len=24 / Msg=1F877C. */
static const uint8_t KAT256_3BYTE_MSG[3] = {0x1F, 0x87, 0x7C};
static const char *KAT256_3BYTE_MD =
    "05FE7DE2D8CE1770DF766739F788037D0CF2CA7C2B7620835CC34F45B3FCF919";

/* Grøstl-256, Len=512 (one full 64-byte block) - triggers the
 * "padding spans two blocks" branch in finalize. */
static const char *KAT256_64B_MSG_HEX =
    "E926AE8B0AF6E53176DBFFCC2A6B88C6BD765F939D3D178A9BDE9EF3AA131C61"
    "E31C1E42CDFAF4B4DCDE579A37E150EFBEF5555B4C1CB40439D835A724E2FAE7";
static const char *KAT256_64B_MD =
    "5ADEBBFDF6FD6178892B39A97A32B29FB605F97E1E5C3BBCF624A0E9CD72D145";

/* Grøstl-256, Len=1024 (two full 64-byte blocks). */
static const char *KAT256_128B_MSG_HEX =
    "2B6DB7CED8665EBE9DEB080295218426BDAA7C6DA9ADD2088932CDFFBAA1C141"
    "29BCCDD70F369EFB149285858D2B1D155D14DE2FDB680A8B027284055182A0CA"
    "E275234CC9C92863C1B4AB66F304CF0621CD54565F5BFF461D3B461BD40DF281"
    "98E3732501B4860EADD503D26D6E69338F4E0456E9E9BAF3D827AE685FB1D817";
static const char *KAT256_128B_MD =
    "B8A871928FCC39AB286E5A768B0AE61DDBD765FBC55C2DD2F3D10477D362A08F";

/* Grøstl-512, empty message. */
static const char *KAT512_EMPTY_MD =
    "6D3AD29D279110EEF3ADBD66DE2A0345A77BAEDE1557F5D099FCE0C03D6DC2BA"
    "8E6D4A6633DFBD66053C20FAA87D1A11F39A7FBE4A6C2F009801370308FC4AD8";

/* Grøstl-512, Len=24 / Msg=1F877C. */
static const char *KAT512_3BYTE_MD =
    "413907C17D8CA9E5477DE5491914DC4EB621F35C96267F8E807AFFC0335DD8F6"
    "781C053CED249FF3C8C5A4D4AC62FE3D9E6660B30CC09621DE7162E6C271D3C7";

/* Grøstl-512, Len=1024 (one full 128-byte block). */
static const char *KAT512_128B_MD =
    "FF410B511135DBC0B8644C28EFA3EC632326FEB98E50EDC6390C441610D7C514"
    "ACDF0A61A0BF01AA9DC1F55D92E085248EBA1C24EE23978B4986AF41C13A6176";

/* ================================================================
 * Test helpers.
 * ================================================================ */

static int
check_hash(const uint8_t *got, const char *expected_hex, size_t n,
           const char *label)
{
    uint8_t *expected;
    int exp_len = hex_decode(expected_hex, &expected);
    if (exp_len < 0 || (size_t)exp_len != n) {
        FAIL("expected hex malformed");
        return 0;
    }
    int ok = memcmp(got, expected, n) == 0;
    if (!ok) {
        printf("FAIL (%s)\n        got:      ", label);
        hex_print(got, n);
        printf("\n        expected: ");
        hex_print(expected, n);
        printf("\n");
    }
    free(expected);
    return ok;
}

/* ================================================================
 * Grøstl-256 one-shot KATs.
 * ================================================================ */

static void
test_grostl256_empty(void)
{
    TEST("Grøstl-256(empty) matches NIST KAT");

    uint8_t md[32];
    voleith_grostl256(md, NULL, 0);
    if (check_hash(md, KAT256_EMPTY_MD, 32, "Grøstl-256 empty"))
        PASS();
}

static void
test_grostl256_3byte(void)
{
    TEST("Grøstl-256(1F877C) matches NIST KAT");

    uint8_t md[32];
    voleith_grostl256(md, KAT256_3BYTE_MSG, sizeof(KAT256_3BYTE_MSG));
    if (check_hash(md, KAT256_3BYTE_MD, 32, "Grøstl-256 3-byte"))
        PASS();
}

static void
test_grostl256_64byte(void)
{
    TEST("Grøstl-256(64-byte message) matches NIST KAT");

    uint8_t *msg;
    int msg_len = hex_decode(KAT256_64B_MSG_HEX, &msg);
    if (msg_len != 64) {
        FAIL("msg hex");
        return;
    }
    uint8_t md[32];
    voleith_grostl256(md, msg, 64);
    free(msg);
    if (check_hash(md, KAT256_64B_MD, 32, "Grøstl-256 64-byte"))
        PASS();
}

static void
test_grostl256_128byte(void)
{
    TEST("Grøstl-256(128-byte message) matches NIST KAT");

    uint8_t *msg;
    int msg_len = hex_decode(KAT256_128B_MSG_HEX, &msg);
    if (msg_len != 128) {
        FAIL("msg hex");
        return;
    }
    uint8_t md[32];
    voleith_grostl256(md, msg, 128);
    free(msg);
    if (check_hash(md, KAT256_128B_MD, 32, "Grøstl-256 128-byte"))
        PASS();
}

/* ================================================================
 * Grøstl-512 one-shot KATs.
 * ================================================================ */

static void
test_grostl512_empty(void)
{
    TEST("Grøstl-512(empty) matches NIST KAT");

    uint8_t md[64];
    voleith_grostl512(md, NULL, 0);
    if (check_hash(md, KAT512_EMPTY_MD, 64, "Grøstl-512 empty"))
        PASS();
}

static void
test_grostl512_3byte(void)
{
    TEST("Grøstl-512(1F877C) matches NIST KAT");

    uint8_t md[64];
    voleith_grostl512(md, KAT256_3BYTE_MSG, sizeof(KAT256_3BYTE_MSG));
    if (check_hash(md, KAT512_3BYTE_MD, 64, "Grøstl-512 3-byte"))
        PASS();
}

static void
test_grostl512_128byte(void)
{
    TEST("Grøstl-512(128-byte message) matches NIST KAT");

    uint8_t *msg;
    int msg_len = hex_decode(KAT256_128B_MSG_HEX, &msg);
    if (msg_len != 128) {
        FAIL("msg hex");
        return;
    }
    uint8_t md[64];
    voleith_grostl512(md, msg, 128);
    free(msg);
    if (check_hash(md, KAT512_128B_MD, 64, "Grøstl-512 128-byte"))
        PASS();
}

/* ================================================================
 * Incremental absorb consistency.  Validates that absorbing the
 * message in 1-byte chunks gives the same digest as the one-shot
 * API.  Exercises buffer-management edge cases in absorb / finalize.
 * ================================================================ */

static void
test_incremental_256(void)
{
    TEST("Grøstl-256 incremental absorb matches one-shot (128 B)");

    uint8_t *msg;
    int msg_len = hex_decode(KAT256_128B_MSG_HEX, &msg);
    if (msg_len != 128) {
        FAIL("msg hex");
        return;
    }

    uint8_t md_oneshot[32];
    uint8_t md_inc[32];

    voleith_grostl256(md_oneshot, msg, 128);

    voleith_grostl_ctx_t ctx;
    voleith_grostl256_init(&ctx);
    for (int i = 0; i < 128; i++)
        voleith_grostl_absorb(&ctx, msg + i, 1);
    voleith_grostl_finalize(&ctx, md_inc);
    voleith_grostl_clear(&ctx);

    free(msg);

    if (memcmp(md_oneshot, md_inc, 32) == 0) {
        PASS();
    } else {
        FAIL("incremental != one-shot");
    }
}

static void
test_incremental_512(void)
{
    TEST("Grøstl-512 incremental absorb matches one-shot (128 B)");

    uint8_t *msg;
    int msg_len = hex_decode(KAT256_128B_MSG_HEX, &msg);
    if (msg_len != 128) {
        FAIL("msg hex");
        return;
    }

    uint8_t md_oneshot[64];
    uint8_t md_inc[64];

    voleith_grostl512(md_oneshot, msg, 128);

    voleith_grostl_ctx_t ctx;
    voleith_grostl512_init(&ctx);
    /* Mix chunk sizes to exercise both partial-buffer-fill and
     * straight-from-caller fast-path code in absorb. */
    voleith_grostl_absorb(&ctx, msg + 0, 1);
    voleith_grostl_absorb(&ctx, msg + 1, 63);
    voleith_grostl_absorb(&ctx, msg + 64, 32);
    voleith_grostl_absorb(&ctx, msg + 96, 32);
    voleith_grostl_finalize(&ctx, md_inc);
    voleith_grostl_clear(&ctx);

    free(msg);

    if (memcmp(md_oneshot, md_inc, 64) == 0) {
        PASS();
    } else {
        FAIL("incremental != one-shot");
    }
}

int
main(void)
{
    printf("grostl tests\n");
    printf("============\n");
    /* Grøstl SubBytes shares the AES S-box backend selection.  The
     * NIST KAT round-trip across CI variants (sw / clmul / aesni /
     * clmul_aesni) is the cross-validation between the bitsliced
     * software path and the AES-NI / ARMv8 hardware paths. */
    printf("SubBytes backend: %s\n", voleith_aes_backend_name());

    printf("\n  Grøstl-256 NIST KATs\n");
    test_grostl256_empty();
    test_grostl256_3byte();
    test_grostl256_64byte();
    test_grostl256_128byte();

    printf("\n  Grøstl-512 NIST KATs\n");
    test_grostl512_empty();
    test_grostl512_3byte();
    test_grostl512_128byte();

    printf("\n  Incremental absorb consistency\n");
    test_incremental_256();
    test_incremental_512();

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
