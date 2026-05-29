/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_grostl_kat.c - Full NIST KAT validation for core/grostl.
 *
 * Parses the official Grøstl round-3 submission KAT files shipped in
 * third_party/Groestl/KAT_MCT/ and hashes every byte-aligned record,
 * comparing against the published MD field.  Where test_grostl.c checks
 * a handful of hand-picked boundaries, this sweeps:
 *
 *   - ShortMsgKAT: all 256 byte-aligned lengths 0..255 bytes -- dense
 *     coverage that catches padding and block-count-encoding bugs at
 *     every block boundary.
 *   - LongMsgKAT: 65 byte-aligned lengths up to 4288 bytes (~67 Grøstl
 *     blocks) -- multi-block absorb beyond what the ShortMsg lengths or
 *     the test_grostl.c hand-picks reach.
 *
 * Record format (standard NIST CAVP):
 *
 *     Len = <bits>
 *     Msg = <hex>
 *     MD  = <hex>
 *
 * Len is in bits.  Records whose length is not a whole number of bytes
 * (Len % 8 != 0) are skipped -- the bitsliced engine processes bytes,
 * not bits.  When a KAT failure needs localizing to a specific round,
 * see the IntermediateValues_*.txt traces in the same directory.
 *
 * The same vectors feed the GF(2^8) circuit test
 * (test_grostl_gf8_circuit.c).
 */

#include "grostl.h"
#include "aes.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VOLEITH_TEST_SOURCE_DIR
#error "VOLEITH_TEST_SOURCE_DIR must be defined by the build system"
#endif

#define KAT_DIR VOLEITH_TEST_SOURCE_DIR "/tests/KAT_MCT/"

/* LongMsgKAT tops out at Len = 34304 bits, i.e. 4288 message bytes. */
#define KAT_MAX_MSG_BYTES 4288
/* "Msg = " + up to 8576 hex chars + CR/LF + null + slack. */
#define KAT_LINE_MAX 9216

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

/* Decode a hex string into a caller-supplied buffer.  Returns the byte
 * length on success, -1 on malformed input or insufficient capacity. */
static int
hex_decode_into(const char *s, uint8_t *out, size_t out_cap)
{
    size_t len, n, i;

    len = strlen(s);
    if (len % 2 != 0)
        return -1;
    n = len / 2;
    if (n > out_cap)
        return -1;
    for (i = 0; i < n; i++) {
        int hi = hex_nibble(s[2 * i]);
        int lo = hex_nibble(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)n;
}

/* Strip trailing CR/LF/space from a line in place. */
static void
rstrip(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) {
        s[--n] = '\0';
    }
}

/* If line begins with "<key> =", return a pointer to the value (past the
 * '=' and any leading spaces); otherwise NULL. */
static const char *
kat_value(const char *line, const char *key)
{
    size_t klen = strlen(key);

    if (strncmp(line, key, klen) != 0)
        return NULL;
    line += klen;
    while (*line == ' ')
        line++;
    if (*line != '=')
        return NULL;
    line++;
    while (*line == ' ')
        line++;
    return line;
}

/*
 * Hash every byte-aligned record in one KAT file and compare against the
 * published MD.  Returns 0 if all byte-aligned records matched, otherwise
 * the number of mismatches (or -1 if the file could not be opened / was
 * malformed).  On the way it prints a one-line summary of how many
 * records ran versus were skipped.
 */
static int
run_kat_file(const char *path, size_t digest_bytes)
{
    char line[KAT_LINE_MAX];
    char msg_hex[2 * KAT_MAX_MSG_BYTES + 1];
    uint8_t msg[KAT_MAX_MSG_BYTES];
    uint8_t expected[64];
    uint8_t got[64];
    FILE *f;
    const char *val;
    long len_bits = -1;
    int have_msg = 0;
    int failures = 0;
    int ran = 0;
    int skipped = 0;

    f = fopen(path, "r");
    if (f == NULL) {
        printf("FAIL: cannot open %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        rstrip(line);

        if ((val = kat_value(line, "Len")) != NULL) {
            len_bits = strtol(val, NULL, 10);
            have_msg = 0;
            continue;
        }
        if ((val = kat_value(line, "Msg")) != NULL) {
            if (strlen(val) >= sizeof(msg_hex)) {
                printf("FAIL: Msg too long in %s\n", path);
                fclose(f);
                return -1;
            }
            strcpy(msg_hex, val);
            have_msg = 1;
            continue;
        }
        if ((val = kat_value(line, "MD")) == NULL)
            continue;

        /* A complete record ends at the MD line. */
        if (len_bits < 0 || !have_msg) {
            printf("FAIL: malformed record in %s\n", path);
            fclose(f);
            return -1;
        }

        if (len_bits % 8 != 0) {
            skipped++;
            len_bits = -1;
            have_msg = 0;
            continue;
        }

        size_t msg_bytes = (size_t)len_bits / 8;
        if (hex_decode_into(msg_hex, msg, sizeof(msg)) < 0) {
            printf("FAIL: bad Msg hex (Len=%ld) in %s\n", len_bits, path);
            fclose(f);
            return -1;
        }
        if (hex_decode_into(val, expected, sizeof(expected)) !=
            (int)digest_bytes) {
            printf("FAIL: bad MD hex (Len=%ld) in %s\n", len_bits, path);
            fclose(f);
            return -1;
        }

        if (digest_bytes == 32)
            voleith_grostl256(got, msg, msg_bytes);
        else
            voleith_grostl512(got, msg, msg_bytes);

        if (memcmp(got, expected, digest_bytes) != 0) {
            if (failures == 0)
                printf("\n");
            printf("        mismatch at Len=%ld (%zu bytes)\n", len_bits,
                   msg_bytes);
            failures++;
        }
        ran++;

        len_bits = -1;
        have_msg = 0;
    }

    fclose(f);

    if (failures == 0)
        printf("(%d ran, %d skipped) ", ran, skipped);
    else
        printf("        %d/%d records failed ", failures, ran);

    return failures;
}

static void
test_kat_file(const char *file, size_t digest_bytes, const char *label)
{
    char path[512];

    TEST(label);
    snprintf(path, sizeof(path), "%s%s", KAT_DIR, file);
    if (run_kat_file(path, digest_bytes) == 0)
        PASS();
}

int
main(void)
{
    printf("grostl KAT tests\n");
    printf("================\n");
    printf("SubBytes backend: %s\n", voleith_aes_backend_name());
    printf("KAT directory:    %s\n", KAT_DIR);

    printf("\n  Grøstl-256 ShortMsgKAT\n");
    test_kat_file("ShortMsgKAT_256.txt", 32,
                  "Grøstl-256 ShortMsgKAT (all byte-aligned)");

    printf("\n  Grøstl-512 ShortMsgKAT\n");
    test_kat_file("ShortMsgKAT_512.txt", 64,
                  "Grøstl-512 ShortMsgKAT (all byte-aligned)");

    printf("\n  Grøstl-256 LongMsgKAT\n");
    test_kat_file("LongMsgKAT_256.txt", 32,
                  "Grøstl-256 LongMsgKAT (all byte-aligned)");

    printf("\n  Grøstl-512 LongMsgKAT\n");
    test_kat_file("LongMsgKAT_512.txt", 64,
                  "Grøstl-512 LongMsgKAT (all byte-aligned)");

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
