/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_grostl_mct.c - NIST Monte Carlo Test for core/grostl.
 *
 * The Monte Carlo Test chains 100,000 hash invocations and checkpoints
 * the digest every 1,000 iterations, comparing each checkpoint against
 * the published MD.  Where the ShortMsgKAT sweep (test_grostl_kat.c)
 * validates many independent single-pass hashes, the MCT exercises the
 * one thing single-pass tests structurally cannot: state reset between
 * invocations, and padding/block-count behaviour under a long chain of
 * back-to-back calls.  A bug that leaves residual state in the context,
 * or mishandles the block counter, will diverge somewhere in the chain
 * and surface at the next checkpoint.
 *
 * Recurrence (SHA-3-competition MCT, derived from the published vectors
 * in third_party/Groestl/KAT_MCT/MonteCarlo_{256,512}.txt and confirmed
 * against multiple checkpoints):
 *
 *     Msg is a fixed 1024-bit (128-byte) buffer, initialised to Seed.
 *     for j in 0..99:
 *         for i in 0..999:
 *             MD  = Grøstl-N(Msg)               (digest is N/8 bytes)
 *             Msg = MD || Msg[0 : 128 - N/8]    (prepend MD, drop tail)
 *         checkpoint[j] = MD
 *
 * File format:  "Seed = <hex>", then 100 records of "j = <n>" /
 * "MD = <hex>".
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

#define MCT_MSG_BYTES 128 /* 1024-bit seed / working message. */
#define MCT_INNER 1000    /* Hashes per checkpoint. */
#define MCT_LINE_MAX 512  /* "Seed = " + 256 hex chars + slack. */

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

/* One inner hash + message update.  digest_bytes is 32 or 64. */
static void
mct_step(uint8_t msg[MCT_MSG_BYTES], uint8_t *md, size_t digest_bytes)
{
    uint8_t tmp[MCT_MSG_BYTES];

    if (digest_bytes == 32)
        voleith_grostl256(md, msg, MCT_MSG_BYTES);
    else
        voleith_grostl512(md, msg, MCT_MSG_BYTES);

    /* Msg = MD || Msg[0 : 128 - digest_bytes]. */
    memcpy(tmp, md, digest_bytes);
    memcpy(tmp + digest_bytes, msg, MCT_MSG_BYTES - digest_bytes);
    memcpy(msg, tmp, MCT_MSG_BYTES);
}

/*
 * Run the full Monte Carlo chain described by one file and compare each
 * checkpoint against its published MD.  Returns 0 on success, the number
 * of mismatched checkpoints on failure, or -1 if the file could not be
 * read / was malformed.
 */
static int
run_mct_file(const char *path, size_t digest_bytes)
{
    char line[MCT_LINE_MAX];
    uint8_t msg[MCT_MSG_BYTES];
    uint8_t md[64];
    uint8_t expected[64];
    FILE *f;
    const char *val;
    int have_seed = 0;
    int checkpoints = 0;
    int failures = 0;

    f = fopen(path, "r");
    if (f == NULL) {
        printf("FAIL: cannot open %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), f) != NULL) {
        rstrip(line);

        if ((val = kat_value(line, "Seed")) != NULL) {
            if (hex_decode_into(val, msg, sizeof(msg)) != MCT_MSG_BYTES) {
                printf("FAIL: bad Seed in %s\n", path);
                fclose(f);
                return -1;
            }
            have_seed = 1;
            continue;
        }
        if ((val = kat_value(line, "MD")) == NULL)
            continue;

        if (!have_seed) {
            printf("FAIL: MD before Seed in %s\n", path);
            fclose(f);
            return -1;
        }
        if (hex_decode_into(val, expected, sizeof(expected)) !=
            (int)digest_bytes) {
            printf("FAIL: bad MD (checkpoint %d) in %s\n", checkpoints, path);
            fclose(f);
            return -1;
        }

        for (int i = 0; i < MCT_INNER; i++)
            mct_step(msg, md, digest_bytes);

        if (memcmp(md, expected, digest_bytes) != 0) {
            if (failures == 0)
                printf("\n");
            printf("        mismatch at checkpoint j=%d\n", checkpoints);
            failures++;
        }
        checkpoints++;
    }

    fclose(f);

    if (checkpoints == 0) {
        printf("FAIL: no checkpoints parsed from %s\n", path);
        return -1;
    }
    if (failures == 0)
        printf("(%d checkpoints) ", checkpoints);
    else
        printf("        %d/%d checkpoints failed ", failures, checkpoints);

    return failures;
}

static void
test_mct_file(const char *file, size_t digest_bytes, const char *label)
{
    char path[512];

    TEST(label);
    snprintf(path, sizeof(path), "%s%s", KAT_DIR, file);
    if (run_mct_file(path, digest_bytes) == 0)
        PASS();
}

int
main(void)
{
    printf("grostl MonteCarlo tests\n");
    printf("=======================\n");
    printf("SubBytes backend: %s\n", voleith_aes_backend_name());

    printf("\n  Grøstl-256 MonteCarlo\n");
    test_mct_file("MonteCarlo_256.txt", 32, "Grøstl-256 MonteCarlo chain");

    printf("\n  Grøstl-512 MonteCarlo\n");
    test_mct_file("MonteCarlo_512.txt", 64, "Grøstl-512 MonteCarlo chain");

    printf("\n%d/%d tests passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
