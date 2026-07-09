/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs.c - Tests for Reed-Solomon erasure coding (erasure/rs.c).
 *
 * Validated against an independent oracle: known-answer vectors in
 * rs_kat.inc were generated once by Jerasure 2.0 + GF-Complete over GF(2^8)
 * with primitive polynomial 0x11B and a systematic Cauchy construction
 * (X[i] = k+i, Y[j] = j), matching voleith_ec_matrix_generator's CAUCHY
 * case exactly.  Jerasure/GF-Complete are never linked here; see
 * tools/gen_rs_kat/gen_rs_kat.c.  Beyond the KATs, the tests exercise
 * decode from every k-subset and single-chunk repair.
 */

#include "rs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-58s ", name);                                              \
    } while (0)

#define PASS()                                                                 \
    do {                                                                       \
        tests_passed++;                                                        \
        printf("[PASS]\n");                                                    \
    } while (0)

#define FAIL(msg)                                                              \
    do {                                                                       \
        printf("[FAIL] %s\n", msg);                                            \
    } while (0)

/* Layout matches the initializer emitted by tools/gen_rs_kat. */
struct rs_kat {
    int n;
    int k;
    int chunk_bytes;
    uint8_t message[256];
    uint8_t codeword[512];
};

#include "rs_kat.inc"

#define NUM_KATS (sizeof(rs_kats) / sizeof(rs_kats[0]))

/* Advances idx (length k, strictly increasing in [0, n)) to the next
 * combination.  Returns 1 if produced, 0 if exhausted. */
static int
comb_next(size_t *idx, size_t k, size_t n)
{
    size_t pos = k;

    while (pos-- > 0) {
        if (idx[pos] < n - k + pos) {
            size_t j;
            idx[pos]++;
            for (j = pos + 1; j < k; j++)
                idx[j] = idx[j - 1] + 1;
            return 1;
        }
    }
    return 0;
}

/* Verifies encode reproduces the oracle codeword for every KAT. */
static void
test_encode_matches_oracle(void)
{
    size_t t;

    TEST("RS encode matches Jerasure oracle KATs");
    for (t = 0; t < NUM_KATS; t++) {
        const struct rs_kat *kat = &rs_kats[t];
        voleith_rs_t rs;
        uint8_t out[512];

        if (voleith_rs_init(&rs, (size_t)kat->n, (size_t)kat->k,
                            VOLEITH_EC_MATRIX_CAUCHY) != VOLEITH_EC_OK) {
            FAIL("rs_init failed");
            return;
        }
        if (voleith_rs_encode(&rs, kat->message, (size_t)kat->chunk_bytes,
                              out) != VOLEITH_EC_OK) {
            voleith_rs_free(&rs);
            FAIL("rs_encode failed");
            return;
        }
        voleith_rs_free(&rs);
        if (memcmp(out, kat->codeword,
                   (size_t)kat->n * (size_t)kat->chunk_bytes) != 0) {
            FAIL("codeword != oracle");
            return;
        }
    }
    PASS();
}

/* Decodes from every k-subset of each KAT codeword; must recover message. */
static void
test_decode_every_subset(void)
{
    size_t t;

    TEST("RS decode recovers message from every k-subset");
    for (t = 0; t < NUM_KATS; t++) {
        const struct rs_kat *kat = &rs_kats[t];
        size_t n = (size_t)kat->n, k = (size_t)kat->k;
        size_t cb = (size_t)kat->chunk_bytes;
        voleith_rs_t rs;
        size_t idx[16];
        size_t i;

        if (voleith_rs_init(&rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
            VOLEITH_EC_OK) {
            FAIL("rs_init failed");
            return;
        }
        for (i = 0; i < k; i++)
            idx[i] = i;

        do {
            uint8_t recv[512];
            uint8_t rec[256];

            for (i = 0; i < k; i++)
                memcpy(recv + i * cb, kat->codeword + idx[i] * cb, cb);

            if (voleith_rs_decode(&rs, idx, recv, k, cb, rec) !=
                VOLEITH_EC_OK) {
                voleith_rs_free(&rs);
                FAIL("rs_decode failed");
                return;
            }
            if (memcmp(rec, kat->message, k * cb) != 0) {
                voleith_rs_free(&rs);
                FAIL("recovered message != original");
                return;
            }
        } while (comb_next(idx, k, n));

        voleith_rs_free(&rs);
    }
    PASS();
}

/*
 * For each KAT, drops one chunk at a time and repairs it from the first k
 * of the remaining chunks; the repaired chunk must equal the original.
 */
static void
test_single_chunk_repair(void)
{
    size_t t;

    TEST("RS repair reconstructs each single missing chunk");
    for (t = 0; t < NUM_KATS; t++) {
        const struct rs_kat *kat = &rs_kats[t];
        size_t n = (size_t)kat->n, k = (size_t)kat->k;
        size_t cb = (size_t)kat->chunk_bytes;
        voleith_rs_t rs;
        size_t missing;

        if (voleith_rs_init(&rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
            VOLEITH_EC_OK) {
            FAIL("rs_init failed");
            return;
        }

        for (missing = 0; missing < n; missing++) {
            size_t idx[16];
            uint8_t recv[512];
            uint8_t repaired[256];
            size_t have = 0, i;

            /* Collect the first k chunks that are not the missing one. */
            for (i = 0; i < n && have < k; i++) {
                if (i == missing)
                    continue;
                idx[have] = i;
                memcpy(recv + have * cb, kat->codeword + i * cb, cb);
                have++;
            }

            if (voleith_rs_repair(&rs, idx, recv, k, cb, missing, repaired) !=
                VOLEITH_EC_OK) {
                voleith_rs_free(&rs);
                FAIL("rs_repair failed");
                return;
            }
            if (memcmp(repaired, kat->codeword + missing * cb, cb) != 0) {
                voleith_rs_free(&rs);
                FAIL("repaired chunk != original");
                return;
            }
        }
        voleith_rs_free(&rs);
    }
    PASS();
}

/*
 * Healer recipe (plan T6.9): decode the message once, then re-encode a set
 * of target indices with voleith_rs_encode_indices.  Each regenerated chunk
 * must match the original codeword byte-for-byte, i.e. equal what the
 * per-chunk voleith_rs_repair produces.
 */
static void
test_decode_once_encode_indices(void)
{
    size_t t;

    TEST("RS decode-once / encode-indices == per-row repair");
    for (t = 0; t < NUM_KATS; t++) {
        const struct rs_kat *kat = &rs_kats[t];
        size_t n = (size_t)kat->n, k = (size_t)kat->k;
        size_t cb = (size_t)kat->chunk_bytes;
        voleith_rs_t rs;
        size_t idx[16], targets[16];
        uint8_t recv[512], message[256], out[512];
        size_t have = 0, count = 0, i;

        if (voleith_rs_init(&rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
            VOLEITH_EC_OK) {
            FAIL("rs_init failed");
            return;
        }

        /* Survivors: the first k chunks; targets: every other chunk (the
         * "several missing" set the healer regenerates from one decode). */
        for (i = 0; i < n; i++) {
            if (have < k) {
                idx[have] = i;
                memcpy(recv + have * cb, kat->codeword + i * cb, cb);
                have++;
            } else {
                targets[count++] = i;
            }
        }

        if (voleith_rs_decode(&rs, idx, recv, k, cb, message) !=
            VOLEITH_EC_OK) {
            voleith_rs_free(&rs);
            FAIL("rs_decode failed");
            return;
        }
        if (voleith_rs_encode_indices(&rs, message, cb, targets, count, out) !=
            VOLEITH_EC_OK) {
            voleith_rs_free(&rs);
            FAIL("encode_indices failed");
            return;
        }

        for (i = 0; i < count; i++) {
            uint8_t single[256];

            if (memcmp(out + i * cb, kat->codeword + targets[i] * cb, cb) !=
                0) {
                voleith_rs_free(&rs);
                FAIL("regenerated chunk != original");
                return;
            }
            /* Same bytes as the single-row entry point. */
            if (voleith_rs_encode_row(&rs, message, cb, targets[i], single) !=
                    VOLEITH_EC_OK ||
                memcmp(single, out + i * cb, cb) != 0) {
                voleith_rs_free(&rs);
                FAIL("encode_row != encode_indices");
                return;
            }
        }
        voleith_rs_free(&rs);
    }
    PASS();
}

/* Fewer than k chunks must be reported as incomplete, not decoded. */
static void
test_incomplete_rejected(void)
{
    const struct rs_kat *kat = &rs_kats[0];
    size_t k = (size_t)kat->k, cb = (size_t)kat->chunk_bytes;
    voleith_rs_t rs;
    size_t idx[16];
    uint8_t recv[512];
    uint8_t rec[256];
    size_t i;
    int rc;

    TEST("RS decode with < k chunks returns ERR_INCOMPLETE");
    if (voleith_rs_init(&rs, (size_t)kat->n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
        VOLEITH_EC_OK) {
        FAIL("rs_init failed");
        return;
    }
    for (i = 0; i + 1 < k; i++) {
        idx[i] = i;
        memcpy(recv + i * cb, kat->codeword + i * cb, cb);
    }
    rc = voleith_rs_decode(&rs, idx, recv, k - 1, cb, rec);
    voleith_rs_free(&rs);
    if (rc != VOLEITH_EC_ERR_INCOMPLETE) {
        FAIL("expected VOLEITH_EC_ERR_INCOMPLETE");
        return;
    }
    PASS();
}

int
main(void)
{
    printf("=== Reed-Solomon erasure-coding tests ===\n");
    test_encode_matches_oracle();
    test_decode_every_subset();
    test_single_chunk_repair();
    test_decode_once_encode_indices();
    test_incomplete_rejected();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
