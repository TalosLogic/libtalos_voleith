/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_consistency.c - capability-3 plaintext encoding-correctness tests
 * (erasure/rs_consistency.c, plan T6.7).
 *
 * Builds real datasets (RS-encode, compute digests, build tree), then drives
 * voleith_rs_check_consistency:
 *   - a consistent codeword passes,
 *   - a tampered committed digest (simulating a malicious owner) fails,
 *   - the optional whole-file digest check passes on a correct rebuild and
 *     fails when the metadata carries a wrong digest.
 */

#include "rs_consistency.h"

#include "rs.h"
#include "rs_membership.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name)                                                             \
    do {                                                                       \
        tests_run++;                                                           \
        printf("  %-56s ", name);                                              \
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

/* ========================================================================
 * Dataset scaffold (owner side: encode, digest, metadata)
 * ======================================================================== */

struct ds {
    voleith_rs_cr_profile_t cr;
    size_t n, k, cb, digb;
    uint8_t *message; /* k * cb */
    voleith_rs_t rs;
    int rs_init;
    uint8_t *codeword; /* n * cb */
    uint8_t *digests;  /* n * digb */
    voleith_rs_metadata_t meta;
};

static int
ds_init(struct ds *d, voleith_rs_cr_profile_t cr, size_t n, size_t k, size_t cb)
{
    size_t i, j;

    memset(d, 0, sizeof(*d));
    d->cr = cr;
    d->n = n;
    d->k = k;
    d->cb = cb;
    d->digb = voleith_rs_cr_digest_bytes(cr);

    d->message = calloc(k, cb);
    d->codeword = calloc(n, cb);
    d->digests = calloc(n, d->digb);
    if (d->message == NULL || d->codeword == NULL || d->digests == NULL)
        return -1;

    for (i = 0; i < k; i++)
        for (j = 0; j < cb; j++)
            d->message[i * cb + j] = (uint8_t)(i * 17u + j + 5u);

    if (voleith_rs_init(&d->rs, n, k, VOLEITH_EC_MATRIX_CAUCHY) !=
        VOLEITH_EC_OK)
        return -1;
    d->rs_init = 1;

    if (voleith_rs_encode(&d->rs, d->message, cb, d->codeword) != VOLEITH_EC_OK)
        return -1;

    for (i = 0; i < n; i++) {
        if (voleith_rs_chunk_digest(cr, d->codeword + i * cb, cb,
                                    d->digests + i * d->digb,
                                    d->digb) != VOLEITH_EC_OK)
            return -1;
    }

    d->meta.cr_profile = cr;
    d->meta.chunk_size = (uint32_t)cb;
    d->meta.file_len = (uint64_t)k * cb;
    d->meta.n = (uint16_t)n;
    d->meta.k = (uint16_t)k;
    d->meta.whole_file_digest = NULL;
    d->meta.attr_restriction = NULL;
    d->meta.attr_restriction_len = 0;
    d->meta.por_params = NULL;
    d->meta.por_params_len = 0;
    return 0;
}

static void
ds_free(struct ds *d)
{
    free(d->message);
    free(d->codeword);
    free(d->digests);
    if (d->rs_init)
        voleith_rs_free(&d->rs);
}

/* ========================================================================
 * Tests
 * ======================================================================== */

static void
test_consistent_128(void)
{
    struct ds d;
    int ok = 0;

    TEST("consistent codeword passes (CR-128 n=6 k=3)");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     NULL) != VOLEITH_EC_OK) {
        FAIL("check_consistency returned non-OK on a consistent codeword");
        goto out;
    }
    ok = 1;
out:
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_consistent_256(void)
{
    struct ds d;
    int ok = 0;

    TEST("consistent codeword passes (CR-256 n=8 k=4)");
    if (ds_init(&d, VOLEITH_RS_CR_256, 8, 4, 32) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     NULL) != VOLEITH_EC_OK) {
        FAIL("check_consistency returned non-OK on a consistent codeword");
        goto out;
    }
    ok = 1;
out:
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_tampered_parity(void)
{
    struct ds d;
    uint8_t *bad_digests;
    int ok = 0;
    size_t parity_offset;

    TEST("tampered parity digest fails");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    bad_digests = malloc(d.n * d.digb);
    if (bad_digests == NULL) {
        FAIL("oom");
        ds_free(&d);
        return;
    }
    memcpy(bad_digests, d.digests, d.n * d.digb);

    /* Corrupt the first parity chunk digest (index k). */
    parity_offset = d.k * d.digb;
    bad_digests[parity_offset] ^= 0x01;

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, bad_digests,
                                     NULL) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("check_consistency did not return VERIFY on tampered parity");
        goto out;
    }
    ok = 1;
out:
    free(bad_digests);
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_tampered_data(void)
{
    struct ds d;
    uint8_t *bad_digests;
    int ok = 0;

    TEST("tampered data digest fails");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    bad_digests = malloc(d.n * d.digb);
    if (bad_digests == NULL) {
        FAIL("oom");
        ds_free(&d);
        return;
    }
    memcpy(bad_digests, d.digests, d.n * d.digb);

    /* Corrupt a byte in the second data chunk's committed digest (index 1). */
    bad_digests[1 * d.digb + 5] ^= 0xff;

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, bad_digests,
                                     NULL) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("check_consistency did not return VERIFY on tampered data digest");
        goto out;
    }
    ok = 1;
out:
    free(bad_digests);
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_inconsistent_message(void)
{
    struct ds d;
    uint8_t *bad_message;
    int ok = 0;

    TEST("inconsistent message (owner committed wrong codeword) fails");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    /* A different message will re-encode to a different codeword; at least one
     * chunk digest will not match the committed digests from d. */
    bad_message = malloc(d.k * d.cb);
    if (bad_message == NULL) {
        FAIL("oom");
        ds_free(&d);
        return;
    }
    memcpy(bad_message, d.message, d.k * d.cb);
    bad_message[0] ^= 0x01; /* flip one bit in the first data chunk */

    if (voleith_rs_check_consistency(&d.rs, d.cr, bad_message, d.cb, d.digests,
                                     NULL) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("check_consistency did not return VERIFY on wrong message");
        goto out;
    }
    ok = 1;
out:
    free(bad_message);
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_whole_file_pass(void)
{
    struct ds d;
    uint8_t wfd[64]; /* max digest width */
    int ok = 0;

    TEST("whole-file digest passes on correct rebuild");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    /* Compute the expected whole-file digest: H(M[0:file_len]). */
    if (voleith_rs_whole_file_digest(d.cr, d.message, d.meta.file_len, wfd,
                                     sizeof(wfd)) != VOLEITH_EC_OK) {
        FAIL("whole_file_digest");
        ds_free(&d);
        return;
    }
    d.meta.whole_file_digest = wfd;

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     &d.meta) != VOLEITH_EC_OK) {
        FAIL(
            "check_consistency returned non-OK with correct whole-file digest");
        goto out;
    }
    ok = 1;
out:
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_whole_file_fail(void)
{
    struct ds d;
    uint8_t wfd[64];
    int ok = 0;

    TEST("whole-file digest fails on wrong digest");
    if (ds_init(&d, VOLEITH_RS_CR_128, 6, 3, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    /* Compute correct digest, then corrupt one byte. */
    if (voleith_rs_whole_file_digest(d.cr, d.message, d.meta.file_len, wfd,
                                     sizeof(wfd)) != VOLEITH_EC_OK) {
        FAIL("whole_file_digest");
        ds_free(&d);
        return;
    }
    wfd[0] ^= 0x01;
    d.meta.whole_file_digest = wfd;

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     &d.meta) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("check_consistency did not return VERIFY on wrong whole-file "
             "digest");
        goto out;
    }
    ok = 1;
out:
    ds_free(&d);
    if (ok)
        PASS();
}

static void
test_whole_file_file_len_trim(void)
{
    struct ds d;
    uint8_t wfd[64];
    int ok = 0;

    /* When file_len < k*chunk_bytes the last bytes are padding.  The
     * whole-file digest covers only the real file bytes, not the pad. */
    TEST("whole-file digest respects file_len trim");
    if (ds_init(&d, VOLEITH_RS_CR_128, 4, 2, 16) != 0) {
        FAIL("ds_init");
        ds_free(&d);
        return;
    }

    /* Trim three bytes off the end (pretend the last chunk was padded). */
    d.meta.file_len = (uint64_t)(d.k * d.cb) - 3;
    if (voleith_rs_whole_file_digest(d.cr, d.message, d.meta.file_len, wfd,
                                     sizeof(wfd)) != VOLEITH_EC_OK) {
        FAIL("whole_file_digest");
        ds_free(&d);
        return;
    }
    d.meta.whole_file_digest = wfd;

    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     &d.meta) != VOLEITH_EC_OK) {
        FAIL("check_consistency failed with trimmed file_len");
        goto out;
    }

    /* A digest over the full k*chunk_bytes (without trimming) must differ. */
    d.meta.file_len = (uint64_t)(d.k * d.cb);
    if (voleith_rs_check_consistency(&d.rs, d.cr, d.message, d.cb, d.digests,
                                     &d.meta) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("check did not detect file_len mismatch");
        goto out;
    }
    ok = 1;
out:
    ds_free(&d);
    if (ok)
        PASS();
}

/* ========================================================================
 * main
 * ======================================================================== */

int
main(void)
{
    printf("=== RS capability-3 consistency check tests ===\n");

    test_consistent_128();
    test_consistent_256();
    test_tampered_parity();
    test_tampered_data();
    test_inconsistent_message();
    test_whole_file_pass();
    test_whole_file_fail();
    test_whole_file_file_len_trim();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
