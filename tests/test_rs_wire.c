/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_rs_wire.c - dataset descriptor and per-chunk header wire serializers
 * (erasure/rs_wire.c, design section 6.10, plan T6.10).
 *
 * Covers: descriptor serialize/parse round-trip and that the parsed merkle_root
 * recomputes the same R as compute_R (so any tampered descriptor byte changes R
 * or fails to parse); chunk-header round-trip with the possession flag 0; the
 * forward-compat path where header_flags.bit0 is set and a non-empty
 * possession_tag is defined-and-skipped with the certificate intact; and
 * rejection of truncated input, a bad version byte, and a wrong-width R.
 *
 * The certificate is an opaque blob to this layer, so a synthetic byte string
 * stands in for a real gf8 proof.
 */

#include "rs_dataset.h"
#include "rs_wire.h"

#include <stdio.h>
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

/* 64-byte pool: first 32 bytes serve CR-128, all 64 serve CR-256. */
static const uint8_t sample64[64] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
    0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xa5,
    0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x69, 0x96, 0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe};

/* A stand-in certificate blob (opaque to the header layer). */
static const uint8_t fake_cert[37] = {
    0xc0, 0xff, 0xee, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
    0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21};

static const uint8_t fake_poss[9] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4,
                                     0xa5, 0xa6, 0xa7, 0xa8};

static void
baseline_meta(voleith_rs_metadata_t *m, voleith_rs_cr_profile_t cr)
{
    memset(m, 0, sizeof(*m));
    m->cr_profile = cr;
    m->chunk_size = 4096;
    m->file_len = 1000000;
    m->n = 20;
    m->k = 12;
    m->whole_file_digest = sample64; /* present (CR width) */
}

/* ----------------------------------------------------------------------- */

static void
test_descriptor_roundtrip(voleith_rs_cr_profile_t cr, const char *name)
{
    voleith_rs_metadata_t m, p;
    const uint8_t *root_p;
    uint8_t buf[256];
    uint8_t R_direct[64], R_parsed[64];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t want, wrote, root_len, R_len;

    TEST(name);

    baseline_meta(&m, cr);

    if (voleith_rs_descriptor_serialized_len(&m, &want) != VOLEITH_EC_OK) {
        FAIL("serialized_len");
        return;
    }
    {
        size_t meta_len;
        if (voleith_rs_metadata_serialized_len(&m, &meta_len) !=
                VOLEITH_EC_OK ||
            want != db + meta_len) {
            FAIL("serialized_len value");
            return;
        }
    }

    if (voleith_rs_descriptor_serialize(sample64, db, &m, buf, sizeof(buf),
                                        &wrote) != VOLEITH_EC_OK ||
        wrote != want) {
        FAIL("serialize");
        return;
    }
    /* merkle_root sits first, verbatim. */
    if (memcmp(buf, sample64, db) != 0) {
        FAIL("root not at offset 0");
        return;
    }

    /* Parse: width auto-detected, root zero-copy into buf, metadata recovered. */
    if (voleith_rs_descriptor_parse(buf, wrote, &root_p, &root_len, &p) !=
        VOLEITH_EC_OK) {
        FAIL("parse");
        return;
    }
    if (root_len != db || root_p != buf || memcmp(root_p, sample64, db) != 0) {
        FAIL("parsed root");
        return;
    }
    if (p.cr_profile != m.cr_profile || p.chunk_size != m.chunk_size ||
        p.file_len != m.file_len || p.n != m.n || p.k != m.k) {
        FAIL("parsed metadata mismatch");
        return;
    }

    /* The parsed (root, metadata) recompute the same R as compute_R direct. */
    if (voleith_rs_compute_R(sample64, db, &m, R_direct, db) != VOLEITH_EC_OK) {
        FAIL("compute_R direct");
        return;
    }
    if (voleith_rs_descriptor_parse_compute_R(
            buf, wrote, R_parsed, sizeof(R_parsed), &R_len) != VOLEITH_EC_OK ||
        R_len != db || memcmp(R_direct, R_parsed, db) != 0) {
        FAIL("parse_compute_R mismatch");
        return;
    }

    PASS();
}

static void
test_descriptor_tamper(voleith_rs_cr_profile_t cr, const char *name)
{
    voleith_rs_metadata_t m;
    uint8_t buf[256];
    uint8_t R0[64], R1[64];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t wrote, R_len;

    TEST(name);

    baseline_meta(&m, cr);
    if (voleith_rs_descriptor_serialize(sample64, db, &m, buf, sizeof(buf),
                                        &wrote) != VOLEITH_EC_OK) {
        FAIL("serialize");
        return;
    }
    if (voleith_rs_descriptor_parse_compute_R(buf, wrote, R0, sizeof(R0),
                                              &R_len) != VOLEITH_EC_OK) {
        FAIL("baseline R");
        return;
    }

    /* Flip a byte in the merkle_root region: R must change. */
    buf[0] ^= 0x01;
    if (voleith_rs_descriptor_parse_compute_R(buf, wrote, R1, sizeof(R1),
                                              &R_len) != VOLEITH_EC_OK ||
        memcmp(R0, R1, db) == 0) {
        FAIL("root tamper did not change R");
        return;
    }
    buf[0] ^= 0x01;

    /* Flip a byte in the metadata region (chunk_size at root+2): R changes. */
    buf[db + 2] ^= 0x80;
    if (voleith_rs_descriptor_parse_compute_R(buf, wrote, R1, sizeof(R1),
                                              &R_len) != VOLEITH_EC_OK ||
        memcmp(R0, R1, db) == 0) {
        FAIL("metadata tamper did not change R");
        return;
    }
    buf[db + 2] ^= 0x80;

    /* Truncated descriptor fails to parse. */
    if (voleith_rs_descriptor_parse_compute_R(buf, wrote - 1, R1, sizeof(R1),
                                              &R_len) != VOLEITH_EC_ERR_PARAM) {
        FAIL("truncated descriptor accepted");
        return;
    }

    PASS();
}

static void
test_header_roundtrip(voleith_rs_cr_profile_t cr, const char *name)
{
    const uint8_t *R_p, *cert_p, *poss_p;
    uint8_t buf[256];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t want, wrote, R_len, cert_len, poss_len, consumed;

    TEST(name);

    if (voleith_rs_chunk_header_serialized_len(cr, sizeof(fake_cert), 0,
                                               &want) != VOLEITH_EC_OK ||
        want != 1u + 1u + db + 4u + sizeof(fake_cert)) {
        FAIL("serialized_len");
        return;
    }

    if (voleith_rs_chunk_header_serialize(
            cr, sample64, db, fake_cert, sizeof(fake_cert), NULL, 0, buf,
            sizeof(buf), &wrote) != VOLEITH_EC_OK ||
        wrote != want) {
        FAIL("serialize");
        return;
    }
    if (buf[0] != VOLEITH_RS_HEADER_VERSION || buf[1] != 0x00) {
        FAIL("version/flags bytes");
        return;
    }

    if (voleith_rs_chunk_header_parse(cr, buf, wrote, &R_p, &R_len, &cert_p,
                                      &cert_len, &poss_p, &poss_len,
                                      &consumed) != VOLEITH_EC_OK) {
        FAIL("parse");
        return;
    }
    if (R_len != db || memcmp(R_p, sample64, db) != 0) {
        FAIL("parsed R");
        return;
    }
    if (cert_len != sizeof(fake_cert) ||
        memcmp(cert_p, fake_cert, sizeof(fake_cert)) != 0) {
        FAIL("parsed certificate");
        return;
    }
    if (poss_p != NULL || poss_len != 0) {
        FAIL("spurious possession tag");
        return;
    }
    if (consumed != wrote) {
        FAIL("consumed != header length");
        return;
    }

    PASS();
}

static void
test_header_possession_forward_compat(voleith_rs_cr_profile_t cr,
                                      const char *name)
{
    const uint8_t *R_p, *cert_p, *poss_p;
    uint8_t buf[256];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t wrote, R_len, cert_len, poss_len, consumed;

    TEST(name);

    /* A future possession-enabled chunk: header_flags.bit0 set, tag present. */
    if (voleith_rs_chunk_header_serialize(
            cr, sample64, db, fake_cert, sizeof(fake_cert), fake_poss,
            sizeof(fake_poss), buf, sizeof(buf), &wrote) != VOLEITH_EC_OK) {
        FAIL("serialize");
        return;
    }
    if (buf[1] != VOLEITH_RS_HEADER_FLAG_POSSESSION_TAG) {
        FAIL("possession flag not set");
        return;
    }

    /* The same parse path reads it: certificate intact, reserved tag skipped
     * (but exposed for a future consumer). */
    if (voleith_rs_chunk_header_parse(cr, buf, wrote, &R_p, &R_len, &cert_p,
                                      &cert_len, &poss_p, &poss_len,
                                      &consumed) != VOLEITH_EC_OK) {
        FAIL("parse");
        return;
    }
    if (cert_len != sizeof(fake_cert) ||
        memcmp(cert_p, fake_cert, sizeof(fake_cert)) != 0) {
        FAIL("certificate not intact");
        return;
    }
    if (poss_p == NULL || poss_len != sizeof(fake_poss) ||
        memcmp(poss_p, fake_poss, sizeof(fake_poss)) != 0) {
        FAIL("possession tag not recovered");
        return;
    }
    if (consumed != wrote) {
        FAIL("consumed != header length");
        return;
    }

    /* A consumer that ignores the possession tag still parses (NULL outs). */
    if (voleith_rs_chunk_header_parse(cr, buf, wrote, NULL, NULL, &cert_p,
                                      &cert_len, NULL, NULL,
                                      NULL) != VOLEITH_EC_OK ||
        cert_len != sizeof(fake_cert)) {
        FAIL("parse with NULL outs");
        return;
    }

    PASS();
}

static void
test_header_rejects(void)
{
    const voleith_rs_cr_profile_t cr = VOLEITH_RS_CR_128;
    uint8_t buf[256];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t wrote, cert_len;
    const uint8_t *cert_p;

    TEST("header parse rejects truncated / bad version / wrong width / bad "
         "flag");

    if (voleith_rs_chunk_header_serialize(
            cr, sample64, db, fake_cert, sizeof(fake_cert), NULL, 0, buf,
            sizeof(buf), &wrote) != VOLEITH_EC_OK) {
        FAIL("serialize");
        return;
    }

    /* Truncated header (drop the last certificate byte): cert_len overruns. */
    if (voleith_rs_chunk_header_parse(cr, buf, wrote - 1, NULL, NULL, &cert_p,
                                      &cert_len, NULL, NULL,
                                      NULL) != VOLEITH_EC_ERR_PARAM) {
        FAIL("truncated accepted");
        return;
    }

    /* Bad version byte. */
    buf[0] = 0x02;
    if (voleith_rs_chunk_header_parse(cr, buf, wrote, NULL, NULL, &cert_p,
                                      &cert_len, NULL, NULL,
                                      NULL) != VOLEITH_EC_ERR_PARAM) {
        FAIL("bad version accepted");
        return;
    }
    buf[0] = VOLEITH_RS_HEADER_VERSION;

    /* Undefined flag bit set. */
    buf[1] = 0x02;
    if (voleith_rs_chunk_header_parse(cr, buf, wrote, NULL, NULL, &cert_p,
                                      &cert_len, NULL, NULL,
                                      NULL) != VOLEITH_EC_ERR_PARAM) {
        FAIL("undefined flag accepted");
        return;
    }
    buf[1] = 0x00;

    /* Wrong width: a CR-128 header parsed as CR-256 reads R past its end and
     * mis-sizes the certificate (here the buffer is too short for 64-byte R). */
    if (voleith_rs_chunk_header_parse(VOLEITH_RS_CR_256, buf, wrote, NULL, NULL,
                                      &cert_p, &cert_len, NULL, NULL,
                                      NULL) != VOLEITH_EC_ERR_PARAM) {
        FAIL("wrong-width parse accepted");
        return;
    }

    /* serialize with a mismatched R_len is rejected. */
    if (voleith_rs_chunk_header_serialize(
            cr, sample64, 64, fake_cert, sizeof(fake_cert), NULL, 0, buf,
            sizeof(buf), &wrote) != VOLEITH_EC_ERR_PARAM) {
        FAIL("R_len mismatch accepted on serialize");
        return;
    }

    PASS();
}

int
main(void)
{
    printf("=== RS descriptor + chunk-header wire tests ===\n");

    test_descriptor_roundtrip(VOLEITH_RS_CR_128,
                              "descriptor round-trip (CR-128)");
    test_descriptor_roundtrip(VOLEITH_RS_CR_256,
                              "descriptor round-trip (CR-256)");
    test_descriptor_tamper(VOLEITH_RS_CR_128,
                           "descriptor tamper flips R (CR-128)");
    test_descriptor_tamper(VOLEITH_RS_CR_256,
                           "descriptor tamper flips R (CR-256)");
    test_header_roundtrip(VOLEITH_RS_CR_128,
                          "chunk header round-trip (CR-128)");
    test_header_roundtrip(VOLEITH_RS_CR_256,
                          "chunk header round-trip (CR-256)");
    test_header_possession_forward_compat(
        VOLEITH_RS_CR_128, "possession forward-compat skip (CR-128)");
    test_header_possession_forward_compat(
        VOLEITH_RS_CR_256, "possession forward-compat skip (CR-256)");
    test_header_rejects();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
