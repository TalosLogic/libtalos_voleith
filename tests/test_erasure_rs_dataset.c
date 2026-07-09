/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_erasure_rs_dataset.c - dataset metadata serialization and the
 * metadata-to-R binding (erasure/rs_dataset.c, design section 6.7 / 6.10).
 *
 * Covers plan T6.2 (and closes T6.0's acceptance): canonical serialize /
 * parse round-trip, the flags byte, the reserved por_params forward-compat
 * path, malformed-input rejection, and the binding property that every
 * metadata field (and the merkle_root) is committed to R, so any single-field
 * mutation flips R and verify_R rejects it.
 */

#include "rs_dataset.h"

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

/* A 64-byte sample whole-file digest / merkle_root pool (the first 32 bytes
 * serve the 128-bit profile, all 64 the 256-bit profile). */
static const uint8_t sample64[64] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
    0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
    0xdc, 0xfe, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xa5,
    0x5a, 0x3c, 0xc3, 0x0f, 0xf0, 0x69, 0x96, 0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    0x00, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe};

static const uint8_t attr_bytes[5] = {0xde, 0xad, 0xbe, 0xef, 0x01};

static void
baseline_meta(voleith_rs_metadata_t *m, voleith_rs_cr_profile_t cr,
              const uint8_t *wfd, const uint8_t *attr, uint16_t attr_len)
{
    memset(m, 0, sizeof(*m));
    m->cr_profile = cr;
    m->chunk_size = 4096;
    m->file_len = 1000000;
    m->n = 20;
    m->k = 12;
    m->whole_file_digest = wfd;
    m->attr_restriction = attr;
    m->attr_restriction_len = attr ? attr_len : 0;
}

/* Returns 1 if compute_R over (root, base) differs from (root, mut), 0 if
 * equal, -1 on a compute error. */
static int
R_differs(const uint8_t *root, const voleith_rs_metadata_t *base,
          const voleith_rs_metadata_t *mut)
{
    uint8_t R0[64], R1[64];
    size_t db = voleith_rs_cr_digest_bytes(base->cr_profile);

    if (voleith_rs_compute_R(root, db, base, R0, db) != VOLEITH_EC_OK)
        return -1;
    if (voleith_rs_compute_R(root, db, mut, R1, db) != VOLEITH_EC_OK)
        return -1;
    return memcmp(R0, R1, db) != 0 ? 1 : 0;
}

/* ----------------------------------------------------------------------- */

static void
test_serialize_roundtrip(voleith_rs_cr_profile_t cr, const char *name)
{
    voleith_rs_metadata_t m, p;
    uint8_t buf[256], buf2[256];
    size_t db = voleith_rs_cr_digest_bytes(cr);
    size_t want, wrote, wrote2, consumed;
    uint8_t flags;

    TEST(name);

    baseline_meta(&m, cr, sample64, attr_bytes, sizeof(attr_bytes));

    /* serialized_len == 19 + digest + (2 + attr_len). */
    if (voleith_rs_metadata_serialized_len(&m, &want) != VOLEITH_EC_OK) {
        FAIL("serialized_len");
        return;
    }
    if (want != 19 + db + 2 + sizeof(attr_bytes)) {
        FAIL("serialized_len value");
        return;
    }
    if (voleith_rs_metadata_serialize(&m, buf, sizeof(buf), &wrote) !=
            VOLEITH_EC_OK ||
        wrote != want) {
        FAIL("serialize");
        return;
    }

    /* Header bytes are exactly the pinned layout. */
    if (buf[0] != VOLEITH_RS_METADATA_VERSION || buf[1] != (uint8_t)cr) {
        FAIL("header version/profile");
        return;
    }
    if (voleith_rs_metadata_flags(&m, &flags) != VOLEITH_EC_OK ||
        buf[18] != flags ||
        flags != (VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST |
                  VOLEITH_RS_META_FLAG_ATTR_RESTRICTION)) {
        FAIL("flags byte");
        return;
    }

    /* Parse recovers every field; tail pointers are zero-copy into buf. */
    if (voleith_rs_metadata_parse(buf, wrote, &p, &consumed) != VOLEITH_EC_OK ||
        consumed != wrote) {
        FAIL("parse");
        return;
    }
    if (p.cr_profile != m.cr_profile || p.chunk_size != m.chunk_size ||
        p.file_len != m.file_len || p.n != m.n || p.k != m.k) {
        FAIL("parsed scalar mismatch");
        return;
    }
    if (p.whole_file_digest == NULL || p.whole_file_digest < buf ||
        p.whole_file_digest >= buf + wrote ||
        memcmp(p.whole_file_digest, sample64, db) != 0) {
        FAIL("parsed whole_file_digest");
        return;
    }
    if (p.attr_restriction == NULL ||
        p.attr_restriction_len != sizeof(attr_bytes) ||
        memcmp(p.attr_restriction, attr_bytes, sizeof(attr_bytes)) != 0) {
        FAIL("parsed attr_restriction");
        return;
    }
    if (p.por_params != NULL || p.por_params_len != 0) {
        FAIL("parsed spurious por_params");
        return;
    }

    /* Re-serializing the parsed metadata reproduces the byte string. */
    if (voleith_rs_metadata_serialize(&p, buf2, sizeof(buf2), &wrote2) !=
            VOLEITH_EC_OK ||
        wrote2 != wrote || memcmp(buf, buf2, wrote) != 0) {
        FAIL("re-serialize mismatch");
        return;
    }

    PASS();
}

static void
test_flags(void)
{
    voleith_rs_metadata_t m;
    uint8_t flags;

    TEST("flags: none -> 0, all -> 7, inconsistent -> ERR_PARAM");

    /* No optional fields. */
    baseline_meta(&m, VOLEITH_RS_CR_128, NULL, NULL, 0);
    if (voleith_rs_metadata_flags(&m, &flags) != VOLEITH_EC_OK || flags != 0) {
        FAIL("none");
        return;
    }

    /* All three (including reserved por_params). */
    m.whole_file_digest = sample64;
    m.attr_restriction = attr_bytes;
    m.attr_restriction_len = sizeof(attr_bytes);
    m.por_params = attr_bytes;
    m.por_params_len = sizeof(attr_bytes);
    if (voleith_rs_metadata_flags(&m, &flags) != VOLEITH_EC_OK ||
        flags != (VOLEITH_RS_META_FLAG_WHOLE_FILE_DIGEST |
                  VOLEITH_RS_META_FLAG_ATTR_RESTRICTION |
                  VOLEITH_RS_META_FLAG_POR_PARAMS)) {
        FAIL("all");
        return;
    }

    /* Non-NULL pointer with zero length is inconsistent. */
    baseline_meta(&m, VOLEITH_RS_CR_128, NULL, NULL, 0);
    m.attr_restriction = attr_bytes;
    m.attr_restriction_len = 0;
    if (voleith_rs_metadata_flags(&m, &flags) != VOLEITH_EC_ERR_PARAM) {
        FAIL("inconsistent ptr/len");
        return;
    }

    PASS();
}

static void
test_binding_fields_flip_R(voleith_rs_cr_profile_t cr, const char *name)
{
    voleith_rs_metadata_t base, mut;
    uint8_t root[64], root2[64], wfd2[64], attr2[8];
    uint8_t R0[64], R1[64];
    size_t db = voleith_rs_cr_digest_bytes(cr);

    TEST(name);

    memcpy(root, sample64, db);
    baseline_meta(&base, cr, sample64, attr_bytes, sizeof(attr_bytes));

#define EXPECT_FLIP(label, mutate_block)                                       \
    do {                                                                       \
        mut = base;                                                            \
        mutate_block;                                                          \
        if (R_differs(root, &base, &mut) != 1) {                               \
            FAIL(label);                                                       \
            return;                                                            \
        }                                                                      \
    } while (0)

    EXPECT_FLIP("chunk_size", mut.chunk_size = base.chunk_size + 1);
    EXPECT_FLIP("file_len", mut.file_len = base.file_len + 1);
    EXPECT_FLIP("n", mut.n = (uint16_t)(base.n + 1));
    EXPECT_FLIP("k", mut.k = (uint16_t)(base.k + 1));

    /* whole_file_digest: flip one byte of a copy. */
    memcpy(wfd2, sample64, db);
    wfd2[0] ^= 0x01;
    EXPECT_FLIP("whole_file_digest", mut.whole_file_digest = wfd2);

    /* attribute restriction (predicate): flip one byte of a copy. */
    memcpy(attr2, attr_bytes, sizeof(attr_bytes));
    attr2[2] ^= 0x80;
    EXPECT_FLIP("attr_restriction", mut.attr_restriction = attr2);

#undef EXPECT_FLIP

    /* Wrong merkle_root flips R for the same metadata. */
    memcpy(root2, sample64, db);
    root2[0] ^= 0x01;
    if (voleith_rs_compute_R(root, db, &base, R0, db) != VOLEITH_EC_OK ||
        voleith_rs_compute_R(root2, db, &base, R1, db) != VOLEITH_EC_OK ||
        memcmp(R0, R1, db) == 0) {
        FAIL("merkle_root");
        return;
    }

    PASS();
}

static void
test_profile_bound(void)
{
    voleith_rs_metadata_t a, b;
    uint8_t buf[256], d0[64], d1[64];
    size_t wrote;

    TEST("cr_profile is in the canonical string and distinguishes identity");

    /* The cr_profile byte sits at offset 1 of the canonical string (the input
     * to metadata_digest), so it is committed. */
    baseline_meta(&a, VOLEITH_RS_CR_128, NULL, NULL, 0);
    if (voleith_rs_metadata_serialize(&a, buf, sizeof(buf), &wrote) !=
            VOLEITH_EC_OK ||
        buf[1] != (uint8_t)VOLEITH_RS_CR_128) {
        FAIL("profile not at offset 1");
        return;
    }

    /* Two metadatas identical apart from cr_profile have different digests
     * (both the committed profile byte and the selected hash contribute, which
     * is exactly the intent: the profile is part of the dataset identity). */
    baseline_meta(&b, VOLEITH_RS_CR_256, NULL, NULL, 0);
    if (voleith_rs_metadata_digest(&a, d0, sizeof(d0)) != VOLEITH_EC_OK ||
        voleith_rs_metadata_digest(&b, d1, sizeof(d1)) != VOLEITH_EC_OK) {
        FAIL("digest");
        return;
    }
    if (memcmp(d0, d1, 32) == 0) {
        FAIL("profile digest collision");
        return;
    }

    PASS();
}

static void
test_verify_R(voleith_rs_cr_profile_t cr, const char *name)
{
    voleith_rs_metadata_t base, mut;
    uint8_t root[64], R[64];
    size_t db = voleith_rs_cr_digest_bytes(cr);

    TEST(name);

    memcpy(root, sample64, db);
    baseline_meta(&base, cr, sample64, attr_bytes, sizeof(attr_bytes));

    if (voleith_rs_compute_R(root, db, &base, R, db) != VOLEITH_EC_OK) {
        FAIL("compute_R");
        return;
    }

    /* Genuine triple verifies. */
    if (voleith_rs_verify_R(R, db, root, db, &base) != VOLEITH_EC_OK) {
        FAIL("genuine rejected");
        return;
    }

    /* Wrong R rejected. */
    R[0] ^= 0x01;
    if (voleith_rs_verify_R(R, db, root, db, &base) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("tampered R accepted");
        return;
    }
    R[0] ^= 0x01;

    /* Wrong merkle_root rejected. */
    root[0] ^= 0x01;
    if (voleith_rs_verify_R(R, db, root, db, &base) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("wrong root accepted");
        return;
    }
    root[0] ^= 0x01;

    /* Mutated metadata rejected. */
    mut = base;
    mut.k = (uint16_t)(base.k + 1);
    if (voleith_rs_verify_R(R, db, root, db, &mut) != VOLEITH_EC_ERR_VERIFY) {
        FAIL("mutated metadata accepted");
        return;
    }

    /* len(R) disagreeing with cr_profile is a malformed-input PARAM error. */
    if (voleith_rs_verify_R(R, db == 32 ? 64 : 32, root, db, &base) !=
        VOLEITH_EC_ERR_PARAM) {
        FAIL("width mismatch not rejected");
        return;
    }

    PASS();
}

static void
test_parse_rejects(void)
{
    voleith_rs_metadata_t m, p;
    uint8_t buf[256];
    size_t wrote;

    TEST("parse rejects truncated / bad version / unknown flag / overrun");

    baseline_meta(&m, VOLEITH_RS_CR_128, sample64, attr_bytes,
                  sizeof(attr_bytes));
    if (voleith_rs_metadata_serialize(&m, buf, sizeof(buf), &wrote) !=
        VOLEITH_EC_OK) {
        FAIL("serialize");
        return;
    }

    /* Truncated head (< 19 bytes). */
    if (voleith_rs_metadata_parse(buf, 18, &p, NULL) != VOLEITH_EC_ERR_PARAM) {
        FAIL("short head accepted");
        return;
    }

    /* Bad version byte. */
    {
        uint8_t bad[256];
        memcpy(bad, buf, wrote);
        bad[0] = 0x02;
        if (voleith_rs_metadata_parse(bad, wrote, &p, NULL) !=
            VOLEITH_EC_ERR_PARAM) {
            FAIL("bad version accepted");
            return;
        }
    }

    /* Unknown flag bit (0x08) set. */
    {
        uint8_t bad[256];
        memcpy(bad, buf, wrote);
        bad[18] |= 0x08;
        if (voleith_rs_metadata_parse(bad, wrote, &p, NULL) !=
            VOLEITH_EC_ERR_PARAM) {
            FAIL("unknown flag accepted");
            return;
        }
    }

    /* Tail length running past the buffer (truncate after the attr length). */
    if (voleith_rs_metadata_parse(buf, wrote - 1, &p, NULL) !=
        VOLEITH_EC_ERR_PARAM) {
        FAIL("tail overrun accepted");
        return;
    }

    PASS();
}

static void
test_reserved_por_params_roundtrip(void)
{
    voleith_rs_metadata_t m, p;
    uint8_t buf[256];
    uint8_t por[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    size_t wrote, consumed;
    uint8_t flags;

    TEST("reserved por_params serializes/parses via the same code path");

    /* A future possession-enabled dataset: por_params present (flag bit2). */
    baseline_meta(&m, VOLEITH_RS_CR_128, sample64, NULL, 0);
    m.por_params = por;
    m.por_params_len = sizeof(por);

    if (voleith_rs_metadata_flags(&m, &flags) != VOLEITH_EC_OK ||
        (flags & VOLEITH_RS_META_FLAG_POR_PARAMS) == 0) {
        FAIL("por flag not set");
        return;
    }
    if (voleith_rs_metadata_serialize(&m, buf, sizeof(buf), &wrote) !=
        VOLEITH_EC_OK) {
        FAIL("serialize");
        return;
    }
    if (voleith_rs_metadata_parse(buf, wrote, &p, &consumed) != VOLEITH_EC_OK ||
        consumed != wrote) {
        FAIL("parse");
        return;
    }
    if (p.por_params == NULL || p.por_params_len != sizeof(por) ||
        memcmp(p.por_params, por, sizeof(por)) != 0) {
        FAIL("por_params not recovered");
        return;
    }

    PASS();
}

int
main(void)
{
    printf("=== RS dataset metadata + R-binding tests ===\n");

    test_serialize_roundtrip(VOLEITH_RS_CR_128,
                             "serialize round-trip (CR-128)");
    test_serialize_roundtrip(VOLEITH_RS_CR_256,
                             "serialize round-trip (CR-256)");
    test_flags();
    test_binding_fields_flip_R(VOLEITH_RS_CR_128,
                               "every field flips R (CR-128)");
    test_binding_fields_flip_R(VOLEITH_RS_CR_256,
                               "every field flips R (CR-256)");
    test_profile_bound();
    test_verify_R(VOLEITH_RS_CR_128, "verify_R accept/reject (CR-128)");
    test_verify_R(VOLEITH_RS_CR_256, "verify_R accept/reject (CR-256)");
    test_parse_rejects();
    test_reserved_por_params_roundtrip();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
