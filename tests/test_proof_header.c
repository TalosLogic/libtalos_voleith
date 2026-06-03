/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_proof_header.c - Tests for the 48-byte proof metadata header.
 *
 * Step 2 of the implementation plan in
 * docs/PROOF_METADATA_HEADER_DESIGN.md: exercises only the fixed-prefix
 * parse + serialize path.  The fingerprint helpers and the
 * voleith_proof_header_check_identity check are tested in later steps.
 *
 * Tests:
 *   1: Round-trip every legal (version, fs, bavc, param) tuple.
 *   2: Fingerprint bytes round-trip verbatim.
 *   3: Parse rejects each fixed-prefix tamper (magic, version, enums,
 *      flags, reserved).
 *   4: Parse rejects short input.
 *   5: Parse and serialize reject NULL pointers.
 *   6: Serialize rejects out-of-range fields.
 *   7: Serialize size-query mode and short-buffer rejection.
 *   8: voleith_proof_header_check_identity accepts matching circuit +
 *      params, rejects every mismatch flavor and NULL args.
 *   9: voleith_proof_inspect parses v1 headers, supports NULL
 *      header_out, rejects malformed inputs.
 */

#include "proof_header.h"

#include "circuit.h"
#include "circuit_fingerprint.h"
#include "params_fingerprint.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int test_count = 0;
static int pass_count = 0;

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

/*
 * Wrap the size-query serialize API for the common case of writing
 * into a fixed-size local buffer.  Returns voleith_proof_header_serialize's
 * status; on success the buffer holds exactly VOLEITH_PROOF_HEADER_BYTES.
 */
static int
serialize_to_buf(uint8_t buf[VOLEITH_PROOF_HEADER_BYTES],
                 const voleith_proof_header_t *h)
{
    size_t len = VOLEITH_PROOF_HEADER_BYTES;
    return voleith_proof_header_serialize(buf, &len, h);
}

/*
 * Build a freshly-zeroed header populated with the supplied variant
 * values and distinguishable fingerprint bytes.  Used by every test
 * that needs a well-formed starting point.
 */
static void
make_header(voleith_proof_header_t *h, uint8_t version, uint8_t fs,
            uint8_t bavc, uint8_t param)
{
    size_t i;

    memset(h, 0, sizeof(*h));
    h->magic[0] = VOLEITH_PROOF_MAGIC_0;
    h->magic[1] = VOLEITH_PROOF_MAGIC_1;
    h->magic[2] = VOLEITH_PROOF_MAGIC_2;
    h->magic[3] = VOLEITH_PROOF_MAGIC_3;
    h->format_version = version;
    h->fs_kind = fs;
    h->bavc_kind = bavc;
    h->param_set_id = param;
    for (i = 0; i < VOLEITH_PROOF_FINGERPRINT_BYTES; i++) {
        h->circuit_fp[i] = (uint8_t)(0xa0 + i);
        h->params_fp[i] = (uint8_t)(0xb0 + i);
    }
}

/* ================================================================
 * Test 1: Round-trip every legal variant tuple.
 * ================================================================ */
static void
test_roundtrip_all_legal(void)
{
    voleith_proof_header_t h, parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];
    int fs, bavc, param;
    int ok = 1;

    for (fs = 0; fs <= (int)VOLEITH_FS_GROSTL && ok; fs++) {
        for (bavc = 0; bavc <= (int)VOLEITH_BAVC_HALF_TREE && ok; bavc++) {
            for (param = 0; param <= (int)VOLEITH_PARAM_EM_256S && ok;
                 param++) {
                make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, (uint8_t)fs,
                            (uint8_t)bavc, (uint8_t)param);
                if (serialize_to_buf(buf, &h) != 0) {
                    ok = 0;
                    break;
                }
                if (voleith_proof_header_parse(&parsed, buf, sizeof(buf)) !=
                    0) {
                    ok = 0;
                    break;
                }
                /*
                 * Compare per-field.  Comparing the struct with memcmp
                 * would risk reading tail / hole padding that parse
                 * zeroed but a hand-built header populated piecewise.
                 */
                if (parsed.format_version != h.format_version ||
                    parsed.fs_kind != h.fs_kind ||
                    parsed.bavc_kind != h.bavc_kind ||
                    parsed.param_set_id != h.param_set_id ||
                    parsed.flags != h.flags ||
                    memcmp(parsed.magic, h.magic, 4) != 0 ||
                    memcmp(parsed.reserved, h.reserved, 6) != 0 ||
                    memcmp(parsed.circuit_fp, h.circuit_fp,
                           VOLEITH_PROOF_FINGERPRINT_BYTES) != 0 ||
                    memcmp(parsed.params_fp, h.params_fp,
                           VOLEITH_PROOF_FINGERPRINT_BYTES) != 0) {
                    ok = 0;
                    break;
                }
            }
        }
    }
    check("roundtrip: every (fs,bavc,param) tuple", ok);
}

/* ================================================================
 * Test 2: Fingerprint bytes round-trip verbatim, including bytes that
 * would be illegal if interpreted in the fixed prefix.
 * ================================================================ */
static void
test_fingerprint_roundtrip(void)
{
    voleith_proof_header_t h, parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];
    size_t i;

    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    /* Adversarial fingerprint bytes - all 0xff, including bits that
     * would fail prefix validation.  These must pass through untouched. */
    memset(h.circuit_fp, 0xff, VOLEITH_PROOF_FINGERPRINT_BYTES);
    memset(h.params_fp, 0xff, VOLEITH_PROOF_FINGERPRINT_BYTES);

    check("serialize accepts opaque fingerprints",
          serialize_to_buf(buf, &h) == 0);
    check("parse accepts opaque fingerprints",
          voleith_proof_header_parse(&parsed, buf, sizeof(buf)) == 0);

    for (i = 0; i < VOLEITH_PROOF_FINGERPRINT_BYTES; i++) {
        if (parsed.circuit_fp[i] != 0xff || parsed.params_fp[i] != 0xff) {
            check("fingerprint bytes round-trip verbatim", 0);
            return;
        }
    }
    check("fingerprint bytes round-trip verbatim", 1);
}

/* ================================================================
 * Test 3: Parse rejects each fixed-prefix tamper.
 *
 * Strategy: produce one valid serialization, then for each constrained
 * position write a value that should be rejected and confirm parse
 * returns -1.  Fingerprint bytes (16..47) are NOT constrained at parse
 * time, so they are exempt from this loop.
 * ================================================================ */
static void
test_tamper_rejects(void)
{
    voleith_proof_header_t h, parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];
    uint8_t tampered[VOLEITH_PROOF_HEADER_BYTES];
    int ok;

    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    if (serialize_to_buf(buf, &h) != 0) {
        check("tamper setup: serialize baseline", 0);
        return;
    }

    /* Sanity: the baseline parses. */
    check("tamper baseline: parse accepts valid header",
          voleith_proof_header_parse(&parsed, buf, sizeof(buf)) == 0);

    /* Magic: any byte wrong. */
    ok = 1;
    for (size_t i = 0; i < 4; i++) {
        memcpy(tampered, buf, sizeof(tampered));
        tampered[i] ^= 0xff; /* guaranteed different */
        if (voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) ==
            0) {
            ok = 0;
            break;
        }
    }
    check("tamper: parse rejects bad magic at each of 4 bytes", ok);

    /* Format version: 0x00, 0x02, 0xff. */
    ok = 1;
    {
        uint8_t bad_versions[] = {0x00, 0x02, 0xff};
        for (size_t i = 0; i < sizeof(bad_versions); i++) {
            memcpy(tampered, buf, sizeof(tampered));
            tampered[4] = bad_versions[i];
            if (voleith_proof_header_parse(&parsed, tampered,
                                           sizeof(tampered)) == 0) {
                ok = 0;
                break;
            }
        }
    }
    check("tamper: parse rejects bad format_version", ok);

    /* fs_kind out of range. */
    memcpy(tampered, buf, sizeof(tampered));
    tampered[5] = 2;
    check("tamper: parse rejects fs_kind=2",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);
    tampered[5] = 0xff;
    check("tamper: parse rejects fs_kind=0xff",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);

    /* bavc_kind out of range. */
    memcpy(tampered, buf, sizeof(tampered));
    tampered[6] = 2;
    check("tamper: parse rejects bavc_kind=2",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);

    /* param_set_id out of range. */
    memcpy(tampered, buf, sizeof(tampered));
    tampered[7] = 6;
    check("tamper: parse rejects param_set_id=6",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);
    tampered[7] = 0xff;
    check("tamper: parse rejects param_set_id=0xff",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);

    /* Flags: any nonzero bit (low byte). */
    memcpy(tampered, buf, sizeof(tampered));
    tampered[8] = 0x01;
    check("tamper: parse rejects flags low byte set",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);

    /* Flags: any nonzero bit (high byte). */
    memcpy(tampered, buf, sizeof(tampered));
    tampered[9] = 0x80;
    check("tamper: parse rejects flags high byte set",
          voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) != 0);

    /* Reserved: each of the 6 bytes nonzero. */
    ok = 1;
    for (size_t i = 10; i < 16; i++) {
        memcpy(tampered, buf, sizeof(tampered));
        tampered[i] = 0x01;
        if (voleith_proof_header_parse(&parsed, tampered, sizeof(tampered)) ==
            0) {
            ok = 0;
            break;
        }
    }
    check("tamper: parse rejects each nonzero reserved byte", ok);
}

/* ================================================================
 * Test 4: Parse rejects short input.
 * ================================================================ */
static void
test_short_input(void)
{
    voleith_proof_header_t h, parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];

    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    (void)serialize_to_buf(buf, &h);

    /* One byte short. */
    check("parse rejects len = HEADER_BYTES - 1",
          voleith_proof_header_parse(&parsed, buf,
                                     VOLEITH_PROOF_HEADER_BYTES - 1) != 0);
    /* Zero length. */
    check("parse rejects len = 0",
          voleith_proof_header_parse(&parsed, buf, 0) != 0);
    /* Exact length still accepted. */
    check("parse accepts len = HEADER_BYTES",
          voleith_proof_header_parse(&parsed, buf,
                                     VOLEITH_PROOF_HEADER_BYTES) == 0);
    /* Longer length accepted - simulates a caller passing the full
     * proof->len, where the header is just the first 48 bytes. */
    check("parse accepts len > HEADER_BYTES",
          voleith_proof_header_parse(&parsed, buf,
                                     VOLEITH_PROOF_HEADER_BYTES + 1024) == 0);
}

/* ================================================================
 * Test 5: Parse and serialize reject NULL pointers (size-query
 * exception: NULL out with non-NULL len is a valid serialize call).
 * ================================================================ */
static void
test_null_args(void)
{
    voleith_proof_header_t h, parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];
    size_t len;

    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    (void)serialize_to_buf(buf, &h);

    /* Parse rejects NULL out / NULL bytes. */
    check("parse rejects NULL out",
          voleith_proof_header_parse(NULL, buf, sizeof(buf)) != 0);
    check("parse rejects NULL bytes",
          voleith_proof_header_parse(&parsed, NULL, sizeof(buf)) != 0);

    /* Serialize rejects NULL len in either mode. */
    check("serialize rejects NULL len (write mode)",
          voleith_proof_header_serialize(buf, NULL, &h) != 0);
    check("serialize rejects NULL len (size-query mode)",
          voleith_proof_header_serialize(NULL, NULL, &h) != 0);

    /* Serialize rejects NULL header. */
    len = sizeof(buf);
    check("serialize rejects NULL header (write mode)",
          voleith_proof_header_serialize(buf, &len, NULL) != 0);
    check("serialize rejects NULL header (size-query mode)",
          voleith_proof_header_serialize(NULL, &len, NULL) != 0);
}

/* ================================================================
 * Test 6: Serialize rejects out-of-range fields.
 * ================================================================ */
static void
test_serialize_rejects_bad_struct(void)
{
    voleith_proof_header_t h;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES];

    /* Bad magic. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    h.magic[0] = 'X';
    check("serialize rejects bad magic", serialize_to_buf(buf, &h) != 0);

    /* Bad version. */
    make_header(&h, 0x02, VOLEITH_FS_SHAKE, VOLEITH_BAVC_STANDARD,
                VOLEITH_PARAM_EM_128F);
    check("serialize rejects bad format_version",
          serialize_to_buf(buf, &h) != 0);

    /* fs_kind out of range. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, 2, VOLEITH_BAVC_STANDARD,
                VOLEITH_PARAM_EM_128F);
    check("serialize rejects fs_kind out of range",
          serialize_to_buf(buf, &h) != 0);

    /* bavc_kind out of range. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE, 2,
                VOLEITH_PARAM_EM_128F);
    check("serialize rejects bavc_kind out of range",
          serialize_to_buf(buf, &h) != 0);

    /* param_set_id out of range. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, 6);
    check("serialize rejects param_set_id out of range",
          serialize_to_buf(buf, &h) != 0);

    /* Nonzero flags. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    h.flags = 0x1234;
    check("serialize rejects nonzero flags", serialize_to_buf(buf, &h) != 0);

    /* Nonzero reserved. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    h.reserved[3] = 0x01;
    check("serialize rejects nonzero reserved", serialize_to_buf(buf, &h) != 0);
}

/* ================================================================
 * Test 7: Size-query mode and short-buffer rejection in serialize.
 * ================================================================ */
static void
test_serialize_size_query(void)
{
    voleith_proof_header_t h;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES + 16];
    size_t len;

    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);

    /* Size query: out == NULL, len starts as garbage, must be set to 48. */
    len = 0xdeadbeef;
    check("size-query: returns 0",
          voleith_proof_header_serialize(NULL, &len, &h) == 0);
    check("size-query: writes HEADER_BYTES to *len",
          len == VOLEITH_PROOF_HEADER_BYTES);

    /* Size query does not validate struct contents (size is constant). */
    h.format_version = 0xff;
    len = 0;
    check("size-query: succeeds even with invalid struct",
          voleith_proof_header_serialize(NULL, &len, &h) == 0 &&
              len == VOLEITH_PROOF_HEADER_BYTES);

    /* Restore valid header for the write-mode tests. */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);

    /* Short buffer rejected. */
    len = VOLEITH_PROOF_HEADER_BYTES - 1;
    check("write mode: rejects *len = HEADER_BYTES - 1",
          voleith_proof_header_serialize(buf, &len, &h) != 0);
    check("write mode: *len unchanged after short-buffer reject",
          len == VOLEITH_PROOF_HEADER_BYTES - 1);

    /* Zero-size buffer rejected. */
    len = 0;
    check("write mode: rejects *len = 0",
          voleith_proof_header_serialize(buf, &len, &h) != 0);

    /* Exact-size buffer accepted, *len updated to bytes written. */
    len = VOLEITH_PROOF_HEADER_BYTES;
    check("write mode: accepts *len = HEADER_BYTES",
          voleith_proof_header_serialize(buf, &len, &h) == 0);
    check("write mode: *len set to bytes written",
          len == VOLEITH_PROOF_HEADER_BYTES);

    /* Oversized buffer accepted, *len reflects bytes actually written
     * (not the caller-supplied capacity). */
    len = sizeof(buf);
    check("write mode: accepts *len > HEADER_BYTES",
          voleith_proof_header_serialize(buf, &len, &h) == 0);
    check("write mode: *len set to HEADER_BYTES (not buffer capacity)",
          len == VOLEITH_PROOF_HEADER_BYTES);
}

/* ================================================================
 * Test 8: check_identity matches when both fingerprints are correct,
 * rejects when either side mismatches or args are NULL.
 * ================================================================ */
static void
test_check_identity(void)
{
    voleith_proof_header_t h;
    voleith_circuit_t *c1, *c2;
    voleith_params_t custom_params;
    wire_id w0, w1;

    /*
     * Build two distinct circuits so we can confirm a fingerprint
     * computed over c1 does not satisfy the verifier of c2.
     */
    c1 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c1);
    w1 = voleith_circuit_add_witness(c1);
    (void)voleith_circuit_add_xor(c1, w0, w1);

    c2 = voleith_circuit_new();
    w0 = voleith_circuit_add_witness(c2);
    w1 = voleith_circuit_add_witness(c2);
    (void)voleith_circuit_add_and(c2, w0, w1); /* AND, not XOR */

    /* Construct a valid header for (c1, em_128f). */
    make_header(&h, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    check("check_identity setup: circuit_fp computes",
          voleith_circuit_fingerprint(c1, h.circuit_fp) == 0);
    check("check_identity setup: params_fp computes",
          voleith_params_fingerprint(&voleith_params_em_128f, h.params_fp) ==
              0);

    /* Positive case: matching circuit + params accepts. */
    check("check_identity: matching circuit + params returns 0",
          voleith_proof_header_check_identity(&h, c1,
                                              &voleith_params_em_128f) == 0);

    /* Negative: wrong circuit (different fingerprint). */
    check("check_identity: wrong circuit rejected",
          voleith_proof_header_check_identity(&h, c2,
                                              &voleith_params_em_128f) != 0);

    /* Negative: wrong params (different EM set). */
    check("check_identity: wrong params rejected",
          voleith_proof_header_check_identity(&h, c1,
                                              &voleith_params_em_256f) != 0);

    /* Negative: custom params with one tweaked field. */
    custom_params = voleith_params_em_128f;
    custom_params.tau += 1;
    check("check_identity: custom params with tweaked field rejected",
          voleith_proof_header_check_identity(&h, c1, &custom_params) != 0);

    /* NULL args rejected. */
    check("check_identity: NULL header rejected",
          voleith_proof_header_check_identity(NULL, c1,
                                              &voleith_params_em_128f) != 0);
    check("check_identity: NULL circuit rejected",
          voleith_proof_header_check_identity(&h, NULL,
                                              &voleith_params_em_128f) != 0);
    check("check_identity: NULL params rejected",
          voleith_proof_header_check_identity(&h, c1, NULL) != 0);

    voleith_circuit_free(c1);
    voleith_circuit_free(c2);
}

/* ================================================================
 * Test 9: voleith_proof_inspect.
 *
 * Synthesizes a header-only voleith_proof_t (no body) for the parse
 * paths.  End-to-end inspect-on-a-real-proof is covered in
 * test_proof.c.
 * ================================================================ */
static void
test_proof_inspect(void)
{
    voleith_proof_header_t h_built, h_parsed;
    uint8_t buf[VOLEITH_PROOF_HEADER_BYTES + 64];
    voleith_proof_t proof;

    make_header(&h_built, VOLEITH_PROOF_FORMAT_VERSION, VOLEITH_FS_SHAKE,
                VOLEITH_BAVC_STANDARD, VOLEITH_PARAM_EM_128F);
    (void)serialize_to_buf(buf, &h_built);
    /* Fill the trailing simulated body bytes so the inspect call sees
     * realistic "header + body" data even though there is no actual
     * body to parse. */
    memset(buf + VOLEITH_PROOF_HEADER_BYTES, 0xCD,
           sizeof(buf) - VOLEITH_PROOF_HEADER_BYTES);

    /* Valid v1 proof: with header_out, succeeds and populates target. */
    proof.data = buf;
    proof.len = sizeof(buf);
    check("inspect: valid v1 proof returns 0",
          voleith_proof_inspect(&proof, &h_parsed) == 0);
    check("inspect: parsed header matches built header",
          h_parsed.format_version == h_built.format_version &&
              h_parsed.fs_kind == h_built.fs_kind &&
              h_parsed.bavc_kind == h_built.bavc_kind &&
              h_parsed.param_set_id == h_built.param_set_id);

    /* NULL header_out: validates without writing. */
    check("inspect: NULL header_out also returns 0 on valid proof",
          voleith_proof_inspect(&proof, NULL) == 0);

    /* Exact-header-size proof (no body): inspect still succeeds. */
    proof.len = VOLEITH_PROOF_HEADER_BYTES;
    check("inspect: exact HEADER_BYTES length accepted",
          voleith_proof_inspect(&proof, &h_parsed) == 0);

    /* Short proof rejected. */
    proof.len = VOLEITH_PROOF_HEADER_BYTES - 1;
    check("inspect: short proof rejected",
          voleith_proof_inspect(&proof, &h_parsed) != 0);
    check("inspect: short proof rejected with NULL header_out",
          voleith_proof_inspect(&proof, NULL) != 0);

    /* Tampered magic - simulates a legacy / pre-header proof reaching
     * inspect.  inspect returns -1; callers route to legacy verify
     * (or reject) themselves. */
    proof.len = sizeof(buf);
    buf[0] = 'X';
    check("inspect: tampered magic rejected (acts as legacy detector)",
          voleith_proof_inspect(&proof, &h_parsed) != 0);
    buf[0] = VOLEITH_PROOF_MAGIC_0;

    /* NULL proof and NULL proof->data rejected. */
    check("inspect: NULL proof rejected",
          voleith_proof_inspect(NULL, &h_parsed) != 0);
    voleith_proof_t empty_proof = {NULL, sizeof(buf)};
    check("inspect: NULL proof->data rejected",
          voleith_proof_inspect(&empty_proof, &h_parsed) != 0);
}

int
main(void)
{
    printf("test_proof_header: starting\n");
    test_roundtrip_all_legal();
    test_fingerprint_roundtrip();
    test_tamper_rejects();
    test_short_input();
    test_null_args();
    test_serialize_rejects_bad_struct();
    test_serialize_size_query();
    test_check_identity();
    test_proof_inspect();
    printf("test_proof_header: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
