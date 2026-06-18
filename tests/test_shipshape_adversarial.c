/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_adversarial.c - Adversarial regression corpus for the
 * Shipshape (.ship) parser (W4.3 of docs/SHIPSHAPE_IMPLEMENTATION_PLAN.md;
 * ISA design 8.4 item 12).
 *
 * Deterministic ctest counterpart to the libFuzzer harness (fuzz/): every
 * input here is a hand-written adversarial case driven through the public
 * voleith_shipshape_parse_buffer entry point.  Each case asserts the parser
 * rejects the input with the defined error code (and, by running to
 * completion under the test build, that it never crashes or hangs).  The
 * four groups are the axes ISA 8.4 item 12 enumerates:
 *
 *   Group A: each Goal 2 registry rule violated once (ISA 1.5 Goal 2).
 *   Group B: each enforceable 5.1 resource bound exceeded by exactly one.
 *   Group C: an illegal byte (outside FORMAT 2.1's charset) in several
 *            positions.
 *   Group D: truncation at every structural boundary of the grammar.
 *
 * These overlap deliberately with the negative cases in
 * test_shipshape_parser.c; this file is the consolidated regression corpus
 * the fuzzer's findings feed into, kept self-contained per ISA 8.4 item 12.
 */

#include "shipshape.h"

#include <stddef.h>
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

/* A minimal well-formed header (crypto-v1). */
#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

static const char HDR_STR[] = HDR;

/* Parse [buf, buf+len) with the given limits; free the result; return code. */
static int
adv_lim(const char *buf, size_t len, const voleith_shipshape_limits_t *lim)
{
    voleith_shipshape_parsed_t p;
    int r;

    r = voleith_shipshape_parse_buffer(&p, buf, len, lim);
    voleith_shipshape_parsed_free(&p);
    return r;
}

/* Parse a NUL-terminated source with default limits. */
static int
adv(const char *buf)
{
    return adv_lim(buf, 0, NULL);
}

/* Parse an explicit-length buffer (for embedded NULs) with default limits. */
static int
adv_n(const char *buf, size_t len)
{
    return adv_lim(buf, len, NULL);
}

/* ================================================================
 * Group A: each Goal 2 registry rule violated once.
 * ================================================================ */

static void
test_goal2_rules(void)
{
    /* (i) Defining a stdlib name is forbidden: definitions are user/* only
     * (STDLIB Goal 2 (i); FORMAT S4). */
    check("goal2: stdlib definition => SUBCIRCUIT",
          adv(HDR "subcircuit stdlib/crypto/aes/sbox (%x : byte) -> "
                  "(%y : byte) {\n"
                  "SQUARE %x -> %y\n"
                  "}\n") == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* (ii) An unregistered stdlib/crypto name is rejected at the name,
     * before any operand is resolved. */
    check("goal2: unknown crypto name => REGISTRY",
          adv(HDR "WITNESS -> %x : byte\n"
                  "stdlib/crypto/aes/nope(%x) -> %y\n") ==
              VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* (ii) The kdf/* entries are deferred to crypto-v2; under crypto-v1 they
     * are simply unknown names (SPEC 7.5). */
    check("goal2: deferred crypto-v2 entry => REGISTRY",
          adv(HDR "WITNESS -> %k : byte[16]\n"
                  "stdlib/crypto/kdf/ctr_cmac_aes_128(%k) -> %o\n") ==
              VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* (iii) An unsupported declared stdlib version is rejected outright at the
     * header, so the body is never reached.  (crypto-v3 is undefined; only
     * crypto-v1 and crypto-v2 are accepted.) */
    check("goal2: version mismatch => HEADER",
          adv(".shipshape 1\n"
              "field GF(2^8) irreducible 0x11B\n"
              "stdlib crypto-v3\n"
              "WITNESS -> %x : byte\n"
              "stdlib/crypto/aes/sbox(%x) -> %y\n") ==
              VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* The structural namespace is empty in v1: any call into it is rejected
     * like an undefined subcircuit (FORMAT S4, ISA 4). */
    check("goal2: structural namespace call => SUBCIRCUIT",
          adv(HDR "WITNESS -> %x : byte\n"
                  "stdlib/structural/xor8(%x) -> %y\n") ==
              VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);
}

/* ================================================================
 * Group B: each 5.1 resource bound exceeded by exactly one.
 * ================================================================ */

static void
test_bounds_plus_one(void)
{
    static char buf[1 << 17];
    voleith_shipshape_limits_t lim;
    size_t off;
    int i;

    /* MAX_IDENT_LEN (256, including the sigil): a wire token of 256 chars
     * (sigil + 255) is accepted; 257 (sigil + 256) is rejected. */
    off = (size_t)snprintf(buf, sizeof(buf), HDR "WITNESS -> %%");
    for (i = 0; i < 255; i++)
        buf[off++] = 'a';
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, " : byte\n");
    check("bound: ident at cap (256) accepted", adv_n(buf, off) == 0);

    off = (size_t)snprintf(buf, sizeof(buf), HDR "WITNESS -> %%");
    for (i = 0; i < 256; i++)
        buf[off++] = 'a';
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, " : byte\n");
    check("bound: ident over cap (257) => IDENT",
          adv_n(buf, off) == VOLEITH_SHIPSHAPE_ERR_IDENT);

    /* MAX_LINE_BYTES via a tight limit: with max_line_bytes = 40 (the header
     * lines are shorter), a 40-byte body line passes and a 41-byte one is
     * rejected.  The body line is a comment so its content is unconstrained. */
    lim = (voleith_shipshape_limits_t){0, 0, 0, 40};
    off = (size_t)snprintf(buf, sizeof(buf), HDR);
    buf[off++] = '#';
    for (i = 0; i < 39; i++) /* '#' + 39 = 40 bytes on the line */
        buf[off++] = 'a';
    buf[off++] = '\n';
    check("bound: line at cap (40) accepted",
          adv_lim(buf, off, &lim) != VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG);

    off = (size_t)snprintf(buf, sizeof(buf), HDR);
    buf[off++] = '#';
    for (i = 0; i < 40; i++) /* '#' + 40 = 41 bytes on the line */
        buf[off++] = 'a';
    buf[off++] = '\n';
    check("bound: line over cap (41) => LINE_TOO_LONG",
          adv_lim(buf, off, &lim) == VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG);

    /* MAX_FILE_BYTES via a tight limit: a 10-byte input passes the size gate
     * at max_file_bytes = 10 and is rejected at 9 (checked before any read). */
    lim = (voleith_shipshape_limits_t){0, 0, 10, 0};
    check("bound: file at cap (10) passes size gate",
          adv_lim("AAAAAAAAAA", 10, &lim) !=
              VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);
    lim = (voleith_shipshape_limits_t){0, 0, 9, 0};
    check("bound: file over cap (10 > 9) => FILE_TOO_BIG",
          adv_lim("AAAAAAAAAA", 10, &lim) ==
              VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);

    /* MAX_WIRES via a tight limit: with max_wires = 4, a byte[4] declaration
     * fits and byte[5] is one over. */
    lim = (voleith_shipshape_limits_t){4, 0, 0, 0};
    check("bound: wires at cap (4) accepted",
          adv_lim(HDR "WITNESS -> %v : byte[4]\n", 0, &lim) == 0);
    check("bound: wires over cap (5 > 4) => LIMIT",
          adv_lim(HDR "WITNESS -> %v : byte[5]\n", 0, &lim) ==
              VOLEITH_SHIPSHAPE_ERR_LIMIT);

    /* MAX_GATES via a tight limit: three ADD gates fit at max_gates = 3 and
     * the third is one over at max_gates = 2 (the two witnesses are inputs,
     * not gates). */
    lim = (voleith_shipshape_limits_t){0, 3, 0, 0};
    check("bound: gates at cap (3) accepted",
          adv_lim(HDR "WITNESS -> %a : byte\n"
                      "WITNESS -> %b : byte\n"
                      "ADD %a %b -> %s\n"
                      "ADD %a %b -> %t\n"
                      "ADD %a %b -> %u\n",
                  0, &lim) == 0);
    lim = (voleith_shipshape_limits_t){0, 2, 0, 0};
    check("bound: gates over cap (3 > 2) => LIMIT",
          adv_lim(HDR "WITNESS -> %a : byte\n"
                      "WITNESS -> %b : byte\n"
                      "ADD %a %b -> %s\n"
                      "ADD %a %b -> %t\n"
                      "ADD %a %b -> %u\n",
                  0, &lim) == VOLEITH_SHIPSHAPE_ERR_LIMIT);

    /* MAX_VECTOR_LEN (2^20): a one-over vector length is rejected before any
     * wire is allocated. */
    check("bound: vector over MAX_VECTOR_LEN (2^20 + 1) => LIMIT",
          adv(HDR "WITNESS -> %v : byte[1048577]\n") ==
              VOLEITH_SHIPSHAPE_ERR_LIMIT);

    /* MAX_INLINE_DEPTH (64): a call chain deeper than the cap aborts while
     * inlining, before the gate array grows. */
    off = (size_t)snprintf(buf, sizeof(buf), HDR);
    off +=
        (size_t)snprintf(buf + off, sizeof(buf) - off,
                         "subcircuit user/d0 (%%x : byte) -> (%%y : byte) {\n"
                         "SQUARE %%x -> %%y\n}\n");
    for (i = 1; i <= 70; i++)
        off += (size_t)snprintf(
            buf + off, sizeof(buf) - off,
            "subcircuit user/d%d (%%x : byte) -> (%%y : byte) {\n"
            "user/d%d(%%x) -> %%y\n}\n",
            i, i - 1);
    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                            "WITNESS -> %%a : byte\n"
                            "user/d70(%%a) -> %%b\n");
    check("bound: inline depth over cap (70 > 64) => INLINE_DEPTH",
          adv_n(buf, off) == VOLEITH_SHIPSHAPE_ERR_INLINE_DEPTH);

    /* MAX_MATRIX_BYTES (8): a LINEAR_MAP matrix must be exactly 8 bytes; a
     * ninth literal is rejected (the parser expects ']' after the eighth). */
    check("bound: LINEAR_MAP matrix over 8 bytes => GATE",
          adv(HDR "WITNESS -> %a : byte\n"
                  "LINEAR_MAP [0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80 0xff] "
                  "%a -> %c\n") == VOLEITH_SHIPSHAPE_ERR_GATE);

    /*
     * MAX_GATES on the Tier 2a registry path: a stdlib/crypto body emits its
     * gates in bulk through the C builders, not the per-statement budget
     * helpers, so the circuit's incremental gate cap is what bounds it.  An
     * aes/encrypt_128 body (200 invs, thousands of gates) is rejected under a
     * tight max_gates, and accepted under default limits.  The 32 key/pt
     * witnesses are inputs and do not count toward max_gates.
     */
    check("bound: registry body over tight max_gates => LIMIT",
          adv_lim(HDR "WITNESS -> %key : byte[16]\n"
                      "WITNESS -> %pt : byte[16]\n"
                      "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n",
                  0, &(voleith_shipshape_limits_t){0, 50, 0, 0}) ==
              VOLEITH_SHIPSHAPE_ERR_LIMIT);
    check("bound: same registry body under default limits parses",
          adv(HDR "WITNESS -> %key : byte[16]\n"
                  "WITNESS -> %pt : byte[16]\n"
                  "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n") == 0);
}

/* ================================================================
 * Group C: an illegal byte (outside FORMAT 2.1's charset) in several
 * positions.  The charset is checked per physical line on read, so any
 * illegal byte anywhere on a body line is VOLEITH_SHIPSHAPE_ERR_CHARSET,
 * comments included.
 * ================================================================ */

/*
 * HDR followed by one body line "<pre><byte><post>\n"; parsed with an
 * explicit length so a NUL byte does not truncate the buffer.
 */
static int
line_with_byte(const char *pre, unsigned char b, const char *post)
{
    static char buf[256];
    size_t off;

    off = (size_t)snprintf(buf, sizeof(buf), "%s%s", HDR_STR, pre);
    buf[off++] = (char)b;
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%s\n", post);
    return adv_n(buf, off);
}

static void
test_illegal_bytes(void)
{
    /* NUL inside a comment (the case that also defeats strlen-based length). */
    check("illegal: NUL in comment => CHARSET",
          line_with_byte("# c", 0x00, "omment") ==
              VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* Vertical tab between tokens. */
    check("illegal: VT (0x0B) between tokens => CHARSET",
          line_with_byte("WITNESS ", 0x0B, "-> %a : byte") ==
              VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* Unit separator at the start of a body line. */
    check("illegal: US (0x1F) at line start => CHARSET",
          line_with_byte("", 0x1F, "") == VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* DEL, the high end of the excluded control range. */
    check("illegal: DEL (0x7F) in a token => CHARSET",
          line_with_byte("CONST 0x6", 0x7F, " -> %c") ==
              VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* A non-ASCII high byte. */
    check("illegal: high byte (0x80) => CHARSET",
          line_with_byte("CONST ", 0x80, "") == VOLEITH_SHIPSHAPE_ERR_CHARSET);
    check("illegal: 0xFF => CHARSET",
          line_with_byte("CONST ", 0xFF, "") == VOLEITH_SHIPSHAPE_ERR_CHARSET);
}

/* ================================================================
 * Group D: truncation at every structural boundary.
 * ================================================================ */

static void
test_truncations(void)
{
    /* Empty input. */
    check("trunc: empty => EMPTY", adv_n("", 0) == VOLEITH_SHIPSHAPE_ERR_EMPTY);

    /* Inside the magic line. */
    check("trunc: partial magic => HEADER",
          adv(".shipshap") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* After the magic, before the field line. */
    check("trunc: magic only => HEADER",
          adv(".shipshape 1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* After the field line, before the stdlib line. */
    check("trunc: magic + field, no stdlib => HEADER",
          adv(".shipshape 1\n"
              "field GF(2^8) irreducible 0x11B\n") ==
              VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* A declaration keyword with nothing after it. */
    check("trunc: WITNESS with no arrow => DECL",
          adv(HDR "WITNESS\n") == VOLEITH_SHIPSHAPE_ERR_DECL);

    /* A declaration cut off before its type. */
    check("trunc: decl with no type => rejected",
          adv(HDR "WITNESS -> %w :\n") != 0);

    /* A vector type with an open bracket and no length or close. */
    check("trunc: vector type, unclosed bracket => rejected",
          adv(HDR "WITNESS -> %v : byte[\n") != 0);

    /* A gate missing its second operand. */
    check("trunc: gate missing operand => GATE",
          adv(HDR "WITNESS -> %a : byte\n"
                  "ADD %a\n") == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* A gate missing its output clause. */
    check("trunc: gate missing output => GATE",
          adv(HDR "WITNESS -> %a : byte\n"
                  "WITNESS -> %b : byte\n"
                  "ADD %a %b\n") == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* A truncated byte literal ("0x" with no hex digits). */
    check("trunc: truncated byte literal => LITERAL",
          adv(HDR "CONST 0x\n") == VOLEITH_SHIPSHAPE_ERR_LITERAL);

    /* A truncated opcode is an unknown opcode. */
    check("trunc: truncated opcode => GATE",
          adv(HDR "WITNESS -> %a : byte\n"
                  "AD %a -> %b\n") == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* A subcircuit body with no closing brace. */
    check("trunc: unclosed subcircuit body => SUBCIRCUIT",
          adv(HDR "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                  "SQUARE %x -> %y\n") == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* A call cut off after the opening parenthesis. */
    check("trunc: unclosed call args => rejected",
          adv(HDR "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                  "SQUARE %x -> %y\n"
                  "}\n"
                  "WITNESS -> %a : byte\n"
                  "user/f(\n") != 0);
}

int
main(void)
{
    printf("test_shipshape_adversarial: starting\n");
    test_goal2_rules();
    test_bounds_plus_one();
    test_illegal_bytes();
    test_truncations();
    printf("test_shipshape_adversarial: %d/%d passed\n", pass_count,
           test_count);
    return (pass_count == test_count) ? 0 : 1;
}
