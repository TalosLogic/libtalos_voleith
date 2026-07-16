/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * test_shipshape_parser.c - Tests for the Shipshape (.ship) parser.
 *
 * Covers W3.1 (entry-point checks), W3.2 (the lexer), W3.3 (the header),
 * and W3.4 (declarations, the wire table, types) of
 * the implementation plan.  The lexer groups reach the
 * tokenizer directly through parsers/shipshape_internal.h; the declaration
 * groups drive the public parse_buffer entry point and inspect the built
 * circuit and the file-order declaration table.
 *
 * Since W3.7 the grammar is complete: declarations, gates, subcircuit
 * calls, and Tier 2a registry calls all parse to a circuit (return 0).
 *
 * Tests:
 *   Group A: Buffer entry validation (NULL / empty / oversized / boundary).
 *   Group B: File entry validation (NULL / missing / empty / oversized).
 *   Group C: Out-struct zeroing on failure and free safety.
 *   Group D: Resource-limit clamping (NULL limits and zero fields => ceiling).
 *   Group E: Lexer token classes (one line per class, kinds and values).
 *   Group F: Lexer bounds exceeded by exactly one (idents, literals, tokens).
 *   Group G: Line layer (CR / LF / CRLF counting, charset incl. comments).
 *   Group H: Line layer through the public parse_buffer entry point.
 *   Group I: Header (three mandatory lines, exact tokens, order, comments).
 *   Group J: Declarations, the wire table, and types (W3.4).
 *   Group K: Gates, assertions, sugar, canonicalization (W3.5).
 *   Group L: Subcircuits, inlining, regions (W3.6).
 *   Group M: Tier 2a registry calls (W3.7).
 */

#define _POSIX_C_SOURCE 200809L

#include "aes_cmac_gf8_circuit.h"
#include "aes_gf8_circuit.h"
#include "gf8_circuit_fingerprint.h"
#include "grostl_gf8_circuit.h"
#include "shipshape.h"
#include "shipshape_internal.h"
#include "shipshape_registry.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * A minimal well-formed header.  Since W3.4 a header with no body parses to
 * an empty-but-valid circuit (return 0), so tests that want to prove the
 * entry / limit / header logic let input through use this prefix and expect
 * success.
 */
static const char VALID_HEADER[] = ".shipshape 1\n"
                                   "field GF(2^8) irreducible 0x11B\n"
                                   "stdlib crypto-v1\n";

/*
 * Parse a NUL-terminated buffer with default limits and return the code,
 * releasing any built result so success paths do not leak.  parsed_free is
 * safe on the zeroed struct a failure leaves behind.
 */
static int
parse_str(const char *buf)
{
    voleith_shipshape_parsed_t p;
    int r;

    r = voleith_shipshape_parse_buffer(&p, buf, 0, NULL);
    voleith_shipshape_parsed_free(&p);
    return r;
}

/*
 * Write `len` bytes of `data` to a fresh temporary file and copy its path
 * into `path_out` (capacity `cap`).  Returns 0 on success, -1 on failure.
 * The caller removes the file with remove() when done.
 */
static int
write_temp(const char *data, size_t len, char *path_out, size_t cap)
{
    char tmpl[] = "/tmp/shipshape_testXXXXXX";
    ssize_t w;
    int fd;

    fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (len > 0) {
        w = write(fd, data, len);
        if (w < 0 || (size_t)w != len) {
            close(fd);
            remove(tmpl);
            return -1;
        }
    }
    close(fd);
    if (strlen(tmpl) + 1 > cap) {
        remove(tmpl);
        return -1;
    }
    memcpy(path_out, tmpl, strlen(tmpl) + 1);
    return 0;
}

/* ================================================================
 * Group A: Buffer entry validation.
 * ================================================================ */

static void
test_buffer_entry(void)
{
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    char big[10];
    int r;

    /* NULL out: cannot zero anything, defined error returned. */
    r = voleith_shipshape_parse_buffer(NULL, "x", 1, NULL);
    check("buffer: NULL out => NULL_ARG", r == VOLEITH_SHIPSHAPE_ERR_NULL_ARG);

    /* NULL buffer. */
    p.circuit = (voleith_gf8_circuit_t *)0x1;
    r = voleith_shipshape_parse_buffer(&p, NULL, 0, NULL);
    check("buffer: NULL buf => NULL_ARG", r == VOLEITH_SHIPSHAPE_ERR_NULL_ARG);
    check("buffer: NULL buf zeroes out", p.circuit == NULL);

    /* Empty buffer via explicit len 0 + empty string (strlen path). */
    p.circuit = (voleith_gf8_circuit_t *)0x1;
    r = voleith_shipshape_parse_buffer(&p, "", 0, NULL);
    check("buffer: empty (strlen) => EMPTY", r == VOLEITH_SHIPSHAPE_ERR_EMPTY);
    check("buffer: empty zeroes out", p.circuit == NULL);

    /* Non-empty input clears the EMPTY gate (then fails later: no header). */
    r = voleith_shipshape_parse_buffer(&p, "anything", 0, NULL);
    check("buffer: non-empty clears EMPTY gate",
          r != VOLEITH_SHIPSHAPE_ERR_EMPTY);

    /*
     * File-too-big boundary (ISA 8.4 item 12 "exceeded by exactly one").
     * With max_file_bytes = 8, a length of 8 passes the size gate (then
     * fails later as a non-header) and an explicit length of 9 is rejected
     * by the size gate itself.
     */
    memset(big, 'A', sizeof(big));
    limits = (voleith_shipshape_limits_t){0, 0, 8, 0};
    r = voleith_shipshape_parse_buffer(&p, big, 8, &limits);
    check("buffer: len == limit passes size gate",
          r != VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);
    r = voleith_shipshape_parse_buffer(&p, big, 9, &limits);
    check("buffer: len == limit+1 => FILE_TOO_BIG",
          r == VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);
}

/* ================================================================
 * Group B: File entry validation.
 * ================================================================ */

static void
test_file_entry(void)
{
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    char path[64];
    char data[16];
    int r;

    /* NULL out. */
    r = voleith_shipshape_parse_file(NULL, "/nonexistent", NULL);
    check("file: NULL out => NULL_ARG", r == VOLEITH_SHIPSHAPE_ERR_NULL_ARG);

    /* NULL path. */
    p.circuit = (voleith_gf8_circuit_t *)0x1;
    r = voleith_shipshape_parse_file(&p, NULL, NULL);
    check("file: NULL path => NULL_ARG", r == VOLEITH_SHIPSHAPE_ERR_NULL_ARG);
    check("file: NULL path zeroes out", p.circuit == NULL);

    /* Missing file => IO. */
    r = voleith_shipshape_parse_file(&p, "/nonexistent/shipshape/path", NULL);
    check("file: missing => IO", r == VOLEITH_SHIPSHAPE_ERR_IO);

    /* Empty file => EMPTY (zero-byte file buffers to len 0). */
    if (write_temp("", 0, path, sizeof(path)) == 0) {
        r = voleith_shipshape_parse_file(&p, path, NULL);
        check("file: empty => EMPTY", r == VOLEITH_SHIPSHAPE_ERR_EMPTY);
        remove(path);
    } else {
        check("file: empty temp-file setup", 0);
    }

    /* Oversized file: 16 bytes against a 4-byte limit => FILE_TOO_BIG. */
    memset(data, 'A', sizeof(data));
    if (write_temp(data, sizeof(data), path, sizeof(path)) == 0) {
        limits = (voleith_shipshape_limits_t){0, 0, 4, 0};
        r = voleith_shipshape_parse_file(&p, path, &limits);
        check("file: oversized => FILE_TOO_BIG",
              r == VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);

        /* Same file under the ceiling clears the size gate. */
        r = voleith_shipshape_parse_file(&p, path, NULL);
        check("file: within limit clears size gate",
              r != VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG);
        remove(path);
    } else {
        check("file: oversized temp-file setup", 0);
    }

    /* A valid-header file parses to an empty circuit through the file path. */
    if (write_temp(VALID_HEADER, sizeof(VALID_HEADER) - 1, path,
                   sizeof(path)) == 0) {
        r = voleith_shipshape_parse_file(&p, path, NULL);
        check("file: valid header parses", r == 0 && p.circuit != NULL);
        voleith_shipshape_parsed_free(&p);
        remove(path);
    } else {
        check("file: valid-header temp-file setup", 0);
    }
}

/* ================================================================
 * Group C: Out-struct zeroing and free safety.
 * ================================================================ */

static void
test_zeroing_and_free(void)
{
    /* A header + a malformed declaration; the failure must zero *out. */
    static const char bad_decl[] = ".shipshape 1\n"
                                   "field GF(2^8) irreducible 0x11B\n"
                                   "stdlib crypto-v1\n"
                                   "WITNESS\n"; /* missing -> %w : type */
    voleith_shipshape_parsed_t p;
    int r;

    p.circuit = (voleith_gf8_circuit_t *)0x1;
    p.decls = (voleith_shipshape_decl_t *)0x1;
    p.n_decls = 99;
    r = voleith_shipshape_parse_buffer(&p, bad_decl, sizeof(bad_decl) - 1,
                                       NULL);
    check("zeroing: decl failure => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);
    check("zeroing: decl failure zeroes out",
          p.circuit == NULL && p.decls == NULL && p.n_decls == 0);

    /* parsed_free is safe on a zero-initialised struct and on NULL. */
    {
        voleith_shipshape_parsed_t z = {0};
        voleith_shipshape_parsed_free(&z);
        check("free: zero struct safe", z.circuit == NULL);
    }
    voleith_shipshape_parsed_free(NULL);
    check("free: NULL safe", 1);
}

/* ================================================================
 * Group D: Resource-limit clamping.
 * ================================================================ */

static void
test_limit_clamping(void)
{
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    int r;

    /* NULL limits selects all ceilings: a small input clears the file gate. */
    r = voleith_shipshape_parse_buffer(&p, VALID_HEADER,
                                       sizeof(VALID_HEADER) - 1, NULL);
    check("clamp: NULL limits uses ceiling", r == 0);
    voleith_shipshape_parsed_free(&p);

    /* All-zero fields are equivalent to NULL limits (each field => ceiling). */
    limits = (voleith_shipshape_limits_t){0, 0, 0, 0};
    r = voleith_shipshape_parse_buffer(&p, VALID_HEADER,
                                       sizeof(VALID_HEADER) - 1, &limits);
    check("clamp: zero fields use ceiling", r == 0);
    voleith_shipshape_parsed_free(&p);

    /*
     * A caller file limit above the hard ceiling is clamped down, never up:
     * the ceiling still governs.  The header is well under both, so it
     * clears the gate either way; this exercises the clamp path without
     * allocating a 64-MiB buffer.
     */
    limits = (voleith_shipshape_limits_t){
        0, 0, VOLEITH_SHIPSHAPE_MAX_FILE_BYTES + 1000, 0};
    r = voleith_shipshape_parse_buffer(&p, VALID_HEADER,
                                       sizeof(VALID_HEADER) - 1, &limits);
    check("clamp: over-ceiling file limit clamped", r == 0);
    voleith_shipshape_parsed_free(&p);
}

/* ================================================================
 * Lexer test helpers.
 * ================================================================ */

/*
 * Tokenize a single one-line buffer `src` (no trailing newline expected).
 * Fills toks[0..max-1] with the token sequence and returns the token count.
 * *err receives the first negative error code, or 0 if the line lexed
 * cleanly to end.  Only the value fields of a token (kind, len, byte_val,
 * int_val) are stable after return; the `lex` pointer dangles once the
 * lexer is freed and is not inspected by these tests.
 */
static int
lex_line(const char *src, size_t line_cap, size_t ident_cap, ss_token_t *toks,
         int max, int *err)
{
    ss_lexer_t lx;
    ss_token_t t;
    int n = 0;
    int r;

    *err = 0;
    if (voleith_shipshape_lex_init(&lx, src, strlen(src), line_cap,
                                   ident_cap) != 0) {
        *err = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        return 0;
    }
    r = voleith_shipshape_lex_read_line(&lx);
    if (r != 0) {
        *err = (r < 0) ? r : 0;
        voleith_shipshape_lex_free(&lx);
        return 0;
    }
    for (;;) {
        r = voleith_shipshape_lex_next_token(&lx, &t);
        if (r < 0) {
            *err = r;
            break;
        }
        if (t.kind == SS_TOK_EOL)
            break;
        if (n < max)
            toks[n] = t;
        n++;
    }
    voleith_shipshape_lex_free(&lx);
    return n;
}

/* Tokenize `src` and return only the first error code (0 if clean). */
static int
lex_err(const char *src, size_t line_cap, size_t ident_cap)
{
    ss_token_t toks[32];
    int err;

    lex_line(src, line_cap, ident_cap, toks, 32, &err);
    return err;
}

/* ================================================================
 * Group E: Lexer token classes.
 * ================================================================ */

static void
test_lexer_token_classes(void)
{
    ss_token_t t[12];
    int err, n;

    /* ADD %a %b -> %c : WORD WIRE WIRE ARROW WIRE. */
    n = lex_line("ADD %a %b -> %c", 0, 0, t, 12, &err);
    check("lex: gate line count", n == 5 && err == 0);
    check("lex: gate kinds",
          n == 5 && t[0].kind == SS_TOK_WORD && t[1].kind == SS_TOK_WIRE &&
              t[2].kind == SS_TOK_WIRE && t[3].kind == SS_TOK_ARROW &&
              t[4].kind == SS_TOK_WIRE);
    check("lex: WORD len", n == 5 && t[0].len == 3); /* "ADD" */
    check("lex: WIRE len", n == 5 && t[1].len == 2); /* "%a" */

    /* Path call with ++ and comma:
     * PATH LPAREN WIRE PLUSPLUS WIRE RPAREN ARROW WIRE COMMA WIRE. */
    n = lex_line("stdlib/crypto/aes/x ( %k ++ %p ) -> %o , %x", 0, 0, t, 12,
                 &err);
    check("lex: call line count", n == 10 && err == 0);
    check("lex: PATH kind", n == 10 && t[0].kind == SS_TOK_PATH);
    check("lex: punctuation kinds",
          n == 10 && t[1].kind == SS_TOK_LPAREN &&
              t[3].kind == SS_TOK_PLUSPLUS && t[5].kind == SS_TOK_RPAREN &&
              t[6].kind == SS_TOK_ARROW && t[8].kind == SS_TOK_COMMA);

    /* A bare single-segment identifier is a WORD, not a PATH. */
    n = lex_line("aes", 0, 0, t, 12, &err);
    check("lex: single segment is WORD",
          n == 1 && t[0].kind == SS_TOK_WORD && err == 0);

    /* Matrix and byte literals: WORD LBRACKET BYTE BYTE RBRACKET WIRE. */
    n = lex_line("LINEAR_MAP [0x51 0xD0] %a", 0, 0, t, 12, &err);
    check("lex: matrix line count", n == 6 && err == 0);
    check("lex: bracket + byte kinds", n == 6 && t[1].kind == SS_TOK_LBRACKET &&
                                           t[2].kind == SS_TOK_BYTE_LIT &&
                                           t[3].kind == SS_TOK_BYTE_LIT &&
                                           t[4].kind == SS_TOK_RBRACKET);
    check("lex: byte values",
          n == 6 && t[2].byte_val == 0x51 && t[3].byte_val == 0xD0);
    check("lex: lowercase hex digits", lex_err("0xab", 0, 0) == 0);

    /* Integer literals incl. 0 and a vector index. */
    n = lex_line("FROBENIUS_K 3 %a", 0, 0, t, 12, &err);
    check("lex: int literal kind/value",
          n == 3 && t[1].kind == SS_TOK_INT_LIT && t[1].int_val == 3);
    n = lex_line("%state[0]", 0, 0, t, 12, &err);
    check("lex: index sequence",
          n == 4 && t[0].kind == SS_TOK_WIRE && t[1].kind == SS_TOK_LBRACKET &&
              t[2].kind == SS_TOK_INT_LIT && t[2].int_val == 0 &&
              t[3].kind == SS_TOK_RBRACKET);
    n = lex_line("255", 0, 0, t, 12, &err);
    check("lex: multi-digit int", n == 1 && t[0].int_val == 255);

    /* Declaration line: WORD ARROW WIRE COLON WORD. */
    n = lex_line("WITNESS -> %k : byte", 0, 0, t, 12, &err);
    check("lex: decl kinds",
          n == 5 && t[0].kind == SS_TOK_WORD && t[1].kind == SS_TOK_ARROW &&
              t[2].kind == SS_TOK_WIRE && t[3].kind == SS_TOK_COLON &&
              t[4].kind == SS_TOK_WORD);

    /* Braces. */
    n = lex_line("{ }", 0, 0, t, 12, &err);
    check("lex: braces",
          n == 2 && t[0].kind == SS_TOK_LBRACE && t[1].kind == SS_TOK_RBRACE);

    /* Comments and blank lines yield no tokens. */
    check("lex: comment line empty",
          lex_line("# a comment", 0, 0, t, 12, &err) == 0 && err == 0);
    check("lex: trailing comment ignored",
          lex_line("%a # tail", 0, 0, t, 12, &err) == 1 && err == 0);
    check("lex: blank line empty",
          lex_line("   \t  ", 0, 0, t, 12, &err) == 0 && err == 0);
}

/* ================================================================
 * Group F: Lexer bounds exceeded by exactly one.
 * ================================================================ */

static void
test_lexer_bounds(void)
{
    /* Identifier length (incl. sigil / separators), cap 4. */
    check("lex: wire at ident cap", lex_err("%abc", 0, 4) == 0);
    check("lex: wire over ident cap",
          lex_err("%abcd", 0, 4) == VOLEITH_SHIPSHAPE_ERR_IDENT);
    check("lex: path at ident cap", lex_err("a/b", 0, 3) == 0);
    check("lex: path over ident cap",
          lex_err("a/bc", 0, 3) == VOLEITH_SHIPSHAPE_ERR_IDENT);

    /* Malformed identifiers. */
    check("lex: bare sigil", lex_err("%", 0, 0) == VOLEITH_SHIPSHAPE_ERR_IDENT);
    check("lex: sigil then digit",
          lex_err("%1a", 0, 0) == VOLEITH_SHIPSHAPE_ERR_IDENT);
    check("lex: trailing path separator",
          lex_err("a/", 0, 0) == VOLEITH_SHIPSHAPE_ERR_IDENT);

    /* Byte literals. */
    check("lex: byte ok", lex_err("0x1f", 0, 0) == 0);
    check("lex: byte one digit",
          lex_err("0x1", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);
    check("lex: byte three digits",
          lex_err("0x123", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);
    check("lex: byte non-hex",
          lex_err("0xZZ", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);
    check("lex: uppercase X rejected",
          lex_err("0X12", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);

    /* Integer literals. */
    check("lex: zero ok", lex_err("0", 0, 0) == 0);
    check("lex: leading zero",
          lex_err("01", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);
    check("lex: digit-letter glue",
          lex_err("12a", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);
    check("lex: uint32 max ok", lex_err("4294967295", 0, 0) == 0);
    check("lex: uint32 overflow",
          lex_err("4294967296", 0, 0) == VOLEITH_SHIPSHAPE_ERR_LITERAL);

    /* Multi-character punctuation halves. */
    check("lex: arrow ok", lex_err("->", 0, 0) == 0);
    check("lex: lone dash", lex_err("-", 0, 0) == VOLEITH_SHIPSHAPE_ERR_TOKEN);
    check("lex: plusplus ok", lex_err("++", 0, 0) == 0);
    check("lex: lone plus", lex_err("+", 0, 0) == VOLEITH_SHIPSHAPE_ERR_TOKEN);

    /* Stray legal-charset byte that begins no token. */
    check("lex: stray dot", lex_err(".", 0, 0) == VOLEITH_SHIPSHAPE_ERR_TOKEN);
    check("lex: stray caret",
          lex_err("^", 0, 0) == VOLEITH_SHIPSHAPE_ERR_TOKEN);
}

/* ================================================================
 * Group G: Line layer (newlines, charset).
 * ================================================================ */

/* Count physical lines in `buf` via the lexer, or return the first error. */
static int
count_lines(const char *buf, size_t len, size_t line_cap, int *err)
{
    ss_lexer_t lx;
    int lines = 0;
    int r;

    *err = 0;
    if (voleith_shipshape_lex_init(&lx, buf, len, line_cap, 0) != 0) {
        *err = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        return 0;
    }
    for (;;) {
        r = voleith_shipshape_lex_read_line(&lx);
        if (r < 0) {
            *err = r;
            break;
        }
        if (r == 1)
            break;
        lines++;
    }
    voleith_shipshape_lex_free(&lx);
    return lines;
}

static void
test_line_layer(void)
{
    const char mixed[] = "a\nb\rc\r\nd"; /* LF, CR, CRLF, then EOF */
    const char illegal_mid[] = "a\x01"
                               "b";
    const char illegal_comment[] = "# ok\x07tail\n";
    int err, lines;

    /* Each of LF, CR, CRLF terminates exactly one line; no trailing NL. */
    lines = count_lines(mixed, sizeof(mixed) - 1, 0, &err);
    check("line: mixed newlines count 4", lines == 4 && err == 0);

    /* CRLF is one newline, not two empty-separated lines. */
    {
        const char crlf[] = "x\r\ny\r\n";
        lines = count_lines(crlf, sizeof(crlf) - 1, 0, &err);
        check("line: CRLF pair counts once", lines == 2 && err == 0);
    }

    /* Illegal byte in content and inside a comment are both rejected. */
    check("line: illegal byte in content",
          count_lines(illegal_mid, sizeof(illegal_mid) - 1, 0, &err) >= 0 &&
              err == VOLEITH_SHIPSHAPE_ERR_CHARSET);
    err = 0;
    count_lines(illegal_comment, sizeof(illegal_comment) - 1, 0, &err);
    check("line: illegal byte in comment",
          err == VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* Line length: terminator bytes do not count toward the content limit. */
    err = 0;
    count_lines("        ", 8, 8, &err); /* len 8, cap 8 */
    check("line: content at cap ok", err == 0);
    err = 0;
    count_lines("         ", 9, 8, &err); /* len 9, cap 8 */
    check("line: content over cap", err == VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG);
    err = 0;
    count_lines("aaaaaaaa\r\n", 10, 8, &err); /* 8 content + CRLF, cap 8 */
    check("line: CRLF not counted in length", err == 0);
}

/* ================================================================
 * Group H: Line layer through the public entry point.
 * ================================================================ */

static void
test_line_layer_public(void)
{
    const char clean[] = ".shipshape 1\n"
                         "field GF(2^8) irreducible 0x11B\n"
                         "stdlib crypto-v1\n";
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    int r;

    /* A lexically clean (headered) file clears the line layer and parses. */
    r = voleith_shipshape_parse_buffer(&p, clean, sizeof(clean) - 1, NULL);
    check("public: clean file parses", r == 0);
    voleith_shipshape_parsed_free(&p);

    /* An illegal byte anywhere fails with CHARSET. */
    r = voleith_shipshape_parse_buffer(&p, "abc\x01z", 5, NULL);
    check("public: illegal byte => CHARSET",
          r == VOLEITH_SHIPSHAPE_ERR_CHARSET);

    /* A line over the caller's MAX_LINE_BYTES fails with LINE_TOO_LONG. */
    limits = (voleith_shipshape_limits_t){0, 0, 0, 8};
    r = voleith_shipshape_parse_buffer(&p, "123456789\n", 0, &limits);
    check("public: over-long line => LINE_TOO_LONG",
          r == VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG);

    /*
     * A line exactly at the caller's limit is read (not LINE_TOO_LONG); it
     * then fails header matching, proving the length gate let it through.
     */
    r = voleith_shipshape_parse_buffer(&p, "12345678\n", 0, &limits);
    check("public: line at limit read, not too long",
          r != VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG);
}

/* ================================================================
 * Group I: Header (three mandatory lines, exact tokens, order).
 * ================================================================ */

static void
test_header(void)
{
    /* Canonical valid header parses to an empty-but-valid circuit. */
    check("hdr: valid header", parse_str(VALID_HEADER) == 0);

    /* Comments and blank lines before and between header lines accepted. */
    check("hdr: comments and blanks between lines",
          parse_str("# leading comment\n"
                    "\n"
                    ".shipshape 1\n"
                    "   # between version and field\n"
                    "\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == 0);

    /* A trailing comment on a header line is accepted. */
    check("hdr: trailing comments",
          parse_str(".shipshape 1 # version\n"
                    "field GF(2^8) irreducible 0x11B # field\n"
                    "stdlib crypto-v1 # std\n") == 0);

    /* Surrounding and inter-token whitespace (spaces and tabs) accepted. */
    check("hdr: extra whitespace",
          parse_str("   .shipshape\t1   \n"
                    "field\tGF(2^8)  irreducible   0x11B\n"
                    "  stdlib crypto-v1\t\n") == 0);

    /* Wrong version line. */
    check("hdr: magic missing dot",
          parse_str("shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: magic wrong spelling",
          parse_str(".ship 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: magic wrong case",
          parse_str(".Shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: wrong version number",
          parse_str(".shipshape 2\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Wrong field line. */
    check("hdr: wrong field",
          parse_str(".shipshape 1\n"
                    "field GF(2^16) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: wrong irreducible keyword",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irred 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: wrong polynomial",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x87\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: polynomial wrong case",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11b\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Wrong stdlib line (crypto-v3 is not a defined version; crypto-v1 and
     * crypto-v2 are the only accepted spellings). */
    check("hdr: wrong stdlib version",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v3\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Extra token on a header line. */
    check("hdr: extra token on version",
          parse_str(".shipshape 1 extra\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: extra token on stdlib",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1 extra\n") ==
              VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Too few tokens on a header line. */
    check("hdr: missing version value",
          parse_str(".shipshape\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: truncated field line",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* A missing header line entirely. */
    check("hdr: missing stdlib line",
          parse_str(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n") ==
              VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: comments only => missing header",
          parse_str("# just a comment\n\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Reordered header. */
    check("hdr: field before version",
          parse_str("field GF(2^8) irreducible 0x11B\n"
                    ".shipshape 1\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Duplicated header line. */
    check("hdr: duplicate version line",
          parse_str(".shipshape 1\n"
                    ".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Format semver (SHIPSHAPE_FORMAT_VERSIONING.md): bare MAJOR == MAJOR.0,
     * so `.shipshape 1.0` is the same as `.shipshape 1`. */
    check("hdr: format 1.0 == 1", parse_str(".shipshape 1.0\n"
                                            "field GF(2^8) irreducible 0x11B\n"
                                            "stdlib crypto-v1\n") == 0);
    /* Minor up to the parser's max (1) is accepted. */
    check("hdr: format 1.1 accepted",
          parse_str(".shipshape 1.1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == 0);
    /* A minor newer than the parser is ERR_HEADER. */
    check("hdr: format 1.2 too new",
          parse_str(".shipshape 1.2\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    /* An unsupported major is ERR_HEADER (even at minor 0). */
    check("hdr: format 2.0 unsupported major",
          parse_str(".shipshape 2.0\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    /* A leading zero in a version component is malformed. */
    check("hdr: format 1.01 leading zero",
          parse_str(".shipshape 1.01\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    check("hdr: format 01.0 leading zero major",
          parse_str(".shipshape 01.0\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    /* An empty minor after the dot is malformed. */
    check("hdr: format 1. empty minor",
          parse_str(".shipshape 1.\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
    /* A non-numeric version is malformed. */
    check("hdr: format 1.x non-numeric",
          parse_str(".shipshape 1.x\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v1\n") == VOLEITH_SHIPSHAPE_ERR_HEADER);
}

/* ================================================================
 * Group H2: SCALE_INSTANCE, the first minor-1 opcode (1.10.0 / EP.SHIP).
 * ================================================================ */

static void
test_scale_instance(void)
{
    /* Body: c = a * pub, pub an INSTANCE (public) wire, a a WITNESS byte. */
    static const char body[] = "field GF(2^8) irreducible 0x11B\n"
                               "stdlib crypto-v1\n"
                               "WITNESS -> %a : byte\n"
                               "INSTANCE -> %pub : byte\n"
                               "SCALE_INSTANCE %a %pub -> %c\n";

    /* Full 1.1 program with the opcode lowers cleanly. */
    {
        char buf[512];
        snprintf(buf, sizeof(buf), ".shipshape 1.1\n%s", body);
        check("scale_instance: 1.1 program parses", parse_str(buf) == 0);
    }

    /* The same program under 1.0 (or bare 1) is ERR_OPCODE_VERSION: the
     * opcode's introduced-minor (1) exceeds the declared minor (0). */
    {
        char buf[512];
        snprintf(buf, sizeof(buf), ".shipshape 1.0\n%s", body);
        check("scale_instance: rejected at 1.0",
              parse_str(buf) == VOLEITH_SHIPSHAPE_ERR_OPCODE_VERSION);
        snprintf(buf, sizeof(buf), ".shipshape 1\n%s", body);
        check("scale_instance: rejected at bare 1",
              parse_str(buf) == VOLEITH_SHIPSHAPE_ERR_OPCODE_VERSION);
    }

    /* The multiplier %b must be an INSTANCE wire; a WITNESS multiplier is a
     * type error (a secret multiplier would need a VOLE slot). */
    {
        char buf[512];
        snprintf(buf, sizeof(buf),
                 ".shipshape 1.1\n"
                 "field GF(2^8) irreducible 0x11B\n"
                 "stdlib crypto-v1\n"
                 "WITNESS -> %%a : byte\n"
                 "WITNESS -> %%b : byte\n"
                 "SCALE_INSTANCE %%a %%b -> %%c\n");
        check("scale_instance: witness multiplier => TYPE",
              parse_str(buf) == VOLEITH_SHIPSHAPE_ERR_TYPE);
    }
}

/* ================================================================
 * Group J: Declarations, the wire table, and types (W3.4).
 * ================================================================ */

/* Header prefix shared by the declaration sources below. */
#define HDR                                                                    \
    ".shipshape 1\n"                                                           \
    "field GF(2^8) irreducible 0x11B\n"                                        \
    "stdlib crypto-v1\n"

/* Parse `src` with default limits into *p; returns the code. */
static int
parse_decls(const char *src, voleith_shipshape_parsed_t *p)
{
    return voleith_shipshape_parse_buffer(p, src, 0, NULL);
}

/* True iff decl `d` matches the expected name / kind / type / shape. */
static int
decl_is(const voleith_shipshape_decl_t *d, const char *name,
        voleith_shipshape_decl_kind_t kind, int is_bit, int is_vector,
        size_t length)
{
    return strcmp(d->name, name) == 0 && d->kind == kind &&
           d->is_bit == is_bit && d->is_vector == is_vector &&
           d->length == length;
}

static void
test_declarations(void)
{
    voleith_shipshape_parsed_t p;
    int r;

    /* Scalar inputs and a constant build wires and a decl table. */
    r = parse_decls(HDR "WITNESS -> %k : byte\n"
                        "INSTANCE -> %root : byte\n"
                        "CONST 0x63 -> %c\n",
                    &p);
    check("decl: scalar trio parses", r == 0 && p.circuit != NULL);
    check("decl: scalar counts",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 1 &&
              voleith_gf8_circuit_instance_count(p.circuit) == 1 &&
              p.n_decls == 3);
    check("decl: scalar table",
          r == 0 && p.n_decls == 3 &&
              decl_is(&p.decls[0], "k", VOLEITH_SHIPSHAPE_DECL_WITNESS, 0, 0,
                      1) &&
              decl_is(&p.decls[1], "root", VOLEITH_SHIPSHAPE_DECL_INSTANCE, 0,
                      0, 1) &&
              decl_is(&p.decls[2], "c", VOLEITH_SHIPSHAPE_DECL_CONST, 0, 0, 1));
    voleith_shipshape_parsed_free(&p);

    /* Vector witness creates N consecutive wires. */
    r = parse_decls(HDR "WITNESS -> %st : byte[16]\n", &p);
    check("decl: vector parses",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 16);
    check("decl: vector table",
          r == 0 && p.n_decls == 1 &&
              decl_is(&p.decls[0], "st", VOLEITH_SHIPSHAPE_DECL_WITNESS, 0, 1,
                      16) &&
              p.decls[0].first_wire == 0);
    voleith_shipshape_parsed_free(&p);

    /* A zero-length vector is legal: a name with no wires (FORMAT 3.2). */
    r = parse_decls(HDR "WITNESS -> %empty : byte[0]\n", &p);
    check("decl: byte[0] legal",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 0 &&
              p.n_decls == 1 && p.decls[0].length == 0 &&
              p.decls[0].is_vector == 1);
    voleith_shipshape_parsed_free(&p);

    /* A bit witness emits one booleanity ASSERT_PRODUCT (ISA 2.3). */
    r = parse_decls(HDR "WITNESS -> %d : bit\n", &p);
    check("decl: bit witness booleanity",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 1 &&
              voleith_gf8_circuit_assert_product_count(p.circuit) == 1 &&
              p.decls[0].is_bit == 1);
    voleith_shipshape_parsed_free(&p);

    /* A bit vector emits one booleanity constraint per element. */
    r = parse_decls(HDR "WITNESS -> %dirs : bit[4]\n", &p);
    check("decl: bit vector booleanity",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 4 &&
              voleith_gf8_circuit_assert_product_count(p.circuit) == 4);
    voleith_shipshape_parsed_free(&p);

    /* CONST_BIT lowers to a const wire flagged as a bit. */
    r = parse_decls(HDR "CONST_BIT 1 -> %one\n", &p);
    check("decl: const_bit",
          r == 0 && p.n_decls == 1 &&
              decl_is(&p.decls[0], "one", VOLEITH_SHIPSHAPE_DECL_CONST, 1, 0,
                      1) &&
              voleith_gf8_circuit_witness_count(p.circuit) == 0 &&
              voleith_gf8_circuit_instance_count(p.circuit) == 0);
    voleith_shipshape_parsed_free(&p);

    /* SSA (S1): a repeated name, same kind or across kinds, is a redefinition. */
    r = parse_decls(HDR "WITNESS -> %k : byte\n"
                        "WITNESS -> %k : byte\n",
                    &p);
    check("decl: redef same kind => REDEF",
          r == VOLEITH_SHIPSHAPE_ERR_REDEF && p.circuit == NULL);
    r = parse_decls(HDR "WITNESS -> %x : byte\n"
                        "CONST 0x01 -> %x\n",
                    &p);
    check("decl: redef across kinds => REDEF",
          r == VOLEITH_SHIPSHAPE_ERR_REDEF);

    /* Type rules (S5 / ISA 2.3). */
    r = parse_decls(HDR "INSTANCE -> %b : bit\n", &p);
    check("decl: instance bit => TYPE", r == VOLEITH_SHIPSHAPE_ERR_TYPE);
    r = parse_decls(HDR "WITNESS -> %k : word\n", &p);
    check("decl: non-type annotation => TYPE", r == VOLEITH_SHIPSHAPE_ERR_TYPE);
    r = parse_decls(HDR "WITNESS -> %k\n", &p);
    check("decl: missing type => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);
    r = parse_decls(HDR "CONST 0x01 -> %c : byte\n", &p);
    check("decl: type on const => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);

    /* Malformed declarations. */
    r = parse_decls(HDR "WITNESS %k : byte\n", &p); /* missing arrow */
    check("decl: missing arrow => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);
    r = parse_decls(HDR "CONST 0x01 %c\n", &p); /* missing arrow */
    check("decl: const missing arrow => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);
    r = parse_decls(HDR "CONST_BIT 2 -> %b\n", &p); /* value out of {0,1} */
    check("decl: const_bit 2 => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);
    r = parse_decls(HDR "WITNESS -> %k : byte extra\n",
                    &p); /* trailing token */
    check("decl: trailing token => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);

    /*
     * Witness / instance array ordering (ISA 2.11): wires are created in
     * file order, so the first_wire ids increase with declaration order and
     * the per-array counts match the declared element totals.
     */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "INSTANCE -> %x : byte\n"
                        "WITNESS -> %b : byte[3]\n"
                        "CONST 0x05 -> %c\n",
                    &p);
    check("decl: 2.11 counts",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 4 &&
              voleith_gf8_circuit_instance_count(p.circuit) == 1 &&
              p.n_decls == 4);
    check("decl: 2.11 file-order first_wire",
          r == 0 && p.decls[0].first_wire == 0 && /* %a */
              p.decls[1].first_wire == 1 &&       /* %x */
              p.decls[2].first_wire == 2 &&       /* %b[0] */
              p.decls[3].first_wire == 5);        /* %c */
    voleith_shipshape_parsed_free(&p);

    /* A stdlib/crypto call (Tier 2a, W3.7) resolves its name in the
     * registry, then its operands like any call: %k is undefined here. */
    r = parse_decls(HDR "stdlib/crypto/aes/encrypt_128 ( %k ) -> %o\n", &p);
    check("decl: stdlib/crypto call resolves operands => UNDEF",
          r == VOLEITH_SHIPSHAPE_ERR_UNDEF);

    /* A declaration after a comment / blank line still parses. */
    r = parse_decls(HDR "# a comment\n"
                        "\n"
                        "WITNESS -> %k : byte\n",
                    &p);
    check("decl: blank/comment lines skipped",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 1);
    voleith_shipshape_parsed_free(&p);
}

/* ================================================================
 * Group K: Gates, assertions, sugar, canonicalization (W3.5).
 * ================================================================ */

/* True iff the two circuits have the same canonical fingerprint (ISA 5). */
static int
fp_eq(const voleith_gf8_circuit_t *a, const voleith_gf8_circuit_t *b)
{
    uint8_t fa[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];
    uint8_t fb[VOLEITH_GF8_CIRCUIT_FINGERPRINT_BYTES];

    if (a == NULL || b == NULL)
        return 0;
    if (voleith_gf8_circuit_fingerprint(a, fa) != 0 ||
        voleith_gf8_circuit_fingerprint(b, fb) != 0)
        return 0;
    return memcmp(fa, fb, sizeof(fa)) == 0;
}

/*
 * Parse `src` (a HDR-prefixed body) and compare the resulting circuit's
 * fingerprint to `ref` built by the hand-written gf8 builders.  Records one
 * check named `name`.  Frees both the parsed result and `ref`.
 */
static void
check_lowers_to(const char *name, const char *src, voleith_gf8_circuit_t *ref)
{
    voleith_shipshape_parsed_t p;
    int r;

    r = parse_decls(src, &p);
    check(name, r == 0 && fp_eq(p.circuit, ref));
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(ref);
}

static void
test_gates(void)
{
    voleith_shipshape_parsed_t p;
    voleith_gf8_circuit_t *c;
    gf8_wire_id a, b, cc;
    int r;

    /* A mixed gate / assertion circuit matches its hand-built equivalent. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    b = voleith_gf8_add_witness(c);
    voleith_gf8_add_xor(c, a, b);          /* %s */
    voleith_gf8_add_mul(c, a, b);          /* %p */
    voleith_gf8_add_xor(c, a, b);          /* %s2 */
    voleith_gf8_add_xor_const(c, a, 0x1b); /* %t */
    voleith_gf8_add_square(c, b);          /* %q */
    check_lowers_to("gate: mixed circuit fingerprint",
                    HDR "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "ADD %a %b -> %s\n"
                        "MUL %a %b -> %p\n"
                        "ADD %a %b -> %s2\n"
                        "ADD_CONST %a 0x1b -> %t\n"
                        "SQUARE %b -> %q\n",
                    c);

    /* SUM expands to n-1 chained ADD. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    b = voleith_gf8_add_witness(c);
    cc = voleith_gf8_add_witness(c);
    {
        gf8_wire_id acc = voleith_gf8_add_xor(c, a, b);
        voleith_gf8_add_xor(c, acc, cc);
    }
    check_lowers_to("gate: SUM expands to chained ADD",
                    HDR "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "WITNESS -> %c : byte\n"
                        "SUM %a %b %c -> %d\n",
                    c);

    /* FROBENIUS_K k expands to k chained SQUARE. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    {
        gf8_wire_id x = voleith_gf8_add_square(c, a);
        x = voleith_gf8_add_square(c, x);
        voleith_gf8_add_square(c, x);
    }
    check_lowers_to("gate: FROBENIUS_K 3 expands to 3 SQUARE",
                    HDR "WITNESS -> %a : byte\n"
                        "FROBENIUS_K 3 %a -> %c\n",
                    c);

    /* LINEAR_MAP with the squaring matrix canonicalizes to SQUARE. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    check_lowers_to("gate: LINEAR_MAP squaring matrix => SQUARE",
                    HDR "WITNESS -> %a : byte\n"
                        "LINEAR_MAP [0x51 0xD0 0x22 0xF0 0x94 0x60 0x28 0xC0] "
                        "%a -> %c\n",
                    c);

    /* A LINEAR_MAP with a non-squaring matrix is NOT a SQUARE. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "LINEAR_MAP [0x01 0x02 0x04 0x08 0x10 0x20 0x40 0x80] "
                        "%a -> %c\n",
                    &p);
    check("gate: identity LINEAR_MAP differs from SQUARE",
          r == 0 && !fp_eq(p.circuit, c));
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(c);

    /* INV lowers to the canonical witness + 2 assert_product gadget. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c); /* %a */
    {
        gf8_wire_id ci = voleith_gf8_add_witness(c); /* INV output */
        gf8_wire_id a2 = voleith_gf8_add_square(c, a);
        voleith_gf8_assert_product(c, a2, ci, a);
        gf8_wire_id c2 = voleith_gf8_add_square(c, ci);
        voleith_gf8_assert_product(c, a, c2, ci);
    }
    check_lowers_to("gate: INV canonical gadget fingerprint",
                    HDR "WITNESS -> %a : byte\n"
                        "INV %a -> %ai\n",
                    c);

    /*
     * A hand-written PARTIAL inverse pattern parses as what it is: a
     * different circuit with a different fingerprint than the atomic INV.
     */
    {
        voleith_shipshape_parsed_t pi, pp;
        int ri, rp;

        ri = parse_decls(HDR "WITNESS -> %a : byte\n"
                             "INV %a -> %ai\n",
                         &pi);
        rp = parse_decls(HDR "WITNESS -> %a : byte\n"
                             "WITNESS -> %ai : byte\n"
                             "SQUARE %a -> %a2\n"
                             "ASSERT_PRODUCT %a2 %ai %a\n",
                         &pp);
        check("gate: partial INV != atomic INV",
              ri == 0 && rp == 0 && !fp_eq(pi.circuit, pp.circuit));
        voleith_shipshape_parsed_free(&pi);
        voleith_shipshape_parsed_free(&pp);
    }

    /* ASSERT_CONST a k is sugar for ASSERT_ZERO(ADD_CONST(a, k)). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    {
        gf8_wire_id t = voleith_gf8_add_xor_const(c, a, 0x63);
        voleith_gf8_assert_zero(c, t);
    }
    check_lowers_to("gate: ASSERT_CONST sugar",
                    HDR "WITNESS -> %a : byte\n"
                        "ASSERT_CONST %a 0x63\n",
                    c);
}

static void
test_gate_types_and_errors(void)
{
    voleith_shipshape_parsed_t p;
    int r;

    /* MUX requires a bit selector: a byte selector is a type error (2.2). */
    r = parse_decls(HDR "WITNESS -> %sel : byte\n"
                        "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "MUX %sel %a %b -> %c\n",
                    &p);
    check("gate: MUX over byte selector => TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* A bit witness selector is accepted. */
    r = parse_decls(HDR "WITNESS -> %sel : bit\n"
                        "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "MUX %sel %a %b -> %c\n",
                    &p);
    check("gate: MUX over bit selector ok", r == 0);
    voleith_shipshape_parsed_free(&p);

    /* ASSERT_BIT narrows a new name; MUX over it is then legal. */
    r = parse_decls(HDR "WITNESS -> %s : byte\n"
                        "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "ASSERT_BIT %s -> %sb : bit\n"
                        "MUX %sb %a %b -> %c\n",
                    &p);
    check("gate: ASSERT_BIT enables MUX on the refined name", r == 0);
    voleith_shipshape_parsed_free(&p);

    /* The refinement is flow-sensitive: the original byte name stays byte. */
    r = parse_decls(HDR "WITNESS -> %s : byte\n"
                        "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "ASSERT_BIT %s -> %sb : bit\n"
                        "MUX %s %a %b -> %c\n",
                    &p);
    check("gate: later ASSERT_BIT does not legalize MUX on %s",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* Define-before-use (S2): an operand naming an undefined wire => UNDEF. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "ADD %a %nope -> %c\n",
                    &p);
    check("gate: undefined operand => UNDEF", r == VOLEITH_SHIPSHAPE_ERR_UNDEF);

    /* Scalarity (S5): an unindexed vector in an operand position => TYPE. */
    r = parse_decls(HDR "WITNESS -> %v : byte[4]\n"
                        "WITNESS -> %a : byte\n"
                        "ADD %v %a -> %c\n",
                    &p);
    check("gate: bare vector operand => TYPE", r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* An indexed vector element is a valid scalar operand. */
    r = parse_decls(HDR "WITNESS -> %v : byte[4]\n"
                        "WITNESS -> %a : byte\n"
                        "ADD %v[2] %a -> %c\n",
                    &p);
    check("gate: indexed vector element ok", r == 0);
    voleith_shipshape_parsed_free(&p);

    /* An out-of-range index => TYPE (S6). */
    r = parse_decls(HDR "WITNESS -> %v : byte[4]\n"
                        "WITNESS -> %a : byte\n"
                        "ADD %v[4] %a -> %c\n",
                    &p);
    check("gate: index out of range => TYPE", r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* Indexing a scalar => TYPE. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "SQUARE %a[0] -> %c\n",
                    &p);
    check("gate: index on a scalar => TYPE", r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* A gate output reusing a defined name => REDEF (S1). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "SQUARE %a -> %a\n",
                    &p);
    check("gate: output redefines name => REDEF",
          r == VOLEITH_SHIPSHAPE_ERR_REDEF);

    /* An unknown opcode => GATE. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "FOO %a -> %c\n",
                    &p);
    check("gate: unknown opcode => GATE", r == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* FROBENIUS_K with k = 0 => GATE (S9). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "FROBENIUS_K 0 %a -> %c\n",
                    &p);
    check("gate: FROBENIUS_K 0 => GATE", r == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* SUM with a single operand => GATE (grammar requires >= 2). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "SUM %a -> %c\n",
                    &p);
    check("gate: SUM with one operand => GATE",
          r == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* A LINEAR_MAP matrix with the wrong byte count => GATE. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "LINEAR_MAP [0x01 0x02] %a -> %c\n",
                    &p);
    check("gate: short LINEAR_MAP matrix => GATE",
          r == VOLEITH_SHIPSHAPE_ERR_GATE);

    /* A trailing operand on a fixed-arity gate => GATE. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "WITNESS -> %b : byte\n"
                        "SQUARE %a %b -> %c\n",
                    &p);
    check("gate: extra operand => GATE", r == VOLEITH_SHIPSHAPE_ERR_GATE);
}

/* ================================================================
 * Group L: Subcircuits, inlining, regions (W3.6).
 * ================================================================ */

static void
test_subcircuits(void)
{
    voleith_shipshape_parsed_t p;
    voleith_gf8_circuit_t *c;
    gf8_wire_id a, b;
    int r;

    /* A user/* call inlines its body: the circuit equals the hand-built one. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    b = voleith_gf8_add_witness(c);
    voleith_gf8_add_mul(c, a, b);
    check_lowers_to(
        "subckt: basic call inlines to body",
        HDR "subcircuit user/mac (%x : byte, %y : byte) -> (%z : byte) {\n"
            "MUL %x %y -> %z\n"
            "}\n"
            "WITNESS -> %a : byte\n"
            "WITNESS -> %b : byte\n"
            "user/mac(%a, %b) -> %c\n",
        c);

    /* A `++` argument binds a vector parameter to non-contiguous wires;
     * indexing inside the body reaches the right ones. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c); /* %x = wire 0 */
    voleith_gf8_add_witness(c);     /* %mid = wire 1 (gap) */
    b = voleith_gf8_add_witness(c); /* %y = wire 2 */
    voleith_gf8_add_mul(c, a, b);   /* MUL %v[0] %v[1] = MUL w0 w2 */
    check_lowers_to("subckt: ++ arg + vector param indexing",
                    HDR "subcircuit user/dot (%v : byte[2]) -> (%s : byte) {\n"
                        "MUL %v[0] %v[1] -> %s\n"
                        "}\n"
                        "WITNESS -> %x : byte\n"
                        "WITNESS -> %mid : byte\n"
                        "WITNESS -> %y : byte\n"
                        "user/dot(%x ++ %y) -> %p\n",
                    c);

    /* A zero-output (assertion-only) subcircuit: call omits the -> clause. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_assert_zero(c, a);
    check_lowers_to("subckt: zero-output assertion body",
                    HDR "subcircuit user/check (%x : byte) {\n"
                        "ASSERT_ZERO %x\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/check(%a)\n",
                    c);

    /* A zero-parameter subcircuit writes (). */
    c = voleith_gf8_circuit_new();
    voleith_gf8_add_const(c, 0x63);
    check_lowers_to("subckt: zero-parameter body",
                    HDR "subcircuit user/k () -> (%c : byte) {\n"
                        "CONST 0x63 -> %c\n"
                        "}\n"
                        "user/k() -> %z\n",
                    c);

    /* Witness placement (ISA 2.11): a body WITNESS lands at the call site,
     * after the top-level witness; a region marker records the call. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "WITNESS -> %w : byte\n"
                        "MUL %x %w -> %y\n"
                        "}\n"
                        "user/f(%a) -> %b\n",
                    &p);
    check("subckt: body witness lands at call site",
          r == 0 && voleith_gf8_circuit_witness_count(p.circuit) == 2);
    check("subckt: one region per call",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name, "user/f") == 0 &&
              p.regions[0].first_witness == 1 && p.regions[0].n_witness == 1);
    voleith_shipshape_parsed_free(&p);

    /* Nested calls: a region per call, outer recorded before inner. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    voleith_gf8_add_square(c, a);
    r = parse_decls(HDR "subcircuit user/inner (%x : byte) -> (%y : byte) {\n"
                        "SQUARE %x -> %y\n"
                        "}\n"
                        "subcircuit user/outer (%x : byte) -> (%y : byte) {\n"
                        "user/inner(%x) -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/outer(%a) -> %b\n",
                    &p);
    check("subckt: nested call fingerprint", r == 0 && fp_eq(p.circuit, c));
    check("subckt: nested regions in inlining order",
          r == 0 && p.n_regions == 2 &&
              strcmp(p.regions[0].name, "user/outer") == 0 &&
              strcmp(p.regions[1].name, "user/inner") == 0);
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(c);
}

static void
test_subcircuit_errors(void)
{
    voleith_shipshape_parsed_t p;
    int r;

    /* A stdlib/* definition is rejected (definitions are user/*, S4). */
    r = parse_decls(HDR "subcircuit stdlib/crypto/aes/sbox (%x : byte) {\n"
                        "ASSERT_ZERO %x\n"
                        "}\n",
                    &p);
    check("subckt: stdlib def => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* A stdlib/structural call is rejected (empty v1 set, S4). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "stdlib/structural/foo(%a)\n",
                    &p);
    check("subckt: structural call => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* A call to an undefined user subcircuit is rejected. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "user/nope(%a) -> %b\n",
                    &p);
    check("subckt: undefined user call => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* Forward reference: a call before the definition is rejected (S2). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "user/f(%a) -> %b\n"
                        "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "SQUARE %x -> %y\n"
                        "}\n",
                    &p);
    check("subckt: forward reference => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* A duplicate definition is a redefinition (S1). */
    r = parse_decls(HDR "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "SQUARE %x -> %y\n"
                        "}\n"
                        "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "SQUARE %x -> %y\n"
                        "}\n",
                    &p);
    check("subckt: duplicate def => REDEF", r == VOLEITH_SHIPSHAPE_ERR_REDEF);

    /* An argument whose length differs from the parameter's is a type error. */
    r = parse_decls(HDR "subcircuit user/f (%v : byte[2]) -> (%y : byte) {\n"
                        "MUL %v[0] %v[1] -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/f(%a) -> %b\n",
                    &p);
    check("subckt: arg length mismatch => TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* Calling a one-output subcircuit with no output clause mismatches (S7). */
    r = parse_decls(HDR "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "SQUARE %x -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/f(%a)\n",
                    &p);
    check("subckt: missing output clause => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* INSTANCE in a body is rejected (S3). */
    r = parse_decls(HDR "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "INSTANCE -> %pub : byte\n"
                        "ADD %x %pub -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/f(%a) -> %b\n",
                    &p);
    check("subckt: INSTANCE in body => DECL", r == VOLEITH_SHIPSHAPE_ERR_DECL);

    /* A body sees only its parameters: a top-level wire is invisible (UNDEF). */
    r = parse_decls(HDR "WITNESS -> %top : byte\n"
                        "subcircuit user/f (%x : byte) -> (%y : byte) {\n"
                        "ADD %x %top -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/f(%a) -> %b\n",
                    &p);
    check("subckt: body cannot see top-level wires => UNDEF",
          r == VOLEITH_SHIPSHAPE_ERR_UNDEF);
}

static void
test_subcircuit_bombs(void)
{
    static char buf[32768];
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    size_t off;
    int r, i;

    /* Inline-depth bomb: a chain deeper than MAX_INLINE_DEPTH aborts.  Each
     * def is multi-line (the `{` ends its header line, FORMAT 3.6). */
    off = 0;
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%s", VALID_HEADER);
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
                            "WITNESS -> %%a : byte\nuser/d70(%%a) -> %%b\n");
    r = voleith_shipshape_parse_buffer(&p, buf, 0, NULL);
    check("subckt: inline-depth bomb => INLINE_DEPTH",
          r == VOLEITH_SHIPSHAPE_ERR_INLINE_DEPTH);

    /*
     * Amplification bomb: each level doubles the wire count; with a small
     * MAX_WIRES the parser aborts at the budget before the allocation grows.
     */
    off = 0;
    off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%s", VALID_HEADER);
    off +=
        (size_t)snprintf(buf + off, sizeof(buf) - off,
                         "subcircuit user/d0 (%%x : byte) -> (%%y : byte) {\n"
                         "ADD %%x %%x -> %%y\n}\n");
    for (i = 1; i <= 25; i++)
        off += (size_t)snprintf(
            buf + off, sizeof(buf) - off,
            "subcircuit user/d%d (%%x : byte) -> (%%y : byte) {\n"
            "user/d%d(%%x) -> %%p\n"
            "user/d%d(%%x) -> %%q\n"
            "ADD %%p %%q -> %%y\n}\n",
            i, i - 1, i - 1);
    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                            "WITNESS -> %%a : byte\nuser/d25(%%a) -> %%b\n");
    limits = (voleith_shipshape_limits_t){10000, 0, 0, 0}; /* small max_wires */
    r = voleith_shipshape_parse_buffer(&p, buf, 0, &limits);
    check("subckt: amplification bomb => LIMIT",
          r == VOLEITH_SHIPSHAPE_ERR_LIMIT);
}

/* ================================================================
 * Group M: Tier 2a registry calls (W3.7).
 * ================================================================ */

/* The frozen-table index of FQN, or -1 (keeps tests order-independent). */
static int
reg_idx_of(const char *fqn)
{
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++)
        if (strcmp(voleith_shipshape_registry[i].fqn, fqn) == 0)
            return (int)i;
    return -1;
}

static void
test_registry_table(void)
{
    size_t n = voleith_shipshape_registry_count;
    int ok;

    /* crypto-v1 is thirteen entries, frozen and live in lockstep
     * (the Shipshape spec 7.2; canonical order, same FQN / kind / bounds). */
    ok = (n == 13) && (voleith_shipshape_registry_descriptor_count() == n);
    for (size_t i = 0; ok && i < n; i++) {
        const char *fqn = NULL;
        voleith_shipshape_reg_kind_t kind;
        uint32_t pmin, pmax;

        if (voleith_shipshape_registry_descriptor(i, &fqn, &kind, NULL, &pmin,
                                                  &pmax) != 0 ||
            strcmp(fqn, voleith_shipshape_registry[i].fqn) != 0 ||
            kind != voleith_shipshape_registry[i].kind ||
            pmin != voleith_shipshape_registry[i].param_min ||
            pmax != voleith_shipshape_registry[i].param_max)
            ok = 0;
    }
    check("registry: frozen table and live descriptors in sync", ok);
}

/*
 * True iff the spec 7.2 cost formula agrees with the built body: the D3
 * standalone circuit's witness count is the signature inputs plus the
 * entry's invs (each INV adds exactly one witness slot).
 */
static int
cost_matches_standalone(const char *fqn, uint32_t param)
{
    uint32_t in_len[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS];
    voleith_gf8_circuit_t *c;
    size_t n_inputs, invs, n_in = 0;
    int idx = reg_idx_of(fqn), ok;

    if (idx < 0)
        return 0;
    if (voleith_shipshape_registry_signature((size_t)idx, &n_inputs, in_len,
                                             NULL, NULL) != 0 ||
        voleith_shipshape_registry_cost((size_t)idx, param, NULL, &invs) != 0)
        return 0;
    for (size_t i = 0; i < n_inputs; i++)
        n_in += (in_len[i] == VOLEITH_SHIPSHAPE_REGISTRY_PARAM_LEN) ? param
                                                                    : in_len[i];
    c = voleith_shipshape_registry_build_standalone((size_t)idx, param);
    if (c == NULL)
        return 0;
    ok = voleith_gf8_circuit_witness_count(c) == n_in + invs;
    voleith_gf8_circuit_free(c);
    return ok;
}

static void
test_registry_cost(void)
{
    check(
        "registry: cost invs == standalone witness growth",
        cost_matches_standalone("stdlib/crypto/aes/sbox", 0) &&
            cost_matches_standalone("stdlib/crypto/aes/encrypt_128", 0) &&
            cost_matches_standalone("stdlib/crypto/cmac/aes_128", 0) &&
            cost_matches_standalone("stdlib/crypto/cmac/aes_128", 17) &&
            cost_matches_standalone("stdlib/crypto/grostl/hash_256", 0) &&
            cost_matches_standalone("stdlib/crypto/grostl/hash_256_t27", 56) &&
            cost_matches_standalone("stdlib/crypto/grostl/hash_512", 0));
}

static void
test_registry_calls(void)
{
    voleith_shipshape_parsed_t p;
    voleith_gf8_circuit_t *c;
    gf8_wire_id key[32], pt[16], msg[40], ct[16], tag[16], out32[32];
    gf8_wire_id rk[11][16];
    gf8_wire_id a;
    int r;

    /* A FIXED call inlines the C builder's gate sequence (Goal 2 iii). */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    (void)aes_gf8_sbox(c, a);
    check_lowers_to("registry: sbox call lowers to C builder",
                    HDR "WITNESS -> %x : byte\n"
                        "stdlib/crypto/aes/sbox(%x) -> %y\n",
                    c);

    /* A two-argument FIXED entry. */
    c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        pt[i] = voleith_gf8_add_witness(c);
    aes128_gf8_circuit(c, key, pt, ct);
    check_lowers_to("registry: encrypt_128 lowers to C builder",
                    HDR "WITNESS -> %key : byte[16]\n"
                        "WITNESS -> %pt : byte[16]\n"
                        "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n",
                    c);

    /* The rk output is round-major flat (STDLIB 2): flat index 16r+b is
     * rk[r][b], reachable by indexing the bound output vector. */
    c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    aes128_gf8_expand_key(c, key, rk);
    (void)voleith_gf8_add_xor(c, rk[0][0], rk[10][15]);
    check_lowers_to("registry: keyschedule output round-major indexing",
                    HDR "WITNESS -> %key : byte[16]\n"
                        "stdlib/crypto/aes/keyschedule_128(%key) -> %rk\n"
                        "ADD %rk[0] %rk[175] -> %t\n",
                    c);

    /* PARAMETRIC: n inferred from the msg argument's length (SPEC 7.1). */
    c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 40; i++)
        msg[i] = voleith_gf8_add_witness(c);
    aes_cmac_gf8_circuit(c, key, 16, msg, 40, tag);
    check_lowers_to("registry: cmac n=40 inferred from arg",
                    HDR "WITNESS -> %key : byte[16]\n"
                        "WITNESS -> %msg : byte[40]\n"
                        "stdlib/crypto/cmac/aes_128(%key, %msg) -> %tag\n",
                    c);

    /* A ++ chain's summed length supplies n. */
    c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    for (int i = 0; i < 16; i++)
        msg[i] = voleith_gf8_add_witness(c);
    aes_cmac_gf8_circuit(c, key, 16, msg, 16, tag);
    check_lowers_to("registry: cmac n inferred from ++ chain",
                    HDR "WITNESS -> %key : byte[16]\n"
                        "WITNESS -> %lo : byte[8]\n"
                        "WITNESS -> %hi : byte[8]\n"
                        "stdlib/crypto/cmac/aes_128(%key, %lo ++ %hi) "
                        "-> %tag\n",
                    c);

    /* n = 0 via a declared byte[0] vector (RFC 4493 Example 1). */
    c = voleith_gf8_circuit_new();
    for (int i = 0; i < 16; i++)
        key[i] = voleith_gf8_add_witness(c);
    aes_cmac_gf8_circuit(c, key, 16, NULL, 0, tag);
    check_lowers_to("registry: cmac n=0 empty message",
                    HDR "WITNESS -> %key : byte[16]\n"
                        "WITNESS -> %m : byte[0]\n"
                        "stdlib/crypto/cmac/aes_128(%key, %m) -> %tag\n",
                    c);

    /* T27 truncation: identical gates to hash_256 (SPEC 7.3)... */
    c = voleith_gf8_circuit_new();
    grostl256_gf8_circuit(c, NULL, 0, out32);
    check_lowers_to("registry: t27 gate sequence equals hash_256",
                    HDR "WITNESS -> %m : byte[0]\n"
                        "stdlib/crypto/grostl/hash_256_t27(%m) -> %h\n",
                    c);

    /* ...but the bound output is 27 wide: index 26 legal, 27 a type error. */
    r = parse_decls(HDR "WITNESS -> %m : byte[0]\n"
                        "stdlib/crypto/grostl/hash_256_t27(%m) -> %h\n"
                        "ADD %h[26] %h[26] -> %t\n",
                    &p);
    check("registry: t27 output index 26 ok", r == 0);
    voleith_shipshape_parsed_free(&p);
    r = parse_decls(HDR "WITNESS -> %m : byte[0]\n"
                        "stdlib/crypto/grostl/hash_256_t27(%m) -> %h\n"
                        "ADD %h[27] %h[27] -> %t\n",
                    &p);
    check("registry: t27 output index 27 => TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* One region per call, named by the FQN, spanning the inv witnesses. */
    r = parse_decls(HDR "WITNESS -> %x : byte\n"
                        "stdlib/crypto/aes/sbox(%x) -> %y\n",
                    &p);
    check("registry: one region per call",
          r == 0 && p.n_regions == 1 &&
              strcmp(p.regions[0].name, "stdlib/crypto/aes/sbox") == 0 &&
              p.regions[0].first_witness == 1 && p.regions[0].n_witness == 1);
    voleith_shipshape_parsed_free(&p);

    /* A registry call inside a user body: outer region encloses inner. */
    c = voleith_gf8_circuit_new();
    a = voleith_gf8_add_witness(c);
    (void)aes_gf8_sbox(c, a);
    r = parse_decls(HDR "subcircuit user/wrap (%x : byte) -> (%y : byte) {\n"
                        "stdlib/crypto/aes/sbox(%x) -> %y\n"
                        "}\n"
                        "WITNESS -> %a : byte\n"
                        "user/wrap(%a) -> %b\n",
                    &p);
    check("registry: call in user body fingerprint",
          r == 0 && fp_eq(p.circuit, c));
    check("registry: nested region order and spans",
          r == 0 && p.n_regions == 2 &&
              strcmp(p.regions[0].name, "user/wrap") == 0 &&
              strcmp(p.regions[1].name, "stdlib/crypto/aes/sbox") == 0 &&
              p.regions[0].first_witness == 1 && p.regions[0].n_witness == 1 &&
              p.regions[1].first_witness == 1 && p.regions[1].n_witness == 1);
    voleith_shipshape_parsed_free(&p);
    voleith_gf8_circuit_free(c);
}

static void
test_registry_errors(void)
{
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    int r;

    /* Goal 2 (ii): an unregistered stdlib/crypto name is rejected at the
     * name, before any operand is even resolved. */
    r = parse_decls(HDR "stdlib/crypto/aes/nope(%x) -> %y\n", &p);
    check("registry: unknown name => REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* The kdf/* entries are crypto-v2: rejected as unknown (SPEC 7.5). */
    r = parse_decls(HDR "stdlib/crypto/kdf/ctr_cmac_aes_128(%k) -> %o\n", &p);
    check("registry: deferred kdf entry => REGISTRY",
          r == VOLEITH_SHIPSHAPE_ERR_REGISTRY);

    /* Goal 2 (ii): an unsupported declared stdlib version is rejected outright
     * at the header, so the body is never reached.  (crypto-v3 is undefined;
     * only crypto-v1 and crypto-v2 are accepted.) */
    r = parse_decls(".shipshape 1\n"
                    "field GF(2^8) irreducible 0x11B\n"
                    "stdlib crypto-v3\n"
                    "WITNESS -> %x : byte\n"
                    "stdlib/crypto/aes/sbox(%x) -> %y\n",
                    &p);
    check("registry: version mismatch => HEADER",
          r == VOLEITH_SHIPSHAPE_ERR_HEADER);

    /* Argument arity mismatch (S7). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "stdlib/crypto/aes/sbox(%a, %a) -> %y\n",
                    &p);
    check("registry: extra argument => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* Every crypto-v1 entry has one output: omitting the clause (S7)... */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "stdlib/crypto/aes/sbox(%a)\n",
                    &p);
    check("registry: missing output clause => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* ...or binding two names is an arity error too. */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "stdlib/crypto/aes/sbox(%a) -> %y, %z\n",
                    &p);
    check("registry: two output names => SUBCIRCUIT",
          r == VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT);

    /* A fixed-length argument of the wrong length (S6). */
    r = parse_decls(HDR "WITNESS -> %key : byte[8]\n"
                        "WITNESS -> %pt : byte[16]\n"
                        "stdlib/crypto/aes/encrypt_128(%key, %pt) -> %ct\n",
                    &p);
    check("registry: fixed arg length mismatch => TYPE",
          r == VOLEITH_SHIPSHAPE_ERR_TYPE);

    /* The output name obeys SSA in the caller's scope (S1). */
    r = parse_decls(HDR "WITNESS -> %a : byte\n"
                        "WITNESS -> %y : byte\n"
                        "stdlib/crypto/aes/sbox(%a) -> %y\n",
                    &p);
    check("registry: output redefines name => REDEF",
          r == VOLEITH_SHIPSHAPE_ERR_REDEF);

    /* The invs pre-check rejects an instantiation that cannot fit the
     * wire budget before any gate is emitted (ISA 5.1 discipline). */
    limits = (voleith_shipshape_limits_t){100, 0, 0, 0};
    r = voleith_shipshape_parse_buffer(
        &p,
        HDR "WITNESS -> %key : byte[16]\n"
            "WITNESS -> %msg : byte[16]\n"
            "stdlib/crypto/cmac/aes_128(%key, %msg) -> %tag\n",
        0, &limits);
    check("registry: over-budget instantiation => LIMIT",
          r == VOLEITH_SHIPSHAPE_ERR_LIMIT);
}

#undef HDR

/* ================================================================
 * main
 * ================================================================ */

int
main(void)
{
    printf("test_shipshape_parser: starting\n");
    test_buffer_entry();
    test_file_entry();
    test_zeroing_and_free();
    test_limit_clamping();
    test_lexer_token_classes();
    test_lexer_bounds();
    test_line_layer();
    test_line_layer_public();
    test_header();
    test_scale_instance();
    test_declarations();
    test_gates();
    test_gate_types_and_errors();
    test_subcircuits();
    test_subcircuit_errors();
    test_subcircuit_bombs();
    test_registry_table();
    test_registry_cost();
    test_registry_calls();
    test_registry_errors();
    printf("test_shipshape_parser: %d/%d passed\n", pass_count, test_count);
    return (pass_count == test_count) ? 0 : 1;
}
