/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape_internal.h - Shipshape parser internals (NOT a public
 * API).
 *
 * This header exposes the lexer types and entry points that live in
 * parsers/shipshape.c so the parser's own test suite can exercise the
 * lexer directly, before the higher parser stages (header, declarations,
 * gates) that would otherwise be the only way to reach it.  Nothing here
 * is part of the stable public surface (include/voleith_gf8.h /
 * parsers/shipshape.h); the shapes and names may change between releases.
 * Application code must not include this header.
 *
 * Lexical layer reference: FORMAT (docs/CIRC_FORMAT.md) 2 and 7.1; bounds
 * from ISA (docs/GF8_CIRCUIT_ISA_DESIGN.md) 5.1.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_INTERNAL_H
#define VOLEITH_PARSERS_SHIPSHAPE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "shipshape.h"

/* ================================================================
 * Lexer
 * ================================================================ */

/*
 * Token classes produced by the body tokenizer (FORMAT 7.1).  The header
 * lines use fixed literal spellings (".shipshape", "GF(2^8)", "crypto-v1")
 * that are not valid body tokens; they are matched by the header stage
 * with a raw-word reader, not by ss_next_token().
 */
typedef enum {
    SS_TOK_EOL = 0,  /* no more tokens on the current line */
    SS_TOK_WIRE,     /* %ident */
    SS_TOK_PATH,     /* ident('/'ident)+  (two or more segments) */
    SS_TOK_WORD,     /* bare ident: opcode, keyword, type, single segment */
    SS_TOK_BYTE_LIT, /* 0xHH  -> byte_val */
    SS_TOK_INT_LIT,  /* decimal, no leading zero  -> int_val */
    SS_TOK_ARROW,    /* -> */
    SS_TOK_COLON,    /* : */
    SS_TOK_COMMA,    /* , */
    SS_TOK_LPAREN,   /* ( */
    SS_TOK_RPAREN,   /* ) */
    SS_TOK_LBRACKET, /* [ */
    SS_TOK_RBRACKET, /* ] */
    SS_TOK_LBRACE,   /* { */
    SS_TOK_RBRACE,   /* } */
    SS_TOK_PLUSPLUS, /* ++ */
} ss_tok_kind_t;

/*
 * One token.  `lex` points into the lexer's line buffer and is valid only
 * until the next ss_read_line() call; `len` is the lexeme length.  byte_val
 * is set for SS_TOK_BYTE_LIT, int_val for SS_TOK_INT_LIT; both are 0
 * otherwise.
 */
typedef struct {
    ss_tok_kind_t kind;
    const char *lex;
    size_t len;
    uint8_t byte_val;
    uint32_t int_val;
} ss_token_t;

/*
 * Lexer state.  The input buffer is borrowed (not copied); `line` is a
 * single reusable fixed-size buffer of `line_cap + 1` bytes into which each
 * physical line is copied and charset-validated (FORMAT 2.1).  `line_cap`
 * is the effective MAX_LINE_BYTES and `ident_cap` the MAX_IDENT_LEN ceiling
 * (ISA 5.1), both lowerable for testing.
 */
typedef struct {
    const char *pos; /* read cursor in the borrowed input */
    const char *end;
    size_t line_cap;  /* max content bytes per line (excludes NUL) */
    size_t ident_cap; /* max identifier / path / wire lexeme length */
    char *line;       /* reusable line buffer, line_cap + 1 bytes */
    size_t line_len;  /* content bytes in `line` (excludes NUL) */
    size_t line_pos;  /* tokenizer cursor within `line` */
    size_t lineno;    /* 1-based physical line number of `line` */
} ss_lexer_t;

/*
 * Initialise a lexer over [buf, buf+len).  `line_cap` and `ident_cap` are
 * clamped to their ISA 5.1 ceilings (0 selects the ceiling).  Allocates the
 * line buffer.  Returns 0 on success or VOLEITH_SHIPSHAPE_ERR_ALLOC.
 */
int voleith_shipshape_lex_init(ss_lexer_t *, const char *, size_t, size_t,
                               size_t);

/* Release the lexer's line buffer.  Safe on a zeroed struct and on NULL. */
void voleith_shipshape_lex_free(ss_lexer_t *);

/*
 * Read the next physical line into the line buffer, copying and charset-
 * validating each byte and resetting the token cursor.  A CR, LF, or CRLF
 * each terminates exactly one line (FORMAT 2.1); the final line may omit
 * its terminator.
 *
 * Returns 0 when a line is ready (possibly empty), 1 at end of input, or a
 * negative voleith_shipshape_error_t (VOLEITH_SHIPSHAPE_ERR_CHARSET,
 * VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG).
 */
int voleith_shipshape_lex_read_line(ss_lexer_t *);

/*
 * Produce the next token on the current line into *out.  A `#` comment and
 * trailing whitespace yield SS_TOK_EOL.  Returns 0 on success (the token,
 * possibly SS_TOK_EOL, is in *out) or a negative voleith_shipshape_error_t
 * (VOLEITH_SHIPSHAPE_ERR_IDENT, VOLEITH_SHIPSHAPE_ERR_LITERAL,
 * VOLEITH_SHIPSHAPE_ERR_TOKEN).
 */
int voleith_shipshape_lex_next_token(ss_lexer_t *, ss_token_t *);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_INTERNAL_H */
