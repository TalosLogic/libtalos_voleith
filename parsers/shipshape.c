/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape.c - Shipshape (.ship) native GF(2^8) circuit parser
 *
 * W3.1 (the implementation plan): entry-point skeleton.
 * Argument validation, resource-limit clamping, the MAX_FILE_BYTES gate
 * checked before buffering, out-struct zeroing, and free-on-all-paths.
 *
 * W3.2: the lexer (FORMAT 2, 7.1).  A line layer copies each physical line
 * into a single fixed-size buffer, enforcing the charset and MAX_LINE_BYTES
 * and collapsing CR / LF / CRLF to one newline; a body tokenizer over that
 * buffer recognises wires, paths, words, byte / integer literals, and
 * punctuation, enforcing MAX_IDENT_LEN and the literal forms.  The lexer
 * entry points are declared in shipshape_internal.h so the parser test can
 * drive the tokenizer before the body stages route lines through it.
 *
 * W3.3: the header (FORMAT 3.1, 7.1).  parse_body matches the three
 * mandatory lines (.shipshape / field / stdlib) in order, with exact
 * case-sensitive spellings, accepting comment and blank lines before and
 * between them; header tokens are matched as raw words, not body tokens.
 *
 * W3.4: declarations, the wire table, and types (FORMAT 3.2, 7.2 S1-S3, S5;
 * ISA 2.2, 2.3, 2.11).  After the header, parse_body tokenizes each body
 * line and dispatches on its head word: WITNESS / INSTANCE / CONST /
 * CONST_BIT are parsed, type-checked, and lowered into a fresh
 * voleith_gf8_circuit_t, recording each in a file-order declaration table
 * (the parse context's wire table).  Scalar and vector types (byte / bit,
 * with an optional [N], N = 0 legal) are handled; a WITNESS : bit emits the
 * booleanity ASSERT_PRODUCT per element (ISA 2.3); names obey SSA (one
 * definition per scope, S1).
 *
 * W3.5: gates, assertions, sugar (ISA 2.4-2.7, 5.2; FORMAT 3.3, 3.5).  All
 * Tier 1 opcodes and assertions lower into the circuit via a one-token-
 * lookahead operand parser; sugar (SUM, FROBENIUS_K, ASSERT_CONST,
 * ASSERT_BIT) expands inline, INV emits its atomic gadget, LINEAR_MAP with
 * the squaring matrix canonicalizes to SQUARE, and MUX checks its bit
 * selector before expansion.
 *
 * W3.6: subcircuits, inlining, regions (FORMAT 3.4, 3.6, 7.2 S1-S4, S6-S8,
 * S10; ISA 1.4, 2.8, 5.2 Steps 1 and 7).  `subcircuit user/...` definitions
 * are parsed (top-level only, user/* only) and their bodies captured as byte
 * ranges; a `path(...)` call inlines the body at the call site over a fresh
 * body scope, binding parameters to the caller's argument wires (`++` and
 * `[i]` arguments flatten to wire lists), then binds the call's outputs in
 * the caller's scope.  MAX_INLINE_DEPTH and the incremental MAX_WIRES budget
 * bound recursion and amplification; one region marker is emitted per
 * inlined call (semantically transparent, ISA 5.2 Step 7).
 * `stdlib/structural/*` and other namespaces are errors (empty v1 set, S4).
 *
 * W3.7: Tier 2a registry (ISA 1.5 Goal 2, 2.8, 3; STDLIB D1-D4; SPEC 6.3,
 * 7).  A `stdlib/crypto/*` call is looked up by FQN in the frozen crypto-v1
 * table (parsers/shipshape_registry_table.c); an absent name is
 * VOLEITH_SHIPSHAPE_ERR_REGISTRY (Goal 2 rule ii; rule i, no stdlib
 * definitions, is enforced in parse_subckt_def, and the declared-version
 * gate is the exact-match `stdlib crypto-v1` header line).  A PARAMETRIC
 * entry's length parameter is inferred from the argument in its inferred
 * slot (SPEC 7.1); parameter bounds and the derived block count
 * (MAX_BLOCKS_PER_OPCODE) are checked before any gate is emitted, with the
 * entry's invs as a pre-emission lower bound on the wire budget.  The body
 * is then emitted over the caller's argument wires by the linked C builders
 * (voleith_shipshape_registry_inline, Goal 2 rule iii structural identity),
 * the exact wire count is re-checked against the budget, and one region
 * marker named by the FQN is recorded.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "shipshape.h"
#include "shipshape_internal.h"
#include "shipshape_node_hash_types.h"
#include "shipshape_registry.h"

/* ================================================================
 * Parse context
 *
 * State threaded through the body grammar.  The symbol table holds every
 * named wire in the current scope: the top-level WITNESS / INSTANCE / CONST
 * / CONST_BIT declarations (is_decl 1, which become the public declaration
 * table) and the internal outputs of gates, assertions, and ASSERT_BIT
 * rebindings (is_decl 0).  Lookups resolve operands for define-before-use
 * (S2) and carry the flow-sensitive `bit` refinement (S5).  On success the
 * circuit is handed to the caller and the public decl table is built from
 * the is_decl entries; on any failure ctx_free releases everything.
 * ================================================================ */

typedef struct {
    char *name;             /* declared name without the '%' sigil; owned */
    gf8_wire_id first_wire; /* element 0 (invalid for a zero-length vector) */
    gf8_wire_id *elems;     /* explicit element wires, or NULL if contiguous */
    size_t length;          /* element count: vector N (>= 0); scalar 1 */
    int is_vector;          /* 1 if declared with a [N] type */
    int is_bit;             /* current refinement type: 1 bit, 0 byte (S5) */
    int is_decl; /* 1 for a top-level WITNESS/INSTANCE/CONST/CONST_BIT */
    voleith_shipshape_decl_kind_t decl_kind; /* valid iff is_decl */
} ss_sym_t;

/* One subcircuit-signature parameter or output (FORMAT 3.6). */
typedef struct {
    char *name;    /* parameter / output name, no sigil; owned */
    size_t length; /* vector N, or 1 for a scalar */
    int is_bit;    /* refinement: 1 bit, 0 byte */
    int is_vector; /* 1 if a [N] type */
} ss_param_t;

/*
 * One top-level `user/*` subcircuit definition.  The body is captured as a
 * byte range [body_start, body_end) of the input buffer and re-lexed at each
 * call site for inlining (ISA 5.2 Step 1).  `n_outputs == 0` means the
 * definition omits its `-> ( ... )` clause (assertion-only body).
 */
typedef struct {
    char *name; /* fully-qualified "user/..." name; owned */
    ss_param_t *params;
    size_t n_params;
    ss_param_t *outputs;
    size_t n_outputs;
    const char *body_start; /* into the borrowed input buffer */
    const char *body_end;
} ss_subckt_t;

typedef struct {
    voleith_gf8_circuit_t *circuit;
    ss_sym_t *syms; /* the current scope: top level, or an inlined body */
    size_t n_syms;
    size_t cap_syms;
    ss_subckt_t *defs; /* top-level subcircuit definitions, file order */
    size_t n_defs;
    size_t cap_defs;
    voleith_shipshape_region_t *regions; /* inlining-order call sites */
    size_t n_regions;
    size_t cap_regions;
    size_t inline_depth; /* current call-inlining recursion depth */
    const char *buf;     /* input buffer, for body re-lexing */
    size_t buf_len;
    const voleith_shipshape_limits_t *eff;
    int stdlib_version; /* 1 = crypto-v1; 2 = crypto-v2 */
} ss_parse_ctx_t;

/* A growable list of wire ids: call arguments (`++` chains and whole-vector
 * operands) flatten to a wire list before binding to parameters. */
typedef struct {
    gf8_wire_id *w;
    size_t n;
    size_t cap;
} ss_wlist_t;

/*
 * Gate / assertion line parser.  Unlike the declaration grammar, gate
 * operands can carry an optional `[index]` and SUM is variadic, so the
 * parser needs one token of lookahead: `cur` always holds the next
 * unconsumed token of the line.  `err` is sticky: once a negative error code
 * is recorded every further step is a no-op so the first error wins
 * (FORMAT 4).
 */
typedef struct {
    ss_lexer_t *lx;
    ss_token_t cur;
    int err;
} ss_gp_t;

/* ================================================================
 * Static prototypes
 * ================================================================ */

static size_t clamp_limit(size_t, size_t);
static void resolve_limits(const voleith_shipshape_limits_t *,
                           voleith_shipshape_limits_t *);
static int is_id_start(unsigned char);
static int is_id_char(unsigned char);
static int is_dec_digit(unsigned char);
static int hex_val(unsigned char);
static void lex_next_word(ss_lexer_t *, const char **, size_t *);
static int match_header_line(ss_lexer_t *, const char *const *);
static int parse_header(ss_lexer_t *, int *);

/* Symbol table and declarations (W3.4). */
static int tok_word_is(const ss_token_t *, const char *);
static char *dup_name(const char *, size_t);
static int ctx_lookup(const ss_parse_ctx_t *, const char *, size_t);
static int ctx_add_sym(ss_parse_ctx_t *, const char *, size_t);
static int budget_wires(const ss_parse_ctx_t *, size_t);
static int expect_tok(ss_lexer_t *, ss_tok_kind_t, ss_token_t *);
static int parse_type(ss_lexer_t *, ss_token_t *, int *, int *, size_t *);
static int lower_input_decl(ss_parse_ctx_t *, voleith_shipshape_decl_kind_t,
                            const char *, size_t, int, int, size_t);
static int parse_input_decl(ss_parse_ctx_t *, ss_lexer_t *,
                            voleith_shipshape_decl_kind_t);
static int parse_const_decl(ss_parse_ctx_t *, ss_lexer_t *, int);

/* Gates, assertions, sugar (W3.5). */
static void gp_init(ss_gp_t *, ss_lexer_t *);
static void gp_advance(ss_gp_t *);
static int gp_eat(ss_gp_t *, ss_tok_kind_t, ss_token_t *);
static int gp_end(ss_gp_t *);
static int gp_operand(ss_gp_t *, ss_parse_ctx_t *, gf8_wire_id *, int *);
static int gp_bind(ss_gp_t *, ss_parse_ctx_t *, gf8_wire_id, int);
static int gate_add(ss_parse_ctx_t *, ss_gp_t *);
static int gate_add_const(ss_parse_ctx_t *, ss_gp_t *);
static int gate_linear_map(ss_parse_ctx_t *, ss_gp_t *);
static int gate_square(ss_parse_ctx_t *, ss_gp_t *);
static int gate_mul(ss_parse_ctx_t *, ss_gp_t *);
static int gate_mux(ss_parse_ctx_t *, ss_gp_t *);
static int gate_inv(ss_parse_ctx_t *, ss_gp_t *);
static int gate_sum(ss_parse_ctx_t *, ss_gp_t *);
static int gate_frobenius(ss_parse_ctx_t *, ss_gp_t *);
static int assert_zero_g(ss_parse_ctx_t *, ss_gp_t *);
static int assert_equal_g(ss_parse_ctx_t *, ss_gp_t *);
static int assert_product_g(ss_parse_ctx_t *, ss_gp_t *);
static int assert_bit_g(ss_parse_ctx_t *, ss_gp_t *);
static int assert_const_g(ss_parse_ctx_t *, ss_gp_t *);
static int parse_gate_line(ss_parse_ctx_t *, ss_lexer_t *, const ss_token_t *);

/* Subcircuits, inlining, regions (W3.6). */
static gf8_wire_id sym_elem(const ss_sym_t *, size_t);
static int wlist_push(ss_wlist_t *, gf8_wire_id);
static void wlist_free(ss_wlist_t *);
static int gp_type(ss_gp_t *, int *, int *, size_t *);
static int starts_with(const ss_token_t *, const char *);
static const ss_subckt_t *find_def(const ss_parse_ctx_t *, const char *,
                                   size_t);
static int parse_param_list(ss_gp_t *, ss_param_t **, size_t *);
static void free_params(ss_param_t *, size_t);
static int parse_subckt_def(ss_parse_ctx_t *, ss_lexer_t *);
static int resolve_operand_wires(ss_gp_t *, ss_parse_ctx_t *, ss_wlist_t *);
static int resolve_arg(ss_gp_t *, ss_parse_ctx_t *, ss_wlist_t *);
static int region_reserve(ss_parse_ctx_t *, const char *, size_t *, size_t *);
static int inline_call(ss_parse_ctx_t *, const ss_subckt_t *, ss_wlist_t *,
                       size_t, ss_token_t *, size_t);
static int parse_call(ss_parse_ctx_t *, ss_lexer_t *, const ss_token_t *);

/* Tier 2a registry calls (W3.7) and crypto-v2 hash-parametric calls. */
static int registry_lookup(const char *, size_t);
static int registry_call(ss_parse_ctx_t *, size_t, ss_wlist_t *, size_t,
                         ss_token_t *, size_t);
static int registry_lookup_hash(const char *, size_t);
static int registry_call_hash(ss_parse_ctx_t *, size_t,
                              const voleith_node_hash_vt *, ss_wlist_t *,
                              size_t, ss_token_t *, size_t);

static int parse_statement(ss_parse_ctx_t *, ss_lexer_t *, const ss_token_t *);
static int finalize_decls(ss_parse_ctx_t *, voleith_shipshape_parsed_t *);
static void free_syms(ss_parse_ctx_t *);
static void free_defs(ss_parse_ctx_t *);
static void free_regions(ss_parse_ctx_t *);
static void ctx_free(ss_parse_ctx_t *);
static int parse_body(voleith_shipshape_parsed_t *, const char *, size_t,
                      const voleith_shipshape_limits_t *);

/* ================================================================
 * Resource-limit resolution
 * ================================================================ */

/*
 * Resolve one caller-supplied limit against its ceiling: 0 selects the
 * ceiling, and any value above the ceiling is clamped down to it (ISA
 * 5.1).  The result is always in the inclusive range [1, ceiling] for a
 * positive ceiling.
 */
static size_t
clamp_limit(size_t caller, size_t ceiling)
{
    if (caller == 0 || caller > ceiling)
        return ceiling;
    return caller;
}

/*
 * Fill *eff with the effective limits for this parse.  `req` may be NULL,
 * in which case every limit resolves to its ceiling.
 */
static void
resolve_limits(const voleith_shipshape_limits_t *req,
               voleith_shipshape_limits_t *eff)
{
    voleith_shipshape_limits_t zero = {0, 0, 0, 0};

    if (req == NULL)
        req = &zero;
    eff->max_wires = clamp_limit(req->max_wires, VOLEITH_SHIPSHAPE_MAX_WIRES);
    eff->max_gates = clamp_limit(req->max_gates, VOLEITH_SHIPSHAPE_MAX_GATES);
    eff->max_file_bytes =
        clamp_limit(req->max_file_bytes, VOLEITH_SHIPSHAPE_MAX_FILE_BYTES);
    eff->max_line_bytes =
        clamp_limit(req->max_line_bytes, VOLEITH_SHIPSHAPE_MAX_LINE_BYTES);
}

/* ================================================================
 * Lexer (FORMAT 2, 7.1)
 * ================================================================ */

/* id-start: ALPHA / "_" (FORMAT 7.1). */
static int
is_id_start(unsigned char c)
{
    return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

/* id-char: ALPHA / DIGIT / "_". */
static int
is_id_char(unsigned char c)
{
    return is_id_start(c) || (c >= '0' && c <= '9');
}

static int
is_dec_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

/* Hex digit value (0-9 A-F a-f), or -1 if not a hex digit. */
static int
hex_val(unsigned char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int
voleith_shipshape_lex_init(ss_lexer_t *lx, const char *buf, size_t len,
                           size_t line_cap, size_t ident_cap)
{
    memset(lx, 0, sizeof(*lx));
    lx->pos = buf;
    lx->end = buf + len;
    lx->line_cap = clamp_limit(line_cap, VOLEITH_SHIPSHAPE_MAX_LINE_BYTES);
    lx->ident_cap = clamp_limit(ident_cap, VOLEITH_SHIPSHAPE_MAX_IDENT_LEN);
    lx->line = calloc(lx->line_cap + 1, 1);
    if (lx->line == NULL)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return 0;
}

void
voleith_shipshape_lex_free(ss_lexer_t *lx)
{
    if (lx == NULL)
        return;
    free(lx->line);
    lx->line = NULL;
}

int
voleith_shipshape_lex_read_line(ss_lexer_t *lx)
{
    size_t n = 0;

    if (lx->pos >= lx->end)
        return 1; /* end of input */

    while (lx->pos < lx->end) {
        unsigned char b = (unsigned char)*lx->pos;

        if (b == '\n') {
            lx->pos++;
            break;
        }
        if (b == '\r') {
            lx->pos++;
            if (lx->pos < lx->end && *lx->pos == '\n')
                lx->pos++; /* CRLF counts as one newline (FORMAT 2.1) */
            break;
        }
        /* Charset: tab and 0x20-0x7E only, checked everywhere incl. comments. */
        if (b != '\t' && (b < 0x20 || b > 0x7E))
            return VOLEITH_SHIPSHAPE_ERR_CHARSET;
        if (n >= lx->line_cap)
            return VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG;
        lx->line[n++] = (char)b;
        lx->pos++;
    }

    lx->line[n] = '\0';
    lx->line_len = n;
    lx->line_pos = 0;
    lx->lineno++;
    return 0;
}

int
voleith_shipshape_lex_next_token(ss_lexer_t *lx, ss_token_t *out)
{
    const char *s = lx->line;
    size_t len = lx->line_len;
    size_t i = lx->line_pos;
    size_t start;
    unsigned char c;

    memset(out, 0, sizeof(*out));

    /* Skip inline whitespace. */
    while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;

    /* End of line, or a comment running to end of line, yields EOL. */
    if (i >= len || s[i] == '#') {
        lx->line_pos = len;
        out->kind = SS_TOK_EOL;
        out->lex = s + len;
        return 0;
    }

    start = i;
    c = (unsigned char)s[i];

    if (c == '%') {
        /* Wire: "%" id-start id-char*. */
        i++;
        if (i >= len || !is_id_start((unsigned char)s[i]))
            return VOLEITH_SHIPSHAPE_ERR_IDENT;
        i++;
        while (i < len && is_id_char((unsigned char)s[i]))
            i++;
        if (i - start > lx->ident_cap) /* length incl. sigil (FORMAT 2.3) */
            return VOLEITH_SHIPSHAPE_ERR_IDENT;
        out->kind = SS_TOK_WIRE;
    } else if (is_id_start(c)) {
        /* Word, or path if one or more "/" segments follow. */
        int is_path = 0;

        i++;
        while (i < len && is_id_char((unsigned char)s[i]))
            i++;
        while (i < len && s[i] == '/') {
            is_path = 1;
            i++;
            if (i >= len || !is_id_start((unsigned char)s[i]))
                return VOLEITH_SHIPSHAPE_ERR_IDENT;
            i++;
            while (i < len && is_id_char((unsigned char)s[i]))
                i++;
        }
        if (i - start >
            lx->ident_cap) /* length incl. separators (FORMAT 2.3) */
            return VOLEITH_SHIPSHAPE_ERR_IDENT;
        out->kind = is_path ? SS_TOK_PATH : SS_TOK_WORD;
    } else if (is_dec_digit(c)) {
        if (c == '0' && i + 1 < len && s[i + 1] == 'x') {
            /* Byte literal: "0x" 2hex, lowercase x only (FORMAT 2.4). */
            int hi, lo;

            i += 2;
            if (i + 1 >= len || (hi = hex_val((unsigned char)s[i])) < 0 ||
                (lo = hex_val((unsigned char)s[i + 1])) < 0)
                return VOLEITH_SHIPSHAPE_ERR_LITERAL;
            i += 2;
            /* Exactly two hex digits: no third hex/id-char may glue on. */
            if (i < len && is_id_char((unsigned char)s[i]))
                return VOLEITH_SHIPSHAPE_ERR_LITERAL;
            out->kind = SS_TOK_BYTE_LIT;
            out->byte_val = (uint8_t)((hi << 4) | lo);
        } else {
            /* Integer literal: "0" / %x31-39 *DIGIT, no leading zero. */
            size_t dstart = i;
            uint32_t v = 0;

            while (i < len && is_dec_digit((unsigned char)s[i]))
                i++;
            if (i - dstart > 1 && s[dstart] == '0')
                return VOLEITH_SHIPSHAPE_ERR_LITERAL;
            if (i < len && is_id_char((unsigned char)s[i]))
                return VOLEITH_SHIPSHAPE_ERR_LITERAL;
            for (size_t k = dstart; k < i; k++) {
                uint32_t d = (uint32_t)(s[k] - '0');
                if (v > (UINT32_MAX - d) / 10)
                    return VOLEITH_SHIPSHAPE_ERR_LITERAL;
                v = v * 10 + d;
            }
            out->kind = SS_TOK_INT_LIT;
            out->int_val = v;
        }
    } else if (c == '-') {
        if (i + 1 >= len || s[i + 1] != '>')
            return VOLEITH_SHIPSHAPE_ERR_TOKEN;
        i += 2;
        out->kind = SS_TOK_ARROW;
    } else if (c == '+') {
        if (i + 1 >= len || s[i + 1] != '+')
            return VOLEITH_SHIPSHAPE_ERR_TOKEN;
        i += 2;
        out->kind = SS_TOK_PLUSPLUS;
    } else {
        switch (c) {
        case ':':
            out->kind = SS_TOK_COLON;
            break;
        case ',':
            out->kind = SS_TOK_COMMA;
            break;
        case '(':
            out->kind = SS_TOK_LPAREN;
            break;
        case ')':
            out->kind = SS_TOK_RPAREN;
            break;
        case '[':
            out->kind = SS_TOK_LBRACKET;
            break;
        case ']':
            out->kind = SS_TOK_RBRACKET;
            break;
        case '{':
            out->kind = SS_TOK_LBRACE;
            break;
        case '}':
            out->kind = SS_TOK_RBRACE;
            break;
        default:
            return VOLEITH_SHIPSHAPE_ERR_TOKEN;
        }
        i++;
    }

    out->lex = s + start;
    out->len = i - start;
    lx->line_pos = i;
    return 0;
}

/*
 * Read the next raw whitespace-delimited word on the current line for the
 * header stage, whose tokens (".shipshape", "GF(2^8)", "crypto-v1", "0x11B")
 * are not body tokens.  A word runs until a space, tab, or "#" (which begins
 * a comment, FORMAT 2.2).  Sets *word to the lexeme and *wlen to its length;
 * *wlen == 0 means no word remains (end of line or a comment).  The line
 * bytes were already charset-validated by ss_read_line, so this cannot fail.
 */
static void
lex_next_word(ss_lexer_t *lx, const char **word, size_t *wlen)
{
    const char *s = lx->line;
    size_t len = lx->line_len;
    size_t i = lx->line_pos;
    size_t start;

    while (i < len && (s[i] == ' ' || s[i] == '\t'))
        i++;
    if (i >= len || s[i] == '#') {
        lx->line_pos = len;
        *word = s + len;
        *wlen = 0;
        return;
    }
    start = i;
    while (i < len && s[i] != ' ' && s[i] != '\t' && s[i] != '#')
        i++;
    lx->line_pos = i;
    *word = s + start;
    *wlen = i - start;
}

/* ================================================================
 * Header (FORMAT 3.1, 7.1)
 * ================================================================ */

/*
 * Match one header line against `expect`, a NULL-terminated array of exact
 * token spellings.  Blank and comment-only lines before the header line are
 * skipped (FORMAT 2.2, 3.1).  The match is case-sensitive and admits no
 * extra tokens (only a trailing comment or whitespace).  Returns 0 on a
 * full match, VOLEITH_SHIPSHAPE_ERR_HEADER on a wrong / missing / extra
 * token or a missing header line, or a negative read error.
 */
static int
match_header_line(ss_lexer_t *lx, const char *const *expect)
{
    const char *w;
    size_t wl;
    int r, i;

    /* Skip blank / comment-only lines; stop on the first content line. */
    for (;;) {
        r = voleith_shipshape_lex_read_line(lx);
        if (r == 1)
            return VOLEITH_SHIPSHAPE_ERR_HEADER; /* header line missing */
        if (r < 0)
            return r; /* charset / line-too-long */
        lex_next_word(lx, &w, &wl);
        if (wl != 0)
            break;
    }

    /* The first word is already in w/wl; match the whole expected sequence. */
    for (i = 0; expect[i] != NULL; i++) {
        if (i > 0)
            lex_next_word(lx, &w, &wl);
        if (wl == 0)
            return VOLEITH_SHIPSHAPE_ERR_HEADER; /* too few tokens */
        if (wl != strlen(expect[i]) || memcmp(w, expect[i], wl) != 0)
            return VOLEITH_SHIPSHAPE_ERR_HEADER; /* wrong spelling */
    }

    /* No tokens may follow the last expected one. */
    lex_next_word(lx, &w, &wl);
    if (wl != 0)
        return VOLEITH_SHIPSHAPE_ERR_HEADER;
    return 0;
}

/*
 * Parse the three mandatory header lines in order (FORMAT 3.1).  Accepts
 * both `stdlib crypto-v1` and `stdlib crypto-v2` on the third line and
 * reports which was found via *version (set to 1 or 2).  Returns 0 on
 * success or a negative voleith_shipshape_error_t.
 */
static int
parse_header(ss_lexer_t *lx, int *version)
{
    static const char *const version_line[] = {".shipshape", "1", NULL};
    static const char *const field_line[] = {"field", "GF(2^8)", "irreducible",
                                             "0x11B", NULL};
    static const char kw_stdlib[] = "stdlib";
    static const char kw_v1[] = "crypto-v1";
    static const char kw_v2[] = "crypto-v2";
    const char *w;
    size_t wl;
    int r;

    if ((r = match_header_line(lx, version_line)) != 0)
        return r;
    if ((r = match_header_line(lx, field_line)) != 0)
        return r;

    /*
     * Third line: skip blank/comment lines, then match "stdlib" followed by
     * either "crypto-v1" or "crypto-v2" (FORMAT 3.1).
     */
    for (;;) {
        r = voleith_shipshape_lex_read_line(lx);
        if (r == 1)
            return VOLEITH_SHIPSHAPE_ERR_HEADER;
        if (r < 0)
            return r;
        lex_next_word(lx, &w, &wl);
        if (wl != 0)
            break;
    }
    if (wl != sizeof(kw_stdlib) - 1 || memcmp(w, kw_stdlib, wl) != 0)
        return VOLEITH_SHIPSHAPE_ERR_HEADER;
    lex_next_word(lx, &w, &wl);
    if (wl == sizeof(kw_v2) - 1 && memcmp(w, kw_v2, wl) == 0) {
        *version = 2;
    } else if (wl == sizeof(kw_v1) - 1 && memcmp(w, kw_v1, wl) == 0) {
        *version = 1;
    } else {
        return VOLEITH_SHIPSHAPE_ERR_HEADER;
    }
    /* No trailing tokens. */
    lex_next_word(lx, &w, &wl);
    if (wl != 0)
        return VOLEITH_SHIPSHAPE_ERR_HEADER;
    return 0;
}

/* ================================================================
 * Declarations and the wire table (W3.4)
 * ================================================================ */

/* True iff token `t` is a WORD whose lexeme equals the C string `kw`. */
static int
tok_word_is(const ss_token_t *t, const char *kw)
{
    size_t n = strlen(kw);

    return t->kind == SS_TOK_WORD && t->len == n && memcmp(t->lex, kw, n) == 0;
}

/* Copy a non-terminated lexeme slice [s, s+n) into a fresh NUL-terminated
 * string.  Returns the string, or NULL on allocation failure. */
static char *
dup_name(const char *s, size_t n)
{
    char *p = calloc(n + 1, 1);

    if (p == NULL)
        return NULL;
    memcpy(p, s, n);
    return p;
}

/*
 * Look up a name (the slice [name, name+len), without the '%' sigil) in the
 * context's symbol table.  Returns the entry index, or -1 if not defined.
 * Linear scan: this is construction-time code, not a hot path (ISA 5.2
 * lowering happens once).
 */
static int
ctx_lookup(const ss_parse_ctx_t *ctx, const char *name, size_t len)
{
    for (size_t i = 0; i < ctx->n_syms; i++) {
        const char *d = ctx->syms[i].name;

        if (strlen(d) == len && memcmp(d, name, len) == 0)
            return (int)i;
    }
    return -1;
}

/*
 * Append a symbol-table entry for `name`, taking a copy of the name and
 * zeroing the other fields for the caller to fill.  Returns the new entry's
 * index, or VOLEITH_SHIPSHAPE_ERR_ALLOC on allocation failure (a negative
 * value; the table stays consistent so ctx_free can release it).  The caller
 * is responsible for the SSA (S1) redefinition check before calling.
 */
static int
ctx_add_sym(ss_parse_ctx_t *ctx, const char *name, size_t namelen)
{
    char *copy;
    ss_sym_t *s;

    if (ctx->n_syms == ctx->cap_syms) {
        size_t new_cap = ctx->cap_syms == 0 ? 16 : ctx->cap_syms * 2;
        ss_sym_t *p;

        /* L-N4: guard the count*size multiply before growing. */
        if (new_cap > SIZE_MAX / sizeof(*p))
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        p = realloc(ctx->syms, new_cap * sizeof(*p));
        if (p == NULL)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        ctx->syms = p;
        ctx->cap_syms = new_cap;
    }

    copy = dup_name(name, namelen);
    if (copy == NULL)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    s = &ctx->syms[ctx->n_syms];
    memset(s, 0, sizeof(*s));
    s->name = copy;
    return (int)ctx->n_syms++;
}

/*
 * Incremental MAX_WIRES check (ISA 5.1, S8): return 0 if the circuit can
 * still grow by `add` wires, or VOLEITH_SHIPSHAPE_ERR_LIMIT otherwise.
 * Checked before any wire is emitted so an amplification attempt is rejected
 * before the allocation grows.
 */
static int
budget_wires(const ss_parse_ctx_t *ctx, size_t add)
{
    size_t have = voleith_gf8_circuit_wire_count(ctx->circuit);

    if (add > ctx->eff->max_wires - have)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    return 0;
}

/*
 * Incremental MAX_GATES check (ISA 5.1, S8): return 0 if the circuit can
 * still grow by `add` gate (produced, non-input) wires, or
 * VOLEITH_SHIPSHAPE_ERR_LIMIT otherwise.  Gate emission is always paired with
 * a wire, so this is checked alongside budget_wires at each emission site;
 * input declarations (WITNESS / INSTANCE / CONST) grow wires but not gates
 * and are budgeted by budget_wires alone.
 */
static int
budget_gates(const ss_parse_ctx_t *ctx, size_t add)
{
    size_t have = voleith_gf8_circuit_gate_count(ctx->circuit);

    if (add > ctx->eff->max_gates - have)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    return 0;
}

/*
 * Read the next body token and require it to be of kind `want`, storing it
 * in *out.  Returns 0 on a match, VOLEITH_SHIPSHAPE_ERR_DECL on a wrong or
 * missing token (EOL where a token was required), or a negative lexer error
 * (a malformed identifier / literal / token on the line).
 */
static int
expect_tok(ss_lexer_t *lx, ss_tok_kind_t want, ss_token_t *out)
{
    int r = voleith_shipshape_lex_next_token(lx, out);

    if (r < 0)
        return r;
    if (out->kind != want)
        return VOLEITH_SHIPSHAPE_ERR_DECL;
    return 0;
}

/*
 * Parse a type annotation (FORMAT 3.2, 7.1 `type`): a `byte` / `bit` scalar
 * word, optionally followed by a `[` int-lit `]` vector suffix.  The opening
 * `byte` / `bit` word has not yet been read.  Sets *is_bit (1 for bit),
 * *is_vector (1 if a [N] suffix is present), and *length (the vector N, or 1
 * for a scalar).  The token after the type (which must be EOL for a
 * declaration) is left for the caller to read.
 *
 * Returns 0, VOLEITH_SHIPSHAPE_ERR_TYPE for a non-`byte`/`bit` scalar word,
 * VOLEITH_SHIPSHAPE_ERR_DECL for a malformed vector suffix, or a negative
 * lexer error.
 */
static int
parse_type(ss_lexer_t *lx, ss_token_t *after, int *is_bit, int *is_vector,
           size_t *length)
{
    ss_token_t t;
    int r;

    r = voleith_shipshape_lex_next_token(lx, &t);
    if (r < 0)
        return r;
    if (tok_word_is(&t, "byte"))
        *is_bit = 0;
    else if (tok_word_is(&t, "bit"))
        *is_bit = 1;
    else
        return VOLEITH_SHIPSHAPE_ERR_TYPE; /* missing or non-type scalar */

    /* Optional [N] suffix: read one token and branch on it. */
    r = voleith_shipshape_lex_next_token(lx, after);
    if (r < 0)
        return r;
    if (after->kind != SS_TOK_LBRACKET) {
        *is_vector = 0;
        *length = 1;
        return 0; /* scalar; *after is the token following the type */
    }

    if ((r = expect_tok(lx, SS_TOK_INT_LIT, &t)) != 0)
        return r;
    *length = (size_t)t.int_val;
    if ((r = expect_tok(lx, SS_TOK_RBRACKET, &t)) != 0)
        return r;
    *is_vector = 1;

    r = voleith_shipshape_lex_next_token(lx, after);
    if (r < 0)
        return r;
    return 0;
}

/*
 * Lower a WITNESS or INSTANCE declaration into the circuit and record it in
 * the wire table.  `length` wires are created in order (none for a
 * zero-length vector); a `bit` WITNESS additionally emits the booleanity
 * ASSERT_PRODUCT(w, w, w) per element (ISA 2.3).  The incremental MAX_WIRES
 * budget (S8) is checked before any wire is created.
 *
 * Returns 0, VOLEITH_SHIPSHAPE_ERR_LIMIT (MAX_VECTOR_LEN or MAX_WIRES), or
 * VOLEITH_SHIPSHAPE_ERR_ALLOC.
 */
static int
lower_input_decl(ss_parse_ctx_t *ctx, voleith_shipshape_decl_kind_t kind,
                 const char *name, size_t namelen, int is_bit, int is_vector,
                 size_t length)
{
    gf8_wire_id first = GF8_WIRE_ID_INVALID;
    ss_sym_t *s;
    int si;

    if (length > VOLEITH_SHIPSHAPE_MAX_VECTOR_LEN)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    if (budget_wires(ctx, length) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;

    for (size_t i = 0; i < length; i++) {
        gf8_wire_id w;

        if (kind == VOLEITH_SHIPSHAPE_DECL_INSTANCE)
            w = voleith_gf8_add_instance(ctx->circuit);
        else
            w = voleith_gf8_add_witness(ctx->circuit);
        if (w == GF8_WIRE_ID_INVALID)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        if (i == 0)
            first = w;
        if (is_bit && kind == VOLEITH_SHIPSHAPE_DECL_WITNESS)
            voleith_gf8_assert_product(ctx->circuit, w, w, w);
    }
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    si = ctx_add_sym(ctx, name, namelen);
    if (si < 0)
        return si;
    s = &ctx->syms[si];
    s->first_wire = first;
    s->length = length;
    s->is_vector = is_vector;
    s->is_bit = is_bit;
    s->is_decl = (ctx->inline_depth == 0); /* only top-level decls are public */
    s->decl_kind = kind;
    return 0;
}

/*
 * Parse a `WITNESS -> %w : type` or `INSTANCE -> %w : type` declaration; the
 * leading keyword has already been consumed.  A type annotation is REQUIRED
 * (FORMAT 3.2).  INSTANCE admits `byte` / `byte[N]` only: a `bit` instance
 * is not one of the bit origins of ISA 2.2 / 2.3 and is a type error.
 *
 * Returns 0 or a negative voleith_shipshape_error_t.
 */
static int
parse_input_decl(ss_parse_ctx_t *ctx, ss_lexer_t *lx,
                 voleith_shipshape_decl_kind_t kind)
{
    ss_token_t wire, after;
    const char *name;
    size_t namelen, length;
    int is_bit, is_vector, r;

    if ((r = expect_tok(lx, SS_TOK_ARROW, &after)) != 0)
        return r;
    if ((r = expect_tok(lx, SS_TOK_WIRE, &wire)) != 0)
        return r;
    if ((r = expect_tok(lx, SS_TOK_COLON, &after)) != 0)
        return r;

    if ((r = parse_type(lx, &after, &is_bit, &is_vector, &length)) != 0)
        return r;
    if (after.kind != SS_TOK_EOL)
        return VOLEITH_SHIPSHAPE_ERR_DECL; /* extra token after the type */

    if (kind == VOLEITH_SHIPSHAPE_DECL_INSTANCE) {
        if (is_bit)
            return VOLEITH_SHIPSHAPE_ERR_TYPE; /* no bit instances (ISA 2.3) */
        if (ctx->inline_depth > 0)
            return VOLEITH_SHIPSHAPE_ERR_DECL; /* INSTANCE top-level only (S3) */
    }

    /* The WIRE lexeme is "%name"; the SSA name excludes the sigil. */
    name = wire.lex + 1;
    namelen = wire.len - 1;
    if (ctx_lookup(ctx, name, namelen) >= 0)
        return VOLEITH_SHIPSHAPE_ERR_REDEF; /* S1 */

    return lower_input_decl(ctx, kind, name, namelen, is_bit, is_vector,
                            length);
}

/*
 * Parse a `CONST <byte> -> %w` (is_bit 0) or `CONST_BIT <0|1> -> %w`
 * (is_bit 1) declaration; the leading keyword has been consumed.  No type
 * annotation is permitted (FORMAT 3.2): the value's type is fixed by the
 * keyword.  Both lower to a single constant wire (ISA 2.3).
 *
 * Returns 0 or a negative voleith_shipshape_error_t.
 */
static int
parse_const_decl(ss_parse_ctx_t *ctx, ss_lexer_t *lx, int is_bit)
{
    ss_token_t val, wire, after;
    const char *name;
    size_t namelen;
    uint8_t byte;
    gf8_wire_id w;
    ss_sym_t *s;
    int si, r;

    if (is_bit) {
        if ((r = expect_tok(lx, SS_TOK_INT_LIT, &val)) != 0)
            return r;
        if (val.int_val > 1)
            return VOLEITH_SHIPSHAPE_ERR_DECL; /* CONST_BIT value not 0/1 */
        byte = (uint8_t)val.int_val;
    } else {
        if ((r = expect_tok(lx, SS_TOK_BYTE_LIT, &val)) != 0)
            return r;
        byte = val.byte_val;
    }

    if ((r = expect_tok(lx, SS_TOK_ARROW, &after)) != 0)
        return r;
    if ((r = expect_tok(lx, SS_TOK_WIRE, &wire)) != 0)
        return r;
    /* No type annotation, and nothing else, may follow (FORMAT 3.2). */
    if ((r = expect_tok(lx, SS_TOK_EOL, &after)) != 0)
        return r;

    name = wire.lex + 1;
    namelen = wire.len - 1;
    if (ctx_lookup(ctx, name, namelen) >= 0)
        return VOLEITH_SHIPSHAPE_ERR_REDEF; /* S1 */

    if (budget_wires(ctx, 1) != 0) /* one wire (ISA 5.1, S8) */
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;

    w = voleith_gf8_add_const(ctx->circuit, byte);
    if (w == GF8_WIRE_ID_INVALID || !voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    si = ctx_add_sym(ctx, name, namelen);
    if (si < 0)
        return si;
    s = &ctx->syms[si];
    s->first_wire = w;
    s->length = 1;
    s->is_vector = 0;
    s->is_bit = is_bit;
    s->is_decl = (ctx->inline_depth == 0); /* only top-level decls are public */
    s->decl_kind = VOLEITH_SHIPSHAPE_DECL_CONST;
    return 0;
}

/* ================================================================
 * Gates, assertions, sugar (W3.5)
 * ================================================================ */

/*
 * The squaring matrix for the header's field (ISA 2.4).  A LINEAR_MAP
 * carrying it canonicalizes to SQUARE (ISA 5.2 Step 3).
 */
static const uint8_t SQUARING_MATRIX[8] = {0x51, 0xD0, 0x22, 0xF0,
                                           0x94, 0x60, 0x28, 0xC0};

/* Read the next token of the gate line into gp->cur, recording any lexer
 * error stickily.  No-op once an error has been recorded. */
static void
gp_advance(ss_gp_t *gp)
{
    int r;

    if (gp->err != 0)
        return;
    r = voleith_shipshape_lex_next_token(gp->lx, &gp->cur);
    if (r < 0)
        gp->err = r;
}

/* Prime the gate parser on `lx` (positioned just after the head opcode):
 * reads the first operand-or-clause token into cur. */
static void
gp_init(ss_gp_t *gp, ss_lexer_t *lx)
{
    gp->lx = lx;
    gp->err = 0;
    gp->cur.kind = SS_TOK_EOL;
    gp_advance(gp);
}

/*
 * Require cur to be of kind `kind`; copy it to *out (if non-NULL) and
 * advance.  Records VOLEITH_SHIPSHAPE_ERR_GATE on a mismatch.  Returns the
 * sticky error (0 on success).
 */
static int
gp_eat(ss_gp_t *gp, ss_tok_kind_t kind, ss_token_t *out)
{
    if (gp->err != 0)
        return gp->err;
    if (gp->cur.kind != kind) {
        gp->err = VOLEITH_SHIPSHAPE_ERR_GATE;
        return gp->err;
    }
    if (out != NULL)
        *out = gp->cur;
    gp_advance(gp);
    return gp->err;
}

/* Require the statement to end here (cur is EOL). */
static int
gp_end(ss_gp_t *gp)
{
    if (gp->err != 0)
        return gp->err;
    if (gp->cur.kind != SS_TOK_EOL)
        gp->err = VOLEITH_SHIPSHAPE_ERR_GATE;
    return gp->err;
}

/*
 * Parse and resolve one scalar operand (FORMAT 3.3, 7.1 `operand`): a wire
 * name, optionally indexed `[i]` for a vector element.  Enforces
 * define-before-use (S2) and scalarity (S5): an undefined name is UNDEF, an
 * unindexed vector or an out-of-range / scalar index is TYPE.  Sets *wire to
 * the resolved circuit wire and, if non-NULL, *is_bit to its refinement
 * type.  Returns the sticky error (0 on success).
 */
static int
gp_operand(ss_gp_t *gp, ss_parse_ctx_t *ctx, gf8_wire_id *wire, int *is_bit)
{
    ss_token_t w, idx;
    const ss_sym_t *s;
    int si;

    if (gp_eat(gp, SS_TOK_WIRE, &w) != 0)
        return gp->err;
    si = ctx_lookup(ctx, w.lex + 1, w.len - 1);
    if (si < 0)
        return (gp->err = VOLEITH_SHIPSHAPE_ERR_UNDEF); /* S2 */
    s = &ctx->syms[si];

    if (gp->cur.kind == SS_TOK_LBRACKET) {
        if (!s->is_vector)
            return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE); /* index a scalar */
        gp_advance(gp);                                    /* consume '[' */
        if (gp_eat(gp, SS_TOK_INT_LIT, &idx) != 0)
            return gp->err;
        if ((size_t)idx.int_val >= s->length)
            return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE); /* range (S6) */
        if (gp_eat(gp, SS_TOK_RBRACKET, NULL) != 0)
            return gp->err;
        *wire = sym_elem(s, (size_t)idx.int_val);
    } else {
        if (s->is_vector)
            return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE); /* bare vector S5 */
        *wire = s->first_wire;
    }
    if (is_bit != NULL)
        *is_bit = s->is_bit;
    return 0;
}

/*
 * Parse a `-> %name` output clause, require end-of-statement, and bind the
 * fresh scalar name to `wire` with refinement `is_bit` (S1 SSA).  Returns
 * the sticky error (0 on success).
 */
static int
gp_bind(ss_gp_t *gp, ss_parse_ctx_t *ctx, gf8_wire_id wire, int is_bit)
{
    ss_token_t w;
    ss_sym_t *s;
    int si;

    if (gp_eat(gp, SS_TOK_ARROW, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_WIRE, &w) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    if (ctx_lookup(ctx, w.lex + 1, w.len - 1) >= 0)
        return (gp->err = VOLEITH_SHIPSHAPE_ERR_REDEF);
    si = ctx_add_sym(ctx, w.lex + 1, w.len - 1);
    if (si < 0)
        return (gp->err = si);
    s = &ctx->syms[si];
    s->first_wire = wire;
    s->length = 1;
    s->is_bit = is_bit;
    return 0;
}

/* ADD a b -> c (ISA 2.4). */
static int
gate_add(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a, b, c;

    if (gp_operand(gp, ctx, &a, NULL) != 0 ||
        gp_operand(gp, ctx, &b, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = voleith_gf8_add_xor(ctx->circuit, a, b);
    if (c == GF8_WIRE_ID_INVALID)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/* ADD_CONST a <byte> -> c (ISA 2.4). */
static int
gate_add_const(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    ss_token_t k;
    gf8_wire_id a, c;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_BYTE_LIT, &k) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = voleith_gf8_add_xor_const(ctx->circuit, a, k.byte_val);
    if (c == GF8_WIRE_ID_INVALID)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/*
 * LINEAR_MAP [M0 .. M7] a -> c (ISA 2.4).  A matrix equal to the squaring
 * matrix canonicalizes to SQUARE (Step 3); otherwise it lowers to a
 * linear-map wire entry.
 */
static int
gate_linear_map(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    uint8_t M[8];
    ss_token_t b;
    gf8_wire_id a, c;

    if (gp_eat(gp, SS_TOK_LBRACKET, NULL) != 0)
        return gp->err;
    for (int i = 0; i < 8; i++) {
        if (gp_eat(gp, SS_TOK_BYTE_LIT, &b) != 0)
            return gp->err;
        M[i] = b.byte_val;
    }
    if (gp_eat(gp, SS_TOK_RBRACKET, NULL) != 0)
        return gp->err;
    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    if (memcmp(M, SQUARING_MATRIX, 8) == 0)
        c = voleith_gf8_add_square(ctx->circuit, a);
    else
        c = voleith_gf8_add_linear_map(ctx->circuit, a, M);
    if (c == GF8_WIRE_ID_INVALID)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/* SQUARE a -> c (ISA 2.4). */
static int
gate_square(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a, c;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = voleith_gf8_add_square(ctx->circuit, a);
    if (c == GF8_WIRE_ID_INVALID)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/* MUL a b -> c (ISA 2.5). */
static int
gate_mul(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a, b, c;

    if (gp_operand(gp, ctx, &a, NULL) != 0 ||
        gp_operand(gp, ctx, &b, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = voleith_gf8_add_mul(ctx->circuit, a, b);
    if (c == GF8_WIRE_ID_INVALID || !voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/*
 * MUX sel a b -> c (ISA 2.5; surface order sel, a, b).  The selector must be
 * `bit`; the check happens before the three-gate expansion (Goal 4).  Lowers
 * via voleith_gf8_add_mux to diff = ADD(b,a), prod = MUL(sel,diff),
 * c = ADD(a,prod) (Step 2).
 */
static int
gate_mux(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id sel, a, b, c;
    int sel_bit;

    if (gp_operand(gp, ctx, &sel, &sel_bit) != 0)
        return gp->err;
    if (!sel_bit)
        return VOLEITH_SHIPSHAPE_ERR_TYPE; /* selector not a bit (2.2/2.5) */
    if (gp_operand(gp, ctx, &a, NULL) != 0 ||
        gp_operand(gp, ctx, &b, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, 3) != 0 || budget_gates(ctx, 3) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = voleith_gf8_add_mux(ctx->circuit, a, b, sel);
    if (c == GF8_WIRE_ID_INVALID || !voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return gp_bind(gp, ctx, c, 0);
}

/*
 * INV a -> c (ISA 2.6).  Lowers atomically to the canonical gadget (Step 4):
 *   c  = add_witness()
 *   a2 = add_square(a);  assert_product(a2, c, a)
 *   c2 = add_square(c);  assert_product(a, c2, c)
 * The output `c` is the witness wire and occupies a witness slot (ISA 2.11).
 */
static int
gate_inv(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    ss_token_t w;
    gf8_wire_id a, c, a2, c2;
    ss_sym_t *s;
    int si;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_ARROW, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_WIRE, &w) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    if (ctx_lookup(ctx, w.lex + 1, w.len - 1) >= 0)
        return VOLEITH_SHIPSHAPE_ERR_REDEF;
    if (budget_wires(ctx, 3) != 0 || /* c, a2, c2 */
        budget_gates(ctx, 2) != 0)   /* a2, c2 (c is a witness) */
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;

    c = voleith_gf8_add_witness(ctx->circuit);
    a2 = voleith_gf8_add_square(ctx->circuit, a);
    voleith_gf8_assert_product(ctx->circuit, a2, c, a);
    c2 = voleith_gf8_add_square(ctx->circuit, c);
    voleith_gf8_assert_product(ctx->circuit, a, c2, c);
    if (c == GF8_WIRE_ID_INVALID || a2 == GF8_WIRE_ID_INVALID ||
        c2 == GF8_WIRE_ID_INVALID || !voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    si = ctx_add_sym(ctx, w.lex + 1, w.len - 1);
    if (si < 0)
        return si;
    s = &ctx->syms[si];
    s->first_wire = c;
    s->length = 1;
    return 0;
}

/* SUM a1 .. an -> c, n >= 2 (ISA 2.4): n-1 chained ADD (Step 2). */
static int
gate_sum(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id acc, next;
    size_t count;

    if (gp_operand(gp, ctx, &acc, NULL) != 0)
        return gp->err;
    count = 1;
    while (gp->cur.kind == SS_TOK_WIRE) {
        if (gp_operand(gp, ctx, &next, NULL) != 0)
            return gp->err;
        if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
            return VOLEITH_SHIPSHAPE_ERR_LIMIT;
        acc = voleith_gf8_add_xor(ctx->circuit, acc, next);
        if (acc == GF8_WIRE_ID_INVALID)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        count++;
    }
    if (count < 2) /* grammar / S9: SUM has >= 2 inputs */
        return VOLEITH_SHIPSHAPE_ERR_GATE;
    return gp_bind(gp, ctx, acc, 0);
}

/* FROBENIUS_K <k> a -> c, k >= 1 (ISA 2.4): k chained SQUARE (Step 2, S9). */
static int
gate_frobenius(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    ss_token_t kt;
    gf8_wire_id a, c;
    size_t k;

    if (gp_eat(gp, SS_TOK_INT_LIT, &kt) != 0)
        return gp->err;
    k = (size_t)kt.int_val;
    if (k < 1) /* S9 */
        return VOLEITH_SHIPSHAPE_ERR_GATE;
    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (budget_wires(ctx, k) != 0 || budget_gates(ctx, k) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    c = a;
    for (size_t i = 0; i < k; i++) {
        c = voleith_gf8_add_square(ctx->circuit, c);
        if (c == GF8_WIRE_ID_INVALID)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    }
    return gp_bind(gp, ctx, c, 0);
}

/* ASSERT_ZERO a (ISA 2.7). */
static int
assert_zero_g(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    voleith_gf8_assert_zero(ctx->circuit, a);
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return 0;
}

/* ASSERT_EQUAL a b (ISA 2.7). */
static int
assert_equal_g(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a, b;

    if (gp_operand(gp, ctx, &a, NULL) != 0 ||
        gp_operand(gp, ctx, &b, NULL) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    voleith_gf8_assert_equal(ctx->circuit, a, b);
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return 0;
}

/* ASSERT_PRODUCT a b c (ISA 2.7). */
static int
assert_product_g(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    gf8_wire_id a, b, c;

    if (gp_operand(gp, ctx, &a, NULL) != 0 ||
        gp_operand(gp, ctx, &b, NULL) != 0 ||
        gp_operand(gp, ctx, &c, NULL) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    voleith_gf8_assert_product(ctx->circuit, a, b, c);
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return 0;
}

/*
 * ASSERT_BIT a -> a' : bit (ISA 2.7).  Sugar for ASSERT_PRODUCT(a, a, a)
 * (Step 2); the produced name a' aliases the SAME wire as a, narrowed to
 * bit.  No fresh wire is introduced.  The `: bit` annotation is required.
 */
static int
assert_bit_g(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    ss_token_t w;
    gf8_wire_id a;
    ss_sym_t *s;
    int si;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_ARROW, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_WIRE, &w) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_COLON, NULL) != 0)
        return gp->err;
    if (gp->err == 0 &&
        (gp->cur.kind != SS_TOK_WORD || !tok_word_is(&gp->cur, "bit")))
        return VOLEITH_SHIPSHAPE_ERR_TYPE; /* the ": bit" is required */
    gp_advance(gp);
    if (gp_end(gp) != 0)
        return gp->err;
    if (ctx_lookup(ctx, w.lex + 1, w.len - 1) >= 0)
        return VOLEITH_SHIPSHAPE_ERR_REDEF;

    voleith_gf8_assert_product(ctx->circuit, a, a, a);
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    si = ctx_add_sym(ctx, w.lex + 1, w.len - 1);
    if (si < 0)
        return si;
    s = &ctx->syms[si];
    s->first_wire = a; /* same wire, refined to bit (ISA 2.7) */
    s->length = 1;
    s->is_bit = 1;
    return 0;
}

/*
 * ASSERT_CONST a <byte> (ISA 2.7).  Sugar for ASSERT_ZERO(ADD_CONST(a, k))
 * (Step 2): an XOR-const wire is emitted and asserted zero.
 */
static int
assert_const_g(ss_parse_ctx_t *ctx, ss_gp_t *gp)
{
    ss_token_t k;
    gf8_wire_id a, t;

    if (gp_operand(gp, ctx, &a, NULL) != 0)
        return gp->err;
    if (gp_eat(gp, SS_TOK_BYTE_LIT, &k) != 0)
        return gp->err;
    if (gp_end(gp) != 0)
        return gp->err;
    if (budget_wires(ctx, 1) != 0 || budget_gates(ctx, 1) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    t = voleith_gf8_add_xor_const(ctx->circuit, a, k.byte_val);
    if (t == GF8_WIRE_ID_INVALID)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    voleith_gf8_assert_zero(ctx->circuit, t);
    if (!voleith_gf8_circuit_ok(ctx->circuit))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    return 0;
}

/*
 * Dispatch a gate or assertion line whose head WORD is `head` (already
 * matched as neither a declaration keyword nor "subcircuit").  Unknown
 * opcodes are VOLEITH_SHIPSHAPE_ERR_GATE.  Returns 0 or a negative
 * voleith_shipshape_error_t.
 */
static int
parse_gate_line(ss_parse_ctx_t *ctx, ss_lexer_t *lx, const ss_token_t *head)
{
    ss_gp_t gp;
    int r;

    gp_init(&gp, lx);

    if (tok_word_is(head, "ADD"))
        r = gate_add(ctx, &gp);
    else if (tok_word_is(head, "ADD_CONST"))
        r = gate_add_const(ctx, &gp);
    else if (tok_word_is(head, "LINEAR_MAP"))
        r = gate_linear_map(ctx, &gp);
    else if (tok_word_is(head, "SQUARE"))
        r = gate_square(ctx, &gp);
    else if (tok_word_is(head, "MUL"))
        r = gate_mul(ctx, &gp);
    else if (tok_word_is(head, "MUX"))
        r = gate_mux(ctx, &gp);
    else if (tok_word_is(head, "INV"))
        r = gate_inv(ctx, &gp);
    else if (tok_word_is(head, "SUM"))
        r = gate_sum(ctx, &gp);
    else if (tok_word_is(head, "FROBENIUS_K"))
        r = gate_frobenius(ctx, &gp);
    else if (tok_word_is(head, "ASSERT_ZERO"))
        r = assert_zero_g(ctx, &gp);
    else if (tok_word_is(head, "ASSERT_EQUAL"))
        r = assert_equal_g(ctx, &gp);
    else if (tok_word_is(head, "ASSERT_PRODUCT"))
        r = assert_product_g(ctx, &gp);
    else if (tok_word_is(head, "ASSERT_BIT"))
        r = assert_bit_g(ctx, &gp);
    else if (tok_word_is(head, "ASSERT_CONST"))
        r = assert_const_g(ctx, &gp);
    else
        r = VOLEITH_SHIPSHAPE_ERR_GATE; /* unknown opcode */

    return r;
}

/* ================================================================
 * Subcircuits, inlining, regions (W3.6)
 * ================================================================ */

/* Resolve element `idx` of a vector (or scalar) symbol to its wire. */
static gf8_wire_id
sym_elem(const ss_sym_t *s, size_t idx)
{
    if (s->elems != NULL)
        return s->elems[idx];
    return s->first_wire + (gf8_wire_id)idx;
}

/* Append a wire to a wire list; returns 0 or VOLEITH_SHIPSHAPE_ERR_ALLOC. */
static int
wlist_push(ss_wlist_t *l, gf8_wire_id v)
{
    if (l->n == l->cap) {
        size_t nc = l->cap == 0 ? 8 : l->cap * 2;
        gf8_wire_id *p;

        if (nc > SIZE_MAX / sizeof(*p)) /* L-N4 */
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        p = realloc(l->w, nc * sizeof(*p));
        if (p == NULL)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        l->w = p;
        l->cap = nc;
    }
    l->w[l->n++] = v;
    return 0;
}

static void
wlist_free(ss_wlist_t *l)
{
    free(l->w);
    l->w = NULL;
    l->n = 0;
    l->cap = 0;
}

/*
 * Parse a type annotation off the gate parser's token stream (the `byte` /
 * `bit` scalar word is `gp->cur`).  Mirrors parse_type but over the
 * lookahead parser, for subcircuit signatures.  Sets *is_bit / *is_vector /
 * *length and consumes the type, leaving the following token in gp->cur.
 */
static int
gp_type(ss_gp_t *gp, int *is_bit, int *is_vector, size_t *length)
{
    ss_token_t t;

    if (gp->err != 0)
        return gp->err;
    if (tok_word_is(&gp->cur, "byte"))
        *is_bit = 0;
    else if (tok_word_is(&gp->cur, "bit"))
        *is_bit = 1;
    else
        return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE);
    gp_advance(gp);

    if (gp->cur.kind != SS_TOK_LBRACKET) {
        *is_vector = 0;
        *length = 1;
        return gp->err;
    }
    gp_advance(gp); /* consume '[' */
    if (gp_eat(gp, SS_TOK_INT_LIT, &t) != 0)
        return gp->err;
    *length = (size_t)t.int_val;
    if (gp_eat(gp, SS_TOK_RBRACKET, NULL) != 0)
        return gp->err;
    *is_vector = 1;
    return gp->err;
}

/* True iff PATH/WORD token `t`'s lexeme begins with the C string `pre`. */
static int
starts_with(const ss_token_t *t, const char *pre)
{
    size_t n = strlen(pre);

    return t->len >= n && memcmp(t->lex, pre, n) == 0;
}

/* Find a defined subcircuit by name (slice [name, name+len)); NULL if none. */
static const ss_subckt_t *
find_def(const ss_parse_ctx_t *ctx, const char *name, size_t len)
{
    for (size_t i = 0; i < ctx->n_defs; i++) {
        const char *d = ctx->defs[i].name;

        if (strlen(d) == len && memcmp(d, name, len) == 0)
            return &ctx->defs[i];
    }
    return NULL;
}

/* Free a parameter / output list and its owned names. */
static void
free_params(ss_param_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        free(p[i].name);
    free(p);
}

/*
 * Parse a parenthesized signature parameter list off `gp`, starting at the
 * token after '(' and ending with gp->cur == ')'.  An empty list is legal.
 * Allocates *out (NULL when empty) and sets *n_out.  Returns 0 or a negative
 * voleith_shipshape_error_t; on failure *out is freed and left NULL.
 */
static int
parse_param_list(ss_gp_t *gp, ss_param_t **out, size_t *n_out)
{
    ss_param_t *params = NULL;
    size_t n = 0, cap = 0;
    int r = 0;

    *out = NULL;
    *n_out = 0;
    if (gp->cur.kind == SS_TOK_RPAREN)
        return 0; /* zero parameters */

    for (;;) {
        ss_token_t wire;
        int is_bit, is_vector;
        size_t length;

        if (gp_eat(gp, SS_TOK_WIRE, &wire) != 0) {
            r = gp->err;
            goto fail;
        }
        if (gp_eat(gp, SS_TOK_COLON, NULL) != 0) {
            r = gp->err;
            goto fail;
        }
        if (gp_type(gp, &is_bit, &is_vector, &length) != 0) {
            r = gp->err;
            goto fail;
        }
        if (length > VOLEITH_SHIPSHAPE_MAX_VECTOR_LEN) {
            r = VOLEITH_SHIPSHAPE_ERR_LIMIT;
            goto fail;
        }

        if (n == cap) {
            size_t nc = cap == 0 ? 4 : cap * 2;
            ss_param_t *p;

            if (nc > SIZE_MAX / sizeof(*p)) {
                r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                goto fail;
            }
            p = realloc(params, nc * sizeof(*p));
            if (p == NULL) {
                r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                goto fail;
            }
            params = p;
            cap = nc;
        }
        params[n].name = dup_name(wire.lex + 1, wire.len - 1);
        if (params[n].name == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto fail;
        }
        params[n].is_bit = is_bit;
        params[n].is_vector = is_vector;
        params[n].length = is_vector ? length : 1;
        n++;

        if (gp->cur.kind == SS_TOK_COMMA) {
            gp_advance(gp);
            continue;
        }
        break;
    }
    *out = params;
    *n_out = n;
    return 0;

fail:
    free_params(params, n);
    return r;
}

/*
 * Parse a `subcircuit user/... (params) [-> (outs)] {` definition line and
 * capture its body range, then store it in ctx->defs.  The `subcircuit`
 * keyword has been consumed.  Definitions are top-level only (S: no nesting),
 * `user/*` only (S4).  Returns 0 or a negative voleith_shipshape_error_t.
 */
static int
parse_subckt_def(ss_parse_ctx_t *ctx, ss_lexer_t *lx)
{
    ss_gp_t gp;
    ss_token_t path;
    ss_param_t *params = NULL, *outputs = NULL;
    size_t n_params = 0, n_outputs = 0;
    const char *body_start, *body_end, *line_start;
    ss_subckt_t *def;
    char *name = NULL;
    int r;

    if (ctx->inline_depth > 0)
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* no nested definitions */

    gp_init(&gp, lx);
    if (gp_eat(&gp, SS_TOK_PATH, &path) != 0)
        return gp.err;
    if (!starts_with(&path, "user/"))
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* defs are user/* (S4) */
    if (find_def(ctx, path.lex, path.len) != NULL)
        return VOLEITH_SHIPSHAPE_ERR_REDEF; /* duplicate definition (S1) */

    if (gp_eat(&gp, SS_TOK_LPAREN, NULL) != 0)
        return gp.err;
    if ((r = parse_param_list(&gp, &params, &n_params)) != 0)
        return r;
    if (gp_eat(&gp, SS_TOK_RPAREN, NULL) != 0) {
        free_params(params, n_params);
        return gp.err;
    }

    if (gp.cur.kind == SS_TOK_ARROW) {
        gp_advance(&gp);
        if (gp_eat(&gp, SS_TOK_LPAREN, NULL) != 0) {
            free_params(params, n_params);
            return gp.err;
        }
        if ((r = parse_param_list(&gp, &outputs, &n_outputs)) != 0) {
            free_params(params, n_params);
            return r;
        }
        if (gp_eat(&gp, SS_TOK_RPAREN, NULL) != 0) {
            free_params(params, n_params);
            free_params(outputs, n_outputs);
            return gp.err;
        }
    }

    if (gp_eat(&gp, SS_TOK_LBRACE, NULL) != 0 || gp_end(&gp) != 0) {
        free_params(params, n_params);
        free_params(outputs, n_outputs);
        return gp.err != 0 ? gp.err : VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT;
    }

    /* path.lex points into lx->line, which the body-capture reads below
     * overwrite; the name must be copied out before the first of them. */
    name = dup_name(path.lex, path.len);
    if (name == NULL) {
        r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto fail;
    }

    /* Body runs from the next line to the line whose head token is '}'. */
    body_start = lx->pos;
    body_end = lx->pos;
    for (;;) {
        ss_token_t h;

        line_start = lx->pos;
        r = voleith_shipshape_lex_read_line(lx);
        if (r == 1) {
            r = VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* unterminated body */
            goto fail;
        }
        if (r < 0)
            goto fail; /* charset / line-too-long */
        r = voleith_shipshape_lex_next_token(lx, &h);
        if (r < 0)
            goto fail;
        if (h.kind == SS_TOK_RBRACE) {
            ss_token_t after;

            body_end = line_start;
            if ((r = voleith_shipshape_lex_next_token(lx, &after)) < 0)
                goto fail;
            if (after.kind != SS_TOK_EOL) {
                r = VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* junk after '}' */
                goto fail;
            }
            break;
        }
    }

    if (ctx->n_defs == ctx->cap_defs) {
        size_t nc = ctx->cap_defs == 0 ? 8 : ctx->cap_defs * 2;
        ss_subckt_t *p;

        if (nc > SIZE_MAX / sizeof(*p)) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto fail;
        }
        p = realloc(ctx->defs, nc * sizeof(*p));
        if (p == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto fail;
        }
        ctx->defs = p;
        ctx->cap_defs = nc;
    }
    def = &ctx->defs[ctx->n_defs];
    def->name = name;
    def->params = params;
    def->n_params = n_params;
    def->outputs = outputs;
    def->n_outputs = n_outputs;
    def->body_start = body_start;
    def->body_end = body_end;
    ctx->n_defs++;
    return 0;

fail:
    free(name);
    free_params(params, n_params);
    free_params(outputs, n_outputs);
    return r;
}

/*
 * Resolve one operand (a wire name, optionally indexed) into the wire list
 * `out`, appending its wire(s): one for a scalar or `%v[i]`, all N for a
 * whole vector `%v`.  Enforces define-before-use (S2) and index range (S6).
 */
static int
resolve_operand_wires(ss_gp_t *gp, ss_parse_ctx_t *ctx, ss_wlist_t *out)
{
    ss_token_t w, idx;
    const ss_sym_t *s;
    int si, r;

    if (gp_eat(gp, SS_TOK_WIRE, &w) != 0)
        return gp->err;
    si = ctx_lookup(ctx, w.lex + 1, w.len - 1);
    if (si < 0)
        return (gp->err = VOLEITH_SHIPSHAPE_ERR_UNDEF);
    s = &ctx->syms[si];

    if (gp->cur.kind == SS_TOK_LBRACKET) {
        if (!s->is_vector)
            return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE);
        gp_advance(gp);
        if (gp_eat(gp, SS_TOK_INT_LIT, &idx) != 0)
            return gp->err;
        if ((size_t)idx.int_val >= s->length)
            return (gp->err = VOLEITH_SHIPSHAPE_ERR_TYPE);
        if (gp_eat(gp, SS_TOK_RBRACKET, NULL) != 0)
            return gp->err;
        if ((r = wlist_push(out, sym_elem(s, (size_t)idx.int_val))) != 0)
            return (gp->err = r);
    } else if (s->is_vector) {
        for (size_t i = 0; i < s->length; i++)
            if ((r = wlist_push(out, sym_elem(s, i))) != 0)
                return (gp->err = r);
    } else {
        if ((r = wlist_push(out, s->first_wire)) != 0)
            return (gp->err = r);
    }
    return 0;
}

/*
 * Resolve one call argument (`operand ( "++" operand )*`) into `out`: the
 * concatenation of its operands' wire lists (FORMAT 3.4, S6).
 */
static int
resolve_arg(ss_gp_t *gp, ss_parse_ctx_t *ctx, ss_wlist_t *out)
{
    if (resolve_operand_wires(gp, ctx, out) != 0)
        return gp->err;
    while (gp->cur.kind == SS_TOK_PLUSPLUS) {
        gp_advance(gp);
        if (resolve_operand_wires(gp, ctx, out) != 0)
            return gp->err;
    }
    return 0;
}

/*
 * Reserve the next region marker for a call to `name` (ISA 5.2 Step 7):
 * record the name and the current witness count, leaving n_witness 0 for
 * the caller to patch once the body is in.  Writes the marker's index to
 * *region_idx and the recorded witness count to *first_witness.  Returns
 * 0 or VOLEITH_SHIPSHAPE_ERR_ALLOC.
 */
static int
region_reserve(ss_parse_ctx_t *ctx, const char *name, size_t *region_idx,
               size_t *first_witness)
{
    size_t fw = voleith_gf8_circuit_witness_count(ctx->circuit);

    if (ctx->n_regions == ctx->cap_regions) {
        size_t nc = ctx->cap_regions == 0 ? 8 : ctx->cap_regions * 2;
        voleith_shipshape_region_t *p;

        if (nc > SIZE_MAX / sizeof(*p)) /* L-N4 */
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        p = realloc(ctx->regions, nc * sizeof(*p));
        if (p == NULL)
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        ctx->regions = p;
        ctx->cap_regions = nc;
    }
    ctx->regions[ctx->n_regions].name = dup_name(name, strlen(name));
    if (ctx->regions[ctx->n_regions].name == NULL)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    ctx->regions[ctx->n_regions].first_witness = fw;
    ctx->regions[ctx->n_regions].n_witness = 0;
    ctx->regions[ctx->n_regions].inputs = NULL;
    ctx->regions[ctx->n_regions].n_inputs = 0;
    ctx->regions[ctx->n_regions].cv2_valid = 0;
    ctx->regions[ctx->n_regions].cv2_type_id = 0;
    ctx->regions[ctx->n_regions].cv2_n_params = 0;
    ctx->regions[ctx->n_regions].cv2_depth_param = 0;
    ctx->regions[ctx->n_regions].cv2_leaf_param = 0;
    for (size_t ci = 0; ci < VOLEITH_SHIPSHAPE_REG_MAX_PARAMS; ci++)
        ctx->regions[ctx->n_regions].cv2_params[ci] = 0;
    *region_idx = ctx->n_regions++;
    *first_witness = fw;
    return 0;
}

/*
 * Inline a resolved call of `def` with `n_args` argument wire lists into the
 * circuit (ISA 5.2 Step 1), binding the `n_outs` output names of `outs` in
 * the caller's (current) scope.  Emits one region marker.  Enforces
 * MAX_INLINE_DEPTH (S8), arity, and the S6 length match.  Returns 0 or a
 * negative voleith_shipshape_error_t.
 */
static int
inline_call(ss_parse_ctx_t *ctx, const ss_subckt_t *def, ss_wlist_t *args,
            size_t n_args, ss_token_t *outs, size_t n_outs)
{
    ss_sym_t *parent_syms;
    size_t parent_n, parent_cap, region_idx, first_witness;
    ss_wlist_t *out_wires = NULL;
    ss_lexer_t blx;
    int r = 0, have_blx = 0;

    if (ctx->inline_depth >= VOLEITH_SHIPSHAPE_MAX_INLINE_DEPTH)
        return VOLEITH_SHIPSHAPE_ERR_INLINE_DEPTH;
    if (n_args != def->n_params || n_outs != def->n_outputs)
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* arity (S7) */
    for (size_t i = 0; i < n_args; i++)
        if (args[i].n != def->params[i].length)
            return VOLEITH_SHIPSHAPE_ERR_TYPE; /* length mismatch (S6) */

    /*
     * Reserve a region marker (patched with the witness span at the end).
     * user/* regions never dispatch to a Tier 2a backend, so inputs are
     * intentionally not recorded (they remain NULL/0 from region_reserve).
     */
    if ((r = region_reserve(ctx, def->name, &region_idx, &first_witness)) != 0)
        return r;

    /* Swap in a fresh body scope; the parent scope is restored at the end. */
    parent_syms = ctx->syms;
    parent_n = ctx->n_syms;
    parent_cap = ctx->cap_syms;
    ctx->syms = NULL;
    ctx->n_syms = 0;
    ctx->cap_syms = 0;
    ctx->inline_depth++;

    /* Bind each parameter to its argument's wires in the body scope. */
    for (size_t i = 0; i < n_args; i++) {
        const ss_param_t *pm = &def->params[i];
        ss_sym_t *s;
        int si = ctx_add_sym(ctx, pm->name, strlen(pm->name));

        if (si < 0) {
            r = si;
            goto restore;
        }
        s = &ctx->syms[si];
        s->is_bit = pm->is_bit;
        s->is_vector = pm->is_vector;
        s->length = pm->length;
        if (pm->is_vector) {
            s->elems = calloc(pm->length ? pm->length : 1, sizeof(gf8_wire_id));
            if (s->elems == NULL) {
                r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                goto restore;
            }
            for (size_t k = 0; k < pm->length; k++)
                s->elems[k] = args[i].w[k];
            s->first_wire = pm->length ? args[i].w[0] : GF8_WIRE_ID_INVALID;
        } else {
            s->first_wire = args[i].w[0];
        }
    }

    /* Re-lex and parse the body over its captured byte range. */
    r = voleith_shipshape_lex_init(
        &blx, def->body_start, (size_t)(def->body_end - def->body_start),
        ctx->eff->max_line_bytes, VOLEITH_SHIPSHAPE_MAX_IDENT_LEN);
    if (r != 0)
        goto restore;
    have_blx = 1;
    for (;;) {
        ss_token_t h;

        r = voleith_shipshape_lex_read_line(&blx);
        if (r == 1) {
            r = 0;
            break;
        }
        if (r < 0)
            break;
        r = voleith_shipshape_lex_next_token(&blx, &h);
        if (r < 0)
            break;
        if (h.kind == SS_TOK_EOL)
            continue;
        r = parse_statement(ctx, &blx, &h);
        if (r != 0)
            break;
    }
    if (r != 0)
        goto restore;

    /* Capture the body's output wires before the body scope is dropped. */
    if (n_outs > 0) {
        out_wires = calloc(n_outs, sizeof(*out_wires));
        if (out_wires == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto restore;
        }
        for (size_t j = 0; j < def->n_outputs; j++) {
            const ss_param_t *op = &def->outputs[j];
            int si = ctx_lookup(ctx, op->name, strlen(op->name));
            const ss_sym_t *s;

            if (si < 0) {
                r = VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* output undefined */
                goto restore;
            }
            s = &ctx->syms[si];
            if (s->is_vector != op->is_vector || s->length != op->length) {
                r = VOLEITH_SHIPSHAPE_ERR_TYPE; /* output shape mismatch */
                goto restore;
            }
            if (op->is_bit && !s->is_bit) {
                /* A bit-declared output must be backed by a bit wire so the
                 * caller's refinement is sound (ISA 2.2). */
                r = VOLEITH_SHIPSHAPE_ERR_TYPE;
                goto restore;
            }
            for (size_t k = 0; k < op->length; k++)
                if ((r = wlist_push(&out_wires[j], sym_elem(s, k))) != 0)
                    goto restore;
        }
    }

    r = 0;

restore:
    if (have_blx)
        voleith_shipshape_lex_free(&blx);
    /* Drop the body scope and restore the caller's scope. */
    free_syms(ctx);
    ctx->syms = parent_syms;
    ctx->n_syms = parent_n;
    ctx->cap_syms = parent_cap;
    ctx->inline_depth--;
    ctx->regions[region_idx].n_witness =
        voleith_gf8_circuit_witness_count(ctx->circuit) - first_witness;

    /* Bind the call's output names in the caller's scope (S1, S7). */
    if (r == 0) {
        for (size_t j = 0; j < n_outs; j++) {
            const ss_param_t *op = &def->outputs[j];
            ss_token_t *nm = &outs[j];
            ss_sym_t *s;
            int si;

            if (ctx_lookup(ctx, nm->lex + 1, nm->len - 1) >= 0) {
                r = VOLEITH_SHIPSHAPE_ERR_REDEF;
                break;
            }
            si = ctx_add_sym(ctx, nm->lex + 1, nm->len - 1);
            if (si < 0) {
                r = si;
                break;
            }
            s = &ctx->syms[si];
            s->is_bit = op->is_bit;
            s->is_vector = op->is_vector;
            s->length = op->length;
            if (op->is_vector) {
                s->elems =
                    calloc(op->length ? op->length : 1, sizeof(gf8_wire_id));
                if (s->elems == NULL) {
                    r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                    break;
                }
                for (size_t k = 0; k < op->length; k++)
                    s->elems[k] = out_wires[j].w[k];
                s->first_wire =
                    op->length ? out_wires[j].w[0] : GF8_WIRE_ID_INVALID;
            } else {
                s->first_wire = out_wires[j].w[0];
            }
        }
    }

    if (out_wires != NULL) {
        for (size_t j = 0; j < n_outs; j++)
            wlist_free(&out_wires[j]);
        free(out_wires);
    }
    return r;
}

/* ================================================================
 * Tier 2a registry calls (W3.7)
 * ================================================================ */

/*
 * Find a `stdlib/crypto/*` name (slice [name, name+len)) in the frozen
 * crypto-v1 table.  Returns the entry index, or -1 if the name is not
 * registered (Goal 2 rule ii: no fallback of any kind).
 */
static int
registry_lookup(const char *name, size_t len)
{
    for (size_t i = 0; i < voleith_shipshape_registry_count; i++) {
        const char *fqn = voleith_shipshape_registry[i].fqn;

        if (strlen(fqn) == len && memcmp(fqn, name, len) == 0)
            return (int)i;
    }
    return -1;
}

/*
 * Find a `stdlib/crypto/*` name in the frozen crypto-v2 hash-parametric
 * table.  Returns the entry index, or -1 if the name is not registered.
 */
static int
registry_lookup_hash(const char *name, size_t len)
{
    for (size_t i = 0; i < voleith_shipshape_reg_hash_count; i++) {
        const char *fqn = voleith_shipshape_reg_hash[i].fqn;

        if (strlen(fqn) == len && memcmp(fqn, name, len) == 0)
            return (int)i;
    }
    return -1;
}

/*
 * Lower a call to frozen-table entry `idx` with `n_args` resolved argument
 * wire lists, binding the single output name of `outs` in the caller's
 * scope (SPEC 6.2, 7.1, 7.2).  The length parameter of a PARAMETRIC entry
 * is inferred from the argument in the signature's inferred slot; bounds
 * and the derived block count are checked before any gate is emitted, with
 * the entry's invs as a pre-emission lower bound on the wire budget (the
 * exact count is re-checked after the body is in, which also preserves
 * budget_wires' invariant that the circuit never exceeds max_wires).
 * Emits one region marker named by the FQN.  Returns 0 or a negative
 * voleith_shipshape_error_t.
 */
static int
registry_call(ss_parse_ctx_t *ctx, size_t idx, ss_wlist_t *args, size_t n_args,
              ss_token_t *outs, size_t n_outs)
{
    const voleith_shipshape_reg_entry_t *e = &voleith_shipshape_registry[idx];
    uint32_t in_len[VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS], out_len, param;
    size_t n_inputs, blocks, invs, n_in_total, region_idx, first_witness;
    gf8_wire_id *in_flat = NULL, *out_w = NULL;
    const char *live_fqn;
    int out_is_vector, r;

    /* Fail closed if the frozen table and the linked live builders have
     * diverged (CI keeps them byte-identical; Goal 2 rule iii). */
    if (voleith_shipshape_registry_descriptor(idx, &live_fqn, NULL, NULL, NULL,
                                              NULL) != 0 ||
        strcmp(live_fqn, e->fqn) != 0)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;
    if (voleith_shipshape_registry_signature(idx, &n_inputs, in_len, &out_len,
                                             &out_is_vector) != 0)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;

    if (n_args != n_inputs || n_outs != 1)
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* arity (S7) */

    /* Infer the length parameter and check the fixed lengths (S6, 7.1). */
    param = 0;
    for (size_t i = 0; i < n_args; i++) {
        if (in_len[i] == VOLEITH_SHIPSHAPE_REGISTRY_PARAM_LEN) {
            if (args[i].n < e->param_min || args[i].n > e->param_max)
                return VOLEITH_SHIPSHAPE_ERR_LIMIT;
            param = (uint32_t)args[i].n;
        } else if (args[i].n != (size_t)in_len[i]) {
            return VOLEITH_SHIPSHAPE_ERR_TYPE;
        }
    }

    /* Instantiation bounds, before any gate is emitted (SPEC 7.1). */
    if (voleith_shipshape_registry_cost(idx, param, &blocks, &invs) != 0)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;
    if (blocks > VOLEITH_SHIPSHAPE_MAX_BLOCKS_PER_OPCODE)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    /*
     * Cheap early-out on the witness-slot lower bound (invs <= wires added),
     * so an obviously-oversized call is rejected before a region is reserved
     * or arguments are flattened.  It is only a lower bound: the circuit's
     * incremental wire/gate caps (armed in parse_body) are what hard-bound
     * the body as the builder emits it.
     */
    if (budget_wires(ctx, invs) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;

    if ((r = region_reserve(ctx, e->fqn, &region_idx, &first_witness)) != 0)
        return r;

    /* Flatten the arguments into one signature-order wire array. */
    n_in_total = 0;
    for (size_t i = 0; i < n_args; i++)
        n_in_total += args[i].n;
    in_flat = calloc(n_in_total ? n_in_total : 1, sizeof(*in_flat));
    out_w = calloc(out_len ? out_len : 1, sizeof(*out_w));
    if (in_flat == NULL || out_w == NULL) {
        r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }
    n_in_total = 0;
    for (size_t i = 0; i < n_args; i++)
        for (size_t k = 0; k < args[i].n; k++)
            in_flat[n_in_total++] = args[i].w[k];

    /*
     * Record the flattened input wire ids on the region for Tier 2a dispatch
     * (W8.3a).  The copy is taken before registry_inline so the ids are
     * available regardless of whether the build succeeds or fails.
     */
    if (n_in_total > 0) {
        gf8_wire_id *inp = calloc(n_in_total, sizeof(*inp));

        if (inp == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto done;
        }
        memcpy(inp, in_flat, n_in_total * sizeof(*inp));
        ctx->regions[region_idx].inputs = inp;
        ctx->regions[region_idx].n_inputs = n_in_total;
    }

    if (voleith_shipshape_registry_inline(idx, ctx->circuit, in_flat, param,
                                          out_w) != 0) {
        r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }

    /*
     * The builder emits gates directly rather than through the budgeted gate
     * helpers, so the active wire/gate ceilings are enforced by the circuit's
     * incremental caps (armed in parse_body): a body that crosses one is
     * stopped mid-emission with alloc_ok cleared and the count pinned at the
     * cap.  A cleared ok flag with a count at the ceiling is a limit
     * violation; cleared for any other reason is an allocation failure.
     */
    if (!voleith_gf8_circuit_ok(ctx->circuit)) {
        if (voleith_gf8_circuit_wire_count(ctx->circuit) >=
                ctx->eff->max_wires ||
            voleith_gf8_circuit_gate_count(ctx->circuit) >= ctx->eff->max_gates)
            r = VOLEITH_SHIPSHAPE_ERR_LIMIT;
        else
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }
    ctx->regions[region_idx].n_witness =
        voleith_gf8_circuit_witness_count(ctx->circuit) - first_witness;

    /* Bind the call's output name in the caller's scope (S1, S7). */
    {
        ss_token_t *nm = &outs[0];
        ss_sym_t *s;
        int si;

        if (ctx_lookup(ctx, nm->lex + 1, nm->len - 1) >= 0) {
            r = VOLEITH_SHIPSHAPE_ERR_REDEF;
            goto done;
        }
        si = ctx_add_sym(ctx, nm->lex + 1, nm->len - 1);
        if (si < 0) {
            r = si;
            goto done;
        }
        s = &ctx->syms[si];
        s->is_bit = 0; /* every registry output is byte-typed (7.2) */
        s->is_vector = out_is_vector;
        s->length = out_len;
        if (out_is_vector) {
            /* Builder outputs are gate outputs, not consecutive ids. */
            s->elems = calloc(out_len ? out_len : 1, sizeof(gf8_wire_id));
            if (s->elems == NULL) {
                r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                goto done;
            }
            for (size_t k = 0; k < out_len; k++)
                s->elems[k] = out_w[k];
            s->first_wire = out_len ? out_w[0] : GF8_WIRE_ID_INVALID;
        } else {
            s->first_wire = out_w[0];
        }
    }
    r = 0;

done:
    free(in_flat);
    free(out_w);
    return r;
}

/*
 * Lower a call to a frozen hash-parametric entry `idx` with type selector
 * `vt` and `n_args` resolved argument wire lists.  Assertion-only entries
 * (out_is_node_vec == 0) bind no output; the single-output entry binds the
 * output name from `outs[0]` in the caller's scope.  Emits one region
 * marker named `fqn[typename]`.  Returns 0 or a negative
 * voleith_shipshape_error_t.
 */
static int
registry_call_hash(ss_parse_ctx_t *ctx, size_t idx,
                   const voleith_node_hash_vt *vt, ss_wlist_t *args,
                   size_t n_args, ss_token_t *outs, size_t n_outs)
{
    const voleith_shipshape_reg_hash_entry_t *e;
    const char *live_fqn;
    size_t node, blocks, invs, n_in_total, region_idx, first_witness;
    uint32_t params[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
    int param_set[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
    gf8_wire_id *in_flat = NULL, *out_w = NULL;
    size_t want_outs, out_len;
    size_t i, k;
    int r;
    char rname[128];
    const voleith_shipshape_node_hash_type_t *nht;
    int snr;

    e = &voleith_shipshape_reg_hash[idx];

    /* Fail-closed: live descriptor fqn must match frozen fqn. */
    if (voleith_shipshape_reg_hash_descriptor(idx, &live_fqn, NULL, NULL, NULL,
                                              NULL, NULL, NULL, NULL, NULL,
                                              NULL, NULL, NULL) != 0 ||
        strcmp(live_fqn, e->fqn) != 0)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;

    node = vt->node_bytes;

    /* Assertion-only entries have no output; one output otherwise. */
    want_outs = e->out_is_node_vec ? 1 : 0;
    if (n_args != (size_t)e->n_inputs || n_outs != want_outs)
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT;

    /*
     * I2: defense-in-depth on the frozen table.  Every index the lowering
     * below uses to address the REG_MAX_PARAMS-sized params[] / param_set[]
     * arrays (and the cv2_params[] copy target on the region) comes from the
     * compile-time frozen registry, not from the .ship file: e->n_params as a
     * count, e->depth_param / e->leaf_param as indices, and each PARAM input's
     * value as an index.  A violation is a registry-authoring error, not an
     * attack, but reject it fail-closed here so a malformed entry can never
     * drive an out-of-bounds access.  (The frozen table is runtime const data,
     * not expressible in a _Static_assert, so this is a one-shot runtime guard
     * at the use site.)
     */
    if (e->n_params > VOLEITH_SHIPSHAPE_REG_MAX_PARAMS ||
        e->depth_param >= VOLEITH_SHIPSHAPE_REG_MAX_PARAMS ||
        e->leaf_param >= VOLEITH_SHIPSHAPE_REG_MAX_PARAMS ||
        e->n_inputs > VOLEITH_SHIPSHAPE_REGISTRY_MAX_INPUTS)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;
    for (i = 0; i < (size_t)e->n_inputs; i++)
        if (e->in[i].kind == SS_ARGLEN_PARAM &&
            e->in[i].value >= VOLEITH_SHIPSHAPE_REG_MAX_PARAMS)
            return VOLEITH_SHIPSHAPE_ERR_REGISTRY;

    for (i = 0; i < VOLEITH_SHIPSHAPE_REG_MAX_PARAMS; i++) {
        params[i] = 0;
        param_set[i] = 0;
    }

    /*
     * PASS 1: bind PARAM lengths and check FIXED, left to right.
     * DEPTH_TIMES_NODE and NODE slots are deferred to pass 2 so that
     * depth is guaranteed bound before it is used.
     */
    for (i = 0; i < (size_t)e->n_inputs; i++) {
        switch (e->in[i].kind) {
        case SS_ARGLEN_FIXED:
            if (args[i].n != (size_t)e->in[i].value)
                return VOLEITH_SHIPSHAPE_ERR_TYPE;
            break;
        case SS_ARGLEN_PARAM:
            k = e->in[i].value;
            if (!param_set[k]) {
                if (args[i].n < (size_t)e->param_min[k] ||
                    args[i].n > (size_t)e->param_max[k])
                    return VOLEITH_SHIPSHAPE_ERR_LIMIT;
                params[k] = (uint32_t)args[i].n;
                param_set[k] = 1;
            } else if (args[i].n != (size_t)params[k]) {
                return VOLEITH_SHIPSHAPE_ERR_TYPE;
            }
            break;
        case SS_ARGLEN_DEPTH_TIMES_NODE:
        case SS_ARGLEN_NODE:
            /* defer */
            break;
        }
    }

    /* PASS 2: DEPTH_TIMES_NODE and NODE checks. */
    for (i = 0; i < (size_t)e->n_inputs; i++) {
        switch (e->in[i].kind) {
        case SS_ARGLEN_DEPTH_TIMES_NODE:
            if (!param_set[e->depth_param])
                return VOLEITH_SHIPSHAPE_ERR_TYPE;
            if (args[i].n != (size_t)params[e->depth_param] * node)
                return VOLEITH_SHIPSHAPE_ERR_TYPE;
            break;
        case SS_ARGLEN_NODE:
            if (args[i].n != node)
                return VOLEITH_SHIPSHAPE_ERR_TYPE;
            break;
        case SS_ARGLEN_FIXED:
        case SS_ARGLEN_PARAM:
            break;
        }
    }

    /*
     * Fixed-leaf check: if vt->fixed_leaf_bytes != 0, the effective leaf
     * data width must match it.  The same rule as build_standalone (n_params
     * == 3 identifies indexed_merkle, which uses leaf record = 2*tb + ib).
     */
    if (vt->fixed_leaf_bytes != 0) {
        size_t eff_leaf;

        if (e->n_params == 3)
            eff_leaf = (size_t)2 * params[0] + params[1]; /* 2*tb + ib */
        else
            eff_leaf = params[e->leaf_param];
        if (eff_leaf != vt->fixed_leaf_bytes)
            return VOLEITH_SHIPSHAPE_ERR_TYPE;
    }

    /* Cost + budget, before any gate is emitted. */
    if (voleith_shipshape_reg_hash_cost(idx, vt, params, &blocks, &invs) != 0)
        return VOLEITH_SHIPSHAPE_ERR_REGISTRY;
    if (blocks > VOLEITH_SHIPSHAPE_MAX_BLOCKS_PER_OPCODE)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;
    if (budget_wires(ctx, invs) != 0)
        return VOLEITH_SHIPSHAPE_ERR_LIMIT;

    /*
     * Build the region name "fqn[typename]" into a local buffer.  128 bytes
     * covers the longest fqn (48) + '[' + longest type name (16) + ']' + NUL.
     * Resolve the type name by matching the caller-supplied vt pointer against
     * the frozen node-hash type table (vt is the authoritative identity).
     */
    {
        size_t ti;

        nht = NULL;
        for (ti = 0; ti < voleith_shipshape_node_hash_types_count; ti++) {
            if (voleith_shipshape_node_hash_types[ti].vt == vt) {
                nht = &voleith_shipshape_node_hash_types[ti];
                break;
            }
        }
        if (nht == NULL)
            return VOLEITH_SHIPSHAPE_ERR_REGISTRY;
    }
    snr = snprintf(rname, sizeof(rname), "%s[%s]", e->fqn, nht->name);
    if (snr < 0 || (size_t)snr >= sizeof(rname))
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    if ((r = region_reserve(ctx, rname, &region_idx, &first_witness)) != 0)
        return r;

    /* Flatten args into one signature-order wire array. */
    n_in_total = 0;
    for (i = 0; i < n_args; i++)
        n_in_total += args[i].n;
    out_len = e->out_is_node_vec ? node : 1;
    in_flat = calloc(n_in_total > 0 ? n_in_total : 1, sizeof(*in_flat));
    out_w = calloc(out_len, sizeof(*out_w));
    if (in_flat == NULL || out_w == NULL) {
        r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }
    n_in_total = 0;
    for (i = 0; i < n_args; i++)
        for (k = 0; k < args[i].n; k++)
            in_flat[n_in_total++] = args[i].w[k];

    /*
     * Record the flattened input wire ids on the region for Tier 2a dispatch
     * (W8.3a).  Same pattern as registry_call: copy before reg_hash_inline so
     * the ids are available on all exit paths.
     */
    if (n_in_total > 0) {
        gf8_wire_id *inp = calloc(n_in_total, sizeof(*inp));

        if (inp == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto done;
        }
        memcpy(inp, in_flat, n_in_total * sizeof(*inp));
        ctx->regions[region_idx].inputs = inp;
        ctx->regions[region_idx].n_inputs = n_in_total;
    }

    /*
     * Record the crypto-v2 construction parameters on the region for Tier 2a
     * construction dispatch (W8.5a).  A construction backend reads these to
     * drive the path walk (node-hash type, depth, leaf/sk width) without
     * re-deriving them from the witness span.
     */
    ctx->regions[region_idx].cv2_valid = 1;
    ctx->regions[region_idx].cv2_type_id = nht->type_id;
    ctx->regions[region_idx].cv2_n_params = e->n_params;
    ctx->regions[region_idx].cv2_depth_param = e->depth_param;
    ctx->regions[region_idx].cv2_leaf_param = e->leaf_param;
    for (i = 0; i < e->n_params; i++)
        ctx->regions[region_idx].cv2_params[i] = params[i];

    if (voleith_shipshape_reg_hash_inline(idx, ctx->circuit, vt, params,
                                          in_flat, out_w) != 0) {
        r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }

    if (!voleith_gf8_circuit_ok(ctx->circuit)) {
        if (voleith_gf8_circuit_wire_count(ctx->circuit) >=
                ctx->eff->max_wires ||
            voleith_gf8_circuit_gate_count(ctx->circuit) >= ctx->eff->max_gates)
            r = VOLEITH_SHIPSHAPE_ERR_LIMIT;
        else
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
        goto done;
    }
    ctx->regions[region_idx].n_witness =
        voleith_gf8_circuit_witness_count(ctx->circuit) - first_witness;

    /* Bind the output only for entries that produce one (out_is_node_vec). */
    if (e->out_is_node_vec) {
        ss_token_t *nm = &outs[0];
        ss_sym_t *s;
        int si;

        if (ctx_lookup(ctx, nm->lex + 1, nm->len - 1) >= 0) {
            r = VOLEITH_SHIPSHAPE_ERR_REDEF;
            goto done;
        }
        si = ctx_add_sym(ctx, nm->lex + 1, nm->len - 1);
        if (si < 0) {
            r = si;
            goto done;
        }
        s = &ctx->syms[si];
        s->is_bit = 0;
        s->is_vector = 1;
        s->length = out_len;
        s->elems = calloc(out_len > 0 ? out_len : 1, sizeof(gf8_wire_id));
        if (s->elems == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
            goto done;
        }
        for (k = 0; k < out_len; k++)
            s->elems[k] = out_w[k];
        s->first_wire = out_len > 0 ? out_w[0] : GF8_WIRE_ID_INVALID;
    }
    r = 0;

done:
    free(in_flat);
    free(out_w);
    return r;
}

/*
 * Parse and inline a subcircuit call `path ( args ) [-> outs]`; `path` (the
 * head PATH token) has been consumed.  Routes by namespace: `user/*` inlines
 * the in-file definition; `stdlib/crypto/*` inlines the frozen-registry
 * entry's canonical body (W3.7); `stdlib/structural/*` and any other
 * namespace are errors (S4).  Returns 0 or a negative
 * voleith_shipshape_error_t.
 */
static int
parse_call(ss_parse_ctx_t *ctx, ss_lexer_t *lx, const ss_token_t *head)
{
    ss_gp_t gp;
    const ss_subckt_t *def = NULL;
    ss_wlist_t *args = NULL;
    ss_token_t *outs = NULL;
    size_t n_args = 0, cap_args = 0, n_outs = 0, cap_outs = 0;
    int reg_idx = -1, hash_idx = -1, r;
    const voleith_node_hash_vt *hash_vt = NULL;

    if (starts_with(head, "stdlib/crypto/")) {
        reg_idx = registry_lookup(head->lex, head->len);
        if (reg_idx < 0) {
            hash_idx = registry_lookup_hash(head->lex, head->len);
            if (hash_idx < 0)
                return VOLEITH_SHIPSHAPE_ERR_REGISTRY; /* unknown (Goal 2 ii) */
        }
    } else if (starts_with(head, "user/")) {
        def = find_def(ctx, head->lex, head->len);
        if (def == NULL)
            return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* undefined/forward (S2) */
    } else {
        return VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT; /* structural/unknown (S4) */
    }

    gp_init(&gp, lx);

    /*
     * Bracket dispatch (crypto-v2): insert before the LPAREN eat.
     *
     * v1 hit + bracket:  bracket is not permitted on v1 entries.
     * v2 hit + bracket:  parse type selector, resolve vt.
     * v2 hit + no bracket:  the bracket is mandatory; reject.
     */
    if (reg_idx >= 0 && gp.cur.kind == SS_TOK_LBRACKET) {
        /* v1 entry, no bracket allowed. */
        r = VOLEITH_SHIPSHAPE_ERR_REGISTRY;
        goto done;
    }
    if (hash_idx >= 0) {
        ss_token_t typetok;
        const voleith_shipshape_node_hash_type_t *nht;

        /* crypto-v2 entries require stdlib crypto-v2. */
        if (ctx->stdlib_version != 2) {
            r = VOLEITH_SHIPSHAPE_ERR_REGISTRY;
            goto done;
        }
        /* The bracket selector is mandatory. */
        if (gp.cur.kind != SS_TOK_LBRACKET) {
            r = VOLEITH_SHIPSHAPE_ERR_REGISTRY;
            goto done;
        }
        gp_advance(&gp); /* consume '[' */
        if (gp_eat(&gp, SS_TOK_WORD, &typetok) != 0) {
            r = gp.err;
            goto done;
        }
        nht =
            voleith_shipshape_node_hash_type_by_name(typetok.lex, typetok.len);
        if (nht == NULL) {
            r = VOLEITH_SHIPSHAPE_ERR_REGISTRY;
            goto done;
        }
        /* Two-type form (comma in bracket) is rejected: phase-1 is single. */
        if (gp.cur.kind == SS_TOK_COMMA) {
            r = VOLEITH_SHIPSHAPE_ERR_REGISTRY;
            goto done;
        }
        if (gp_eat(&gp, SS_TOK_RBRACKET, NULL) != 0) {
            r = gp.err;
            goto done;
        }
        hash_vt = nht->vt;
    }

    if (gp_eat(&gp, SS_TOK_LPAREN, NULL) != 0) {
        r = gp.err;
        goto done;
    }

    if (gp.cur.kind != SS_TOK_RPAREN) {
        for (;;) {
            if (n_args == cap_args) {
                size_t nc = cap_args == 0 ? 4 : cap_args * 2;
                ss_wlist_t *p;

                if (nc > SIZE_MAX / sizeof(*p)) {
                    r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                    goto done;
                }
                p = realloc(args, nc * sizeof(*p));
                if (p == NULL) {
                    r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                    goto done;
                }
                args = p;
                cap_args = nc;
            }
            memset(&args[n_args], 0, sizeof(args[n_args]));
            if (resolve_arg(&gp, ctx, &args[n_args]) != 0) {
                n_args++; /* count it so cleanup frees its list */
                r = gp.err;
                goto done;
            }
            n_args++;
            if (gp.cur.kind == SS_TOK_COMMA) {
                gp_advance(&gp);
                continue;
            }
            break;
        }
    }
    if (gp_eat(&gp, SS_TOK_RPAREN, NULL) != 0) {
        r = gp.err;
        goto done;
    }

    /* Optional output name list. */
    if (gp.cur.kind == SS_TOK_ARROW) {
        gp_advance(&gp);
        for (;;) {
            ss_token_t w;

            if (gp_eat(&gp, SS_TOK_WIRE, &w) != 0) {
                r = gp.err;
                goto done;
            }
            if (n_outs == cap_outs) {
                size_t nc = cap_outs == 0 ? 4 : cap_outs * 2;
                ss_token_t *p;

                if (nc > SIZE_MAX / sizeof(*p)) {
                    r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                    goto done;
                }
                p = realloc(outs, nc * sizeof(*p));
                if (p == NULL) {
                    r = VOLEITH_SHIPSHAPE_ERR_ALLOC;
                    goto done;
                }
                outs = p;
                cap_outs = nc;
            }
            outs[n_outs++] = w;
            if (gp.cur.kind == SS_TOK_COMMA) {
                gp_advance(&gp);
                continue;
            }
            break;
        }
    }
    if (gp_end(&gp) != 0) {
        r = gp.err;
        goto done;
    }

    if (def != NULL)
        r = inline_call(ctx, def, args, n_args, outs, n_outs);
    else if (hash_idx >= 0)
        r = registry_call_hash(ctx, (size_t)hash_idx, hash_vt, args, n_args,
                               outs, n_outs);
    else
        r = registry_call(ctx, (size_t)reg_idx, args, n_args, outs, n_outs);

done:
    for (size_t i = 0; i < n_args; i++)
        wlist_free(&args[i]);
    free(args);
    free(outs);
    return r;
}

/*
 * Dispatch one body statement whose head token is `head`.  Declarations, the
 * W3.5 gate / assertion opcodes, `subcircuit` definitions (head WORD), and
 * `path(...)` calls (head PATH, both `user/*` and the Tier 2a
 * `stdlib/crypto/*` registry) are parsed.
 *
 * Returns 0 or a negative voleith_shipshape_error_t.
 */
static int
parse_statement(ss_parse_ctx_t *ctx, ss_lexer_t *lx, const ss_token_t *head)
{
    if (head->kind == SS_TOK_PATH)
        return parse_call(ctx, lx, head);
    if (head->kind != SS_TOK_WORD)
        return VOLEITH_SHIPSHAPE_ERR_GATE; /* no statement starts here */

    if (tok_word_is(head, "WITNESS"))
        return parse_input_decl(ctx, lx, VOLEITH_SHIPSHAPE_DECL_WITNESS);
    if (tok_word_is(head, "INSTANCE"))
        return parse_input_decl(ctx, lx, VOLEITH_SHIPSHAPE_DECL_INSTANCE);
    if (tok_word_is(head, "CONST"))
        return parse_const_decl(ctx, lx, 0);
    if (tok_word_is(head, "CONST_BIT"))
        return parse_const_decl(ctx, lx, 1);
    if (tok_word_is(head, "subcircuit"))
        return parse_subckt_def(ctx, lx);

    return parse_gate_line(ctx, lx, head);
}

/*
 * Build the public file-order declaration table in *out from the is_decl
 * entries of the symbol table.  Returns 0 or VOLEITH_SHIPSHAPE_ERR_ALLOC; on
 * failure *out's declaration fields are left untouched (NULL / 0).
 */
static int
finalize_decls(ss_parse_ctx_t *ctx, voleith_shipshape_parsed_t *out)
{
    voleith_shipshape_decl_t *decls;
    size_t n = 0, j = 0;

    for (size_t i = 0; i < ctx->n_syms; i++)
        if (ctx->syms[i].is_decl)
            n++;
    if (n == 0)
        return 0;

    decls = calloc(n, sizeof(*decls));
    if (decls == NULL)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;

    for (size_t i = 0; i < ctx->n_syms; i++) {
        const ss_sym_t *s = &ctx->syms[i];
        char *name;

        if (!s->is_decl)
            continue;
        name = dup_name(s->name, strlen(s->name));
        if (name == NULL) {
            for (size_t k = 0; k < j; k++)
                free((void *)decls[k].name);
            free(decls);
            return VOLEITH_SHIPSHAPE_ERR_ALLOC;
        }
        decls[j].name = name;
        decls[j].first_wire = s->first_wire;
        decls[j].length = s->length;
        decls[j].kind = s->decl_kind;
        decls[j].is_bit = s->is_bit;
        decls[j].is_vector = s->is_vector;
        j++;
    }
    out->decls = decls;
    out->n_decls = n;
    return 0;
}

/* Release the current scope's symbol table, its names, and any explicit
 * element arrays; leaves the circuit untouched. */
static void
free_syms(ss_parse_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->n_syms; i++) {
        free(ctx->syms[i].name);
        free(ctx->syms[i].elems);
    }
    free(ctx->syms);
    ctx->syms = NULL;
    ctx->n_syms = 0;
    ctx->cap_syms = 0;
}

/* Release the subcircuit definition table and its owned names / params. */
static void
free_defs(ss_parse_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->n_defs; i++) {
        free(ctx->defs[i].name);
        free_params(ctx->defs[i].params, ctx->defs[i].n_params);
        free_params(ctx->defs[i].outputs, ctx->defs[i].n_outputs);
    }
    free(ctx->defs);
    ctx->defs = NULL;
    ctx->n_defs = 0;
    ctx->cap_defs = 0;
}

/* Release the region side table and its owned names and input wire arrays. */
static void
free_regions(ss_parse_ctx_t *ctx)
{
    for (size_t i = 0; i < ctx->n_regions; i++) {
        free((void *)ctx->regions[i].name);
        free(ctx->regions[i].inputs);
    }
    free(ctx->regions);
    ctx->regions = NULL;
    ctx->n_regions = 0;
    ctx->cap_regions = 0;
}

/* Release everything the parse context owns (circuit, symbol table,
 * definitions, regions).  Safe on a zeroed context. */
static void
ctx_free(ss_parse_ctx_t *ctx)
{
    voleith_gf8_circuit_free(ctx->circuit);
    free_syms(ctx);
    free_defs(ctx);
    free_regions(ctx);
    memset(ctx, 0, sizeof(*ctx));
}

/* ================================================================
 * Body grammar
 * ================================================================ */

/*
 * Parse the lexer / header / declaration / gate grammar over `buf` (`len`
 * bytes, already entry-validated) into a fresh circuit and declaration table
 * stored in *out.  Returns 0 on success or a negative
 * voleith_shipshape_error_t.
 *
 * On success *out owns the circuit and the declaration table.  On any
 * failure the partially built circuit and tables are released here and *out
 * is left as the caller's entry zeroing (FORMAT 4 first-error-stop).
 */
static int
parse_body(voleith_shipshape_parsed_t *out, const char *buf, size_t len,
           const voleith_shipshape_limits_t *eff)
{
    ss_parse_ctx_t ctx;
    ss_lexer_t lx;
    ss_token_t head;
    int r;

    memset(&ctx, 0, sizeof(ctx));
    ctx.eff = eff;
    ctx.buf = buf;
    ctx.buf_len = len;
    ctx.circuit = voleith_gf8_circuit_new();
    if (ctx.circuit == NULL)
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    /*
     * Arm the circuit's incremental wire/gate ceilings with the effective
     * limits (S8, SPEC 8.5).  This bounds bulk emitters that do not route
     * through the per-statement budget_* helpers (the Tier 2a registry
     * bodies, registry_call) the moment a ceiling is crossed, rather than
     * after the whole body has been materialized.
     */
    voleith_gf8_circuit_set_limits(ctx.circuit, eff->max_wires, eff->max_gates);

    r = voleith_shipshape_lex_init(&lx, buf, len, eff->max_line_bytes,
                                   VOLEITH_SHIPSHAPE_MAX_IDENT_LEN);
    if (r != 0) {
        ctx_free(&ctx);
        return r;
    }

    r = parse_header(&lx, &ctx.stdlib_version);
    if (r != 0)
        goto done;

    /* Body: one statement per non-blank line until end of input or error. */
    for (;;) {
        r = voleith_shipshape_lex_read_line(&lx);
        if (r == 1) {
            r = 0; /* end of input: the body is complete */
            break;
        }
        if (r < 0)
            break; /* charset / line-too-long */

        r = voleith_shipshape_lex_next_token(&lx, &head);
        if (r < 0)
            break;
        if (head.kind == SS_TOK_EOL)
            continue; /* blank or comment-only line */

        r = parse_statement(&ctx, &lx, &head);
        if (r != 0)
            break;
    }

done:
    voleith_shipshape_lex_free(&lx);
    if (r != 0) {
        ctx_free(&ctx);
        return r;
    }

    r = finalize_decls(&ctx, out);
    if (r != 0) {
        ctx_free(&ctx);
        return r;
    }

    /* Hand the circuit and the region side table to the caller; the symbol
     * table and definition table are parse-time only. */
    out->circuit = ctx.circuit;
    out->regions = ctx.regions;
    out->n_regions = ctx.n_regions;
    ctx.regions = NULL;
    ctx.n_regions = 0;
    ctx.cap_regions = 0;
    free_syms(&ctx);
    free_defs(&ctx);
    return 0;
}

/* ================================================================
 * Public API
 * ================================================================ */

int
voleith_shipshape_parse_buffer(voleith_shipshape_parsed_t *out, const char *buf,
                               size_t len,
                               const voleith_shipshape_limits_t *limits)
{
    voleith_shipshape_limits_t eff;
    int err;

    if (out == NULL)
        return VOLEITH_SHIPSHAPE_ERR_NULL_ARG;
    memset(out, 0, sizeof(*out));

    if (buf == NULL)
        return VOLEITH_SHIPSHAPE_ERR_NULL_ARG;

    resolve_limits(limits, &eff);

    if (len == 0)
        len = strlen(buf);
    if (len == 0)
        return VOLEITH_SHIPSHAPE_ERR_EMPTY;

    /* MAX_FILE_BYTES gate: checked before any parsing work (ISA 5.1). */
    if (len > eff.max_file_bytes)
        return VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG;

    err = parse_body(out, buf, len, &eff);
    if (err != 0) {
        /*
         * First-error-stop (FORMAT 4): parse_body releases its own partial
         * circuit and table on failure and writes nothing into *out, so the
         * caller's entry zeroing already holds.  Re-zero defensively in case
         * a future path leaves a partial result.
         */
        voleith_shipshape_parsed_free(out);
    }
    return err;
}

int
voleith_shipshape_parse_file(voleith_shipshape_parsed_t *out, const char *path,
                             const voleith_shipshape_limits_t *limits)
{
    voleith_shipshape_limits_t eff;
    FILE *fp;
    char *buf;
    long sz;
    int err;

    if (out == NULL)
        return VOLEITH_SHIPSHAPE_ERR_NULL_ARG;
    memset(out, 0, sizeof(*out));

    if (path == NULL)
        return VOLEITH_SHIPSHAPE_ERR_NULL_ARG;

    resolve_limits(limits, &eff);

    fp = fopen(path, "rb");
    if (fp == NULL)
        return VOLEITH_SHIPSHAPE_ERR_IO;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return VOLEITH_SHIPSHAPE_ERR_IO;
    }
    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return VOLEITH_SHIPSHAPE_ERR_IO;
    }

    /*
     * MAX_FILE_BYTES gate at the entry point: reject before allocating or
     * reading the file body (ISA 5.1).
     */
    if ((size_t)sz > eff.max_file_bytes) {
        fclose(fp);
        return VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG;
    }
    rewind(fp);

    buf = calloc((size_t)sz + 1, 1);
    if (buf == NULL) {
        fclose(fp);
        return VOLEITH_SHIPSHAPE_ERR_ALLOC;
    }

    if ((size_t)sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return VOLEITH_SHIPSHAPE_ERR_IO;
    }
    fclose(fp);
    /* buf[(size_t)sz] is already '\0' from calloc. */

    err = voleith_shipshape_parse_buffer(out, buf, (size_t)sz, limits);
    free(buf);
    return err;
}

void
voleith_shipshape_parsed_free(voleith_shipshape_parsed_t *p)
{
    if (p == NULL)
        return;
    voleith_gf8_circuit_free(p->circuit);
    for (size_t i = 0; i < p->n_decls; i++)
        free((void *)p->decls[i].name);
    free(p->decls);
    for (size_t i = 0; i < p->n_regions; i++) {
        free((void *)p->regions[i].name);
        free(p->regions[i].inputs);
    }
    free(p->regions);
    memset(p, 0, sizeof(*p));
}
