/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/bristol.c - Bristol Fashion circuit parser
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bristol.h"

/* ================================================================
 * Cursor
 * ================================================================ */

/*
 * Read-only cursor over an in-memory buffer.  pos advances as tokens are
 * consumed; end marks one past the last valid byte.
 */
typedef struct {
    const char *pos;
    const char *end;
} cursor_t;

/* ================================================================
 * Static prototypes
 * ================================================================ */

static void skip_ws_inline(cursor_t *);
static void skip_to_next_line(cursor_t *);
static int read_uint(cursor_t *, uint32_t *);
static int read_word(cursor_t *, char *, size_t);
static int parse_header_line1(cursor_t *, uint32_t *, uint32_t *);
static int parse_header_line2(cursor_t *, const voleith_bristol_config_t *,
                              size_t **, uint32_t *, uint32_t *);
static int parse_header_line3(cursor_t *, size_t **, uint32_t *, uint32_t *);

/* ================================================================
 * Tokenizer helpers
 * ================================================================ */

/* Skip spaces and tabs only; newlines are line-significant and not consumed. */
static void
skip_ws_inline(cursor_t *c)
{
    while (c->pos < c->end && (*c->pos == ' ' || *c->pos == '\t'))
        c->pos++;
}

/* Advance past the next '\n', or to end if none found. */
static void
skip_to_next_line(cursor_t *c)
{
    while (c->pos < c->end && *c->pos != '\n')
        c->pos++;
    if (c->pos < c->end)
        c->pos++; /* consume the '\n' */
}

/*
 * Read a decimal uint32_t after skipping inline whitespace.  Returns 0 on
 * success; -1 if no digit is present or the value overflows uint32_t.
 */
static int
read_uint(cursor_t *c, uint32_t *out)
{
    skip_ws_inline(c);
    if (c->pos >= c->end || *c->pos < '0' || *c->pos > '9')
        return -1;
    uint32_t v = 0;
    while (c->pos < c->end && *c->pos >= '0' && *c->pos <= '9') {
        uint32_t d = (uint32_t)(*c->pos - '0');
        if (v > (UINT32_MAX - d) / 10)
            return -1; /* overflow */
        v = v * 10 + d;
        c->pos++;
    }
    *out = v;
    return 0;
}

/*
 * Read a whitespace-delimited word into buf (NUL-terminated, at most cap-1
 * characters) after skipping inline whitespace.  Stops at newlines.
 * Returns 0 on success; -1 if no word is found or it does not fit in cap.
 */
static int
read_word(cursor_t *c, char *buf, size_t cap)
{
    skip_ws_inline(c);
    if (c->pos >= c->end || *c->pos == '\n' || *c->pos == '\r')
        return -1;
    size_t n = 0;
    while (c->pos < c->end && *c->pos != ' ' && *c->pos != '\t' &&
           *c->pos != '\n' && *c->pos != '\r') {
        if (n + 1 >= cap)
            return -1; /* word does not fit */
        buf[n++] = *c->pos++;
    }
    buf[n] = '\0';
    return 0;
}

/* ================================================================
 * Header parsing
 * ================================================================ */

/*
 * Parse header line 1: "<n_gates> <n_wires>".
 *
 * Older (pre-Fashion) Bristol files had a three-integer first line.  If a
 * third integer is found on this line, returns
 * VOLEITH_BRISTOL_ERR_OLD_FORMAT.  Advances cursor to the next line on
 * success.
 */
static int
parse_header_line1(cursor_t *c, uint32_t *n_gates, uint32_t *n_wires)
{
    if (read_uint(c, n_gates) != 0)
        return VOLEITH_BRISTOL_ERR_HEADER;
    if (read_uint(c, n_wires) != 0)
        return VOLEITH_BRISTOL_ERR_HEADER;

    /* A digit still on this line means the older three-integer header. */
    skip_ws_inline(c);
    if (c->pos < c->end && *c->pos >= '0' && *c->pos <= '9')
        return VOLEITH_BRISTOL_ERR_OLD_FORMAT;

    skip_to_next_line(c);
    return 0;
}

/*
 * Parse header line 2: "<n_input_values> <bits_1> ... <bits_k>".
 *
 * Validates n_input_values == cfg->n_input_roles; returns
 * VOLEITH_BRISTOL_ERR_ROLE_MISMATCH on mismatch.
 *
 * Old-format detection: in Bristol Fashion the per-value bit counts follow
 * immediately on the same line.  If n_input_values > 0 but the line ends
 * before any sizes, returns VOLEITH_BRISTOL_ERR_OLD_FORMAT.
 *
 * On success, *sizes_out is a calloc'd array of n_input_values elements
 * (caller must free on any subsequent error).  *n_vals_out and *sum_out
 * receive the count and total bit count respectively.
 */
static int
parse_header_line2(cursor_t *c, const voleith_bristol_config_t *cfg,
                   size_t **sizes_out, uint32_t *n_vals_out, uint32_t *sum_out)
{
    uint32_t n_vals;
    if (read_uint(c, &n_vals) != 0)
        return VOLEITH_BRISTOL_ERR_HEADER;

    /*
     * In Bristol Fashion, per-value sizes follow on the same line.  A count
     * with no sizes is the older format where only the total is given.
     */
    if (n_vals > 0) {
        skip_ws_inline(c);
        if (c->pos >= c->end || *c->pos == '\n' || *c->pos == '\r')
            return VOLEITH_BRISTOL_ERR_OLD_FORMAT;
    }

    if ((size_t)n_vals != cfg->n_input_roles)
        return VOLEITH_BRISTOL_ERR_ROLE_MISMATCH;

    size_t *sizes = NULL;
    if (n_vals > 0) {
        sizes = calloc(n_vals, sizeof(size_t));
        if (sizes == NULL)
            return VOLEITH_BRISTOL_ERR_ALLOC;
    }

    uint32_t sum = 0;
    for (uint32_t i = 0; i < n_vals; i++) {
        uint32_t bits;
        if (read_uint(c, &bits) != 0) {
            free(sizes);
            return VOLEITH_BRISTOL_ERR_HEADER;
        }
        sizes[i] = (size_t)bits;
        if (sum > UINT32_MAX - bits) {
            free(sizes);
            return VOLEITH_BRISTOL_ERR_HEADER;
        }
        sum += bits;
    }

    skip_to_next_line(c);
    *sizes_out = sizes;
    *n_vals_out = n_vals;
    *sum_out = sum;
    return 0;
}

/*
 * Parse header line 3: "<n_output_values> <bits_1> ... <bits_m>".
 *
 * Symmetric to parse_header_line2 but for outputs; no role validation is
 * performed (output wire classification is the caller's concern).
 *
 * On success, *sizes_out is a calloc'd array of n_output_values elements.
 */
static int
parse_header_line3(cursor_t *c, size_t **sizes_out, uint32_t *n_vals_out,
                   uint32_t *sum_out)
{
    uint32_t n_vals;
    if (read_uint(c, &n_vals) != 0)
        return VOLEITH_BRISTOL_ERR_HEADER;

    size_t *sizes = NULL;
    if (n_vals > 0) {
        sizes = calloc(n_vals, sizeof(size_t));
        if (sizes == NULL)
            return VOLEITH_BRISTOL_ERR_ALLOC;
    }

    uint32_t sum = 0;
    for (uint32_t i = 0; i < n_vals; i++) {
        uint32_t bits;
        if (read_uint(c, &bits) != 0) {
            free(sizes);
            return VOLEITH_BRISTOL_ERR_HEADER;
        }
        sizes[i] = (size_t)bits;
        if (sum > UINT32_MAX - bits) {
            free(sizes);
            return VOLEITH_BRISTOL_ERR_HEADER;
        }
        sum += bits;
    }

    skip_to_next_line(c);
    *sizes_out = sizes;
    *n_vals_out = n_vals;
    *sum_out = sum;
    return 0;
}

/* ================================================================
 * Public API
 * ================================================================ */

/*
 * Parse a Bristol Fashion circuit from an in-memory buffer.
 *
 * If len is 0 the parser uses strlen(buf).  On success fills *out and
 * returns 0; the caller owns all fields and must call
 * voleith_bristol_parsed_free().  On failure *out is zeroed and a
 * negative voleith_bristol_error_t is returned.
 */
int
voleith_bristol_parse_buffer(voleith_bristol_parsed_t *out, const char *buf,
                             size_t len, const voleith_bristol_config_t *cfg)
{
    voleith_circuit_t *circuit = NULL;
    size_t *input_value_sizes = NULL;
    size_t *output_value_sizes = NULL;
    wire_id *bw_to_vw = NULL;
    uint32_t n_gates, n_wires;
    uint32_t n_input_values, sum_input_bits;
    uint32_t n_output_values, sum_output_bits;
    int err;

    memset(out, 0, sizeof(*out));
    if (len == 0)
        len = strlen(buf);
    cursor_t c = {buf, buf + len};

    err = parse_header_line1(&c, &n_gates, &n_wires);
    if (err != 0)
        goto fail;

    err = parse_header_line2(&c, cfg, &input_value_sizes, &n_input_values,
                             &sum_input_bits);
    if (err != 0)
        goto fail;

    err = parse_header_line3(&c, &output_value_sizes, &n_output_values,
                             &sum_output_bits);
    if (err != 0)
        goto fail;

    /* Declared wire count must accommodate all input and output wires. */
    if (sum_input_bits > n_wires || sum_output_bits > n_wires) {
        err = VOLEITH_BRISTOL_ERR_HEADER;
        goto fail;
    }

    circuit = voleith_circuit_new();
    if (circuit == NULL) {
        err = VOLEITH_BRISTOL_ERR_ALLOC;
        goto fail;
    }

    /*
     * Allocate the Bristol-to-voleith wire-ID map.  WIRE_ID_INVALID equals
     * UINT32_MAX (all bits set), so memset 0xFF initialises every slot to
     * the sentinel, letting the gate loop detect undefined wires.
     */
    if (n_wires > 0) {
        bw_to_vw = calloc(n_wires, sizeof(wire_id));
        if (bw_to_vw == NULL) {
            err = VOLEITH_BRISTOL_ERR_ALLOC;
            goto fail;
        }
        memset(bw_to_vw, 0xFF, (size_t)n_wires * sizeof(wire_id));
    }

    /* Walk input values; record the returned voleith wire IDs in bw_to_vw. */
    {
        uint32_t bw = 0;
        for (uint32_t i = 0; i < n_input_values; i++) {
            size_t bits = input_value_sizes[i];
            int is_witness = (cfg->input_roles[i] == VOLEITH_BRISTOL_WITNESS);
            for (size_t b = 0; b < bits; b++) {
                wire_id vw = is_witness ? voleith_circuit_add_witness(circuit)
                                        : voleith_circuit_add_instance(circuit);
                if (vw == WIRE_ID_INVALID) {
                    err = VOLEITH_BRISTOL_ERR_ALLOC;
                    goto fail;
                }
                bw_to_vw[bw++] = vw;
            }
        }
    }

    /* Skip the blank separator line between the header block and gate list. */
    skip_to_next_line(&c);

    /* Gate loop: parse one line per gate. */
    for (uint32_t g = 0; g < n_gates; g++) {
        uint32_t n_in, n_out, in0, in1, out_id;
        wire_id vw = WIRE_ID_INVALID;
        char name[8];

        if (read_uint(&c, &n_in) != 0 || read_uint(&c, &n_out) != 0) {
            err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
            goto fail;
        }
        /* Only unary/binary gates with exactly one output are supported. */
        if (n_in < 1 || n_in > 2 || n_out != 1) {
            err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
            goto fail;
        }
        if (read_uint(&c, &in0) != 0) {
            err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
            goto fail;
        }
        in1 = UINT32_MAX;
        if (n_in == 2 && read_uint(&c, &in1) != 0) {
            err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
            goto fail;
        }
        if (read_uint(&c, &out_id) != 0 ||
            read_word(&c, name, sizeof(name)) != 0) {
            err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
            goto fail;
        }
        skip_to_next_line(&c);

        /* Validate output wire: in range and not previously assigned. */
        if (out_id >= n_wires) {
            err = VOLEITH_BRISTOL_ERR_WIRE_ORDER;
            goto fail;
        }
        if (bw_to_vw[out_id] != WIRE_ID_INVALID) {
            err = VOLEITH_BRISTOL_ERR_WIRE_REDEF;
            goto fail;
        }

        if (strcmp(name, "XOR") == 0) {
            if (n_in != 2) {
                err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
                goto fail;
            }
            /*
             * Bristol Fashion guarantees topological ordering by file
             * position, NOT by numeric wire-ID ordering.  Check that each
             * input wire is within range and already defined (non-sentinel),
             * NOT that in_id < out_id.
             */
            if (in0 >= n_wires || bw_to_vw[in0] == WIRE_ID_INVALID ||
                in1 >= n_wires || bw_to_vw[in1] == WIRE_ID_INVALID) {
                err = VOLEITH_BRISTOL_ERR_WIRE_ORDER;
                goto fail;
            }
            vw = voleith_circuit_add_xor(circuit, bw_to_vw[in0], bw_to_vw[in1]);
        } else if (strcmp(name, "AND") == 0) {
            if (n_in != 2) {
                err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
                goto fail;
            }
            if (in0 >= n_wires || bw_to_vw[in0] == WIRE_ID_INVALID ||
                in1 >= n_wires || bw_to_vw[in1] == WIRE_ID_INVALID) {
                err = VOLEITH_BRISTOL_ERR_WIRE_ORDER;
                goto fail;
            }
            vw = voleith_circuit_add_and(circuit, bw_to_vw[in0], bw_to_vw[in1]);
        } else if (strcmp(name, "INV") == 0) {
            if (n_in != 1) {
                err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
                goto fail;
            }
            if (in0 >= n_wires || bw_to_vw[in0] == WIRE_ID_INVALID) {
                err = VOLEITH_BRISTOL_ERR_WIRE_ORDER;
                goto fail;
            }
            vw = voleith_circuit_add_not(circuit, bw_to_vw[in0]);
        } else if (strcmp(name, "EQ") == 0) {
            /*
             * EQ is a constant-injection gate: the "input" field on the
             * EQ line is a literal 0 or 1, NOT a wire ID.  Do not look it
             * up in bw_to_vw or apply wire-order validation to it.
             */
            if (n_in != 1 || in0 > 1) {
                err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
                goto fail;
            }
            vw = voleith_circuit_add_const(circuit, (uint8_t)in0);
        } else if (strcmp(name, "EQW") == 0) {
            if (n_in != 1) {
                err = VOLEITH_BRISTOL_ERR_GATE_SYNTAX;
                goto fail;
            }
            if (in0 >= n_wires || bw_to_vw[in0] == WIRE_ID_INVALID) {
                err = VOLEITH_BRISTOL_ERR_WIRE_ORDER;
                goto fail;
            }
            /* EQW aliases the input wire; no new circuit node is needed. */
            bw_to_vw[out_id] = bw_to_vw[in0];
            continue;
        } else {
            err = VOLEITH_BRISTOL_ERR_UNKNOWN_GATE;
            goto fail;
        }

        if (vw == WIRE_ID_INVALID) {
            err = VOLEITH_BRISTOL_ERR_ALLOC;
            goto fail;
        }
        bw_to_vw[out_id] = vw;
    }
    /* All n_wires slots must have been defined by gates or inputs. */
    for (uint32_t i = 0; i < n_wires; i++) {
        if (bw_to_vw[i] == WIRE_ID_INVALID) {
            err = VOLEITH_BRISTOL_ERR_WIRE_COUNT;
            goto fail;
        }
    }

    if (sum_input_bits > 0) {
        out->input_wires = calloc(sum_input_bits, sizeof(wire_id));
        if (out->input_wires == NULL) {
            err = VOLEITH_BRISTOL_ERR_ALLOC;
            goto fail;
        }
        memcpy(out->input_wires, bw_to_vw,
               (size_t)sum_input_bits * sizeof(wire_id));
    }
    out->n_input_wires = sum_input_bits;

    if (sum_output_bits > 0) {
        out->output_wires = calloc(sum_output_bits, sizeof(wire_id));
        if (out->output_wires == NULL) {
            err = VOLEITH_BRISTOL_ERR_ALLOC;
            goto fail;
        }
        memcpy(out->output_wires, bw_to_vw + (n_wires - sum_output_bits),
               (size_t)sum_output_bits * sizeof(wire_id));
    }
    out->n_output_wires = sum_output_bits;

    out->input_value_sizes = input_value_sizes;
    input_value_sizes = NULL;
    out->n_input_values = n_input_values;

    out->output_value_sizes = output_value_sizes;
    output_value_sizes = NULL;
    out->n_output_values = n_output_values;

    out->circuit = circuit;
    circuit = NULL;

    free(bw_to_vw);
    bw_to_vw = NULL;

    err = 0;

fail:
    free(bw_to_vw);
    free(input_value_sizes);
    free(output_value_sizes);
    voleith_circuit_free(circuit);
    if (err != 0) {
        free(out->input_wires);
        free(out->output_wires);
        memset(out, 0, sizeof(*out));
    }
    return err;
}

int
voleith_bristol_parse_file(voleith_bristol_parsed_t *out, const char *path,
                           const voleith_bristol_config_t *cfg)
{
    FILE *fp;
    char *buf;
    long sz;
    int err;

    fp = fopen(path, "r");
    if (fp == NULL)
        return VOLEITH_BRISTOL_ERR_IO;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return VOLEITH_BRISTOL_ERR_IO;
    }
    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return VOLEITH_BRISTOL_ERR_IO;
    }
    rewind(fp);

    buf = calloc((size_t)sz + 1, 1);
    if (buf == NULL) {
        fclose(fp);
        return VOLEITH_BRISTOL_ERR_ALLOC;
    }

    if ((size_t)sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return VOLEITH_BRISTOL_ERR_IO;
    }
    fclose(fp);
    /* buf[(size_t)sz] is already '\0' from calloc. */

    err = voleith_bristol_parse_buffer(out, buf, (size_t)sz, cfg);
    free(buf);
    return err;
}

void
voleith_bristol_parsed_free(voleith_bristol_parsed_t *p)
{
    if (p == NULL)
        return;
    voleith_circuit_free(p->circuit);
    free(p->input_wires);
    free(p->output_wires);
    free(p->input_value_sizes);
    free(p->output_value_sizes);
    memset(p, 0, sizeof(*p));
}
