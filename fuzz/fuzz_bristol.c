/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fuzz_bristol.c - libFuzzer harness for the Bristol Fashion parser entry
 * point (ISA 1.5 last parser invariant; 8.4 item 11; the Bristol parser
 * shipped in 1.5.0 without a harness).
 *
 * A Bristol circuit file is untrusted input; the parser must stay
 * memory-safe and terminate on any byte sequence.  Two properties of the
 * Bristol entry point shape this harness:
 *
 *   1. It takes a caller-supplied per-input-value role array whose length
 *      must equal the file's declared input-value count, or the parser stops
 *      at VOLEITH_BRISTOL_ERR_ROLE_MISMATCH before the gate parser.  We peek
 *      that count from the header and present a matching role array.
 *
 *   2. It has no resource-limit struct: the header counts n_wires and
 *      n_output_values each drive an unbounded calloc (parsers/bristol.c
 *      lines 307 and 218), so a header declaring billions of wires requests
 *      a multi-gigabyte buffer.  That is out-of-scope-by-policy for the
 *      parser (the caller must impose limits, see
 *      the 1.5.0 security review); the caller here is this harness, so it
 *      caps those header dimensions.  Without the cap the fuzzer trivially
 *      finds a giant-header input and reports a spurious OOM instead of
 *      exercising the parser.
 *
 * Build with -DVOLEITH_FUZZ=ON (Clang); see fuzz/README.md.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bristol.h"

/* Cap on header-declared input-value roles (bounds the role array). */
#define FUZZ_BRISTOL_MAX_ROLES 4096

/*
 * Cap on the allocation-driving header dimensions (n_wires, n_output_values).
 * 2^20 keeps the largest transient buffer at a few MB while admitting every
 * realistic circuit (AES-256 is ~37k wires).
 */
#define FUZZ_BRISTOL_MAX_DIM (1u << 20)

/* Advance past the next newline, stopping at the NUL terminator. */
static const char *
next_line(const char *s)
{
    while (*s != '\0' && *s != '\n')
        s++;
    if (*s == '\n')
        s++;
    return s;
}

/*
 * Read the first decimal integer at or after s on the current line, skipping
 * inline blanks.  Saturates at UINT32_MAX.  Returns 1 and sets *out (and
 * *end, if non-NULL, to just past the digits) on success, 0 if the next
 * token is not a digit.  Never crosses a newline or the NUL terminator.
 */
static int
line_uint(const char *s, uint32_t *out, const char **end)
{
    unsigned long long v = 0;

    while (*s == ' ' || *s == '\t')
        s++;
    if (*s < '0' || *s > '9')
        return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10ull + (unsigned long long)(*s - '0');
        if (v > 0xffffffffull)
            v = 0xffffffffull;
        s++;
    }
    *out = (uint32_t)v;
    if (end != NULL)
        *end = s;
    return 1;
}

/*
 * The file's declared input-value count: the first integer on header line 2.
 * Clamped to FUZZ_BRISTOL_MAX_ROLES (a clamp only narrows coverage); a
 * malformed header yields 0, which the parser rejects in its own header
 * stage.
 */
static size_t
peek_input_count(const char *s)
{
    uint32_t v;

    s = next_line(s); /* skip header line 1 (n_gates n_wires) */
    if (!line_uint(s, &v, NULL))
        return 0;
    if (v > FUZZ_BRISTOL_MAX_ROLES)
        return FUZZ_BRISTOL_MAX_ROLES;
    return v;
}

/*
 * True unless a well-formed header declares an allocation dimension over the
 * cap.  A malformed header passes (returns true): the parser rejects it
 * before reaching the corresponding calloc, so there is nothing to bound.
 */
static int
header_dims_ok(const char *s)
{
    const char *p;
    uint32_t n_gates, n_wires, n_out;

    if (!line_uint(s, &n_gates, &p) || !line_uint(p, &n_wires, NULL))
        return 1; /* line 1 malformed: parse_header_line1 rejects it */
    if (n_gates > FUZZ_BRISTOL_MAX_DIM || n_wires > FUZZ_BRISTOL_MAX_DIM)
        return 0;
    s = next_line(s); /* to line 2 (inputs; bounded by the role clamp) */
    s = next_line(s); /* to line 3 (outputs) */
    if (line_uint(s, &n_out, NULL) && n_out > FUZZ_BRISTOL_MAX_DIM)
        return 0;
    return 1;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    voleith_bristol_input_role_t roles[FUZZ_BRISTOL_MAX_ROLES];
    voleith_bristol_config_t cfg;
    voleith_bristol_parsed_t p;
    char *copy;
    size_t n_roles;

    /*
     * parse_buffer treats len == 0 as "call strlen", so it needs a
     * NUL-terminated buffer; fuzz data is not terminated.  Copy into a
     * size + 1 buffer (the invariant parse_file guarantees) and pass the
     * explicit length.
     */
    copy = malloc(size + 1);
    if (copy == NULL)
        return 0;
    memcpy(copy, data, size);
    copy[size] = '\0';

    if (!header_dims_ok(copy)) {
        free(copy);
        return 0;
    }

    n_roles = peek_input_count(copy);
    for (size_t i = 0; i < n_roles; i++)
        roles[i] = (i & 1) ? VOLEITH_BRISTOL_INSTANCE : VOLEITH_BRISTOL_WITNESS;
    cfg.input_roles = roles;
    cfg.n_input_roles = n_roles;

    if (voleith_bristol_parse_buffer(&p, copy, size, &cfg) == 0)
        voleith_bristol_parsed_free(&p);

    free(copy);
    return 0;
}
