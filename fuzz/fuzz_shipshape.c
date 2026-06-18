/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * fuzz_shipshape.c - libFuzzer harness for the Shipshape (.ship) parser
 * entry point (ISA 1.5 last parser invariant; 8.4 item 11).
 *
 * A .ship file is untrusted input; the parser must stay memory-safe and
 * terminate on any byte sequence.  This harness feeds arbitrary bytes to
 * voleith_shipshape_parse_buffer and frees any built result.  Build with
 * -DVOLEITH_FUZZ=ON (Clang); see fuzz/README.md.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "shipshape.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    voleith_shipshape_parsed_t p;
    voleith_shipshape_limits_t limits;
    char *copy;

    /*
     * parse_buffer treats len == 0 as "call strlen", so it needs a
     * NUL-terminated buffer; fuzz data is not terminated.  Copy into a
     * size + 1 buffer (the same invariant parse_file guarantees) and pass the
     * explicit length.  The exact-size copy keeps AddressSanitizer able to
     * catch a one-past-the-end read.
     */
    copy = malloc(size + 1);
    if (copy == NULL)
        return 0;
    memcpy(copy, data, size);
    copy[size] = '\0';

    /*
     * Tight resource limits so a single input cannot drive a multi-gigabyte
     * allocation and stall the fuzzer.  The parser is memory-safe regardless
     * of the limits; these only bound throughput.
     */
    limits.max_wires = (size_t)1 << 16;
    limits.max_gates = (size_t)1 << 16;
    limits.max_file_bytes = (size_t)1 << 20;
    limits.max_line_bytes = (size_t)1 << 16;

    if (voleith_shipshape_parse_buffer(&p, copy, size, &limits) == 0)
        voleith_shipshape_parsed_free(&p);

    free(copy);
    return 0;
}
