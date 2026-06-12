/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/bristol.h - Bristol Fashion circuit parser
 *
 * Parses the Bristol Fashion boolean-circuit file format and constructs a
 * voleith_circuit_t that can be passed directly to voleith_prove /
 * voleith_verify.
 *
 * Bristol Fashion format summary:
 *   Line 1: <n_gates> <n_wires>
 *   Line 2: <n_input_values> <bits_1> <bits_2> ...
 *   Line 3: <n_output_values> <bits_1> <bits_2> ...
 *   <blank line>
 *   One gate line per gate: <n_in> <n_out> [in_wires...] <out_wire> <type>
 *
 * Supported gate types: XOR, AND, INV, EQ, EQW.
 * Unsupported (rejected): MAND and all other types.
 *
 * Because Bristol has no witness/instance distinction, callers supply a
 * per-input-value role array (voleith_bristol_config_t) that maps each
 * file input value to WITNESS or INSTANCE.
 *
 * Output wires are returned to the caller as wire_id arrays; the caller
 * attaches constraints (assert_equal, assert_zero) as their use case
 * demands.
 */

#ifndef VOLEITH_PARSERS_BRISTOL_H
#define VOLEITH_PARSERS_BRISTOL_H

#include <stddef.h>
#include <stdint.h>

#include "circuit.h"

/* ================================================================
 * Error codes
 * ================================================================ */

/*
 * All parse functions return 0 on success or one of these negative values
 * on failure.  Every error path frees any partial allocations before
 * returning, including the partially-built circuit.
 */
typedef enum {
    VOLEITH_BRISTOL_ERR_IO = -1,     /* file open / read failure */
    VOLEITH_BRISTOL_ERR_HEADER = -2, /* header lines malformed or missing */
    VOLEITH_BRISTOL_ERR_ROLE_MISMATCH =
        -3, /* n_input_roles != file's n_input_values */
    VOLEITH_BRISTOL_ERR_GATE_SYNTAX =
        -4, /* gate line malformed (wrong arity) */
    VOLEITH_BRISTOL_ERR_UNKNOWN_GATE = -5, /* gate type not in the v1 set */
    VOLEITH_BRISTOL_ERR_WIRE_ORDER = -6,   /* input wire id >= output wire id */
    VOLEITH_BRISTOL_ERR_WIRE_REDEF = -7,   /* output wire id already assigned */
    VOLEITH_BRISTOL_ERR_WIRE_COUNT = -8,   /* total wires defined != n_wires */
    VOLEITH_BRISTOL_ERR_ALLOC = -9,        /* allocation failure */
    VOLEITH_BRISTOL_ERR_OLD_FORMAT =
        -10, /* detected pre-Fashion older format */
} voleith_bristol_error_t;

/* ================================================================
 * Input role configuration
 * ================================================================ */

/*
 * Whether a Bristol input value maps to a private witness or a public
 * instance in the proof system.  One role per input value (not per bit).
 */
typedef enum {
    VOLEITH_BRISTOL_WITNESS,  /* private input: bits go to add_witness() */
    VOLEITH_BRISTOL_INSTANCE, /* public input: bits go to add_instance() */
} voleith_bristol_input_role_t;

/*
 * Configuration passed to the parser.  The caller must supply one role entry
 * per input value declared in the file header; the parser validates that
 * n_input_roles matches the file's n_input_values and returns
 * VOLEITH_BRISTOL_ERR_ROLE_MISMATCH if they differ.
 *
 * The parser does not retain a pointer to this struct after the parse call
 * returns.
 */
typedef struct {
    const voleith_bristol_input_role_t *input_roles; /* length n_input_roles */
    size_t n_input_roles;
} voleith_bristol_config_t;

/* ================================================================
 * Parse result
 * ================================================================ */

/*
 * Output of a successful parse.  All pointer fields are heap-allocated;
 * use voleith_bristol_parsed_free() to release them all at once, or take
 * ownership of individual fields and free them separately.
 *
 * input_wires and output_wires are flattened across all input/output values
 * in file order.  Use input_value_sizes[i] to slice input_wires into the
 * bits belonging to each input value (and likewise for output).
 *
 * The circuit is built with topological ordering matching the file.  No
 * constraints are added by the parser; the caller attaches them via
 * voleith_circuit_assert_zero / voleith_circuit_assert_equal.
 *
 * Callers must validate n_input_values, input_value_sizes[], and
 * n_output_wires against their expected circuit shape before indexing
 * the returned arrays or sizing witness/instance buffers.  The parser
 * makes no assumptions about the circuit's purpose.
 */
typedef struct {
    voleith_circuit_t *circuit; /* parser-built circuit; caller frees */

    wire_id *input_wires; /* flattened input wire IDs, file order */
    size_t n_input_wires; /* sum of input_value_sizes[] */

    wire_id *output_wires; /* flattened output wire IDs, file order */
    size_t n_output_wires; /* sum of output_value_sizes[] */

    size_t *
        input_value_sizes; /* bit-counts per input value (length n_input_values) */
    size_t n_input_values;

    size_t *
        output_value_sizes; /* bit-counts per output value (length n_output_values) */
    size_t n_output_values;
} voleith_bristol_parsed_t;

/* ================================================================
 * Parse API
 * ================================================================ */

/*
 * Parse a Bristol Fashion circuit from the file at `path`.
 *
 * On success, fills `out` and returns 0.  The caller owns all fields of
 * `out` and must eventually call voleith_bristol_parsed_free() (or free
 * each field individually).
 *
 * On failure, returns a negative voleith_bristol_error_t code.  `out` is
 * zeroed before returning; no partial allocations are leaked.
 */
int voleith_bristol_parse_file(voleith_bristol_parsed_t *, const char *,
                               const voleith_bristol_config_t *);

/*
 * Parse a Bristol Fashion circuit from an in-memory buffer.
 *
 * `buf` must be NUL-terminated (or `len` bytes may be provided if the
 * buffer is not NUL-terminated; the parser reads at most `len` bytes).
 * If `len` is 0 the parser uses strlen(buf).
 *
 * Return value and ownership are the same as voleith_bristol_parse_file().
 */
int voleith_bristol_parse_buffer(voleith_bristol_parsed_t *, const char *,
                                 size_t, const voleith_bristol_config_t *);

/*
 * Release all memory owned by a parsed result.
 *
 * Safe to call on a zero-initialised struct (the common cleanup pattern:
 * declare as `voleith_bristol_parsed_t p = {0};` and call this
 * unconditionally on all exit paths).  Each pointer field is freed if
 * non-NULL; the circuit is released via voleith_circuit_free().
 * The struct is zeroed on return.
 */
void voleith_bristol_parsed_free(voleith_bristol_parsed_t *);

#endif /* VOLEITH_PARSERS_BRISTOL_H */
