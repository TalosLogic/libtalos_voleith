/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * parsers/shipshape.h - Shipshape (.ship) native GF(2^8) circuit parser
 *
 * Parses the Shipshape v1 text format (the Shipshape spec;
 * "FORMAT" = the format spec; "ISA" = the ISA design)
 * and constructs a voleith_gf8_circuit_t that can be passed directly to the
 * GF(2^8) prover and verifier (proof/gf8_proof.c).
 *
 * Unlike the Bristol parser, a Shipshape file declares its own WITNESS /
 * INSTANCE / CONST wires by name, so no caller-supplied input-role
 * configuration is required.  The magic header (".shipshape 1" line per
 * FORMAT 3.1) is validated on every parse; the filename is never trusted.
 *
 * Parser trust boundary (ISA 1.5): a .ship file is untrusted input.  This
 * parser consumes attacker-controlled bytes and produces a trusted Tier 1
 * IR.  Project standards apply throughout: no assert() on input paths
 * (NDEBUG builds), calloc(n, size) for every count-times-size allocation
 * (L-N4), and first-error-stop with no recovery (FORMAT 4).
 *
 * Scope: the full Shipshape v1 grammar.  Entry points and resource-limit
 * clamping, the lexer, the three-line header, declarations / wire table /
 * refinement types, gates / assertions / sugar with canonicalization,
 * subcircuit definitions / call inlining / region side table, and the
 * Tier 2a `stdlib/crypto/*` registry.  Two conformant parsers lower any
 * v1 `.ship` file to a byte-identical wire and constraint table, and hence
 * the identical 16-byte fingerprint (ISA 5.5); the bundled cross-parser
 * corpus in tests/test_shipshape_conformance.c is the release gate for
 * that guarantee.
 */

#ifndef VOLEITH_PARSERS_SHIPSHAPE_H
#define VOLEITH_PARSERS_SHIPSHAPE_H

#include <stddef.h>
#include <stdint.h>

#include "gf8_circuit.h"
#include "shipshape_registry.h"

/* ================================================================
 * Resource-bound ceilings (ISA 5.1)
 *
 * Hard ceilings on the post-inline IR, part of the format spec rather
 * than implementation choices.  A parser that accepts an input violating
 * these is non-conformant.  Caller-supplied limits (below) are clamped to
 * these values.
 * ================================================================ */

#define VOLEITH_SHIPSHAPE_MAX_WIRES ((size_t)1 << 28)
#define VOLEITH_SHIPSHAPE_MAX_GATES ((size_t)1 << 28)
#define VOLEITH_SHIPSHAPE_MAX_INLINE_DEPTH ((size_t)64)
#define VOLEITH_SHIPSHAPE_MAX_IDENT_LEN ((size_t)256)
#define VOLEITH_SHIPSHAPE_MAX_MATRIX_BYTES ((size_t)8)
#define VOLEITH_SHIPSHAPE_MAX_VECTOR_LEN ((size_t)1 << 20)
#define VOLEITH_SHIPSHAPE_MAX_BLOCKS_PER_OPCODE ((size_t)1 << 20)
#define VOLEITH_SHIPSHAPE_MAX_FILE_BYTES ((size_t)1 << 26) /* 64 MiB */
#define VOLEITH_SHIPSHAPE_MAX_LINE_BYTES ((size_t)1 << 16)

/* ================================================================
 * Error codes
 * ================================================================ */

/*
 * All parse functions return 0 on success or one of these negative values
 * on failure.  Every error path frees any partial allocations before
 * returning, including the partially-built circuit, and zeroes the
 * caller's out-struct (FORMAT 4).
 *
 * The enum is the stable v1 public contract: values do not change as the
 * parser stages land.  Codes are grouped by the workstream step (W3.x)
 * that first emits them; the comments note this so the contract is legible
 * before every stage exists.
 */
typedef enum {
    /* Entry-point and I/O (W3.1). */
    VOLEITH_SHIPSHAPE_ERR_IO = -1,       /* file open / read failure */
    VOLEITH_SHIPSHAPE_ERR_ALLOC = -2,    /* allocation failure */
    VOLEITH_SHIPSHAPE_ERR_NULL_ARG = -3, /* required pointer argument NULL */
    VOLEITH_SHIPSHAPE_ERR_EMPTY = -4,    /* input has zero bytes */
    VOLEITH_SHIPSHAPE_ERR_FILE_TOO_BIG = -5, /* exceeds effective file limit */

    /* Lexer (W3.2). */
    VOLEITH_SHIPSHAPE_ERR_CHARSET = -6,       /* illegal byte (FORMAT 2.1) */
    VOLEITH_SHIPSHAPE_ERR_LINE_TOO_LONG = -7, /* exceeds MAX_LINE_BYTES */
    VOLEITH_SHIPSHAPE_ERR_IDENT = -8,   /* malformed / over-long identifier */
    VOLEITH_SHIPSHAPE_ERR_LITERAL = -9, /* malformed byte / integer literal */
    VOLEITH_SHIPSHAPE_ERR_TOKEN = -20,  /* legal byte, not a valid token start
                                           (malformed -> / ++, stray punct) */

    /* Header (W3.3). */
    VOLEITH_SHIPSHAPE_ERR_HEADER = -10, /* magic / field / stdlib line wrong */

    /* Declarations, types (W3.4). */
    VOLEITH_SHIPSHAPE_ERR_DECL = -11,  /* wire declaration malformed */
    VOLEITH_SHIPSHAPE_ERR_REDEF = -12, /* SSA violation: name redefined (S1) */
    VOLEITH_SHIPSHAPE_ERR_UNDEF = -13, /* use before define (S2) */
    VOLEITH_SHIPSHAPE_ERR_TYPE = -14,  /* type error incl. bit/byte (S5) */

    /* Gates, assertions (W3.5). */
    VOLEITH_SHIPSHAPE_ERR_GATE = -15, /* gate / assertion syntax or arity */
    VOLEITH_SHIPSHAPE_ERR_OPCODE_VERSION = -21, /* opcode newer than the file's
                                                   declared .shipshape minor
                                                   (format-versioning record) */

    /* Subcircuits, inlining (W3.6). */
    VOLEITH_SHIPSHAPE_ERR_SUBCIRCUIT = -16,   /* definition / call error */
    VOLEITH_SHIPSHAPE_ERR_INLINE_DEPTH = -17, /* MAX_INLINE_DEPTH exceeded */
    VOLEITH_SHIPSHAPE_ERR_LIMIT = -18, /* a 5.1 resource bound exceeded */

    /* Tier 2a registry (W3.7). */
    VOLEITH_SHIPSHAPE_ERR_REGISTRY = -19, /* stdlib/crypto lookup / version */
} voleith_shipshape_error_t;

/* ================================================================
 * Caller-supplied resource limits
 * ================================================================ */

/*
 * Per-parse resource limits.  Applications that know their circuits are
 * small SHOULD pass small limits (ISA 5.1).  Each field is clamped to the
 * corresponding ceiling above; a field set to 0 selects the ceiling.  A
 * NULL limits pointer passed to a parse function is equivalent to a struct
 * with every field 0 (all ceilings).
 */
typedef struct {
    size_t max_wires;      /* 0 => VOLEITH_SHIPSHAPE_MAX_WIRES */
    size_t max_gates;      /* 0 => VOLEITH_SHIPSHAPE_MAX_GATES */
    size_t max_file_bytes; /* 0 => VOLEITH_SHIPSHAPE_MAX_FILE_BYTES */
    size_t max_line_bytes; /* 0 => VOLEITH_SHIPSHAPE_MAX_LINE_BYTES */
} voleith_shipshape_limits_t;

/* ================================================================
 * Parse result
 * ================================================================ */

/*
 * Class of a top-level wire declaration, naming which proof-system array a
 * declaration's wires belong to.  CONST_BIT folds into _CONST: like CONST
 * it lowers to a constant wire and appears in neither the witness nor the
 * instance array (its bit refinement is recorded in voleith_shipshape_decl_t
 * .is_bit).
 */
typedef enum {
    VOLEITH_SHIPSHAPE_DECL_WITNESS = 0, /* private input; witness array */
    VOLEITH_SHIPSHAPE_DECL_INSTANCE,    /* public input; instance array */
    VOLEITH_SHIPSHAPE_DECL_CONST,       /* CONST / CONST_BIT literal wire */
} voleith_shipshape_decl_kind_t;

/*
 * One named top-level wire declaration, in file order.  Lets a consumer map
 * a declared name to its circuit wires and size the witness / instance byte
 * arrays (ISA 2.11): the WITNESS declarations in order give the witness-byte
 * layout, the INSTANCE declarations the instance-byte layout.
 *
 * `first_wire` is the circuit wire id of element 0; for a vector it is the
 * first of `length` consecutive wires.  A zero-length vector (`byte[0]`)
 * creates the name with no wires; its `first_wire` is GF8_WIRE_ID_INVALID
 * and must not be dereferenced.  A scalar has `length == 1` and
 * `is_vector == 0`.
 */
typedef struct {
    const char *name;       /* declared name without the '%' sigil; owned */
    gf8_wire_id first_wire; /* wire id of element 0 (invalid if length 0) */
    size_t length;          /* element count: vector N (>= 0); scalar 1 */
    voleith_shipshape_decl_kind_t kind;
    int is_bit;    /* 1 if the refinement type is bit, 0 if byte */
    int is_vector; /* 1 if declared with a [N] type, 0 if scalar */
} voleith_shipshape_decl_t;

/*
 * One region marker, emitted once per inlined subcircuit call site in
 * inlining order (ISA 1.4, 5.2 Step 7).  Region markers are semantically
 * transparent: they are NOT part of the circuit or its fingerprint, only a
 * side table for witness-backend dispatch.  `name` is the call's
 * fully-qualified subcircuit name (e.g. "user/aes_keystream").
 *
 * `first_witness` / `n_witness` bound the half-open range of witness-array
 * slots (ISA 2.11) introduced while inlining this call, nested calls
 * included.  Outer regions therefore enclose the ranges of any regions
 * nested inside them.
 *
 * `inputs` / `n_inputs`: the call's flattened input wire ids in
 * signature order (one entry per byte of each argument, left to right).
 * Populated by the parser for `stdlib/crypto/*` registry calls (both FIXED
 * and PARAMETRIC) so that Tier 2a witness-backend dispatch can assemble the
 * per-region external-input slice without re-parsing the call site.  NULL
 * and 0 for `user/*` regions, which never dispatch.  Owned by the parsed
 * result; freed by voleith_shipshape_parsed_free().
 */
typedef struct {
    const char *name;     /* fully-qualified subcircuit name; owned */
    size_t first_witness; /* first witness slot introduced by this call */
    size_t n_witness;     /* witness slots introduced (nested calls included) */
    gf8_wire_id *inputs;  /* owned; signature-order input wire ids, or NULL */
    size_t n_inputs;      /* count; 0 when no inputs are recorded */
    /*
     * Crypto-v2 construction parameters (W8.5a).  Valid only when the region
     * is a REG_HASH_PARAM bracketed "fqn[type]" construction call: cv2_valid
     * is 1 then, 0 for every crypto-v1 and user region.  A Tier 2a construction
     * backend uses these to drive the path walk (node-hash type, tree depth,
     * leaf / target width) without re-deriving them from the witness span.
     */
    uint8_t cv2_valid;
    uint16_t cv2_type_id;    /* node-hash type id (parser node-hash table)   */
    uint8_t cv2_n_params;    /* number of valid entries in cv2_params        */
    uint8_t cv2_depth_param; /* index into cv2_params holding the tree depth */
    uint8_t cv2_leaf_param;  /* index into cv2_params for the leaf/sk width  */
    uint32_t cv2_params[VOLEITH_SHIPSHAPE_REG_MAX_PARAMS];
} voleith_shipshape_region_t;

/*
 * Output of a successful parse.  The circuit is heap-allocated; release it
 * with voleith_shipshape_parsed_free() (or take ownership of the circuit
 * field and free it via voleith_gf8_circuit_free() yourself).
 *
 * The circuit is built with topological ordering matching the file.  `decls`
 * is the file-order table of top-level WITNESS / INSTANCE / CONST /
 * CONST_BIT declarations (`n_decls` entries, NULL when none); it is the
 * declaration name table that lets consumers size witness / instance
 * buffers (ISA 2.11).  `regions` is the inlining-order side table of
 * subcircuit call sites (`n_regions` entries, NULL when none).
 */
typedef struct {
    voleith_gf8_circuit_t *circuit;  /* parser-built circuit; caller frees */
    voleith_shipshape_decl_t *decls; /* file-order declarations; caller frees */
    size_t n_decls;                  /* number of entries in decls */
    voleith_shipshape_region_t *regions; /* inlining-order call sites; owned */
    size_t n_regions;                    /* number of entries in regions */
} voleith_shipshape_parsed_t;

/* ================================================================
 * Parse API
 * ================================================================ */

/*
 * Parse a Shipshape circuit from the file at `path`.
 *
 * `limits` may be NULL (all ceilings).  The file size is checked against
 * the effective file-byte limit before any of the file is buffered
 * (ISA 5.1).
 *
 * On success, fills `out` and returns 0; the caller owns `out` and must
 * eventually call voleith_shipshape_parsed_free().  On failure, returns a
 * negative voleith_shipshape_error_t and zeroes `out` (when non-NULL); no
 * partial allocations are leaked.
 */
int voleith_shipshape_parse_file(voleith_shipshape_parsed_t *, const char *,
                                 const voleith_shipshape_limits_t *);

/*
 * Parse a Shipshape circuit from an in-memory buffer.
 *
 * If `len` is 0 the parser uses strlen(buf); otherwise it reads at most
 * `len` bytes and does not require NUL termination.  `len` is checked
 * against the effective file-byte limit before any work is done.
 *
 * Return value and ownership match voleith_shipshape_parse_file().
 */
int voleith_shipshape_parse_buffer(voleith_shipshape_parsed_t *, const char *,
                                   size_t, const voleith_shipshape_limits_t *);

/*
 * Release all memory owned by a parsed result.
 *
 * Safe to call on a zero-initialised struct (the common cleanup pattern:
 * declare as `voleith_shipshape_parsed_t p = {0};` and call this
 * unconditionally on all exit paths).  Safe to call with a NULL argument.
 * The circuit is released via voleith_gf8_circuit_free(), the declaration
 * table and its names are freed, and the struct is zeroed on return.
 */
void voleith_shipshape_parsed_free(voleith_shipshape_parsed_t *);

#endif /* VOLEITH_PARSERS_SHIPSHAPE_H */
