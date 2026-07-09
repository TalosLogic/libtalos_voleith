/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * erasure.h - Common types for the erasure-coding module
 *
 * The erasure module is a plaintext data layer (sibling to vole/) that
 * provides Reed-Solomon (storage) and RLNC (transport) coding over the
 * core field arithmetic.  It depends only on core/ and is not one of the
 * five proof layers.  In-circuit proving of erasure relations lives in
 * circuits/ (Layer 5) and is built on top of, and validated against, this
 * plaintext layer.  See docs/ERASURE_CODES_DESIGN.md.
 *
 * This umbrella header carries the shared error codes, the field selector,
 * and the chunk descriptor used by both rs.* (GF(2^8)) and rlnc.*
 * (GF(2^16)).  It declares no algorithms.
 */

#ifndef VOLEITH_ERASURE_H
#define VOLEITH_ERASURE_H

#include <stddef.h>
#include <stdint.h>

/* ========================================================================
 * Status / error codes
 *
 * Follows the project convention: 0 on success, negative on failure.
 * ======================================================================== */

#define VOLEITH_EC_OK 0           /* Success. */
#define VOLEITH_EC_ERR_PARAM (-1) /* Invalid argument (NULL, bad n/k, ...). */
#define VOLEITH_EC_ERR_SINGULAR (-2)   /* Submatrix not invertible. */
#define VOLEITH_EC_ERR_INCOMPLETE (-3) /* Too few chunks to reconstruct. */
#define VOLEITH_EC_ERR_NOMEM (-4)      /* Allocation failed. */
#define VOLEITH_EC_ERR_FIELD (-5)  /* Unknown / unsupported field selector. */
#define VOLEITH_EC_ERR_VERIFY (-6) /* A binding / verification check failed. */

/* ========================================================================
 * Field selector
 *
 * Selects the finite field a coder or generator matrix operates over.
 * GF(2^8) (core/field.h) backs Reed-Solomon; GF(2^16) (core/field16.h)
 * backs RLNC.
 * ======================================================================== */

typedef enum {
    VOLEITH_EC_FIELD_GF8 = 8,
    VOLEITH_EC_FIELD_GF16 = 16
} voleith_ec_field_t;

/* Returns the element width in bytes for a field selector (1 or 2), or 0
 * for an unknown selector. */
static inline size_t
voleith_ec_field_elem_bytes(voleith_ec_field_t field)
{
    switch (field) {
    case VOLEITH_EC_FIELD_GF8:
        return 1;
    case VOLEITH_EC_FIELD_GF16:
        return 2;
    default:
        return 0;
    }
}

/* ========================================================================
 * Chunk descriptor
 *
 * A single coded or source chunk: a contiguous byte buffer of len bytes,
 * tagged with the coordinate index that identifies it within its code
 * (the row index of C = G . M for RS, the source position for an RLNC
 * source symbol).  The descriptor does not own the buffer; the caller
 * manages its lifetime.
 * ======================================================================== */

typedef struct {
    uint8_t *data; /* Chunk payload (not owned). */
    size_t len;    /* Payload length in bytes. */
    size_t index;  /* Coordinate / position index within the code. */
} voleith_ec_chunk_t;

#endif /* VOLEITH_ERASURE_H */
