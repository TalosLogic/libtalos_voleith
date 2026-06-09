/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * field_dispatch.h - Internal field-mul ops-table and dispatch declarations.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   core/field.c          (publishes voleith_field_ops, runs init)
 *   core/field_clmul.c    (defines voleith_field_ops_clmul)
 *   core/field_pmull.c    (defines voleith_field_ops_pmull)
 *   core/field_scalar.c   (defines voleith_field_ops_scalar)
 *
 * The three statically-defined ops tables are guarded by the same
 * VOLEITH_HAVE_* macros that gate their TUs.  voleith_field_ops points
 * to whichever table voleith_field_dispatch_init() selects.
 */

#ifndef VOLEITH_FIELD_DISPATCH_H
#define VOLEITH_FIELD_DISPATCH_H

#include <stdatomic.h>
#include "field.h"

typedef struct {
    void (*gf128_mul)(voleith_gf128_t *, const voleith_gf128_t *,
                      const voleith_gf128_t *);
    void (*gf192_mul)(voleith_gf192_t *, const voleith_gf192_t *,
                      const voleith_gf192_t *);
    void (*gf256_mul)(voleith_gf256_t *, const voleith_gf256_t *,
                      const voleith_gf256_t *);
    const char *name;
} voleith_field_ops_t;

#ifdef VOLEITH_HAVE_CLMUL
extern const voleith_field_ops_t voleith_field_ops_clmul;
#endif
#ifdef VOLEITH_HAVE_PMULL
extern const voleith_field_ops_t voleith_field_ops_pmull;
#endif
extern const voleith_field_ops_t voleith_field_ops_scalar;

/* Selected at init; read by the public forwarders in core/field.c. */
extern _Atomic(const voleith_field_ops_t *) voleith_field_ops;

/* Called by public forwarders on first use. */
void voleith_field_dispatch_init(void);

/* Resets the dispatch table pointer to NULL (test-only). */
void voleith_field_dispatch_reset(void);

#endif /* VOLEITH_FIELD_DISPATCH_H */
