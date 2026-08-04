/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * rs_opener_gf8.c - generic designated-opener dispatch.
 *
 * The PKE-independent layer: a registry of compiled opener-scheme backends keyed
 * by the frozen scheme_id, plus the generic entry points that resolve params,
 * check the witness scheme tag, and dispatch to the selected backend.  See
 * rs_opener_gf8.h; the only backend today is Argus (rs_opener_argus_gf8.h).
 */

#include "rs_opener_gf8.h"

#include "rs_opener_argus_gf8.h" /* voleith_rs_opener_argus */

#include <stddef.h>
#include <stdint.h>

/* Compiled backends, keyed by scheme_id.  Adding a backend appends one row. */
static const voleith_rs_opener_scheme_t *const OPENER_SCHEMES[] = {
    &voleith_rs_opener_argus,
    NULL,
};

const voleith_rs_opener_scheme_t *
voleith_rs_opener_scheme(uint8_t scheme_id)
{
    size_t i;

    for (i = 0; OPENER_SCHEMES[i] != NULL; i++)
        if (OPENER_SCHEMES[i]->scheme_id == scheme_id)
            return OPENER_SCHEMES[i];
    return NULL;
}

size_t
voleith_rs_opener_tag_bytes(const voleith_rs_opener_scheme_t *scheme,
                            uint32_t set, size_t id_len)
{
    const void *params;

    if (scheme == NULL)
        return 0;
    params = scheme->params(set);
    if (params == NULL)
        return 0;
    return scheme->tag_bytes(params, id_len);
}

int
voleith_rs_opener_verify(const voleith_rs_opener_scheme_t *scheme, uint32_t set,
                         const uint8_t *pk, const uint8_t *tag, size_t tag_len,
                         const voleith_rs_opener_witness_t *witness,
                         const uint8_t *id, size_t id_len)
{
    const void *params;

    if (scheme == NULL || pk == NULL || tag == NULL || witness == NULL ||
        id == NULL)
        return VOLEITH_RS_OPENER_EARGS;
    if (witness->scheme_id != scheme->scheme_id)
        return VOLEITH_RS_OPENER_ESCHEME;

    params = scheme->params(set);
    if (params == NULL)
        return VOLEITH_RS_OPENER_ESET;

    return scheme->verify(params, pk, tag, tag_len, witness->data, id, id_len);
}
