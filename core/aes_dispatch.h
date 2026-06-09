/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * aes_dispatch.h - Internal AES ops-table and dispatch declarations.
 *
 * Not in include/; not part of the public API.  Consumed by:
 *   core/aes.c          (publishes voleith_aes_ops, runs init)
 *   core/aes_aesni.c    (defines voleith_aes_ops_aesni)
 *   core/aes_armv8.c    (defines voleith_aes_ops_armv8)
 *   core/aes_ct64_ops.c (defines voleith_aes_ops_bitsliced)
 *
 * The three statically-defined ops tables are guarded by the same
 * VOLEITH_HAVE_* macros that gate their TUs.  voleith_aes_ops points
 * to whichever table voleith_aes_dispatch_init() selects.
 */

#ifndef VOLEITH_AES_DISPATCH_H
#define VOLEITH_AES_DISPATCH_H

#include <stdatomic.h>
#include "aes.h"

typedef struct {
    int (*key_expand)(voleith_aes_ctx_t *, const uint8_t *, int);
    void (*encrypt)(const voleith_aes_ctx_t *, uint8_t[16], const uint8_t[16]);
    void (*encrypt_x4)(const voleith_aes_ctx_t *, uint8_t[64],
                       const uint8_t[64]);
    voleith_aes_backend_t backend_tag;
    const char *name;
} voleith_aes_ops_t;

#ifdef VOLEITH_HAVE_AES_NI
extern const voleith_aes_ops_t voleith_aes_ops_aesni;
#endif
#ifdef VOLEITH_HAVE_ARMV8_AES
extern const voleith_aes_ops_t voleith_aes_ops_armv8;
#endif
extern const voleith_aes_ops_t voleith_aes_ops_bitsliced;

/* Selected at init; read by the public forwarders in core/aes.c. */
extern _Atomic(const voleith_aes_ops_t *) voleith_aes_ops;

/* Called by public forwarders on first use. */
void voleith_aes_dispatch_init(void);

#endif /* VOLEITH_AES_DISPATCH_H */
