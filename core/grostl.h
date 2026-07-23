/*
 * Copyright (c) 2026 Jason Crawford
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * grostl.h - alias shim over <ichor/grostl.h>.
 *
 * Grøstl-256/512 moved to libtalos_ichor (shared with libtalos_syndrome).
 * voleith's in-circuit node-hash builders in circuits/ include this shim and
 * reach only the public voleith_grostl* API, which maps 1:1 to ichor_grostl*.
 * The voleith_grostl{256,512}_compress_node software oracles keep a
 * byte-identical, int-returning, fixed-array signature so the in-circuit
 * builder and the oracle still share one definition.
 * See docs/private/ICHOR_MIGRATION_1_10_1.md.
 *
 * voleith_grostl_dispatch_reset is test-only in ichor: its alias resolves only
 * under ICHOR_ENABLE_FORCE_BACKEND, matching the guard on the ichor
 * declaration.  ichor also exposes init_iv / finalize_fixed; voleith does not
 * use those names, so they are reached (if needed) through <ichor/grostl.h>
 * directly rather than aliased here.
 */

#ifndef VOLEITH_GROSTL_H
#define VOLEITH_GROSTL_H

#include <ichor/grostl.h>

typedef ichor_grostl_ctx_t voleith_grostl_ctx_t;

#define voleith_grostl256 ichor_grostl256
#define voleith_grostl512 ichor_grostl512
#define voleith_grostl256_init ichor_grostl256_init
#define voleith_grostl512_init ichor_grostl512_init
#define voleith_grostl_absorb ichor_grostl_absorb
#define voleith_grostl_finalize ichor_grostl_finalize
#define voleith_grostl_clear ichor_grostl_clear
#define voleith_grostl256_compress_node ichor_grostl256_compress_node
#define voleith_grostl512_compress_node ichor_grostl512_compress_node
#define voleith_grostl_backend_name ichor_grostl_backend_name

#ifdef ICHOR_ENABLE_FORCE_BACKEND
#define voleith_grostl_dispatch_reset ichor_grostl_dispatch_reset
#endif

#endif /* VOLEITH_GROSTL_H */
